"""Network assurance: Cisco syslog / traps / telemetry / config / LLDP → topology-aware root cause,
alarm suppression, flap detection, change-correlated outages → the ``netops`` fast path, plus the
Kafka-bridge contract (``/ingest/netops`` push and the ``/ingest/verdicts`` cursor feed).

All device names, addresses and users are invented.
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

import pytest

from aegis.agents.netops import NetworkAssurance
from aegis.agents.netops.assurance import role_of
from aegis.agents.orchestrator.netops import is_network_fault, network_fault_chain
from aegis.ingest import AlertCheckpoint
from aegis.ingest.base import CONSUMED
from aegis.ingest.netops import NetopsConsumer, canon_iface, normalize, parse_syslog_line, reset_shared_detector
from aegis.ingest.stream import StreamConsumer, StreamQueue

FIX = Path(__file__).resolve().parents[1] / "ingest" / "fixtures" / "netops"
T = 1_793_253_600.0          # 2026-10-29T06:00:00Z


def _campus(**kw) -> NetworkAssurance:
    """CORE-01 ─ DIST-01 (dual-homed via CORE-02) ─ ACC-01 (120 users); DIST-02 single-homed ─ ACC-02 (80)."""
    d = NetworkAssurance(clock=lambda: T, **kw)
    for a, ai, b, bi in [("CORE-01", "Ethernet1/1", "CORE-02", "Ethernet1/1"),
                         ("DIST-01", "Ethernet1/49", "CORE-01", "Ethernet1/2"), ("DIST-01", "Ethernet1/50", "CORE-02", "Ethernet1/2"),
                         ("DIST-02", "Ethernet1/49", "CORE-01", "Ethernet1/3"),
                         ("ACC-01", "GigabitEthernet1/0/49", "DIST-01", "Ethernet1/5"),
                         ("ACC-02", "GigabitEthernet1/0/49", "DIST-02", "Ethernet1/5")]:
        d.observe({"kind": "topology", "device": a, "neighbor": b, "iface": ai, "neighbor_iface": bi, "ts": T,
                   "users": {"ACC-01": 120, "ACC-02": 80}.get(a, 0)})
    return d


def _down(dev: str, iface: str, ts: float, *, nxos: bool = False) -> dict:
    line = (f"<189>{dev}: 2026 Oct 29 06:00:00 UTC: %ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface {iface} is down (Link failure)" if nxos
            else f"<189>{dev}: *Oct 29 2026 06:00:00.000 UTC: %LINK-3-UPDOWN: Interface {iface}, changed state to down")
    return parse_syslog_line(line, ts=ts)


def _up(dev: str, iface: str, ts: float) -> dict:
    return parse_syslog_line(f"<189>{dev}: *Oct 29 2026 06:00:00.000 UTC: %LINK-3-UPDOWN: Interface {iface}, changed state to up", ts=ts)


# ----------------------------------------------------------------------------- parsers --

def test_syslog_parser_handles_ios_nxos_and_relay_shapes():
    ev = parse_syslog_line("<189>1234: *Oct 29 20:05:01.123 UTC: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/24, changed state to down")
    assert ev["facility"] == "LINK" and ev["mnemonic"] == "LINK-3-UPDOWN" and ev["state"] == "down"
    assert ev["iface"] == "GigabitEthernet1/0/24" and ev["severity"] == 3
    ev = parse_syslog_line("<189>DIST-01 2026 Oct 29 20:05:03 UTC: %ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/49 is down (Link failure)")
    assert ev["device"] == "DIST-01" and ev["state"] == "down" and ev["iface"] == "Ethernet1/49"
    ev = parse_syslog_line("<189>CORE-01: Oct 29 2026 20:06:00: %BGP-5-ADJCHANGE: neighbor 10.0.0.2 Down BGP Notification sent")
    assert ev["device"] == "CORE-01" and ev["facility"] == "BGP" and ev["state"] == "down" and ev["peer"] == "10.0.0.2"
    ev = parse_syslog_line("<189>ACC-03: %OSPF-5-ADJCHG: Process 1, Nbr 10.1.0.1 on GigabitEthernet1/0/49 from FULL to DOWN, Neighbor Down: Dead timer expired")
    assert ev["state"] == "down" and ev["iface"] == "GigabitEthernet1/0/49"
    assert parse_syslog_line("just some text without a cisco message") is None
    # the bridge's fold line parses as a harmless system message
    ev = parse_syslog_line("<189>ACC-17: %AEGIS-5-FLAP_SUPPRESSED: Interface GigabitEthernet1/0/49, 35 further up/down transitions suppressed by the Kafka bridge in 300 s")
    assert ev["facility"] == "AEGIS" and ev["state"] is None


def test_interface_names_are_canonical_so_both_ends_match():
    assert canon_iface("Gi1/0/49") == "GigabitEthernet1/0/49"
    assert canon_iface("Eth1/49") == "Ethernet1/49"
    assert canon_iface("Te1/1/1") == "TenGigabitEthernet1/1/1"
    assert canon_iface("Hu0/0/0/0") == "HundredGigE0/0/0/0"
    assert canon_iface("GigabitEthernet1/0/1") == "GigabitEthernet1/0/1"
    assert canon_iface("Po10") == "Port-channel10"


def test_normalize_dispatches_every_record_kind():
    tr = normalize({"trap": "IF-MIB::linkDown", "host": "ACC-01", "varbinds": {"ifDescr": "Gi1/0/49"}})
    assert tr["kind"] == "trap" and tr["state"] == "down" and tr["iface"] == "GigabitEthernet1/0/49" and tr["device"] == "ACC-01"
    assert normalize({"snmpTrapOID": "BGP4-MIB::bgpBackwardTransition", "host": "CORE-01"})["state"] == "down"
    t = normalize({"device": "WAN-01", "interface": "Gi0/0/1", "ifHighSpeed": 1000, "in_octets": 10, "out_octets": 5, "crc": 2})
    assert t["kind"] == "telemetry" and t["iface"] == "GigabitEthernet0/0/1" and t["counters"]["crc"] == 2
    f = normalize({"srcaddr": "10.1.1.1", "dstaddr": "10.2.2.2", "dOctets": 5000, "exporter": "WAN-01"})
    assert f["kind"] == "flow"
    c = normalize({"kind": "config_change", "device": "DIST-02", "config_hash": "abc", "user": "jdoe", "change_ticket": "CHG-1"})
    assert c["kind"] == "config" and c["change_ticket"] == "CHG-1" and c["user"] == "jdoe"
    top = normalize({"device": "ACC-01", "neighbor": "DIST-01", "local_iface": "Gi1/0/49", "neighbor_iface": "Eth1/5"})
    assert top["kind"] == "topology" and top["iface"] == "GigabitEthernet1/0/49" and top["neighbor_iface"] == "Ethernet1/5"
    assert normalize({"unrelated": True}) is None
    assert role_of("DIST-07") == "distribution" and role_of("WAN-EDGE-1") == "wan-edge" and role_of("SW-ACC-3") == "access"


# ---------------------------------------------------------------------------- detector --

def test_single_homed_cut_is_one_critical_root_cause_with_symptoms_suppressed():
    d = _campus()
    alerts = d.observe(_down("DIST-02", "Ethernet1/49", T + 300, nxos=True))
    assert len(alerts) == 1
    a = alerts[0]
    n = a["netops"]
    assert n["fault"] == "link_down" and a["device"] == "DIST-02" and a["iface"] == "Ethernet1/49"
    assert a["severity"] == "critical" and n["downstream"] == ["ACC-02"] and n["users_affected"] == 80 and n["redundant"] is False
    # the far end, the stranded access switch and its OSPF are the same outage
    assert d.observe(_down("CORE-01", "Ethernet1/3", T + 300.2, nxos=True)) == []
    assert d.observe(_down("ACC-02", "GigabitEthernet1/0/49", T + 301)) == []
    assert d.observe(parse_syslog_line("<189>ACC-02: %OSPF-5-ADJCHG: Process 1, Nbr 10.2.0.1 on GigabitEthernet1/0/49 from FULL to DOWN", ts=T + 336)) == []
    inc = d.incident_for(a["id"])
    assert inc["suppressed"] == 3 and "ACC-02" in inc["symptoms"]


def test_dual_homed_cut_is_medium_redundant_with_nothing_downstream():
    d = _campus()
    (a,) = d.observe(_down("DIST-01", "Ethernet1/49", T + 60, nxos=True))
    assert a["severity"] == "medium" and a["netops"]["redundant"] is True and a["netops"]["downstream_count"] == 0
    # ACC-01 keeps its path through CORE-02; no symptom, no alert from it either
    assert d.observe(_down("ACC-01", "GigabitEthernet1/0/7", T + 61)) == []       # an edge port, not even a known link


def test_incident_stays_open_while_the_link_is_down_and_closes_on_restore():
    d = _campus(corr_window_s=120.0, silent_s=180.0)
    for dev in ("CORE-01", "DIST-01", "DIST-02", "ACC-01", "ACC-02"):
        d.observe({"kind": "telemetry", "device": dev, "iface": "x", "ts": T, "counters": {}})
    (a,) = d.observe(_down("DIST-02", "Ethernet1/49", T + 10, nxos=True))
    # every minute for 10 min (well past the correlation window) everyone else reports in; ACC-02 stays silent: same outage
    for m in range(1, 11):
        for dev in ("CORE-01", "DIST-01", "DIST-02", "ACC-01"):
            assert d.observe({"kind": "telemetry", "device": dev, "iface": "x", "ts": T + 60 * m, "counters": {}}) == []
    assert d.stats["device_unreachable"] == 0 and d.incident_for(a["id"])["suppressed"] >= 1
    # the fibre is spliced: incident closes, a later symptom is new
    d.observe(_up("DIST-02", "Ethernet1/49", T + 700))
    for dev in ("CORE-01", "DIST-01", "DIST-02", "ACC-01"):
        d.observe({"kind": "telemetry", "device": dev, "iface": "x", "ts": T + 850, "counters": {}})
    assert d.observe(_down("ACC-02", "GigabitEthernet1/0/49", T + 760)) == []        # inside the post-restore grace window
    (b,) = d.observe(_down("ACC-02", "GigabitEthernet1/0/49", T + 900))
    assert b["netops"]["fault"] == "link_down" and b["device"] == "ACC-02"


def test_edge_port_churn_is_silent_but_a_flapping_uplink_is_one_alert():
    d = _campus(flap_n=5, flap_window_s=300)
    for i in range(10):                                   # users plugging in and out all morning
        d.observe(_down("ACC-01", f"GigabitEthernet1/0/{i + 1}", T + i * 20))
    assert d.stats["link_down"] == 0 and d.stats["flaps"] == 0
    alerts = []
    for i in range(8):
        f = _down if i % 2 == 0 else _up
        alerts += d.observe(f("ACC-01", "GigabitEthernet1/0/49", T + 1000 + i * 30))
    kinds = [a["netops"]["fault"] for a in alerts]
    assert kinds.count("link_flap") == 1 and kinds[0] == "link_down"         # first down is real; the 5th transition names the flap
    flap = next(a for a in alerts if a["netops"]["fault"] == "link_flap")
    assert flap["netops"]["transitions"] >= 5 and flap["netops"]["peer"] == "DIST-01"


def test_unticketed_change_then_outage_is_bad_config_push_with_the_pusher_named():
    d = _campus(bad_push_s=600)
    drift = d.observe({"kind": "config", "device": "DIST-02", "config_hash": "v1", "ts": T})
    assert drift == []                                    # first sighting is golden
    (dr,) = d.observe({"kind": "config", "device": "DIST-02", "config_hash": "v2", "user": "jdoe", "source_ip": "10.20.0.77", "ts": T + 100})
    assert dr["netops"]["fault"] == "config_drift" and dr["netops"]["change_ticket"] is None
    (bp,) = d.observe(parse_syslog_line("<189>DIST-02: %BGP-5-ADJCHANGE: neighbor 10.0.0.1 Down BGP Notification sent", ts=T + 190))
    n = bp["netops"]
    assert n["fault"] == "bad_config_push" and bp["severity"] == "critical" and n["user"] == "jdoe" and n["source_ip"] == "10.20.0.77"
    chain = network_fault_chain(bp)
    assert chain.verdict == "malicious"
    acts = {a.action_type: a for a in chain.recommended_actions}
    assert {"config_rollback", "revoke_sessions", "escalate"} <= set(acts)
    assert acts["revoke_sessions"].target == "jdoe" and acts["config_rollback"].target == "DIST-02"
    assert all(a.requires_hitl for a in chain.recommended_actions if a.action_type != "monitor")


def test_ticketed_change_then_outage_is_never_malicious():
    d = _campus(bad_push_s=600)
    d.observe({"kind": "config", "device": "DIST-02", "config_hash": "v1", "ts": T})
    (dr,) = d.observe({"kind": "config", "device": "DIST-02", "config_hash": "v2", "user": "netops-svc", "change_ticket": "CHG-44102", "ts": T + 100})
    assert network_fault_chain(dr).verdict == "benign"
    (adj,) = d.observe(parse_syslog_line("<189>DIST-02: %BGP-5-ADJCHANGE: neighbor 10.0.0.1 Down BGP Notification sent", ts=T + 160))
    assert adj["netops"]["fault"] == "adjacency_loss"
    chain = network_fault_chain(adj)
    assert chain.verdict != "malicious" and not {a.action_type for a in chain.recommended_actions} & {"config_rollback", "revoke_sessions"}


def test_telemetry_errors_congestion_and_silence():
    d = _campus(err_per_min=100, util_pct=90, util_samples=3, silent_s=180)
    out = []
    for i in range(4):
        out += d.observe({"kind": "telemetry", "device": "ACC-01", "iface": "GigabitEthernet1/0/49", "ts": T + i * 60,
                          "counters": {"crc": 600 * i, "in_octets": 1e9 + i * 1e6, "out_octets": 1e9, "speed_bps": 1e9}})
    assert [a["netops"]["fault"] for a in out] == ["interface_errors"]
    out = []
    for i in range(5):                                      # 95 % of a 1 Gbit/s link for five minutes
        octets = 0.95 * 1000e6 / 8 * 60
        out += d.observe({"kind": "telemetry", "device": "DIST-02", "iface": "Ethernet1/49", "ts": T + i * 60,
                          "counters": {"in_octets": 1e12 + i * octets * 0.5, "out_octets": 1e12 + i * octets * 0.5, "speed_bps": 1e9}})
    assert [a["netops"]["fault"] for a in out] == ["congestion"]
    # silence: everyone reports every minute; ACC-02 goes quiet after T+300 → one device_unreachable, once
    silent = []
    for m in range(5, 12):
        for dev in ("CORE-01", "CORE-02", "DIST-01", "DIST-02", "ACC-01", "ACC-02"):
            if dev == "ACC-02" and m > 5:
                continue
            silent += d.observe({"kind": "telemetry", "device": dev, "iface": "x", "ts": T + 60 * m, "counters": {"in_octets": m}})
    assert [(a["netops"]["fault"], a["device"]) for a in silent] == [("device_unreachable", "ACC-02")]


# ------------------------------------------------------------------------- fast path --

def test_fast_path_routes_every_fault_and_actions_are_hitl():
    d = _campus()
    (a,) = d.observe(_down("DIST-02", "Ethernet1/49", T + 1, nxos=True))
    assert is_network_fault(a) and not is_network_fault({"alert_type": "waf_block"})
    chain = network_fault_chain(a)
    assert chain.verdict == "suspicious" and chain.confidence >= 0.85 and chain.metadata["netops"]["downstream"] == 1
    kinds = [a.action_type for a in chain.recommended_actions]
    assert "escalate" in kinds and "monitor" in kinds
    assert any("ACC-02" in e.signal or "80" in e.signal for e in chain.evidence)


def test_pipeline_end_to_end_audit_verifies(tmp_path, monkeypatch):
    from aegis.eval.fault_injection import _env
    from aegis.eval.network_fault_bench import _env as bench_env
    with _env(bench_env(tmp_path)):
        from aegis.service import build_pipeline
        reset_shared_detector()
        p = build_pipeline(tmp_path / "audit.jsonl", fresh=True)
        import io
        p.response._hitl_stream = io.StringIO()
        c = NetopsConsumer(checkpoint=AlertCheckpoint())
        alerts = list(c.iter_alerts(path=str(FIX / "campus.sample.log")))
        assert [a["netops"]["fault"] for a in alerts] == ["link_down"] and alerts[0]["device"] == "DIST-01"
        assert alerts[0]["netops"]["downstream_count"] == 2 and alerts[0]["netops"]["users_affected"] == 200
        chain = p.orch.handle(alerts[0])
        p.response.execute(chain)
        assert chain.metadata["netops"]["fault"] == "link_down" and p.audit.verify()
        assert c.events >= 11 and c.detector.stats["suppressed"] >= 5


# -------------------------------------------------------------- stream + push + feed --

def test_stream_routes_netops_by_source_or_content():
    reset_shared_detector()
    q = StreamQueue(capacity=100)
    q.put("syslog-relay", '{"device":"DIST-01","neighbor":"CORE-01","local_iface":"Ethernet1/49","neighbor_iface":"Ethernet1/2","role":"distribution","neighbor_role":"core"}')
    q.put("syslog-relay", '{"device":"ACC-01","neighbor":"DIST-01","local_iface":"Gi1/0/49","neighbor_iface":"Eth1/5","role":"access","neighbor_role":"distribution","users":50}')
    q.put("anything", "<189>DIST-01: 2026 Oct 29 06:05:00 UTC: %ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/49 is down (Link failure)")
    q.put("anything", "<189>ACC-01: *Oct 29 2026 06:05:01.000 UTC: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/49, changed state to down")
    alerts = list(StreamConsumer(queue=q, checkpoint=AlertCheckpoint()).iter_alerts())
    assert len(alerts) == 1 and alerts[0]["netops"]["fault"] == "link_down" and alerts[0]["ingest_source"] == "anything"
    assert alerts[0]["netops"]["downstream"] == ["ACC-01"]


def test_push_netops_and_verdict_feed(tmp_path):
    from aegis.ingest.http_push import PushServer
    reset_shared_detector()
    q = StreamQueue(capacity=1000)
    audit = tmp_path / "audit.jsonl"
    rows = [{"alert_id": f"a{i}", "verdict": "suspicious", "integrity_hash": f"h{i}"} for i in range(3)]
    audit.write_text("".join(json.dumps(r) + "\n" for r in rows))
    srv = PushServer(token="tok", bind="127.0.0.1:0", queue=q, audit_path=audit).start()
    try:
        body = (FIX / "campus.sample.log").read_text().encode()
        req = urllib.request.Request(f"{srv.url}/ingest/netops?feed=syslog", data=body,
                                     headers={"Authorization": "Bearer tok"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            assert r.status == 200 and json.loads(r.read())["accepted"] > 10

        def get(qs: str):
            rq = urllib.request.Request(f"{srv.url}/ingest/verdicts{qs}", headers={"Authorization": "Bearer tok"})
            with urllib.request.urlopen(rq, timeout=10) as r:
                return json.loads(r.read())

        first = get("?after=0&limit=2")
        assert [v["seq"] for v in first["verdicts"]] == [1, 2] and first["next"] == 2
        assert first["verdicts"][0]["prev_hash"] == "0" * 64 and first["verdicts"][1]["prev_hash"] == "h0"
        rest = get("?after=2")
        assert rest["count"] == 1 and rest["verdicts"][0]["chain"]["alert_id"] == "a2" and rest["verdicts"][0]["prev_hash"] == "h1"
        assert get("?after=3")["verdicts"] == []
        with pytest.raises(urllib.error.HTTPError) as ei:
            urllib.request.urlopen(urllib.request.Request(f"{srv.url}/ingest/verdicts", headers={"Authorization": "Bearer wrong"}), timeout=10)
        assert ei.value.code == 401
    finally:
        srv.stop()
    alerts = list(StreamConsumer(queue=q, checkpoint=AlertCheckpoint()).iter_alerts())
    assert len(alerts) == 1 and alerts[0]["ingest_source"] == "netops-syslog" and alerts[0]["device"] == "DIST-01"


def test_registry_netops_file_source(monkeypatch, tmp_path):
    from aegis.ingest import sources_from_env
    reset_shared_detector()
    monkeypatch.setenv("AEGIS_SOURCES", "netops")
    monkeypatch.setenv("NETOPS_EVENT_FILE", str(FIX / "campus.sample.log"))
    monkeypatch.setenv("AEGIS_CHECKPOINT", str(tmp_path / "cp.json"))
    (name, it), *_ = sources_from_env()
    got = list(it)
    assert name == "netops" and [a["netops"]["fault"] for a in got] == ["link_down"]


# ------------------------------------------------------------- blast radius edge cases --

def _campus_with_cross_homed_access() -> NetworkAssurance:
    """Like _campus, plus ACC-04 dual-homed to BOTH DIST-01 and DIST-02 (150 users)."""
    d = _campus()
    d.observe({"kind": "topology", "device": "ACC-04", "neighbor": "DIST-02", "iface": "GigabitEthernet1/0/49",
               "neighbor_iface": "Ethernet1/6", "ts": T, "users": 150, "role": "access"})
    d.observe({"kind": "topology", "device": "ACC-04", "neighbor": "DIST-01", "iface": "GigabitEthernet1/0/50",
               "neighbor_iface": "Ethernet1/7", "ts": T, "users": 150, "role": "access"})
    return d


def test_an_access_switch_is_never_a_transit_path():
    """ACC-04 hangs off both distributions. Graph-wise that makes DIST-02 'reachable' via ACC-04 → DIST-01 after
    its own uplink is cut — but an access switch does not forward between distributions, so DIST-02's single-homed
    children are stranded and the cut is critical, not redundant."""
    d = _campus_with_cross_homed_access()
    (a,) = d.observe(_down("DIST-02", "Ethernet1/49", T + 10, nxos=True))
    assert a["severity"] == "critical" and a["netops"]["redundant"] is False
    assert a["netops"]["downstream"] == ["ACC-02"] and a["netops"]["users_affected"] == 80       # ACC-04 still has DIST-01
    # ACC-04 losing its DIST-02 leg is a redundant loss for ACC-04
    d2 = _campus_with_cross_homed_access()
    (b,) = d2.observe(_down("ACC-04", "GigabitEthernet1/0/49", T + 10))
    assert b["severity"] == "medium" and b["netops"]["redundant"] is True


def test_losing_the_last_redundant_uplink_widens_the_incident_instead_of_folding():
    d = _campus_with_cross_homed_access()
    (first,) = d.observe(_down("DIST-01", "Ethernet1/49", T + 10, nxos=True))
    assert first["severity"] == "medium" and first["netops"]["redundant"] is True
    (second,) = d.observe(_down("DIST-01", "Ethernet1/50", T + 40, nxos=True))
    n = second["netops"]
    assert second["severity"] == "critical" and n["last_path"] is True
    assert n["downstream"] == ["ACC-01"] and n["users_affected"] == 120           # ACC-04 still has its DIST-02 leg
    # and the access switches behind it are now symptoms of THAT incident
    assert d.observe(_down("ACC-01", "GigabitEthernet1/0/49", T + 41)) == []
    assert d.incident_for(second["id"])["suppressed"] == 1


# ------------------------------------------------------------ review round 1 regressions --

def test_relay_headers_and_odd_timestamps_are_handled():
    """N2 / N3 / N4: rsyslog/syslog-ng wrappers parse (host taken from the relay header), nanosecond clocks are
    scaled, and a line with no hostname is never a per-device fault."""
    from aegis.ingest.netops import _ts_any
    ev = parse_syslog_line("<189>Oct 29 20:05:01 SW1 123: *Oct 29 20:05:01.123 UTC: %LINK-3-UPDOWN: Interface Gi1/0/5, changed state to down")
    assert ev and ev["device"] == "SW1" and ev["state"] == "down" and ev["iface"] == "GigabitEthernet1/0/5"
    ev = parse_syslog_line("<189>1 2026-10-29T20:05:01Z SW2 - - - %LINK-3-UPDOWN: Interface Gi1/0/6, changed state to down")
    assert ev and ev["device"] == "SW2" and ev["state"] == "down"
    ev = parse_syslog_line("<189>Oct 29 20:05:01 10.1.2.3 123: %LINK-3-UPDOWN: Interface Gi1/0/7, changed state to down")
    assert ev and ev["device"] == "10.1.2.3"
    assert abs(_ts_any(1700000000000000000) - 1.7e9) < 1 and abs(_ts_any(1700000000000) - 1.7e9) < 1 and _ts_any("nan") is None
    d = _campus()
    anon = parse_syslog_line("<189>123: *Oct 29 20:05:01.123 UTC: %LINK-3-UPDOWN: Interface Gi1/0/5, changed state to down", ts=T + 1)
    assert anon["device"] == "unknown"
    for i in range(8):
        assert d.observe({**anon, "ts": T + 1 + i}) == []
    # a telemetry record from the year 53 million does not declare the estate dead
    assert d.observe({"kind": "telemetry", "device": "CORE-01", "iface": "x", "ts": 1.7e15, "counters": {}}) == []
    assert d.observe({"kind": "telemetry", "device": "DIST-01", "iface": "x", "ts": "nan", "counters": {}}) == []
    assert d.stats["device_unreachable"] == 0


def test_syslog_only_devices_are_never_silent_and_both_ends_close_the_incident():
    """N1 / N6."""
    d = _campus(silent_s=180.0)
    d.observe(parse_syslog_line("<189>DIST-01: %SYS-5-CONFIG_I: Configured from console by admin on vty0 (10.9.9.9)", ts=T))
    assert d.observe(_down("ACC-01", "GigabitEthernet1/0/7", T + 400)) == []       # DIST-01 has only ever sent syslog: not "silent"
    assert d.stats["device_unreachable"] == 0
    # CORE-01 reports first, DIST-02 later reports the up: the incident must still close
    (a,) = d.observe(_down("CORE-01", "Ethernet1/3", T + 500, nxos=True))
    assert a["device"] == "CORE-01"
    d.observe(_up("DIST-02", "Ethernet1/49", T + 600))
    assert next(i for i in d._incidents if i.alert_id == a["id"]).closed is not None
    (b,) = d.observe(_down("ACC-02", "GigabitEthernet1/0/49", T + 600 + 1000))
    assert b["device"] == "ACC-02"                                                   # not suppressed under a closed incident


def test_flap_counts_physical_transitions_once_and_parallel_links_are_redundant():
    """N5 / N7."""
    d = _campus(flap_n=5, flap_window_s=300)
    # one unplug/replug + one unplug, each announced by LINK and LINEPROTO: 3 transitions, not 5
    for ts, st in ((T + 1, "down"), (T + 1.5, "down"), (T + 20, "up"), (T + 20.5, "up"), (T + 40, "down")):
        out = d.observe(_down("ACC-01", "GigabitEthernet1/0/7", ts) if st == "down" else _up("ACC-01", "GigabitEthernet1/0/7", ts))
        assert out == [], out
    assert d.stats["flaps"] == 0
    # DIST-02 gets a second uplink to CORE-01 (LACP member): losing one of the two is redundant, nothing downstream
    d.observe({"kind": "topology", "device": "DIST-02", "neighbor": "CORE-01", "iface": "Ethernet1/50", "neighbor_iface": "Ethernet1/4", "ts": T})
    (a,) = d.observe(_down("DIST-02", "Ethernet1/50", T + 100, nxos=True))
    assert a["severity"] == "medium" and a["netops"]["redundant"] is True and a["netops"]["downstream_count"] == 0


def test_topology_learned_after_the_fault_keeps_the_root_cause():
    """N8: LLDP arriving after the first syslog (service restarted mid-outage) inherits the pseudo-link's state."""
    d = NetworkAssurance(clock=lambda: T)
    d.observe(_down("DIST-01", "Ethernet1/49", T + 1, nxos=True))                   # nothing known yet: tracked as a pseudo-link
    for a, ai, b, bi in [("DIST-01", "Ethernet1/49", "CORE-01", "Ethernet1/2"), ("ACC-01", "GigabitEthernet1/0/49", "DIST-01", "Ethernet1/5")]:
        d.observe({"kind": "topology", "device": a, "neighbor": b, "iface": ai, "neighbor_iface": bi, "ts": T + 2})
    link = d._iface_link[("DIST-01", "Ethernet1/49")]
    assert link.state == "down" and link.b == "CORE-01"
    # ACC-01's uplink is a different cable: DIST-01 losing its core uplink does not take it down, so a
    # link-down on it is a second, real fault and is raised (review T5: the old `== [] or count <= 1`
    # could not fail). The inherited state survives it.
    (b,) = d.observe(_down("ACC-01", "GigabitEthernet1/0/49", T + 3))
    assert b["netops"]["peer"] == "DIST-01" and b["netops"]["fault"] == "link_down"
    assert d._iface_link[("DIST-01", "Ethernet1/49")].state == "down"


def test_stale_ticket_does_not_shield_a_new_push():
    """N9."""
    d = _campus(bad_push_s=600)
    d.observe({"kind": "config", "device": "DIST-02", "ts": T, "change_ticket": "CHG-1", "config_hash": "a1"})
    d.observe(parse_syslog_line("<189>DIST-02: %SYS-5-CONFIG_I: Configured from console by rverma on vty0 (10.1.2.3)", ts=T + 2 * 86400))
    (a,) = d.observe(_down("DIST-02", "Ethernet1/49", T + 2 * 86400 + 60, nxos=True))
    assert a["netops"]["fault"] == "bad_config_push" and a["netops"]["user"] == "rverma" and a["netops"]["source_ip"] == "10.1.2.3"
