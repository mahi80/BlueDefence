"""Round-3 review, last items: E15 journal, G1-18 breaker floor, I3-13, I3-17/R3-15, I3-18, R3-13, S3-20..25, O3-19/20."""

from __future__ import annotations

import json
import types

import pytest

# ---- E15: pushed records survive a restart -------------------------------------------------------------------------

def test_stream_journal_replays_what_was_not_handled(tmp_path):
    from aegis.ingest.base import AlertCheckpoint
    from aegis.ingest.stream import StreamConsumer, StreamQueue
    q = StreamQueue(100, journal=tmp_path / "j.jsonl")
    assert q.put_many("alerts", [json.dumps({"id": f"a{i}"}) for i in range(5)], passthrough=True)
    it = StreamConsumer(queue=q, checkpoint=AlertCheckpoint()).iter_alerts()
    assert next(it)["id"] == "a0" and next(it)["id"] == "a1"         # a0 handled; a1 in hand when "the process dies"
    after_crash = StreamQueue(100, journal=tmp_path / "j.jsonl")
    assert [json.loads(i.line)["id"] for i in after_crash.drain()] == ["a1", "a2", "a3", "a4"]


def test_a_consumer_stopping_early_puts_records_back(tmp_path):
    from aegis.ingest.base import AlertCheckpoint
    from aegis.ingest.stream import StreamConsumer, StreamQueue
    q = StreamQueue(100)
    q.put_many("alerts", [json.dumps({"id": f"b{i}"}) for i in range(3)], passthrough=True)
    it = StreamConsumer(queue=q, checkpoint=AlertCheckpoint()).iter_alerts()
    next(it)
    it.close()
    assert len(q) == 3                                                # nothing drained-and-dropped


def test_unwritable_journal_answers_503(tmp_path):
    from aegis.ingest.stream import StreamQueue
    q = StreamQueue(100, journal=tmp_path / "j.jsonl")
    (tmp_path / "j.jsonl").mkdir()                                     # cannot be appended to
    assert q.put_many("waf", ["x"]) is False and len(q) == 0


# ---- G1-18: the outflow breaker's own floor ---------------------------------------------------------------------------

def test_breaker_uses_its_own_floor_and_ignores_the_tier(monkeypatch):
    from aegis.agents.response.contracts import gate
    monkeypatch.setenv("AEGIS_AUTONOMY_TIER", "L3")
    act = types.SimpleNamespace(action_type="hold", target="TRSY-001")
    chain = types.SimpleNamespace(confidence=0.92)
    assert gate(act, chain)[0] is False                                # the general rule: tier L3, floor 0.95
    assert gate(act, chain, own_floor=0.90)[0] is True                 # the breaker's opt-in floor
    assert gate(act, chain, own_floor=0.95)[0] is False


# ---- I3-13: Event Hub ----------------------------------------------------------------------------------------------------

def test_unseen_partitions_get_the_configured_start():
    from aegis.ingest.eventhub import EventHubReader as EventHubConsumer
    c = object.__new__(EventHubConsumer)
    c.default_start, c._positions = "earliest", {"0": 120}
    assert c.starting_position(["0", "1", "2"]) == {"0": 120, "1": "-1", "2": "-1"}


# ---- I3-17 / R3-15: feed liveness -----------------------------------------------------------------------------------------

def test_liveness_counts_parsed_records_not_received_ones():
    from aegis.ingest.base import AlertCheckpoint
    from aegis.ingest.stream import StreamConsumer, StreamQueue
    q = StreamQueue(100)
    q.put_many("alerts", ["not json at all", json.dumps({"id": "ok-1"})], passthrough=True)
    list(StreamConsumer(queue=q, checkpoint=AlertCheckpoint()).iter_alerts())
    assert q.stats.by_source["alerts"] == 2 and q.stats.parsed_by_source["alerts"] == 1


def test_idle_feed_names_make_room():
    from aegis.ingest.watchdog import FeedWatchdog
    t = [1_000_000.0]
    wd = FeedWatchdog(clock=lambda: t[0])
    for i in range(256):
        wd.record(f"junk-{i}")
    t[0] += 2 * 86400
    wd.record("real-feed")
    assert "real-feed" in wd._count


# ---- R3-13: RFC 5424 structured data ----------------------------------------------------------------------------------------

def test_rfc5424_with_structured_data_is_network_syslog():
    from aegis.ingest.stream import _SYSLOG_HEAD
    line = '<189>1 2026-11-03T10:00:00Z core-sw01 - - - [meta sequenceId="1"] %LINK-3-UPDOWN: Interface Gi1/0/1, down'
    assert _SYSLOG_HEAD.search(line)
    assert not _SYSLOG_HEAD.search('GET /x/%SYS-5-CONFIG_I: HTTP/1.1')


# ---- S3-20: the ownership resolver ---------------------------------------------------------------------------------------

def test_ownership_resolver_circuit_breaks():
    from aegis.agents.api_abuse.ownership import HttpOwnership
    calls = []

    def down(url, headers, timeout):
        calls.append(url)
        raise TimeoutError("resolver down")
    o = HttpOwnership("https://own.example/owners", fetch=down)
    for i in range(20):
        assert o.owners_of("account", str(i)) is None
    assert len(calls) == 3 and o.skipped == 17


# ---- S3-22 / S3-23: odd field types --------------------------------------------------------------------------------------

def test_one_tool_crashing_keeps_the_others():
    from aegis.agents.transaction import tools
    alert = {"user_id": "u_42891", "rail": "upi", "amount_inr": "250000", "beneficiary_account": ["x", None],
             "velocity": {"bad": object()}}
    res = tools.run_all_tools(alert)
    assert len(res) >= 5
    rail = next(r for r in res if r.name == "payment_rail")
    assert rail.data["novel_rail"] is False                           # "upi" is the user's UPI


def test_string_false_is_false():
    from aegis.agents.mobile.tools import jailbreak_root_check
    assert jailbreak_root_check({"is_jailbroken": "false", "is_rooted": "0"}).weight == "low"


def test_dict_payload_is_scanned_not_escalated():
    from aegis.agents.perimeter import tools
    res = tools.run_all_tools(json.dumps({"q": "' OR 1=1--"}), "203.0.113.9", None, alert={})
    assert next(r for r in res if r.name == "decode_payload").data["primitives"]["sqli"]


# ---- S3-24 / O3-19: addresses ----------------------------------------------------------------------------------------------

def test_mapped_ipv6_source_is_internal():
    from aegis.agents.ndr.egress import EgressDetector
    d = EgressDetector.from_env()
    assert d._is_internal("::ffff:10.1.2.3") is True


@pytest.mark.parametrize("ip,public", [("172.2.3.4", True), ("172.200.1.1", True), ("172.20.1.1", False),
                                       ("100.64.0.9", False), ("169.254.169.254", False), ("8.26.56.26", True)])
def test_swarm_looks_up_only_public_addresses(ip, public):
    from aegis.agents.orchestrator.swarm import _public_ip
    assert _public_ip(ip) is public


# ---- S3-25: EDR normaliser and MTD -----------------------------------------------------------------------------------------

def test_edr_records_become_host_alerts():
    from aegis.agents.edr.normalize import to_alert
    a = to_alert({"name": "pack_aegis-host_exec_lolbin_events", "hostIdentifier": "srv-2",
                  "columns": {"parent": "412", "parent_name": "w3wp.exe", "path": "C:\\Windows\\System32\\cmd.exe",
                              "cmdline": "cmd /c whoami"}})       # a row a scorer fires on (round 4 S4-8 pre-filter)
    assert a["parent_process"] == "w3wp.exe" and a["parent_pid"] == "412" and a["id"].startswith("edr-")
    assert to_alert({"unrelated": 1}) is None


def test_beacon_aggregator_is_bounded():
    from aegis.agents.edr.normalize import BeaconAggregator
    agg = BeaconAggregator(max_pairs=10, max_points=5)
    for i in range(100):
        agg.add(f"h{i}", "1.2.3.4", float(i))
        agg.add("h0", "9.9.9.9", float(i))
    assert len(agg._log) <= 10 and len(agg._log[("h0", "9.9.9.9")]) == 5


def test_mtd_rate_cap_is_a_sliding_minute_and_sessions_are_safe():
    from aegis.mtd.policy import Asset, MTDController, RotationAction
    t = [0.0]
    ctl = MTDController(policy=lambda obs, st: [RotationAction(a, {"port": 1}, "r") for a in st.assets],
                        clock=lambda: t[0])
    for i in range(10):
        ctl.register(Asset(id=f"a{i}", kind="port", current_coords={}))
    ctl.register(Asset(id="busy", kind="port", current_coords={}, active_sessions=3))
    assert len(ctl.step({})) == 8                                      # the cap
    assert ctl.step({}) == []                                          # same minute
    t[0] += 61
    out = ctl.step({})
    assert out and all(a.asset_id != "busy" for a in out)             # a new minute; never the busy asset


# ---- O3-20: span attributes reach OTel -----------------------------------------------------------------------------------

def test_attributes_set_inside_a_span_reach_otel(monkeypatch):
    from aegis.agents.shared import observability as obs
    seen = {}

    class Span:
        def set_attribute(self, k, v):
            seen[k] = v

    class Tracer:
        def start_as_current_span(self, name):
            import contextlib
            return contextlib.nullcontext(Span())
    monkeypatch.setattr(obs, "_OTEL_TRACER", Tracer())
    with obs.span("x", alert_id="A1") as rec:
        rec.attributes["verdict"] = "malicious"
    assert seen == {"alert_id": "A1", "verdict": "malicious"}


# ---- I3-18: the edge -------------------------------------------------------------------------------------------------------

def test_edge_sender_is_one_bounded_thread():
    import importlib.util
    import sys
    from pathlib import Path
    p = Path(__file__).resolve().parents[2] / "scripts" / "demo_target.py"
    spec = importlib.util.spec_from_file_location("demo_target_t", p)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["demo_target_t"] = mod
    spec.loader.exec_module(mod)
    s = mod._AlertSender(cap=3)
    s._thread = types.SimpleNamespace(is_alive=lambda: True)          # keep it from sending in the test
    for i in range(10):
        s.submit("http://127.0.0.1:9/x", b"{}", {})
    assert len(s._hi) + len(s._lo) == 3 and s.dropped == 7
