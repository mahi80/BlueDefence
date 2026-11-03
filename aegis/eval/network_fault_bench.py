"""Network fault bench — a simulated campus/WAN under injected faults, judged by the real pipeline.

~50 devices: two cores, four distribution switches (three dual-homed, one single-homed), forty access
switches with users behind them, two WAN edges. Three hours of simulated time: interface telemetry
every 60 s from every device, LLDP, the ordinary edge-port churn of users plugging and unplugging,
and an occasional ticketed change. Into that, the faults a NOC actually sees:

    fibre_cut            the single-homed distribution uplink goes dark: 10 access switches lose the
                         core, each reports its uplink down and its OSPF adjacency lost, telemetry stops
                         → ONE alert, the uplink, critical, 10 downstream / ~1,000 users, the rest folded in
    redundant_cut        a dual-homed distribution switch loses one uplink → one medium alert, redundant
                         path noted, nothing stranded, no access-layer alarms at all
    flapping_link        an access uplink flaps 8 times in four minutes → one link_flap with a port-shut
                         proposal, not eight link_down alerts
    bad_config_push      a distribution switch is reconfigured with no ticket; 90 s later its BGP
                         session drops → bad_config_push (malicious) with config_rollback + revoke sessions
    ticketed_change      the same shape under ticket CHG-44102 → adjacency_loss (suspicious) and a benign
                         ticketed drift — never malicious, never a rollback
    congestion           a WAN uplink sits at 94–97% for five samples → congestion
    interface_errors     a trunk port's CRC counter climbs 600/min → interface_errors, before it flaps
    silent_device        an access switch stops sending telemetry → device_unreachable

Scored on what a Cisco network-assurance product is judged on: root-cause accuracy (right fault, right
device, right port), alarm reduction (raw alarms in : alerts out), time to detect, and — above all —
zero alerts on healthy devices and zero remediation proposed where nothing is wrong.

    python -m aegis.eval.network_fault_bench [--gate] [--json out.json] [--verbose]
"""

from __future__ import annotations

import argparse
import io
import json
import random
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

T0 = datetime(2026, 10, 29, 6, 0, 0, tzinfo=UTC)
MINUTES = 180
TELEMETRY_S = 60.0

CORES = ["CORE-01", "CORE-02"]
DISTS = ["DIST-01", "DIST-02", "DIST-03", "DIST-04"]
SINGLE_HOMED = "DIST-03"
WANS = ["WAN-01", "WAN-02"]
ACCESS_PER_DIST = 10
USERS_PER_ACCESS = (60, 140)

# the faults and where they land (device, iface) — the bench's expected root causes
FAULTS: dict[str, dict] = {
    "fibre_cut":        {"device": "DIST-03", "iface": "Ethernet1/49", "fault": "link_down", "at": 40 * 60, "min_downstream": 10, "min_reduction": 10.0},
    "redundant_cut":    {"device": "DIST-01", "iface": "Ethernet1/49", "fault": "link_down", "at": 70 * 60, "max_downstream": 0, "redundant": True},
    "flapping_link":    {"device": "ACC-17", "iface": "GigabitEthernet1/0/49", "fault": "link_flap", "at": 90 * 60},
    "bad_config_push":  {"device": "DIST-02", "iface": None, "fault": "bad_config_push", "at": 110 * 60, "verdict": "malicious", "actions": {"config_rollback", "revoke_sessions"}},
    "ticketed_change":  {"device": "DIST-04", "iface": None, "fault": "adjacency_loss", "at": 125 * 60, "not_verdict": "malicious", "not_actions": {"config_rollback"}},
    "congestion":       {"device": "WAN-01", "iface": "GigabitEthernet0/0/1", "fault": "congestion", "at": 140 * 60},
    "interface_errors": {"device": "ACC-33", "iface": "GigabitEthernet1/0/49", "fault": "interface_errors", "at": 150 * 60},
    "silent_device":    {"device": "ACC-40", "iface": None, "fault": "device_unreachable", "at": 160 * 60},
}
DETECT_WITHIN_S = {"link_down": 60, "link_flap": 300, "bad_config_push": 120, "adjacency_loss": 60, "congestion": 6 * TELEMETRY_S,
                   "interface_errors": 4 * TELEMETRY_S, "device_unreachable": 240 + TELEMETRY_S}


@dataclass
class Topology:
    links: list[tuple[str, str, str, str]]          # (device, iface, neighbor, neighbor_iface)
    users: dict[str, int]
    roles: dict[str, str]
    uplink: dict[str, tuple[str, str]]              # access/dist -> (its uplink iface, upstream device)

    @property
    def devices(self) -> list[str]:
        return sorted({d for d, _, _, _ in self.links} | {n for _, _, n, _ in self.links})


def build_topology(seed: int = 7) -> Topology:
    rng = random.Random(seed)
    links: list[tuple[str, str, str, str]] = [("CORE-01", "Ethernet1/1", "CORE-02", "Ethernet1/1")]
    users: dict[str, int] = {}
    roles = {c: "core" for c in CORES}
    uplink: dict[str, tuple[str, str]] = {}
    for i, d in enumerate(DISTS):
        roles[d] = "distribution"
        links.append((d, "Ethernet1/49", "CORE-01", f"Ethernet1/{2 + i}"))
        uplink[d] = ("Ethernet1/49", "CORE-01")
        if d != SINGLE_HOMED:
            links.append((d, "Ethernet1/50", "CORE-02", f"Ethernet1/{2 + i}"))
    n = 0
    for di, d in enumerate(DISTS):
        for j in range(ACCESS_PER_DIST):
            n += 1
            a = f"ACC-{n:02d}"
            roles[a] = "access"
            links.append((a, "GigabitEthernet1/0/49", d, f"Ethernet1/{5 + j}"))
            uplink[a] = ("GigabitEthernet1/0/49", d)
            users[a] = rng.randint(*USERS_PER_ACCESS)
    for i, w in enumerate(WANS):
        roles[w] = "wan-edge"
        links.append((w, "GigabitEthernet0/0/1", CORES[i], f"Ethernet1/{20 + i}"))
        uplink[w] = ("GigabitEthernet0/0/1", CORES[i])
    return Topology(links=links, users=users, roles=roles, uplink=uplink)


# ------------------------------------------------------------- the record stream --

def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).isoformat().replace("+00:00", "Z")


def _syslog(ts: float, device: str, text: str) -> str:
    """A Cisco IOS-XE style line as a syslog relay would forward it."""
    stamp = datetime.fromtimestamp(ts, UTC).strftime("%b %d %Y %H:%M:%S")
    return f"<189>{device}: *{stamp}: {text}"


def _telemetry(ts: float, device: str, iface: str, *, in_oct: float, out_oct: float, speed_mbps: int, in_err: float = 0.0,
               crc: float = 0.0, out_disc: float = 0.0, oper: str = "up") -> str:
    return json.dumps({"ts": _iso(ts), "device": device, "interface": iface, "ifHighSpeed": speed_mbps, "in_octets": int(in_oct),
                       "out_octets": int(out_oct), "in_errors": int(in_err), "crc": int(crc), "out_discards": int(out_disc), "oper_status": oper})


@dataclass
class Injected:
    name: str
    raw_alarms: int = 0                 # vendor alarms the fault produced (syslog + traps), for the reduction ratio


def build_records(topo: Topology, seed: int = 7) -> tuple[list[tuple[float, str]], dict[str, Injected]]:
    rng = random.Random(seed)
    now = T0.timestamp()
    end = now + MINUTES * 60
    out: list[tuple[float, str]] = []
    inj = {k: Injected(k) for k in FAULTS}

    # LLDP: every link, both directions, at start
    for d, di, n, ni in topo.links:
        out.append((now, json.dumps({"device": d, "neighbor": n, "local_iface": di, "neighbor_iface": ni, "role": topo.roles[d],
                                     "neighbor_role": topo.roles[n], "users": topo.users.get(d, 0), "ts": _iso(now)})))
        out.append((now, json.dumps({"device": n, "neighbor": d, "local_iface": ni, "neighbor_iface": di, "role": topo.roles[n],
                                     "neighbor_role": topo.roles[d], "users": topo.users.get(n, 0), "ts": _iso(now)})))

    # golden configs seen at start (first-seen golden)
    for d in topo.devices:
        out.append((now + 1, json.dumps({"device": d, "config_hash": f"golden-{d}", "ts": _iso(now + 1)})))

    # background telemetry on every uplink, counters that climb like a normal day
    octets: dict[tuple[str, str], tuple[float, float]] = {}
    for d in topo.devices:
        iface = topo.uplink.get(d, ("Ethernet1/1", ""))[0]
        octets[(d, iface)] = (rng.uniform(1e12, 2e12), rng.uniform(1e12, 2e12))

    fibre = FAULTS["fibre_cut"]["at"]
    silent_at = FAULTS["silent_device"]["at"]
    stranded = {a for a, (_, up) in topo.uplink.items() if up == SINGLE_HOMED}
    t = now
    while t < end:
        rel = t - now
        for d in topo.devices:
            if d == "ACC-40" and rel >= silent_at:
                continue                                    # the silent device
            if (d in stranded or d == SINGLE_HOMED) and rel >= fibre:
                continue                                    # behind the cut: unreachable, no telemetry
            iface = topo.uplink.get(d, ("Ethernet1/1", ""))[0]
            speed = 10_000 if topo.roles[d] in ("core", "distribution") else 1_000
            i_o, o_o = octets[(d, iface)]
            util = rng.uniform(0.08, 0.35)
            if d == "WAN-01" and FAULTS["congestion"]["at"] <= rel < FAULTS["congestion"]["at"] + 6 * TELEMETRY_S:
                util = rng.uniform(0.94, 0.97)             # the congestion window
            i_o += util * speed * 1e6 / 8 * TELEMETRY_S * 0.55
            o_o += util * speed * 1e6 / 8 * TELEMETRY_S * 0.45
            octets[(d, iface)] = (i_o, o_o)
            crc = 0.0
            if d == "ACC-33" and rel >= FAULTS["interface_errors"]["at"]:
                crc = 600.0 * ((rel - FAULTS["interface_errors"]["at"]) / TELEMETRY_S + 1)   # 600/min, climbing
            disc = rng.uniform(2_000, 8_000) if (d == "WAN-01" and util > 0.9) else 0.0
            out.append((t, _telemetry(t, d, iface, in_oct=i_o, out_oct=o_o, speed_mbps=speed, crc=crc, out_disc=disc)))
        t += TELEMETRY_S

    # edge-port churn: users plugging and unplugging on access switches all day (must stay silent)
    access = [d for d, r in topo.roles.items() if r == "access"]
    for _ in range(400):
        d = rng.choice(access)
        port = f"GigabitEthernet1/0/{rng.randint(1, 48)}"
        at = now + rng.uniform(0, MINUTES * 60)
        if (d in stranded and at - now >= fibre) or (d == "ACC-40" and at - now >= silent_at):
            continue                                    # a switch with no path to the collector sends nothing
        out.append((at, _syslog(at, d, f"%LINK-3-UPDOWN: Interface {port}, changed state to down")))
        out.append((at + rng.uniform(5, 120), _syslog(at, d, f"%LINEPROTO-5-UPDOWN: Line protocol on Interface {port}, changed state to up")))

    # ---- fibre cut: DIST-03 uplink, 10 access switches behind it
    f = now + fibre
    out.append((f, _syslog(f, "DIST-03", "%ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/49 is down (Link failure)")))
    out.append((f + 0.2, _syslog(f, "CORE-01", "%LINK-3-UPDOWN: Interface Ethernet1/4, changed state to down")))
    inj["fibre_cut"].raw_alarms += 2
    for k, a in enumerate(sorted(stranded)):
        dt = f + 1 + k * 0.7
        out.append((dt, _syslog(dt, a, "%LINK-3-UPDOWN: Interface GigabitEthernet1/0/49, changed state to down")))
        out.append((dt + 0.3, _syslog(dt, a, "%LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet1/0/49, changed state to down")))
        out.append((dt + 35, _syslog(dt, a, "%OSPF-5-ADJCHG: Process 1, Nbr 10.3.0.1 on GigabitEthernet1/0/49 from FULL to DOWN, Neighbor Down: Dead timer expired")))
        out.append((dt + 2, json.dumps({"trap": "IF-MIB::linkDown", "host": a, "varbinds": {"ifDescr": "Gi1/0/49"}, "ts": _iso(dt + 2)})))
        inj["fibre_cut"].raw_alarms += 4
    out.append((f + 40, _syslog(f, "DIST-03", "%OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.1 on Ethernet1/49 from FULL to DOWN, Neighbor Down: Dead timer expired")))
    inj["fibre_cut"].raw_alarms += 1

    # ---- redundant cut: DIST-01 loses CORE-01 uplink, CORE-02 carries it
    r = now + FAULTS["redundant_cut"]["at"]
    out.append((r, _syslog(r, "DIST-01", "%ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/49 is down (Link failure)")))
    out.append((r + 0.2, _syslog(r, "CORE-01", "%LINK-3-UPDOWN: Interface Ethernet1/2, changed state to down")))
    inj["redundant_cut"].raw_alarms += 2

    # ---- flapping link: ACC-17 uplink, 8 transitions in 4 min
    fl = now + FAULTS["flapping_link"]["at"]
    for k in range(8):
        st = "down" if k % 2 == 0 else "up"
        dt = fl + k * 30
        out.append((dt, _syslog(dt, "ACC-17", f"%LINK-3-UPDOWN: Interface GigabitEthernet1/0/49, changed state to {st}")))
        inj["flapping_link"].raw_alarms += 1

    # ---- bad config push: DIST-02, no ticket, then BGP drops
    b = now + FAULTS["bad_config_push"]["at"]
    out.append((b, json.dumps({"kind": "config_change", "device": "DIST-02", "config_hash": "changed-DIST-02", "user": "jdoe",
                               "source_ip": "10.20.0.77", "ts": _iso(b)})))
    out.append((b + 90, _syslog(b + 90, "DIST-02", "%BGP-5-ADJCHANGE: neighbor 10.0.0.1 Down BGP Notification sent")))
    inj["bad_config_push"].raw_alarms += 2

    # ---- ticketed change: DIST-04 under CHG-44102, then BGP drops (planned maintenance)
    c = now + FAULTS["ticketed_change"]["at"]
    out.append((c, json.dumps({"kind": "config_change", "device": "DIST-04", "config_hash": "changed-DIST-04", "user": "netops-svc",
                               "change_ticket": "CHG-44102", "ts": _iso(c)})))
    out.append((c + 60, _syslog(c + 60, "DIST-04", "%BGP-5-ADJCHANGE: neighbor 10.0.0.1 Down BGP Notification sent")))
    inj["ticketed_change"].raw_alarms += 2

    inj["congestion"].raw_alarms += 6
    inj["interface_errors"].raw_alarms += 4
    inj["silent_device"].raw_alarms += 1
    out.sort(key=lambda x: x[0])
    return out, inj


# -------------------------------------------------------------------- run --

@dataclass
class FaultResult:
    name: str
    expected: dict
    alerts: list[dict] = field(default_factory=list)
    chains: list[dict] = field(default_factory=list)
    detected_at_s: float | None = None
    root_cause_ok: bool = False
    verdict_ok: bool = True
    actions_ok: bool = True
    downstream_ok: bool = True
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"name": self.name, "expected": {k: v for k, v in self.expected.items() if k != "actions" and k != "not_actions"},
                "alerts": len(self.alerts), "detected_at_s": self.detected_at_s, "root_cause_ok": self.root_cause_ok,
                "verdict_ok": self.verdict_ok, "actions_ok": self.actions_ok, "downstream_ok": self.downstream_ok,
                "reasons": self.reasons, "first": self.chains[0] if self.chains else None}


def _env(td: Path) -> dict[str, Any]:
    from .purple_team.harness import model_env
    env: dict[str, Any] = {
        "AEGIS_EDITION": "external", "ACP_DASHBOARD_URL": None, "ACP_API_KEY": None, "ACP_GOVERN": None,
        "AEGIS_PERSIST": None, "AEGIS_RULE_FEED": None, "AEGIS_HITL_TRANSPORT": "file", "AEGIS_SWARM": "0",
        "AEGIS_INVESTIGATE": "0", "AEGIS_TWIN": "0", "AEGIS_CAMPAIGN_CONTEXT": "0", "AEGIS_CVE_INTEL": "0",
        "AEGIS_INTEL_MOCK": "1", "AEGIS_PII_TOKENIZATION": "0", "AEGIS_DATASET_CAPTURE": "0",
        "AEGIS_ENFORCEMENT_MODE": "shadow", "AEGIS_AUTO_BLOCK": "shadow", "AEGIS_OUTFLOW_BREAKER": "off",
        "AEGIS_WAF_VENDOR": "mock", "AEGIS_SOAR_VENDOR": "mock", "AEGIS_INGEST_HTTP": None, "AEGIS_INGEST_BIND": None,
        "AEGIS_METRICS_BIND": None, "AEGIS_HITL_DIR": str(td / "hitl"), "AEGIS_HITL_STATE": str(td / "hitl" / "pending.jsonl"),
        "AEGIS_TI_CACHE": str(td), "AEGIS_RECEIPTS_DIR": str(td), "AEGIS_CHECKPOINT": str(td / "ingest.json"), "ACP_HOME": str(td / "acp"),
        "AEGIS_NET_GOLDEN": None, "AEGIS_NET_GOLDEN_FIRST_SEEN": "1", "AEGIS_NET_INVENTORY": None,
        "AEGIS_NET_FLAP_N": None, "AEGIS_NET_FLAP_WINDOW_S": None, "AEGIS_NET_CORR_WINDOW_S": None, "AEGIS_NET_ERR_PER_MIN": None,
        "AEGIS_NET_UTIL_PCT": None, "AEGIS_NET_UTIL_SAMPLES": None, "AEGIS_NET_SILENT_S": None, "AEGIS_NET_BAD_PUSH_S": None,
    }
    env.update(model_env() or {"LLM_BACKEND": "mock"})
    return env


def run(seed: int = 7, *, verbose: bool = False) -> dict:
    from ..ingest import netops as netops_mod
    from ..ingest.base import CONSUMED, AlertCheckpoint
    from ..ingest.netops import NetopsConsumer
    from .fault_injection import _env as env_ctx

    topo = build_topology(seed)
    records, injected = build_records(topo, seed)
    now = T0.timestamp()
    results = {k: FaultResult(k, v) for k, v in FAULTS.items()}
    healthy_alerts: list[dict] = []
    wrong_remediation: list[str] = []
    fault_devices = {v["device"] for v in FAULTS.values()}
    stranded = {a for a, (_, up) in topo.uplink.items() if up == SINGLE_HOMED}

    with tempfile.TemporaryDirectory() as tds:
        td = Path(tds)
        with env_ctx(_env(td)):
            from ..service import build_pipeline
            netops_mod.reset_shared_detector()
            p = build_pipeline(td / "audit.jsonl", fresh=True)
            p.response._hitl_stream = io.StringIO()
            consumer = NetopsConsumer(detector=netops_mod.shared_detector(), checkpoint=AlertCheckpoint())
            det = netops_mod.shared_detector()
            for ts, line in records:
                rec: Any = line
                if line[:1] in "{[":
                    rec = json.loads(line)
                got = consumer.normalize(rec)
                if got is CONSUMED or not got:
                    continue
                for alert in got:
                    chain = p.orch.handle(alert)
                    p.response.execute(chain, alert)
                    n = alert["netops"]
                    rel = ts - now
                    row = {"at_s": round(rel), "fault": n["fault"], "device": alert["device"], "iface": alert.get("iface"),
                           "verdict": chain.verdict, "confidence": round(float(chain.confidence), 2),
                           "downstream": n.get("downstream_count", 0), "users": n.get("users_affected", 0),
                           "redundant": n.get("redundant"), "actions": [a.action_type for a in chain.recommended_actions]}
                    if verbose:
                        print(f"  {rel / 60:6.1f} min  {row['fault']:18s} {row['device']:8s} {str(row['iface'] or ''):24s} "
                              f"→ {row['verdict']} {row['confidence']:.2f}  downstream={row['downstream']} actions={row['actions']}")
                    # attribute to a fault by device (+ time), else it is an alert on a healthy device
                    owner = next((k for k, v in FAULTS.items() if v["device"] == alert["device"] and rel >= v["at"] - 5), None)
                    if owner is None:
                        healthy_alerts.append(row)
                    else:
                        results[owner].alerts.append(alert)
                        results[owner].chains.append(row)
                    for a in chain.recommended_actions:
                        if a.action_type in ("config_rollback", "interface_shutdown") and str(a.target).split(":")[0] not in fault_devices:
                            wrong_remediation.append(f"{a.action_type} -> {a.target} ({row['fault']} on {row['device']})")
            incidents = det.incidents()
            stats = dict(det.stats)

    # ---- judge each fault
    for k, r in results.items():
        e = r.expected
        want_fault = e["fault"]
        hit = next((c for c in r.chains if c["fault"] == want_fault), None)
        if hit is None:
            r.reasons.append(f"no {want_fault} alert (got {[c['fault'] for c in r.chains] or 'nothing'})")
            r.root_cause_ok = False
        else:
            r.detected_at_s = hit["at_s"] - e["at"]
            iface_ok = e["iface"] is None or hit["iface"] == e["iface"]
            r.root_cause_ok = hit["device"] == e["device"] and iface_ok
            if not r.root_cause_ok:
                r.reasons.append(f"root cause {hit['device']} {hit['iface']} != {e['device']} {e['iface']}")
            limit = DETECT_WITHIN_S.get(want_fault, 120)
            if r.detected_at_s > limit:
                r.reasons.append(f"detected {r.detected_at_s:.0f} s after the fault (limit {limit} s)")
            if "min_downstream" in e and hit["downstream"] < e["min_downstream"]:
                r.downstream_ok = False
                r.reasons.append(f"downstream {hit['downstream']} < {e['min_downstream']}")
            if "max_downstream" in e and hit["downstream"] > e["max_downstream"]:
                r.downstream_ok = False
                r.reasons.append(f"downstream {hit['downstream']} > {e['max_downstream']} (redundant path missed)")
            if e.get("redundant") and not hit["redundant"]:
                r.downstream_ok = False
                r.reasons.append("redundant path not recognised")
            if "verdict" in e and hit["verdict"] != e["verdict"]:
                r.verdict_ok = False
                r.reasons.append(f"verdict {hit['verdict']} != {e['verdict']}")
            if "actions" in e and not e["actions"] <= set(hit["actions"]):
                r.actions_ok = False
                r.reasons.append(f"actions {hit['actions']} lack {sorted(e['actions'] - set(hit['actions']))}")
        if "not_verdict" in e and any(c["verdict"] == e["not_verdict"] for c in r.chains):
            r.verdict_ok = False
            r.reasons.append(f"a {e['not_verdict']} verdict on a ticketed change")
        if "not_actions" in e and any(set(c["actions"]) & e["not_actions"] for c in r.chains):
            r.actions_ok = False
            r.reasons.append(f"{sorted(e['not_actions'])} proposed on a ticketed change")
        if want_fault in ("link_down", "link_flap") and len([c for c in r.chains if c["fault"] == want_fault]) > 1:
            r.reasons.append(f"{len(r.chains)} alerts for one fault — not correlated into one")

    fibre = results["fibre_cut"]
    fibre_inc = next((i for i in incidents if i["device"] == "DIST-03" and i["fault"] == "link_down"), None)
    raw = injected["fibre_cut"].raw_alarms + len(stranded)                 # + the silent-device checks the cut also triggers
    reduction = raw / max(1, len(fibre.chains))
    if fibre_inc is None or reduction < FAULTS["fibre_cut"]["min_reduction"]:
        fibre.reasons.append(f"alarm reduction {reduction:.1f}x < {FAULTS['fibre_cut']['min_reduction']}x")

    from .purple_team.harness import model_label
    return {
        "bench": "network_fault_bench", "judge": model_label(), "devices": len(topo.devices), "minutes": MINUTES, "records": len(records),
        "faults": {k: r.to_dict() for k, r in results.items()},
        "fibre_cut_alarms_in": raw, "fibre_cut_alerts_out": len(fibre.chains), "alarm_reduction": round(reduction, 1),
        "fibre_cut_suppressed": fibre_inc["suppressed"] if fibre_inc else 0,
        "healthy_device_alerts": healthy_alerts, "wrong_remediations": wrong_remediation, "detector_stats": stats,
        "pass": all(r.root_cause_ok and r.verdict_ok and r.actions_ok and r.downstream_ok and not r.reasons for r in results.values())
                and not healthy_alerts and not wrong_remediation,
    }


def render(rep: dict) -> str:
    L = [f"=== Network fault bench: {rep['devices']} devices, {rep['minutes']} min, {rep['records']:,} records — judge: {rep['judge']} ===",
         f"  {'fault':18s} {'root cause':34s} {'detect':>8s}  {'verdict':10s} {'downstream':>10s}  {'actions':40s} result"]
    for k, r in rep["faults"].items():
        f = r["first"] or {}
        rc = f"{f.get('device', '—')} {f.get('iface') or ''}".strip()
        det = f"{r['detected_at_s']:.0f} s" if r["detected_at_s"] is not None else "—"
        ok = r["root_cause_ok"] and r["verdict_ok"] and r["actions_ok"] and r["downstream_ok"] and not r["reasons"]
        L.append(f"  {k:18s} {rc:34s} {det:>8s}  {f.get('verdict', '—'):10s} {str(f.get('downstream', '—')):>10s}  "
                 f"{', '.join(f.get('actions', []))[:40]:40s} {'PASS' if ok else 'FAIL: ' + '; '.join(r['reasons'])}")
    L.append(f"  fibre cut: {rep['fibre_cut_alarms_in']} vendor alarms in → {rep['fibre_cut_alerts_out']} alert out "
             f"({rep['alarm_reduction']}x reduction, {rep['fibre_cut_suppressed']} folded in as symptoms)")
    L.append(f"  alerts on healthy devices: {len(rep['healthy_device_alerts'])} · remediation proposed where nothing is wrong: {len(rep['wrong_remediations'])}")
    for h in rep["healthy_device_alerts"][:5]:
        L.append(f"    ! healthy: {h}")
    for w in rep["wrong_remediations"][:5]:
        L.append(f"    ! wrong remediation: {w}")
    L.append(f"  gate: {'PASS' if rep['pass'] else 'FAIL'}")
    return "\n".join(L)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", default="")
    ap.add_argument("--gate", action="store_true", help="exit 1 unless every fault is caught at its root cause with no false alarms")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args(argv)
    rep = run(args.seed, verbose=args.verbose)
    print(render(rep))
    if args.json:
        Path(args.json).write_text(json.dumps(rep, indent=1, default=str))
    return 0 if (rep["pass"] or not args.gate) else 1


if __name__ == "__main__":
    raise SystemExit(main())
