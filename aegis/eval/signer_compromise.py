"""Signer-compromise kill chain vs the real AEGIS pipeline — would it have stopped a Binance-style drain?

On 29 Oct 2026 attackers drained ~USD 6.3B from Binance hot wallets in about 20 minutes. Every outflow
was signed by Binance's own signing service: per Binance, a compromised DevOps engineer's laptop gave
access to the container that submits withdrawals; the attacker then granted itself a persistent
permission (an EIP-7702 delegation) and swept the wallets. Staging was visible ~36 h before the drain.

This replays that pattern **translated to a bank** — the payment signer that submits SWIFT / RTGS
transfers stands in for the exchange's withdrawal signer — and drives every stage through the real
pipeline as the alert its real feed would produce:

    0  staging            T-36 h    attacker infrastructure (on-chain / attacker-side)   not observable
    1  endpoint           T-24 h    DevOps laptop: credential-store read, then EDR tamper  CrowdStrike alert
    2  c2                 T-24 h +  the laptop beacons out                                 Zeek records -> the REAL NDR detector
    3  privileged_access  T-2 h     DevOps identity execs into the payment-signer pod      Kubernetes audit event
    4  persistence        T-15 min  signer policy changed (allowlist widened, limit raised) payment-signer audit event
    5  drain              T0..+20 m 12 high-value SWIFT transfers to new beneficiaries     core-banking txn stream

Then a containment model, for each analyst approval latency: an action that cuts the attacker's path
stops the attack from the moment it executes — before T0 the drain never happens, during the drain the
remaining transfers stop. Auto-run actions execute at once; human-gated ones after the latency. Laptop /
C2 actions only count before stage 3 (once the attacker sits in the signer, isolating the laptop no
longer cuts the path); identity, signer and payment actions count at any time. ``escalate`` alone cuts
nothing. These rules are a model of the chain, stated so a reader can disagree with them.

The triage judge is whatever the caller's environment selects (``LLM_BACKEND`` …); with none it is the
deterministic mock, so this measures the deterministic layer — say so when quoting the numbers.

    python -m aegis.eval.signer_compromise [--json out.json] [--latencies 300,3600,28800]
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

from .egress_bench import AGENT_SVC_JA4, BROWSER_JA4, IMPLANT_JA4, Actor, World, _records

T0 = datetime(2026, 10, 29, 20, 5, 0, tzinfo=UTC)        # drain start (the Binance outflows began ~20:05 UTC)
H = 3600.0

LAPTOP_HOST, LAPTOP_IP, DEVOPS_USER = "DEVOPS-LT-07", "10.20.0.77", "u_devops_12"
C2_SNI, C2_IP = "telemetry-cdn.update-relay.example", "203.0.113.91"
SIGNER_POD, TREASURY = "payments/withdrawal-signer-0", "ACC-TREASURY-NOSTRO-01"
DRAIN_N, DRAIN_GAP_S = 12, 100.0
DRAIN_AMOUNTS_INR = [4.2e9, 3.8e9, 5.1e9, 4.7e9, 3.3e9, 6.0e9, 4.4e9, 5.5e9, 3.9e9, 4.8e9, 5.2e9, 4.1e9]

_RANK = {"benign": 0, "uncertain": 1, "suspicious": 2, "malicious": 3}
_ACCESS_ACTIONS = {"isolate", "block_egress", "kill_process", "quarantine_file"}
_IDENTITY_ACTIONS = {"lock_account", "revoke_sessions", "force_logout", "rotate_credential"}
_PAYMENT_ACTIONS = {"hold", "block", "block_export"}


@dataclass
class StageResult:
    stage: str
    t_s: float                          # seconds relative to T0 (negative = before the drain)
    observable: bool = True
    alerts: int = 0
    first_alert_t_s: float | None = None
    verdict: str = ""
    confidence: float = 0.0
    by: str = ""
    actions: list[dict] = field(default_factory=list)       # type, target, hitl, executed, breaks, scope
    note: str = ""

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in ("stage", "t_s", "observable", "alerts", "first_alert_t_s", "verdict",
                                              "confidence", "by", "actions", "note")}


def _scope(action_type: str, target: str) -> str | None:
    """Which part of the attacker's path an action cuts — None if it cuts nothing."""
    t = str(target or "")
    if action_type in _ACCESS_ACTIONS and any(x in t for x in (LAPTOP_HOST, LAPTOP_IP, C2_SNI, C2_IP)):
        return "access"
    if action_type in _ACCESS_ACTIONS and ("withdrawal-signer" in t or "signer" in t.lower()):
        return "signer"
    if action_type in _IDENTITY_ACTIONS and DEVOPS_USER in t:
        return "identity"
    if action_type in _PAYMENT_ACTIONS:
        return "payment"
    return None


def _record(res: StageResult, chain: Any, summary: Any, t_s: float) -> None:
    res.alerts += 1
    if res.first_alert_t_s is None:
        res.first_alert_t_s = t_s
    if (_RANK.get(chain.verdict, 0), float(chain.confidence)) > (_RANK.get(res.verdict, -1), res.confidence):
        res.verdict, res.confidence, res.by = chain.verdict, round(float(chain.confidence), 2), chain.investigated_by
    executed = {id(e.action) for e in summary.executed if e.status == "executed"}
    for a in chain.recommended_actions:
        sc = _scope(a.action_type, str(a.target))
        res.actions.append({"type": a.action_type, "target": str(a.target)[:60], "hitl": bool(a.requires_hitl),
                            "executed": id(a) in executed, "scope": sc, "t_s": t_s})


# ---------------------------------------------------------------- stage alerts --

def endpoint_alert() -> dict:
    return {"id": "SC-S1-EDR", "source": "CrowdStrike Falcon", "event": "tamper_protection_disabled", "host": LAPTOP_HOST,
            "user": DEVOPS_USER, "initiated_by": "local_admin", "sensor_offline_minutes": 0, "host_last_seen_minutes_ago": 1,
            "asset_in_inventory": True, "host_role": "laptop", "prior_event_30m": "credential_store_access",
            "os_patch_age_days": 41, "disk_encrypted": True}


def privileged_access_alert() -> dict:
    return {"id": "SC-S3-K8S", "source": "Kubernetes Audit", "severity": "high", "anomaly_score": 0.82,
            "user": DEVOPS_USER, "verb": "create", "resource": "pods/exec", "namespace": "payments",
            "name": SIGNER_POD.split("/")[1], "source_ip": LAPTOP_IP, "user_agent": "kubectl/v1.31.2",
            "first_seen_source_ip_for_user": True, "change_ticket": None, "outside_change_window": True,
            "summary": "interactive exec into the payment-signer pod from a laptop never used for production access"}


def persistence_alert() -> dict:
    return {"id": "SC-S4-SIGNER", "source": "Payment Signer (HSM audit)", "severity": "critical", "anomaly_score": 0.9,
            "event": "signing_policy_changed", "actor": "svc-withdrawal-signer", "initiated_from": SIGNER_POD,
            "change": "beneficiary allowlist +18 accounts; per-transfer limit raised from INR 50 crore to INR 1,000 crore",
            "change_ticket": None, "outside_change_window": True, "dual_control": False, "user": DEVOPS_USER}


def drain_alerts() -> list[tuple[float, dict]]:
    out, total = [], 0.0
    for i, amt in enumerate(DRAIN_AMOUNTS_INR):
        total += amt
        out.append((i * DRAIN_GAP_S, {
            "id": f"SC-S5-TXN-{i + 1:02d}", "source": "Core Banking (txn stream)", "severity": "critical",
            "anomaly_score": 0.93, "user_id": "svc_payments_signer", "rail": "SWIFT", "amount_inr": amt,
            "beneficiary_account": f"ACC-NEW-OFFSHORE-{i + 1:02d}", "sender_account": TREASURY, "sender_geo": "IN",
            "beneficiary_geo": "HK" if i % 2 else "AE", "new_beneficiary": True,
            "recent_24h_count": i + 1, "recent_24h_total_inr": total,
            "recent_amounts_inr": DRAIN_AMOUNTS_INR[max(0, i - 3): i + 1]}))
    return out


def c2_world(seed: int = 11) -> World:
    """A small office network — ordinary agent and browsing traffic — plus the DevOps laptop's implant."""
    rng = random.Random(seed)
    hosts = [f"10.20.0.{10 + i}" for i in range(12)] + [LAPTOP_IP]
    minutes = 60
    actors = [
        Actor("os_update", hosts, "update.os-vendor.example", "198.51.100.20", interval=900, jitter=0.05, in_bytes=(40_000, 90_000)),
        Actor("edr_telemetry", hosts, "telemetry.edr-vendor.example", "198.51.100.21", interval=60, jitter=0.03, ja4=AGENT_SVC_JA4),
        Actor("chat_presence", hosts, "presence.collab.example", "198.51.100.22", interval=30, jitter=0.10),
        Actor("devops_c2", [LAPTOP_IP], C2_SNI, C2_IP, interval=60, jitter=0.06, out_bytes=(600, 700), in_bytes=(250, 350),
              ja4=IMPLANT_JA4, threat="devops_c2", start=120,
              tls12_cert={"subject": f"CN={C2_SNI}", "issuer": f"CN={C2_SNI}", "age_days": 2, "validity_days": 3650,
                          "validation": "self signed certificate"}),
    ]
    sites = [f"site-{k}.example" for k in range(200)]
    for host in hosts:
        for _ in range(rng.randint(20, 40)):
            k = int(rng.paretovariate(1.2)) % len(sites)
            actors.append(Actor("browsing", [host], sites[k], f"192.0.2.{(k % 250) + 1}", once=True, ja4=BROWSER_JA4,
                                start=rng.uniform(0, minutes * 60.0), in_bytes=(20_000, 400_000)))
    w = World(hosts=hosts, minutes=minutes, actors=actors, gated={"devops_c2": "suspicious"}, deadline_min={"devops_c2": 30},
              reported=(), register_rows=[], ioc_rows=[])
    w.records = _records(w, rng, (T0.timestamp() - 24 * H), minutes * 60.0)
    return w


# ------------------------------------------------------------------- the run --

def _env(td: Path) -> dict[str, Any]:
    from .purple_team.harness import model_env
    env: dict[str, Any] = {
        "AEGIS_EDITION": "external", "ACP_DASHBOARD_URL": None, "ACP_API_KEY": None, "ACP_GOVERN": None,
        "AEGIS_PERSIST": None, "AEGIS_RULE_FEED": None, "AEGIS_HITL_TRANSPORT": "file",
        "AEGIS_SWARM": "1", "AEGIS_SWARM_MAX_SECONDS": "5", "AEGIS_INVESTIGATE": "0", "AEGIS_TWIN": "0",
        "AEGIS_CAMPAIGN_CONTEXT": "1", "AEGIS_CVE_INTEL": "0", "AEGIS_INTEL_MOCK": "1", "AEGIS_PII_TOKENIZATION": "0",
        "AEGIS_DATASET_CAPTURE": "0", "AEGIS_ENFORCEMENT_MODE": "shadow", "AEGIS_AUTO_BLOCK": "shadow",
        "AEGIS_WAF_VENDOR": "mock", "AEGIS_SOAR_VENDOR": "mock", "AEGIS_INGEST_HTTP": None, "AEGIS_INGEST_BIND": None,
        "AEGIS_METRICS_BIND": None, "AEGIS_TLS_IOC_FILE": None, "AEGIS_AI_REGISTER": None, "AEGIS_INTERNAL_NETS": None,
        "AEGIS_NDR_ALLOW_DOMAINS": None, "AEGIS_NDR_ALLOW_HOSTS": None,
        "AEGIS_HITL_DIR": str(td / "hitl"), "AEGIS_HITL_STATE": str(td / "hitl" / "pending.jsonl"),
        "AEGIS_TI_CACHE": str(td), "AEGIS_RECEIPTS_DIR": str(td), "AEGIS_CHECKPOINT": str(td / "ingest.json"),
        "AEGIS_SHADOW_AI_REGISTER": str(td / "shadow_ai.json"), "ACP_HOME": str(td / "acp"),
    }
    env.update(model_env() or {"LLM_BACKEND": "mock"})
    return env


def run(seed: int = 11) -> list[StageResult]:
    from ..agents.ndr.egress import EgressDetector
    from ..ingest.base import CONSUMED, AlertCheckpoint
    from ..ingest.ndr import NdrConsumer
    from .fault_injection import _env as env_ctx

    stages = [StageResult("0 staging", -36 * H, observable=False,
                          note="attacker-side infrastructure (Binance: mixer-funded wallet, sweeper contract) — "
                               "no bank feed sees it"),
              StageResult("1 endpoint", -24 * H), StageResult("2 c2", -24 * H + 120),
              StageResult("3 privileged_access", -2 * H), StageResult("4 persistence", -15 * 60.0),
              StageResult("5 drain", 0.0)]
    by_name = {s.stage.split(" ", 1)[1]: s for s in stages}
    with tempfile.TemporaryDirectory() as tds:
        td = Path(tds)
        with env_ctx(_env(td)):
            from ..service import build_pipeline
            p = build_pipeline(td / "audit.jsonl", fresh=True)
            p.response._hitl_stream = io.StringIO()

            def handle(stage: StageResult, alert: dict, t_s: float) -> None:
                chain = p.orch.handle(alert)
                summary = p.response.execute(chain)
                _record(stage, chain, summary, t_s)

            handle(by_name["endpoint"], endpoint_alert(), -24 * H)

            world = c2_world(seed)
            detector = EgressDetector.from_env()
            consumer = NdrConsumer(detector=detector, checkpoint=AlertCheckpoint())
            c2 = by_name["c2"]
            try:
                for rec in world.records:
                    got = consumer.normalize(rec)
                    if got is CONSUMED or not got:
                        continue
                    for alert in got:
                        if alert.get("source_ip") != LAPTOP_IP:
                            continue                      # background noise: the bench measures that elsewhere
                        at = datetime.fromisoformat(alert["timestamp"].replace("Z", "+00:00")).timestamp() - T0.timestamp()
                        handle(c2, alert, at)
            finally:
                detector.usage.write()
            if not c2.alerts:
                c2.note = "the network detector raised nothing for the laptop's beacon in the 60-minute window"

            handle(by_name["privileged_access"], privileged_access_alert(), -2 * H)
            handle(by_name["persistence"], persistence_alert(), -15 * 60.0)
            for t_s, alert in drain_alerts():
                handle(by_name["drain"], alert, t_s)
    return stages


def contain(stages: list[StageResult], latency_s: float) -> dict:
    """When the first path-cutting action would execute, and how much of the drain leaves before it."""
    access_cutoff = -2 * H                                 # stage 3: the attacker is in the signer from here
    best: tuple[float, dict, str] | None = None
    for s in stages:
        for a in s.actions:
            if not a["scope"]:
                continue
            exec_t = a["t_s"] + (0.0 if (a["executed"] or not a["hitl"]) else latency_s)
            if a["scope"] == "access" and exec_t >= access_cutoff:
                continue                                   # too late to matter: the foothold has moved on
            if best is None or exec_t < best[0]:
                best = (exec_t, a, s.stage)
    drain = drain_alerts()
    total = sum(x["amount_inr"] for _, x in drain)
    if best is None:
        return {"latency_s": latency_s, "stopped_at_s": None, "by": None, "stage": None,
                "lost_inr": total, "lost_share": 1.0, "prevented": False}
    t = best[0]
    lost = sum(x["amount_inr"] for ts, x in drain if ts < t)
    return {"latency_s": latency_s, "stopped_at_s": round(t, 1), "by": f"{best[1]['type']} -> {best[1]['target']}",
            "stage": best[2], "lost_inr": lost, "lost_share": round(lost / total, 3), "prevented": lost == 0}


def _hhmm(t_s: float | None) -> str:
    if t_s is None:
        return "—"
    sign, t = ("-" if t_s < 0 else "+"), abs(t_s)
    return f"T{sign}{int(t // 3600)}h{int(t % 3600 // 60):02d}m"


def _crore(inr: float) -> str:
    return f"INR {inr / 1e7:,.0f} cr"


def report(stages: list[StageResult], latencies: tuple[float, ...]) -> dict:
    total = sum(x["amount_inr"] for _, x in drain_alerts())
    first = next((s for s in stages if s.verdict in ("suspicious", "malicious")), None)
    first_mal = next((s for s in stages if s.verdict == "malicious"), None)
    from .purple_team.harness import model_label
    return {"scenario": "signer_compromise (Binance Oct 2026 pattern, bank-translated)", "judge": model_label(),
            "drain_total_inr": total,
            "first_detection": {"stage": first.stage, "at": _hhmm(first.first_alert_t_s)} if first else None,
            "first_malicious": {"stage": first_mal.stage, "at": _hhmm(first_mal.first_alert_t_s)} if first_mal else None,
            "stages": [s.to_dict() for s in stages],
            "containment": [contain(stages, L) for L in latencies]}


def render(rep: dict) -> str:
    lines = [f"=== {rep['scenario']} — judge: {rep['judge']} ===",
             f"  {'stage':22s} {'when':>9s}  {'alerts':>6s}  {'verdict':10s} {'conf':>4s}  {'by':16s} path-cutting actions (HITL?)"]
    for s in rep["stages"]:
        if not s["observable"]:
            lines.append(f"  {s['stage']:22s} {_hhmm(s['t_s']):>9s}  {'—':>6s}  not observable — {s['note']}")
            continue
        cuts = sorted({f"{a['type']}{'*' if a['hitl'] else ''}" for a in s["actions"] if a["scope"]})
        other = sorted({a["type"] for a in s["actions"] if not a["scope"]})
        lines.append(f"  {s['stage']:22s} {_hhmm(s['first_alert_t_s']):>9s}  {s['alerts']:>6d}  {s['verdict'] or '—':10s} "
                     f"{s['confidence']:.2f}  {s['by'] or '—':16s} {', '.join(cuts) or 'none'}"
                     + (f"   (also: {', '.join(other)})" if other else ""))
    fd, fm = rep["first_detection"], rep["first_malicious"]
    lines.append(f"  first detection: {fd['stage'] + ' at ' + fd['at'] if fd else 'none'} · "
                 f"first malicious: {fm['stage'] + ' at ' + fm['at'] if fm else 'none'}   (* = waits for a human)")
    lines.append(f"  drain at risk: {_crore(rep['drain_total_inr'])} in {DRAIN_N} transfers over {DRAIN_N * DRAIN_GAP_S / 60:.0f} min")
    for c in rep["containment"]:
        lat = c["latency_s"]
        lat_s = f"{lat / 3600:g} h" if lat >= 3600 else f"{lat / 60:g} min"
        if c["stopped_at_s"] is None:
            lines.append(f"  analyst approves in {lat_s:>6s}: nothing cuts the path — whole drain lost ({_crore(c['lost_inr'])})")
        else:
            out = "drain PREVENTED" if c["prevented"] else f"lost {_crore(c['lost_inr'])} ({c['lost_share']:.0%})"
            lines.append(f"  analyst approves in {lat_s:>6s}: {c['by']} lands at {_hhmm(c['stopped_at_s'])} "
                         f"(from {c['stage']}) — {out}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", default="", help="write the full report as JSON")
    ap.add_argument("--latencies", default="300,3600,28800", help="analyst approval latencies, seconds")
    ap.add_argument("--seed", type=int, default=11)
    args = ap.parse_args(argv)
    lats = tuple(float(x) for x in args.latencies.split(",") if x.strip())
    rep = report(run(args.seed), lats)
    print(render(rep))
    if args.json:
        Path(args.json).write_text(json.dumps(rep, indent=1, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
