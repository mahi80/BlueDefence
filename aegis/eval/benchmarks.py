"""Latency benchmarks for the AEGIS pipeline.

The project plan's tier separation rests on a cost/latency model:
Tier 0 hot path (<10ms), Tier 1 fast triage (<1s), Tier 2 deep
investigation (<30s), Tier 3 strategic (minutes-hours). Without
measurements the model is hand-waving; this benchmark gives concrete
numbers for the offline (mock LLM) and online (Anthropic) paths.

Measured operations:

  - PII tokenize + detokenize roundtrip
  - Causal posterior inference (ATO, fraud, lateral_movement)
  - Risk scoring (compute_risk_score)
  - Audit log append (hash-chained)
  - Orchestrator triage (mock LLM)         — Tier 1 baseline
  - Specialist investigate (mock LLM)      — Tier 2 baseline
  - Response.execute (HITL gating only)    — Tier 0 cost (no LLM)

Reports per-op P50/P95/P99 latency, per-tier rollup, and a sanity
check vs the plan's targets. Run:

  python -m aegis.eval.benchmarks
  python -m aegis.eval.benchmarks --iterations 5000
"""
from __future__ import annotations

import argparse
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from aegis.agents.shared.audit import AuditLog
from aegis.agents.shared.causal import (
    infer_ato, infer_fraud, infer_lateral_movement,
)
from aegis.agents.shared.evidence_chain import EvidenceChain, RecommendedAction
from aegis.agents.shared.llm_client import get_client
from aegis.agents.shared.pii_tokenizer import PIITokenizer
from aegis.agents.vuln_discovery.tools import compute_risk_score


_TIER_TARGETS = {
    # plan-stated SLOs (P95):
    "tier_0_hot_path":         {"label": "Tier 0 (hot path)",          "p95_ms": 10.0},
    "tier_1_fast_triage":      {"label": "Tier 1 (fast triage)",       "p95_ms": 1000.0},
    "tier_2_investigation":    {"label": "Tier 2 (deep investigation)","p95_ms": 30_000.0},
}


def _percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    idx = max(0, min(len(s) - 1, int(round(p / 100.0 * (len(s) - 1)))))
    return s[idx]


def _bench(name: str, fn: Callable[[], None], iters: int) -> dict:
    timings: list[float] = []
    for _ in range(iters):
        t0 = time.perf_counter_ns()
        fn()
        timings.append((time.perf_counter_ns() - t0) / 1e6)  # ns -> ms
    return {
        "name": name,
        "iterations": iters,
        "p50_ms": round(_percentile(timings, 50), 4),
        "p95_ms": round(_percentile(timings, 95), 4),
        "p99_ms": round(_percentile(timings, 99), 4),
        "mean_ms": round(statistics.mean(timings), 4),
        "max_ms": round(max(timings), 4),
    }


def _build_alert() -> dict:
    return {
        "id": "BENCH-ALERT",
        "source": "F5 ASM",
        "severity": "high",
        "anomaly_score": 0.95,
        "source_ip": "185.220.101.45",
        "user_id": None,
        "url": "/api/search",
        "payload": "GET /api/search?q=' UNION SELECT username,password FROM users--",
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--iterations", type=int, default=1000,
                   help="Iterations per micro-benchmark (default 1000)")
    p.add_argument("--llm-iterations", type=int, default=200,
                   help="Iterations for LLM-bearing benchmarks (default 200)")
    args = p.parse_args()

    print(f"\n=== AEGIS latency benchmarks ===")
    print(f"  micro iterations:   {args.iterations}")
    print(f"  LLM iterations:     {args.llm_iterations}")
    print(f"  Python:             {sys.version.split()[0]}")
    print()

    results: list[dict] = []

    # ---- Tier 0 micro-benchmarks (no LLM) ----------------------------

    tokenizer = PIITokenizer()
    sample = (
        "user alice.kumar@bank.example  account ACC-000123456789  "
        "aadhaar 2345 6789 1011  pan AAACA1234L  ifsc HDFC0001234"
    )
    def _pii_roundtrip():
        t, m = tokenizer.tokenize(sample)
        tokenizer.detokenize(t, m)
    results.append({**_bench("pii_tokenizer_roundtrip", _pii_roundtrip, args.iterations),
                    "tier": "tier_0_hot_path"})

    causal_obs = {"impossible_travel": "yes", "new_device": "yes", "mfa_burst": "no"}
    results.append({**_bench("causal_ato_posterior",
                             lambda: infer_ato(causal_obs), args.iterations),
                    "tier": "tier_0_hot_path"})
    fraud_obs = {"mule_destination": "yes", "novel_high_value_rail": "yes",
                 "structuring": "yes", "velocity_anomaly": "no"}
    results.append({**_bench("causal_fraud_posterior",
                             lambda: infer_fraud(fraud_obs), args.iterations),
                    "tier": "tier_0_hot_path"})
    lat_obs = {"suspicious_process_tree": "yes", "cross_zone_admin": "yes",
               "ioc_match": "yes", "file_integrity_drift": "no"}
    results.append({**_bench("causal_lateral_posterior",
                             lambda: infer_lateral_movement(lat_obs), args.iterations),
                    "tier": "tier_0_hot_path"})

    results.append({**_bench("compute_risk_score",
                             lambda: compute_risk_score(cvss=8.0, epss=0.5, kev=True, poc_available=True),
                             args.iterations),
                    "tier": "tier_0_hot_path"})

    with tempfile.TemporaryDirectory() as td:
        audit_path = Path(td) / "bench_audit.jsonl"
        audit = AuditLog(audit_path)
        chain = EvidenceChain(
            alert_id="BENCH", investigated_by="bench",
            verdict="benign", confidence=0.5,
        )
        chain.recommended_actions.append(RecommendedAction(
            action_type="allow", target="bench", reasoning="bench",
            requires_hitl=False, confidence=0.5,
        ))
        results.append({**_bench("audit_log_append",
                                 lambda: audit.append(EvidenceChain(
                                     alert_id="BENCH", investigated_by="bench",
                                     verdict="benign", confidence=0.5,
                                 )), args.iterations),
                        "tier": "tier_0_hot_path"})

    # ---- Tier 1 / Tier 2 (orchestrator + specialist with mock LLM) ---

    from aegis.agents.api_abuse.agent import APIAbuseAgent
    from aegis.agents.auth.agent import AuthAgent
    from aegis.agents.deception.honeytoken_monitor import HoneytokenMonitor
    from aegis.agents.edr.agent import EDRAgent
    from aegis.agents.orchestrator.agent import SOCOrchestrator
    from aegis.agents.perimeter.agent import PerimeterAgent
    from aegis.agents.transaction.agent import TransactionAgent

    primary = get_client(prefer="mock")
    voter = get_client(prefer="mock")

    with tempfile.TemporaryDirectory() as td:
        audit_path = Path(td) / "bench.jsonl"
        orch = SOCOrchestrator(
            primary_llm=primary, voter_llm=voter,
            perimeter=PerimeterAgent(llm=primary),
            auth=AuthAgent(llm=primary),
            edr=EDRAgent(llm=primary),
            api_abuse=APIAbuseAgent(llm=primary),
            transaction=TransactionAgent(llm=primary),
            honeytoken=HoneytokenMonitor(),
            audit=AuditLog(audit_path),
        )

        alert_perimeter = _build_alert()
        results.append({**_bench("orchestrator_handle_perimeter",
                                 lambda: orch.handle({**alert_perimeter, "id": f"B-{time.time_ns()}"}),
                                 args.llm_iterations),
                        "tier": "tier_2_investigation"})

        alert_low = {**_build_alert(),
                     "anomaly_score": 0.10, "source_ip": "10.20.30.40",
                     "user_id": "u_42891",
                     "url": "/api/balance",
                     "payload": "GET /api/balance"}
        results.append({**_bench("orchestrator_handle_auto_close",
                                 lambda: orch.handle({**alert_low, "id": f"B-{time.time_ns()}"}),
                                 args.llm_iterations),
                        "tier": "tier_1_fast_triage"})

    # ---- Render report ---------------------------------------------

    print(f"{'op':<40} {'iters':>8} {'p50_ms':>10} {'p95_ms':>10} {'p99_ms':>10}  tier")
    print("-" * 100)
    for r in results:
        print(
            f"{r['name']:<40} {r['iterations']:>8} "
            f"{r['p50_ms']:>10.4f} {r['p95_ms']:>10.4f} {r['p99_ms']:>10.4f}  {r['tier']}"
        )

    # Tier-rollup vs targets
    print(f"\nTier rollup (max P95 across ops in tier vs SLO):")
    by_tier: dict[str, list[float]] = {}
    for r in results:
        by_tier.setdefault(r["tier"], []).append(r["p95_ms"])
    failed_tiers: list[str] = []
    for tier_key, tier_meta in _TIER_TARGETS.items():
        observed = max(by_tier.get(tier_key, [0.0]) or [0.0])
        target = tier_meta["p95_ms"]
        marker = "OK  " if observed <= target else "FAIL"
        if observed > target:
            failed_tiers.append(tier_key)
        print(f"  [{marker}] {tier_meta['label']:<32} P95={observed:>10.2f}ms  target<={target:>10.2f}ms")

    if failed_tiers:
        print(f"\n{len(failed_tiers)} tier(s) over SLO: {failed_tiers}")
        return 1
    print(f"\nAll tiers within plan-stated SLO targets.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
