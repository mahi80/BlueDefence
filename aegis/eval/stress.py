"""Concurrent stress test for the AEGIS pipeline.

The latency benchmarks (eval/benchmarks.py) measure single-threaded
per-op timings vs the plan's tier SLOs. This harness measures behavior
under CONCURRENT load — the realistic deployment scenario where the
SOC's SIEM is feeding alerts in parallel across many threads.

Verifies:

  - End-to-end throughput (alerts/sec) at N=4/8/16 worker threads.
  - Latency percentiles under concurrency (P50 / P95 / P99 / max).
  - Audit-chain integrity holds under concurrent appends — the
    SHA-256 hash chain serializes writes via the AuditLog._lock,
    so this is the production-realistic check that no corruption
    leaks through.
  - Per-specialist breakdown — different alert classes route to
    different agents; we want to see which one is slow under load.

Run:
  python -m aegis.eval.stress
  python -m aegis.eval.stress --workers 16 --duration 30
"""
from __future__ import annotations

import argparse
import concurrent.futures
import random
import statistics
import sys
import tempfile
import time
from pathlib import Path
from threading import Lock

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from aegis.agents.api_abuse.agent import APIAbuseAgent
from aegis.agents.auth.agent import AuthAgent
from aegis.agents.deception.honeytoken_monitor import HoneytokenMonitor
from aegis.agents.edr.agent import EDRAgent
from aegis.agents.orchestrator.agent import SOCOrchestrator
from aegis.agents.perimeter.agent import PerimeterAgent
from aegis.agents.shared.audit import AuditLog
from aegis.agents.shared.llm_client import get_client
from aegis.agents.transaction.agent import TransactionAgent


def _alert_pool() -> list[dict]:
    """Mix of alert classes covering all dispatch paths."""
    return [
        # Web/L7 — perimeter
        {"id": "S-PERIM", "source": "F5 ASM", "severity": "high",
         "anomaly_score": 0.95, "source_ip": "185.220.101.45",
         "user_id": None, "url": "/api/search",
         "payload": "GET /api/search?q=' UNION SELECT username,password FROM users--"},
        # Auth — ATO
        {"id": "S-AUTH", "source": "Okta", "severity": "high",
         "anomaly_score": 0.9, "user_id": "u_42891", "user_role": "retail_customer",
         "prev_geo": "IN-MH", "curr_geo": "RU-MO", "minutes_since_prev_login": 12,
         "device_fingerprint": {"ua": "Mozilla/5.0 (Linux) Firefox/115",
                                 "screen": "1366x768", "tz": "UTC"},
         "mfa_failures": [], "observed": {"failed_logins_24h": 1, "session_count_24h": 2,
                                            "endpoint": "/api/profile"}},
        # EDR
        {"id": "S-EDR", "source": "CrowdStrike Falcon", "severity": "high",
         "anomaly_score": 0.92, "host": "STRESS-WS-01", "user_id": "u_77104",
         "parent_process": "winword.exe", "child_process": "powershell.exe",
         "cmdline": "powershell.exe -enc SQBFAFgAIAAoAA==",
         "src_zone": "user_workstation", "dst_zone": "internet_egress",
         "dst_port": 443, "file_hash": "44d88612fea8a8f36de82e1278abb02f",
         "dest_domain": "evil.example.com", "dest_ip": None,
         "file_path": None, "file_hash_current": None},
        # API abuse — BOLA
        {"id": "S-API", "source": "API Gateway", "severity": "high",
         "anomaly_score": 0.85, "principal_id": "u_77104",
         "role": "wealth_advisor", "accessed_object_owner": "u_42891",
         "endpoint": "/api/users/u_42891", "http_method": "PUT",
         "params": {"user_id": "u_42891"}, "observed_per_min": 18.0},
        # Transaction
        {"id": "S-TXN", "source": "Core Banking (txn stream)", "severity": "high",
         "anomaly_score": 0.88, "user_id": "u_42891", "rail": "RTGS",
         "amount_inr": 950000.0, "beneficiary_account": "ACC-MULE-001",
         "sender_geo": "IN", "recent_24h_count": 4,
         "recent_24h_total_inr": 200000.0,
         "recent_amounts_inr": [950000.0, 950000.0, 950000.0]},
        # Honeytoken (deception fast-path; no LLM call)
        {"id": "S-HONEY", "source": "F5 ASM", "severity": "high",
         "anomaly_score": 0.99, "source_ip": "203.0.113.66",
         "user_id": None, "url": "/admin-internal-debug",
         "payload": "GET /admin-internal-debug HTTP/1.1"},
        # Auto-close path
        {"id": "S-AUTOCLOSE", "source": "F5 ASM", "severity": "low",
         "anomaly_score": 0.10, "source_ip": "10.20.30.40",
         "user_id": "u_42891", "url": "/api/balance",
         "payload": "GET /api/balance"},
    ]


def _build_orchestrator(audit_path: Path) -> SOCOrchestrator:
    primary = get_client(prefer="mock")
    voter = get_client(prefer="mock")
    return SOCOrchestrator(
        primary_llm=primary, voter_llm=voter,
        perimeter=PerimeterAgent(llm=primary),
        auth=AuthAgent(llm=primary),
        edr=EDRAgent(llm=primary),
        api_abuse=APIAbuseAgent(llm=primary),
        transaction=TransactionAgent(llm=primary),
        honeytoken=HoneytokenMonitor(),
        audit=AuditLog(audit_path),
    )


def _percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    idx = max(0, min(len(s) - 1, int(round(p / 100.0 * (len(s) - 1)))))
    return s[idx]


def _run(n_workers: int, duration_s: float, audit_path: Path) -> dict:
    orch = _build_orchestrator(audit_path)
    pool = _alert_pool()
    timings_per_specialist: dict[str, list[float]] = {}
    timings_lock = Lock()
    end_time = time.time() + duration_s

    def worker(worker_id: int):
        rng = random.Random(worker_id * 31 + 7)
        local_buckets: dict[str, list[float]] = {}
        local_count = 0
        while time.time() < end_time:
            template = rng.choice(pool)
            alert = dict(template)
            alert["id"] = f"{template['id']}-{worker_id}-{local_count}"
            local_count += 1
            t0 = time.perf_counter()
            chain = orch.handle(alert)
            elapsed = time.perf_counter() - t0
            local_buckets.setdefault(chain.investigated_by, []).append(elapsed)
        with timings_lock:
            for k, v in local_buckets.items():
                timings_per_specialist.setdefault(k, []).extend(v)

    start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=n_workers) as ex:
        list(ex.map(worker, range(n_workers)))
    actual_duration = time.time() - start

    all_timings: list[float] = []
    for v in timings_per_specialist.values():
        all_timings.extend(v)
    total_alerts = len(all_timings)

    return {
        "workers": n_workers,
        "duration_s": round(actual_duration, 2),
        "total_alerts": total_alerts,
        "throughput_alerts_per_s": round(total_alerts / max(actual_duration, 1e-3), 1),
        "p50_ms": round(_percentile(all_timings, 50) * 1000, 2),
        "p95_ms": round(_percentile(all_timings, 95) * 1000, 2),
        "p99_ms": round(_percentile(all_timings, 99) * 1000, 2),
        "max_ms": round(max(all_timings, default=0) * 1000, 2),
        "by_specialist": {
            sp: {
                "count": len(t),
                "p95_ms": round(_percentile(t, 95) * 1000, 2),
                "mean_ms": round(statistics.mean(t) * 1000, 2),
            }
            for sp, t in timings_per_specialist.items()
        },
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--workers", type=int, default=8,
                   help="Number of concurrent worker threads (default 8)")
    p.add_argument("--duration", type=float, default=5.0,
                   help="Run duration in seconds per scenario (default 5)")
    p.add_argument("--scenarios", default="1,4,8",
                   help="Comma-separated worker counts to run (default 1,4,8)")
    args = p.parse_args()

    scenarios = [int(x) for x in args.scenarios.split(",") if x.strip()]
    print(f"\n=== AEGIS concurrent stress test ===")
    print(f"  scenarios:    {scenarios} workers")
    print(f"  duration:     {args.duration}s per scenario")

    failed_scenarios: list[int] = []
    with tempfile.TemporaryDirectory() as td:
        for n in scenarios:
            audit_path = Path(td) / f"audit-{n}.jsonl"
            print(f"\n[scenario] {n} worker(s) for {args.duration}s")
            r = _run(n, args.duration, audit_path)
            print(
                f"  total_alerts={r['total_alerts']}  "
                f"throughput={r['throughput_alerts_per_s']:.1f}/s  "
                f"P50={r['p50_ms']}ms  P95={r['p95_ms']}ms  P99={r['p99_ms']}ms  max={r['max_ms']}ms"
            )
            print(f"  by specialist:")
            for sp, stats in sorted(r["by_specialist"].items(), key=lambda x: -x[1]["count"]):
                print(f"    {sp:<24} count={stats['count']:>5}  P95={stats['p95_ms']:>6.2f}ms  mean={stats['mean_ms']:>6.2f}ms")

            audit = AuditLog(audit_path)
            integrity_ok = audit.verify()
            print(f"  audit chain integrity under {n}-way concurrency: {'PASS' if integrity_ok else 'FAIL'}")
            if not integrity_ok:
                failed_scenarios.append(n)

    if failed_scenarios:
        print(f"\nFAILED scenarios (audit chain broke): {failed_scenarios}")
        return 1
    print(f"\nAll {len(scenarios)} concurrency scenarios held audit-chain integrity.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
