"""Throughput and latency soak for the orchestrator.

This measures what a pilot is judged on: how long one alert takes end to end
and how many the process can sustain. It runs the real `SOCOrchestrator.handle`
path (fast paths included), so the number is the pipeline's, not a mock loop's.

    # against the configured backend (mock if nothing is configured)
    python -m aegis.eval.soak --alerts 200

    # against a recorded transcript: deterministic, offline, no spend
    AEGIS_EVAL_TRANSCRIPT=aegis/eval/transcripts/historical.jsonl \
        python -m aegis.eval.soak --alerts 200 --gate --target-p95 15 --target-eps 50

A run on the mock says so and refuses to gate: the mock is instant and would
"pass" any latency target. Exit codes follow `aegis.eval.run`: 0 met, 1 missed,
2 not credible under --gate.
"""
from __future__ import annotations

import argparse
import copy
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

from aegis.eval.run import HERE, _build_with_meta
from aegis.eval.transcripts import describe


def _corpus() -> list[dict]:
    """The two eval corpora, in order. They are the only labelled alert shapes
    in the repo; a soak on them measures the pipeline, not detection quality."""
    alerts: list[dict] = []
    for name in ("historical_alerts", "injection_corpus"):
        p = HERE / name / "cases.json"
        if p.exists():
            alerts.extend(json.loads(p.read_text(encoding="utf-8")))
    return alerts


def _pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = min(len(ordered) - 1, max(0, int(round((p / 100.0) * (len(ordered) - 1)))))
    return ordered[k]


def run(n: int) -> dict:
    cases = _corpus()
    if not cases:
        raise SystemExit("no eval corpus found under aegis/eval/")
    with tempfile.TemporaryDirectory() as td:
        orch, meta, client = _build_with_meta(Path(td) / "audit.jsonl")
        latencies: list[float] = []
        verdicts: dict[str, int] = {}
        t0 = time.perf_counter()
        for i in range(n):
            alert = copy.deepcopy(cases[i % len(cases)]["alert"])
            a = time.perf_counter()
            chain = orch.handle(alert)
            latencies.append((time.perf_counter() - a) * 1000.0)
            verdicts[chain.verdict] = verdicts.get(chain.verdict, 0) + 1
        wall = time.perf_counter() - t0
    return {
        "backend": meta,
        "backend_label": describe(meta),
        "credible": bool(meta.get("credible")) and not getattr(client, "misses", []),
        "alerts": n,
        "wall_s": round(wall, 3),
        "alerts_per_s": round(n / wall, 2) if wall else 0.0,
        "latency_ms": {
            "mean": round(statistics.fmean(latencies), 1),
            "p50": round(_pct(latencies, 50), 1),
            "p95": round(_pct(latencies, 95), 1),
            "p99": round(_pct(latencies, 99), 1),
            "max": round(max(latencies), 1),
        },
        "verdicts": verdicts,
        "transcript_misses": len(getattr(client, "misses", []) or []),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m aegis.eval.soak")
    ap.add_argument("--alerts", type=int, default=100)
    ap.add_argument("--json", dest="json_out", default="")
    ap.add_argument("--gate", action="store_true", help="exit non-zero when a target is missed or the run is not credible")
    ap.add_argument("--target-p95", type=float, default=0.0, help="milliseconds")
    ap.add_argument("--target-eps", type=float, default=0.0, help="alerts per second")
    args = ap.parse_args(argv)
    if args.alerts <= 0:
        ap.error("--alerts must be positive")

    summary = run(args.alerts)
    lat = summary["latency_ms"]
    print(f"backend : {summary['backend_label']}")
    print(f"alerts  : {summary['alerts']} in {summary['wall_s']}s  ({summary['alerts_per_s']}/s)")
    print(f"latency : p50 {lat['p50']} ms · p95 {lat['p95']} ms · p99 {lat['p99']} ms · max {lat['max']} ms")
    print(f"verdicts: {summary['verdicts']}")
    if summary["transcript_misses"]:
        print(f"transcript misses: {summary['transcript_misses']} — re-record the transcript")

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(summary, indent=2), encoding="utf-8")

    if not summary["credible"]:
        print("\nNOT CREDIBLE: this ran on the mock or with transcript misses; the numbers describe a keyword router.")
        return 2 if args.gate else 0

    missed = []
    if args.target_p95 and lat["p95"] > args.target_p95:
        missed.append(f"p95 {lat['p95']} ms > {args.target_p95} ms")
    if args.target_eps and summary["alerts_per_s"] < args.target_eps:
        missed.append(f"{summary['alerts_per_s']}/s < {args.target_eps}/s")
    if missed:
        print("\nMISSED: " + "; ".join(missed))
        return 1
    print("\ntargets met")
    return 0


if __name__ == "__main__":
    sys.exit(main())
