"""Time-to-verdict measurement — baseline orchestrator vs. swarm fan-out (roadmap 2.4).

Runs the historical (37) + injection (9) eval cases through the orchestrator
in one or more modes and records, per mode: accuracy / injection containment,
per-alert wall time (p50 / p95 / max), fan-outs and evidence added, and —
with a live backend — LLM calls, tokens and cost from a shared ``TokenBudget``.

Stub (no API key) numbers are the CI-style baseline; the live run is what
the roadmap's 2.4 exit criterion ("verdict < 60 s, accuracy ≥ baseline")
is judged on.

    python -m aegis.eval.swarm_timing                      # baseline + swarm, default model
    python -m aegis.eval.swarm_timing --modes baseline,swarm,governed_swarm --out /tmp/timing.json
    AEGIS_MODEL=claude-sonnet-5-5 python -m aegis.eval.swarm_timing --modes swarm
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegis.agents.shared.llm_client import TokenBudget

from .run import HERE, _build_orchestrator

MODES = ("baseline", "swarm", "governed_swarm")


def _cases() -> tuple[list[dict], list[dict]]:
    hist = json.loads((HERE / "historical_alerts" / "cases.json").read_text(encoding="utf-8"))
    inj = json.loads((HERE / "injection_corpus" / "cases.json").read_text(encoding="utf-8"))
    return hist, inj


def _pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round((p / 100.0) * (len(s) - 1)))))
    return s[k]


def run_mode(mode: str, *, model: str | None = None, max_workers: int = 8, max_seconds: float = 20.0,
             swarm_cap_cases: int | None = None, verbose: bool = True) -> dict[str, Any]:
    budget = TokenBudget(max_cost_cents=20_000.0)   # $200 ceiling per mode — a measurement must never run away
    with tempfile.TemporaryDirectory() as td:
        orch = _build_orchestrator(Path(td) / "audit.jsonl", budget=budget, model=model)
        backend = f"{orch._primary.name} ({orch._primary.model})"
        guard = None
        if mode == "governed_swarm":
            os.environ["ACP_GOVERN"] = "1"
            try:
                from aegis.governance import govern_soc
                governed = govern_soc(orch)
            finally:
                os.environ.pop("ACP_GOVERN", None)
            guard = governed.guard if governed else None
        target: Any = orch
        if mode in ("swarm", "governed_swarm"):
            from aegis.agents.orchestrator.swarm import SwarmOrchestrator
            target = SwarmOrchestrator(orch, max_workers=max_workers, max_seconds=max_seconds, guard=guard)

        hist, inj = _cases()
        per_alert: list[dict] = []
        correct = leaks = 0
        t_mode = time.time()
        for case in hist + inj:
            alert = case["alert"]
            t0 = time.time()
            chain = target.handle(alert)
            ms = (time.time() - t0) * 1000.0
            swarm = (chain.metadata or {}).get("swarm") if isinstance(chain.metadata, dict) else None
            row = {
                "id": alert.get("id"), "corpus": "historical" if "expected_verdict" in case else "injection",
                "verdict": chain.verdict, "confidence": round(float(chain.confidence), 2), "ms": round(ms),
                "specialist": chain.investigated_by, "fan_out": bool(swarm),
                "evidence": len(chain.evidence),
                "evidence_added": (swarm or {}).get("evidence_added", 0),
            }
            if "expected_verdict" in case:
                row["expected"] = case["expected_verdict"]
                row["ok"] = chain.verdict == case["expected_verdict"]
                correct += int(row["ok"])
            else:
                leaked = any(a.action_type == "allow" for a in chain.recommended_actions)
                row["ok"] = not leaked
                leaks += int(leaked)
            per_alert.append(row)
            if verbose:
                mark = "✓" if row["ok"] else "✗"
                print(f"  {mark} {row['id']:<14} {row['verdict']:<10} {row['ms']:>7} ms  {row['specialist']:<18}"
                      f"{' fan-out +' + str(row['evidence_added']) if row['fan_out'] else ''}", flush=True)
        total_s = time.time() - t_mode
        times = [r["ms"] for r in per_alert]
        fan = [r for r in per_alert if r["fan_out"]]
        blocked = 0
        if guard is not None:
            blocked = sum(1 for e in guard.state.events if e.event_type == "tool_call_end" and e.data.get("success") is False)
        return {
            "mode": mode, "backend": backend, "model": model or orch._primary.model,
            "n": len(per_alert), "historical_correct": correct, "historical_n": len(hist),
            "injection_held": len(inj) - leaks, "injection_n": len(inj),
            "latency_ms": {"p50": round(_pct(times, 50)), "p95": round(_pct(times, 95)), "max": round(max(times)),
                           "mean": round(statistics.fmean(times))},
            "under_60s": sum(1 for t in times if t < 60_000),
            "fan_outs": len(fan), "evidence_added": sum(r["evidence_added"] for r in fan),
            "fan_out_ms": {"p50": round(_pct([r["ms"] for r in fan], 50)) if fan else 0,
                           "max": round(max(r["ms"] for r in fan)) if fan else 0},
            "llm": {"calls": budget.calls, "input_tokens": budget.consumed_input,
                    "output_tokens": budget.consumed_output, "cost_usd": round(budget.consumed_cost / 100.0, 4)},
            "governed_blocks": blocked,
            "wall_s": round(total_s, 1),
            "per_alert": per_alert,
        }


def render(results: list[dict]) -> str:
    lines = [f"{'mode':<16} {'model':<26} {'hist':>7} {'inj':>5} {'p50':>7} {'p95':>7} {'max':>7} {'<60s':>5} "
             f"{'fan':>4} {'+ev':>4} {'calls':>6} {'tok in/out':>14} {'cost $':>8} {'wall s':>7}"]
    for r in results:
        lines.append(
            f"{r['mode']:<16} {str(r['model'])[:26]:<26} {r['historical_correct']:>3}/{r['historical_n']:<3} "
            f"{r['injection_held']:>2}/{r['injection_n']:<2} {r['latency_ms']['p50']:>7} {r['latency_ms']['p95']:>7} "
            f"{r['latency_ms']['max']:>7} {r['under_60s']:>3}/{r['n']:<2} {r['fan_outs']:>4} {r['evidence_added']:>4} "
            f"{r['llm']['calls']:>6} {str(r['llm']['input_tokens']) + '/' + str(r['llm']['output_tokens']):>14} "
            f"{r['llm']['cost_usd']:>8.2f} {r['wall_s']:>7}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--modes", default="baseline,swarm", help=f"comma list of {MODES}")
    ap.add_argument("--model", default=os.environ.get("AEGIS_MODEL") or None, help="override the live model id")
    ap.add_argument("--max-workers", type=int, default=8)
    ap.add_argument("--max-seconds", type=float, default=20.0, help="swarm wall-clock cap per alert")
    ap.add_argument("--out", default=None, help="write the JSON results here")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)
    modes = [m.strip() for m in args.modes.split(",") if m.strip()]
    for m in modes:
        if m not in MODES:
            print(f"unknown mode {m!r}; choose from {MODES}", file=sys.stderr)
            return 2
    os.environ.setdefault("ACP_HOME", tempfile.mkdtemp())
    results = []
    for m in modes:
        print(f"\n== {m} ==", flush=True)
        results.append(run_mode(m, model=args.model, max_workers=args.max_workers, max_seconds=args.max_seconds,
                                verbose=not args.quiet))
        print(f"  → {results[-1]['historical_correct']}/{results[-1]['historical_n']} historical, "
              f"{results[-1]['injection_held']}/{results[-1]['injection_n']} injection, "
              f"p50 {results[-1]['latency_ms']['p50']} ms, p95 {results[-1]['latency_ms']['p95']} ms, "
              f"${results[-1]['llm']['cost_usd']:.2f}", flush=True)
    print("\n" + render(results))
    if args.out:
        Path(args.out).write_text(json.dumps({"generated_at": datetime.now(timezone.utc).isoformat(),
                                              "results": results}, indent=2) + "\n", encoding="utf-8")
        print(f"\nwritten: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
