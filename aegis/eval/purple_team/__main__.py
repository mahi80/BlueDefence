from __future__ import annotations

import argparse
import json
import logging
import sys

from .harness import render, run_all


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Purple-team benchmark: adaptive AI-agent attackers vs AEGIS (mock LLM by default).")
    ap.add_argument("--mode", choices=["auto", "human", "both"], default="both")
    ap.add_argument("--approval-latency", type=float, default=300.0, help="simulated seconds an analyst takes to approve a block")
    ap.add_argument("--only", default="", help="comma-separated campaign names")
    ap.add_argument("--no-benign", action="store_true", help="attacker traffic only (no collateral measurement)")
    ap.add_argument("--json", default="", help="write the per-campaign results here")
    ap.add_argument("--verbose", action="store_true", help="print every attacker step")
    args = ap.parse_args(argv)
    logging.getLogger().setLevel(logging.CRITICAL)
    modes = ("auto", "human") if args.mode == "both" else (args.mode,)
    only = {s.strip() for s in args.only.split(",") if s.strip()} or None
    results = run_all(modes=modes, approval_latency_s=args.approval_latency, only=only, benign=not args.no_benign,
                      verbose=args.verbose)
    print(render(results))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump([r.to_dict() for r in results], fh, indent=1)
    return 1 if any(r.gate_pass is False for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
