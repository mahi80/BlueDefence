"""Meta-agent main loop — observe, propose, validate, queue.

Run:
  python -m aegis.meta_agent.main                 # observe current eval state
  python -m aegis.meta_agent.main --seed-failure  # demo: pre-seed a gap
                                                  #   in perimeter primitives
                                                  #   then close the loop

Output: appends to aegis/meta_agent/_proposals.jsonl. Each entry is a
hash-chained {proposal, validation, status} record. HITL review picks
this up.

The meta-agent NEVER auto-deploys changes. Only outputs proposals.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Force UTF-8 stdout on Windows consoles.
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from aegis.agents.shared.llm_client import get_client

from .observer import Patch, observe
from .proposer import propose
from .queue import ProposalQueue
from .validator import validate


_QUEUE_PATH = Path(__file__).parent / "_proposals.jsonl"


def _seed_patches() -> list[Patch]:
    """Demo seeding: remove '@@version' from the perimeter SQLi
    primitives so EVAL-007 (which relies solely on the primitive list
    for detection — no IP-rep boost, no mock-hardcoded match) fails.
    The meta-agent should observe the gap, propose restoring the
    primitive, and validate that restoration closes the failure.
    """
    return [Patch(
        target="aegis.agents.perimeter.tools._SQLI_PRIMITIVES",
        mutate=lambda current: tuple(p for p in current if p != "@@version"),
        description="DEMO SEED: remove '@@version' to create a deliberate eval gap",
    )]


def _print_failures(label: str, failures) -> None:
    print(f"\n[{label}] {len(failures)} failure(s)")
    for f in failures:
        print(f"  - {f.case_id:<28} suite={f.suite:<16} expected={f.expected:<11} got={f.got:<11} conf={f.confidence:.2f}")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--seed-failure", action="store_true",
                   help="Demo: pre-seed an eval gap so the loop has work to do")
    p.add_argument("--queue", default=str(_QUEUE_PATH),
                   help="Path to the proposals JSONL queue")
    args = p.parse_args()

    from aegis.persist import sink_from_env
    queue = ProposalQueue(Path(args.queue), sink=sink_from_env(sync=True))  # Phase 0.3

    seeds = _seed_patches() if args.seed_failure else []
    if seeds:
        print("[meta-agent] applying demo seed patches:")
        for s in seeds:
            print(f"  - {s.description}")

    print("\n[meta-agent] phase 1: observe")
    failures = observe(patches=seeds)
    _print_failures("observed", failures)

    if not failures:
        print("\n[meta-agent] No failures. Nothing to propose.")
        print(f"[meta-agent] queue integrity: {'PASS' if queue.verify() else 'FAIL'}")
        return 0

    print("\n[meta-agent] phase 2: propose")
    proposals = propose(failures, llm=get_client())
    print(f"[meta-agent] {len(proposals)} proposal(s) generated")
    for prop in proposals:
        print(f"  - {prop.id}: {prop.change_type} on {prop.target_module}")
        print(f"      change={prop.change}")
        print(f"      rationale={prop.rationale[:100]}{'...' if len(prop.rationale) > 100 else ''}")

    print("\n[meta-agent] phase 3: validate")
    accepted = 0
    for prop in proposals:
        # Validation is run with the SAME seed patches still in place — we
        # measure the proposal's effect ON TOP of the current (seeded) state.
        # This is what production would do too: proposed change vs current prod state.
        # The validator internally manages its own monkey-patch lifecycle for the proposal;
        # the seed patches are still in effect via _apply_patches in observer.observe.
        with _stack_patches(seeds):
            result = validate(prop, baseline_failures=failures)
        verdict = "ACCEPT" if result.recommend_accept else "REJECT"
        print(
            f"  - {prop.id}: {verdict}  "
            f"failures {result.failures_before} -> {result.failures_after}, "
            f"regressions={result.regressions}  ({result.notes})"
        )
        if result.recommend_accept:
            queue.append(prop, result)
            accepted += 1

    print(f"\n[meta-agent] {accepted} proposal(s) queued for HITL at {args.queue}")
    print(f"[meta-agent] queue integrity: {'PASS' if queue.verify() else 'FAIL'}")
    return 0


# Helper: apply patches as a stack so validate() sees the seed in place
import contextlib  # noqa: E402


@contextlib.contextmanager
def _stack_patches(patches):
    from .observer import _apply_patches
    with _apply_patches(patches):
        yield


if __name__ == "__main__":
    sys.exit(main())
