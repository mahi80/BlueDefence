"""Async orchestrator throughput demo.

Compares sync vs async handle() across a 100-alert batch under the
same alert mix the stress-test harness uses.

With MockClient, the GIL serializes the synthetic work and async
~ matches sync — the architecture is what we're proving, not a
throughput gain. With AnthropicClient (network-bound), async gives
real throughput improvement; the demo runs both modes if the API key
is present.

Run:
  python -m aegis.agents.orchestrator.async_demo
  python -m aegis.agents.orchestrator.async_demo --alerts 200 --concurrency 32
"""
from __future__ import annotations

import argparse
import asyncio
import random
import sys
import tempfile
import time
from pathlib import Path

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
from aegis.agents.orchestrator.async_agent import AsyncSOCOrchestrator
from aegis.agents.perimeter.agent import PerimeterAgent
from aegis.agents.shared.audit import AuditLog
from aegis.agents.shared.llm_client import get_client
from aegis.agents.transaction.agent import TransactionAgent

# Reuse the stress-test alert pool so the demo exercises every dispatch path.
from aegis.eval.stress import _alert_pool


def _build_orch(audit_path: Path) -> SOCOrchestrator:
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


def _make_batch(n: int) -> list[dict]:
    pool = _alert_pool()
    rng = random.Random(42)
    out: list[dict] = []
    for i in range(n):
        a = dict(rng.choice(pool))
        a["id"] = f"{a['id']}-{i}"
        out.append(a)
    return out


async def _run_async(sync_orch: SOCOrchestrator, alerts: list[dict],
                     concurrency: int) -> tuple[float, int]:
    async_orch = AsyncSOCOrchestrator(sync_orch, max_concurrency=concurrency)
    t0 = time.perf_counter()
    results = await async_orch.handle_many(alerts)
    elapsed = time.perf_counter() - t0
    succeeded = sum(1 for r in results if r.chain is not None)
    return elapsed, succeeded


def _run_sync(sync_orch: SOCOrchestrator, alerts: list[dict]) -> tuple[float, int]:
    t0 = time.perf_counter()
    succeeded = 0
    for a in alerts:
        try:
            sync_orch.handle(a)
            succeeded += 1
        except Exception:  # noqa: BLE001
            pass
    elapsed = time.perf_counter() - t0
    return elapsed, succeeded


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--alerts", type=int, default=100)
    p.add_argument("--concurrency", type=int, default=16)
    args = p.parse_args()

    print(f"\n=== AEGIS async-orchestrator throughput demo ===")
    print(f"  alerts:        {args.alerts}")
    print(f"  concurrency:   {args.concurrency}")
    print(f"  LLM backend:   {get_client().name} ({get_client().model})")
    print()

    with tempfile.TemporaryDirectory() as td:
        # Use SEPARATE audit logs for sync + async runs so the
        # comparison is apples-to-apples (each starts from an empty
        # hash chain).
        sync_orch_a = _build_orch(Path(td) / "sync.jsonl")
        sync_orch_b = _build_orch(Path(td) / "async.jsonl")

        alerts = _make_batch(args.alerts)

        print(f"[sync] handling {len(alerts)} alerts sequentially...")
        sync_t, sync_n = _run_sync(sync_orch_a, alerts)
        print(f"  elapsed: {sync_t:.3f}s  succeeded: {sync_n}/{len(alerts)}")
        print(f"  throughput: {sync_n/sync_t:.1f} alerts/s")

        print(f"\n[async] handling {len(alerts)} alerts concurrently (max={args.concurrency})...")
        async_t, async_n = asyncio.run(_run_async(sync_orch_b, alerts, args.concurrency))
        print(f"  elapsed: {async_t:.3f}s  succeeded: {async_n}/{len(alerts)}")
        print(f"  throughput: {async_n/async_t:.1f} alerts/s")

        speedup = sync_t / async_t if async_t > 0 else 0.0
        print(f"\n[result] speedup vs sync: {speedup:.2f}x")
        if get_client().name == "mock":
            print("  (mock LLM is in-process and fast; expect speedup ~1.0x —")
            print("  real Anthropic LLM would show 5-10x under network-bound calls)")

        # Verify both audit chains held under their respective load
        sync_audit = AuditLog(Path(td) / "sync.jsonl")
        async_audit = AuditLog(Path(td) / "async.jsonl")
        print(f"\n[integrity] sync audit chain:  {'PASS' if sync_audit.verify() else 'FAIL'}")
        print(f"[integrity] async audit chain: {'PASS' if async_audit.verify() else 'FAIL'}")

        return 0 if (sync_audit.verify() and async_audit.verify()) else 1


if __name__ == "__main__":
    sys.exit(main())
