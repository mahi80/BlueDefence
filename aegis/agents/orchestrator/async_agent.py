"""Async orchestrator path — concurrent dispatch for production throughput.

The sync `SOCOrchestrator.handle()` is fine for low-volume bank
contexts but bottlenecks on LLM I/O at scale. Real Anthropic calls
are 200-500 ms; with sync handle() and 5 alerts/sec, the orchestrator
spends ~95% of its time waiting on the network. Async lets the event
loop schedule the next alert's triage while the previous one is in
flight.

Design constraint: don't fork the whole agent stack. The async
orchestrator is a thin shell that:

  1. Wraps each sync `SOCOrchestrator.handle()` call in
     `asyncio.to_thread()` — sync code runs in the default executor,
     async coroutines suspend at the await point so the loop can
     pick up other work.
  2. Exposes a `handle_many()` coroutine that processes a batch of
     alerts concurrently (with a configurable concurrency cap to
     respect the LLM provider's rate limits).
  3. Same return shape (`EvidenceChain`) — downstream
     audit/ServiceNow/Slack adapters don't change.

With a sync MockClient, asyncio doesn't speed anything up (the GIL
serializes the synthetic work); the real win is when AnthropicClient
makes network-bound calls. The architecture stays the same; the
benefit shows up under a real LLM backend.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import AsyncIterator, Iterable, Optional

from ..shared.evidence_chain import EvidenceChain
from .agent import SOCOrchestrator


@dataclass
class AsyncResult:
    alert_id: str
    chain: Optional[EvidenceChain] = None
    error: Optional[str] = None


class AsyncSOCOrchestrator:
    """Async wrapper over SOCOrchestrator. Same dispatch logic; just
    processes multiple alerts concurrently via asyncio.to_thread().
    """

    def __init__(self, sync: SOCOrchestrator, *, max_concurrency: int = 16):
        self._sync = sync
        self._sem = asyncio.Semaphore(max_concurrency)

    async def handle(self, alert: dict) -> EvidenceChain:
        """Single-alert path. Suspends at the LLM call so the event
        loop can pick up other work.
        """
        async with self._sem:
            return await asyncio.to_thread(self._sync.handle, alert)

    async def handle_many(self, alerts: Iterable[dict]) -> list[AsyncResult]:
        """Process N alerts concurrently. Returns one AsyncResult per
        alert in input order. Failures are captured per-alert; one
        bad alert doesn't fail the batch.
        """
        async def _one(a: dict) -> AsyncResult:
            try:
                chain = await self.handle(a)
                return AsyncResult(alert_id=a.get("id", "?"), chain=chain)
            except Exception as exc:  # noqa: BLE001
                return AsyncResult(alert_id=a.get("id", "?"), error=str(exc))

        tasks = [asyncio.create_task(_one(a)) for a in alerts]
        return await asyncio.gather(*tasks)

    async def stream(self, alerts: AsyncIterator[dict]) -> AsyncIterator[AsyncResult]:
        """Stream variant — for cases where alerts arrive over time
        (Kafka consumer, websocket from the SIEM). Yields results as
        each completes; back-pressure controlled by the semaphore.
        """
        async def _spawn(a: dict) -> AsyncResult:
            return await self.handle_many([a]).__await__().__next__() if False else (await self.handle_many([a]))[0]

        # Simpler: maintain a set of in-flight tasks, yield as they finish.
        in_flight: set[asyncio.Task] = set()
        async for a in alerts:
            t = asyncio.create_task(self.handle(a))
            in_flight.add(t)
            # If we're at the cap, wait for at least one to finish before pulling next
            if len(in_flight) >= self._sem._value:  # type: ignore[attr-defined]
                done, in_flight = await asyncio.wait(in_flight, return_when=asyncio.FIRST_COMPLETED)
                for t in done:
                    chain = t.result()
                    yield AsyncResult(alert_id=chain.alert_id, chain=chain)
        if in_flight:
            done, _ = await asyncio.wait(in_flight)
            for t in done:
                chain = t.result()
                yield AsyncResult(alert_id=chain.alert_id, chain=chain)
