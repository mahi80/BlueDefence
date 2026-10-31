"""Native async Anthropic client with streaming.

Companion to the sync AnthropicClient. Used by:

  - AsyncSOCOrchestrator when running on real Anthropic LLM
  - Bulk/batch consumers that want streaming-token UI behavior
  - Any specialist that wants to overlap LLM I/O with local work

Same retry/budget/cache discipline as AnthropicClient. The native
async path avoids the asyncio.to_thread() hop the
AsyncSOCOrchestrator uses to wrap the sync client — meaningfully
better at high concurrency because we don't pay per-call thread
overhead.

Streaming: complete_stream() yields text chunks as they arrive.
Useful for live demo / UX where the analyst wants to see the LLM's
reasoning unfold rather than wait for the whole response.
"""
from __future__ import annotations

import asyncio
import logging
import random
from typing import AsyncIterator, Optional

from .llm_client import (
    LLMResponse,
    TokenBudget,
    TokenBudgetExceeded,
    _compute_cost,
)


_log = logging.getLogger("aegis.async_llm")


class AsyncLLMClient:
    """Abstract async client interface."""
    name: str = "abstract_async"
    model: str = "abstract"

    async def complete(self, system: str, user: str, max_tokens: int = 2048) -> LLMResponse:
        raise NotImplementedError

    async def complete_stream(self, system: str, user: str,
                              max_tokens: int = 2048) -> AsyncIterator[str]:
        """Default fallback: call complete() and yield the whole text
        at once. Real backends override with token-by-token streaming.
        """
        resp = await self.complete(system, user, max_tokens)
        yield resp.text


class AsyncAnthropicClient(AsyncLLMClient):
    """Native async + streaming Anthropic client.

    Uses anthropic.AsyncAnthropic. Same prompt-caching, retry, budget
    flow as the sync AnthropicClient.
    """

    name = "anthropic_async"

    def __init__(
        self,
        model: str = "claude-sonnet-4-6",
        *,
        max_retries: int = 5,
        initial_backoff_s: float = 1.0,
        max_backoff_s: float = 30.0,
        budget: Optional[TokenBudget] = None,
        cache_system_prompt: bool = True,
    ):
        from anthropic import AsyncAnthropic  # imported lazily
        self._client = AsyncAnthropic()
        self.model = model
        self._max_retries = max_retries
        self._initial_backoff = initial_backoff_s
        self._max_backoff = max_backoff_s
        self._budget = budget or TokenBudget()
        self._cache_system = cache_system_prompt

    @property
    def budget(self) -> TokenBudget:
        return self._budget

    async def complete(self, system: str, user: str, max_tokens: int = 2048) -> LLMResponse:
        est_in = (len(system) + len(user)) // 4
        if self._budget.will_exceed(est_in, max_tokens):
            raise TokenBudgetExceeded(
                f"session budget exceeded: in={self._budget.consumed_input}, "
                f"out={self._budget.consumed_output}, cost={self._budget.consumed_cost:.1f}c"
            )

        if self._cache_system and len(system) > 1024:
            system_param = [
                {"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}
            ]
        else:
            system_param = system

        messages = [{"role": "user", "content": user}]

        backoff = self._initial_backoff
        for attempt in range(self._max_retries + 1):
            try:
                msg = await self._client.messages.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    system=system_param,
                    messages=messages,
                )
                text = "".join(
                    block.text for block in msg.content if getattr(block, "type", None) == "text"
                )
                usage = msg.usage
                resp = LLMResponse(
                    text=text,
                    model=self.model,
                    input_tokens=getattr(usage, "input_tokens", 0),
                    output_tokens=getattr(usage, "output_tokens", 0),
                    cache_creation_input_tokens=getattr(usage, "cache_creation_input_tokens", 0) or 0,
                    cache_read_input_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0,
                    retries=attempt,
                )
                resp.cost_cents = _compute_cost(resp)
                self._budget.add(resp)
                return resp
            except Exception as exc:  # noqa: BLE001
                if not self._is_retriable(exc) or attempt == self._max_retries:
                    raise
                sleep_s = min(backoff, self._max_backoff) * (0.5 + random.random())
                _log.warning(
                    "AsyncAnthropic call attempt %d/%d hit %s; sleeping %.1fs",
                    attempt + 1, self._max_retries + 1, type(exc).__name__, sleep_s,
                )
                await asyncio.sleep(sleep_s)
                backoff = min(backoff * 2, self._max_backoff)
        raise RuntimeError("retry loop fell through")

    async def complete_stream(self, system: str, user: str,
                              max_tokens: int = 2048) -> AsyncIterator[str]:
        """Token-by-token streaming. Yields text chunks as they arrive
        from the model. Useful for live UI; same budget tracking as
        non-streaming complete() (final usage applied when stream ends).
        """
        est_in = (len(system) + len(user)) // 4
        if self._budget.will_exceed(est_in, max_tokens):
            raise TokenBudgetExceeded(
                f"session budget exceeded: in={self._budget.consumed_input}, "
                f"out={self._budget.consumed_output}, cost={self._budget.consumed_cost:.1f}c"
            )

        if self._cache_system and len(system) > 1024:
            system_param = [
                {"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}
            ]
        else:
            system_param = system

        async with self._client.messages.stream(
            model=self.model,
            max_tokens=max_tokens,
            system=system_param,
            messages=[{"role": "user", "content": user}],
        ) as stream:
            async for chunk in stream.text_stream:
                yield chunk
            final = await stream.get_final_message()
        usage = final.usage
        resp = LLMResponse(
            text="",  # streamed already
            model=self.model,
            input_tokens=getattr(usage, "input_tokens", 0),
            output_tokens=getattr(usage, "output_tokens", 0),
            cache_creation_input_tokens=getattr(usage, "cache_creation_input_tokens", 0) or 0,
            cache_read_input_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0,
        )
        resp.cost_cents = _compute_cost(resp)
        self._budget.add(resp)

    def _is_retriable(self, exc: Exception) -> bool:
        retriable_names = {
            "RateLimitError", "APIConnectionError", "InternalServerError",
            "APITimeoutError", "OverloadedError",
        }
        if type(exc).__name__ in retriable_names:
            return True
        status = getattr(exc, "status_code", None)
        if status in (408, 409, 429) or (status and status >= 500):
            return True
        return False


# ---- Async mock for offline tests --------------------------------

class AsyncMockClient(AsyncLLMClient):
    """Async wrapper that internally calls the sync MockClient.
    Used by aegis.eval tests + demos that want async semantics offline.
    """

    name = "async_mock"
    model = "mock-rules-1"

    def __init__(self):
        from .llm_client import MockClient
        self._inner = MockClient()

    async def complete(self, system: str, user: str, max_tokens: int = 2048) -> LLMResponse:
        return await asyncio.to_thread(self._inner.complete, system, user, max_tokens)

    async def complete_stream(self, system: str, user: str,
                              max_tokens: int = 2048) -> AsyncIterator[str]:
        resp = await self.complete(system, user, max_tokens)
        # Yield one chunk per ~80 chars to simulate streaming UX
        for i in range(0, len(resp.text), 80):
            yield resp.text[i:i + 80]
            await asyncio.sleep(0)


def get_async_client(prefer: Optional[str] = None) -> AsyncLLMClient:
    """Factory mirroring get_client() but for async."""
    import os
    pref = (prefer or os.environ.get("LLM_BACKEND", "auto")).lower()
    if pref == "mock":
        return AsyncMockClient()
    if pref in ("anthropic", "auto") and os.environ.get("ANTHROPIC_API_KEY"):
        try:
            return AsyncAnthropicClient()
        except Exception as exc:  # noqa: BLE001
            _log.warning("AsyncAnthropic unavailable (%s) — falling back to mock", exc)
            return AsyncMockClient()
    return AsyncMockClient()
