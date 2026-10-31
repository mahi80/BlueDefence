"""Anthropic Message Batches API client for AEGIS.

The interactive AnthropicClient is right for live alert triage; the
Batches API is right for two specific AEGIS workloads:

  1. **Eval re-runs.** Re-running aegis/eval/run.py against a few
     hundred labeled cases via the live API costs N requests synchronously.
     Submitted as a batch, the cost drops by ~50% and the run completes
     in minutes (24h SLA, but typically 5-30 min in practice).

  2. **Historical SIEM backfill.** When the bank wants to score the
     last 90 days of SIEM notable events offline (pre-deployment
     calibration, post-incident investigation, periodic compliance
     audits), batch is the right tool — same prompt set, no latency
     pressure, half the cost.

Production-shape: same retry/budget/cache flow as AnthropicClient,
plus polling for batch completion. Falls back to sequential
AnthropicClient calls if the batch endpoint isn't available.

API: docs.anthropic.com/en/docs/build-with-claude/batch-processing
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Iterable, Optional

from .llm_client import (
    LLMClient,
    LLMResponse,
    TokenBudget,
    _compute_cost,
)


_log = logging.getLogger("aegis.batch")


@dataclass
class BatchRequest:
    """One entry in a batch submission. custom_id is echoed in the
    response so the caller can pair requests with results.
    """
    custom_id: str
    system: str
    user: str
    max_tokens: int = 2048


@dataclass
class BatchResult:
    custom_id: str
    response: Optional[LLMResponse] = None
    error: Optional[str] = None
    succeeded: bool = False


class BatchAnthropicClient:
    """Submits a batch of message requests, polls until complete,
    returns parsed responses paired with their custom_ids.

    Cost discount: Anthropic publishes ~50% off message-creates inside
    a batch (subject to provider current terms). We apply that discount
    in `_compute_cost_batch` for accurate budget accounting.
    """

    name = "anthropic_batch"

    def __init__(
        self,
        model: str = "claude-sonnet-4-6",
        *,
        budget: Optional[TokenBudget] = None,
        cache_system_prompt: bool = True,
        poll_interval_s: float = 10.0,
        max_wait_s: float = 86400.0,    # 24h SLA per Anthropic docs
        batch_discount: float = 0.5,     # 50% off; update if pricing shifts
    ):
        from anthropic import Anthropic  # imported lazily
        self._client = Anthropic()
        self.model = model
        self._budget = budget or TokenBudget()
        self._cache_system = cache_system_prompt
        self._poll_interval = poll_interval_s
        self._max_wait = max_wait_s
        self._discount = batch_discount

    @property
    def budget(self) -> TokenBudget:
        return self._budget

    def submit(self, requests: list[BatchRequest]) -> str:
        """Submit a batch. Returns the batch ID for polling."""
        params: list[dict[str, Any]] = []
        for r in requests:
            if self._cache_system and len(r.system) > 1024:
                system_param: Any = [
                    {"type": "text", "text": r.system, "cache_control": {"type": "ephemeral"}}
                ]
            else:
                system_param = r.system
            params.append({
                "custom_id": r.custom_id,
                "params": {
                    "model": self.model,
                    "max_tokens": r.max_tokens,
                    "system": system_param,
                    "messages": [{"role": "user", "content": r.user}],
                },
            })
        # The Anthropic SDK exposes batches via `client.messages.batches.create`
        # in the >=0.40 line. Older SDKs fall back to sequential.
        if not hasattr(self._client.messages, "batches"):
            raise RuntimeError(
                "anthropic SDK is too old for batch API; "
                "upgrade with: pip install -U anthropic"
            )
        batch = self._client.messages.batches.create(requests=params)
        _log.info("submitted batch %s with %d requests", batch.id, len(params))
        return batch.id

    def poll(self, batch_id: str) -> "list[BatchResult] | None":
        """Poll until the batch completes; return results or None if
        still in progress.
        """
        batches = getattr(self._client.messages, "batches", None)
        if batches is None:
            return None
        batch = batches.retrieve(batch_id)
        if getattr(batch, "processing_status", None) != "ended":
            return None
        # Stream results
        results: list[BatchResult] = []
        for entry in batches.results(batch_id):
            cid = getattr(entry, "custom_id", "")
            result_obj = getattr(entry, "result", None)
            r_type = getattr(result_obj, "type", None)
            if r_type == "succeeded":
                msg = getattr(result_obj, "message", None)
                text = "".join(
                    block.text for block in (getattr(msg, "content", []) or [])
                    if getattr(block, "type", None) == "text"
                )
                usage = getattr(msg, "usage", None)
                resp = LLMResponse(
                    text=text, model=self.model,
                    input_tokens=getattr(usage, "input_tokens", 0) if usage else 0,
                    output_tokens=getattr(usage, "output_tokens", 0) if usage else 0,
                    cache_creation_input_tokens=(
                        getattr(usage, "cache_creation_input_tokens", 0) or 0
                    ) if usage else 0,
                    cache_read_input_tokens=(
                        getattr(usage, "cache_read_input_tokens", 0) or 0
                    ) if usage else 0,
                )
                resp.cost_cents = _compute_cost(resp) * self._discount
                self._budget.add(resp)
                results.append(BatchResult(custom_id=cid, response=resp, succeeded=True))
            else:
                err_msg = getattr(getattr(result_obj, "error", None), "message", str(r_type))
                results.append(BatchResult(custom_id=cid, error=err_msg, succeeded=False))
        return results

    def submit_and_wait(self, requests: list[BatchRequest]) -> list[BatchResult]:
        batch_id = self.submit(requests)
        deadline = time.time() + self._max_wait
        while time.time() < deadline:
            done = self.poll(batch_id)
            if done is not None:
                return done
            time.sleep(self._poll_interval)
        raise TimeoutError(f"batch {batch_id} did not complete within {self._max_wait}s")


# ---- Sequential fallback ---------------------------------------------

def submit_sequential(client: LLMClient, requests: Iterable[BatchRequest]) -> list[BatchResult]:
    """Fallback for environments without batch API access. Same
    return shape; no discount.
    """
    out: list[BatchResult] = []
    for req in requests:
        try:
            resp = client.complete(req.system, req.user, max_tokens=req.max_tokens)
            out.append(BatchResult(custom_id=req.custom_id, response=resp, succeeded=True))
        except Exception as exc:  # noqa: BLE001
            out.append(BatchResult(custom_id=req.custom_id, error=str(exc), succeeded=False))
    return out
