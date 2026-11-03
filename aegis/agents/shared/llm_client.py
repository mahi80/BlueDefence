"""LLM client abstraction.

Hostable backends (Bedrock + PrivateLink, Azure OpenAI private endpoint,
self-hosted Llama/Qwen) get adapter classes here later. We ship:

  - AnthropicClient: production-shape wrapper over the official Anthropic
    SDK. Streaming, retries, token budgets, prompt caching, cost tracking.
  - MockClient: deterministic canned responses, used when no API key is
    set so the demo runs offline.

Important: no community multi-provider library (LiteLLM-class). Per the
plan, each provider gets its own thin internal wrapper to keep the
supply-chain surface small.
"""
from __future__ import annotations

import json
import logging
import os
import random
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional


_log = logging.getLogger("aegis.llm")


# ---- Pricing (cents per 1M tokens). Update when Anthropic publishes
# new rates. Used for cost tracking only — never affects routing.
# Approximate, in line with public Anthropic pricing.
_PRICING = {
    "claude-sonnet-4-6":     {"input": 300,  "output": 1500, "cache_read": 30,  "cache_write": 375},
    "claude-opus-4-7":       {"input": 1500, "output": 7500, "cache_read": 150, "cache_write": 1875},
    "claude-haiku-4-5-20251001": {"input": 100, "output": 500, "cache_read": 10, "cache_write": 125},
}


@dataclass
class LLMResponse:
    text: str
    model: str
    input_tokens: int
    output_tokens: int
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0
    cost_cents: float = 0.0
    retries: int = 0
    # Populated when complete_with_tools() is called and the model
    # invokes one of the provided tools. Empty for plain completions.
    tool_calls: list[dict] = field(default_factory=list)


@dataclass
class ToolDef:
    """A tool the LLM can invoke. Mirrors Anthropic's tools API shape."""
    name: str
    description: str
    input_schema: dict  # JSON Schema for the tool's parameters


@dataclass
class TokenBudget:
    """Per-session token + cost budget. Bounds blast radius if an agent
    loops or is prompt-injected into a token-burn attack.
    """
    max_input_tokens: int = 2_000_000
    max_output_tokens: int = 200_000
    max_cost_cents: float = 5_000.0   # $50/session default

    consumed_input: int = 0
    consumed_output: int = 0
    consumed_cost: float = 0.0
    calls: int = 0

    def will_exceed(self, est_input: int, est_output: int) -> bool:
        return (
            self.consumed_input + est_input > self.max_input_tokens
            or self.consumed_output + est_output > self.max_output_tokens
            or self.consumed_cost > self.max_cost_cents
        )

    def add(self, resp: LLMResponse) -> None:
        self.consumed_input += resp.input_tokens + resp.cache_read_input_tokens + resp.cache_creation_input_tokens
        self.consumed_output += resp.output_tokens
        self.consumed_cost += resp.cost_cents
        self.calls += 1


class TokenBudgetExceeded(RuntimeError):
    pass


class DegradedModeClient:
    """Last-resort fallback when the LLM token budget is exhausted —
    the canonical attack against an agentic system is to flood it with
    alerts to burn the LLM budget, then sneak the real attack through
    while the defender is rate-limited.

    DegradedModeClient wraps a real LLMClient and a fallback
    deterministic responder. When the wrapped client raises
    TokenBudgetExceeded (or fails for any retriable reason), we emit
    a CONSERVATIVE verdict via the fallback that:

      - Never auto-allows.
      - Defaults to 'suspicious' / 'uncertain'.
      - Forces HITL on every recommended action.

    This bounds the blast radius if an attacker successfully exhausts
    the budget — the system stays available, just much more
    conservative.
    """

    name = "degraded"

    def __init__(self, primary: "LLMClient", fallback: Optional["LLMClient"] = None):
        self._primary = primary
        self._fallback = fallback or MockClient()
        self.model = f"degraded({primary.model})"
        self._tripped = False

    @property
    def tripped(self) -> bool:
        return self._tripped

    def complete(self, system: str, user: str, max_tokens: int = 2048) -> "LLMResponse":
        if not self._tripped:
            try:
                return self._primary.complete(system, user, max_tokens=max_tokens)
            except TokenBudgetExceeded:
                self._tripped = True
                _log.warning("LLM token budget exhausted — degraded-mode active for session")
            except Exception as exc:  # noqa: BLE001
                # On any other failure we still try the fallback to keep the
                # pipeline up; surface the error in the response model field.
                _log.warning("Primary LLM failed (%s) — degraded-mode for this call", exc)
        # Either tripped permanently or this call failed; use fallback +
        # post-process the verdict to be conservative.
        resp = self._fallback.complete(system, user, max_tokens=max_tokens)
        resp.text = _force_conservative_verdict(resp.text)
        resp.model = self.model
        return resp

    def complete_with_tools(self, system: str, user: str, tools: "list[ToolDef]",
                            *, max_tokens: int = 2048) -> "LLMResponse":
        # Tool-use under degraded mode: same conservative envelope.
        if not self._tripped:
            try:
                return self._primary.complete_with_tools(system, user, tools, max_tokens=max_tokens)
            except TokenBudgetExceeded:
                self._tripped = True
                _log.warning("LLM token budget exhausted — degraded-mode active (tool-use)")
            except Exception as exc:  # noqa: BLE001
                _log.warning("Primary tool-use failed (%s) — degraded-mode for this call", exc)
        resp = self._fallback.complete_with_tools(system, user, tools, max_tokens=max_tokens)
        resp.text = _force_conservative_verdict(resp.text)
        resp.model = self.model
        return resp


def _force_conservative_verdict(text: str) -> str:
    """Post-process a fallback verdict to never auto-allow and to
    force HITL on any non-monitor action. Idempotent: applying twice
    yields the same result.
    """
    try:
        obj = parse_json(text)
    except Exception:  # noqa: BLE001
        return text
    if "verdict" in obj and obj["verdict"] == "benign":
        obj["verdict"] = "uncertain"
        obj["confidence"] = min(float(obj.get("confidence", 0.5)), 0.5)
        obj["summary"] = "[degraded-mode] " + obj.get("summary", "")
    actions = obj.get("actions") or []
    for a in actions:
        if a.get("type") == "allow":
            a["type"] = "monitor"
        if a.get("type") not in ("monitor",):
            a["hitl"] = True
    return json.dumps(obj, indent=2)


class LLMClient:
    name: str = "abstract"
    model: str = "abstract"

    def complete(self, system: str, user: str, max_tokens: int = 2048) -> LLMResponse:
        raise NotImplementedError

    def complete_with_tools(self, system: str, user: str,
                            tools: "list[ToolDef]",
                            *, max_tokens: int = 2048) -> LLMResponse:
        """Default fallback: call complete() and parse JSON as if the
        first tool's input was emitted as a tool_use block. Backends
        with a real tool-use API (AnthropicClient) override this.
        """
        resp = self.complete(system, user, max_tokens=max_tokens)
        if not tools:
            return resp
        try:
            parsed = parse_json(resp.text)
            resp.tool_calls = [{"id": "json-fallback-1", "name": tools[0].name, "input": parsed}]
        except Exception:  # noqa: BLE001
            resp.tool_calls = []
        return resp


class GemmaClient(LLMClient):
    """Self-hosted Gemma client via HuggingFace transformers.

    Right model class for the meta-agent's RL component generator
    specifically: open-weight, runs in the bank's GPU cluster, no PII
    leaves the network — the data-residency story the project plan
    requires for self-hosted inference. Reward-function design and
    hyperparameter tuning are tasks open models handle reasonably
    well, so this is where Gemma earns its keep over a frontier
    proprietary model.

    Lazy import: the transformers + torch stack is multi-GB, and the
    model weights themselves are 9-27 GB depending on size. Production
    runs this in a container with weights pre-loaded; local dev usually
    falls back to MockClient via get_client() unless the model is
    already cached in HF_HOME.
    """

    name = "gemma"

    def __init__(self, model: str = "google/gemma-2-9b-it",
                 device: str = "cuda", dtype: str = "bfloat16", load_4bit: bool | None = None):
        """``model`` is a HF id, a local snapshot, or a **LoRA adapter directory** written by
        ``aegis.finetune.train`` (detected by ``adapter_config.json``: the base model named inside
        it is loaded and the adapter applied with peft). ``AEGIS_LOCAL_4BIT=1`` (default when
        bitsandbytes is installed) loads the base in 4-bit nf4 so an 8B model fits a 12 GB card."""
        try:
            from transformers import AutoTokenizer, AutoModelForCausalLM
            import torch
        except ImportError as exc:  # noqa: BLE001
            raise RuntimeError(
                "transformers + torch not installed. "
                "Install: pip install transformers torch  "
                "(plus the model weights via HF_HOME or a pre-pulled snapshot)"
            ) from exc
        import json as _json
        import os as _os
        from pathlib import Path as _Path
        self.model = model
        adapter = None
        cfg = _Path(model) / "adapter_config.json"
        base = model
        if cfg.exists():
            adapter = model
            base = _json.loads(cfg.read_text()).get("base_model_name_or_path") or model
        if load_4bit is None:
            env = _os.environ.get("AEGIS_LOCAL_4BIT")
            load_4bit = (env not in ("0", "false", "no")) if env is not None else self._have("bitsandbytes")
        kw = {"device_map": device}
        if load_4bit and self._have("bitsandbytes"):
            from transformers import BitsAndBytesConfig
            kw["quantization_config"] = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                                                           bnb_4bit_compute_dtype=getattr(torch, dtype),
                                                           bnb_4bit_use_double_quant=True)
        else:
            kw["torch_dtype"] = getattr(torch, dtype)
        self._tokenizer = AutoTokenizer.from_pretrained(adapter or base)
        self._model = AutoModelForCausalLM.from_pretrained(base, **kw)
        if adapter:
            from peft import PeftModel
            self._model = PeftModel.from_pretrained(self._model, adapter)
        self._model.eval()
        self._device = device
        self.adapter = adapter
        self.base_model = base

    @staticmethod
    def _have(mod: str) -> bool:
        import importlib.util
        return importlib.util.find_spec(mod) is not None

    def complete(self, system: str, user: str, max_tokens: int = 2048) -> LLMResponse:
        import torch
        # same rendering as training and the gate: single user turn, non-thinking mode when the
        # template supports it (Qwen3 otherwise burns the budget on a <think> block)
        from aegis.finetune.gate import _THINK, render_prompt
        messages = [{"role": "user", "content": f"{system}\n\n---\n\n{user}"}]
        prompt = render_prompt(self._tokenizer, messages, add_generation_prompt=True)
        inputs = self._tokenizer(prompt, return_tensors="pt").to(self._model.device)
        n_in = inputs.input_ids.shape[-1]
        with torch.no_grad():
            out = self._model.generate(**inputs, max_new_tokens=max_tokens, do_sample=False)
        text = self._tokenizer.decode(out[0][n_in:], skip_special_tokens=True)
        text = _THINK.sub("", text).strip()
        return LLMResponse(
            text=text, model=self.model,
            input_tokens=int(n_in),
            output_tokens=int(out.shape[-1] - n_in),
        )


class AnthropicClient(LLMClient):
    """Production-shape Anthropic client.

    Features:
      - Retries with exponential backoff on rate-limit (429) and 5xx.
      - Optional streaming (default off — non-streaming is simpler for
        agent loops with structured outputs).
      - Prompt caching for the system prompt (saves ~90% on the
        orchestrator's repeated calls).
      - Token budget tracking, with TokenBudgetExceeded on overrun.
      - Cost tracking per response using the _PRICING table.
    """

    name = "anthropic"

    def __init__(
        self,
        model: str = "claude-sonnet-4-6",
        *,
        max_retries: int = 5,
        initial_backoff_s: float = 1.0,
        max_backoff_s: float = 30.0,
        budget: Optional[TokenBudget] = None,
        cache_system_prompt: bool = True,
        stream: bool = False,
    ):
        from anthropic import Anthropic  # imported lazily
        self._anthropic_mod = __import__("anthropic")
        self._client = Anthropic()
        self.model = model
        self._max_retries = max_retries
        self._initial_backoff = initial_backoff_s
        self._max_backoff = max_backoff_s
        self._budget = budget or TokenBudget()
        self._cache_system = cache_system_prompt
        self._stream = stream

    @property
    def budget(self) -> TokenBudget:
        return self._budget

    def complete(self, system: str, user: str, max_tokens: int = 2048) -> LLMResponse:
        # Pre-check budget with a conservative estimate (1 token per ~4 chars)
        est_in = (len(system) + len(user)) // 4
        if self._budget.will_exceed(est_in, max_tokens):
            raise TokenBudgetExceeded(
                f"session budget exceeded: in={self._budget.consumed_input}, "
                f"out={self._budget.consumed_output}, cost={self._budget.consumed_cost:.1f}c"
            )

        # Build system content. Anthropic API requires a list of blocks
        # for cache_control to apply — caching pays off when system is
        # large (typical for orchestrator + injection-defense preamble).
        if self._cache_system and len(system) > 1024:
            system_param = [
                {"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}
            ]
        else:
            system_param = system

        messages = [{"role": "user", "content": user}]

        return self._call_with_retry(system_param, messages, max_tokens)

    def _call_with_retry(self, system_param, messages, max_tokens: int) -> LLMResponse:
        backoff = self._initial_backoff
        for attempt in range(self._max_retries + 1):
            try:
                return self._call_once(system_param, messages, max_tokens, retries=attempt)
            except Exception as exc:  # noqa: BLE001
                if not self._is_retriable(exc) or attempt == self._max_retries:
                    raise
                # Exponential backoff with full jitter
                sleep_s = min(backoff, self._max_backoff) * (0.5 + random.random())
                _log.warning(
                    "Anthropic call attempt %d/%d hit %s; sleeping %.1fs",
                    attempt + 1, self._max_retries + 1, type(exc).__name__, sleep_s,
                )
                time.sleep(sleep_s)
                backoff = min(backoff * 2, self._max_backoff)
        # Unreachable
        raise RuntimeError("retry loop fell through")

    # ---- Tool-use API ------------------------------------------------

    def complete_with_tools(self, system: str, user: str,
                            tools: list[ToolDef],
                            *, max_tokens: int = 2048) -> LLMResponse:
        """Tool-use variant of complete(). The model receives a tool
        catalog and may emit one or more tool_use blocks alongside text.
        Returns a response with `text` plus `tool_calls` populated.

        Same retry / budget / pricing flow as complete(); the only delta
        is the additional `tools` parameter and the extracted tool calls.
        """
        est_in = (len(system) + len(user) + sum(len(t.description) + len(str(t.input_schema)) for t in tools)) // 4
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

        tools_param = [
            {"name": t.name, "description": t.description, "input_schema": t.input_schema}
            for t in tools
        ]
        messages = [{"role": "user", "content": user}]
        return self._call_tools_with_retry(system_param, messages, tools_param, max_tokens)

    def _call_tools_with_retry(self, system_param, messages, tools_param, max_tokens: int) -> LLMResponse:
        backoff = self._initial_backoff
        for attempt in range(self._max_retries + 1):
            try:
                return self._call_tools_once(system_param, messages, tools_param, max_tokens, retries=attempt)
            except Exception as exc:  # noqa: BLE001
                if not self._is_retriable(exc) or attempt == self._max_retries:
                    raise
                sleep_s = min(backoff, self._max_backoff) * (0.5 + random.random())
                _log.warning(
                    "Anthropic tool-use attempt %d/%d hit %s; sleeping %.1fs",
                    attempt + 1, self._max_retries + 1, type(exc).__name__, sleep_s,
                )
                time.sleep(sleep_s)
                backoff = min(backoff * 2, self._max_backoff)
        raise RuntimeError("retry loop fell through")

    def _call_tools_once(self, system_param, messages, tools_param, max_tokens: int, retries: int) -> LLMResponse:
        msg = self._client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system_param,
            tools=tools_param,
            messages=messages,
        )
        text_parts: list[str] = []
        tool_calls: list[dict] = []
        for block in msg.content:
            btype = getattr(block, "type", None)
            if btype == "text":
                text_parts.append(getattr(block, "text", ""))
            elif btype == "tool_use":
                tool_calls.append({
                    "id": getattr(block, "id", ""),
                    "name": getattr(block, "name", ""),
                    "input": dict(getattr(block, "input", {}) or {}),
                })
        usage = msg.usage
        resp = LLMResponse(
            text="".join(text_parts),
            model=self.model,
            input_tokens=getattr(usage, "input_tokens", 0),
            output_tokens=getattr(usage, "output_tokens", 0),
            cache_creation_input_tokens=getattr(usage, "cache_creation_input_tokens", 0) or 0,
            cache_read_input_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0,
            retries=retries,
            tool_calls=tool_calls,
        )
        resp.cost_cents = _compute_cost(resp)
        self._budget.add(resp)
        return resp

    def _call_once(self, system_param, messages, max_tokens: int, retries: int) -> LLMResponse:
        if self._stream:
            return self._stream_call(system_param, messages, max_tokens, retries)
        msg = self._client.messages.create(
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
            retries=retries,
        )
        resp.cost_cents = _compute_cost(resp)
        self._budget.add(resp)
        return resp

    def _stream_call(self, system_param, messages, max_tokens: int, retries: int) -> LLMResponse:
        text_parts: list[str] = []
        with self._client.messages.stream(
            model=self.model,
            max_tokens=max_tokens,
            system=system_param,
            messages=messages,
        ) as stream:
            for chunk in stream.text_stream:
                text_parts.append(chunk)
            final = stream.get_final_message()
        usage = final.usage
        resp = LLMResponse(
            text="".join(text_parts),
            model=self.model,
            input_tokens=getattr(usage, "input_tokens", 0),
            output_tokens=getattr(usage, "output_tokens", 0),
            cache_creation_input_tokens=getattr(usage, "cache_creation_input_tokens", 0) or 0,
            cache_read_input_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0,
            retries=retries,
        )
        resp.cost_cents = _compute_cost(resp)
        self._budget.add(resp)
        return resp

    def _is_retriable(self, exc: Exception) -> bool:
        # Conservative: retry rate-limits, overload, transient connection issues
        retriable_names = {
            "RateLimitError", "APIConnectionError", "InternalServerError",
            "APITimeoutError", "OverloadedError",
        }
        if type(exc).__name__ in retriable_names:
            return True
        # Status-code-based check via attribute (anthropic.APIStatusError)
        status = getattr(exc, "status_code", None)
        if status in (408, 409, 429) or (status and status >= 500):
            return True
        return False


def _compute_cost(resp: LLMResponse) -> float:
    pricing = _PRICING.get(resp.model)
    if not pricing:
        return 0.0
    # All rates are cents per 1M tokens
    return (
        resp.input_tokens / 1_000_000 * pricing["input"]
        + resp.output_tokens / 1_000_000 * pricing["output"]
        + resp.cache_read_input_tokens / 1_000_000 * pricing["cache_read"]
        + resp.cache_creation_input_tokens / 1_000_000 * pricing["cache_write"]
    )


_MOCK_FALLBACK = False


def mock_fallback_active() -> bool:
    """True when a real LLM was expected but the mock is answering (never true for LLM_BACKEND=mock)."""
    return _MOCK_FALLBACK


class MockClient(LLMClient):
    """Deterministic responder for offline demos.

    Pattern-matches on the user prompt and returns a plausible structured
    JSON verdict. This is NOT a real model — it's a stand-in that
    demonstrates the agent loop without API access.
    """

    name = "mock"
    model = "mock-rules-1"

    def complete(self, system: str, user: str, max_tokens: int = 2048) -> LLMResponse:
        text = self._respond(user)
        return LLMResponse(
            text=text,
            model=self.model,
            input_tokens=len(user) // 4,
            output_tokens=len(text) // 4,
        )

    def _respond(self, user: str) -> str:
        u = user.lower()
        # Orchestrator triage
        if "triage this alert" in u:
            # Injection patterns in payload — dispatch to specialist to record as evidence
            if any(s in u for s in [
                "ignore all previous", "ignore previous instructions",
                "you are now allowed", "<system>", "</system>",
                "override the security", "new instructions:",
                "disregard previous",
            ]):
                return _json({
                    "next": "dispatch_perimeter",
                    "reason": "Possible prompt-injection in payload; specialist will record as evidence.",
                })
            if any(k in u for k in ["sqli", "union select", "' or 1=1", " or 1=1", "xss", "<script", "..%2f", "etc/passwd"]):
                return _json({
                    "next": "dispatch_perimeter",
                    "reason": "Web-layer signature in payload; need Perimeter specialist.",
                })
            # Auth/IAM signals
            if any(k in u for k in [
                '"prev_geo"', '"curr_geo"', '"mfa_failures"', '"device_fingerprint"',
                '"observed":', "impossible_travel", "ato attempt",
            ]):
                return _json({
                    "next": "dispatch_auth",
                    "reason": "Identity / auth signals present; route to Auth/IAM specialist.",
                })
            # EDR/Host signals
            if any(k in u for k in [
                '"parent_process"', '"child_process"', '"cmdline"', '"src_zone"',
                '"file_hash"', '"dst_zone"', "lateral_movement", "process tree",
            ]):
                return _json({
                    "next": "dispatch_edr",
                    "reason": "Host / process signals present; route to EDR specialist.",
                })
            # API-abuse signals (BOLA / schema drift / volumetric / auth boundary)
            if any(k in u for k in [
                '"principal_id"', '"accessed_object_owner"', '"http_method"',
                '"observed_per_min"', '"params":', '"role":',
            ]):
                return _json({
                    "next": "dispatch_api_abuse",
                    "reason": "API-abuse signals present (BOLA / schema / volumetric); route to API Abuse specialist.",
                })
            # Transaction/Fraud signals
            if any(k in u for k in [
                '"beneficiary_account"', '"amount_inr"', '"rail":',
                '"recent_24h_count"', '"recent_amounts_inr"', '"sender_geo"',
            ]):
                return _json({
                    "next": "dispatch_transaction",
                    "reason": "Transaction signals present (mule/velocity/rail/AML); route to Transaction specialist.",
                })
            # DLP / data-exfiltration signals
            if any(k in u for k in [
                '"rows_returned"', '"observed_mb_last_hour"',
                '"recipients"', '"attachment_summary"',
                '"table"', '"sensitivity"', '"egress_volume"',
                "dlp", "purview", "forcepoint",
            ]):
                return _json({
                    "next": "dispatch_dlp",
                    "reason": "Data-egress / bulk-read signals present; route to DLP specialist.",
                })
            # Email / phishing signals
            if any(k in u for k in [
                '"from_address"', '"from_display"', '"headers"',
                '"subject"', '"body"', '"attachments"',
                '"spf"', '"dkim"', '"dmarc"',
                "mimecast", "proofpoint", "m365 atp", "exchange trace",
            ]):
                return _json({
                    "next": "dispatch_email",
                    "reason": "Email / phishing signals present; route to Email specialist.",
                })
            # Mobile-app signals
            if any(k in u for k in [
                '"device_telemetry"', '"sdk_telemetry"',
                '"is_jailbroken"', '"is_rooted"', '"frida_detected"',
                '"mno_signals"', '"sim_swap"',
                "verimatrix", "promon shield", "approov",
            ]):
                return _json({
                    "next": "dispatch_mobile",
                    "reason": "Mobile-device-integrity signals present; route to Mobile specialist.",
                })
            # Wireless signals
            if any(k in u for k in [
                '"ap_record"', '"bssid"', '"ssid"',
                '"deauth_metrics"', '"wpa_signals"',
                "aruba clearpass", "cisco wlc", "meraki", "mist",
            ]):
                return _json({
                    "next": "dispatch_wireless",
                    "reason": "Wireless-infrastructure signals present; route to Wireless specialist.",
                })
            # Cloud control-plane signals (CloudTrail / Azure Activity / GCP Audit
            # / OpenStack Keystone+Neutron / firewall audit)
            if any(k in u for k in [
                '"eventname"', '"operationname"', '"useridentity"',
                '"requestparameters"', "cloudtrail", "azure activity",
                "panorama:", "checkpoint:", "juniper:",
                '"iam:createaccesskey"', '"putbucketpolicy"',
                '"authorizesecuritygroupingress"', '"stoplogging"',
                '"deletetrail"', '"disablekey"',
                # OpenStack
                '"event_type"', "openstack ", "identity.role_assignment",
                "network.security_group_rule", "compute.instance.create",
            ]):
                return _json({
                    "next": "dispatch_cloud_controlplane",
                    "reason": "Cloud control-plane signals present (IAM/network/KMS/logging admin actions); route to Cloud Control-Plane specialist.",
                })
            # Read anomaly_score directly from alert JSON
            m = re.search(r'"anomaly_score":\s*([\d.]+)', u)
            anom = float(m.group(1)) if m else None
            if anom is not None and anom < 0.30:
                return _json({
                    "next": "auto_close",
                    "reason": f"Anomaly score {anom} below threshold; baseline-matching behavior.",
                    "verdict": "benign",
                    "confidence": 0.88,
                })
            return _json({
                "next": "dispatch_perimeter",
                "reason": "Ambiguous; need deeper investigation.",
            })

        # Perimeter specialist verdict
        if "perimeter agent investigation" in u:
            attack_signals = sum(
                1 for s in [
                    "union select", "' or 1=1", " or 1=1", "<script", "..%2f",
                    "etc/passwd", "etc/shadow", "$(", "`whoami`", "; cat", "exec(",
                    "<?php", "$_get[", "$_post[", "system($", "shell_exec(",
                ] if s in u
            )
            # Pick up tool-reported primitive count
            m = re.search(r'"primitive_count":\s*(\d+)', u)
            if m:
                attack_signals += int(m.group(1))
            if "ip_reputation" in u and "known_malicious" in u:
                attack_signals += 2
            # Injection-defense evidence counts as a signal in itself.
            # The defender does NOT act on the injected content, but
            # records the attempt. Treat as suspicious unless other signals push higher.
            # Also catches unicode-obfuscation (U+3000 padding / RLO / zero-width)
            # via the heuristic flag the perimeter agent prepends to user_msg.
            injection_present = (
                "prompt-injection patterns detected" in u
                or "unicode-obfuscation chars present" in u
                or any(s in u for s in [
                    "ignore all previous", "ignore previous instructions",
                    "<system>", "</system>", "you are now allowed",
                    "override the security", "new instructions:",
                    "disregard previous",
                ])
            )
            if attack_signals >= 3:
                return _json({
                    "verdict": "malicious",
                    "confidence": 0.93,
                    "summary": "Confirmed attack: payload contains exploit primitives, IP has prior abuse.",
                    "actions": [
                        {"type": "block", "target": "source_ip", "hitl": True, "confidence": 0.93},
                    ],
                })
            if attack_signals >= 1 or injection_present:
                summary = (
                    "Prompt-injection attempt observed in HTTP fields; "
                    "treating as attack signal but not acting on injected instructions."
                    if injection_present and attack_signals == 0
                    else "Attack primitives observed without strong corroboration; "
                         "could be scanner or real attempt."
                )
                return _json({
                    "verdict": "suspicious",
                    "confidence": 0.65,
                    "summary": summary,
                    "actions": [
                        {"type": "monitor", "target": "source_ip", "hitl": False, "confidence": 0.65},
                        {"type": "challenge", "target": "session", "hitl": False, "confidence": 0.6},
                    ],
                })
            return _json({
                "verdict": "benign",
                "confidence": 0.82,
                "summary": "No exploit primitives in payload, IP reputation clean, request matches user baseline.",
                "actions": [
                    {"type": "allow", "target": "request", "hitl": False, "confidence": 0.82},
                ],
            })

        # Auth specialist verdict
        if "auth/iam agent investigation" in u:
            impossible = '"impossible": true' in u
            burst = '"burst_pattern": true' in u
            unknown_device = '"known": false' in u
            deviations = u.count('"deviations": [')
            # Privileged-baseline signals
            unticketed_admin = "high_impact_action_without_change_ticket" in u
            outside_bastion = "admin_login_outside_bastion_subnet" in u
            admin_drift = "admin_behavioral_drift" in u
            is_privileged_role = '"is_privileged": true' in u
            login_from_bastion = "login_from_bastion_subnet" in u
            has_admin_normal_signals = (
                is_privileged_role
                and login_from_bastion
                and not (unticketed_admin or outside_bastion or admin_drift)
            )

            # Privileged-aware paths come first so they short-circuit the
            # normal logic — the whole point of the privileged baseline
            # is that admin behavior doesn't follow the retail rules.
            if unticketed_admin and (outside_bastion or admin_drift):
                return _json({
                    "verdict": "malicious",
                    "confidence": 0.93,
                    "summary": "Privileged account: high-impact change without ticket + bastion/biometric anomaly — compromised admin pattern.",
                    "actions": [
                        {"type": "lock_account", "target": "user_id", "hitl": True, "confidence": 0.93},
                        {"type": "revoke_sessions", "target": "user_id", "hitl": True, "confidence": 0.93},
                        {"type": "escalate_to_fraud_team", "target": "user_id", "hitl": True, "confidence": 0.93},
                    ],
                })
            if unticketed_admin:
                return _json({
                    "verdict": "suspicious",
                    "confidence": 0.78,
                    "summary": "Privileged account ran high-impact action with no change ticket; verify with admin owner.",
                    "actions": [
                        {"type": "challenge", "target": "session", "hitl": False, "confidence": 0.78},
                        {"type": "monitor", "target": "user_id", "hitl": False, "confidence": 0.78},
                    ],
                })
            if has_admin_normal_signals and not (impossible or burst):
                # Privileged-aware: bastion-subnet admin with no red flags
                # is normal admin work; bastion enforces device cert + MFA
                # so unknown-device-fingerprint here is a known artifact
                # of admin device rotation, not a credential-theft signal.
                return _json({
                    "verdict": "benign",
                    "confidence": 0.88,
                    "summary": "Activity matches admin's privileged baseline (bastion subnet, no red flags); suppressing retail-baseline FPs.",
                    "actions": [{"type": "allow", "target": "session", "hitl": False, "confidence": 0.88}],
                })

            if impossible:
                return _json({
                    "verdict": "malicious",
                    "confidence": 0.92,
                    "summary": "Impossible-travel detected; high-confidence ATO indicator.",
                    "actions": [
                        {"type": "lock_account", "target": "user_id", "hitl": True, "confidence": 0.92},
                        {"type": "revoke_sessions", "target": "user_id", "hitl": True, "confidence": 0.92},
                    ],
                })
            if burst and unknown_device:
                return _json({
                    "verdict": "malicious",
                    "confidence": 0.88,
                    "summary": "MFA burst pattern from unknown device; credential-stuffing or ATO.",
                    "actions": [
                        {"type": "lock_account", "target": "user_id", "hitl": True, "confidence": 0.88},
                    ],
                })
            if burst or unknown_device:
                return _json({
                    "verdict": "suspicious",
                    "confidence": 0.65,
                    "summary": "Single auth-anomaly signal; step-up auth recommended.",
                    "actions": [
                        {"type": "challenge", "target": "session", "hitl": False, "confidence": 0.65},
                        {"type": "monitor", "target": "user_id", "hitl": False, "confidence": 0.65},
                    ],
                })
            return _json({
                "verdict": "benign",
                "confidence": 0.85,
                "summary": "No strong auth-anomaly signals.",
                "actions": [{"type": "allow", "target": "session", "hitl": False, "confidence": 0.85}],
            })

        # EDR specialist verdict
        if "edr agent investigation" in u:
            ioc_n_match = re.search(r'"n":\s*(\d+)', u)
            ioc_n = int(ioc_n_match.group(1)) if ioc_n_match else 0
            susp_pair = '"suspicious_pair": true' in u
            cmdline_indicators = '"cmdline_indicators": true' in u
            cross_zone_admin = '"cross_zone_admin": true' in u
            file_drift = '"drifted": true' in u
            dns_exfil = '"exfil_likely": true' in u
            severity = sum([ioc_n > 0, susp_pair, cmdline_indicators, cross_zone_admin, file_drift, dns_exfil])
            if severity >= 3 or (ioc_n > 0 and (susp_pair or cmdline_indicators)):
                return _json({
                    "verdict": "malicious",
                    "confidence": 0.94,
                    "summary": "Multiple corroborating host signals; intrusion confirmed.",
                    "actions": [
                        {"type": "isolate", "target": "host", "hitl": True, "confidence": 0.94},
                        {"type": "trigger_self_heal", "target": "host", "hitl": True, "confidence": 0.94},
                    ],
                })
            if severity >= 1:
                return _json({
                    "verdict": "suspicious",
                    "confidence": 0.7,
                    "summary": "Single host-anomaly signal; investigate further.",
                    "actions": [
                        {"type": "monitor", "target": "host", "hitl": False, "confidence": 0.7},
                        {"type": "kill_process", "target": "process", "hitl": True, "confidence": 0.7},
                    ],
                })
            return _json({
                "verdict": "benign",
                "confidence": 0.85,
                "summary": "Host activity within baseline.",
                "actions": [{"type": "allow", "target": "host", "hitl": False, "confidence": 0.85}],
            })

        # API Abuse specialist verdict
        if "api abuse agent investigation" in u:
            bola = '"is_bola_pattern": true' in u
            schema_drift = '"drift": true' in u
            extra_unexpected = u.count('"extra_unexpected": ["')
            volumetric_anomaly = '"anomaly": true' in u
            ratio_match = re.search(r'"ratio":\s*([\d.]+)', u)
            ratio = float(ratio_match.group(1)) if ratio_match else 0.0
            auth_violation = '"violation": true' in u
            severity = sum([bola, schema_drift, volumetric_anomaly, auth_violation])
            if (bola and (auth_violation or volumetric_anomaly)) or severity >= 3:
                return _json({
                    "verdict": "malicious",
                    "confidence": 0.92,
                    "summary": "Strong API-abuse signature: BOLA + auth/volumetric corroboration.",
                    "actions": [
                        {"type": "lock_account", "target": "principal_id", "hitl": True, "confidence": 0.92},
                        {"type": "revoke_sessions", "target": "principal_id", "hitl": True, "confidence": 0.92},
                    ],
                })
            if bola or auth_violation or (volumetric_anomaly and ratio >= 5.0):
                return _json({
                    "verdict": "suspicious",
                    "confidence": 0.7,
                    "summary": "Single API-abuse signal; step-up auth + monitor.",
                    "actions": [
                        {"type": "challenge", "target": "session", "hitl": False, "confidence": 0.7},
                        {"type": "monitor", "target": "principal_id", "hitl": False, "confidence": 0.7},
                    ],
                })
            return _json({
                "verdict": "benign",
                "confidence": 0.85,
                "summary": "API call within authorization boundaries; no abuse pattern.",
                "actions": [{"type": "allow", "target": "request", "hitl": False, "confidence": 0.85}],
            })

        # Transaction/Fraud specialist verdict
        if "transaction/fraud agent investigation" in u:
            mule = '"is_mule_shape": true' in u
            high_risk_geo = '"is_high_risk_geo": true' in u
            new_beneficiary = '"is_new_beneficiary": true' in u
            structuring = '"structuring_pattern": true' in u
            novel_rail = '"novel_rail": true' in u
            high_value = '"high_value": true' in u
            sanctioned = '"sanctioned": true' in u
            ratio_match = re.search(r'"count_ratio_p99":\s*([\d.]+)', u)
            count_ratio = float(ratio_match.group(1)) if ratio_match else 0.0
            amt_match = re.search(r'"amount_ratio_p99":\s*([\d.]+)', u)
            amt_ratio = float(amt_match.group(1)) if amt_match else 0.0

            severity = sum([mule, high_risk_geo, structuring, sanctioned,
                            novel_rail and high_value,
                            count_ratio >= 5.0 or amt_ratio >= 5.0])

            if severity >= 3 or sanctioned or (mule and high_risk_geo):
                return _json({
                    "verdict": "malicious",
                    "confidence": 0.94,
                    "summary": "Strong fraud signature: mule + cross-border or sanctioned beneficiary or AML structuring.",
                    "actions": [
                        {"type": "block", "target": "transaction_id", "hitl": True, "confidence": 0.94},
                        {"type": "escalate_to_fraud_team", "target": "user_id", "hitl": True, "confidence": 0.94},
                    ],
                })
            if severity >= 1 or count_ratio >= 2.0 or amt_ratio >= 2.0:
                return _json({
                    "verdict": "suspicious",
                    "confidence": 0.72,
                    "summary": "Transaction-anomaly signal; hold pending step-up auth + fraud-ops review.",
                    "actions": [
                        {"type": "hold", "target": "transaction_id", "hitl": True, "confidence": 0.72},
                        {"type": "challenge", "target": "session", "hitl": False, "confidence": 0.72},
                    ],
                })
            return _json({
                "verdict": "benign",
                "confidence": 0.88,
                "summary": "Transaction within customer baseline; no fraud indicators.",
                "actions": [{"type": "allow", "target": "transaction_id", "hitl": False, "confidence": 0.88}],
            })

        # Cloud control-plane specialist verdict
        if "cloud control-plane agent investigation" in u:
            iam_risk_match = re.search(r'"risk_score":\s*(\d+)', u)
            iam_risk = int(iam_risk_match.group(1)) if iam_risk_match else 0
            grants_public = '"grants_public": true' in u
            encryption_removed = '"encryption_removed": true' in u
            opens_internet_sensitive = '"opens_internet_to_sensitive_port": true' in u
            unknown_peer = '"unknown_peer": true' in u
            kms_high_risk = '"high_risk": true' in u
            logging_disabled = '"logging_disabled": true' in u
            firewall_weakens = '"weakens_posture": true' in u
            wildcard = '"has_wildcard_policy": true' in u
            dangerous_role = '"has_dangerous_role_grant": true' in u
            # K8s + cost-abuse + HSM additions
            k8s_rbac_widened = '"rbac_widened_to_admin": true' in u
            k8s_dangerous = '"dangerous_pod_features": ["' in u
            k8s_exec = '"exec_or_portforward": true' in u
            burst_pattern = '"burst_pattern": true' in u
            gpu_burst = '"is_gpu_instance": true' in u and burst_pattern
            hsm_high_risk = '"hsm_audit"' in u and '"high_risk": true' in u

            if hsm_high_risk:
                return _json({
                    "verdict": "malicious",
                    "confidence": 0.97,
                    "summary": "HSM key export / delete / audit-disable — outside any legitimate key ceremony. Highest-impact event class.",
                    "actions": [
                        {"type": "block", "target": "principal", "hitl": True, "confidence": 0.97},
                        {"type": "lock_account", "target": "principal", "hitl": True, "confidence": 0.97},
                        {"type": "escalate", "target": "principal", "hitl": True, "confidence": 0.97},
                        {"type": "snapshot_forensic", "target": "principal", "hitl": True, "confidence": 0.97},
                    ],
                })
            if k8s_rbac_widened:
                return _json({
                    "verdict": "malicious",
                    "confidence": 0.94,
                    "summary": "K8s RBAC binding widened to cluster-admin — privilege escalation tradecraft.",
                    "actions": [
                        {"type": "block", "target": "principal", "hitl": True, "confidence": 0.94},
                        {"type": "revoke_sessions", "target": "principal", "hitl": True, "confidence": 0.94},
                    ],
                })
            if gpu_burst or (burst_pattern and not (k8s_exec or k8s_dangerous)):
                return _json({
                    "verdict": "malicious" if gpu_burst else "suspicious",
                    "confidence": 0.92 if gpu_burst else 0.7,
                    "summary": (
                        "GPU instance burst — classic post-compromise crypto-mining shape."
                        if gpu_burst
                        else "Compute spin-up burst beyond normal admin workflow."
                    ),
                    "actions": [
                        {"type": "block_export", "target": "principal", "hitl": True, "confidence": 0.92 if gpu_burst else 0.7},
                        {"type": "monitor", "target": "principal", "hitl": False, "confidence": 0.7},
                    ],
                })

            severity = sum([
                iam_risk >= 2 or wildcard or dangerous_role,
                grants_public or encryption_removed,
                opens_internet_sensitive or unknown_peer,
                kms_high_risk,
                logging_disabled,
                firewall_weakens,
                k8s_exec or k8s_dangerous,
            ])

            if logging_disabled:
                # Disabling audit logging is never a routine admin task —
                # treat as malicious-by-default per the system prompt.
                return _json({
                    "verdict": "malicious",
                    "confidence": 0.95,
                    "summary": "Audit logging disabled — attacker tradecraft (hide tracks before campaign).",
                    "actions": [
                        {"type": "block", "target": "principal", "hitl": True, "confidence": 0.95},
                        {"type": "revoke_sessions", "target": "principal", "hitl": True, "confidence": 0.95},
                        {"type": "escalate", "target": "principal", "hitl": True, "confidence": 0.95},
                    ],
                })
            if firewall_weakens:
                # ANY-ANY firewall rule or disabled IPS profile = flat negation
                # of the perimeter; never legitimate change-control output.
                return _json({
                    "verdict": "malicious",
                    "confidence": 0.92,
                    "summary": "Firewall posture-weakening rule (ANY-ANY allow / disabled IPS profile).",
                    "actions": [
                        {"type": "block", "target": "principal", "hitl": True, "confidence": 0.92},
                        {"type": "escalate", "target": "principal", "hitl": True, "confidence": 0.92},
                    ],
                })
            if severity >= 3 or (grants_public and opens_internet_sensitive):
                return _json({
                    "verdict": "malicious",
                    "confidence": 0.92,
                    "summary": "Multiple corroborating control-plane posture-weakening signals; intrusion or insider abuse.",
                    "actions": [
                        {"type": "lock_account", "target": "principal", "hitl": True, "confidence": 0.92},
                        {"type": "escalate", "target": "principal", "hitl": True, "confidence": 0.92},
                    ],
                })
            if severity >= 1:
                return _json({
                    "verdict": "suspicious",
                    "confidence": 0.7,
                    "summary": "Single posture-weakening signal in control plane; verify against change ticket.",
                    "actions": [
                        {"type": "challenge", "target": "principal", "hitl": False, "confidence": 0.7},
                        {"type": "monitor", "target": "principal", "hitl": False, "confidence": 0.7},
                    ],
                })
            return _json({
                "verdict": "benign",
                "confidence": 0.85,
                "summary": "Control-plane action consistent with routine admin work; no posture weakening.",
                "actions": [{"type": "allow", "target": "principal", "hitl": False, "confidence": 0.85}],
            })

        # DLP specialist verdict
        if "dlp agent investigation" in u:
            critical_secret = '"critical_secret": true' in u
            bulk_anomaly = '"is_bulk_anomaly": true' in u
            egress_anomaly = '"is_egress_anomaly": true' in u
            external_with_attach = '"has_attachment": true' in u and '"external_count":' in u and '"external_count": 0' not in u
            hr_risk = '"has_hr_risk": true' in u
            sensitive_pii_match = re.search(r'"pii_count":\s*(\d+)', u)
            pii_count = int(sensitive_pii_match.group(1)) if sensitive_pii_match else 0

            if critical_secret:
                return _json({
                    "verdict": "malicious",
                    "confidence": 0.95,
                    "summary": "Critical secret material in egress payload (private key / AWS key / GitHub token).",
                    "actions": [
                        {"type": "block_export", "target": "principal", "hitl": True, "confidence": 0.95},
                        {"type": "revoke_sessions", "target": "principal", "hitl": True, "confidence": 0.95},
                        {"type": "snapshot_forensic", "target": "principal", "hitl": True, "confidence": 0.95},
                    ],
                })
            if hr_risk and (bulk_anomaly or egress_anomaly or pii_count >= 5):
                return _json({
                    "verdict": "malicious",
                    "confidence": 0.93,
                    "summary": "Insider-threat pattern: HR risk flag + bulk-read / egress anomaly. Departing-employee data theft shape.",
                    "actions": [
                        {"type": "block_export", "target": "principal", "hitl": True, "confidence": 0.93},
                        {"type": "revoke_sessions", "target": "principal", "hitl": True, "confidence": 0.93},
                        {"type": "escalate_to_hr", "target": "principal", "hitl": True, "confidence": 0.93},
                        {"type": "snapshot_forensic", "target": "principal", "hitl": True, "confidence": 0.93},
                    ],
                })
            severity = sum([
                bulk_anomaly,
                egress_anomaly,
                external_with_attach,
                pii_count >= 50,
                hr_risk,
            ])
            if severity >= 3:
                return _json({
                    "verdict": "malicious",
                    "confidence": 0.92,
                    "summary": "Multiple corroborating data-exfil signals; treat as compromised admin smash-grab.",
                    "actions": [
                        {"type": "block_export", "target": "principal", "hitl": True, "confidence": 0.92},
                        {"type": "revoke_sessions", "target": "principal", "hitl": True, "confidence": 0.92},
                    ],
                })
            if severity >= 1:
                return _json({
                    "verdict": "suspicious",
                    "confidence": 0.7,
                    "summary": "Single data-egress signal; redact + throttle pending review.",
                    "actions": [
                        {"type": "redact", "target": "egress_payload", "hitl": False, "confidence": 0.7},
                        {"type": "throttle", "target": "principal", "hitl": False, "confidence": 0.7},
                        {"type": "monitor", "target": "principal", "hitl": False, "confidence": 0.7},
                    ],
                })
            return _json({
                "verdict": "benign",
                "confidence": 0.85,
                "summary": "Egress within baseline; no sensitive-data leakage indicators.",
                "actions": [{"type": "allow", "target": "request", "hitl": False, "confidence": 0.85}],
            })

        # Email/phishing specialist verdict
        if "email/phishing agent investigation" in u:
            display_spoof = '"is_spoof": true' in u
            macro_attach = re.search(r'"macro":\s*\[\s*"', u) is not None
            dangerous_attach = re.search(r'"dangerous":\s*\[\s*"', u) is not None
            lookalike = '"matches": [{"observed":' in u
            phish_score_match = re.search(r'"phish_lexical_score":\s*(\d+)', u)
            phish_score = int(phish_score_match.group(1)) if phish_score_match else 0
            blast_pattern = '"is_blast_pattern": true' in u
            header_fail_match = re.search(r'"fail_count":\s*(\d+)', u)
            header_fails = int(header_fail_match.group(1)) if header_fail_match else 0

            severity = sum([
                display_spoof,
                macro_attach or dangerous_attach,
                lookalike,
                phish_score >= 4,
                blast_pattern,
                header_fails >= 2,
            ])
            if blast_pattern and header_fails >= 1:
                return _json({
                    "verdict": "malicious",
                    "confidence": 0.94,
                    "summary": "Internal account blasting external mail with auth fails — sender account is compromised.",
                    "actions": [
                        {"type": "lock_account", "target": "internal_sender", "hitl": True, "confidence": 0.94},
                        {"type": "revoke_sessions", "target": "internal_sender", "hitl": True, "confidence": 0.94},
                        {"type": "recall_message", "target": "message_id", "hitl": True, "confidence": 0.94},
                    ],
                })
            if severity >= 3 or (display_spoof and (macro_attach or dangerous_attach)):
                return _json({
                    "verdict": "malicious",
                    "confidence": 0.92,
                    "summary": "Multiple phishing indicators including spoof + dangerous attachment.",
                    "actions": [
                        {"type": "quarantine_message", "target": "message_id", "hitl": False, "confidence": 0.92},
                        {"type": "block", "target": "from_address", "hitl": True, "confidence": 0.92},
                    ],
                })
            if severity >= 1:
                return _json({
                    "verdict": "suspicious",
                    "confidence": 0.7,
                    "summary": "Single phishing indicator; quarantine pending review.",
                    "actions": [
                        {"type": "quarantine_message", "target": "message_id", "hitl": False, "confidence": 0.7},
                        {"type": "notify_user", "target": "recipient", "hitl": False, "confidence": 0.7},
                    ],
                })
            return _json({
                "verdict": "benign",
                "confidence": 0.85,
                "summary": "No phishing indicators above threshold.",
                "actions": [{"type": "allow", "target": "message_id", "hitl": False, "confidence": 0.85}],
            })

        # Mobile-app specialist verdict
        if "mobile-app agent investigation" in u:
            tampered = '"tampered": true' in u
            repackaged = '"repackaged": true' in u
            pinning_failed = '"ssl_pinning_failed": true' in u
            sim_swap_recent = '"swap_within_24h": true' in u
            porting = '"number_porting_in_progress": true' in u
            overlay = '"screen_overlay_detected": true' in u
            side_loaded = '"side_loaded": true' in u
            impossible_velocity = '"impossible_velocity": true' in u

            if (tampered or repackaged) and (sim_swap_recent or porting):
                return _json({
                    "verdict": "malicious",
                    "confidence": 0.94,
                    "summary": "Mobile-ATO chain: tampered device + recent SIM swap = canonical mobile takeover pattern.",
                    "actions": [
                        {"type": "lock_account", "target": "user_id", "hitl": True, "confidence": 0.94},
                        {"type": "force_logout", "target": "user_id", "hitl": False, "confidence": 0.94},
                        {"type": "escalate_to_fraud_team", "target": "user_id", "hitl": True, "confidence": 0.94},
                    ],
                })
            severity = sum([
                tampered, repackaged, pinning_failed, sim_swap_recent, porting,
                overlay, side_loaded, impossible_velocity,
            ])
            if overlay or severity >= 3:
                return _json({
                    "verdict": "malicious",
                    "confidence": 0.92,
                    "summary": "Mobile device-integrity violation — overlay attack or multiple corroborating tamper signals.",
                    "actions": [
                        {"type": "force_logout", "target": "user_id", "hitl": False, "confidence": 0.92},
                        {"type": "lock_account", "target": "user_id", "hitl": True, "confidence": 0.92},
                    ],
                })
            if severity >= 1:
                return _json({
                    "verdict": "suspicious",
                    "confidence": 0.7,
                    "summary": "Single mobile-integrity signal; force step-up auth on next critical action.",
                    "actions": [
                        {"type": "challenge", "target": "session", "hitl": False, "confidence": 0.7},
                        {"type": "monitor", "target": "user_id", "hitl": False, "confidence": 0.7},
                    ],
                })
            return _json({
                "verdict": "benign",
                "confidence": 0.85,
                "summary": "Mobile device integrity within baseline.",
                "actions": [{"type": "allow", "target": "session", "hitl": False, "confidence": 0.85}],
            })

        # Wireless specialist verdict
        if "wireless agent investigation" in u:
            rogue_with_authorized = '"rogue_with_authorized_ssid": true' in u
            twin_targets_pos = '"targets_pos_ssid": true' in u and '"twin_match": true' in u
            twin_match = '"twin_match": true' in u
            captive_portal = '"captive_portal": true' in u
            burst = '"burst_pattern": true' in u
            wpa_active = '"active_attack": true' in u
            if twin_targets_pos or rogue_with_authorized:
                return _json({
                    "verdict": "malicious",
                    "confidence": 0.94,
                    "summary": "Rogue AP impersonating authorized SSID — physical-presence attack on bank infrastructure.",
                    "actions": [
                        {"type": "block", "target": "bssid", "hitl": True, "confidence": 0.94},
                        {"type": "escalate", "target": "physical_security", "hitl": True, "confidence": 0.94},
                    ],
                })
            severity = sum([twin_match, captive_portal, burst, wpa_active])
            if severity >= 2 or wpa_active:
                return _json({
                    "verdict": "malicious",
                    "confidence": 0.9,
                    "summary": "Active wireless attack (WPA capture / evil-twin with captive portal / deauth flood).",
                    "actions": [
                        {"type": "block", "target": "bssid", "hitl": True, "confidence": 0.9},
                    ],
                })
            if severity >= 1:
                return _json({
                    "verdict": "suspicious",
                    "confidence": 0.7,
                    "summary": "Single wireless-attack indicator; locate AP via walkdown.",
                    "actions": [
                        {"type": "monitor", "target": "bssid", "hitl": False, "confidence": 0.7},
                        {"type": "escalate", "target": "physical_security", "hitl": True, "confidence": 0.7},
                    ],
                })
            return _json({
                "verdict": "benign",
                "confidence": 0.85,
                "summary": "Wireless event within baseline; likely guest device hotspot or misconfiguration.",
                "actions": [{"type": "allow", "target": "bssid", "hitl": False, "confidence": 0.85}],
            })

        # Vulnerability discovery summary
        if "vulnerability discovery summary" in u:
            crit_n = u.count('"severity": "critical"')
            high_n = u.count('"severity": "high"')
            return _json({
                "summary": f"Found {crit_n} critical and {high_n} high-severity findings; prioritize CVE patches first.",
                "findings": [],
            })

        # Voting agent (second model)
        if "vote on this verdict" in u:
            # Extract proposed verdict and concur 80% of the time, dissent on borderline.
            if "uncertain" in u or "0.5" in u or "0.6" in u:
                return _json({"concur": False, "reason": "Confidence too low; recommend human review."})
            return _json({"concur": True, "reason": "Independent review reaches same verdict."})

        return _json({"verdict": "uncertain", "confidence": 0.5, "summary": "Mock fallback."})


def _json(d: dict) -> str:
    return json.dumps(d, indent=2)


def _promoted_model() -> str | None:
    """Adapter path from the retrain pipeline's promotion pointer (``AEGIS_MODEL_POINTER``), if any."""
    ptr = os.environ.get("AEGIS_MODEL_POINTER", "")
    if not ptr:
        return None
    try:
        import json as _json
        with open(ptr, encoding="utf-8") as fh:
            cur = _json.load(fh)
        adapter = cur.get("adapter")
        if adapter and os.path.isdir(adapter):
            from aegis.finetune.digest import verify_adapter
            ok, why = verify_adapter(adapter, cur.get("sha256"))
            if not ok and os.environ.get("AEGIS_ALLOW_UNVERIFIED_MODEL", "") != "1":
                # the weights on disk are not the ones a human approved, or nobody fingerprinted them: never load
                _log.error("promoted adapter %s refused: %s; falling back to AEGIS_MODEL", adapter, why)
                return None
            if not ok:
                _log.warning("promoted adapter %s loaded UNVERIFIED (%s) — AEGIS_ALLOW_UNVERIFIED_MODEL=1", adapter, why)
            _log.info("using promoted triage model %s (run %s, approved by %s)", adapter, cur.get("run"), cur.get("approved_by"))
            return adapter
        _log.warning("AEGIS_MODEL_POINTER %s names no usable adapter; falling back to AEGIS_MODEL", ptr)
    except Exception as exc:  # noqa: BLE001 — a bad pointer keeps the configured model, never the SOC down
        _log.warning("AEGIS_MODEL_POINTER unreadable (%s); falling back to AEGIS_MODEL", exc)
    return None


def get_client(
    prefer: Optional[str] = None,
    *,
    budget: Optional[TokenBudget] = None,
    model: Optional[str] = None,
    stream: bool = False,
) -> LLMClient:
    """Return the best available client. MockClient if no creds.

    The optional `budget` argument lets you share a TokenBudget across
    primary + voter clients in the same orchestrator session — both
    consume from the same envelope, and either will raise
    TokenBudgetExceeded when the cap is hit.
    """
    pref = (prefer or os.environ.get("LLM_BACKEND", "auto")).lower()
    inner: LLMClient
    if pref == "mock":
        inner = MockClient()
    elif pref in ("gemma", "local"):
        # AEGIS_MODEL may name a HF id, a local snapshot or a fine-tuned LoRA adapter directory;
        # AEGIS_MODEL_POINTER names the retrain pipeline's current.json (roadmap 3.5) — the
        # human-promoted adapter wins, so a promotion takes effect at the next restart, not by editing env
        try:
            inner = GemmaClient(model=model or _promoted_model() or os.environ.get("AEGIS_MODEL") or "google/gemma-2-9b-it")
        except Exception as exc:  # noqa: BLE001
            _log.warning("GemmaClient unavailable (%s) — falling back to mock", exc)
            inner = MockClient()
    elif pref in ("vllm", "tgi"):
        # the fine-tuned Qwen served privately over an OpenAI-compatible endpoint (production
        # throughput path; the local backend is dev/eval). The served model / LoRA-adapter name
        # comes from AEGIS_VLLM_MODEL (or the `model` arg); mapping a C3-promoted adapter to its
        # served name is wired with the GPU side, so _promoted_model() (a local path) is not used here.
        try:
            from .vllm_client import VLLMClient, VLLMConfig
            cfg = VLLMConfig.from_env()
            if model:
                cfg.model = model
            inner = VLLMClient(cfg, budget=budget)
        except Exception as exc:  # noqa: BLE001
            _log.error("VLLMClient unavailable (%s: %s) — falling back to mock", type(exc).__name__, str(exc)[:160])
            inner = MockClient()
    elif pref in ("anthropic", "auto") and os.environ.get("ANTHROPIC_API_KEY"):
        try:
            kwargs: dict[str, Any] = {"stream": stream}
            if budget is not None:
                kwargs["budget"] = budget
            if model:
                kwargs["model"] = model
            inner = AnthropicClient(**kwargs)
        except Exception as exc:  # noqa: BLE001
            _log.error("AnthropicClient unavailable (%s: %s) — primary LLM is now the MOCK client; verdicts are placeholders until this is fixed", type(exc).__name__, str(exc)[:160])
            inner = MockClient()
    else:
        if pref != "mock":
            # "auto" with no API key (a missing secret, an unmounted env file) used to fall to the mock
            # silently — and the mock auto-closes low-anomaly alerts as benign. Say so loudly, and mark it so
            # the orchestrator refuses the auto-close shortcut while it lasts.
            _log.error("no LLM configured (LLM_BACKEND=%s, ANTHROPIC_API_KEY unset): the primary LLM is the MOCK "
                       "client — verdicts are placeholders and auto-close is disabled until this is fixed", pref)
        inner = MockClient()
    if isinstance(inner, MockClient) and pref != "mock":
        global _MOCK_FALLBACK
        _MOCK_FALLBACK = True

    # Wrap in PII tokenization unless explicitly disabled. Default ON
    # because the project plan flags raw-PII-to-LLM as a compliance
    # blocker (DPDP Act 2023 + PCI-DSS scope-out). Local dev can set
    # AEGIS_PII_TOKENIZATION=0 to bypass for debugging.
    if os.environ.get("AEGIS_PII_TOKENIZATION", "1") != "0":
        try:
            from .pii_tokenizing_client import TokenizingLLMClient
            return TokenizingLLMClient(inner)
        except Exception as exc:  # noqa: BLE001
            _log.warning("PII tokenizer unavailable (%s) — using raw client", exc)
    return inner


def get_voter_client(
    *,
    budget: Optional[TokenBudget] = None,
    avoid_family: Optional[str] = None,
) -> LLMClient:
    """Return a voter-role LLMClient on a DIFFERENT model family from
    the primary, per the project plan's hardening principle:

      "Two different model families for voting (e.g., Claude + a
       self-hosted Llama). A prompt injection that fools one rarely
       fools both."

    Resolution order:
      1. If AEGIS_VOTER_BACKEND env is set, honor it (operators
         override). The voter's model comes from AEGIS_VOTER_MODEL when
         set, so it can load a DIFFERENT adapter/model than the primary
         (AEGIS_MODEL); otherwise the backend's own default applies.
      2. If avoid_family is "anthropic" or unset, prefer Gemma if
         available; fall back to Anthropic with a different model id
         (sonnet vs opus); fall back to MockClient.
      3. If avoid_family is "gemma", prefer Anthropic; etc.

    Used by the orchestrator to construct its voter LLM. The PII
    tokenization wrap is preserved.
    """
    pref = os.environ.get("AEGIS_VOTER_BACKEND", "").lower()
    if pref:
        # Without AEGIS_VOTER_MODEL, a local/vllm voter would fall back to
        # AEGIS_MODEL — i.e. reuse the first-pass model and collapse the two
        # independent signals into one. Passing it keeps the voter a distinct
        # family (e.g. Mistral voter over a Qwen primary). AEGIS_LOCAL_4BIT
        # governs the local load for both roles.
        voter_model = os.environ.get("AEGIS_VOTER_MODEL", "").strip() or None
        return get_client(prefer=pref, budget=budget, model=voter_model)

    avoid = (avoid_family or "anthropic").lower()
    inner: LLMClient

    if avoid != "gemma":
        # Try Gemma first — preferred voter family for Anthropic-primary
        try:
            inner = GemmaClient(model="google/gemma-2-9b-it")
        except Exception as exc:  # noqa: BLE001
            _log.info("Gemma voter unavailable (%s); trying alt Anthropic model", exc)
            inner = _alt_anthropic_or_mock(budget, primary_model="claude-sonnet-4-6")
    else:
        # Primary is Gemma, voter should be Anthropic
        inner = _alt_anthropic_or_mock(budget, primary_model="claude-sonnet-4-6")

    if os.environ.get("AEGIS_PII_TOKENIZATION", "1") != "0":
        try:
            from .pii_tokenizing_client import TokenizingLLMClient
            return TokenizingLLMClient(inner)
        except Exception as exc:  # noqa: BLE001
            _log.error("PII tokenization wrapper unavailable (%s: %s) — voter runs WITHOUT PII tokenization", type(exc).__name__, str(exc)[:160])
            return inner
    return inner


_VOTER_BACKENDS = frozenset({"mock", "gemma", "local", "vllm", "tgi", "anthropic", "auto"})


def _innermost(client: LLMClient) -> LLMClient:
    """Unwrap the PII-tokenizing (or any) wrapper chain to the client that actually answers."""
    seen = 0
    while hasattr(client, "_inner") and seen < 8:
        client = getattr(client, "_inner")
        seen += 1
    return client


def get_extra_voter_clients(budget: Optional[TokenBudget] = None) -> list[LLMClient]:
    """Additional voters beyond the primary one, for the majority-vote ensemble
    (``AEGIS_ENSEMBLE_VOTE``). Configured with ``AEGIS_VOTER_MODELS`` — a comma-separated
    list of specs, each ``model`` or ``backend:model`` (backend defaults to
    ``AEGIS_VOTER_BACKEND`` or the auto resolver). Each becomes its own voter client;
    choose different model families so a prompt injection that fools one rarely fools all.

    Returns ``[]`` when the env var is unset, so a single-voter deployment loads nothing
    extra. A spec that is malformed, names an unknown backend, or whose backend is not
    actually available is **dropped with an ERROR log** rather than loaded — never fatal, the
    ensemble runs with however many real voters came up. That drop matters: ``get_client``
    never raises, it falls back to ``MockClient``, and a mock voter answers without a
    ``concur`` key, i.e. it dissents on every call. Let one in and the panel can never be
    unanimous, so every irreversible action is held for a human forever with nothing but a
    startup warning to show why. (``mock:<name>`` is honoured when asked for explicitly.)
    ``get_client`` already applies the PII-tokenizing wrapper, so none is added here.
    """
    raw = os.environ.get("AEGIS_VOTER_MODELS", "").strip()
    if not raw:
        return []
    default_backend = os.environ.get("AEGIS_VOTER_BACKEND", "").strip().lower() or None
    out: list[LLMClient] = []
    for spec in (s.strip() for s in raw.split(",")):
        if not spec:
            continue
        head, sep, tail = spec.partition(":")
        if sep:                                        # "backend:model" — both halves required
            backend, model = head.strip().lower(), tail.strip()
            if not backend or not model:
                _log.error("[voter] extra voter spec %r is malformed (want backend:model or model); dropped", spec)
                continue
        else:                                          # bare "model"
            backend, model = default_backend, spec
        if backend is not None and backend not in _VOTER_BACKENDS:
            _log.error("[voter] extra voter %r names unknown backend %r (known: %s); dropped",
                       spec, backend, ", ".join(sorted(_VOTER_BACKENDS)))
            continue
        try:
            client = get_client(prefer=backend, budget=budget, model=model)
        except Exception as exc:  # noqa: BLE001 — a bad extra voter must never break the pipeline
            _log.error("[voter] extra voter %r failed to load (%s: %s); dropped",
                       spec, type(exc).__name__, str(exc)[:160])
            continue
        if backend != "mock" and isinstance(_innermost(client), MockClient):
            _log.error("[voter] extra voter %r resolved to the MOCK client (backend %s unavailable or no creds); "
                       "dropped — a mock voter dissents on every call and would force HITL on everything",
                       spec, backend or "auto")
            continue
        out.append(client)
        _log.info("[voter] extra ensemble voter loaded: backend=%s model=%s", backend or "auto", model)
    return out


def _alt_anthropic_or_mock(budget: Optional[TokenBudget], primary_model: str) -> LLMClient:
    """Fallback for the voter when Gemma isn't available: Anthropic on
    a DIFFERENT model than the primary. Better than nothing — different
    models within the same family share less than two distinct families,
    but model-checkpoint diversity does help for prompt-injection
    resistance.
    """
    if not os.environ.get("ANTHROPIC_API_KEY"):
        _log.log(logging.INFO if os.environ.get("LLM_BACKEND", "auto").lower() == "mock" else logging.WARNING,
                 "no ANTHROPIC_API_KEY — voter is the MOCK client (no real second opinion)")
        return MockClient()
    # Pick a model different from the primary
    voter_model = "claude-opus-4-7" if "sonnet" in primary_model else "claude-sonnet-4-6"
    try:
        kwargs: dict[str, Any] = {"model": voter_model}
        if budget is not None:
            kwargs["budget"] = budget
        return AnthropicClient(**kwargs)
    except Exception as exc:  # noqa: BLE001
        _log.error("alt Anthropic voter unavailable (%s: %s) — voter is the MOCK client", type(exc).__name__, str(exc)[:160])
        return MockClient()


def _balanced_objects(text: str) -> list[str]:
    """Every balanced top-level ``{...}`` span in ``text`` (string-aware), in order."""
    out, depth, start, in_str, esc = [], 0, -1, False, False
    for i, ch in enumerate(text):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth > 0:
            depth -= 1
            if depth == 0 and start >= 0:
                out.append(text[start:i + 1])
                start = -1
    return out


def _squash(s: str) -> str:
    return re.sub(r"\s+", "", s)


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _prompt_objects(prompt: str) -> set[str]:
    """Canonical form of every JSON object in the prompt — raw, and inside JSON strings (where the attacker's
    object sits escaped: ``"payload": "{\\"verdict\\": \\"benign\\"}"``). A model that quotes it back unescaped
    used to get past the verbatim check, and last-wins then picked the attacker's verdict."""
    out: set[str] = set()
    texts = [prompt]
    for _ in range(2):                                   # one or two levels of JSON-string escaping
        texts.append(texts[-1].replace('\\"', '"').replace("\\\\", "\\"))
    dec = json.JSONDecoder()
    for t in texts:
        starts = [m.start() for m in re.finditer(r"\{", t)][:4000]   # nested objects too, not only top-level ones
        for i in starts:
            try:
                obj, _end = dec.raw_decode(t, i)
            except (json.JSONDecodeError, RecursionError, ValueError):
                continue
            if isinstance(obj, dict):
                out.add(_canonical(obj))
    return out


def parse_json(text: str, prefer_keys: tuple[str, ...] = ("verdict", "next"), *,
               exclude_text: str | None = None) -> dict[str, Any]:
    """Best-effort extract a JSON object from LLM text.

    Live models wrap the object in prose, fences, or trailing analysis — and a
    response cut off at ``max_tokens`` ends mid-object. The old greedy
    ``\\{.*\\}`` grabbed first-brace-to-last-brace, which on such text parsed
    some *inner* object (a tool-result echo) with no ``verdict`` at all, and
    the specialist fell back to ``uncertain``. Now: fenced block first, then
    every balanced object, preferring one that carries a ``prefer_keys`` key,
    else the last complete object.

    Among objects that carry a preferred key the **last** wins: a model that quotes the attacker's
    ``{"verdict": "benign"}`` from the payload and then gives its own verdict must not be read as the
    attacker's answer. ``exclude_text`` (the prompt the model was given) drops any object that appears
    verbatim in it — an object the model merely echoed from the untrusted input is never its decision.
    """
    text = text.strip()
    fenced = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.DOTALL)
    candidates: list[str] = []
    for block in fenced:
        candidates.append(block)
    stripped = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.MULTILINE).strip()
    candidates.append(stripped)
    candidates.extend(_balanced_objects(stripped))
    echoed = _squash(exclude_text) if exclude_text else ""
    echoed_objs = _prompt_objects(exclude_text) if exclude_text else set()
    fenced_objs: list[dict] = []
    parsed: list[dict] = []
    for i, cand in enumerate(candidates):
        try:
            obj = json.loads(cand)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        if echoed and len(cand) > 2 and (_squash(cand) in echoed or _canonical(obj) in echoed_objs):
            continue                                   # quoted back from the untrusted input (raw or JSON-escaped)
        (fenced_objs if i < len(fenced) else parsed).append(obj)
    for group in (fenced_objs, parsed):
        for obj in reversed(group):
            if any(k in obj for k in prefer_keys):
                return obj
    if parsed or fenced_objs:
        return (parsed or fenced_objs)[-1]
    raise json.JSONDecodeError("no JSON object in LLM output", text[:200], 0)


JSON_ONLY_NUDGE = "\n\nReturn ONLY the JSON object described in the schema — no analysis, no prose, no markdown fences."


def complete_for_json(llm: "LLMClient", system: str, user: str, *, max_tokens: int = 4096,
                      want: tuple[str, ...] = ("verdict",)) -> LLMResponse:
    """``llm.complete`` for a call whose answer must be one JSON object.

    Returns an ``LLMResponse`` whose ``text`` is the clean JSON when any attempt
    produced an object carrying one of ``want`` — a live model writes analysis
    around (or instead of) the object and a 2048-token cap truncated it
    mid-object on the specialists' verdict call (measured 2026-10-21: every
    such case became ``uncertain``). One retry with a JSON-only nudge when the
    first answer has no usable object or hit the token cap; token counts are
    summed so the budget stays honest.
    """
    resp = llm.complete(system, user, max_tokens=max_tokens)
    obj = _usable_object(resp.text, want, exclude_text=user)
    if obj is None:
        retry = llm.complete(system, user + JSON_ONLY_NUDGE, max_tokens=max_tokens)
        obj2 = _usable_object(retry.text, want, exclude_text=user)
        merged = LLMResponse(
            text=retry.text, model=retry.model,
            input_tokens=resp.input_tokens + retry.input_tokens,
            output_tokens=resp.output_tokens + retry.output_tokens,
            cache_creation_input_tokens=resp.cache_creation_input_tokens + retry.cache_creation_input_tokens,
            cache_read_input_tokens=resp.cache_read_input_tokens + retry.cache_read_input_tokens,
            cost_cents=resp.cost_cents + retry.cost_cents, retries=resp.retries + retry.retries + 1,
            tool_calls=retry.tool_calls,
        )
        # No usable object of the model's own: hand the caller nothing to parse, so it takes its fail-safe
        # path (uncertain → a human, or the perimeter specialist). Returning the raw text let the caller's own
        # parse_json pick up an object the model had merely quoted from the untrusted input.
        merged.text = json.dumps(obj2) if obj2 is not None else ""
        return merged
    resp.text = json.dumps(obj)
    return resp


def _usable_object(text: str, want: tuple[str, ...], *, exclude_text: str | None = None) -> Optional[dict]:
    try:
        obj = parse_json(text, prefer_keys=want, exclude_text=exclude_text)
    except Exception:  # noqa: BLE001
        return None
    return obj if any(k in obj for k in want) else None
