"""vLLM / TGI backend — serve the fine-tuned Qwen privately over an OpenAI-compatible API.

The ``local`` (GemmaClient) backend loads the checkpoint in-process with transformers +
PEFT: fine for dev, eval and low volume, but single-request, no continuous batching, no
PagedAttention. For a bank running real alert volume, the fine-tuned Qwen should sit behind
a **vLLM** (or TGI) server on the GPU host, and AEGIS talks to it over HTTP. vLLM also serves
**named LoRA adapters** addressed by the ``model`` field — which is the mechanism the
self-evolving loop (roadmap C3) needs to hot-swap a freshly promoted adapter with no restart.

This client is deliberately stdlib-only (``urllib``), matching the project rule of a thin
internal wrapper per provider rather than a community multi-provider library — the OpenAI
wire shape is small and stable. The HTTP transport is injectable (``transport=``) so the
client is fully unit-tested with no server and no GPU (CI-safe).

Rendering matches ``GemmaClient`` exactly — a single user turn ``{system}\\n\\n---\\n\\n{user}``
— so the ``vllm`` and ``local`` backends feed the model the identical prompt the fine-tune was
trained and gated on. Qwen3 "thinking" is disabled via ``chat_template_kwargs`` and any stray
``<think>`` block is stripped defensively.

Env (read by ``VLLMConfig.from_env``):
    AEGIS_VLLM_URL          base URL, OpenAI-style (default http://localhost:8000/v1)
    AEGIS_VLLM_MODEL        served model / LoRA-adapter name (falls back to AEGIS_MODEL, then "qwen")
    AEGIS_VLLM_API_KEY      bearer token if the server requires one (optional)
    AEGIS_VLLM_TIMEOUT      per-request timeout seconds (default 60)
    AEGIS_VLLM_TEMPERATURE  sampling temperature (default 0.0 — deterministic triage)
    AEGIS_VLLM_MAX_RETRIES  retries on 429/5xx/connection errors (default 3)
    AEGIS_VLLM_NO_THINK     1 (default) sends chat_template_kwargs={"enable_thinking": false}

GPU-side wiring (serving the adapter, registering a promoted checkpoint for hot-swap) lands
with C3; this module is the client half and carries no GPU dependency.
"""

from __future__ import annotations

import json
import logging
import os
import random
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Optional

from .llm_client import LLMClient, LLMResponse, TokenBudget, TokenBudgetExceeded

_log = logging.getLogger("aegis.llm.vllm")

#: body-dict in, parsed-response-dict out; lets tests run with no server
Transport = Callable[[dict], dict]

_RETRIABLE_STATUS = {408, 409, 429}


@dataclass
class VLLMConfig:
    base_url: str = "http://localhost:8000/v1"
    model: str = "qwen"
    api_key: str = ""
    timeout_s: float = 60.0
    temperature: float = 0.0
    max_retries: int = 3
    disable_thinking: bool = True

    @classmethod
    def from_env(cls) -> "VLLMConfig":
        def _f(name: str, default: float) -> float:
            try:
                return float(os.environ.get(name, "").strip() or default)
            except (TypeError, ValueError):
                return default

        model = (os.environ.get("AEGIS_VLLM_MODEL", "").strip()
                 or os.environ.get("AEGIS_MODEL", "").strip() or "qwen")
        return cls(
            base_url=(os.environ.get("AEGIS_VLLM_URL", "").strip() or "http://localhost:8000/v1"),
            model=model,
            api_key=os.environ.get("AEGIS_VLLM_API_KEY", "").strip(),
            timeout_s=_f("AEGIS_VLLM_TIMEOUT", 60.0),
            temperature=_f("AEGIS_VLLM_TEMPERATURE", 0.0),
            max_retries=int(_f("AEGIS_VLLM_MAX_RETRIES", 3.0)),
            disable_thinking=os.environ.get("AEGIS_VLLM_NO_THINK", "1").strip().lower() not in {"0", "false", "no", "off"},
        )


class _RetriableHTTP(RuntimeError):
    """Transport error worth retrying; carries an optional HTTP status."""

    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status_code = status


class VLLMClient(LLMClient):
    """OpenAI-compatible chat client for a self-hosted vLLM/TGI server."""

    name = "vllm"

    def __init__(self, config: Optional[VLLMConfig] = None, *, budget: Optional[TokenBudget] = None,
                 transport: Optional[Transport] = None):
        self.config = config or VLLMConfig()
        self.model = self.config.model
        self._budget = budget or TokenBudget()
        self._transport = transport or self._http_transport

    @property
    def budget(self) -> TokenBudget:
        return self._budget

    def set_model(self, model: str) -> None:
        """Point the client at a different served model / LoRA adapter name.

        vLLM routes a request to a loaded adapter by the ``model`` field, so once C3 has
        registered a promoted adapter with the server, switching is just this — no reconnect,
        no reconstruction. The GPU-side load/register step is out of scope here."""
        self.model = str(model)

    # -- the one call the specialists make
    def complete(self, system: str, user: str, max_tokens: int = 2048) -> LLMResponse:
        est_in = (len(system) + len(user)) // 4
        if self._budget.will_exceed(est_in, max_tokens):
            raise TokenBudgetExceeded(
                f"session budget exceeded: in={self._budget.consumed_input}, "
                f"out={self._budget.consumed_output}, cost={self._budget.consumed_cost:.1f}c")

        # identical rendering to GemmaClient: one user turn, so vllm and local feed the model
        # the exact prompt the fine-tune was trained and gated on
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "user", "content": f"{system}\n\n---\n\n{user}"}],
            "max_tokens": int(max_tokens),
            "temperature": float(self.config.temperature),
            "stream": False,
        }
        if self.config.disable_thinking:
            # Qwen3 emits a <think> block by default; disable via the server's chat template.
            # Harmless to a server that ignores it.
            body["chat_template_kwargs"] = {"enable_thinking": False}

        data = self._call_with_retry(body)
        text, in_tok, out_tok = _parse_chat_completion(data)
        text = _strip_think(text)
        if not in_tok:
            in_tok = est_in
        if not out_tok:
            out_tok = max(1, len(text) // 4)
        resp = LLMResponse(text=text, model=self.model, input_tokens=int(in_tok), output_tokens=int(out_tok))
        # cost stays 0: self-hosted inference is not metered per token
        self._budget.add(resp)
        return resp

    # -- transport with bounded retry/backoff (no external dependency)
    def _call_with_retry(self, body: dict) -> dict:
        backoff = 0.5
        last: Exception | None = None
        for attempt in range(self.config.max_retries + 1):
            try:
                return self._transport(body)
            except _RetriableHTTP as exc:
                last = exc
                if attempt == self.config.max_retries:
                    break
                sleep_s = min(backoff, 8.0) * (0.5 + random.random())
                _log.warning("[vllm] attempt %d/%d failed (%s); retrying in %.1fs",
                             attempt + 1, self.config.max_retries + 1, str(exc)[:160], sleep_s)
                time.sleep(sleep_s)
                backoff *= 2
            except Exception as exc:  # noqa: BLE001 — non-retriable (bad request, parse): surface at once
                raise RuntimeError(f"vLLM request failed: {str(exc)[:200]}") from exc
        raise RuntimeError(f"vLLM request failed after {self.config.max_retries + 1} attempts: {last}")

    def _http_transport(self, body: dict) -> dict:
        url = self.config.base_url.rstrip("/") + "/chat/completions"
        raw = json.dumps(body).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        req = urllib.request.Request(url, data=raw, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout_s) as resp:  # noqa: S310 — operator-configured host
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            status = int(getattr(exc, "code", 0) or 0)
            if status in _RETRIABLE_STATUS or status >= 500:
                raise _RetriableHTTP(f"HTTP {status}", status) from exc
            detail = ""
            try:
                detail = exc.read().decode("utf-8")[:200]
            except Exception:  # noqa: BLE001
                pass
            raise RuntimeError(f"vLLM HTTP {status}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise _RetriableHTTP(f"connection error: {exc.reason}") from exc


def _parse_chat_completion(data: dict) -> tuple[str, int, int]:
    """Pull (text, prompt_tokens, completion_tokens) from an OpenAI-shaped chat response."""
    if not isinstance(data, dict):
        raise RuntimeError("vLLM response was not a JSON object")
    choices = data.get("choices") or []
    if not choices:
        raise RuntimeError(f"vLLM response had no choices: {str(data)[:160]}")
    msg = (choices[0] or {}).get("message") or {}
    text = msg.get("content")
    if text is None:
        text = (choices[0] or {}).get("text", "")      # /completions-shaped fallback
    usage = data.get("usage") or {}
    return str(text or ""), int(usage.get("prompt_tokens") or 0), int(usage.get("completion_tokens") or 0)


def _strip_think(text: str) -> str:
    try:
        from aegis.finetune.gate import _THINK
        return _THINK.sub("", text or "").strip()
    except Exception:  # noqa: BLE001 — never let a missing import break a verdict
        return (text or "").strip()


__all__ = ["VLLMClient", "VLLMConfig"]
