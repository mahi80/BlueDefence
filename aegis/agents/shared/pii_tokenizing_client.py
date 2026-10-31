"""TokenizingLLMClient — transparent middleware that tokenizes PII
before sending to the inner LLM client and detokenizes on response.

Wraps any LLMClient. The agent code doesn't know it's there:

    raw_client = AnthropicClient(...)
    safe_client = TokenizingLLMClient(raw_client)
    # ... use safe_client like a normal LLMClient ...

This is the right integration point because:
  - It can't be bypassed by an agent forgetting to call tokenize()
  - It composes cleanly with any backend (Anthropic, Gemma, mock)
  - The agent's structured outputs are detokenized BEFORE going into
    EvidenceChain / audit log, so the audit retains the real values
    (which the bank's reviewers can see) but the LLM never did.
"""
from __future__ import annotations

import logging
from typing import Optional

from .llm_client import LLMClient, LLMResponse, TokenBudget
from .pii_tokenizer import PIITokenizer, TokenMap


_log = logging.getLogger("aegis.pii")


class TokenizingLLMClient(LLMClient):
    name: str = "tokenizing"
    model: str = ""

    def __init__(self, inner: LLMClient,
                 tokenizer: Optional[PIITokenizer] = None,
                 *, log_kinds: bool = True):
        self._inner = inner
        self._tokenizer = tokenizer or PIITokenizer()
        self._log_kinds = log_kinds
        self.name = f"tokenizing({inner.name})"
        self.model = inner.model

    # Delegate budget access if the inner has one
    @property
    def budget(self) -> Optional[TokenBudget]:
        return getattr(self._inner, "budget", None)

    def complete(self, system: str, user: str, max_tokens: int = 2048) -> LLMResponse:
        sys_t, user_t, merged = self._tokenize_pair(system, user)
        resp = self._inner.complete(sys_t, user_t, max_tokens=max_tokens)
        resp.text = self._tokenizer.detokenize(resp.text, merged)
        return resp

    def complete_with_tools(self, system: str, user: str, tools, *,
                            max_tokens: int = 2048) -> LLMResponse:
        """Tool-use path: tokenize input, detokenize output text + each
        string-valued field in tool_call inputs.
        """
        sys_t, user_t, merged = self._tokenize_pair(system, user)
        resp = self._inner.complete_with_tools(sys_t, user_t, tools, max_tokens=max_tokens)
        resp.text = self._tokenizer.detokenize(resp.text, merged)
        # Detokenize string values inside each tool_call's input
        for call in resp.tool_calls:
            inp = call.get("input") or {}
            for k, v in list(inp.items()):
                if isinstance(v, str):
                    inp[k] = self._tokenizer.detokenize(v, merged)
                elif isinstance(v, list):
                    inp[k] = [
                        self._tokenizer.detokenize(item, merged) if isinstance(item, str) else item
                        for item in v
                    ]
        return resp

    def _tokenize_pair(self, system: str, user: str):
        sys_t, sys_map = self._tokenizer.tokenize(system)
        user_t, user_map = self._tokenizer.tokenize(user)
        merged = TokenMap(
            by_token={**sys_map.by_token, **user_map.by_token},
            by_value={**sys_map.by_value, **user_map.by_value},
        )
        if self._log_kinds and merged.by_token:
            _log.info("PII tokenized for LLM call: %s", self._tokenizer.stats(merged))
        return sys_t, user_t, merged
