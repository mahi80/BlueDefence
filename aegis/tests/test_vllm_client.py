"""vLLM backend: OpenAI-compatible client for the self-hosted fine-tuned Qwen.

All CI-safe — the HTTP transport is injected, so nothing here needs a server or a GPU."""

from __future__ import annotations

import urllib.error

import pytest

from aegis.agents.shared.llm_client import TokenBudget, TokenBudgetExceeded, get_client
from aegis.agents.shared.vllm_client import VLLMClient, VLLMConfig, _RetriableHTTP, _parse_chat_completion


def _ok(content: str = '{"verdict":"benign"}', prompt=11, completion=5):
    return {"choices": [{"message": {"content": content}}],
            "usage": {"prompt_tokens": prompt, "completion_tokens": completion}}


def _client(transport, **cfg):
    return VLLMClient(VLLMConfig(**cfg) if cfg else VLLMConfig(model="qwen3-8b-triage"), transport=transport)


def test_complete_builds_openai_request_and_parses():
    seen = {}

    def transport(body):
        seen["body"] = body
        return _ok()

    c = _client(transport, model="qwen3-8b-triage", temperature=0.0)
    r = c.complete("SYSTEM PROMPT", "the alert", max_tokens=256)

    b = seen["body"]
    assert b["model"] == "qwen3-8b-triage"
    assert b["messages"] == [{"role": "user", "content": "SYSTEM PROMPT\n\n---\n\nthe alert"}]
    assert b["max_tokens"] == 256 and b["temperature"] == 0.0 and b["stream"] is False
    assert b["chat_template_kwargs"] == {"enable_thinking": False}     # Qwen3 no-think by default
    assert r.text == '{"verdict":"benign"}'
    assert r.input_tokens == 11 and r.output_tokens == 5
    assert r.model == "qwen3-8b-triage" and r.cost_cents == 0.0        # self-hosted = unmetered


def test_think_block_is_stripped():
    c = _client(lambda body: _ok(content='<think>reasoning here</think>{"verdict":"malicious"}'))
    assert c.complete("s", "u").text == '{"verdict":"malicious"}'


def test_usage_fallback_estimates_when_absent():
    c = _client(lambda body: {"choices": [{"message": {"content": "xxxxxxxx"}}]})  # no usage
    r = c.complete("s" * 40, "u" * 40)
    assert r.input_tokens == (40 + 40) // 4           # estimated from prompt length
    assert r.output_tokens == max(1, len("xxxxxxxx") // 4)


def test_completions_shape_fallback():
    # a /completions-style payload (choices[].text) still parses
    text, pin, pout = _parse_chat_completion({"choices": [{"text": "hello"}], "usage": {}})
    assert text == "hello" and pin == 0 and pout == 0


def test_no_think_disabled_omits_kwargs():
    seen = {}

    def transport(body):
        seen["body"] = body
        return _ok()

    _client(transport, model="m", disable_thinking=False).complete("s", "u")
    assert "chat_template_kwargs" not in seen["body"]


def test_set_model_switches_served_adapter():
    seen = []
    c = _client(lambda body: (seen.append(body["model"]), _ok())[1], model="qwen3-8b-triage")
    c.complete("s", "u")
    c.set_model("qwen3-8b-triage-v5")      # C3 hot-swap: next call targets the new adapter name
    c.complete("s", "u")
    assert seen == ["qwen3-8b-triage", "qwen3-8b-triage-v5"]
    assert c.model == "qwen3-8b-triage-v5"


def test_retries_then_succeeds(monkeypatch):
    monkeypatch.setattr("aegis.agents.shared.vllm_client.time.sleep", lambda *_: None)
    calls = {"n": 0}

    def flaky(body):
        calls["n"] += 1
        if calls["n"] < 3:
            raise _RetriableHTTP("HTTP 503", 503)
        return _ok()

    r = _client(flaky, model="m", max_retries=3).complete("s", "u")
    assert calls["n"] == 3 and r.text == '{"verdict":"benign"}'


def test_retries_exhausted_raises(monkeypatch):
    monkeypatch.setattr("aegis.agents.shared.vllm_client.time.sleep", lambda *_: None)

    def always_503(body):
        raise _RetriableHTTP("HTTP 503", 503)

    with pytest.raises(RuntimeError, match="after 3 attempts"):
        _client(always_503, model="m", max_retries=2).complete("s", "u")


def test_non_retriable_error_fails_fast():
    calls = {"n": 0}

    def bad_request(body):
        calls["n"] += 1
        raise RuntimeError("vLLM HTTP 400: bad model")

    with pytest.raises(RuntimeError, match="vLLM request failed"):
        _client(bad_request, model="m", max_retries=3).complete("s", "u")
    assert calls["n"] == 1                 # no retry on a non-retriable error


def test_budget_exceeded_short_circuits():
    budget = TokenBudget(max_output_tokens=10, consumed_output=10)
    called = {"n": 0}
    c = VLLMClient(VLLMConfig(model="m"), budget=budget,
                   transport=lambda body: (called.__setitem__("n", called["n"] + 1), _ok())[1])
    with pytest.raises(TokenBudgetExceeded):
        c.complete("s", "u", max_tokens=100)
    assert called["n"] == 0                # transport never hit once the budget is blown


def test_http_transport_maps_status(monkeypatch):
    c = VLLMClient(VLLMConfig(base_url="http://localhost:8000/v1", model="m"))

    def raise_http(code):
        def _raise(req, timeout=None):
            raise urllib.error.HTTPError(req.full_url, code, "err", {}, None)
        return _raise

    monkeypatch.setattr("aegis.agents.shared.vllm_client.urllib.request.urlopen", raise_http(503))
    with pytest.raises(_RetriableHTTP) as ei:
        c._http_transport({"model": "m"})
    assert ei.value.status_code == 503

    monkeypatch.setattr("aegis.agents.shared.vllm_client.urllib.request.urlopen", raise_http(400))
    with pytest.raises(RuntimeError, match="vLLM HTTP 400"):   # client error → not retriable
        c._http_transport({"model": "m"})

    def raise_urlerror(req, timeout=None):
        raise urllib.error.URLError("refused")
    monkeypatch.setattr("aegis.agents.shared.vllm_client.urllib.request.urlopen", raise_urlerror)
    with pytest.raises(_RetriableHTTP):                        # connection error → retriable
        c._http_transport({"model": "m"})


def test_config_from_env(monkeypatch):
    for k in ("AEGIS_VLLM_URL", "AEGIS_VLLM_MODEL", "AEGIS_MODEL", "AEGIS_VLLM_TEMPERATURE",
              "AEGIS_VLLM_NO_THINK", "AEGIS_VLLM_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AEGIS_VLLM_URL", "http://gpu-host:8000/v1")
    monkeypatch.setenv("AEGIS_MODEL", "qwen3-8b-triage")       # falls back to AEGIS_MODEL
    monkeypatch.setenv("AEGIS_VLLM_TEMPERATURE", "0.2")
    monkeypatch.setenv("AEGIS_VLLM_NO_THINK", "0")
    cfg = VLLMConfig.from_env()
    assert cfg.base_url == "http://gpu-host:8000/v1"
    assert cfg.model == "qwen3-8b-triage"
    assert cfg.temperature == 0.2 and cfg.disable_thinking is False


def test_config_model_defaults_to_qwen(monkeypatch):
    for k in ("AEGIS_VLLM_MODEL", "AEGIS_MODEL"):
        monkeypatch.delenv(k, raising=False)
    assert VLLMConfig.from_env().model == "qwen"


def test_get_client_routes_vllm_backend(monkeypatch):
    monkeypatch.setenv("AEGIS_PII_TOKENIZATION", "0")          # unwrap to assert the concrete client
    monkeypatch.setenv("LLM_BACKEND", "vllm")
    c = get_client()
    assert isinstance(c, VLLMClient) and c.name == "vllm"
