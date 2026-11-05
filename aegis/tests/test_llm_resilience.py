"""Model-call bounds: one timeout, one retry policy, and a breaker that fails fast."""
from __future__ import annotations

import time

import pytest

from aegis.agents.shared.llm_client import (
    AnthropicClient,
    CircuitBreaker,
    LLMCircuitOpen,
    LLMDeadlineExceeded,
    _env_float,
)


class _Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


def _client(breaker, *, retries=5, backoff=1.0, deadline=90.0):
    """An AnthropicClient without an SDK client: only the retry machinery is under test."""
    c = object.__new__(AnthropicClient)
    c.model = "test-model"
    c._breaker = breaker
    c._max_retries = retries
    c._initial_backoff = backoff
    c._max_backoff = 30.0
    c.deadline_s = deadline
    return c


class _Boom(Exception):
    status_code = 503                      # retriable by _is_retriable


class _Fatal(Exception):
    status_code = 400                      # not retriable


def test_breaker_opens_after_n_failures_and_recovers():
    clock = _Clock()
    b = CircuitBreaker(failures=3, reset_s=30, clock=clock)
    for _ in range(3):
        assert b.allow() is True
        b.record_failure()
    assert b.allow() is False and b.is_open is True

    clock.advance(31)
    assert b.is_open is False
    assert b.allow() is True               # the single half-open probe
    assert b.allow() is False              # everyone else waits behind it
    b.record_success()
    assert b.allow() is True and b.is_open is False


def test_failed_probe_reopens_the_window():
    clock = _Clock()
    b = CircuitBreaker(failures=2, reset_s=10, clock=clock)
    b.record_failure(); b.record_failure()
    clock.advance(11)
    assert b.allow() is True
    b.record_failure()                     # probe failed
    assert b.allow() is False


def test_retry_raises_circuit_open_instead_of_calling_again():
    b = CircuitBreaker(failures=1, reset_s=60, clock=_Clock())
    c = _client(b, retries=0)
    calls = []

    def boom(_attempt):
        calls.append(_attempt)
        raise _Boom("503")

    with pytest.raises(_Boom):
        c._retry(boom, label="test")
    # that call opened the breaker; the next alert must not touch the provider
    with pytest.raises(LLMCircuitOpen):
        c._retry(boom, label="test")
    assert calls == [0]


def test_non_retriable_errors_do_not_open_the_breaker():
    b = CircuitBreaker(failures=1, reset_s=60, clock=_Clock())
    c = _client(b, retries=5)
    for _ in range(5):
        with pytest.raises(_Fatal):
            c._retry(lambda a: (_ for _ in ()).throw(_Fatal("400")), label="test")
    assert b.is_open is False


def test_retry_honours_the_wall_clock_deadline():
    b = CircuitBreaker(failures=99, reset_s=60, clock=_Clock())
    c = _client(b, retries=5, backoff=30.0, deadline=1.0)
    started = time.monotonic()
    with pytest.raises(LLMDeadlineExceeded):
        c._retry(lambda a: (_ for _ in ()).throw(_Boom("503")), label="test")
    assert time.monotonic() - started < 5    # it refused to sleep into the next attempt


def test_success_closes_the_breaker():
    b = CircuitBreaker(failures=3, reset_s=60, clock=_Clock())
    c = _client(b)
    b.record_failure(); b.record_failure()
    assert c._retry(lambda a: "ok", label="test") == "ok"
    assert b.is_open is False
    b.record_failure()
    assert b.allow() is True                 # counter was reset by the success


def test_client_sets_one_timeout_and_no_sdk_retries(monkeypatch):
    import anthropic
    seen = {}

    class FakeAnthropic:
        def __init__(self, **kw):
            seen.update(kw)

    monkeypatch.setattr(anthropic, "Anthropic", FakeAnthropic)
    c = AnthropicClient(timeout_s=12.5)
    assert seen == {"timeout": 12.5, "max_retries": 0}
    assert c.timeout_s == 12.5


def test_env_float_rejects_garbage():
    import os
    os.environ["AEGIS_TEST_FLOAT"] = "not-a-number"
    try:
        assert _env_float("AEGIS_TEST_FLOAT", 7.0) == 7.0
    finally:
        del os.environ["AEGIS_TEST_FLOAT"]
