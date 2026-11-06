"""Hardening from the 2026-11 source review: fail closed, and don't grade the mock.

Each test pins a property whose regression is silent in production:
  - PII tokenisation must not disappear because an import failed
  - an eval gate must not call itself green against MockClient
  - the daily heartbeat must not carry the host's name by default
"""

from __future__ import annotations

import json
import sys

import pytest

from aegis.agents.shared.audit import AuditLog
from aegis.agents.shared.evidence_chain import EvidenceChain
from aegis.agents.shared.llm_client import (
    MockClient,
    get_client,
    is_mock_client,
    require_live_llm,
)
from aegis.license import heartbeat_payload


def test_pii_tokenisation_fails_closed_when_the_wrapper_cannot_load(monkeypatch):
    monkeypatch.delenv("AEGIS_PII_TOKENIZATION", raising=False)
    monkeypatch.setitem(sys.modules, "aegis.agents.shared.pii_tokenizing_client", None)
    with pytest.raises(RuntimeError, match="PII tokenization is enabled"):
        get_client(prefer="mock")


def test_pii_tokenisation_opt_out_returns_the_raw_client(monkeypatch):
    monkeypatch.setenv("AEGIS_PII_TOKENIZATION", "0")
    assert isinstance(get_client(prefer="mock"), MockClient)


def test_mock_is_detected_through_the_pii_wrapper(monkeypatch):
    monkeypatch.delenv("AEGIS_PII_TOKENIZATION", raising=False)
    assert is_mock_client(get_client(prefer="mock"))


def test_eval_gate_refuses_to_grade_the_mock(monkeypatch):
    monkeypatch.setenv("AEGIS_PII_TOKENIZATION", "0")
    monkeypatch.delenv("AEGIS_EVAL_ALLOW_MOCK", raising=False)
    with pytest.raises(SystemExit, match="Refusing to grade"):
        require_live_llm(get_client(prefer="mock"), "unit eval")


def test_eval_gate_allows_an_explicit_offline_run(monkeypatch):
    monkeypatch.setenv("AEGIS_PII_TOKENIZATION", "0")
    monkeypatch.setenv("AEGIS_EVAL_ALLOW_MOCK", "1")
    require_live_llm(get_client(prefer="mock"), "unit eval")          # must not raise


def test_heartbeat_omits_the_hostname_by_default():
    payload = heartbeat_payload(installation_id="i-test", audit_path=None, env={})
    assert "host" not in payload
    assert "python" in payload


def test_heartbeat_includes_the_hostname_only_on_request():
    payload = heartbeat_payload(installation_id="i-test", audit_path=None,
                                env={"AEGIS_HEARTBEAT_INCLUDE_HOST": "1"})
    assert payload["host"]


def _chain(alert_id: str) -> EvidenceChain:
    return EvidenceChain(alert_id=alert_id, investigated_by="test", verdict="benign", confidence=0.5)


def test_two_writers_append_one_chain(tmp_path):
    """A CLI and the service (or two services) must not each fork the chain from their own in-memory tail."""
    path = tmp_path / "audit.jsonl"
    a, b = AuditLog(path), AuditLog(path)
    for i in range(3):
        a.append(_chain(f"a{i}"))
        b.append(_chain(f"b{i}"))
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert [r["alert_id"] for r in rows] == ["a0", "b0", "a1", "b1", "a2", "b2"]
    assert AuditLog(path).verify() is True


def test_dashboard_skips_gates_without_a_live_model_and_fails_real_disagreements():
    """CI has no model key: the dashboard must say SKIP rather than claim a green eval gate, but a genuine
    disagreement (non-zero exit without the refusal marker) still fails the run."""
    from aegis.eval.dashboard import SuiteResult, _eval_status, overall_status

    refusal = ("historical/injection eval: the resolved LLM backend is MockClient (no model credentials). "
               "Refusing to grade the deterministic keyword table as if it were a model.")
    assert _eval_status(1, refusal, 0, 0) == "SKIP"
    assert _eval_status(1, "DISAGREE: alert-7", 8, 9) == "FAIL"
    assert _eval_status(0, "", 9, 9) == "PASS"

    mixed = [SuiteResult("manifest", status="PASS"), SuiteResult("historical", status="SKIP")]
    assert overall_status(mixed) == "SKIP"
    assert overall_status(mixed + [SuiteResult("red team", status="FAIL")]) == "FAIL"
