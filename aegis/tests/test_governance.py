"""Phase 0.1 — the SOC orchestrator as a governed ACP agent.

Runs against the real orchestrator in stub-LLM mode (no API key) and the
real acp-sdk (>= 0.8.2). Governance is opt-in, so the default eval path is
untouched.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

acp = pytest.importorskip("acp", reason="acp-sdk not installed")
from acp import ACPViolation  # noqa: E402

from aegis import governance  # noqa: E402
from aegis.agents.response.agent import ResponseAgent  # noqa: E402
from aegis.agents.shared.evidence_chain import EvidenceChain, RecommendedAction  # noqa: E402
from aegis.eval.run import HERE, _build_orchestrator  # noqa: E402

CASES = json.loads((HERE / "historical_alerts" / "cases.json").read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    monkeypatch.setenv("ACP_HOME", str(tmp_path))  # isolate the per-machine agent registry
    monkeypatch.delenv("ACP_DASHBOARD_URL", raising=False)
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "LLM_BACKEND"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ACP_GOVERN", "1")


@pytest.fixture
def orch():
    with tempfile.TemporaryDirectory() as td:
        yield _build_orchestrator(Path(td) / "audit.jsonl")


def _events(guard, kind: str):
    return [e for e in guard.state.events if e.event_type == kind]


def test_disabled_by_default_leaves_the_orchestrator_untouched(orch, monkeypatch):
    monkeypatch.delenv("ACP_GOVERN", raising=False)
    assert governance.governance_enabled() is False
    assert governance.govern_soc(orch) is None
    assert not getattr(orch.handle, "_acp_wrapped", False)
    assert orch.handle.__func__ is type(orch).handle  # still the class method, not a wrapper


def test_acp_govern_zero_wins_over_dashboard_url(monkeypatch):
    monkeypatch.setenv("ACP_DASHBOARD_URL", "https://dash.example")
    monkeypatch.setenv("ACP_GOVERN", "0")
    assert governance.governance_enabled() is False


def test_governed_orchestrator_handles_every_historical_case_with_same_verdicts(orch):
    governed = governance.govern_soc(orch)
    assert governed is not None and governed.agent_code == "SOC-AGENTQ-01"
    assert len(governed.specialists) == 10
    for case in CASES:
        chain = orch.handle(case["alert"])
        assert chain.verdict == case["expected_verdict"], case["alert"]["id"]
    guard = governed.guard
    assert guard.state.task_count == len(CASES)  # one ACP task per alert
    starts = _events(guard, "tool_call_start")
    tools = {e.data["tool"] for e in starts}
    assert governance.TOOL_ORCHESTRATOR in tools
    assert any(t.startswith("specialist.") for t in tools)
    assert not any(e.data["success"] is False for e in _events(guard, "tool_call_end"))
    # the guard never saw an alert payload, only identifiers
    for e in starts:
        assert set(e.data["args"]) <= {"alert_id", "type", "source", "category", "severity", "tenant"}


def test_pause_gate_stops_the_brain_and_escalates(orch):
    governed = governance.govern_soc(orch)
    guard = governed.guard
    alert = CASES[0]["alert"]
    specialist_calls_before = len([e for e in _events(guard, "tool_call_start")
                                   if e.data["tool"].startswith("specialist.")])
    guard._paused = True  # what the dashboard's 423 pause-gate sets via the reporter
    chain = orch.handle(alert)
    assert chain.verdict == "uncertain"
    assert chain.recommended_actions[0].action_type == "escalate"
    assert chain.recommended_actions[0].requires_hitl is True
    assert chain.metadata["governance_block"]["control"] == "AGENT_PAUSED"
    specialist_calls_after = len([e for e in _events(guard, "tool_call_start")
                                  if e.data["tool"].startswith("specialist.")])
    assert specialist_calls_after == specialist_calls_before  # no specialist ran while paused
    guard._paused = False
    assert orch.handle(alert).verdict == CASES[0]["expected_verdict"]  # resumes cleanly


def test_q30_closes_the_matrix_to_the_declared_tools(orch):
    governed = governance.govern_soc(orch)
    guard = governed.guard
    governed.begin_alert("probe")
    with pytest.raises(ACPViolation) as exc:
        guard.pre_tool_call("response.nuke_from_orbit", {"target": "x"})
    assert exc.value.code == "ACP-730"
    assert "response.block" in governed.tools or governed.response_wrapped is False


def test_response_actions_are_governed_and_fail_safe(orch):
    response = ResponseAgent()
    governed = governance.govern_soc(orch, response=response)
    assert governed.response_wrapped is True
    assert "response.throttle" in governed.tools and "response.block" in governed.tools
    chain = EvidenceChain(alert_id="a-1", investigated_by="test", verdict="malicious", confidence=0.9)
    chain.recommended_actions.append(RecommendedAction(
        action_type="throttle", target="203.0.113.7", reasoning="test", requires_hitl=False, confidence=0.9))
    chain.recommended_actions.append(RecommendedAction(
        action_type="block", target="203.0.113.7", reasoning="test", requires_hitl=False, confidence=0.9))

    governed.begin_alert("a-1")
    alert = {"id": "a-1", "src_ip": "203.0.113.7"}         # unattended targets must be grounded in the alert (#74)
    summary = response.execute(chain, alert)
    assert [a.action.action_type for a in summary.executed] == ["throttle"]
    assert [a.action.action_type for a in summary.hitl_queue] == ["block"]  # HITL policy unchanged
    tools = [e.data["tool"] for e in _events(governed.guard, "tool_call_start")]
    assert "response.throttle" in tools and "response.block" not in tools  # HITL-queued never reached the guard

    governed.guard._paused = True
    summary = response.execute(chain, alert)
    assert summary.executed == []
    assert any("[ACP blocked]" in a.note for a in summary.hitl_queue)  # auto-safe action parked for a human
    approved = response.approve(chain.recommended_actions[1], approver="ciso")
    assert approved.status == "skipped" and "[ACP blocked]" in approved.note


def test_govern_soc_is_idempotent(orch):
    first = governance.govern_soc(orch)
    second = governance.govern_soc(orch)
    assert second is first
    assert getattr(orch.handle, "_acp_wrapped", False)
    assert first.guard.state.task_count == 0  # re-governing opened no task
