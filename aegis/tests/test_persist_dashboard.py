"""Phase 0.3 — chains and proposals are shipped to the dashboard, never blocking the agent."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from aegis.agents.shared.audit import AuditLog
from aegis.agents.shared.evidence_chain import EvidenceChain, RecommendedAction
from aegis.meta_agent.proposer import Proposal
from aegis.meta_agent.queue import ProposalQueue
from aegis.meta_agent.validator import ValidationResult
from aegis.persist import DashboardSink, sink_from_env


class FakeDashboard:
    def __init__(self, *, fail=False, refuse=False):
        self.calls: list[tuple[str, str, dict, dict]] = []
        self.fail, self.refuse = fail, refuse

    def __call__(self, method, url, json_body, headers, timeout):
        self.calls.append((method, url, json_body, headers))
        if self.fail:
            raise ConnectionError("dashboard down")
        if self.refuse:
            return {"error": "verdict must be one of ..."}
        return {"status": "created", "id": "EC-1"}


def _chain(alert_id="EVAL-005"):
    c = EvidenceChain(alert_id=alert_id, investigated_by="auth", verdict="malicious", confidence=0.9)
    c.recommended_actions.append(RecommendedAction(
        action_type="lock_account", target="user_id", reasoning="ATO", requires_hitl=True, confidence=0.9))
    return c


def _sink(dash, **kw):
    return DashboardSink("https://dash.test", "k3y", agent_name="aegis-soc-orchestrator",
                         agent_code="SOC-AGENTQ-01", bu="Security", transport=dash, **kw)


def test_audit_log_ships_each_chain_with_its_hash_and_prev_hash():
    dash = FakeDashboard()
    with tempfile.TemporaryDirectory() as td:
        log = AuditLog(Path(td) / "audit.jsonl", sink=_sink(dash, sync=True))
        c1 = log.append(_chain("A"))
        c2 = log.append(_chain("B"))
        assert log.verify()  # the local hash chain is untouched
    assert [u for _, u, _, _ in dash.calls] == ["https://dash.test/api/soc/chains"] * 2
    b1, b2 = dash.calls[0][2], dash.calls[1][2]
    assert b1["chain"]["integrity_hash"] == c1.integrity_hash and b1["prev_hash"] == "0" * 64
    assert b2["chain"]["integrity_hash"] == c2.integrity_hash and b2["prev_hash"] == c1.integrity_hash
    assert b1["agent_name"] == "aegis-soc-orchestrator" and b1["agent_code"] == "SOC-AGENTQ-01"
    assert b1["bu"] == "Security" and b1["source"] == "aegis"
    assert b1["chain"]["recommended_actions"][0]["action_type"] == "lock_account"
    assert dash.calls[0][3]["X-API-Key"] == "k3y"


def test_background_mode_never_blocks_and_flush_drains():
    dash = FakeDashboard()
    sink = _sink(dash)  # async queue + daemon thread
    with tempfile.TemporaryDirectory() as td:
        log = AuditLog(Path(td) / "audit.jsonl", sink=sink)
        for i in range(5):
            log.append(_chain(f"A{i}"))
    assert sink.flush(timeout=5)
    assert len(dash.calls) == 5 and sink.shipped == 5 and sink.failed == 0


def test_dashboard_down_or_refusing_never_breaks_the_investigation():
    for dash in (FakeDashboard(fail=True), FakeDashboard(refuse=True)):
        sink = _sink(dash, sync=True)
        with tempfile.TemporaryDirectory() as td:
            log = AuditLog(Path(td) / "audit.jsonl", sink=sink)
            chain = log.append(_chain())
            assert chain.integrity_hash and log.verify()
            assert json.loads((Path(td) / "audit.jsonl").read_text().splitlines()[0])["alert_id"] == "EVAL-005"
        assert sink.shipped == 0 and sink.failed == 1 and sink.last_error


def test_proposal_queue_ships_entries_with_validation_and_hashes():
    dash = FakeDashboard()
    proposal = Proposal(id="PROP-SQLI-001", target_module="aegis/agents/perimeter/tools.py",
                        change_type="heuristic_primitive", change={"pattern": "union select"},
                        rationale="3 missed union-based SQLi cases", evidence_case_ids=["EVAL-014"])
    validation = ValidationResult(proposal_id="PROP-SQLI-001", failures_before=26, failures_after=23,
                                  regressions=0, recommend_accept=True, notes="clean")
    with tempfile.TemporaryDirectory() as td:
        q = ProposalQueue(Path(td) / "proposals.jsonl", sink=_sink(dash, sync=True))
        h = q.append(proposal, validation)
        assert q.verify() and len(q.list_pending()) == 1
    (_, url, body, _), = dash.calls
    assert url == "https://dash.test/api/soc/proposals"
    assert body["integrity_hash"] == h and body["prev_hash"] == "0" * 64 and body["status"] == "pending_hitl"
    assert body["proposal"]["id"] == "PROP-SQLI-001"
    assert body["proposal"]["target"] == "aegis/agents/perimeter/tools.py"
    assert body["proposal"]["title"].startswith("heuristic_primitive: 3 missed")
    assert body["validation"]["passed"] is True and body["validation"]["failures_after"] == 23


def test_sink_from_env(monkeypatch):
    monkeypatch.delenv("ACP_DASHBOARD_URL", raising=False)
    assert sink_from_env() is None
    monkeypatch.setenv("ACP_DASHBOARD_URL", "https://dash.example/")
    monkeypatch.setenv("AEGIS_PERSIST", "0")
    assert sink_from_env() is None
    monkeypatch.setenv("AEGIS_PERSIST", "1")
    s = sink_from_env(sync=True)
    assert s is not None and s.dashboard_url == "https://dash.example" and s.sync is True


def test_no_sink_keeps_the_old_behaviour():
    with tempfile.TemporaryDirectory() as td:
        log = AuditLog(Path(td) / "audit.jsonl")
        log.append(_chain())
        assert log.verify()
