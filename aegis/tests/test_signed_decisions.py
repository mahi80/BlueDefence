"""Signed decisions (idea from AiSOC's separation of duties): only a row the console wrote for a signed-in
analyst, or one signed on the host with `python -m aegis.hitl decide`, can approve an action
(code review 2026-11-02 response #7: anything that could append to decisions.jsonl was an approver)."""

from __future__ import annotations

import io
import json

from aegis.agents.response.agent import ResponseAgent
from aegis.agents.response.autonomy import AutonomyPolicy
from aegis.agents.response.connectors import ConnectorRegistry
from aegis.agents.response.connectors.mock_vendor import MockImperva
from aegis.agents.response.connectors.waf import ImpervaWafConnector
from aegis.agents.response.hitl_timeout import HitlTimeoutPolicy
from aegis.agents.shared.evidence_chain import EvidenceChain, RecommendedAction
from aegis.hitl import FileHITL
from aegis.hitl.__main__ import main as hitl_cli
from aegis.ingest.console_api import ConsoleAPI


def _setup(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_CONSOLE_TOKEN", "console-token-for-tests")
    srv = MockImperva()
    waf = ImpervaWafConnector(site_id="s", api_id="mock", api_key="mock", transport=srv, dry_run=False)
    hitl = FileHITL(tmp_path)
    agent = ResponseAgent(connectors=ConnectorRegistry([waf]), hitl=hitl, hitl_stream=io.StringIO(),
                          autonomy=AutonomyPolicy(mode="off"), hitl_timeout=HitlTimeoutPolicy(mode="off"))
    c = EvidenceChain(alert_id="S1", investigated_by="perimeter", verdict="malicious", confidence=0.95)
    c.recommended_actions.append(RecommendedAction(action_type="block", target="203.0.113.9", reasoning="r",
                                                   requires_hitl=True, confidence=0.9))
    agent.execute(c.finalize(), {"src_ip": "203.0.113.9"})
    return agent, srv, hitl.pending[0].approval_id


def _append(tmp_path, row):
    with (tmp_path / "decisions.jsonl").open("a") as f:
        f.write(json.dumps(row) + "\n")


def test_a_hand_appended_line_does_not_approve(tmp_path, monkeypatch, caplog):
    agent, srv, aid = _setup(tmp_path, monkeypatch)
    _append(tmp_path, {"approval_id": aid, "status": "approved", "decided_by": "ciso"})
    assert agent.sync_hitl() == [] and not srv.blocked_ips()
    assert "ignored: unsigned decision row" in caplog.text


def test_a_tampered_signed_row_does_not_approve(tmp_path, monkeypatch):
    agent, srv, aid = _setup(tmp_path, monkeypatch)
    ConsoleAPI(None, tmp_path).decide(aid, "rejected", decided_by="analyst:priya")
    lines = (tmp_path / "decisions.jsonl").read_text().splitlines()
    row = json.loads(lines[-1]); row["status"] = "approved"; row["decided_by"] = "ciso:forged"   # keeps the old sig
    (tmp_path / "decisions.jsonl").write_text(json.dumps(row) + "\n")
    assert agent.sync_hitl() == [] and not srv.blocked_ips()


def test_the_console_decision_is_signed_and_runs(tmp_path, monkeypatch):
    agent, srv, aid = _setup(tmp_path, monkeypatch)
    assert ConsoleAPI(None, tmp_path).decide(aid, "approved", decided_by="analyst:priya")[0] == 200
    assert "sig" in json.loads((tmp_path / "decisions.jsonl").read_text().splitlines()[-1])
    (d,) = agent.sync_hitl()
    assert d.status == "approved" and d.decided_by == "analyst:priya" and srv.blocked_ips() == {"203.0.113.9"}


def test_cli_signs_an_operator_decision(tmp_path, monkeypatch):
    agent, srv, aid = _setup(tmp_path, monkeypatch)
    assert hitl_cli(["decide", aid, "approve", "--by", "ops:ravi", "--dir", str(tmp_path)]) == 0
    (d,) = agent.sync_hitl()
    assert d.status == "approved" and srv.blocked_ips()


def test_nobody_may_claim_to_be_the_service(tmp_path, monkeypatch):
    agent, srv, aid = _setup(tmp_path, monkeypatch)
    assert hitl_cli(["decide", aid, "approve", "--by", "aegis:hitl-timeout", "--dir", str(tmp_path)]) == 2
    from aegis.hitl.signing import sign
    _append(tmp_path, sign({"approval_id": aid, "status": "approved", "decided_by": "aegis:hitl-timeout", "ts": 1.0}))
    assert agent.sync_hitl() == [] and not srv.blocked_ips()


def test_without_a_key_rows_are_accepted_with_a_warning(tmp_path, monkeypatch, caplog):
    agent, _srv, aid = _setup(tmp_path, monkeypatch)
    monkeypatch.delenv("AEGIS_CONSOLE_TOKEN")
    monkeypatch.delenv("AEGIS_DECISION_KEY", raising=False)
    import aegis.hitl.signing as sg
    monkeypatch.setattr(sg, "_warned", False)
    _append(tmp_path, {"approval_id": aid, "status": "approved", "decided_by": "lab"})
    (d,) = agent.sync_hitl()
    assert d.status == "approved" and "NOT signed" in caplog.text


def test_a_forged_model_promotion_acceptance_is_ignored(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AEGIS_CONSOLE_TOKEN", "console-token-for-tests")
    from aegis.finetune.retrain import _accepted_local
    (tmp_path / "proposals.jsonl").write_text(json.dumps({"id": "model-promotion:r1", "change_type": "model_promotion",
                                                          "change": {"run": "r1"}}) + "\n")
    (tmp_path / "proposal-decisions.jsonl").write_text(json.dumps({"proposal_id": "model-promotion:r1", "decision": "accept",
                                                                   "decided_by": "ciso"}) + "\n")
    assert _accepted_local(False, tmp_path) == [] and "unsigned" in capsys.readouterr().out
    ConsoleAPI(None, tmp_path).decide_proposal("model-promotion:r1", "accept", decided_by="ciso:asha", rationale="ok")
    assert _accepted_local(False, tmp_path)[0]["decided_by"] == "ciso:asha"
