"""Pending approvals survive a restart (every transport), and decisions taken while AEGIS was down
are applied on the next sync. Before the journal, a restart silently dropped every pending card."""

from __future__ import annotations

import io
import json
import logging


from aegis.agents.response.agent import ResponseAgent
from aegis.agents.response.autonomy import AutonomyPolicy
from aegis.agents.response.connectors import ConnectorRegistry
from aegis.agents.response.connectors.cloud_waf import CloudflareWafConnector
from aegis.agents.response.connectors import mock_cloud_waf as m
from aegis.agents.shared.evidence_chain import EvidenceChain, RecommendedAction
from aegis.hitl import DashboardHITL, FileHITL, ServiceNowHITL
from test_edition_and_hitl_transports import SNow
from test_hitl_dashboard import FakeDashboard


def _chain(aid="web-1", target="203.0.113.7"):
    c = EvidenceChain(alert_id=aid, investigated_by="perimeter", verdict="malicious", confidence=0.91)
    c.recommended_actions.append(RecommendedAction(action_type="block", target=target, reasoning="stuffing", requires_hitl=True, confidence=0.9))
    return c.finalize()


class Resp:
    def __init__(self):
        self.approved = []

    def approve(self, action, approver, source_alert_id):
        self.approved.append((action.action_type, action.target, approver, source_alert_id))
        return {"status": "executed"}


def test_file_transport_restart_then_decision(tmp_path):
    state = tmp_path / "state.jsonl"
    h1 = FileHITL(tmp_path / "hitl", state_path=state)
    c1, c2 = _chain("web-1"), _chain("web-2", "198.51.100.9")
    a1 = h1.request(c1.recommended_actions[0], c1)
    a2 = h1.request(c2.recommended_actions[0], c2)
    # analyst rejects one before the crash
    with h1.decisions_file.open("a") as f:
        f.write(json.dumps({"approval_id": a2, "status": "rejected", "decided_by": "soc"}) + "\n")
    assert [d.status for d in h1.sync(Resp())] == ["rejected"]
    del h1                                                       # ---- crash / redeploy
    with (tmp_path / "hitl" / "decisions.jsonl").open("a") as f:  # decision taken while AEGIS was down
        f.write(json.dumps({"approval_id": a1, "status": "approved", "decided_by": "ciso"}) + "\n")
    h2 = FileHITL(tmp_path / "hitl", state_path=state)
    assert [p.approval_id for p in h2.pending] == [a1] and h2.restored == 1
    p = h2.pending[0]
    assert p.action.target == "203.0.113.7" and p.alert_id == "web-1" and p.chain.metadata["restored_from_journal"]
    r = Resp()
    (d,) = h2.sync(r)
    assert d.status == "approved" and r.approved == [("block", "203.0.113.7", "ciso", "web-1")]
    # settled → a third start restores nothing; the journal was compacted
    h3 = FileHITL(tmp_path / "hitl", state_path=state)
    assert h3.pending == [] and h3.restored == 0
    assert h2.request(c1.recommended_actions[0], c1) != a1      # idempotency key was released on settle


def test_journal_defaults_to_the_file_transport_directory(tmp_path, monkeypatch):
    monkeypatch.delenv("AEGIS_HITL_STATE")
    h = FileHITL(tmp_path / "hitl")
    c = _chain()
    h.request(c.recommended_actions[0], c)
    assert (tmp_path / "hitl" / "pending.jsonl").exists()
    monkeypatch.setenv("AEGIS_HITL_STATE", "off")
    h_off = FileHITL(tmp_path / "hitl2")
    h_off.request(c.recommended_actions[0], c)
    assert not (tmp_path / "hitl2" / "pending.jsonl").exists()


def test_dashboard_transport_restart_polls_the_same_approval(tmp_path):
    dash = FakeDashboard()
    state = tmp_path / "s.jsonl"
    h1 = DashboardHITL("https://dash.test", "k", transport=dash, state_path=state)
    c = _chain()
    aid = h1.request(c.recommended_actions[0], c)
    dash.decide(aid, "approved", by="ciso@bank.in")
    h2 = DashboardHITL("https://dash.test", "k", transport=dash, state_path=state)
    r = Resp()
    (d,) = h2.sync(r)
    assert d.approval_id == aid and r.approved[0][2] == "ciso@bank.in"
    assert sum(1 for mth, url, *_ in dash.calls if url.endswith("/api/approvals/create")) == 1   # not re-filed


def test_servicenow_transport_restart_keeps_the_ticket(tmp_path):
    sn = SNow()
    state = tmp_path / "s.jsonl"
    h1 = ServiceNowHITL("https://bank.service-now.com", user="u", password="p", transport=sn, state_path=state)
    c = _chain()
    aid = h1.request(c.recommended_actions[0], c)
    h2 = ServiceNowHITL("https://bank.service-now.com", user="u", password="p", transport=sn, state_path=state)
    assert h2.pending[0].approval_id == aid and h2.pending[0].external_id == "sys1"
    assert h2.request(c.recommended_actions[0], c) == aid and len(sn.records) == 1     # idempotent across the restart


def test_other_transports_entries_corrupt_rows_and_expiry(tmp_path, caplog):
    state = tmp_path / "s.jsonl"
    h1 = FileHITL(tmp_path / "hitl", state_path=state)
    c = _chain()
    aid = h1.request(c.recommended_actions[0], c)
    with state.open("a") as f:
        f.write("not json\n")
        f.write(json.dumps({"transport": "file", "op": "filed", "approval_id": "bad", "alert_id": "x", "action": {"nope": 1}}) + "\n")
        f.write(json.dumps({"transport": "dashboard", "op": "filed", "approval_id": "dash-1", "alert_id": "y",
                            "action": c.recommended_actions[0].model_dump()}) + "\n")
    with caplog.at_level(logging.WARNING):
        h2 = FileHITL(tmp_path / "hitl", state_path=state)
        assert [p.approval_id for p in h2.pending] == [aid]
    assert any("not restorable" in r.message for r in caplog.records) and any("unreadable row" in r.message for r in caplog.records)
    # requested_at survives, so expiry still counts from the original filing
    h2.pending[0].requested_at -= 3600
    (d,) = h2.sync(Resp(), max_age_sec=60)
    assert d.status == "expired"


def test_unwritable_journal_is_loud_but_never_blocks_filing(tmp_path, caplog):
    blocker = tmp_path / "is-a-file"
    blocker.write_text("x")
    h = FileHITL(tmp_path / "hitl", state_path=blocker / "pending.jsonl")
    c = _chain()
    with caplog.at_level(logging.WARNING):
        aid = h.request(c.recommended_actions[0], c)
    assert aid and h.pending and any("will not survive a restart" in r.message for r in caplog.records)


def test_service_restart_executes_a_block_approved_while_down(tmp_path, monkeypatch):
    """End to end: the real ResponseAgent + live mock Cloudflare across two process lifetimes."""
    state = tmp_path / "state.jsonl"
    srv = m.MockCloudflare(token="t")

    def agent():
        cf = CloudflareWafConnector(api_token="t", zone_id="z", base_url=m.CF_BASE, transport=srv, dry_run=False)
        return ResponseAgent(connectors=ConnectorRegistry([cf]), hitl=FileHITL(tmp_path / "hitl", state_path=state),
                             autonomy=AutonomyPolicy(mode="off"), hitl_stream=io.StringIO())
    a1 = agent()
    s = a1.execute(_chain("web-9", "203.0.113.99"))
    assert s.hitl_queue and not srv.blocked()
    aid = a1._hitl.pending[0].approval_id
    del a1                                                                   # ---- restart
    with (tmp_path / "hitl" / "decisions.jsonl").open("a") as f:
        f.write(json.dumps({"approval_id": aid, "status": "approved", "decided_by": "ciso"}) + "\n")
    a2 = agent()
    (d,) = a2.sync_hitl()
    assert d.status == "approved" and srv.blocked() == {"203.0.113.99"}
