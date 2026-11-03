"""A human-approved action is not undone by the TTL sweep an hour later (code review 2026-11-02, response #9)."""

from __future__ import annotations

from aegis.agents.response.agent import ResponseAgent, approved_ttl_sec
from aegis.agents.response.connectors import ConnectorRegistry
from aegis.agents.response.connectors.base import LoggingConnector
from aegis.agents.shared.evidence_chain import RecommendedAction


class _Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


def _agent(clock):
    conn = LoggingConnector(dry_run=False, clock=clock)
    return ResponseAgent(connectors=ConnectorRegistry([conn], fallback=conn)), conn


def _act(t, target):
    return RecommendedAction(action_type=t, target=target, reasoning="r", requires_hitl=True, confidence=0.9)


def test_approved_containment_survives_the_sweep(monkeypatch):
    monkeypatch.delenv("AEGIS_APPROVED_TTL_SEC", raising=False)
    clock = _Clock()
    agent, conn = _agent(clock)
    for t, target in (("isolate", "host:app-ledger-07"), ("block_egress", "evil-c2.example"), ("lock_account", "u-1")):
        assert agent.approve(_act(t, target), approver="ciso@bank").status == "executed"
    clock.t += 7 * 86400
    assert agent.sweep_expired() == []
    assert {r.target for r in conn.active_receipts} == {"host:app-ledger-07", "evil-c2.example", "u-1"}
    assert all(r.expires_at is None for r in conn.active_receipts)


def test_approved_ip_block_lasts_a_day_then_expires(monkeypatch):
    monkeypatch.delenv("AEGIS_APPROVED_BLOCK_TTL_SEC", raising=False)
    clock = _Clock()
    agent, _conn = _agent(clock)
    agent.approve(_act("block", "203.0.113.7"), approver="soc-l2@bank")
    clock.t += 3600 + 1
    assert agent.sweep_expired() == []
    clock.t += 86400
    assert [r.target for r in agent.sweep_expired()] == ["203.0.113.7"]


def test_timeout_path_keeps_the_connector_default():
    assert approved_ttl_sec("block", "aegis:hitl-timeout") is None
    assert approved_ttl_sec("isolate", "ciso@bank") == 0


def test_automated_reapply_never_shortens_an_approved_action():
    clock = _Clock()
    agent, conn = _agent(clock)
    agent.approve(_act("block_egress", "evil-c2.example"), approver="ciso@bank")
    conn.apply(_act("block_egress", "evil-c2.example"), alert_id="A-2", ttl_sec=3600)     # automated re-apply
    (r,) = conn.active_receipts
    assert r.expires_at is None and "ciso@bank" in r.approver
    clock.t += 2 * 3600
    assert agent.sweep_expired() == []
