"""Action contracts (idea from AiSOC's capability contracts + approval matrix): every action type has one, the
agent's auto-safe / always-HITL sets come from them, and an unattended action clears contract, tier and
confidence. Pinned expectations below are deliberate: weakening a contract must be a visible test change
(code review 2026-11-03 T7 — dropping `config_rollback` from the HITL set used to pass the whole suite)."""

from __future__ import annotations

import io

import pytest

from aegis.agents.response import agent as A
from aegis.agents.response.contracts import (
    CONTRACTS,
    Impact,
    always_hitl,
    auto_safe,
    gate,
    missing_contracts,
)
from aegis.agents.shared.evidence_chain import EvidenceChain, RecommendedAction

NEVER_UNATTENDED = {"block_egress", "block_export", "config_rollback", "escalate_to_fraud_team", "escalate_to_hr",
                    "interface_shutdown", "isolate", "kill_process", "lock_account", "quarantine_file", "recall_message",
                    "revoke_sessions", "rotate_credential", "snapshot_forensic", "trigger_self_heal"}


def test_every_action_type_has_a_contract():
    assert missing_contracts() == []


def test_agent_sets_are_the_contract_sets():
    assert A._ALWAYS_HITL_ACTIONS == set(always_hitl()) and A._AUTO_SAFE_ACTIONS == set(auto_safe())
    assert not (A._ALWAYS_HITL_ACTIONS & A._AUTO_SAFE_ACTIONS)


def test_pinned_policy():
    assert NEVER_UNATTENDED | {"block", "hold"} == set(always_hitl())
    assert set(auto_safe()) == {"allow", "monitor", "notify_user", "challenge", "throttle", "redact", "force_logout",
                                "quarantine_message"}
    assert {a for a, c in CONTRACTS.items() if c.impact == Impact.IRREVERSIBLE} == {"kill_process", "recall_message",
                                                                                     "rotate_credential"}


def _chain(conf):
    return EvidenceChain(alert_id="A", investigated_by="t", verdict="malicious", confidence=conf)


def _act(t):
    return RecommendedAction(action_type=t, target="203.0.113.7", reasoning="r", requires_hitl=False, confidence=0.9)


@pytest.mark.parametrize("action", sorted(NEVER_UNATTENDED))
def test_severe_or_policy_actions_never_pass_the_gate(action, monkeypatch):
    monkeypatch.setenv("AEGIS_AUTONOMY_TIER", "L4")
    ok, _ = gate(_act(action), _chain(1.0))
    assert not ok or CONTRACTS[action].impact == Impact.HIGH


def test_confidence_floor_per_impact():
    assert gate(_act("throttle"), _chain(0.72))[0] and not gate(_act("throttle"), _chain(0.6))[0]
    assert gate(_act("force_logout"), _chain(0.9))[0] and not gate(_act("force_logout"), _chain(0.8))[0]
    assert gate(_act("monitor"), _chain(0.0))[0]


@pytest.mark.parametrize("tier,allowed", [("L0", {"monitor"}), ("L1", {"monitor"}), ("L2", {"monitor", "throttle"}),
                                          ("L3", {"monitor", "throttle", "force_logout"}),
                                          ("L4", {"monitor", "throttle", "force_logout", "hold"}),
                                          ("bogus", {"monitor"})])
def test_autonomy_tier_ceiling(monkeypatch, tier, allowed):
    monkeypatch.setenv("AEGIS_AUTONOMY_TIER", tier)
    ran = {a for a in ("monitor", "throttle", "force_logout", "hold") if gate(_act(a), _chain(0.99))[0]}
    assert ran == allowed


def test_protected_target_raises_impact():
    assert gate(_act("throttle"), _chain(0.8))[0]
    assert not gate(_act("throttle"), _chain(0.8), protected=True)[0]          # low → moderate: needs 0.85


def test_hand_off_and_unknown_never_execute():
    assert not gate(_act("escalate"), _chain(1.0))[0]
    assert not gate(_act("nonsense"), _chain(1.0))[0]


def test_low_confidence_guess_waits_for_a_human_end_to_end():
    """A 40%-confidence chain used to throttle with no human, exactly like a 0.97 one."""
    from aegis.agents.response.connectors import ConnectorRegistry
    from aegis.agents.response.connectors.base import LoggingConnector
    conn = LoggingConnector(dry_run=False)
    agent = A.ResponseAgent(connectors=ConnectorRegistry([conn], fallback=conn), hitl_stream=io.StringIO())
    for conf, ran in ((0.4, False), (0.97, True)):
        c = _chain(conf)
        c.recommended_actions.append(_act("throttle"))
        s = agent.execute(c.finalize(), {"src_ip": "203.0.113.7"})
        assert bool(s.executed) is ran


def test_never_block_guard_in_approve_is_live():
    """Review T2 / mutation M05: removing the never-block check from approve() passed the whole suite. It is
    the only guard on the self-healing isolate branch, which bypasses the connector registry."""
    from aegis.agents.response.connectors import ConnectorRegistry
    from aegis.agents.response.connectors.base import LoggingConnector

    class Heal:
        def __init__(self):
            self.severed = []

        def snapshot_and_sever(self, target, source_alert=None):
            self.severed.append(target)
    heal = Heal()
    conn = LoggingConnector(dry_run=False)
    agent = A.ResponseAgent(connectors=ConnectorRegistry([], fallback=conn), self_healing=heal, hitl_stream=io.StringIO())
    act = RecommendedAction(action_type="isolate", target="127.0.0.1", reasoning="r", requires_hitl=True, confidence=0.9)
    assert agent.approve(act, approver="ciso").status == "skipped" and heal.severed == []
    ok = RecommendedAction(action_type="isolate", target="203.0.113.7", reasoning="r", requires_hitl=True, confidence=0.9)
    assert agent.approve(ok, approver="ciso").status == "executed" and heal.severed == ["203.0.113.7"]


def test_verify_adapter_refuses_a_missing_digest(tmp_path):
    """Review T3 / mutation M09."""
    from aegis.finetune.digest import verify_adapter
    (tmp_path / "a.safetensors").write_bytes(b"w")
    assert verify_adapter(tmp_path, None)[0] is False and verify_adapter(tmp_path, "")[0] is False
