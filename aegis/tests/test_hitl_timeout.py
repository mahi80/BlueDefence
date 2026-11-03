"""HITL timeout fallback (AEGIS_HITL_TIMEOUT) — the few-analyst auto-execute policy.

Design under test: unanimity/clear reversible cases keep moving on a timeout; irreversible
actions and split/dissent votes hold for a human. Default off == byte-identical old behaviour.
"""
from __future__ import annotations

import time

from aegis.agents.response.hitl_timeout import HitlTimeoutPolicy, HOLD, SHADOW, EXECUTE
from aegis.agents.shared.evidence_chain import EvidenceChain, RecommendedAction
from aegis.hitl.base import BaseHITL


def _chain(conf: float = 0.75, concur=True, verdict: str = "suspicious") -> EvidenceChain:
    c = EvidenceChain(alert_id="A1", investigated_by="test", verdict=verdict, confidence=conf)
    c.metadata["vote_concur"] = concur
    c.metadata["vote_tally"] = "2/3"
    return c


def _action(atype: str = "block", target: str = "203.0.113.5", conf: float = 0.75) -> RecommendedAction:
    return RecommendedAction(action_type=atype, target=target, reasoning="r", requires_hitl=True, confidence=conf)


# ---- policy.evaluate ---------------------------------------------------

def test_off_always_holds():
    p = HitlTimeoutPolicy(mode="off", wait_sec=120)
    assert p.evaluate(_action("block"), _chain(), age_sec=9999)[0] == HOLD


def test_within_window_holds():
    p = HitlTimeoutPolicy(mode="live", wait_sec=120)
    assert p.evaluate(_action("block"), _chain(), age_sec=30)[0] == HOLD


def test_reversible_majority_concur_executes_live():
    p = HitlTimeoutPolicy(mode="live", wait_sec=120, min_confidence=0.6)
    for atype in ("block", "block_egress", "throttle", "challenge"):
        d, why = p.evaluate(_action(atype, target="evil-c2.example" if atype == "block_egress" else "203.0.113.5"),
                            _chain(conf=0.97, concur=True), age_sec=200)
        assert d == EXECUTE, (atype, why)


def test_confidence_floor_follows_the_action_impact():
    """Per-impact floors from the action contracts (AiSOC's approval-matrix idea): the timeout's own 0.6 floor
    is not enough for a moderate block (0.85) or a high-impact egress block (0.95)."""
    p = HitlTimeoutPolicy(mode="live", wait_sec=120, min_confidence=0.6)
    assert p.evaluate(_action("throttle"), _chain(conf=0.75), age_sec=200)[0] == EXECUTE          # low: 0.70
    assert p.evaluate(_action("block"), _chain(conf=0.75), age_sec=200)[0] == HOLD                # moderate: 0.85
    assert p.evaluate(_action("block"), _chain(conf=0.9), age_sec=200)[0] == EXECUTE
    egress = _action("block_egress", target="evil-c2.example")
    assert p.evaluate(egress, _chain(conf=0.9), age_sec=200)[0] == HOLD                           # high: 0.95


def test_irreversible_always_holds_even_past_window():
    p = HitlTimeoutPolicy(mode="live", wait_sec=120)
    for atype in ("isolate", "revoke_sessions", "lock_account", "rotate_credential", "kill_process"):
        d, why = p.evaluate(_action(atype), _chain(concur=True), age_sec=9999)
        assert d == HOLD, (atype, why)


def test_dissent_or_tie_holds():
    p = HitlTimeoutPolicy(mode="live", wait_sec=120)
    d, why = p.evaluate(_action("block"), _chain(concur=False), age_sec=200)
    assert d == HOLD and "majority concur" in why


def test_low_confidence_holds():
    p = HitlTimeoutPolicy(mode="live", wait_sec=120, min_confidence=0.6)
    assert p.evaluate(_action("block"), _chain(conf=0.4), age_sec=200)[0] == HOLD


def test_shadow_is_eligible_but_record_only():
    p = HitlTimeoutPolicy(mode="shadow", wait_sec=120)
    assert p.evaluate(_action("block"), _chain(conf=0.9, concur=True), age_sec=200)[0] == SHADOW


def test_from_env_defaults_off(monkeypatch):
    monkeypatch.delenv("AEGIS_HITL_TIMEOUT", raising=False)
    assert HitlTimeoutPolicy.from_env().mode == "off"
    monkeypatch.setenv("AEGIS_HITL_TIMEOUT", "live")
    monkeypatch.setenv("AEGIS_HITL_TIMEOUT_SEC", "90")
    pol = HitlTimeoutPolicy.from_env()
    assert pol.mode == "live" and pol.wait_sec == 90


# ---- integration through BaseHITL.sync --------------------------------

class _StubHITL(BaseHITL):
    """A transport where no human ever decides — isolates the timeout path."""
    name = "stub"
    def __init__(self):
        super().__init__(state_path="off")
    def _file(self, card):
        return "ext-" + card["id"]
    def _poll(self, p):
        return None


class _StubResp:
    def __init__(self):
        self.approved = []
    def approve(self, action, approver, source_alert_id=None):
        self.approved.append((action, approver, source_alert_id))
        return f"executed:{action.action_type}"


def _file_aged(h: _StubHITL, action, chain, age_sec: float) -> str:
    aid = h.request(action, chain, timeout_ok=True)      # filed as unattended-eligible
    h._pending[aid].requested_at = time.time() - age_sec
    return aid


def test_sync_auto_executes_reversible_on_timeout():
    h, ra = _StubHITL(), _StubResp()
    _file_aged(h, _action("block"), _chain(conf=0.9, concur=True), age_sec=300)
    decs = h.sync(ra, timeout_policy=HitlTimeoutPolicy(mode="live", wait_sec=120))
    assert len(ra.approved) == 1 and ra.approved[0][0].action_type == "block"
    assert ra.approved[0][1] == "aegis:hitl-timeout"
    assert any(d.status == "approved" and d.decided_by == "aegis:hitl-timeout" for d in decs)
    assert not h.pending   # settled, no longer pending


def test_sync_holds_irreversible_on_timeout():
    h, ra = _StubHITL(), _StubResp()
    _file_aged(h, _action("isolate"), _chain(concur=True), age_sec=300)
    decs = h.sync(ra, timeout_policy=HitlTimeoutPolicy(mode="live", wait_sec=120))
    assert ra.approved == [] and decs == []
    assert len(h.pending) == 1   # still waiting for a human


def test_sync_holds_on_dissent():
    h, ra = _StubHITL(), _StubResp()
    _file_aged(h, _action("block"), _chain(concur=False), age_sec=300)
    h.sync(ra, timeout_policy=HitlTimeoutPolicy(mode="live", wait_sec=120))
    assert ra.approved == [] and len(h.pending) == 1


def test_sync_shadow_does_not_execute():
    h, ra = _StubHITL(), _StubResp()
    _file_aged(h, _action("block"), _chain(concur=True), age_sec=300)
    h.sync(ra, timeout_policy=HitlTimeoutPolicy(mode="shadow", wait_sec=120))
    assert ra.approved == [] and len(h.pending) == 1


def test_no_policy_preserves_plain_expiry():
    # back-compat: no timeout_policy + max_age_sec -> expired, nothing executed
    h, ra = _StubHITL(), _StubResp()
    _file_aged(h, _action("block"), _chain(concur=True), age_sec=300)
    decs = h.sync(ra, max_age_sec=120)
    assert ra.approved == []
    assert len(decs) == 1 and decs[0].status == "expired"
    assert not h.pending


def test_off_policy_with_max_age_still_expires():
    h, ra = _StubHITL(), _StubResp()
    _file_aged(h, _action("block"), _chain(concur=True), age_sec=300)
    decs = h.sync(ra, max_age_sec=120, timeout_policy=HitlTimeoutPolicy(mode="off"))
    assert ra.approved == []
    assert len(decs) == 1 and decs[0].status == "expired"
