"""Outflow guard, outflow circuit breaker, privileged-identity guard — what fires, and what must not."""

from __future__ import annotations

import pytest

from aegis.agents.orchestrator.privileged import is_privileged_event, privileged_chain
from aegis.agents.orchestrator.treasury import BOOK, is_treasury_outflow, treasury_outflow_chain
from aegis.agents.response.breaker import OutflowBreaker
from aegis.agents.shared.evidence_chain import RecommendedAction


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    BOOK.reset()
    for k in ("AEGIS_HIGH_VALUE_INR", "AEGIS_OUTFLOW_BURST_N", "AEGIS_OUTFLOW_WINDOW_S", "AEGIS_TREASURY_ACCOUNTS",
              "AEGIS_PRIVILEGED_USERS", "AEGIS_PRIVILEGED_HOSTS", "AEGIS_CROWN_JEWELS"):
        monkeypatch.delenv(k, raising=False)
    yield
    BOOK.reset()


def _txn(i, amount=4e9, *, sender="ACC-TREASURY-NOSTRO-01", new=True, minute=0, user="svc_payments_signer"):
    return {"id": f"T{i}", "source": "Core Banking (txn stream)", "rail": "SWIFT", "amount_inr": amount,
            "user_id": user, "sender_account": sender, "beneficiary_account": f"ACC-NEW-{i}", "new_beneficiary": new,
            "sender_geo": "IN", "beneficiary_geo": "HK", "timestamp": f"2026-10-29T20:{minute:02d}:00+00:00"}


# ---- outflow guard -------------------------------------------------------

def test_small_or_known_beneficiary_transfers_stay_with_the_transaction_specialist():
    assert not is_treasury_outflow(_txn(1, amount=5e6))                 # under INR 1 crore
    assert not is_treasury_outflow(_txn(2, new=False))                  # routine payment to a known payee
    assert not is_treasury_outflow({"id": "x", "source": "Okta"})


def test_unknown_beneficiary_fails_closed():
    a = _txn(1)
    del a["new_beneficiary"]                                            # no flag: the register decides, unknown = new
    assert is_treasury_outflow(a)


def test_single_large_transfer_is_held_for_a_human_and_burst_becomes_a_drain():
    c1 = treasury_outflow_chain(_txn(1, minute=5))
    assert (c1.investigated_by, c1.verdict, c1.confidence) == ("treasury", "suspicious", 0.85)
    assert [(a.action_type, a.requires_hitl) for a in c1.recommended_actions][0] == ("hold", True)
    assert not c1.metadata.get("outflow_breaker")
    treasury_outflow_chain(_txn(2, minute=6))
    c3 = treasury_outflow_chain(_txn(3, minute=7))
    assert (c3.verdict, c3.confidence) == ("malicious", 0.95)
    assert c3.metadata["outflow_breaker"] is True and c3.metadata["treasury"]["count"] == 3
    hold = c3.recommended_actions[0]
    assert (hold.action_type, hold.target, hold.requires_hitl) == ("hold", "outbound:ACC-TREASURY-NOSTRO-01", False)


def test_burst_window_and_dedup():
    treasury_outflow_chain(_txn(1, minute=0))
    treasury_outflow_chain(_txn(1, minute=0))                            # same transaction replayed: counted once
    c = treasury_outflow_chain(_txn(2, minute=59))                        # 59 min later: outside the 30-min window
    assert c.metadata["treasury"]["count"] == 1 and not c.metadata.get("outflow_breaker")


def test_customer_account_large_new_payee_is_suspicious_not_treasury():
    c = treasury_outflow_chain(_txn(1, sender="ACC-CUST-889", user="u_123"))
    assert (c.verdict, c.confidence) == ("suspicious", 0.75) and c.metadata["treasury"]["treasury_sender"] is False


# ---- breaker -------------------------------------------------------------

def _burst_chain():
    for i, m in ((1, 0), (2, 1)):
        treasury_outflow_chain(_txn(i, minute=m))
    return treasury_outflow_chain(_txn(3, minute=2))


def test_breaker_only_takes_the_burst_hold_on_outbound():
    br = OutflowBreaker(mode="live")
    c = _burst_chain()
    ok, _ = br.check(c.recommended_actions[0], c)
    assert ok
    single = treasury_outflow_chain(_txn(9, minute=40))                  # a lone transfer: never auto
    assert not br.check(single.recommended_actions[0], single)[0]
    wide = RecommendedAction(action_type="hold", target="all-payments", requires_hitl=False, confidence=0.95, reasoning="x")
    assert not br.check(wide, c)[0]                                      # nothing wider than one sender
    c.metadata["vote_concur"] = False
    assert not br.check(c.recommended_actions[0], c)[0]                  # a dissenting voter keeps it human


def test_breaker_budget_and_off(monkeypatch):
    br = OutflowBreaker(mode="live", max_per_hour=1)
    c = _burst_chain()
    assert br.check(c.recommended_actions[0], c)[0]
    br.take()
    assert not br.check(c.recommended_actions[0], c)[0]
    assert not OutflowBreaker(mode="off").check(c.recommended_actions[0], c)[0]
    monkeypatch.setenv("AEGIS_OUTFLOW_BREAKER", "live")
    assert OutflowBreaker.from_env().mode == "live"
    monkeypatch.delenv("AEGIS_OUTFLOW_BREAKER")
    assert OutflowBreaker.from_env().mode == "shadow"                     # shadow by default


class _StubConnectors:
    """Records what the response agent asked for; ``active`` decides whether the vendor placed it."""

    def __init__(self, active: bool):
        self.active, self.applied, self.previewed = active, [], []

    def apply(self, action, **kw):
        from types import SimpleNamespace
        self.applied.append((action.action_type, str(action.target), kw.get("approver"), kw.get("ttl_sec")))
        return SimpleNamespace(status="applied" if self.active else "dry_run", active=self.active,
                               connector="stub-soar", detail="held", error="")

    def preview(self, action, **kw):
        self.previewed.append((action.action_type, str(action.target), kw.get("approver")))


def test_response_agent_runs_the_burst_hold_only_when_live():
    import io
    from aegis.agents.response.agent import ResponseAgent

    def dispatch(mode, active=True, chain=None):
        BOOK.reset()
        c = chain or _burst_chain()
        stub = _StubConnectors(active)
        agent = ResponseAgent(hitl_stream=io.StringIO(), breaker=OutflowBreaker(mode=mode, ttl_sec=3600), connectors=stub)
        return agent._dispatch(c.recommended_actions[0], c), stub

    done, stub = dispatch("live")                                       # live: placed now, with the TTL, by the breaker
    assert done.status == "executed" and stub.applied == [("hold", "outbound:ACC-TREASURY-NOSTRO-01", "aegis:breaker", 3600)]
    done, stub = dispatch("live", active=False)                         # vendor did not place it: still a human's
    assert done.status == "queued_for_hitl"
    done, stub = dispatch("shadow")                                     # shadow: recorded, not placed, human decides
    assert done.status == "queued_for_hitl" and stub.applied == []
    assert stub.previewed == [("hold", "outbound:ACC-TREASURY-NOSTRO-01", "aegis:breaker-shadow")]
    BOOK.reset()
    single = treasury_outflow_chain(_txn(9, minute=40))
    done, stub = dispatch("live", chain=single)                         # a lone transfer's hold never runs by itself
    assert done.status == "queued_for_hitl" and stub.applied == []


# ---- privileged guard ----------------------------------------------------

def _edr(**kw):
    a = {"id": "E1", "source": "CrowdStrike Falcon", "event": "tamper_protection_disabled", "host": "DEVOPS-LT-07",
         "user": "u_devops_12", "host_role": "laptop", "prior_event_30m": "credential_store_access"}
    a.update(kw)
    return a


def test_engineer_laptop_compromise_is_a_crown_jewel_incident(monkeypatch):
    assert not is_privileged_event(_edr())                               # not configured as privileged: not this path
    monkeypatch.setenv("AEGIS_PRIVILEGED_HOSTS", "DEVOPS-LT-07")
    c = privileged_chain(_edr())
    assert (c.investigated_by, c.verdict, c.confidence) == ("privileged", "malicious", 0.92)
    acts = {(a.action_type, a.target, a.requires_hitl) for a in c.recommended_actions}
    assert {("isolate", "DEVOPS-LT-07", True), ("revoke_sessions", "u_devops_12", True),
            ("rotate_credential", "u_devops_12", True)} <= acts


def test_role_tag_marks_an_engineer_and_maintenance_is_not_compromise():
    assert is_privileged_event(_edr(host="X", user="u_9", user_role="DevSecOps engineer"))
    assert not is_privileged_event(_edr(host="X", user="u_9", user_role="DevSecOps",
                                        context={"maintenance_window": {"ticket": "CHG-1", "covers_host": True}}))


def _exec(**kw):
    a = {"id": "K1", "source": "Kubernetes Audit", "user": "u_devops_12", "verb": "create", "resource": "pods/exec",
         "namespace": "payments", "name": "withdrawal-signer-0", "change_ticket": None, "outside_change_window": True,
         "first_seen_source_ip_for_user": True}
    a.update(kw)
    return a


def test_crown_jewel_access_scored_on_its_signals(monkeypatch):
    monkeypatch.setenv("AEGIS_PRIVILEGED_USERS", "u_devops_12")
    c = privileged_chain(_exec())
    assert (c.verdict, c.confidence) == ("malicious", 0.88)
    assert ("revoke_sessions", "u_devops_12") in {(a.action_type, a.target) for a in c.recommended_actions}
    ok = privileged_chain(_exec(change_ticket="CHG-7781", outside_change_window=False, first_seen_source_ip_for_user=False))
    assert ok.verdict == "benign" and [a.action_type for a in ok.recommended_actions] == ["monitor"]
    assert not is_privileged_event(_exec(namespace="marketing", name="cms-0"))      # not a crown jewel


def test_signer_policy_change_without_controls_holds_its_payments():
    a = {"id": "P1", "source": "Payment Signer (HSM audit)", "event": "signing_policy_changed",
         "actor": "svc-withdrawal-signer", "change": "allowlist +18", "change_ticket": None,
         "outside_change_window": True, "dual_control": False, "user": "u_devops_12"}
    assert is_privileged_event(a)
    c = privileged_chain(a)
    assert (c.verdict, c.confidence) == ("malicious", 0.93)
    hold = next(x for x in c.recommended_actions if x.action_type == "hold")
    assert hold.target == "outbound:svc-withdrawal-signer" and hold.requires_hitl is True   # a human holds this one
    approved = privileged_chain({**a, "change_ticket": "CHG-9", "outside_change_window": False, "dual_control": True})
    assert approved.verdict == "benign"
