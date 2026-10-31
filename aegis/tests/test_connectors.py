"""Phase 1.1 — connector contract, receipts, registry, ResponseAgent dispatch."""

from __future__ import annotations

import io


from aegis.agents.response.agent import ResponseAgent
from aegis.agents.response.connectors import (
    Connector, ConnectorError, ConnectorRegistry, LoggingConnector, enforcement_mode,
)
from aegis.agents.shared.evidence_chain import EvidenceChain, RecommendedAction


class FakeClock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


class FakeWaf(Connector):
    """A vendor connector as 1.2 will write it: only _do_apply/_do_rollback."""

    name = "waf-fake"
    actions = frozenset({"block", "throttle", "challenge"})

    def __init__(self, **kw):
        super().__init__(**kw)
        self.calls: list[tuple[str, str]] = []
        self.fail_next = False

    def _do_apply(self, action, key, ttl_sec):
        self.calls.append(("apply", f"{action.action_type}:{action.target}:{ttl_sec}"))
        if self.fail_next:
            self.fail_next = False
            raise ConnectorError("vendor said no")
        return f"rule-{key[:6]}", f"{action.action_type} {action.target} for {ttl_sec}s", f"undo-{key[:6]}"

    def _do_rollback(self, receipt):
        self.calls.append(("rollback", receipt.rollback_token))
        return f"removed {receipt.vendor_ref}"


def _action(action_type="block", target="203.0.113.7", hitl=False):
    return RecommendedAction(action_type=action_type, target=target, reasoning="t",
                             requires_hitl=hitl, confidence=0.9)


def test_apply_is_idempotent_and_ttl_rolls_back_on_sweep():
    clk = FakeClock()
    waf = FakeWaf(dry_run=False, default_ttl_sec=600, clock=clk)
    r1 = waf.apply(_action(), alert_id="A1", approver="ciso")
    assert r1.status == "applied" and r1.active and r1.vendor_ref.startswith("rule-")
    assert r1.expires_at == clk.t + 600 and r1.alert_id == "A1" and r1.approver == "ciso"
    r2 = waf.apply(_action(target="203.0.113.7 "))  # same target, trailing space → same key
    assert r2 is r1 and r1.renewals == 1 and r1.status == "renewed"
    assert len([c for c in waf.calls if c[0] == "apply"]) == 2  # renew re-applies with the vendor
    assert len(waf.active_receipts) == 1

    clk.t += 599
    assert waf.sweep_expired() == []
    clk.t += 2
    swept = waf.sweep_expired()
    assert [r.status for r in swept] == ["expired"] and swept[0] is r1
    assert ("rollback", r1.rollback_token) in waf.calls and waf.active_receipts == []


def test_shadow_mode_never_calls_the_vendor():
    waf = FakeWaf(dry_run=True)
    r = waf.apply(_action("throttle"))
    assert r.status == "dry_run" and r.dry_run and r.active and "[shadow] would throttle" in r.detail
    assert waf.calls == []
    rb = waf.rollback(r)
    assert rb.status == "rolled_back" and waf.calls == []


def test_vendor_failure_becomes_a_failed_receipt_not_an_exception():
    waf = FakeWaf(dry_run=False)
    waf.fail_next = True
    r = waf.apply(_action())
    assert r.status == "failed" and not r.active and "vendor said no" in r.error
    assert waf.active_receipts == []
    assert waf.apply(_action("lock_account")).status == "unsupported"


def test_permanent_receipt_needs_explicit_ttl_zero():
    clk = FakeClock()
    waf = FakeWaf(dry_run=False, clock=clk)
    r = waf.apply(_action(), ttl_sec=0)
    assert r.expires_at is None
    clk.t += 10**9
    assert waf.sweep_expired() == [] and r.active


def test_registry_routes_and_falls_back_to_logging():
    waf = FakeWaf(dry_run=False)
    reg = ConnectorRegistry([waf])
    assert reg.route("block") is waf
    assert isinstance(reg.route("lock_account"), LoggingConnector)
    r = reg.apply(_action("lock_account", "user_42"))
    assert r.connector == "log" and r.status == "applied" and r.active
    assert reg.mode == "live"
    assert ConnectorRegistry([FakeWaf(dry_run=True)]).mode == "shadow"
    assert ConnectorRegistry().mode == "log-only"
    rb = reg.rollback(r)
    assert rb.status == "rolled_back"


def test_enforcement_mode_env(monkeypatch):
    monkeypatch.delenv("AEGIS_ENFORCEMENT_MODE", raising=False)
    assert enforcement_mode() == "shadow" and FakeWaf().dry_run is True
    monkeypatch.setenv("AEGIS_ENFORCEMENT_MODE", "live")
    assert enforcement_mode() == "live" and FakeWaf().dry_run is False


# -------------------------------------------------------- ResponseAgent --

def _chain(alert_id="EVAL-005"):
    c = EvidenceChain(alert_id=alert_id, investigated_by="perimeter", verdict="malicious", confidence=0.9)
    c.recommended_actions.append(_action("throttle"))
    c.recommended_actions.append(_action("block"))
    return c


def test_response_agent_auto_actions_produce_receipts():
    waf = FakeWaf(dry_run=False)
    agent = ResponseAgent(connectors=ConnectorRegistry([waf]), hitl_stream=io.StringIO())
    summary = agent.execute(_chain())
    assert [a.action.action_type for a in summary.executed] == ["throttle"]
    rcpt = summary.executed[0].receipt
    assert rcpt is not None and rcpt.connector == "waf-fake" and rcpt.status == "applied"
    assert rcpt.alert_id == "EVAL-005" and summary.receipts == [rcpt]
    assert "[auto:waf-fake:applied]" in summary.executed[0].note
    assert [a.action.action_type for a in summary.hitl_queue] == ["block"]  # HITL policy unchanged


def test_response_agent_default_registry_is_the_logging_fallback():
    agent = ResponseAgent(hitl_stream=io.StringIO())
    summary = agent.execute(_chain())
    assert summary.executed[0].receipt.connector == "log"
    assert agent.connectors.mode == "log-only"


def test_approve_goes_through_connector_with_approver_on_receipt():
    waf = FakeWaf(dry_run=False)
    agent = ResponseAgent(connectors=ConnectorRegistry([waf]), hitl_stream=io.StringIO())
    ex = agent.approve(_action("block"), approver="ciso@bank.in", source_alert_id="EVAL-005")
    assert ex.status == "executed" and ex.receipt.approver == "ciso@bank.in" and ex.receipt.alert_id == "EVAL-005"
    assert "approved by ciso@bank.in" in ex.note
    assert agent._high_impact_counter == 1

    waf.fail_next = True
    ex2 = agent.approve(_action("block", "198.51.100.9"), approver="ciso@bank.in")
    assert ex2.status == "queued_for_hitl" and ex2.receipt.status == "failed" and "human needed" in ex2.note


def test_two_person_rule_on_protected_targets():
    agent = ResponseAgent(connectors=ConnectorRegistry([FakeWaf(dry_run=False)]),
                          protected_targets=["10.0.0.0/8", "prod-*"], hitl_stream=io.StringIO())
    assert agent.two_person_required(_action("block", "10.1.4.20"))
    assert agent.two_person_required(_action("isolate", "PROD-DB-01"))
    assert not agent.two_person_required(_action("block", "203.0.113.7"))
    assert not agent.two_person_required(_action("throttle", "10.1.4.20"))  # not a two-person action

    ex = agent.approve(_action("block", "10.1.4.20"), approver="ciso")
    assert ex.status == "queued_for_hitl" and "second approver" in ex.note and ex.receipt is None
    ex = agent.approve(_action("block", "10.1.4.20"), approver="ciso", second_approver="ciso")
    assert ex.status == "queued_for_hitl"  # same person twice does not count
    ex = agent.approve(_action("block", "10.1.4.20"), approver="ciso", second_approver="soc-lead")
    assert ex.status == "executed" and ex.receipt.approver == "ciso+soc-lead"
    assert agent._high_impact_counter == 1  # only the executed one consumed the budget


def test_two_person_rule_off_without_protected_targets(monkeypatch):
    monkeypatch.delenv("AEGIS_PROTECTED_TARGETS", raising=False)
    agent = ResponseAgent(connectors=ConnectorRegistry([FakeWaf(dry_run=False)]), hitl_stream=io.StringIO())
    assert agent.approve(_action("block", "10.1.4.20"), approver="ciso").status == "executed"
    monkeypatch.setenv("AEGIS_PROTECTED_TARGETS", "10.0.0.0/8")
    agent2 = ResponseAgent(connectors=ConnectorRegistry([FakeWaf(dry_run=False)]), hitl_stream=io.StringIO())
    assert agent2.approve(_action("block", "10.1.4.20"), approver="ciso").status == "queued_for_hitl"


def test_rate_limit_and_sweep_via_agent():
    clk = FakeClock()
    waf = FakeWaf(dry_run=False, default_ttl_sec=60, clock=clk)
    agent = ResponseAgent(connectors=ConnectorRegistry([waf]), hitl_stream=io.StringIO())
    agent._high_impact_max = 2
    assert agent.approve(_action("block", "1.1.1.1"), approver="a").status == "executed"
    assert agent.approve(_action("block", "2.2.2.2"), approver="a").status == "executed"
    assert agent.approve(_action("block", "3.3.3.3"), approver="a").status == "skipped"
    clk.t += 61
    assert len(agent.sweep_expired()) == 2 and waf.active_receipts == []


def test_receipt_to_dict_is_json_friendly():
    r = FakeWaf(dry_run=False).apply(_action())
    d = r.to_dict()
    assert set(d) >= {"receipt_id", "connector", "action_type", "target", "idempotency_key", "status",
                      "dry_run", "applied_at", "expires_at", "vendor_ref", "rollback_token", "approver"}
    assert isinstance(d["applied_at"], float)
