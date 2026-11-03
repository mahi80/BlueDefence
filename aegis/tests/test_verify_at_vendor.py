"""Read enforcement back at the vendor (idea from AiSOC: unattended containment is verified, the gap counted).
A vendor that does not show the action turns "executed" into a human's problem, and an action released or
removed outside AEGIS is marked drifted instead of being reported as still in force."""

from __future__ import annotations

import io

from aegis.agents.response.agent import ResponseAgent
from aegis.agents.response.autonomy import AutonomyPolicy
from aegis.agents.response.connectors import ConnectorRegistry
from aegis.agents.response.connectors.base import STATUS_DRIFTED
from aegis.agents.response.connectors.edr import CrowdStrikeConnector
from aegis.agents.response.connectors.mock_vendor import (
    MockCrowdStrike,
    MockImperva,
    MockZscaler,
)
from aegis.agents.response.connectors.swg import ZscalerConnector
from aegis.agents.response.connectors.waf import ImpervaWafConnector
from aegis.agents.shared.evidence_chain import EvidenceChain, RecommendedAction


def _act(t, target, hitl=False):
    return RecommendedAction(action_type=t, target=target, reasoning="r", requires_hitl=hitl, confidence=0.95)


def _imperva(srv):
    return ImpervaWafConnector(site_id="s", api_id="mock", api_key="mock", transport=srv, dry_run=False)


def test_applied_action_is_read_back():
    srv = MockImperva()
    agent = ResponseAgent(connectors=ConnectorRegistry([_imperva(srv)]), hitl_stream=io.StringIO(),
                          autonomy=AutonomyPolicy(mode="off"))
    c = EvidenceChain(alert_id="V1", investigated_by="t", verdict="malicious", confidence=0.97)
    c.recommended_actions.append(_act("throttle", "203.0.113.7"))
    s = agent.execute(c.finalize(), {"src_ip": "203.0.113.7"})
    assert s.executed and s.executed[0].receipt.verified is True


def test_vendor_that_does_not_show_it_routes_to_a_human(monkeypatch):
    monkeypatch.setenv("AEGIS_VERIFY_RETRY_S", "0")
    class Lossy(MockImperva):                      # accepts the rule, then it is not there (a silent vendor drop)
        def handle(self, method, url, body, headers):
            res = super().handle(method, url, body, headers)
            if method == "POST":
                self.rules.clear()
            return res
    conn = _imperva(Lossy())
    agent = ResponseAgent(connectors=ConnectorRegistry([conn]), hitl_stream=io.StringIO(), autonomy=AutonomyPolicy(mode="off"))
    c = EvidenceChain(alert_id="V2", investigated_by="t", verdict="malicious", confidence=0.97)
    c.recommended_actions.append(_act("throttle", "203.0.113.7"))
    s = agent.execute(c.finalize(), {"src_ip": "203.0.113.7"})
    assert not s.executed and "NOT in place" in s.hitl_queue[0].note
    assert not conn.active_receipts and s.hitl_queue[0].receipt.status == STATUS_DRIFTED


def test_release_at_the_vendor_is_detected_as_drift_and_re_approval_contains_again(monkeypatch):
    monkeypatch.setenv("AEGIS_VERIFY_GRACE_S", "0")
    vendor = MockCrowdStrike()
    edr = CrowdStrikeConnector(base_url="https://cs", token_provider=lambda: "mock-cs-token", transport=vendor, dry_run=False)
    agent = ResponseAgent(connectors=ConnectorRegistry([edr]), hitl_stream=io.StringIO())
    act = _act("isolate", "app-ledger-07", hitl=True)
    ex = agent.approve(act, approver="ciso")
    assert ex.status == "executed" and ex.receipt.verified is True
    vendor.contained.clear()                                       # someone lifts containment in Falcon
    assert agent.check_drift() == []                               # one miss is not drift (round 3 G3-1)
    (r,) = agent.check_drift()
    assert r.status == STATUS_DRIFTED and not edr.active_receipts
    assert agent.approve(act, approver="ciso").status == "executed" and vendor.contained


def test_zscaler_and_unverifiable_connectors(monkeypatch):
    monkeypatch.setenv("AEGIS_VERIFY_GRACE_S", "0")
    zia = MockZscaler()
    z = ZscalerConnector(base_url="https://zia", category_id="C1", token_provider=lambda: "mock", transport=zia, dry_run=False)
    agent = ResponseAgent(connectors=ConnectorRegistry([z]), hitl_stream=io.StringIO())
    ex = agent.approve(_act("block_egress", "evil-c2.example", hitl=True), approver="ciso")
    assert ex.receipt.verified is True
    zia.categories["C1"].clear()
    assert agent.check_drift() == []
    assert [r.target for r in agent.check_drift()] == ["evil-c2.example"]
