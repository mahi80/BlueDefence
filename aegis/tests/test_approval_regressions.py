"""Regressions in the approval fixes, found by the 2026-11-03 review (R2, R3, R4, R8, W11).

R2  two-person rule could never complete through the queue (the first approval settled the card `failed`)
R3  an approval that could not run yet was dropped, and the console still showed it `approved`
R4  re-approving after a release at the vendor was a no-op renewal (host stayed uncontained)
R8  ServiceNow / dashboard read errors looked like "no decision yet" and fed the timeout auto-execute
W11 a shadow receipt still active after the flip to live was "renewed" with no vendor call
"""

from __future__ import annotations

import io
import json

import pytest

from aegis.agents.response.agent import ResponseAgent
from aegis.agents.response.autonomy import AutonomyPolicy
from aegis.agents.response.connectors import ConnectorRegistry
from aegis.agents.response.connectors.edr import CrowdStrikeConnector
from aegis.agents.response.connectors.mock_vendor import MockCrowdStrike, MockImperva
from aegis.agents.response.connectors.waf import ImpervaWafConnector
from aegis.agents.response.hitl_timeout import HitlTimeoutPolicy
from aegis.agents.shared.evidence_chain import EvidenceChain, RecommendedAction
from aegis.hitl import FileHITL
from aegis.hitl.servicenow import ServiceNowHITL
from aegis.ingest.console_api import ConsoleAPI


def _chain(aid, action="isolate", target="db-core"):
    c = EvidenceChain(alert_id=aid, investigated_by="edr", verdict="malicious", confidence=0.95)
    c.metadata["vote_concur"] = True
    c.recommended_actions.append(RecommendedAction(action_type=action, target=target, reasoning="r",
                                                   requires_hitl=True, confidence=0.9))
    return c.finalize()


def _edr(vendor, *, dry_run=False):
    return CrowdStrikeConnector(base_url="https://cs.mock", token_provider=lambda: "mock-cs-token",
                                transport=vendor, dry_run=dry_run)


def _agent(hitl, conn, **kw):
    return ResponseAgent(connectors=ConnectorRegistry([conn]), hitl=hitl, hitl_stream=io.StringIO(),
                         autonomy=AutonomyPolicy(mode="off"), hitl_timeout=HitlTimeoutPolicy(mode="off"), **kw)


def test_two_person_rule_completes_through_the_console(tmp_path):
    vendor = MockCrowdStrike()
    hitl = FileHITL(tmp_path)
    agent = _agent(hitl, _edr(vendor), protected_targets=["db-*"])
    agent.execute(_chain("A1"))
    api = ConsoleAPI(None, tmp_path)
    (card,) = api.approvals()["approvals"]
    assert api.decide(card["id"], "approved", decided_by="analyst:priya")[0] == 200
    assert agent.sync_hitl() == [] and vendor.contained == set()
    card = api.approvals()["approvals"][0]
    assert card["status"] == "awaiting_second" and card["decided_by"] == "analyst:priya"
    assert api.decide(card["id"], "approved", decided_by="analyst:priya")[0] == 409        # not the same person
    assert api.decide(card["id"], "approved", decided_by="ciso:asha")[0] == 200
    (d,) = agent.sync_hitl()
    assert d.status == "approved" and d.decided_by == "analyst:priya+ciso:asha" and vendor.contained == {"b" * 32}
    assert api.approvals()["approvals"][0]["status"] == "approved"


def test_first_approval_survives_a_restart(tmp_path):
    vendor = MockCrowdStrike()
    hitl = FileHITL(tmp_path)
    agent = _agent(hitl, _edr(vendor), protected_targets=["db-*"])
    agent.execute(_chain("A2"))
    api = ConsoleAPI(None, tmp_path)
    aid = api.approvals()["approvals"][0]["id"]
    api.decide(aid, "approved", decided_by="analyst:priya")
    agent.sync_hitl()
    hitl2 = FileHITL(tmp_path)                                      # service restarts
    agent2 = _agent(hitl2, _edr(vendor), protected_targets=["db-*"])
    assert agent2.sync_hitl() == [] and hitl2.pending[0].first_approver == "analyst:priya"
    api.decide(aid, "approved", decided_by="ciso:asha")
    (d,) = agent2.sync_hitl()
    assert d.status == "approved" and vendor.contained


def test_console_shows_failed_when_an_approval_could_not_run(tmp_path):
    srv = MockImperva()
    waf = ImpervaWafConnector(site_id="s", api_id="mock", api_key="mock", transport=srv, dry_run=False)
    hitl = FileHITL(tmp_path)
    agent = _agent(hitl, waf)
    agent.execute(_chain("A3", action="block", target="203.0.113.9"))
    api = ConsoleAPI(None, tmp_path)
    aid = api.approvals()["approvals"][0]["id"]
    api.decide(aid, "approved", decided_by="analyst:priya")

    def boom(*a, **k):
        raise RuntimeError("WAF 503")
    agent.approve = boom
    for _ in range(3):
        agent.sync_hitl()
    card = api.approvals()["approvals"][0]
    assert card["status"] == "failed" and "WAF 503" in (card["rationale"] or "")
    assert api.decide(aid, "approved", decided_by="ciso:asha")[0] == 409


def test_re_approval_after_release_at_the_vendor_contains_again(tmp_path):
    vendor = MockCrowdStrike()
    agent = _agent(None, _edr(vendor))
    act = RecommendedAction(action_type="isolate", target="app-ledger-07", reasoning="r", requires_hitl=True, confidence=0.9)
    assert agent.approve(act, approver="analyst:priya").status == "executed"
    vendor.contained.clear()                                        # released in the Falcon console
    ex = agent.approve(act, approver="ciso:asha")
    assert ex.status == "executed" and vendor.contained == {"a" * 32}
    assert ex.receipt.status == "applied"


def test_shadow_receipt_is_enforced_after_the_flip_to_live():
    srv = MockImperva()
    waf = ImpervaWafConnector(site_id="s", api_id="mock", api_key="mock", transport=srv, dry_run=True)
    act = RecommendedAction(action_type="challenge", target="203.0.113.77", reasoning="r", requires_hitl=False, confidence=0.9)
    assert waf.apply(act).dry_run
    waf.dry_run = False
    r = waf.apply(act, approver="analyst:priya")
    assert r.status == "applied" and not r.dry_run and srv.rules


@pytest.mark.parametrize("status", [401, 500])
def test_servicenow_read_error_never_reaches_the_timeout(status):
    def transport(method, url, body, headers, timeout):
        if method == "POST":
            return 201, {"result": {"sys_id": "abc"}}
        return status, {"error": {"message": "nope"}}
    hitl = ServiceNowHITL("https://snow", user="u", password="p", transport=transport, state_path="off")
    srv = MockImperva()
    waf = ImpervaWafConnector(site_id="s", api_id="mock", api_key="mock", transport=srv, dry_run=False)
    agent = ResponseAgent(connectors=ConnectorRegistry([waf]), hitl=hitl, hitl_stream=io.StringIO(),
                          autonomy=AutonomyPolicy(mode="off"),
                          hitl_timeout=HitlTimeoutPolicy(mode="live", wait_sec=0))
    agent.execute(_chain("S1", action="throttle", target="203.0.113.5"))
    assert agent.sync_hitl() == [] and not srv.rules and len(hitl.pending) == 1


def test_dashboard_error_body_is_not_pending():
    from aegis.hitl import DashboardHITL
    hitl = DashboardHITL("https://d", "k", transport=lambda *a: {"error": "db down"}, state_path="off")

    class _P:
        approval_id, external_id = "x", ""
    with pytest.raises(RuntimeError):
        hitl._poll(_P())
    assert json.dumps({"ok": True})
