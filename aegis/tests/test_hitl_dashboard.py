"""Phase 0.2 — HITL cards become dashboard approvals; decisions come back.

A fake transport stands in for the dashboard; no network, no SDK needed.
"""

from __future__ import annotations

import io


from aegis.agents.response.agent import ResponseAgent
from aegis.agents.shared.evidence_chain import EvidenceChain, RecommendedAction
from aegis.hitl import DashboardHITL, hitl_from_env


class FakeDashboard:
    """Records what the agent sends and lets a test decide approvals."""

    def __init__(self, *, fail=False):
        self.calls: list[tuple[str, str, dict | None, dict]] = []
        self.statuses: dict[str, dict] = {}
        self.fail = fail

    def __call__(self, method, url, json_body, headers, timeout):
        self.calls.append((method, url, json_body, headers))
        if self.fail:
            raise ConnectionError("dashboard down")
        if url.endswith("/api/approvals/create"):
            self.statuses[json_body["id"]] = {"status": "pending"}
            return {"status": "pending", "approval_id": json_body["id"]}
        approval_id = url.rsplit("/", 2)[-2]
        return {"approval_id": approval_id, **self.statuses.get(approval_id, {"error": "not found"})}

    def decide(self, approval_id, status, by="ciso@bank.in", reason=""):
        self.statuses[approval_id] = {"status": status, "decided_by": by, "reject_reason": reason}


def _chain(alert_id="web-001"):
    chain = EvidenceChain(alert_id=alert_id, investigated_by="perimeter", verdict="malicious", confidence=0.91)
    chain.specialist_invocations.append("perimeter")
    chain.recommended_actions.append(RecommendedAction(
        action_type="throttle", target="203.0.113.7", reasoning="burst", requires_hitl=False, confidence=0.9))
    chain.recommended_actions.append(RecommendedAction(
        action_type="block", target="203.0.113.7", reasoning="credential stuffing from this ASN",
        requires_hitl=False, confidence=0.93))
    chain.integrity_hash = f"sha256:{alert_id}"  # set by AuditLog.append in the real pipeline
    return chain.finalize()


def _hitl(dash, **kw):
    return DashboardHITL("https://dash.test", "k3y", agent_name="aegis-soc-orchestrator", bu="Security",
                         transport=dash, **kw)


def test_hitl_card_is_filed_as_a_dashboard_approval_not_printed():
    dash = FakeDashboard()
    out = io.StringIO()
    agent = ResponseAgent(hitl=_hitl(dash), hitl_stream=out)
    summary = agent.execute(_chain())

    assert [a.action.action_type for a in summary.executed] == ["throttle"]
    assert [a.action.action_type for a in summary.hitl_queue] == ["block"]
    assert "dashboard approval aegis_web-001_block_" in summary.hitl_queue[0].note
    assert out.getvalue() == ""  # no stdout card

    method, url, body, headers = dash.calls[0]
    assert (method, url) == ("POST", "https://dash.test/api/approvals/create")
    assert headers["X-API-Key"] == "k3y"
    assert body["agent"] == "aegis-soc-orchestrator" and body["bu"] == "Security" and body["tier"] == "TIER_2"
    assert body["action"] == "block -> 203.0.113.7"
    args = body["args"]
    assert args["source"] == "aegis" and args["alert_id"] == "web-001"
    assert args["verdict"] == "malicious" and args["chain_confidence"] == 0.91
    assert args["integrity_hash"] == "sha256:web-001" and args["specialists"] == ["perimeter"]
    assert "payload" not in args  # the approver sees the decision context, never the raw alert


def test_dashboard_down_falls_back_to_the_stdout_card():
    dash = FakeDashboard(fail=True)
    out = io.StringIO()
    agent = ResponseAgent(hitl=_hitl(dash), hitl_stream=out)
    summary = agent.execute(_chain())
    assert "[HITL APPROVAL REQUEST]" in out.getvalue()
    assert "dashboard approval" not in summary.hitl_queue[0].note


def test_sync_executes_approved_and_records_rejected():
    dash = FakeDashboard()
    hitl = _hitl(dash)
    agent = ResponseAgent(hitl=hitl, hitl_stream=io.StringIO())
    agent.execute(_chain("web-001"))
    agent.execute(_chain("web-002"))
    assert len(hitl.pending) == 2
    assert agent.sync_hitl() == []  # still pending on the dashboard

    ids = [p.approval_id for p in hitl.pending]
    dash.decide(ids[0], "approved", by="ciso@bank.in")
    dash.decide(ids[1], "rejected", by="soc-lead@bank.in", reason="known partner scanner")
    decisions = agent.sync_hitl()

    assert {d.status for d in decisions} == {"approved", "rejected"}
    approved = next(d for d in decisions if d.status == "approved")
    assert approved.executed.status == "executed" and "ciso@bank.in" in approved.executed.note
    rejected = next(d for d in decisions if d.status == "rejected")
    assert rejected.executed is None and rejected.reason == "known partner scanner"
    assert hitl.pending == [] and len(hitl.decisions) == 2
    assert agent._high_impact_counter == 1  # only the approved action consumed the blast-radius budget


def test_request_is_idempotent_per_alert_action_target():
    dash = FakeDashboard()
    hitl = _hitl(dash)
    chain = _chain()
    first = hitl.request(chain.recommended_actions[1], chain)
    second = hitl.request(chain.recommended_actions[1], chain)
    assert first == second and len(dash.calls) == 1


def test_expiry_settles_old_requests_without_executing():
    dash = FakeDashboard()
    hitl = _hitl(dash)
    agent = ResponseAgent(hitl=hitl, hitl_stream=io.StringIO())
    agent.execute(_chain())
    hitl.pending[0].requested_at -= 10_000
    decisions = agent.sync_hitl(max_age_sec=3600)
    assert decisions[0].status == "expired" and decisions[0].executed is None
    assert hitl.pending == []


def test_hitl_from_env(monkeypatch):
    monkeypatch.delenv("ACP_DASHBOARD_URL", raising=False)
    assert hitl_from_env() is None
    monkeypatch.setenv("ACP_DASHBOARD_URL", "https://dash.example/")
    monkeypatch.setenv("ACP_API_KEY", "abc")
    h = hitl_from_env()
    assert h is not None and h.dashboard_url == "https://dash.example" and h.api_key == "abc"


def test_no_transport_keeps_the_old_behaviour():
    out = io.StringIO()
    agent = ResponseAgent(hitl_stream=out)
    summary = agent.execute(_chain())
    assert "[HITL APPROVAL REQUEST]" in out.getvalue()
    assert agent.sync_hitl() == []
    assert len(summary.hitl_queue) == 1


# ── async tier updates the card in place (roadmap 2.4b / HITL card rendering) ──

def test_investigation_card_is_compact_abstract_and_capped():
    from aegis.hitl import investigation_card
    chain = _chain("web-009")
    assert investigation_card(chain) is None                                   # async tier has not run
    chain.metadata["blast_graph"] = {
        "nodes": [{"id": f"n{i}", "type": "host", "distance": i % 3, "sensitivity": 0.3} for i in range(300)]
                 + [{"id": "cbs-db", "type": "core_banking_db", "distance": 2, "sensitivity": 1.0}],
        "edges": [{"a": f"n{i}", "relation": "lateral_to", "b": f"n{i+1}", "ts": "", "confidence": 1.0, "source": "endpoint", "b_type": "host"} for i in range(299)],
        "summary": {"nodes_reached": 301, "counts": {"hosts": 300, "data": 1},
                    "critical_assets_reached": [{"id": "cbs-db", "type": "core_banking_db", "distance": 2}],
                    "choke_edges": [{"edge": "n1 -lateral_to-> n2", "protects": ["cbs-db"], "n": 1, "source": "endpoint"}],
                    "walkers": ["identity", "endpoint"], "truncated": [], "earliest_touch": None}}
    chain.metadata["mitigation_plan"] = {"steps": [{"order": 1, "action_type": "isolate", "target": "n1", "why": "w", "protects": ["cbs-db"],
                                                     "radius_reduction": 1, "disruption": 0.6, "rollback": "r", "requires_hitl": True, "edge": ""}],
                                         "protected": ["cbs-db"], "unprotected": [], "disruption": 0.6, "efficiency": 1.67, "candidates_considered": 3, "note": ""}
    chain.metadata["twin"] = {"personas": 60, "rounds": 12, "crown_rate": 0.7, "with_plan": {"crown_rate": 0.1}, "plan_effectiveness": 0.86,
                              "median_rounds_to_crown": 4, "by_archetype": {"apt_operator": {"n": 60, "crown": 42}}, "ranked_cuts": [], "persona_source": "evidence"}
    chain.metadata["containment"] = [{"step": 1, "action": "isolate", "target": "n1", "critical_before": ["cbs-db"], "critical_after": [],
                                      "nodes_before": 301, "nodes_after": 4, "shrank": True, "new_nodes": []}]
    chain.metadata["campaign_context"] = {"events_in_window": 40, "window_minutes": 30, "sources": ["waf"], "enumeration": {"distinct_endpoints": 33},
                                          "automation": {"requests_per_min": 12.0}, "waf": {"blocked": 3, "attack_classes": ["sqli"]},
                                          "access": {"cross_owner_reads": 5, "cross_owner_writes": 0}, "timeline": {"span_minutes": 29.5, "first_event_at": "t0"}}
    import json as _json
    card = investigation_card(chain)
    assert card["verdict"] == "malicious"
    assert card["blast_radius"]["critical"][0]["id"] == "cbs-db" and card["blast_radius"]["choke_edges"][0]["protects"] == ["cbs-db"]
    assert card["blast_radius"]["nodes"][0]["d"] == 0 and len(card["blast_radius"]["nodes"]) <= 60     # seeds first, capped
    assert card["plan"]["steps"][0] == {"n": 1, "action": "isolate", "target": "n1", "why": "w", "protects": ["cbs-db"], "reduction": 1,
                                        "disruption": 0.6, "rollback": "r", "hitl": True}
    assert card["twin"]["exposure"] == 0.7 and card["twin"]["with_plan"] == 0.1 and card["twin"]["plan_effectiveness"] == 0.86
    assert card["containment"][0]["shrank"] and card["containment"][0]["before"] == 1 and card["containment"][0]["after"] == 0
    assert card["campaign"]["events"] == 40 and card["campaign"]["attack_classes"] == ["sqli"]
    assert len(_json.dumps(card)) <= 24_000
    assert "alert" not in card and "payload" not in _json.dumps(card)


def test_attach_investigation_updates_every_pending_card_for_the_alert():
    from aegis.hitl import investigation_card

    class Dash(FakeDashboard):
        def __call__(self, method, url, json_body, headers, timeout):
            if url.endswith("/context"):
                self.calls.append((method, url, json_body, headers)); return {"status": "pending", "updated": True}
            return super().__call__(method, url, json_body, headers, timeout)

    dash = Dash(); hitl = _hitl(dash)
    chain = _chain("web-010")
    for a in chain.recommended_actions:
        hitl.request(a, chain)
    other = _chain("web-011"); hitl.request(other.recommended_actions[0], other)
    chain.metadata["mitigation_plan"] = {"steps": [], "protected": [], "unprotected": [], "disruption": 0, "efficiency": 0, "candidates_considered": 0, "note": ""}
    n = hitl.attach_investigation("web-010", investigation_card(chain))
    ctx = [c for c in dash.calls if c[1].endswith("/context")]
    assert n == 2 and len(ctx) == 2 and all("web-010" in c[1] for c in ctx)
    assert all(c[2]["investigation"]["plan"] is not None and c[3]["X-API-Key"] == "k3y" for c in ctx)
    assert hitl.attach_investigation("web-010", None) == 0
    assert _hitl(FakeDashboard(fail=True)).attach_investigation("web-010", {"x": 1}) == 0     # down dashboard: card keeps verdict-time content


def test_investigator_on_done_hook_feeds_the_card(monkeypatch):
    from aegis.agents.orchestrator.walkers import Investigator, MockTenant
    seen = []
    inv = Investigator(MockTenant(spread=0.5), on_done=lambda alert, chain, s: seen.append((chain.alert_id, "blast_graph" in chain.metadata)))
    chain = _chain("web-012")
    fut = inv.submit({"id": "web-012", "source": "WAF", "source_ip": "203.0.113.7", "user_id": "u1"}, chain)
    assert fut is not None; fut.result(timeout=30); inv.drain()
    assert seen == [("web-012", True)]
