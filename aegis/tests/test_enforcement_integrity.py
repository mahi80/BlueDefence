"""Regression tests for the approval / enforcement integrity fixes (code review 2026-11-02, "fix first" set).

Each test reproduces a defect the review confirmed: an action that did not run being recorded as approved,
a rejected block auto-executing when the decision channel is down, a restart turning a dissent into a
concur, a lifetime rate cap, an approved isolate never reaching the EDR, the auto-block bypassing ACP
governance, a swarm-raised verdict keeping a stale concur, a swallowed audit failure, and a failed action
being reported as containment.
"""

from __future__ import annotations

import io
import logging

import pytest

from aegis.agents.response.agent import ResponseAgent
from aegis.agents.response.autonomy import AutonomyPolicy
from aegis.agents.response.connectors import ConnectorRegistry
from aegis.agents.response.connectors.mock_vendor import MockImperva
from aegis.agents.response.connectors.waf import ImpervaWafConnector
from aegis.agents.response.hitl_timeout import EXECUTE, HOLD, HitlTimeoutPolicy
from aegis.agents.shared.evidence_chain import EvidenceChain, RecommendedAction
from aegis.hitl import DashboardHITL, FileHITL
from aegis.hitl.base import Decision, execution_outcome


def _chain(aid: str, target: str = "203.0.113.5", *, concur: bool | None = True, action: str = "block") -> EvidenceChain:
    c = EvidenceChain(alert_id=aid, investigated_by="perimeter", verdict="malicious", confidence=0.95)
    if concur is not None:
        c.metadata["vote_concur"] = concur
        c.metadata["vote_tally"] = "3/3" if concur else "1/3"
    c.recommended_actions.append(RecommendedAction(action_type=action, target=target, reasoning="r",
                                                   requires_hitl=True, confidence=0.9))
    return c.finalize()


class Dash:
    """Fake ACP dashboard: files cards, returns decisions, and can go down."""

    def __init__(self):
        self.down = False
        self.statuses: dict[str, dict] = {}

    def __call__(self, method, url, body, headers, timeout):
        if self.down:
            raise ConnectionError("dashboard down")
        if url.endswith("/create"):
            self.statuses[body["id"]] = {"status": "pending"}
            return {"approval_id": body["id"]}
        return self.statuses.get(url.rsplit("/", 2)[-2], {"error": "not found"})


def _agent(hitl, srv, *, timeout_mode="off", **kw) -> ResponseAgent:
    waf = ImpervaWafConnector(site_id="s", api_id="mock", api_key="mock", transport=srv, dry_run=False)
    return ResponseAgent(connectors=ConnectorRegistry([waf]), hitl=hitl, hitl_stream=io.StringIO(),
                         autonomy=AutonomyPolicy(mode="off"),
                         hitl_timeout=HitlTimeoutPolicy(mode=timeout_mode, wait_sec=120), **kw)


# ---- the HITL sync settles by what actually happened -------------------------------------------

def test_execution_outcome():
    assert execution_outcome(None) == (True, "")
    assert execution_outcome({"recorded": True}) == (True, "")
    assert execution_outcome({"error": "EDR 503"}) == (False, "EDR 503")


def test_protected_target_waits_for_a_second_approver_then_runs(caplog):
    """Two-person rule: the first approval keeps the card pending (it used to settle `failed` and be lost);
    the same person again changes nothing; a different approver executes it."""
    srv, dash = MockImperva(), Dash()
    hitl = DashboardHITL("https://d", "k", transport=dash, state_path="off")
    agent = _agent(hitl, srv, protected_targets=["10.0.0.0/8"])
    agent.execute(_chain("P1", "10.1.2.3"))
    aid = hitl.pending[0].approval_id
    dash.statuses[aid] = {"status": "approved", "decided_by": "ciso"}
    with caplog.at_level(logging.WARNING, logger="aegis.hitl"):
        assert agent.sync_hitl() == []
    assert "second, different approver" in caplog.text and hitl.pending[0].first_approver == "ciso"
    assert agent.sync_hitl() == [] and srv.blocked_ips() == set()          # same approver again: still waiting
    dash.statuses[aid] = {"status": "approved", "decided_by": "soc-lead"}
    (d,) = agent.sync_hitl()
    assert d.status == "approved" and d.decided_by == "ciso+soc-lead" and srv.blocked_ips() == {"10.1.2.3"}


def test_vendor_failure_on_approval_is_retried_then_failed_not_approved(caplog):
    srv, dash = MockImperva(), Dash()
    hitl = DashboardHITL("https://d", "k", transport=dash, state_path="off")
    agent = _agent(hitl, srv)
    agent.execute(_chain("V1"))
    dash.statuses[hitl.pending[0].approval_id] = {"status": "approved", "decided_by": "ciso"}

    def boom(*a, **k):
        raise RuntimeError("connector exploded")
    agent.approve = boom          # approve() raising is the other failure shape
    assert agent.sync_hitl() == [] and agent.sync_hitl() == []          # kept and retried, not lost
    with caplog.at_level(logging.ERROR, logger="aegis.hitl"):
        (d,) = agent.sync_hitl()
    assert d.status == "failed" and "connector exploded" in d.reason and "gave up after 3" in d.reason
    assert "NOT executed" in caplog.text


def test_rate_capped_approval_runs_once_the_window_clears():
    srv, dash = MockImperva(), Dash()
    hitl = DashboardHITL("https://d", "k", transport=dash, state_path="off")
    agent = _agent(hitl, srv)
    agent._high_impact_max = 0                                          # cap reached
    agent.execute(_chain("R1"))
    dash.statuses[hitl.pending[0].approval_id] = {"status": "approved", "decided_by": "ciso"}
    assert agent.sync_hitl() == [] and len(hitl.pending) == 1
    agent._high_impact_max = 10                                         # window cleared
    (d,) = agent.sync_hitl()
    assert d.status == "approved" and srv.blocked_ips()


def test_decision_channel_down_never_triggers_the_timeout_auto_execute():
    """The analyst rejected the block; the dashboard is unreachable at the next sync. It used to auto-execute."""
    srv, dash = MockImperva(), Dash()
    hitl = DashboardHITL("https://d", "k", transport=dash, state_path="off")
    agent = _agent(hitl, srv, timeout_mode="live")
    agent.execute(_chain("B1", "198.51.100.7"))
    p = hitl.pending[0]
    dash.statuses[p.approval_id] = {"status": "rejected", "decided_by": "analyst"}
    p.requested_at -= 600
    dash.down = True
    assert agent.sync_hitl() == []
    assert srv.blocked_ips() == set() and len(hitl.pending) == 1
    dash.down = False
    (d,) = agent.sync_hitl()
    assert d.status == "rejected" and srv.blocked_ips() == set()


# ---- a restart keeps the vote ------------------------------------------------------------------

def test_restored_card_keeps_the_dissent(tmp_path):
    srv = MockImperva()
    state = tmp_path / "state.jsonl"
    a1 = _agent(FileHITL(tmp_path / "hitl", state_path=state), srv, timeout_mode="live")
    a1.execute(_chain("R1", concur=False))
    a2 = _agent(FileHITL(tmp_path / "hitl", state_path=state), srv, timeout_mode="live")
    (p,) = a2._hitl.pending
    assert p.chain.metadata["vote_concur"] is False and p.chain.metadata["vote_tally"] == "1/3"
    p.requested_at -= 600
    assert a2.sync_hitl() == [] and srv.blocked_ips() == set()


def test_timeout_policy_needs_a_recorded_concur():
    pol = HitlTimeoutPolicy(mode="live", wait_sec=0)
    action = RecommendedAction(action_type="block", target="203.0.113.5", reasoning="r", requires_hitl=True, confidence=0.9)
    assert pol.evaluate(action, _chain("T1", concur=None), age_sec=10)[0] == HOLD
    assert pol.evaluate(action, _chain("T2", concur=False), age_sec=10)[0] == HOLD
    assert pol.evaluate(action, _chain("T3", concur=True), age_sec=10)[0] == EXECUTE


# ---- the blast-radius cap is a rolling window, not a lifetime counter ---------------------------

def test_high_impact_cap_is_a_rolling_window(monkeypatch):
    import aegis.agents.response.agent as mod
    clock = [1000.0]
    monkeypatch.setattr(mod.time, "monotonic", lambda: clock[0])
    agent = _agent(None, MockImperva())
    for i in range(10):
        assert agent.approve(_chain(f"C{i}", f"203.0.113.{i + 1}").recommended_actions[0], approver="ciso").status == "executed"
    assert agent.approve(_chain("C10", "203.0.113.50").recommended_actions[0], approver="ciso").status == "skipped"
    clock[0] += 61
    assert agent.approve(_chain("C11", "203.0.113.51").recommended_actions[0], approver="ciso").status == "executed"


# ---- an approved isolate reaches the EDR -------------------------------------------------------

def test_approved_isolate_goes_to_the_edr_not_the_self_heal_mock():
    calls = []

    class Heal:
        def snapshot_and_sever(self, target, **kw):
            calls.append(target)

    from aegis.agents.response.connectors.base import Connector

    class FakeEdr(Connector):
        name = "fake-edr"
        actions = frozenset({"isolate"})

        def _do_apply(self, action, key, ttl):
            calls.append(("edr", action.target))
            return "applied", "dev-1", "contained"

        def _do_rollback(self, r):
            return "lifted"

    agent = ResponseAgent(connectors=ConnectorRegistry([FakeEdr(dry_run=False)]), self_healing=Heal(),
                          hitl_stream=io.StringIO(), autonomy=AutonomyPolicy(mode="off"))
    ex = agent.approve(_chain("I1", "FIN-WS-0421", action="isolate").recommended_actions[0], approver="analyst")
    assert ex.status == "executed" and ex.receipt is not None and calls == [("edr", "FIN-WS-0421")]
    # with no EDR configured the workload pipeline still takes it
    agent2 = ResponseAgent(connectors=ConnectorRegistry([]), self_healing=Heal(), hitl_stream=io.StringIO(),
                           autonomy=AutonomyPolicy(mode="off"))
    agent2.approve(_chain("I2", "pod-x", action="isolate").recommended_actions[0], approver="analyst")
    assert calls[-1] == "pod-x"


# ---- the unattended auto-block is governed ------------------------------------------------------

def test_live_auto_block_is_stopped_by_governance(monkeypatch):
    from aegis import governance

    class exc(Exception):          # stands in for acp.ACPViolation (the SDK is optional here)
        pass
    monkeypatch.setattr(governance, "_violation_type", lambda: exc)
    _guard_response = governance._guard_response

    class PausedGuard:
        def __init__(self):
            self.seen: list[str] = []

        def pre_tool_call(self, tool, args, **kw):
            self.seen.append(tool)
            raise exc("agent paused")

        def post_tool_call(self, *a, **k):
            pass

    srv = MockImperva()
    waf = ImpervaWafConnector(site_id="s", api_id="mock", api_key="mock", transport=srv, dry_run=False)
    agent = ResponseAgent(connectors=ConnectorRegistry([waf]), hitl_stream=io.StringIO(),
                          autonomy=AutonomyPolicy(mode="live"), hitl_timeout=HitlTimeoutPolicy(mode="off"))
    guard = PausedGuard()
    _guard_response(agent, guard)
    c = EvidenceChain(alert_id="G1", investigated_by="perimeter", verdict="malicious", confidence=0.97)
    c.metadata["vote_concur"] = True
    c.recommended_actions.append(RecommendedAction(action_type="block", target="203.0.113.7", reasoning="r",
                                                   requires_hitl=False, confidence=0.95))
    summary = agent.execute(c.finalize())
    assert summary.executed == [] and srv.blocked_ips() == set()
    assert "response.block" in guard.seen
    assert agent.connectors.active_receipts == []


# ---- the containment loop only counts actions that ran ------------------------------------------

def test_failed_or_dry_run_execution_is_not_containment():
    from aegis.agents.orchestrator.walkers.investigation import investigate
    from aegis.agents.orchestrator.walkers.loop import ContainmentLoop
    from aegis.agents.orchestrator.walkers.sources import MockTenant
    from aegis.agents.response.agent import ExecutedAction
    from aegis.agents.response.connectors.base import Receipt

    alert = {"id": "L1", "user_id": "alice", "host": "ws-14"}
    chain = EvidenceChain(alert_id="L1", investigated_by="t", verdict="malicious", confidence=0.9)
    src = MockTenant(spread=1.0)
    investigate(alert, chain, src)
    loop = ContainmentLoop(src)
    loop.track(alert, chain)
    act = RecommendedAction(action_type="revoke_sessions", target="alice", reasoning="r", requires_hitl=True, confidence=0.9)
    dry = Receipt("r1", "x", "revoke_sessions", "alice", "k", "dry_run", True, 0.0, None)
    for ex in ({"error": "EDR 503"}, ExecutedAction(action=act, status="executed", receipt=dry),
               ExecutedAction(action=act, status="skipped")):
        d = Decision("a", "L1", "revoke_sessions", "alice", "approved", "ciso", "", executed=ex)
        assert loop.on_decisions([d]) == []
    assert src.contained == set()


# ---- the swarm: a raised verdict needs a fresh concur, and the re-seal is audited ---------------

@pytest.fixture
def swarm_parts():
    from aegis.agents.orchestrator import swarm as sw
    return sw


def test_swarm_raise_resets_vote_concur(swarm_parts):
    sw = swarm_parts
    chain = EvidenceChain(alert_id="S1", investigated_by="perimeter", verdict="suspicious", confidence=0.92)
    chain.metadata["vote_concur"] = True
    hit = sw.WorkerResult("intel", evidence=[sw.EvidenceItem(source=next(iter(sw._CONFIRMING_SOURCES)), signal="known bad",
                                                              weight="high")])
    class Orch:
        _voter = None
    so = sw.SwarmOrchestrator(Orch(), workers={}, voter=None)
    so._extra_voters = []                            # no re-vote available
    so._merge(chain, [hit], 0.0)
    assert chain.verdict == "malicious"
    assert chain.metadata["vote_concur"] is False and chain.metadata["verdict_raised_by_swarm"] is True
    ok, _why = AutonomyPolicy(mode="live").check(
        RecommendedAction(action_type="block", target="203.0.113.7", reasoning="r", requires_hitl=False, confidence=0.95),
        chain, protected=lambda t: False)
    assert not ok


def test_swarm_reseal_audit_failure_propagates(swarm_parts):
    from aegis.agents.shared.audit import AuditWriteError
    sw = swarm_parts

    class Orch:
        def record(self, alert, chain):
            raise AuditWriteError("disk full")

    so = sw.SwarmOrchestrator(Orch(), workers={}, voter=None)
    chain = EvidenceChain(alert_id="S2", investigated_by="perimeter", verdict="suspicious", confidence=0.8)
    with pytest.raises(AuditWriteError):
        so._reseal({"id": "S2"}, chain)
