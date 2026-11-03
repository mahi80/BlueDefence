"""The numbers the analyst sees on the blast radius (code review 2026-11-03, group D: B1–B8, B10, B13, B14)."""

from __future__ import annotations

import io
import time

from aegis.agents.orchestrator.walkers.graph import BlastGraph, Edge
from aegis.agents.orchestrator.walkers.investigation import investigate
from aegis.agents.orchestrator.walkers.loop import ContainmentLoop
from aegis.agents.orchestrator.walkers.mitigation import plan_mitigation
from aegis.agents.orchestrator.walkers.sources import InventorySource
from aegis.agents.orchestrator.walkers.twin import Persona, simulate
from aegis.agents.orchestrator.walkers.walk import run_walkers, seeds_from
from aegis.agents.shared.evidence_chain import EvidenceChain


def _chain(aid="A1"):
    return EvidenceChain(alert_id=aid, investigated_by="t", verdict="malicious", confidence=0.9)


def _estate(n_dc=20):
    """u1 logs on to LT-1, which reaches n_dc domain controllers; u1 also holds a session into CORE (cbs)."""
    rows = [{"a": "u1", "relation": "logged_on", "b": "LT-1", "b_type": "host"}]
    rows += [{"a": "LT-1", "relation": "lateral_to", "b": f"DC-{i}", "b_type": "domain_controller"} for i in range(n_dc)]
    rows += [{"a": "u1", "relation": "assumed", "b": "role-cbs", "b_type": "cloud_role"},
             {"a": "role-cbs", "relation": "touched", "b": "cbs-db", "b_type": "core_banking_db"}]
    return rows


# ---- B1: counts are not the 10-item display list ----------------------------------------------------

def test_twenty_critical_assets_are_reported_as_twenty():
    src = InventorySource(_estate(20))
    g = run_walkers({"id": "A1", "user": "u1"}, src, hops=3).graph
    s = g.summary()
    assert s["critical_count"] == 21 and len(s["critical_ids"]) == 21 and len(s["critical_assets_reached"]) == 10
    assert "21 critical asset(s) reached" in g.signal()


def test_containment_of_many_assets_reads_true_before_and_after():
    src = InventorySource(_estate(20))
    alert = {"id": "A1", "user": "u1"}
    chain = _chain()
    investigate(alert, chain, src, hops=3)
    loop = ContainmentLoop(src, hops=3)
    loop.track(alert, chain)
    e = loop.after_action("A1", "isolate", "LT-1")
    assert len(e.critical_before) == 21 and e.critical_after == ["cbs-db"] and e.shrank and e.new_nodes == []


# ---- B2: an action cuts only what it cuts --------------------------------------------------------------

def test_revoke_sessions_does_not_sever_the_users_other_paths():
    src = InventorySource(_estate(2) + [{"a": "u1", "relation": "holds_session", "b": "sess-1", "b_type": "session"}])
    src.mark_contained("revoke_sessions", "u1")
    g = run_walkers({"id": "A2", "user": "u1"}, src, hops=3).graph
    assert "sess-1" not in g.nodes and "DC-0" not in g.nodes    # session / logon edges are cut
    assert g.summary()["critical_ids"] == ["cbs-db"]            # the cloud-role path is not (it used to vanish too)
    src.mark_contained("lock_account", "u1")
    assert run_walkers({"id": "A3", "user": "u1"}, src, hops=3).graph.summary()["nodes_reached"] == 1


# ---- B3: failed queries are visible --------------------------------------------------------------------

class _Down:
    name = "siem-down"

    def __getattr__(self, item):
        def fail(*a, **k):
            raise TimeoutError("SIEM 504")
        return fail


def test_failed_queries_are_not_reported_as_nothing_to_cut():
    chain = _chain()
    s = investigate({"id": "A4", "user": "u1", "host": "LT-1"}, chain, _Down())
    assert s["incomplete"] and sum(s["query_errors"].values()) > 0
    ev = next(e for e in chain.evidence if e.source == "investigation.blast_graph")
    assert "INCOMPLETE" in ev.signal and ev.weight == "medium"
    assert chain.metadata["investigation"]["incomplete"] is True
    from aegis.hitl.card import investigation_card
    assert investigation_card(chain)["blast_radius"]["incomplete"] is True


# ---- B4: no baseline, no claim -------------------------------------------------------------------------

def test_action_before_the_walk_finished_makes_no_containment_claim():
    src = InventorySource(_estate(4))
    alert = {"id": "A5", "user": "u1"}
    chain = _chain("A5")                                       # tracked at submit: no blast_graph yet
    loop = ContainmentLoop(src, hops=3)
    loop.track(alert, chain)
    e = loop.after_action("A5", "throttle", "203.0.113.5")
    c = chain.metadata["containment"][-1]
    assert c["baseline"] is False and c["new_nodes"] == [] and e.critical_before == []
    assert not any("Attacker moved" in ev.signal for ev in chain.evidence)
    assert not chain.recommended_actions                       # no "re-plan" off an empty baseline


# ---- B5: steps added after execute() are filed ---------------------------------------------------------

def test_plan_steps_added_by_the_investigation_reach_an_analyst():
    from aegis.agents.response.agent import ResponseAgent
    from aegis.agents.response.connectors import ConnectorRegistry
    from aegis.agents.response.connectors.base import LoggingConnector
    out = io.StringIO()
    conn = LoggingConnector(dry_run=False)
    agent = ResponseAgent(connectors=ConnectorRegistry([conn], fallback=conn), hitl_stream=out)
    chain = _chain("A6")
    s = investigate({"id": "A6", "user": "u1", "src_ip": "203.0.113.5"}, chain, InventorySource(_estate(3)),
                    hops=3, file_actions=lambda a, c, acts: agent.file_for_review(c, acts))
    assert s["actions_added"] >= 1 and s["actions_filed"] == s["actions_added"]
    assert out.getvalue()                                                             # the stdout cards were printed
    assert all(a.requires_hitl for a in chain.recommended_actions)                    # nothing post-hoc runs unattended
    assert not conn.active_receipts


# ---- B6 / B7: seeds -------------------------------------------------------------------------------------

def test_padded_nested_seeds_are_capped():
    alert = {"id": "A7", "user": "u1", **{f"pad{i}": {"user": f"x{i}"} for i in range(400)}}
    seeds = seeds_from(alert)
    assert len(seeds) == 20 and seeds[0] == ("u1", "account")


def test_action_targets_never_come_from_nested_client_fields():
    alert = {"id": "A8", "src_ip": "203.0.113.5", "request": {"body": {"user": "cfo"}}}
    assert ("cfo", "account") in seeds_from(alert)
    assert seeds_from(alert, top_level_only=True) == [("203.0.113.5", "ip")]
    chain = _chain("A8")
    investigate(alert, chain, InventorySource([{"a": "cfo", "relation": "assumed", "b": "role-x", "b_type": "cloud_role"},
                                               {"a": "role-x", "relation": "touched", "b": "kms-1", "b_type": "kms"}]), hops=3)
    assert not any(a.action_type == "challenge" and a.target == "cfo" for a in chain.recommended_actions)


# ---- B8: choke edges on a hub ---------------------------------------------------------------------------

def test_choke_edges_on_a_2000_edge_hub_are_fast_and_cached():
    g = BlastGraph(); g.seed("u1", "account")
    g.add([Edge("u1", "logged_on", "HUB", b_type="host")])
    g.add([Edge("HUB", "lateral_to", f"h{i}", b_type="host") for i in range(2000)])
    g.add([Edge("h7", "lateral_to", "DC-1", b_type="domain_controller")])
    t = time.perf_counter()
    first = g.choke_edges()
    g.summary(); g.signal(); g.to_dict()
    assert time.perf_counter() - t < 2.0
    assert first[0]["protects"] == ["DC-1"] and len(first) == 3


# ---- B10: the re-walk refreshes what depends on the graph ----------------------------------------------

def test_rewalk_replaces_the_plan_and_marks_the_twin_stale():
    src = InventorySource(_estate(3))
    alert = {"id": "A9", "user": "u1"}
    chain = _chain("A9")
    investigate(alert, chain, src, hops=3, twin=True, twin_personas=10)
    step = lambda: [(st["action_type"], st["target"]) for st in chain.metadata["mitigation_plan"]["steps"]]
    assert ("force_logout", "u1") in step()
    loop = ContainmentLoop(src, hops=3)
    loop.track(alert, chain)
    loop.after_action("A9", "force_logout", "u1")
    assert ("force_logout", "u1") not in step() and step()     # the executed step is gone, the rest remains
    assert chain.metadata["twin"].get("stale")


# ---- B13: a time-boxed twin divides by what it simulated -------------------------------------------------

def test_truncated_twin_rate_uses_simulated_personas():
    g = BlastGraph(); g.seed("u1", "account")
    g.add([Edge("u1", "lateral_to", "DC-1", b_type="domain_controller")])
    ps = [Persona(f"p{i}", "apt", "move", 0.0, 1.0, {"move": 1.0}) for i in range(50)]
    rep = simulate(g, ps, max_seconds=-1)                     # out of time before the first persona
    assert rep.truncated and rep.simulated == 0 and rep.crown_rate() == 0.0
    full = simulate(g, ps[:5])
    assert full.crown_rate() == 1.0


# ---- B14: plan actions fit the target type -------------------------------------------------------------

def test_role_target_is_not_given_revoke_sessions():
    g = BlastGraph(); g.seed("u1", "account")
    g.add([Edge("u1", "assumed", "role-cloud-admin", b_type="cloud_role"),
           Edge("role-cloud-admin", "touched", "kms-1", b_type="kms")])
    acts = {(s.action_type, s.target) for s in plan_mitigation(g).steps}
    assert ("revoke_sessions", "role-cloud-admin") not in acts
