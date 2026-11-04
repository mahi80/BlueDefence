"""Blast-radius walkers, graph scoring, choke edges and the async investigation tier (roadmap 2.4b / 2.5)."""

from __future__ import annotations

import json

from aegis.agents.orchestrator.walkers import BlastGraph, Edge, Investigator, MockTenant, investigate, run_walkers
from aegis.agents.orchestrator.walkers.walk import seeds_from
from aegis.agents.shared.evidence_chain import EvidenceChain, EvidenceItem
from aegis.eval.run import HERE


def _cases():
    return json.loads((HERE / "historical_alerts" / "cases.json").read_text())


def test_seeds_cover_vendor_vocabularies():
    s = dict(seeds_from({"id": "x", "user_id": "u1", "source_ip": "203.0.113.5", "device_fingerprint": {"ua": "x"},
                         "identity": {"actor_id": "u2"}, "account": "ACC1", "session_id": "s1"}))
    assert s == {"u1": "account", "203.0.113.5": "ip", "u2": "account", "ACC1": "bank_account", "s1": "session"}


def test_graph_distance_sensitivity_and_choke_edges():
    g = BlastGraph(); g.seed("u1", "account")
    g.add([Edge("u1", "holds_session", "s1", "2026-10-01T09:00:00+00:00", 1.0, "identity", "session"),
           Edge("s1", "lateral_to", "JMP-1", "2026-10-01T09:05:00+00:00", 1.0, "endpoint", "jump_host"),
           Edge("JMP-1", "connected_to", "cbs-db", "2026-10-01T09:07:00+00:00", 1.0, "network", "core_banking_db"),
           Edge("u1", "logged_on", "LT-1", "2026-10-01T08:00:00+00:00", 1.0, "endpoint", "host")])
    n = g.nodes
    assert n["s1"].distance == 1 and n["JMP-1"].distance == 2 and n["cbs-db"].distance == 3 and n["LT-1"].distance == 1
    assert [x.id for x in g.critical_reached()] == ["JMP-1", "cbs-db"]
    assert n["cbs-db"].score < n["JMP-1"].score                        # farther = lower impact-weighted score
    assert g.earliest_touch() == "2026-10-01T08:00:00+00:00"
    cuts = g.choke_edges()
    assert cuts[0]["edge"] in ("u1 -holds_session-> s1", "s1 -lateral_to-> JMP-1") and cuts[0]["n"] == 2
    assert "Blast radius" in g.signal() and "2 critical asset(s)" in g.signal()
    g2 = BlastGraph(); assert g2.add([Edge("a", "r", "b")]) == 1 and g2.add([Edge("a", "r", "b")]) == 0   # dedup


def test_walkers_are_deterministic_time_boxed_and_governed():
    alert = _cases()[29]["alert"]
    a = run_walkers(alert, MockTenant(spread=.6)); b = run_walkers(alert, MockTenant(spread=.6))
    assert a.graph.to_dict()["edges"] == b.graph.to_dict()["edges"] and a.graph.summary()["nodes_reached"] > 5
    assert set(a.graph.walkers_run) == {"identity", "endpoint", "network", "cloud", "data", "transaction"}
    tight = run_walkers(alert, MockTenant(spread=.9), max_seconds=0.0)
    assert tight.graph.truncated                                                        # wall clock honoured
    quiet = run_walkers({"id": "q", "user_id": "u_quiet"}, MockTenant(spread=0.0))
    assert not quiet.graph.critical_reached()

    class Guard:
        calls = []
        def pre_tool_call(self, tool, meta):
            self.calls.append(tool)
            if tool == "walker.transaction":
                raise RuntimeError("paused")
        def post_tool_call(self, tool, **kw): pass
    g = Guard(); rep = run_walkers(alert, MockTenant(), guard=g)
    assert "walker.identity" in g.calls and rep.per_walker["transaction"]["skipped"].startswith("governance")
    assert "transaction" not in rep.graph.walkers_run


def test_investigate_attaches_graph_never_changes_verdict_and_records():
    alert = _cases()[4]["alert"]
    chain = EvidenceChain(alert_id=alert["id"], verdict="suspicious", confidence=0.6, investigated_by="test")
    recorded = []
    s = investigate(alert, chain, MockTenant(spread=.7), record=lambda a, c: recorded.append(c.alert_id))
    assert chain.verdict == "suspicious" and recorded == [alert["id"]]
    assert "blast_graph" in chain.metadata and chain.metadata["investigation"]["tier"] == "async"
    assert any(ev.source == "investigation.blast_graph" for ev in chain.evidence)
    steps = [r.action for r in chain.reasoning]
    assert "investigate_blast_radius" in steps and steps[-1] == "plan_mitigation"
    assert "Verdict unchanged" in next(r for r in chain.reasoning if r.action == "investigate_blast_radius").conclusion
    assert s["nodes_reached"] == chain.metadata["blast_graph"]["summary"]["nodes_reached"]


def test_investigator_background_tier_only_for_triggering_verdicts():
    inv = Investigator(MockTenant(spread=.5), max_workers=1)
    alert = _cases()[4]["alert"]
    benign = EvidenceChain(alert_id="b1", verdict="benign", confidence=0.9, investigated_by="t")
    assert inv.submit(alert, benign) is None and inv.status("b1") == {"state": "none"}
    chain = EvidenceChain(alert_id=alert["id"], verdict="malicious", confidence=0.9, investigated_by="t")
    fut = inv.submit(alert, chain); fut2 = inv.submit(alert, chain)
    assert fut is fut2                                                                   # idempotent per alert id
    inv.drain(); st = inv.status(alert["id"])
    assert st["state"] == "done" and st["summary"]["edges"] >= 1 and chain.verdict == "malicious"


# ---------------- 2.6 mitigation = minimum cut ----------------
def test_plan_prefers_one_cheap_cut_over_many_expensive_ones():
    from aegis.agents.orchestrator.walkers import plan_mitigation
    g = BlastGraph(); g.seed("u1", "account")
    # one session fans out to three critical assets; locking the account would also work but costs more
    g.add([Edge("u1", "holds_session", "s1", source="identity", b_type="session"),
           Edge("s1", "lateral_to", "JMP-1", source="endpoint", b_type="jump_host"),
           Edge("s1", "lateral_to", "DC-1", source="endpoint", b_type="domain_controller"),
           Edge("s1", "connected_to", "cbs-db", source="network", b_type="core_banking_db"),
           Edge("u1", "member_of", "role-admin", source="identity", b_type="admin_role")])
    p = plan_mitigation(g)
    assert p.steps and p.steps[0].action_type == "revoke_sessions" and p.steps[0].target == "u1"
    assert set(p.steps[0].protects) == {"JMP-1", "DC-1", "cbs-db"} and p.steps[0].radius_reduction == 3
    assert p.steps[0].requires_hitl and p.steps[0].rollback
    assert "role-admin" not in p.protected                      # admin_role (0.8) sits below the critical line; not a target
    assert len(p.steps) == 1 and not p.unprotected and p.efficiency > 1.0   # one action, not three
    assert "Mitigation plan" in p.signal()


def test_plan_fallback_isolates_host_when_no_cut_exists_and_empty_when_nothing_critical():
    from aegis.agents.orchestrator.walkers import plan_mitigation
    g = BlastGraph(); g.seed("LT-9", "host")
    g.add([Edge("LT-9", "mounted", "cbs-db", source="network", b_type="core_banking_db")])   # no SEVER entry: no cheap cut
    p = plan_mitigation(g)
    # review T6: `A and B or C` never reached the fallback; this now exercises it and nothing else
    assert [(s.action_type, s.target) for s in p.steps] == [("isolate", "LT-9")]
    assert p.unprotected == ["cbs-db"] and p.steps[0].requires_hitl
    quiet = BlastGraph(); quiet.seed("u2", "account"); quiet.add([Edge("u2", "logged_on", "LT-1", b_type="host")])
    assert plan_mitigation(quiet).steps == [] and "nothing to cut" in plan_mitigation(quiet).note


def test_investigate_attaches_plan_and_actions_under_hitl_policy():
    alert = _cases()[4]["alert"]
    chain = EvidenceChain(alert_id=alert["id"], verdict="malicious", confidence=0.9, investigated_by="t")
    before = len(chain.recommended_actions)
    investigate(alert, chain, MockTenant(spread=.7))
    assert "mitigation_plan" in chain.metadata and chain.verdict == "malicious"
    added = chain.recommended_actions[before:]
    assert added and added[0].action_type in ("throttle", "challenge") and not added[0].requires_hitl   # immediate auto-safe first
    for a in added:
        if a.action_type in ("block", "isolate", "lock_account", "revoke_sessions", "hold", "rotate_credential", "block_export"):
            assert a.requires_hitl
    assert len({(a.action_type, a.target) for a in chain.recommended_actions}) == len(chain.recommended_actions)   # deduplicated
    assert chain.reasoning[-1].action == "plan_mitigation"


def test_q30_allowlist_includes_walkers():
    from aegis.governance import _walker_tools
    assert set(_walker_tools()) >= {"walker.identity", "walker.endpoint", "walker.network", "walker.cloud", "walker.data", "walker.transaction"}


# ---------------- 2.8b campaign context + 2.7 containment loop ----------------
def test_campaign_context_folds_prior_events_into_training_shape():
    from aegis.agents.orchestrator.walkers import EventStore, attach_campaign_context, campaign_summary
    store = EventStore(window_min=30)
    base = 1_800_000_000.0
    import datetime as _dt
    def ts(sec): return _dt.datetime.fromtimestamp(base + sec, tz=_dt.UTC).isoformat()
    probes = ["/static/js/main.chunk.js.map", "/asset-manifest.json", "/.env", "/api/v1/items?id=101", "/api/v1/items?id=102",
              "/api/v1/items?id=103", "/api/v1/items?id=104"]
    for i, u in enumerate(probes):
        store.add({"id": f"A-{i}", "source": "F5 ASM", "source_ip": "203.0.113.7", "url": u, "ts": ts(i * 10),
                   "waf_rule": "none" if i < 3 else "Illegal Resource Access", "blocked": i >= 3, "http_status": 403 if i >= 3 else 200,
                   "referer_present": False})
    last = {"id": "A-9", "source": "F5 ASM", "source_ip": "203.0.113.7", "url": "/api/transfer", "ts": ts(80), "waf_rule": "SQL Injection",
            "blocked": False, "http_status": 200, "referer_present": False}
    out = attach_campaign_context(last, store)
    cc = out["campaign_context"]
    assert last.get("campaign_context") is None                                   # original untouched
    assert cc["alert_type"] == "campaign_summary" and cc["events_in_window"] == 7
    assert cc["enumeration"]["distinct_endpoints"] == 7 and cc["enumeration"]["no_referer_ratio"] == 1.0
    assert cc["enumeration"]["sequential_id_pattern"] is True
    assert cc["recon"]["probe_count"] >= 3 and cc["waf"]["distinct_signatures"] >= 1 and cc["waf"]["blocked"] == 4
    assert "recon_to_exploit_minutes" in cc["timeline"] and cc["timeline"]["recon_to_exploit_minutes"] == 0.5
    assert cc["automation"]["inter_request_stddev_ms"] == 0                      # metronomic
    assert campaign_summary({"id": "lonely", "source_ip": "198.51.100.1"}, store) is None     # no history → nothing attached


def test_swarm_attaches_campaign_context_before_triage():
    from aegis.agents.orchestrator.swarm import SwarmOrchestrator
    from aegis.agents.orchestrator.walkers import EventStore
    seen = {}
    class Orch:
        _voter = None
        def handle(self, alert):
            seen["alert"] = alert
            return EvidenceChain(alert_id=alert["id"], verdict="benign", confidence=0.9, investigated_by="t")
    sw = SwarmOrchestrator(Orch(), event_store=EventStore(), campaign_min_events=2)
    for i in range(3):
        chain = sw.handle({"id": f"E-{i}", "source_ip": "203.0.113.9", "url": f"/x/{i}"})
    assert "campaign_context" in seen["alert"] and seen["alert"]["campaign_context"]["events_in_window"] == 2
    # the swarm no longer copies it onto the chain after the seal (round 7 O-9): the orchestrator attaches it before
    # sealing — this stub does not, so the chain carries none
    assert "campaign_context" not in chain.metadata


def test_containment_loop_confirms_shrink_and_replans_on_movement():
    from aegis.agents.orchestrator.walkers import ContainmentLoop
    alert = _cases()[4]["alert"]
    src = MockTenant(spread=.7)
    chain = EvidenceChain(alert_id=alert["id"], verdict="malicious", confidence=0.9, investigated_by="t")
    investigate(alert, chain, src)
    crit0 = [x["id"] for x in chain.metadata["blast_graph"]["summary"]["critical_assets_reached"]]
    assert crit0
    loop = ContainmentLoop(src); loop.track(alert, chain)
    user = alert["user_id"]
    e = loop.after_action(alert["id"], "revoke_sessions", user)
    assert e is not None and e.action == "revoke_sessions" and len(e.critical_after) < len(crit0) and e.shrank
    assert chain.metadata["containment"][0]["shrank"] and chain.verdict == "malicious"
    assert any(ev.source == "investigation.containment" and "Containment confirmed" in ev.signal for ev in chain.evidence)
    # attacker moves: a new critical node appears → re-plan adds steps
    class Moving(MockTenant):
        def flows_from(self, x, w):
            return super().flows_from(x, w) + [Edge(x, "connected_to", "swift-gw-9", "2026-10-01T09:30:00+00:00", 1.0, "network", "swift_gateway")]
    mv = Moving(spread=.7); loop2 = ContainmentLoop(mv); loop2.track(alert, chain)
    n_before = len(chain.recommended_actions)
    e2 = loop2.after_action(alert["id"], "throttle", "203.0.113.1")
    assert e2.new_nodes and "swift-gw-9" in e2.new_nodes
    moved = [ev for ev in chain.evidence if ev.source == "investigation.containment" and "Attacker moved" in ev.signal]
    assert moved and (len(chain.recommended_actions) > n_before or "already covered" in moved[-1].signal)
    assert chain.verdict == "malicious"
    assert loop2.after_action("nope", "block", "x") is None                              # untracked alert → no-op


def test_loop_on_decisions_only_fires_for_approved_executed():
    from types import SimpleNamespace as NS
    from aegis.agents.orchestrator.walkers import ContainmentLoop
    alert = _cases()[4]["alert"]
    chain = EvidenceChain(alert_id=alert["id"], verdict="suspicious", confidence=0.6, investigated_by="t")
    src = MockTenant(spread=.6); investigate(alert, chain, src)
    loop = ContainmentLoop(src); loop.track(alert, chain)
    out = loop.on_decisions([NS(status="rejected", alert_id=alert["id"], action_type="block", target="x", executed=None),
                             NS(status="approved", alert_id=alert["id"], action_type="revoke_sessions", target=alert["user_id"],
                                executed=NS(status="executed")),
                             NS(status="approved", alert_id=alert["id"], action_type="isolate", target="h", executed=NS(status="skipped"))])
    assert len(out) == 1 and out[0].action == "revoke_sessions"


# ---------------- 2.9 attacker-simulation twin ----------------
def test_twin_is_abstract_deterministic_and_governed():
    from aegis.agents.orchestrator.walkers import Persona, simulate
    from aegis.agents.orchestrator.walkers.twin import ARCHETYPES, MOVES, persona_from_evidence, run_twin
    assert set(MOVES) == {"move", "escalate", "collect", "exfil", "persist", "wait"}            # fixed abstract vocabulary
    g = BlastGraph(); g.seed("u1", "account")
    g.add([Edge("u1", "holds_session", "s1", source="identity", b_type="session"),
           Edge("s1", "lateral_to", "JMP-1", source="endpoint", b_type="jump_host"),
           Edge("JMP-1", "connected_to", "cbs-db", source="network", b_type="core_banking_db"),
           Edge("u1", "logged_on", "LT-1", source="endpoint", b_type="host"),
           Edge("LT-1", "resolved", "young-domain", source="network", b_type="domain")])
    ps = [Persona(f"p{i}", "apt_operator", "persist", .5, .8, ARCHETYPES["apt_operator"]["weights"]) for i in range(40)]
    a = simulate(g, ps, rounds=6, seed=3); b = simulate(g, ps, rounds=6, seed=3)
    _nt = lambda d: {k: v for k, v in d.items() if k != "elapsed_ms"}                            # noqa: E731 — wall clock is not part of the outcome
    assert _nt(a.to_dict()) == _nt(b.to_dict()) and a.crown_rate() > 0.3                        # deterministic, reaches the crown
    held = simulate(g, ps, rounds=6, seed=3, pending_cuts={"s1 -lateral_to-> JMP-1"})
    assert held.crown_rate() < a.crown_rate()                                                # a pending cut holds futures
    contained = simulate(g, ps, rounds=6, seed=3, contained={"s1"})
    assert contained.crown_rate() == 0.0                                                     # a contained node ends the future
    assert a.ranked_cuts()[0]["edge"] in ("u1 -holds_session-> s1", "s1 -lateral_to-> JMP-1", "JMP-1 -connected_to-> cbs-db")
    # persona mix follows the evidence
    import random
    chain = EvidenceChain(alert_id="x", verdict="malicious", confidence=.9, investigated_by="t")
    chain.evidence.append(EvidenceItem(source="t", signal="canary file modified, 4200 renames/min at high entropy", weight="high"))
    mix = {}
    for p in persona_from_evidence(chain, {}, 200, random.Random(1)):
        mix[p.archetype] = mix.get(p.archetype, 0) + 1
    assert max(mix, key=mix.get) == "ransomware_crew"
    # governed: a blocked guard skips the twin, verdict untouched
    class Guard:
        def pre_tool_call(self, tool, meta): raise RuntimeError("paused")
        def post_tool_call(self, tool, **kw): pass
    rep = run_twin({"id": "x"}, chain, g, guard=Guard())
    assert rep.personas == 0 and chain.metadata["twin"]["skipped"].startswith("governance") and chain.verdict == "malicious"


def test_investigate_with_twin_reports_plan_effectiveness_and_reranks():
    alert = _cases()[4]["alert"]
    chain = EvidenceChain(alert_id=alert["id"], verdict="malicious", confidence=.9, investigated_by="t")
    s = investigate(alert, chain, MockTenant(spread=.7), twin=True, twin_personas=60)
    t = chain.metadata["twin"]
    assert t["personas"] == 60 and 0 <= t["crown_rate"] <= 1 and t["persona_source"] == "evidence"
    assert "with_plan" in t and t["plan_effectiveness"] is not None and 0 <= t["plan_effectiveness"] <= 1
    assert t["plan_reranked"] and t["plan_reranked"][0]["order"] == 1
    assert any(ev.source == "investigation.twin" for ev in chain.evidence) and chain.reasoning[-1].action == "simulate_twin"
    assert chain.verdict == "malicious" and s["twin"]["crown_rate"] == t["crown_rate"]
    assert not any(k in json.dumps(t).lower() for k in ("curl ", "powershell", "cmd.exe", "select "))   # a game over the graph, nothing operational


def test_q30_allowlist_includes_twin():
    from aegis.governance import _walker_tools
    assert "twin.simulate" in _walker_tools()
