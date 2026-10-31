"""Investigation-tier quality gate (roadmap 2.7 "evals for radius completeness and plan minimality").

The fine-tuned model has a gate; the swarm's walkers / planner / loop / twin had unit tests.
This gives them a gate too: scripted worlds with **known ground truth** — which critical
assets are really reachable, the optimal cut, how the world changes after a step — and
hard pass/fail metrics:

    radius completeness   every truly reachable critical asset is in the graph
    radius precision      no critical asset that is NOT reachable appears
    plan coverage         the plan protects every reachable critical asset (or declares it)
    plan minimality       #steps ≤ optimal + 1
    plan policy           every containment step is requires_hitl
    loop shrink           after executing step 1 the reachable critical set shrinks
    twin effectiveness    the pending plan stops ≥ 50 % of simulated futures

    python -m aegis.eval.investigation_quality        # exit 1 on any failure (CI)
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field

from aegis.agents.orchestrator.walkers import ContainmentLoop, Edge, investigate
from aegis.agents.shared.evidence_chain import EvidenceChain


class ScriptedSource:
    """A TelemetrySource built from an explicit edge list: ``(a, relation, b, b_type)``."""
    name = "scripted"

    def __init__(self, edges: list[tuple[str, str, str, str]]):
        self._edges = [Edge(a, rel, b, "2026-10-01T09:00:00+00:00", 1.0, "scripted", t) for a, rel, b, t in edges]
        self.contained: set[str] = set()

    def mark_contained(self, action_type: str, target: str) -> None:
        self.contained.add(target)

    def _from(self, a: str, rels: tuple[str, ...]) -> list[Edge]:
        if a in self.contained:
            return []
        return [e for e in self._edges if e.a == a and e.relation in rels]

    # identity
    def sessions_for_user(self, u, w): return self._from(u, ("holds_session",))
    def devices_for_user(self, u, w): return self._from(u, ("logged_on_from",))
    def groups_and_roles(self, u): return self._from(u, ("member_of",))
    def consented_apps(self, u, w): return self._from(u, ("consented",))
    # endpoint
    def process_children(self, h, w): return self._from(h, ("spawned",))
    def lateral_from(self, h, w): return self._from(h, ("lateral_to",))
    def hosts_for_user(self, u, w): return self._from(u, ("logged_on",))
    def files_written(self, h, w): return self._from(h, ("wrote",))
    # network
    def flows_from(self, x, w): return self._from(x, ("connected_to",))
    def dns_from(self, x, w): return self._from(x, ("resolved",))
    def rules_touched_by(self, p, w): return self._from(p, ("modified_rule",))
    # cloud
    def keys_and_roles(self, p, w): return self._from(p, ("assumed",))
    def resources_touched(self, p, w): return self._from(p, ("touched",))
    # data
    def tables_queried(self, u, w): return self._from(u, ("queried",))
    def downloads(self, u, w): return self._from(u, ("downloaded_from",))
    # transaction
    def beneficiaries(self, a, w): return self._from(a, ("sent_to",))
    def fan_in(self, a, w): return self._from(a, ("received_from",))
    def linked_accounts(self, a): return self._from(a, ("linked_to",))


@dataclass
class Scenario:
    name: str
    alert: dict
    edges: list[tuple[str, str, str, str]]
    truly_reachable_critical: set[str]
    optimal_steps: int
    first_step_shrinks: bool = True
    notes: str = ""


SCENARIOS: list[Scenario] = [
    Scenario(
        "session-fanout", {"id": "IQ-1", "source": "Okta", "user_id": "u1", "source_ip": "203.0.113.1"},
        [("u1", "holds_session", "s1", "session"), ("s1", "lateral_to", "JMP-1", "jump_host"),
         ("s1", "lateral_to", "DC-1", "domain_controller"), ("JMP-1", "connected_to", "cbs-db", "core_banking_db"),
         ("u1", "logged_on", "LT-1", "host"), ("LT-1", "resolved", "cdn.example", "domain")],
        {"JMP-1", "DC-1", "cbs-db"}, optimal_steps=1, notes="one revoke_sessions cuts all three"),
    Scenario(
        "two-independent-paths", {"id": "IQ-2", "source": "CrowdStrike", "host": "LT-2", "user_id": "u2"},
        [("LT-2", "lateral_to", "FS-1", "file_server"), ("FS-1", "connected_to", "cbs-db", "core_banking_db"),
         ("u2", "assumed", "role-deploy", "cloud_role"), ("role-deploy", "touched", "bucket-kyc", "storage_bucket_pii")],
        {"cbs-db", "bucket-kyc"}, optimal_steps=2, notes="host path and cloud path need separate cuts"),
    Scenario(
        "direct-adjacency-fallback", {"id": "IQ-3", "source": "Sentinel", "host": "JMP-9"},
        [("JMP-9", "connected_to", "cbs-db", "core_banking_db"), ("JMP-9", "connected_to", "swift-gw", "swift_gateway")],
        {"cbs-db", "swift-gw"}, optimal_steps=1, notes="block/isolate the seed host covers both"),
    Scenario(
        "nothing-critical", {"id": "IQ-4", "source": "Okta", "user_id": "u4"},
        [("u4", "logged_on", "LT-4", "host"), ("LT-4", "resolved", "update.example", "domain")],
        set(), optimal_steps=0, first_step_shrinks=False, notes="benign-shaped: empty plan"),
    Scenario(
        "transaction-mule", {"id": "IQ-5", "source": "CBS", "account": "ACC-1"},
        [("ACC-1", "sent_to", "mule-77", "mule_account"), ("ACC-1", "linked_to", "ACC-2", "bank_account"),
         ("ACC-2", "sent_to", "mule-77", "mule_account")],
        {"mule-77"}, optimal_steps=1, notes="hold on ACC-1 severs its sent_to; ACC-2 path needs a second — planner may take 2"),
    Scenario(
        "three-hop-beyond-walk", {"id": "IQ-6", "source": "Okta", "user_id": "u6"},
        [("u6", "holds_session", "s6", "session"), ("s6", "lateral_to", "SRV-6", "server"),
         ("SRV-6", "lateral_to", "SRV-7", "server"), ("SRV-7", "connected_to", "cbs-db", "core_banking_db")],
        {"cbs-db"}, optimal_steps=1, notes="4 hops: the 2-hop walk must still reach it via chained frontiers"),
]


@dataclass
class Result:
    name: str
    ok: bool
    checks: dict[str, bool] = field(default_factory=dict)
    detail: str = ""


def run_scenario(sc: Scenario, *, with_twin: bool = True) -> Result:
    src = ScriptedSource(sc.edges)
    chain = EvidenceChain(alert_id=sc.alert["id"], verdict="malicious", confidence=0.9, investigated_by="iq")
    s = investigate(sc.alert, chain, src, hops=4, twin=with_twin, twin_personas=80, twin_rounds=10)
    reached = {x["id"] for x in s["critical_assets_reached"]}
    plan = s["mitigation"]
    steps = plan["steps"]
    checks = {
        "radius_completeness": sc.truly_reachable_critical <= reached,
        "radius_precision": reached <= sc.truly_reachable_critical,
        "plan_coverage": set(plan["protected"]) | set(plan["unprotected"]) >= sc.truly_reachable_critical and not plan["unprotected"],
        "plan_minimality": len(steps) <= sc.optimal_steps + 1,
        "plan_policy": all(st["requires_hitl"] for st in steps if st["action_type"] in
                           ("block", "isolate", "lock_account", "revoke_sessions", "hold", "rotate_credential", "block_export", "kill_process")),
    }
    if sc.truly_reachable_critical and steps:
        loop = ContainmentLoop(src); loop.track(sc.alert, chain)
        e = loop.after_action(sc.alert["id"], steps[0]["action_type"], steps[0]["target"])
        checks["loop_shrink"] = (e is not None and e.shrank) == sc.first_step_shrinks
        if with_twin:
            t = chain.metadata.get("twin", {})
            eff = t.get("plan_effectiveness")
            checks["twin_effectiveness"] = (eff is None and t.get("crown_rate", 0) == 0) or (eff is not None and eff >= 0.5)
    else:
        checks["empty_plan_when_nothing_critical"] = (not steps) == (not sc.truly_reachable_critical)
    ok = all(checks.values())
    detail = (f"reached={sorted(reached)} steps={[(st['action_type'], st['target']) for st in steps]} "
              f"twin_eff={chain.metadata.get('twin', {}).get('plan_effectiveness')}")
    return Result(sc.name, ok, checks, detail)


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Investigation-tier quality gate (walkers, planner, loop, twin).")
    ap.add_argument("--no-twin", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)
    print("\n=== Investigation quality (radius / plan / loop / twin) ===")
    failed = 0
    for sc in SCENARIOS:
        r = run_scenario(sc, with_twin=not args.no_twin)
        bad = [k for k, v in r.checks.items() if not v]
        print(f"  {'PASS' if r.ok else 'FAIL'}  {r.name:28s} " + ("" if r.ok else f"failed: {', '.join(bad)}  ") + (r.detail if args.verbose or not r.ok else ""))
        failed += 0 if r.ok else 1
    print(f"  {len(SCENARIOS) - failed}/{len(SCENARIOS)} scenarios pass")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
