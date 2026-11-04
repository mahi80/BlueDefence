"""Mitigation as a minimum cut (roadmap 2.6).

Given the blast graph, find the **smallest set of actions** that disconnects the attacker's
reachable set from the critical assets, rank candidate cuts by *assets protected ÷ business
disruption*, and emit an ordered **plan** — step, target, why, radius reduction, rollback,
``requires_hitl`` — rather than a list of everything that could be done.

    revoke one token + isolate two hosts   beats   locking nine accounts

How a cut becomes actions: every edge in the graph has a *relation*; each relation maps to the
action that severs it (``holds_session`` → revoke_sessions on the account, ``lateral_to`` →
isolate the source host, ``assumed`` → rotate the key / revoke the role, ``sent_to`` → hold the
account …) with a disruption cost (how much legitimate work the action stops). The search is
greedy over single-edge cuts (exact, from ``BlastGraph.choke_edges``) extended to small
multi-edge sets, scored by protected sensitivity ÷ total disruption. Containment actions keep
the response agent's HITL policy; auto-safe steps (throttle, challenge, monitor) are added as
the *immediate* first steps so something happens while the human reads the card.

The plan is attached to the chain as evidence + ``metadata.mitigation_plan`` and as
``RecommendedAction``s (deduplicated against what the specialists already proposed). It never
executes anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import time
from itertools import combinations

from ...shared.evidence_chain import EvidenceChain, EvidenceItem, ReasoningStep, RecommendedAction
from .graph import BlastGraph, Edge

# relation -> (action_type, which end is the target, disruption 0..1, rollback text)
SEVER = {
    "holds_session":   ("revoke_sessions", "a", 0.25, "user signs in again (step-up MFA)"),
    "logged_on_from":  ("revoke_sessions", "a", 0.25, "user signs in again from a registered device"),
    "logged_on":       ("force_logout",    "a", 0.15, "user signs in again"),
    "member_of":       ("lock_account",    "a", 0.6,  "unlock after identity verification"),
    "consented":       ("block",           "b", 0.1,  "re-consent the app after review"),
    "spawned":         ("kill_process",    "b", 0.2,  "restart the process / service"),
    "lateral_to":      ("isolate",         "a", 0.7,  "release host isolation from the EDR console"),
    "wrote":           ("isolate",         "a", 0.7,  "release host isolation"),
    "connected_to":    ("block",           "a", 0.4,  "remove the firewall/NSG block"),
    "resolved":        ("block",           "b", 0.05, "remove the DNS sinkhole"),
    "modified_rule":   ("hold",            "b", 0.3,  "re-apply the rule under a ticket"),
    "assumed":         ("rotate_credential", "b", 0.35, "issue a new key / re-grant the role"),
    "touched":         ("revoke_sessions", "a", 0.3,  "principal re-authenticates"),
    "queried":         ("revoke_sessions", "a", 0.3,  "user re-authenticates"),
    "downloaded_from": ("block_export",    "a", 0.4,  "lift the export hold"),
    "sent_to":         ("hold",            "a", 0.5,  "release the hold after the customer confirms"),
    "received_from":   ("hold",            "b", 0.5,  "release the hold"),
    "linked_to":       ("monitor",         "b", 0.0,  "—"),
}
IMMEDIATE = [("throttle", 0.05, "slow the source"), ("challenge", 0.1, "step-up the session"), ("monitor", 0.0, "watch the frontier")]
_HITL = {"block", "force_logout", "isolate", "lock_account", "revoke_sessions", "trigger_self_heal", "kill_process", "quarantine_file",
         "escalate_to_fraud_team", "hold", "block_export", "recall_message", "rotate_credential", "escalate_to_hr", "snapshot_forensic"}


@dataclass
class Step:
    order: int
    action_type: str
    target: str
    why: str
    protects: list[str]
    radius_reduction: int          # critical nodes no longer reachable after this step
    disruption: float
    rollback: str
    requires_hitl: bool
    edge: str = ""


@dataclass
class Plan:
    steps: list[Step] = field(default_factory=list)
    protected: list[str] = field(default_factory=list)
    unprotected: list[str] = field(default_factory=list)
    protected_sensitivity: float = 0.0
    disruption: float = 0.0
    candidates_considered: int = 0
    note: str = ""

    @property
    def efficiency(self) -> float:
        return round(self.protected_sensitivity / (self.disruption + 0.1), 2)

    def to_dict(self) -> dict:
        return {"steps": [s.__dict__ for s in self.steps], "protected": self.protected, "unprotected": self.unprotected,
                "protected_sensitivity": round(self.protected_sensitivity, 2), "disruption": round(self.disruption, 2),
                "efficiency": self.efficiency, "candidates_considered": self.candidates_considered, "note": self.note}

    def signal(self) -> str:
        n = len([s for s in self.steps if s.requires_hitl])
        return (f"Mitigation plan: {len(self.steps)} step(s) ({n} need approval) protect {len(self.protected)} critical asset(s) "
                f"at disruption {self.disruption:.2f} (efficiency {self.efficiency})"
                + (f"; {len(self.unprotected)} asset(s) have no cut — containment by isolation only" if self.unprotected else ""))


def _sever(e: Edge) -> tuple[str, str, float, str]:
    act, end, cost, rb = SEVER.get(e.relation, ("monitor", "b", 0.0, "—"))
    return act, (e.a if end == "a" else e.b), cost, rb


_PRINCIPALS = ("account", "account_privileged")
_HOSTS = ("host", "server", "jump_host", "file_server", "device_managed", "device_unmanaged", "domain_controller", "backup_server")
# the node types each principal / host action can actually be applied to
_APPLIES_TO = {"revoke_sessions": _PRINCIPALS, "force_logout": _PRINCIPALS,
               "lock_account": (*_PRINCIPALS, "admin_role", "cloud_role"), "isolate": _HOSTS}


def _fit(g: BlastGraph, act: str, target: str) -> str:
    """The relation picks the action, but the target's type decides whether it applies: ``touched`` from a
    cloud role used to plan ``revoke_sessions(role-cloud-admin)`` (review B14). A mismatch falls back to the
    containment that fits the type; an unknown type keeps the relation's action."""
    allowed = _APPLIES_TO.get(act)
    t = g.nodes[target].type if target in g.nodes else "unknown"
    if allowed is None or t == "unknown" or t in allowed:
        return act
    return _fallback_action(g, target)


def _candidates(g: BlastGraph, crit: set[str]) -> dict[tuple[str, str], list[Edge]]:
    """Unique (action, target) pairs on some path to a critical node, with the edges each severs.
    One action removes *every* edge it maps to — revoking a user's sessions cuts all of them."""
    out: dict[tuple[str, str], list[Edge]] = {}
    # nodes that can reach a critical asset, by one reverse walk — a forward reach per edge was O(E²)
    radj: dict[str, list[str]] = {}
    for e in g.edges:
        radj.setdefault(e.b, []).append(e.a)
    leads = set(crit); stack = list(crit)
    while stack:
        x = stack.pop()
        for y in radj.get(x, ()):
            if y not in leads:
                leads.add(y); stack.append(y)
    for e in g.edges:
        if e.b not in leads:
            continue
        act, target, _cost, _rb = _sever(e)
        if act == "monitor":
            continue
        act = _fit(g, act, target)
        out.setdefault((act, target), []).append(e)
    return out


def _fallback_action(g: BlastGraph, node_id: str) -> str:
    t = g.nodes[node_id].type if node_id in g.nodes else "unknown"
    if t in ("host", "server", "jump_host", "file_server", "device_managed", "device_unmanaged", "domain_controller", "backup_server"):
        return "isolate"
    if t.startswith("account") or t in ("admin_role", "cloud_role"):
        return "lock_account"
    return "block"


#: pairs are only tried among this many best single cuts, and the whole search is wall-clock bounded: a 391-node
#: graph used to take 35 s of CPU (all pairs × full reach × list-membership removal) on the investigation pool and
#: the containment loop (review round 7 O-6)
MAX_PAIR_POOL = 20
PLAN_MAX_SECONDS = 2.0


def plan_mitigation(g: BlastGraph, *, max_steps: int = 4, max_combo: int = 2,
                    max_seconds: float = PLAN_MAX_SECONDS) -> Plan:
    """Greedy minimum cut over *actions*: each candidate is an (action, target) pair that severs
    every edge it maps to; pick the single action or pair with the best protected-sensitivity ÷
    disruption, repeat on what is still reachable, stop at ``max_steps`` or when everything
    critical is cut. Each step carries protects / reduction / rollback / HITL."""
    crit = {n.id for n in g.critical_reached()}
    seeds = {n.id for n in g.nodes.values() if n.distance == 0}
    plan = Plan()
    if not crit:
        plan.note = "no critical asset reachable — nothing to cut; watch the frontier"
        return plan
    base = g._reach(seeds, g.edges) & crit
    cands = _candidates(g, crit)
    plan.candidates_considered = len(cands)
    cut_edges: list[Edge] = []; used: set[tuple[str, str]] = set(); remaining = set(base)
    deadline = time.monotonic() + max_seconds

    def _rest(removed: list[Edge]) -> list[Edge]:
        gone = {id(e) for e in removed}
        return [x for x in g.edges if id(x) not in gone]

    def _score(combo: tuple) -> tuple[float, set[str]]:
        protected = remaining - (g._reach(seeds, _rest(cut_edges + [e for key in combo for e in cands[key]])) & remaining)
        if not protected:
            return 0.0, protected
        sens = sum(g.nodes[c].sensitivity for c in protected)
        cost = sum(SEVER.get(cands[key][0].relation, ("", "", 0.0, ""))[2] for key in combo) + 0.05 * (len(combo) - 1)
        return sens / (cost + 0.1), protected

    timed_out = False
    while remaining and len(plan.steps) < max_steps and not timed_out:
        best = None; best_score = 0.0
        pool = [k for k in cands if k not in used]
        singles: list[tuple[float, tuple]] = []
        for key in pool:
            if time.monotonic() > deadline:
                timed_out = True; break
            sc, _ = _score((key,))
            singles.append((sc, key))
            if sc > best_score:
                best, best_score = (key,), sc
        if max_combo >= 2 and not timed_out:
            # a pair can protect what neither cut does alone, so pair candidates are ranked by what their edges
            # lead to (single score, then edge count) — but only the top MAX_PAIR_POOL are paired
            ranked = [k for _, k in sorted(singles, key=lambda t: (-t[0], -len(cands[t[1]])))][:MAX_PAIR_POOL]
            for combo in combinations(ranked, 2):
                if time.monotonic() > deadline:
                    timed_out = True; break
                sc, _ = _score(combo)
                if sc > best_score:
                    best, best_score = combo, sc
        if best is None:
            break
        # the combo protects as a unit: every key in it becomes a step (a pair's second cut is not optional)
        removed = cut_edges + [e for key in best for e in cands[key]]
        rest = _rest(removed)
        protected_now = sorted(remaining - (g._reach(seeds, rest) & remaining))
        first_order = len(plan.steps) + 1
        for key in best:
            act, target = key
            e0 = cands[key][0]; cost = SEVER[e0.relation][2]; rb = SEVER[e0.relation][3]
            used.add(key)
            joint = f" (together with step {first_order})" if len(best) > 1 and len(plan.steps) + 1 != first_order else ""
            plan.steps.append(Step(len(plan.steps) + 1, act, target,
                                   f"{act} on {target} severs {len(cands[key])} edge(s) ({e0.relation}…) — cuts the path to {', '.join(protected_now[:3])}{joint}",
                                   protected_now, len(protected_now), cost, rb, act in _HITL,
                                   "; ".join(f"{e.a} -{e.relation}-> {e.b}" for e in cands[key][:3])))
            plan.disruption += cost
        cut_edges = removed
        remaining -= set(protected_now)
    if timed_out:
        plan.note = (plan.note + "; " if plan.note else "") + f"search stopped at its {max_seconds:.0f} s budget — plan may not be minimal"
    plan.protected = sorted(base - remaining); plan.unprotected = sorted(remaining)
    plan.protected_sensitivity = sum(g.nodes[c].sensitivity for c in plan.protected)
    for n in plan.unprotected[:2]:
        # nothing cheaper cuts it: contain the node that touches it, by its type
        src = next((e.a for e in g.edges if e.b == n), None)
        if src:
            act = _fallback_action(g, src)
            plan.steps.append(Step(len(plan.steps) + 1, act, src, f"{n} is reachable from {src} with no cheaper cut", [n], 1,
                                   0.7 if act == "isolate" else 0.6, "release isolation / unlock after verification", True,
                                   "; ".join(f"{e.a} -{e.relation}-> {e.b}" for e in g.edges if e.a == src)[:300]))
            plan.disruption += 0.7 if act == "isolate" else 0.6
    return plan


def attach_plan(chain: EvidenceChain, g: BlastGraph, plan: Plan, *, source_ip: str | None = None,
                principal: str | None = None) -> None:
    """Evidence + metadata + RecommendedActions: immediate auto-safe steps first (throttle the
    source IP, challenge the principal — whichever the alert names), then the cut."""
    chain.evidence.append(EvidenceItem(source="investigation.mitigation_plan", signal=plan.signal(),
                                       weight="high" if plan.steps else "low", raw_data=plan.to_dict()))
    chain.metadata["mitigation_plan"] = plan.to_dict()
    existing = {(a.action_type, a.target) for a in chain.recommended_actions}
    ordered: list[RecommendedAction] = []
    if plan.steps:
        for act, target in (("throttle", source_ip), ("challenge", principal)):
            if target and (act, target) not in existing:
                why = dict((a, w) for a, _c, w in IMMEDIATE)[act]
                ordered.append(RecommendedAction(action_type=act, target=target, reasoning=f"immediate, auto-safe: {why} while the plan is reviewed",
                                                 requires_hitl=False, confidence=0.7))
                existing.add((act, target))
    for s in plan.steps:
        if (s.action_type, s.target) in existing:
            continue
        ordered.append(RecommendedAction(action_type=s.action_type, target=s.target,
                                         reasoning=f"plan step {s.order}: {s.why}; protects {s.radius_reduction} critical asset(s); rollback: {s.rollback}",
                                         requires_hitl=s.requires_hitl, confidence=0.8))
        existing.add((s.action_type, s.target))
    chain.recommended_actions.extend(ordered)
    chain.reasoning.append(ReasoningStep(
        step=len(chain.reasoning) + 1, action="plan_mitigation",
        observation=f"{plan.candidates_considered} cut candidates; {len(plan.steps)} step(s) chosen; disruption {plan.disruption:.2f}",
        conclusion=plan.signal() + (f". Steps: " + " → ".join(f"{s.action_type}({s.target})" for s in plan.steps) if plan.steps else ""),
    ))


__all__ = ["IMMEDIATE", "Plan", "SEVER", "Step", "attach_plan", "plan_mitigation"]
