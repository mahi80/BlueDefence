"""The containment loop (roadmap 2.7).

After an approved action executes, re-walk the graph for that alert and compare: did the set
of reachable critical assets shrink? If yes, record it. If new critical nodes appear (the
attacker moved), re-plan and add the new steps as fresh ``RecommendedAction``s (HITL policy
unchanged) with an evidence item saying so. Verdict is never touched; the loop only ever adds.

Sources that can reflect containment implement ``mark_contained(action_type, target)`` so a
re-walk sees the severed edges — the ``MockTenant`` does; real adapters see the vendor's own
state (an isolated host stops producing lateral edges).
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ...shared.bounded import BoundedDict
from ...shared.evidence_chain import EvidenceChain, EvidenceItem, ReasoningStep, RecommendedAction
from .mitigation import plan_mitigation
from .sources import TelemetrySource
from .walk import DEFAULT_WALKERS, run_walkers

logger = logging.getLogger("aegis.containment")

# One lock per alert, shared by the investigation tier and the containment loop: both rewrite the same chain's
# metadata from different threads, and a pre-containment graph could be written last (review B11).
_CHAIN_LOCKS: BoundedDict = BoundedDict(5000)
_CHAIN_LOCKS_GUARD = threading.Lock()


def chain_lock(alert_id: str) -> threading.Lock:
    with _CHAIN_LOCKS_GUARD:
        lk = _CHAIN_LOCKS.get(str(alert_id))
        if lk is None:
            lk = _CHAIN_LOCKS[str(alert_id)] = threading.Lock()
        return lk


@dataclass
class LoopEntry:
    step: int
    action: str
    target: str
    critical_before: list[str]
    critical_after: list[str]
    nodes_before: int
    nodes_after: int

    @property
    def shrank(self) -> bool:
        return len(self.critical_after) < len(self.critical_before)

    @property
    def new_nodes(self) -> list[str]:
        return sorted(set(self.critical_after) - set(self.critical_before))

    def to_dict(self) -> dict:
        return {**self.__dict__, "shrank": self.shrank, "new_nodes": self.new_nodes}


@dataclass
class ContainmentLoop:
    source: TelemetrySource
    guard: Any = None
    hops: int = 2
    max_seconds: float = 10.0
    record: Optional[Callable[[dict, EvidenceChain], Any]] = None
    # files re-plan steps with the approval channel (they are added after the first HITL pass — review B5)
    file_actions: Callable[[dict, EvidenceChain, list], Any] | None = None
    # alerts whose containment is followed: the most recent 5,000 (each holds the alert + chain)
    _tracked: dict[str, tuple[dict, EvidenceChain]] = field(default_factory=lambda: BoundedDict(5000))
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _pool: Any = None

    def track(self, alert: dict, chain: EvidenceChain) -> None:
        with self._lock:
            self._tracked[str(chain.alert_id)] = (alert, chain)

    def tracked_chains(self, alert_ids) -> list[tuple[str, EvidenceChain]]:
        """(alert_id, chain) for the tracked alerts among ``alert_ids`` — the chains whose
        ``metadata.containment`` the HITL card should now show."""
        with self._lock:
            out = []; seen = set()
            for aid in alert_ids:
                aid = str(aid)
                if aid in self._tracked and aid not in seen:
                    seen.add(aid); out.append((aid, self._tracked[aid][1]))
            return out

    def after_action(self, alert_id: str, action_type: str, target: str) -> Optional[LoopEntry]:
        """Called once an approved action has executed. Re-walk, compare, re-plan if needed."""
        with self._lock:
            pair = self._tracked.get(str(alert_id))
        if pair is None:
            return None
        with chain_lock(alert_id):
            return self._after_action(pair, alert_id, action_type, target)

    def submit_decisions(self, decisions: list, on_done: Callable[[list], Any] | None = None) -> int:
        """``on_decisions`` on a background worker: a re-walk plus planner per approval used to run on the ingest
        thread, so a few approvals stalled ingest for a minute (review B12). One worker keeps checks in order.
        Returns how many decisions were handed over."""
        todo = [d for d in decisions if getattr(d, "status", "") == "approved"]
        if not todo:
            return 0
        if self._pool is None:
            from concurrent.futures import ThreadPoolExecutor
            self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="aegis-containment")

        def run() -> None:
            try:
                entries = self.on_decisions(todo)
                if on_done is not None and entries:
                    on_done(entries)
            except Exception as e:  # noqa: BLE001
                logger.warning("[containment] background check failed: %s", str(e)[:200])
        self._pool.submit(run)
        return len(todo)

    def drain(self, timeout: float = 30.0) -> None:
        """Wait for queued containment checks (tests, graceful shutdown)."""
        if self._pool is not None:
            self._pool.submit(lambda: None).result(timeout=timeout)

    def _after_action(self, pair: tuple, alert_id: str, action_type: str, target: str) -> LoopEntry | None:
        alert, chain = pair
        before_graph = (chain.metadata.get("blast_graph") or {}).get("summary")
        mark = getattr(self.source, "mark_contained", None)
        if callable(mark):
            mark(action_type, target)
        rep = run_walkers(alert, self.source, walkers=DEFAULT_WALKERS, hops=self.hops, max_seconds=self.max_seconds, guard=self.guard)
        g = rep.graph; s = g.summary()
        crit_after = list(s["critical_ids"])
        verdict_before = chain.verdict
        if not before_graph:
            # the action ran before the investigation finished: there is no pre-action graph to compare with, and
            # comparing with nothing read as "attacker moved: N new critical" (review B4). Record the post-action
            # walk as the graph and say plainly that containment could not be measured.
            entry = LoopEntry(len(chain.metadata.get("containment", [])) + 1, action_type, target, [], crit_after, 0,
                              s["nodes_reached"])
            d = entry.to_dict(); d.update(baseline=False, new_nodes=[], shrank=False)
            chain.metadata.setdefault("containment", []).append(d)
            self._refresh(chain, g, s)
            chain.evidence.append(EvidenceItem(
                source="investigation.containment", weight="low", raw_data=d,
                signal=f"{action_type}({target}) executed before the blast-radius walk finished — no baseline, so its effect "
                       f"cannot be measured; {s['critical_count']} critical asset(s) reachable now"))
            chain.reasoning.append(ReasoningStep(step=len(chain.reasoning) + 1, action="containment_check",
                                                 observation=f"after {action_type}({target}): {s['nodes_reached']} nodes, {s['edges']} edges",
                                                 conclusion="no pre-action baseline; effect not measured. Verdict unchanged."))
            self._record(alert, chain, alert_id)
            return entry
        # the full id list, not the 10-item display list (review B1); older chains only have the display list
        crit_before = list(before_graph.get("critical_ids") or [x["id"] for x in before_graph.get("critical_assets_reached", [])])
        nodes_before = int(before_graph.get("nodes_reached", 0))
        entry = LoopEntry(len(chain.metadata.get("containment", [])) + 1, action_type, target, crit_before, crit_after,
                          nodes_before, s["nodes_reached"])
        chain.metadata.setdefault("containment", []).append(entry.to_dict())
        self._refresh(chain, g, s)
        new_actions: list[RecommendedAction] = []
        if entry.new_nodes:
            plan = plan_mitigation(g)
            existing = {(a.action_type, a.target) for a in chain.recommended_actions}
            added = 0
            for st in plan.steps:
                if (st.action_type, st.target) in existing:
                    continue
                ra = RecommendedAction(
                    action_type=st.action_type, target=st.target, requires_hitl=st.requires_hitl, confidence=0.8,
                    reasoning=f"re-plan after {action_type}({target}): attacker reached {', '.join(entry.new_nodes[:3])}; {st.why}; rollback: {st.rollback}")
                chain.recommended_actions.append(ra); new_actions.append(ra)
                existing.add((st.action_type, st.target)); added += 1
            chain.evidence.append(EvidenceItem(
                source="investigation.containment", weight="high",
                signal=f"Attacker moved after {action_type}({target}): {len(entry.new_nodes)} new critical asset(s) reachable "
                       f"({', '.join(entry.new_nodes[:3])}); " + (f"{added} new plan step(s) queued" if added else "already covered by pending plan steps — approve them"),
                raw_data=entry.to_dict()))
            conclusion = f"radius did not shrink — {len(entry.new_nodes)} new critical node(s); re-planned ({added} step(s))."
        else:
            chain.evidence.append(EvidenceItem(
                source="investigation.containment", weight="medium" if entry.shrank else "low",
                signal=(f"Containment confirmed: {action_type}({target}) cut reachable critical assets {len(crit_before)} → {len(crit_after)}"
                        if entry.shrank else f"{action_type}({target}) executed; reachable critical assets unchanged at {len(crit_after)}"),
                raw_data=entry.to_dict()))
            conclusion = (f"radius shrank {len(crit_before)} → {len(crit_after)} critical." if entry.shrank
                          else f"no change ({len(crit_after)} critical still reachable) — next plan step is still needed.")
        chain.reasoning.append(ReasoningStep(step=len(chain.reasoning) + 1, action="containment_check",
                                             observation=f"after {action_type}({target}): {s['nodes_reached']} nodes, {s['edges']} edges",
                                             conclusion=conclusion + " Verdict unchanged."))
        assert chain.verdict == verdict_before
        self._record(alert, chain, alert_id)
        if new_actions and self.file_actions is not None:
            try:
                self.file_actions(alert, chain, new_actions)
            except Exception as e:  # noqa: BLE001
                logger.error("[containment] filing %d re-plan step(s) for %s failed: %s", len(new_actions), alert_id, str(e)[:160])
        return entry

    def _record(self, alert: dict, chain: EvidenceChain, alert_id: str) -> None:
        if self.record is not None:
            try:
                self.record(alert, chain)
            except Exception as e:  # noqa: BLE001
                logger.warning("[containment] re-record of %s failed: %s", alert_id, str(e)[:120])

    @staticmethod
    def _refresh(chain: EvidenceChain, g: Any, s: dict) -> None:
        """The re-walk replaces the graph, so everything derived from the old graph goes with it (review B10):
        the plan is recomputed (executed steps drop out), the choke edges follow, and the twin — simulated on the
        old graph — is marked stale."""
        chain.metadata["blast_graph"] = g.to_dict()
        chain.metadata["mitigation_plan"] = plan_mitigation(g).to_dict()
        inv = chain.metadata.get("investigation")
        if isinstance(inv, dict):
            inv.update(critical_reached=s["critical_count"], choke_edges=s["choke_edges"], incomplete=s["incomplete"],
                       query_errors=s["query_errors"])
        twin = chain.metadata.get("twin")
        if isinstance(twin, dict) and not twin.get("skipped"):
            twin["stale"] = "simulated before the latest containment step; re-run to refresh"

    def on_decisions(self, decisions: list) -> list[LoopEntry]:
        """Feed the HITL sync result: every approved + executed decision triggers a check."""
        out = []
        for d in decisions:
            if getattr(d, "status", "") != "approved":
                continue
            ex = getattr(d, "executed", None)
            # only an action that actually ran changes the world: a connector failure ({"error": ...}),
            # a skipped / still-queued action, or a shadow-mode dry run must not be reported as containment
            if isinstance(ex, dict) and ex.get("error"):
                continue
            if ex is not None and not isinstance(ex, dict) and getattr(ex, "status", "") not in ("executed", "approved", ""):
                continue
            receipt = getattr(ex, "receipt", None)
            if receipt is not None and getattr(receipt, "dry_run", False):
                continue
            e = self.after_action(getattr(d, "alert_id", ""), getattr(d, "action_type", ""), getattr(d, "target", ""))
            if e is not None:
                out.append(e)
        return out


__all__ = ["ContainmentLoop", "LoopEntry", "chain_lock"]
