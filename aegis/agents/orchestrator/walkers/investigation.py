"""The post-verdict investigation tier (roadmap 2.4b).

The verdict and the first HITL card are already out when this runs. ``investigate()`` walks the
blast graph for a sealed chain, attaches it as evidence + ``chain.metadata["blast_graph"]``,
appends a reasoning step, and re-records the chain (new audit entry, persisted row updated in
place) — **never** changing the verdict: the swarm's confirming-evidence rule is the only thing
that raises a verdict, and reach is impact, not likelihood.

``Investigator`` runs that in a bounded background pool keyed by alert id, so the hot path
returns immediately and callers (the service loop, the dashboard) can poll ``status(alert_id)``.
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any, Callable, Optional

from ...shared.evidence_chain import EvidenceChain, EvidenceItem, ReasoningStep
from .mitigation import attach_plan, plan_mitigation
from .twin import run_twin
from .sources import MockTenant, TelemetrySource, tenant_from_env
from .walk import DEFAULT_WALKERS, run_walkers

logger = logging.getLogger("aegis.investigation")
INVESTIGATE_VERDICTS = frozenset({"suspicious", "malicious", "uncertain"})


def investigate(alert: dict, chain: EvidenceChain, source: TelemetrySource, *, guard: Any = None,
                hops: int = 2, max_seconds: float = 10.0, record: Optional[Callable[[dict, EvidenceChain], Any]] = None,
                twin: bool = False, twin_personas: int = 60, twin_rounds: int = 12, llm: Any = None) -> dict:
    """Walk, plan the minimum cut, attach both, re-record. Returns the graph summary (+ ``mitigation``).
    Verdict untouched by construction; the plan only adds RecommendedActions under the HITL policy."""
    verdict_before = chain.verdict
    rep = run_walkers(alert, source, walkers=DEFAULT_WALKERS, hops=hops, max_seconds=max_seconds, guard=guard)
    g = rep.graph; s = g.summary()
    crit = s["critical_assets_reached"]
    chain.evidence.append(EvidenceItem(
        source="investigation.blast_graph", signal=g.signal(),
        weight="high" if crit else ("medium" if s["nodes_reached"] > 3 else "low"),
        raw_data={"summary": s, "per_walker": rep.per_walker},
    ))
    chain.metadata["blast_graph"] = g.to_dict()
    chain.metadata["investigation"] = {"tier": "async", "elapsed_ms": rep.elapsed_ms, "source": getattr(source, "name", "?"),
                                       "hops": hops, "critical_reached": len(crit), "choke_edges": s["choke_edges"]}
    chain.reasoning.append(ReasoningStep(
        step=len(chain.reasoning) + 1, action="investigate_blast_radius",
        observation=(f"{len(s['walkers'])} walkers, {s['edges']} edges, {s['nodes_reached']} nodes reached in {rep.elapsed_ms} ms"
                     + (f"; time-boxed: {', '.join(s['truncated'])}" if s["truncated"] else "")),
        conclusion=(f"{len(crit)} critical asset(s) reachable" + (f" — first: {crit[0]['id']} at {crit[0]['distance']} hop(s)" if crit else "")
                    + (f"; top cut candidate: {s['choke_edges'][0]['edge']} (protects {s['choke_edges'][0]['n']})" if s["choke_edges"] else "")
                    + f". Verdict unchanged ({verdict_before}); reach is impact, not likelihood."),
    ))
    plan = plan_mitigation(g)
    from .walk import seeds_from
    ip_seed = next((nid for nid, t in seeds_from(alert) if t == "ip"), None)
    acct_seed = next((nid for nid, t in seeds_from(alert) if t == "account"), None)
    attach_plan(chain, g, plan, source_ip=ip_seed, principal=acct_seed)
    s["mitigation"] = plan.to_dict()
    if twin:
        rep = run_twin(alert, chain, g, llm=llm, personas=twin_personas, rounds=twin_rounds, max_seconds=max_seconds / 2, guard=guard,
                       contained=getattr(source, "contained", None))
        s["twin"] = chain.metadata.get("twin", rep.to_dict())
    assert chain.verdict == verdict_before
    if record is not None:
        try:
            record(alert, chain)
        except Exception as e:  # noqa: BLE001 — never lose the graph over bookkeeping
            logger.warning("[investigation] re-record of %s failed: %s", chain.alert_id, str(e)[:120])
    return s


class Investigator:
    """Background runner: ``submit(alert, chain)`` → Future; ``status(alert_id)``; ``drain()``."""

    def __init__(self, source: TelemetrySource | None = None, *, guard: Any = None, max_workers: int = 2,
                 hops: int = 2, max_seconds: float = 10.0, record: Optional[Callable[[dict, EvidenceChain], Any]] = None,
                 verdicts: frozenset[str] = INVESTIGATE_VERDICTS, twin: bool = False, twin_personas: int = 60,
                 twin_rounds: int = 12, llm: Any = None, on_done: Optional[Callable[[dict, EvidenceChain, dict], Any]] = None):
        self.source = source or MockTenant()
        self.on_done = on_done            # e.g. update the HITL card in place (aegis.service)
        self._guard = guard; self.hops = hops; self.max_seconds = max_seconds; self._record = record
        self.twin = twin; self.twin_personas = twin_personas; self.twin_rounds = twin_rounds; self._llm = llm
        self.verdicts = frozenset(verdicts)
        self._pool = ThreadPoolExecutor(max_workers=max(1, max_workers), thread_name_prefix="aegis-investigate")
        self._jobs: dict[str, dict] = {}; self._lock = threading.Lock()

    def wants(self, chain: EvidenceChain) -> bool:
        return chain.verdict in self.verdicts

    def submit(self, alert: dict, chain: EvidenceChain) -> Optional[Future]:
        if not self.wants(chain):
            return None
        aid = str(chain.alert_id)
        with self._lock:
            if aid in self._jobs and self._jobs[aid]["state"] in ("queued", "running"):
                return self._jobs[aid]["future"]
            fut = self._pool.submit(self._run, alert, chain)
            self._jobs.pop(aid, None)                 # re-insert so the newest job is last
            self._jobs[aid] = {"state": "queued", "submitted": time.time(), "future": fut}
            self._prune_locked()
        return fut

    MAX_JOBS = 5000

    def _prune_locked(self) -> None:
        """Keep the most recent finished jobs (each holds a graph summary); never drop a queued / running one."""
        excess = len(self._jobs) - self.MAX_JOBS
        if excess <= 0:
            return
        for aid in [a for a, j in self._jobs.items() if j["state"] in ("done", "failed")][:excess]:
            del self._jobs[aid]

    def _run(self, alert: dict, chain: EvidenceChain) -> dict:
        aid = str(chain.alert_id)
        with self._lock:
            self._jobs[aid]["state"] = "running"
        try:
            s = investigate(alert, chain, self.source, guard=self._guard, hops=self.hops, max_seconds=self.max_seconds, record=self._record,
                            twin=self.twin, twin_personas=self.twin_personas, twin_rounds=self.twin_rounds, llm=self._llm)
            with self._lock:
                self._jobs[aid].update(state="done", finished=time.time(), summary=s)
            if self.on_done is not None:
                try:
                    self.on_done(alert, chain, s)
                except Exception as e:  # noqa: BLE001 — a card update failure never fails the investigation
                    logger.warning("[investigation] on_done hook failed for %s: %s", aid, e)
            return s
        except Exception as e:  # noqa: BLE001
            with self._lock:
                self._jobs[aid].update(state="failed", finished=time.time(), error=f"{type(e).__name__}: {str(e)[:160]}")
            logger.warning("[investigation] %s failed: %s", aid, e)
            raise

    def status(self, alert_id: str) -> dict:
        with self._lock:
            j = self._jobs.get(str(alert_id))
            return {k: v for k, v in j.items() if k != "future"} if j else {"state": "none"}

    def drain(self, timeout: float = 30.0) -> None:
        """Wait for in-flight jobs (tests, graceful shutdown)."""
        with self._lock:
            futs = [j["future"] for j in self._jobs.values() if j["state"] in ("queued", "running")]
        for f in futs:
            try:
                f.result(timeout=timeout)
            except Exception:  # noqa: BLE001, S110 — failures were already logged by _run(); drain only waits
                pass


def investigator_from_env(*, guard: Any = None, record: Any = None, llm: Any = None, on_done: Any = None) -> Optional[Investigator]:
    """``AEGIS_INVESTIGATE=1`` (default off) turns the tier on; ``AEGIS_INVESTIGATE_MAX_SECONDS`` caps a walk;
    ``AEGIS_TWIN=1`` adds the attacker-simulation twin (``AEGIS_TWIN_PERSONAS``, ``AEGIS_TWIN_ROUNDS``)."""
    import os
    on = lambda k, d="0": os.environ.get(k, d).strip().lower() in {"1", "true", "yes", "on"}  # noqa: E731
    if not on("AEGIS_INVESTIGATE"):
        return None
    return Investigator(tenant_from_env(), guard=guard, record=record,
                        max_seconds=float(os.environ.get("AEGIS_INVESTIGATE_MAX_SECONDS", "10")),
                        max_workers=int(os.environ.get("AEGIS_INVESTIGATE_WORKERS", "2")),
                        twin=on("AEGIS_TWIN"), twin_personas=int(os.environ.get("AEGIS_TWIN_PERSONAS", "60")),
                        twin_rounds=int(os.environ.get("AEGIS_TWIN_ROUNDS", "12")), llm=llm, on_done=on_done)


__all__ = ["INVESTIGATE_VERDICTS", "Investigator", "investigate", "investigator_from_env"]
