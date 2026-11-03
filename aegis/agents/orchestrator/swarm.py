"""Swarm fan-out (roadmap Phase 2.1).

When the orchestrator's first pass lands on ``suspicious`` / ``malicious``
(or ``uncertain`` — the cases a human will have to look at), the alert is
handed to a swarm of **short-lived workers** that run in parallel, each
with one narrow job and no memory of the others:

    ioc_extract      pull IPs / domains / URLs / hashes / users out of the alert
    intel_enrich     look every IOC up in the threat-intel store
    blast_radius     which accounts, hosts, sessions, endpoints are implicated
    log_hunt         write the KQL / SPL hunt queries an analyst would run next
    deception_check  did the attacker touch a honeytoken anywhere in the alert
    patch_proposal   if the payload names a weakness, draft the patch plan
    analyst_brief    one-paragraph brief for the human (LLM; mock-safe)

Every worker returns ``EvidenceItem``s (and, rarely, ``RecommendedAction``s)
that are merged into the chain; the independent voter re-scores the
enriched chain; ``chain.metadata["swarm"]`` records what ran, what it
found, how long it took and what it cost. The swarm **never lowers** a
verdict — it can only add evidence and raise confidence or escalate.

Governed: each worker is a governed tool call (``swarm.<name>``) under the
SOC agent's ACPGuard — the per-alert budget, Q30 allowlist and the
dashboard pause-gate all apply, so pausing ``SOC-AGENTQ-01`` stops the
swarm mid-flight. Caps: ``max_workers`` in flight, ``max_seconds``
wall-clock; a worker that raises or times out is recorded, never fatal.

The MiroFish-scale "thousands of agents" is a different thing — an
attacker-simulation twin — and is not what this module does.
"""

from __future__ import annotations

import logging
from collections import deque
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ..shared.audit import AuditWriteError
from ..shared.evidence_chain import EvidenceChain, EvidenceItem, ReasoningStep, RecommendedAction
from ..shared.injection_defense import wrap_untrusted
from .voting import vote_best

logger = logging.getLogger("aegis.swarm")

SWARM_TRIGGER_VERDICTS = frozenset({"suspicious", "malicious", "uncertain"})
_CONFIRMING_SOURCES = frozenset({"swarm.intel_enrich", "swarm.deception_check"})
_VERDICT_RANK = {"benign": 0, "uncertain": 1, "suspicious": 2, "malicious": 3}

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|in|io|ru|cn|xyz|top|info|biz|co|bank)\b", re.I)
_URL = re.compile(r"https?://[^\s\"'<>]+", re.I)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_PRIVATE_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.", "127.")


@dataclass
class WorkerResult:
    worker: str
    evidence: list[EvidenceItem] = field(default_factory=list)
    actions: list[RecommendedAction] = field(default_factory=list)
    note: str = ""
    error: str = ""
    elapsed_ms: int = 0
    skipped: bool = False

    @property
    def ok(self) -> bool:
        return not self.error and not self.skipped


#: worker(alert, chain, ctx) -> WorkerResult ; ctx carries shared services
WorkerFn = Callable[[dict, EvidenceChain, dict], WorkerResult]


# ----------------------------------------------------------------- workers --

def _text_blob(alert: dict) -> str:
    """Everything stringy in the alert, flattened, for IOC regexes."""
    parts: list[str] = []

    def walk(v: Any) -> None:
        if isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, (list, tuple)):
            for x in v:
                walk(x)
        elif v is not None:
            parts.append(str(v))

    walk(alert)
    return " ".join(parts)[:20_000]


def worker_ioc_extract(alert: dict, chain: EvidenceChain, ctx: dict) -> WorkerResult:
    blob = _text_blob(alert)
    ips = sorted({ip for ip in _IPV4.findall(blob) if not ip.startswith(_PRIVATE_PREFIXES)})
    hashes = sorted(set(_SHA256.findall(blob)) | set(_MD5.findall(blob)))
    urls = sorted(set(_URL.findall(blob)))[:20]
    domains = sorted({d.lower() for d in _DOMAIN.findall(blob) if not d.lower().endswith((".bank.in",))})[:20]
    emails = sorted(set(_EMAIL.findall(blob)))[:20]
    users = sorted({str(alert.get(k)) for k in ("user_id", "user_upn", "principal_id") if alert.get(k)})
    iocs = {"ips": ips, "hashes": hashes, "urls": urls, "domains": domains, "emails": emails, "users": users}
    count = sum(len(v) for v in iocs.values())
    res = WorkerResult("ioc_extract", note=f"{count} indicators")
    if count:
        res.evidence.append(EvidenceItem(
            source="swarm.ioc_extract", weight="medium" if ips or hashes else "low",
            signal=f"Extracted {count} indicators: {len(ips)} external IPs, {len(hashes)} hashes, "
                   f"{len(domains)} domains, {len(urls)} URLs, {len(users)} principals",
            raw_data=iocs,
        ))
    ctx["iocs"] = iocs
    return res


def worker_intel_enrich(alert: dict, chain: EvidenceChain, ctx: dict) -> WorkerResult:
    store = ctx.get("ioc_store")
    res = WorkerResult("intel_enrich")
    iocs = ctx.get("iocs") or {}
    if store is None:
        res.skipped = True
        res.note = "no threat-intel store configured"
        return res
    hits = []
    for kind, values in (("ip", iocs.get("ips", [])), ("domain", iocs.get("domains", [])),
                         ("url", iocs.get("urls", [])), ("hash_sha256", [h for h in iocs.get("hashes", []) if len(h) == 64]),
                         ("hash_md5", [h for h in iocs.get("hashes", []) if len(h) == 32])):
        for v in values:
            ioc = store.lookup(v, kind)  # type: ignore[arg-type]
            if ioc is not None:
                hits.append({"kind": kind, "value": v, "confidence": ioc.confidence, "source": ioc.source, "tags": list(ioc.tags)})
    res.note = f"{len(hits)} intel hits"
    if hits:
        top = max(h["confidence"] for h in hits)
        res.evidence.append(EvidenceItem(
            source="swarm.intel_enrich", weight="high" if top >= 0.8 else "medium",
            signal=f"{len(hits)} indicator(s) known to threat intel: " + ", ".join(f"{h['kind']}={h['value']}" for h in hits[:5]),
            raw_data={"hits": hits},
        ))
    return res


def worker_blast_radius(alert: dict, chain: EvidenceChain, ctx: dict) -> WorkerResult:
    implicated: dict[str, list[str]] = {"accounts": [], "hosts": [], "endpoints": [], "sessions": []}
    for k in ("user_id", "user_upn", "principal_id", "accessed_object_owner", "beneficiary_account"):
        if alert.get(k):
            implicated["accounts"].append(str(alert[k]))
    for k in ("host", "dest_ip", "unit_hostname", "waf_host", "compromised_entity"):
        if alert.get(k):
            implicated["hosts"].append(str(alert[k]))
    for k in ("url", "endpoint", "app", "site"):
        if alert.get(k):
            implicated["endpoints"].append(str(alert[k])[:200])
    obs = alert.get("observed") if isinstance(alert.get("observed"), dict) else {}
    if obs.get("endpoint"):
        implicated["endpoints"].append(str(obs["endpoint"]))
    if obs.get("session_count_24h"):
        implicated["sessions"].append(f"{obs['session_count_24h']} sessions in 24h")
    if alert.get("session_id"):
        implicated["sessions"].append(str(alert["session_id"]))
    total = sum(len(v) for v in implicated.values())
    res = WorkerResult("blast_radius", note=f"{total} implicated entities")
    if total:
        wide = len(implicated["accounts"]) > 1 or len(implicated["hosts"]) > 1
        res.evidence.append(EvidenceItem(
            source="swarm.blast_radius", weight="high" if wide else "medium",
            signal=f"Blast radius: {len(implicated['accounts'])} account(s), {len(implicated['hosts'])} host(s), "
                   f"{len(implicated['endpoints'])} endpoint(s)",
            raw_data=implicated,
        ))
    ctx["blast_radius"] = implicated
    return res


def worker_log_hunt(alert: dict, chain: EvidenceChain, ctx: dict) -> WorkerResult:
    """The queries an analyst would run next — produced, not executed
    (execution needs the SIEM connectors; the text is evidence for the human)."""
    iocs = ctx.get("iocs") or {}
    queries: list[dict] = []
    for ip in iocs.get("ips", [])[:3]:
        queries.append({"engine": "kql", "purpose": f"all activity from {ip} (24h)",
                        "query": f"union SecurityEvent, CommonSecurityLog, SigninLogs | where TimeGenerated > ago(24h) "
                                 f"| where SourceIP == '{ip}' or IPAddress == '{ip}' | summarize count() by Type, bin(TimeGenerated, 1h)"})
        queries.append({"engine": "spl", "purpose": f"web hits from {ip}",
                        "query": f'index=web src_ip="{ip}" earliest=-24h | stats count by uri, status'})
    for user in iocs.get("users", [])[:2]:
        queries.append({"engine": "kql", "purpose": f"sign-ins for {user} (7d)",
                        "query": f"SigninLogs | where TimeGenerated > ago(7d) | where UserPrincipalName has '{user}' "
                                 f"or UserId == '{user}' | project TimeGenerated, IPAddress, Location, ResultType, AppDisplayName"})
    for h in iocs.get("hashes", [])[:2]:
        queries.append({"engine": "kql", "purpose": f"hosts that ran {h[:12]}…",
                        "query": f"DeviceProcessEvents | where SHA256 == '{h}' or MD5 == '{h}' | summarize by DeviceName"})
    res = WorkerResult("log_hunt", note=f"{len(queries)} hunt queries")
    if queries:
        res.evidence.append(EvidenceItem(
            source="swarm.log_hunt", weight="low",
            signal=f"{len(queries)} hunt queries prepared for the analyst (KQL/SPL)", raw_data={"queries": queries},
        ))
    return res


def worker_deception_check(alert: dict, chain: EvidenceChain, ctx: dict) -> WorkerResult:
    monitor = ctx.get("honeytoken")
    res = WorkerResult("deception_check")
    if monitor is None:
        res.skipped, res.note = True, "no honeytoken monitor"
        return res
    touched = bool(monitor.alert_touches_decoy(alert))
    res.note = "decoy touched" if touched else "no decoy touched"
    if touched:
        res.evidence.append(EvidenceItem(
            source="swarm.deception_check", weight="high",
            signal="The activity touched a honeytoken — no legitimate workflow references it",
            raw_data={"decoy": True},
        ))
        res.actions.append(RecommendedAction(
            action_type="escalate", target=str(alert.get("id", "")), requires_hitl=True, confidence=0.95,
            reasoning="Honeytoken contact is a near-certain attacker signal; escalate regardless of other evidence",
        ))
    return res


def worker_patch_proposal(alert: dict, chain: EvidenceChain, ctx: dict) -> WorkerResult:
    """If the payload names a weakness class, draft a patch plan (a plan, not a deploy)."""
    blob = _text_blob(alert).lower()
    weakness = None
    for key, name in (("union select", "SQL injection"), ("' or 1=1", "SQL injection"), ("<script", "Cross-site scripting"),
                      ("../", "Path traversal"), ("..%2f", "Path traversal"), ("$(", "Command injection"),
                      ("etc/passwd", "Path traversal"), ("@@version", "SQL injection")):
        if key in blob:
            weakness = name
            break
    res = WorkerResult("patch_proposal")
    if weakness is None:
        res.skipped, res.note = True, "no code weakness implied by payload"
        return res
    target = str(alert.get("url") or alert.get("endpoint") or "affected endpoint")[:200]
    plan = {
        "weakness": weakness,
        "target": target,
        "steps": [
            f"Add a virtual patch at the WAF for {target} ({weakness} signature) — TTL'd, see connectors",
            f"Open a fix ticket: parameterise inputs / encode output for {target}",
            "Add the payload to the regression corpus (eval/injection_corpus) so the fix is measured",
        ],
    }
    res.note = f"{weakness} on {target}"
    res.evidence.append(EvidenceItem(
        source="swarm.patch_proposal", weight="low",
        signal=f"Patch plan drafted: {weakness} on {target}", raw_data=plan,
    ))
    return res


def worker_analyst_brief(alert: dict, chain: EvidenceChain, ctx: dict) -> WorkerResult:
    llm = ctx.get("llm")
    res = WorkerResult("analyst_brief")
    if llm is None:
        res.skipped, res.note = True, "no LLM client"
        return res
    wrapped = wrap_untrusted("alert", str({k: v for k, v in alert.items() if k not in ("payload", "raw")})[:3000])
    prompt = (
        "Write a 3-sentence analyst brief: what happened, why the verdict, what the human should decide. "
        f"Verdict so far: {chain.verdict} ({chain.confidence:.2f}); evidence items: {len(chain.evidence)}.\n\n"
        f"{wrapped.wrapped}"
    )
    try:
        out = llm.complete("You are a SOC analyst writing for a senior human reviewer. Plain prose only.", prompt, max_tokens=300)
        text = (out.text or "").strip()[:1200]
    except Exception as e:  # noqa: BLE001
        res.error = f"{type(e).__name__}: {str(e)[:120]}"
        return res
    if not text:
        res.skipped, res.note = True, "empty brief"
        return res
    res.note = "brief written"
    res.evidence.append(EvidenceItem(source="swarm.analyst_brief", weight="low", signal=f"Analyst brief: {text[:300]}",
                                     raw_data={"brief": text, "model": getattr(out, "model", "")}))
    return res


DEFAULT_WORKERS: dict[str, WorkerFn] = {
    "ioc_extract": worker_ioc_extract,
    "intel_enrich": worker_intel_enrich,
    "blast_radius": worker_blast_radius,
    "log_hunt": worker_log_hunt,
    "deception_check": worker_deception_check,
    "patch_proposal": worker_patch_proposal,
    "analyst_brief": worker_analyst_brief,
}
#: workers that need ioc_extract's output run after it
_DEPENDS_ON_IOCS = ("intel_enrich", "log_hunt")


# ------------------------------------------------------------- orchestrator --

class SwarmOrchestrator:
    """Wraps a SOCOrchestrator: first pass as usual, then the swarm on the
    verdicts worth it. Drop-in: ``handle(alert) -> EvidenceChain``."""

    name = "swarm_orchestrator"

    def __init__(self, orchestrator: Any, *, workers: Optional[dict[str, WorkerFn]] = None,
                 max_workers: int = 8, max_seconds: float = 20.0,
                 trigger_verdicts: frozenset[str] = SWARM_TRIGGER_VERDICTS,
                 guard: Any = None, ioc_store: Any = None, voter: Any = None, event_store: Any = None,
                 campaign_min_events: int = 3):
        self._orch = orchestrator
        self._events = event_store                   # roadmap 2.8b: campaign context folded in BEFORE triage
        self._campaign_min = campaign_min_events
        self._workers = dict(workers) if workers is not None else dict(DEFAULT_WORKERS)
        self.max_workers = max(1, int(max_workers))
        self.max_seconds = float(max_seconds)
        self.trigger_verdicts = frozenset(trigger_verdicts)
        self._guard = guard
        self._ioc_store = ioc_store
        self._voter = voter if voter is not None else getattr(orchestrator, "_voter", None)
        # Re-vote with the same reviewer panel the orchestrator uses (ensemble when
        # AEGIS_ENSEMBLE_VOTE is on). An explicitly passed `voter` overrides the panel;
        # otherwise inherit the orchestrator's extras. The panel is assembled live at
        # vote time so a voter swapped in after construction is honored.
        self._extra_voters = [] if voter is not None else list(getattr(orchestrator, "_extra_voters", None) or [])
        self._pool = ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="aegis-swarm")
        self._lock = threading.Lock()
        # recent fan-outs for the status page / tests — the last 1,000, not one per alert forever
        self.runs: deque[dict] = deque(maxlen=1000)

    # passthrough so the governance wrapper and callers see one object
    def __getattr__(self, item: str) -> Any:
        return getattr(self._orch, item)

    def handle(self, alert: dict) -> EvidenceChain:
        if self._events is not None:
            # the last N minutes of the same source / session / user, in the campaign-summary shape
            # the fine-tuned first-pass is trained on; the original dict is left untouched
            try:
                from .walkers.campaign import attach_campaign_context
                alert = attach_campaign_context(alert, self._events, min_events=self._campaign_min)
            except Exception as e:  # noqa: BLE001 — context is a bonus, never a blocker
                logger.debug("[swarm] campaign context skipped: %s", str(e)[:120])
        chain = self._orch.handle(alert)
        if isinstance(alert.get("tls_client"), dict) and "tls_client" not in chain.metadata:
            chain.metadata["tls_client"] = alert["tls_client"]
        if "campaign_context" in alert:
            cc = alert["campaign_context"]
            chain.metadata["campaign_context"] = {k: cc[k] for k in ("events_in_window", "window_minutes", "enumeration", "waf", "timeline", "identity", "adaptation") if k in cc}
        if chain.verdict not in self.trigger_verdicts:
            return chain
        return self.fan_out(alert, chain)

    def fan_out(self, alert: dict, chain: EvidenceChain) -> EvidenceChain:
        started = time.time()
        ctx: dict[str, Any] = {
            "ioc_store": self._ioc_store,
            "honeytoken": getattr(self._orch, "_honeytoken", None),
            "llm": getattr(self._orch, "_primary", None),
        }
        results: list[WorkerResult] = []
        # phase 1: ioc extraction (others depend on it), then everything else in parallel
        first = [n for n in self._workers if n == "ioc_extract"]
        rest = [n for n in self._workers if n != "ioc_extract"]
        for group in (first, rest):
            if not group:
                continue
            remaining = self.max_seconds - (time.time() - started)
            if remaining <= 0:
                results.extend(WorkerResult(n, skipped=True, note="wall-clock cap reached") for n in group)
                continue
            futures = {self._pool.submit(self._run_worker, name, alert, chain, ctx): name for name in group}
            done, pending = wait(futures, timeout=remaining)
            for f in done:
                results.append(f.result())
            for f in pending:
                f.cancel()
                results.append(WorkerResult(futures[f], error=f"timed out after {self.max_seconds:.0f}s"))
        self._merge(chain, results, started)
        self._reseal(alert, chain)
        return chain

    def _reseal(self, alert: dict, chain: EvidenceChain) -> None:
        """Re-seal: the enriched chain (new evidence, re-vote, metadata.swarm) is what the ResponseAgent
        acts on, so it gets its own audit entry and its own persisted row — the pre-swarm entry stays as
        the first-pass record."""
        record = getattr(self._orch, "record", None)
        if callable(record):
            try:
                record(alert, chain)
            except AuditWriteError:
                # the enriched chain is what the ResponseAgent acts on: no audit row, no action —
                # propagate so the service defers the alert exactly like a failed first seal
                raise
            except Exception as e:  # noqa: BLE001 — persistence (dashboard row) is bookkeeping, not the audit
                logger.warning("[swarm] re-seal of %s failed: %s", chain.alert_id, str(e)[:120])

    # ------------------------------------------------------------ internals --

    def _run_worker(self, name: str, alert: dict, chain: EvidenceChain, ctx: dict) -> WorkerResult:
        t0 = time.time()
        tool = f"swarm.{name}"
        meta = {"alert_id": str(alert.get("id", "unknown")), "worker": name, "verdict": chain.verdict}
        if self._guard is not None:
            try:
                self._guard.pre_tool_call(tool, meta)
            except Exception as e:  # noqa: BLE001 — a governance block (incl. pause-gate) skips the worker
                logger.warning("[swarm.%s] skipped by governance on alert %s: %s", name, meta["alert_id"], str(e)[:120])
                return WorkerResult(name, skipped=True, note=f"governance: {str(e)[:120]}", elapsed_ms=0)
        try:
            res = self._workers[name](alert, chain, ctx)
        except Exception as e:  # noqa: BLE001 — one worker's crash is a result, not the swarm's
            logger.warning("[swarm.%s] crashed on alert %s: %s: %s", name, meta["alert_id"], type(e).__name__, str(e)[:160])
            res = WorkerResult(name, error=f"{type(e).__name__}: {str(e)[:160]}")
        res.elapsed_ms = int((time.time() - t0) * 1000)
        if self._guard is not None:
            try:
                self._guard.post_tool_call(tool, result={"evidence": len(res.evidence), "note": res.note[:120]},
                                           success=not res.error, error=res.error or None)
            except Exception as exc:  # noqa: BLE001 — the pre-call already governed the worker; a post-hook failure is logged, not fatal
                logger.debug("[acp] post_tool_call failed for %s: %s", tool, exc)
        return res

    def _merge(self, chain: EvidenceChain, results: list[WorkerResult], started: float) -> None:
        with self._lock:
            order = {n: i for i, n in enumerate(self._workers)}
            results.sort(key=lambda r: order.get(r.worker, 99))
            before_conf, before_verdict = chain.confidence, chain.verdict
            added = 0
            existing_actions = {(a.action_type, a.target) for a in chain.recommended_actions}
            for r in results:
                for ev in r.evidence:
                    chain.evidence.append(ev)
                    added += 1
                for a in r.actions:
                    if (a.action_type, a.target) not in existing_actions:
                        chain.recommended_actions.append(a)
                        existing_actions.add((a.action_type, a.target))
            # the swarm never lowers a verdict; *confirming* evidence can raise it one step.
            # Only an intel hit or a decoy touch confirms anything — blast radius is impact,
            # not likelihood (counting it raised single-signal "suspicious" cases to
            # "malicious" on the live-model eval, 2026-10-21).
            confirmed = any(ev.weight == "high" and ev.source in _CONFIRMING_SOURCES
                            for r in results for ev in r.evidence)
            raised = False
            if confirmed and _VERDICT_RANK.get(chain.verdict, 0) < _VERDICT_RANK["malicious"]:
                chain.verdict = "malicious" if chain.verdict == "suspicious" else "suspicious"
                raised = True
                chain.metadata["verdict_raised_by_swarm"] = True
            chain.specialist_invocations.extend(f"swarm.{r.worker}" for r in results if r.ok)
            # independent re-vote on the enriched chain
            vote_note = ""
            panel = [v for v in [self._voter, *self._extra_voters] if v is not None]
            if panel and added:
                try:
                    v = vote_best(panel, chain)
                    vote_note = v.reason
                    if v.final_confidence > chain.confidence:
                        chain.confidence = min(1.0, v.final_confidence)
                    chain.metadata["swarm_vote_concur"] = v.concur
                    chain.metadata["swarm_vote_tally"] = f"{v.n_concur}/{v.n_voters}"
                    chain.metadata["swarm_vote_unanimous"] = v.unanimous
                except Exception as e:  # noqa: BLE001
                    vote_note = f"re-vote failed: {str(e)[:100]}"
            if raised:
                # The first-pass concur was for the old verdict. Autonomy and the HITL timeout read
                # ``vote_concur``: after a raise it is the re-vote's answer, and no re-vote = no concur.
                chain.metadata["vote_concur"] = chain.metadata.get("swarm_vote_concur") is True
                if "swarm_vote_tally" in chain.metadata:
                    chain.metadata["vote_tally"] = chain.metadata["swarm_vote_tally"]
            chain.reasoning.append(ReasoningStep(
                step=len(chain.reasoning) + 1, action="swarm_fan_out",
                observation=f"{len([r for r in results if r.ok])}/{len(results)} workers returned, {added} evidence items; "
                            + "; ".join(f"{r.worker}: {r.note or r.error or 'skipped'}" for r in results),
                conclusion=(f"Verdict {before_verdict}→{chain.verdict}, confidence {before_conf:.2f}→{chain.confidence:.2f}. "
                            + (vote_note or "No re-vote.")),
            ))
            run = {
                "workers": {r.worker: {"ok": r.ok, "skipped": r.skipped, "error": r.error, "note": r.note,
                                       "evidence": len(r.evidence), "elapsed_ms": r.elapsed_ms} for r in results},
                "evidence_added": added,
                "verdict_before": before_verdict, "verdict_after": chain.verdict,
                "confidence_before": round(before_conf, 3), "confidence_after": round(chain.confidence, 3),
                "elapsed_ms": int((time.time() - started) * 1000),
                "max_workers": self.max_workers, "max_seconds": self.max_seconds,
            }
            chain.metadata["swarm"] = run
            self.runs.append({"alert_id": chain.alert_id, **run})
            logger.info("[swarm] %s: %d workers, +%d evidence, %s→%s in %d ms", chain.alert_id, len(results), added,
                        before_verdict, chain.verdict, run["elapsed_ms"])


def swarm_from_env(orchestrator: Any, **kw: Any) -> Any:
    """Wrap when AEGIS_SWARM=1 (default off); caps from AEGIS_SWARM_MAX_WORKERS / _MAX_SECONDS.

    Campaign context (``AEGIS_CAMPAIGN_CONTEXT``, default on) is independent of the swarm: it is
    cheap and in-memory, and the adaptive-attacker fast path depends on it. With the swarm off,
    the orchestrator is still wrapped — with no workers and no fan-out — just to fold context in."""
    import os
    on = {"1", "true", "yes", "on"}
    if "event_store" not in kw and os.environ.get("AEGIS_CAMPAIGN_CONTEXT", "1").strip().lower() in on:
        from .walkers.campaign import EventStore
        kw["event_store"] = EventStore(window_min=int(os.environ.get("AEGIS_CAMPAIGN_WINDOW_MIN", "30")))
    if os.environ.get("AEGIS_SWARM", "0").strip().lower() not in on:
        if kw.get("event_store") is None:
            return orchestrator
        return SwarmOrchestrator(orchestrator, workers={}, max_workers=1, trigger_verdicts=frozenset(),
                                 event_store=kw["event_store"])
    return SwarmOrchestrator(
        orchestrator,
        max_workers=int(os.environ.get("AEGIS_SWARM_MAX_WORKERS", "8")),
        max_seconds=float(os.environ.get("AEGIS_SWARM_MAX_SECONDS", "20")),
        **kw,
    )
