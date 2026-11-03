"""Long-running SOC service — the process that runs on a SOC host (roadmap 1.6 sandbox, then prod).

``aegis.main`` is the five-phase walking-skeleton demo: one pass over a sample
stream, then vuln/MTD/intel/audit phases. A sandbox or a bank needs the first
phase *forever*: poll the configured sources, run every new alert through the
(governed, swarm) orchestrator and the ResponseAgent, pull HITL decisions back
from the dashboard, roll back expired enforcement, flush persistence — repeat.

    python -m aegis.service                       # poll every AEGIS_POLL_SECONDS (60)
    python -m aegis.service --once                # one cycle, exit 0 — the smoke test
    python -m aegis.service --interval 30 --audit /var/lib/aegis/audit.jsonl

Everything is configured by the same env the demo uses (``AEGIS_SOURCES``,
``SENTINEL_*``, ``ACP_DASHBOARD_URL``, ``AEGIS_SWARM``, ``AEGIS_*_VENDOR`` …);
``build_pipeline`` is the single place the pieces are wired, shared with
``aegis.main``. The audit log is append-only across restarts (the demo truncates
it; the service never does).
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aegis.agents.api_abuse.agent import APIAbuseAgent
from aegis.agents.auth.agent import AuthAgent
from aegis.agents.cloud_controlplane.agent import CloudControlPlaneAgent
from aegis.agents.deception.honeytoken_monitor import HoneytokenMonitor
from aegis.agents.dlp.agent import DLPAgent
from aegis.agents.edr.agent import EDRAgent
from aegis.agents.email.agent import EmailAgent
from aegis.agents.mobile.agent import MobileAgent
from aegis.agents.orchestrator.agent import SOCOrchestrator
from aegis.agents.orchestrator.swarm import swarm_from_env
from aegis.agents.orchestrator.walkers.investigation import investigator_from_env
from aegis.agents.orchestrator.walkers.loop import ContainmentLoop
from aegis.agents.perimeter.agent import PerimeterAgent
from aegis.agents.response.agent import ResponseAgent
from aegis.agents.response.connectors import registry_from_env
from aegis.agents.response.receipts import receipt_log_from_env
from aegis.agents.shared.audit import AuditLog
from aegis.agents.shared.llm_client import get_client, get_voter_client, get_extra_voter_clients
from aegis.agents.orchestrator.voting import ensemble_enabled
from aegis.agents.shared.audit import AuditWriteError
from aegis.ingest.netops import checkpoint_shared_detector
from aegis.ops import sdnotify
from aegis.agents.threat_intel.agent import ThreatIntelAgent
from aegis.agents.threat_intel.cve_feeds import cve_intel_from_env
from aegis.agents.transaction.agent import TransactionAgent
from aegis.agents.wireless.agent import WirelessAgent
from aegis.evolve import sync_from_env as sync_rules_from_env
from aegis.governance import govern_soc
from aegis.healing.pipeline import SelfHealingPipeline
from aegis.edition import apply_edition
from aegis.hitl import hitl_from_env, investigation_card
from aegis.persist import sink_from_env

logger = logging.getLogger("aegis.service")

DEFAULT_AUDIT = Path(os.environ.get("AEGIS_AUDIT_PATH", "") or (Path(__file__).parent / "_audit_log.jsonl"))


@dataclass
class Pipeline:
    """Everything one SOC process needs, wired once."""

    orch: Any
    response: ResponseAgent
    audit: AuditLog
    audit_path: Path
    threat_intel: ThreatIntelAgent
    connectors: Any
    receipt_log: Any = None
    persist_sink: Any = None
    governed: Any = None
    rules_report: Any = None
    primary_name: str = ""
    primary_model: str = ""
    investigator: Any = None            # post-verdict async tier (AEGIS_INVESTIGATE=1), roadmap 2.4b / 2.5
    containment: Any = None             # re-walk after each approved action (roadmap 2.7); on with the investigator
    edition: str = "full"               # external | soc | full (aegis.edition)
    push_server: Any = None             # HTTP push receiver (AEGIS_INGEST_HTTP=1) — Cloudflare Logpush / Firehose / forwarders
    eventhub: Any = None                # Azure Event Hub reader (AEGIS_SOURCES includes eventhub)
    stream: Any = None                  # the shared StreamQueue the receivers feed; the loop wakes on it
    watchdog: Any = None                # feed-liveness watchdog (AEGIS_FEED_WATCHDOG=1); a silent feed is not "no attacks"
    metrics_server: Any = None          # standalone /metrics (AEGIS_METRICS_BIND) for a deployment with no push receiver
    license: Any = None                 # aegis.license.LicenseState — per-installation licence (AEGIS_LICENSE)
    license_meter: Any = None           # 24 h peak eps / devices against the licence
    _license_holder: Any = None         # shared with the push receiver so /healthz and /ingest/license see updates

    def set_license(self, state: Any) -> None:
        """Replace the licence state everywhere it is read (pipeline, receiver, metrics) and make the
        environment + env-built policies honour it. Never raises."""
        from aegis import license as licensing
        self.license = state
        if self._license_holder is not None:
            self._license_holder["state"] = state
        try:
            if state.status == "expired" and state.enforce:
                # a RUNNING service past grace degrades instead of dying: shadow + evaluation features until renewed
                for k, v in licensing.SHADOW_ENV.items():
                    os.environ[k] = v
                for offs in licensing.FEATURE_ENV_OFF.values():
                    os.environ.update(offs)
                logger.error("[license] %s — running in evaluation mode; the service will refuse to START until renewed", state.reason)
            else:
                licensing.apply(state)
            self.response.refresh_policies()
        except Exception as e:  # noqa: BLE001
            logger.warning("[license] could not apply licence state: %s", str(e)[:200])
        _license_metrics(state)
    model_key: str = ""                 # change-key of the promotion pointer the live model reflects (hot-reload)

    def hot_reload_from_pointer(self) -> Any:
        """Apply a human-approved model promotion at runtime (AEGIS_HOT_RELOAD). For the vllm
        backend this swaps the shared primary client in place via set_model — no restart; for
        the local backend it reports that the promotion applies at restart. Cheap no-op when the
        pointer is unset or unchanged."""
        from aegis.finetune.hot_reload import apply_reload, read_pointer
        result = apply_reload(getattr(self.orch, "_primary", None), self.model_key, read_pointer())
        if result.mode != "noop":
            self.model_key = result.key or self.model_key
        if result.changed:
            self.primary_model = result.served_model or self.primary_model
            logger.info("[service] hot-reloaded triage model → run=%s served=%s",
                        result.run, result.served_model)
        return result

    @property
    def swarm_on(self) -> bool:
        return self.orch.__class__.__name__ == "SwarmOrchestrator" and bool(getattr(self.orch, "_workers", None))

    def banner(self) -> str:
        g = self.governed
        lic = self.license
        return (f"[{self.edition}] LLM backend: {self.primary_name} ({self.primary_model})"
                + (f" — {lic.describe()} — installation {lic.installation_id}" if lic is not None else "")
                + (f" — governed by ACP as {g.agent_code}" if g else " — ungoverned brain")
                + f" — HITL {getattr(getattr(self.response, '_hitl', None), 'name', 'stdout')}"
                + (f" — swarm on ({self.orch.max_workers} workers, {self.orch.max_seconds:.0f}s cap)"
                   if self.swarm_on else "")
                + (" — campaign context on" if getattr(self.orch, "_events", None) is not None else "")
                + f" — connectors {self.connectors.mode}"
                + f" — auto-block {getattr(getattr(self.response, '_autonomy', None), 'mode', 'off')}"
                + (f" — push receiver {self.push_server.url} (+/metrics)" if self.push_server is not None else "")
                + (f" — metrics {self.metrics_server.url}/metrics" if self.metrics_server is not None else "")
                + (" — event hub reader on" if self.eventhub is not None else "")
                + (" — feed watchdog on" if self.watchdog is not None else ""))

    def close(self) -> None:
        try:
            from aegis.ingest.ndr import flush
            flush()                                      # the discovered-AI-usage register, if NDR ran
        except Exception as e:  # noqa: BLE001
            logger.warning("[service] AI usage register flush failed: %s", e)
        for r in (self.push_server, self.eventhub, self.metrics_server):
            if r is not None:
                try:
                    r.stop()
                except Exception as e:  # noqa: BLE001
                    logger.warning("[service] receiver stop failed: %s", e)


def build_pipeline(audit_path: Path | str = DEFAULT_AUDIT, *, fresh: bool = False,
                   include_mock_intel: bool | None = None) -> Pipeline:
    """Wire the SOC: specialists → orchestrator (→ swarm) → response, governance, sinks.

    ``fresh=True`` truncates the audit log first (the demo does; a service must not).
    ``include_mock_intel`` seeds the IOC store with the built-in mock feed (demo default);
    the service reads ``AEGIS_INTEL_MOCK`` (default off) when it is not given.
    """
    from aegis import license as licensing
    lic_state = licensing.apply(licensing.check())       # per-installation licence first: it may cap the edition / force shadow
    _lic_holder: dict[str, Any] = {"state": lic_state}  # the receiver reads the LIVE state (renewal / over-limit update it)
    edition = apply_edition()                            # fills edition defaults, refuses contradictory config (fail fast)
    audit_path = Path(audit_path)
    if fresh and audit_path.exists():
        audit_path.unlink()
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    if include_mock_intel is None:
        include_mock_intel = os.environ.get("AEGIS_INTEL_MOCK", "0").strip().lower() in {"1", "true", "yes", "on"}

    primary = get_client()
    # Voter on a different model family for prompt-injection resistance.
    voter = get_voter_client(avoid_family="anthropic")
    # Extra voters for the majority-vote ensemble (AEGIS_ENSEMBLE_VOTE). Built only when the
    # flag is on, so a single-voter deployment loads no extra models; AEGIS_VOTER_MODELS lists
    # them. With >=2 live voters the orchestrator runs the ensemble; otherwise the single-voter
    # path, unchanged.
    extra_voters = get_extra_voter_clients() if ensemble_enabled() else []
    persist_sink = sink_from_env()                       # Phase 0.3 — chains/receipts → dashboard
    from aegis.store import store_from_env
    index = store_from_env(audit_path)                   # derived DuckDB/SQLite/Postgres/MSSQL index of the chain (AEGIS_INDEX_URL)
    audit = AuditLog(audit_path, sink=persist_sink, index=index)
    receipt_log = receipt_log_from_env(audit_path.parent, sink=persist_sink)   # Phase 1.5
    connectors = registry_from_env(on_receipt=[receipt_log] if receipt_log else [])
    response = ResponseAgent(self_healing=SelfHealingPipeline(), hitl=hitl_from_env(), connectors=connectors)

    cve_intel = cve_intel_from_env()                     # AEGIS_CVE_INTEL=1 — KEV + NVD + EPSS consumer (cached)
    threat_intel = ThreatIntelAgent(llm=primary, cve_intel=cve_intel)
    threat_intel.refresh_from_feeds(include_mock=include_mock_intel, include_tenable=True,
                                    include_kev=cve_intel is not None, include_nvd=cve_intel is not None,
                                    publish=cve_intel is not None and bool(os.environ.get("ACP_DASHBOARD_URL")))   # KEV/NVD → dashboard advisory library
    threat_intel.distribute_to_perimeter()
    threat_intel.distribute_to_edr()
    from aegis.ingest.ndr import set_ioc_store, set_sink
    set_ioc_store(threat_intel.store)                    # the network sensor's egress detector checks feed domains / IPs too
    set_sink(persist_sink if persist_sink is not None and persist_sink.enabled else None)   # discovered AI usage → /ai-registry

    orch: Any = SOCOrchestrator(
        primary_llm=primary, voter_llm=voter, extra_voters=extra_voters,
        perimeter=PerimeterAgent(llm=primary), auth=AuthAgent(llm=primary), edr=EDRAgent(llm=primary),
        api_abuse=APIAbuseAgent(llm=primary), transaction=TransactionAgent(llm=primary),
        cloud_controlplane=CloudControlPlaneAgent(llm=primary), dlp=DLPAgent(llm=primary),
        email=EmailAgent(llm=primary), mobile=MobileAgent(llm=primary), wireless=WirelessAgent(llm=primary),
        honeytoken=HoneytokenMonitor(), audit=audit,
    )
    rules_report = sync_rules_from_env()                 # Phase 3.1 — accepted rules before the first alert
    governed = govern_soc(orch, response=response)       # Phase 0.1 — the brain is a governed ACP agent
    orch = swarm_from_env(orch, guard=governed.guard if governed else None, ioc_store=threat_intel.store)
    record = getattr(orch, "record", None)
    hitl = getattr(response, "_hitl", None)
    logger.info("[service] %s; HITL transport: %s", edition.describe(), getattr(hitl, "name", "stdout"))
    # the async tier updates the HITL card in place (blast radius / plan / twin) once it finishes
    on_done = (lambda alert, chain, summary: hitl.attach_investigation(chain.alert_id, investigation_card(chain))) \
        if hitl is not None and hasattr(hitl, "attach_investigation") else None
    investigator = investigator_from_env(guard=governed.guard if governed else None, record=record if callable(record) else None,
                                         llm=getattr(orch, "_primary", None), on_done=on_done)
    containment = (ContainmentLoop(investigator.source, guard=governed.guard if governed else None,
                                   record=record if callable(record) else None) if investigator is not None else None)
    # streaming ingest: receivers start once here (the registry runs every cycle); the blocklist
    # endpoint serves the active enforcement set to any edge enforcer
    from aegis.ingest.stream import get_stream
    from aegis.ingest.http_push import push_server_from_env
    def _status() -> dict:
        from aegis.ingest.netops import _last_checkpoint, _state_path
        out = {"audit": {"path": str(audit_path), "degraded": audit.degraded, "write_failures": audit.write_failures,
                         "last_error": audit.last_error, "tail": audit.tail_hash[:16]},
               "netops_checkpoint_age_s": int(time.time() - _last_checkpoint) if _last_checkpoint and _state_path() else None}
        out["degraded"] = audit.degraded
        if index is not None:
            out["index"] = {"dialect": index.dialect, "stale": index.stale, "failures": index.failures}
        return out
    push_server = push_server_from_env(blocklist=lambda: connectors.active_receipts, audit_path=audit_path,
                                       license=lambda: _lic_holder["state"], status=_status, index=index)
    eventhub = None
    if "eventhub" in [x.strip().lower() for x in os.environ.get("AEGIS_SOURCES", "").split(",")]:
        from aegis.ingest.eventhub import eventhub_from_env
        eventhub = eventhub_from_env()
    from aegis.ingest.watchdog import feed_watchdog_from_env
    watchdog = feed_watchdog_from_env()              # a dead feed must page someone, not hide as silence
    from aegis.agents.shared.observability import metrics_server_from_env
    metrics_server = metrics_server_from_env()       # the push receiver serves /metrics too; this is for poll-only SOCs
    p = Pipeline(orch=orch, response=response, audit=audit, audit_path=audit_path, threat_intel=threat_intel,
                 connectors=connectors, receipt_log=receipt_log, persist_sink=persist_sink, governed=governed,
                 rules_report=rules_report, primary_name=primary.name, primary_model=primary.model,
                 investigator=investigator, containment=containment, edition=edition.name,
                 push_server=push_server, eventhub=eventhub, stream=get_stream(), watchdog=watchdog,
                 metrics_server=metrics_server, license=lic_state, _license_holder=_lic_holder,
                 license_meter=licensing.LicenseMeter(eps_limit=lic_state.eps_limit, devices_limit=lic_state.devices_limit,
                                                      allowance_s=_envf("AEGIS_LICENSE_OVERLIMIT_DAYS", 7) * 86400))
    _license_metrics(lic_state)
    # record which promotion the live model reflects, so hot-reload fires only on a CHANGE. The
    # local backend applied the pointer at startup (via _promoted_model); the vllm backend does
    # not, so leave its key empty and let the first hot-reload cycle apply the promoted adapter.
    try:
        from aegis.finetune.hot_reload import pointer_key, read_pointer, unwrap
        _ptr = read_pointer()
        _inner = unwrap(getattr(p.orch, "_primary", None))
        p.model_key = "" if (_ptr and hasattr(_inner, "set_model")) else pointer_key(_ptr or {})
    except Exception as exc:  # noqa: BLE001 — pointer init must never block startup
        logger.warning("[service] hot-reload startup key init failed: %s", exc)
    return p


@dataclass
class CycleStats:
    alerts: int = 0
    executed: int = 0
    hitl_queued: int = 0
    decisions: int = 0
    rolled_back: int = 0
    errors: int = 0
    audit_failures: int = 0
    deferred: int = 0
    lost: int = 0          # alerts that could be neither handled nor parked
    source_errors: list[str] = field(default_factory=list)
    redelivered: int = 0
    seconds: float = 0.0
    investigations: int = 0
    containment_checks: int = 0
    verdicts: dict[str, int] = field(default_factory=dict)
    streamed: int = 0                   # alerts that arrived by push / stream this cycle
    max_lag_ms: int = 0                 # worst vendor-timestamp → AEGIS-receipt lag among them
    max_handle_ms: int = 0              # worst receipt → verdict-sealed time among them

    def line(self) -> str:
        v = " ".join(f"{k}={n}" for k, n in sorted(self.verdicts.items()))
        lag = f" streamed={self.streamed} lag_ms={self.max_lag_ms} handle_ms={self.max_handle_ms}" if self.streamed else ""
        extra = (f"deferred={self.deferred} " if self.deferred else "") + (f"redelivered={self.redelivered} " if self.redelivered else "") \
            + (f"LOST={self.lost} " if self.lost else "")
        return (f"alerts={self.alerts} executed={self.executed} hitl_queued={self.hitl_queued} "
                f"decisions={self.decisions} rolled_back={self.rolled_back} errors={self.errors} {extra}"
                f"{self.seconds:.1f}s{lag} {v}".rstrip())


_SOURCE_ERROR = "__aegis_source_error__"


def _alerts_from_env(watchdog: Any = None) -> Iterator[dict]:
    """Every configured source in turn. A source that raises (Sentinel 401, a vendor 503) ends only ITS pass:
    the error is handed to run_cycle as a marker and the next source still runs (code review 2026-11-03 E6 —
    one chained iterator let a single bad bearer token blind the WAF feed for as long as it lasted)."""
    from aegis.ingest import sources_from_env
    for name, it in sources_from_env():
        try:
            for alert in it:
                if watchdog is not None:
                    # attribute each polled alert to its ingest source for liveness; pushed/streamed
                    # vendors are counted from StreamQueue.stats.by_source in the service loop instead
                    watchdog.record(name)
                yield alert
        except Exception as e:  # noqa: BLE001 — reported per source, the others keep running
            yield {_SOURCE_ERROR: name, "error": f"{type(e).__name__}: {str(e)[:200]}"}


def _stream_alerts(p: Pipeline) -> Iterator[dict]:
    """Only what the receivers have queued — the fast path between polls."""
    from aegis.ingest import AlertCheckpoint, StreamConsumer
    cp = AlertCheckpoint(Path(os.environ.get("AEGIS_CHECKPOINT", ".aegis-ingest.json")))
    yield from StreamConsumer(queue=p.stream, checkpoint=cp).iter_alerts()


_last_drift_check = 0.0


def _drift_check(p: Any) -> None:
    """Every AEGIS_VERIFY_EVERY_S (default 300 s; 0 = off) read active enforcement back at the vendors: an
    action released or removed outside AEGIS is marked drifted instead of being reported as still in force."""
    global _last_drift_check
    every = float(os.environ.get("AEGIS_VERIFY_EVERY_S", "300") or 0)
    if every <= 0 or time.time() - _last_drift_check < every:
        return
    _last_drift_check = time.time()
    try:
        drifted = p.response.check_drift()
        if drifted:
            logger.error("[service] %d action(s) no longer in force at the vendor: %s", len(drifted),
                         ", ".join(f"{r.action_type} {r.target} ({r.connector})" for r in drifted[:10]))
    except Exception as e:  # noqa: BLE001 — a read-back failure must not stop the cycle
        logger.warning("[service] vendor drift check failed: %s", str(e)[:200])


def run_cycle(p: Pipeline, alerts: Iterator[dict] | None = None, *, max_alerts: int = 0,
              sweep: bool = True, hitl: bool = True, storm: "StormControl | None" = None) -> CycleStats:
    """One pass: new alerts → orchestrator → response; then HITL sync, TTL sweep, flush.
    ``hitl=False`` / ``sweep=False`` make the short stream-triggered pass between polls skip
    the dashboard round-trips; the interval cycle still does them. In storm mode (``storm.active``)
    model-bound alerts are spilled to the deferred queue and only fast paths run."""
    stats = CycleStats()
    t0 = time.time()
    it = iter(alerts if alerts is not None else _alerts_from_env(p.watchdog))
    while True:
        try:
            alert = next(it)
        except StopIteration:
            break
        except Exception as e:  # noqa: BLE001 — a vendor API down (Sentinel 503, bad bearer) ends THIS source's pass, not the service
            stats.errors += 1
            logger.error("[service] source stopped mid-cycle: %s: %s — remaining sources skipped until the next cycle",
                         type(e).__name__, str(e)[:200])
            break
        if _SOURCE_ERROR in alert:
            stats.errors += 1
            stats.source_errors.append(alert[_SOURCE_ERROR])
            logger.error("[service] source %s stopped mid-cycle: %s — the other sources keep running",
                         alert[_SOURCE_ERROR], alert.get("error"))
            continue
        if max_alerts and stats.alerts >= max_alerts:
            break
        stats.alerts += 1
        sdnotify.watchdog()
        if storm is not None and storm.active and not alert.get("deferred_at") and not p.orch.is_fast_path(alert):
            if storm.queue.push(alert):
                stats.deferred += 1
                continue
        try:
            chain = p.orch.handle(alert)
            summary = p.response.execute(chain, alert)
        except AuditWriteError as e:
            # the evidence could not be written, so nothing was executed for this alert (fail closed). The consumer
            # has already checkpointed it, so "retry from the source" is not an option: park it in the deferred
            # queue and re-feed it once the log is writable. One line per cycle — a full disk is noisy enough.
            stats.errors += 1
            stats.audit_failures += 1
            # a re-fed alert that fails again is parked again: its old row is behind the cursor once the re-feed
            # batch is acked (code review 2026-11-03 E1 — it used to vanish with dropped=0)
            if storm is not None and storm.queue.push({**alert, "audit_deferred": True}, "audit"):
                stats.deferred += 1
            else:
                stats.lost += 1
                logger.error("[service] alert %s could not be parked (no spill space) — it must be re-sent from its source",
                             alert.get("id"))
            if stats.audit_failures == 1:
                logger.error("[service] audit log not writable (%s): alerts are parked in the deferred queue and re-fed once it is", e)
            continue
        except Exception:
            stats.errors += 1
            logger.exception("[service] alert %s failed", alert.get("id"))
            continue
        if alert.get("received_at"):
            stats.streamed += 1
            stats.max_lag_ms = max(stats.max_lag_ms, int(alert.get("ingest_lag_ms") or 0))
            stats.max_handle_ms = max(stats.max_handle_ms, int((time.time() - float(alert["received_at"])) * 1000))
        if p.investigator is not None:
            # async tier: the verdict and the HITL card are out; the blast graph attaches afterwards
            try:
                if p.investigator.submit(alert, chain) is not None:
                    stats.investigations += 1
                    if p.containment is not None:
                        p.containment.track(alert, chain)
            except Exception as e:  # noqa: BLE001
                logger.warning("[service] investigation submit failed for %s: %s", alert.get("id"), e)
        stats.executed += len(summary.executed)
        stats.hitl_queued += len(summary.hitl_queue)
        stats.verdicts[chain.verdict] = stats.verdicts.get(chain.verdict, 0) + 1
        logger.info("[service] %s %s/%.2f by %s — executed=%d hitl=%d", alert.get("id"), chain.verdict,
                    float(chain.confidence), chain.investigated_by, len(summary.executed), len(summary.hitl_queue))
    try:
        decisions = p.response.sync_hitl() if hitl else []
        stats.decisions = len(decisions)
        if p.containment is not None and decisions:
            try:
                entries = p.containment.on_decisions(decisions)
                stats.containment_checks = len(entries)
                hitl = getattr(p.response, "_hitl", None)
                if entries and hitl is not None and hasattr(hitl, "attach_investigation"):
                    for aid, chain in p.containment.tracked_chains(d.alert_id for d in decisions):
                        hitl.attach_investigation(aid, investigation_card(chain))     # containment timeline onto the card
            except Exception as e:  # noqa: BLE001
                logger.warning("[service] containment loop failed: %s", e)
    except Exception as e:  # noqa: BLE001
        stats.errors += 1
        logger.warning("[service] HITL sync failed: %s", str(e)[:200])
    if sweep:
        try:
            stats.rolled_back = len(p.response.sweep_expired())
        except Exception as e:  # noqa: BLE001
            stats.errors += 1
            logger.warning("[service] TTL sweep failed: %s", str(e)[:200])
        _drift_check(p)
    if p.persist_sink is not None:
        p.persist_sink.flush()
    stats.seconds = time.time() - t0
    _meter_license(p, stats)
    return stats


def _envf(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "") or default)
    except ValueError:
        logger.warning("[service] %s=%r is not a number; using %s", name, os.environ.get(name), default)
        return default


def _license_metrics(state: Any) -> None:
    from aegis.agents.shared.observability import METRICS
    for st in ("valid", "grace", "over_limit", "expired", "missing", "invalid"):
        METRICS.set("aegis_license_state", 1.0 if state.status == st else 0.0, status=st)
    METRICS.set("aegis_license_days_left", float(state.days_left) if state.days_left is not None else -1.0)
    METRICS.set("aegis_license_enforced", 1.0 if state.enforce else 0.0)


def _meter_license(p: Pipeline, stats: CycleStats) -> None:
    """Events this cycle against the licence: polled alerts plus everything the stream drained (streamed alerts
    are inside stats.alerts too, so they are subtracted once). Over the limit for longer than the allowance →
    over_limit, which forces shadow for the rest of the run. Never a stop, never a drop."""
    meter, state = p.license_meter, p.license
    if meter is None or state is None:
        return
    from aegis import license as licensing
    drained = int(getattr(getattr(p.stream, "stats", None), "drained", 0) or 0)
    delta = max(0, drained - int(getattr(meter, "_last_drained", 0)))
    meter._last_drained = drained
    devices = None
    try:
        from aegis.ingest.netops import _shared as net_det   # the netops inventory is the device count when present
        if net_det is not None:
            devices = len(getattr(net_det, "_adj", {}) or {})
    except Exception:  # noqa: BLE001
        devices = None
    over = meter.observe(max(0, stats.alerts - stats.streamed) + delta, time.time(), devices)
    if over and state.status == "valid":
        new = licensing.check(over_limit=True)
        if new.status == "over_limit":
            p.set_license(new)
            logger.warning("[license] %s", new.reason)
    elif state.status in ("grace", "over_limit") and time.time() - getattr(meter, "_last_warn", 0.0) > 3600:
        meter._last_warn = time.time()                       # hourly, not every cycle
        logger.warning("[license] %s", state.describe())
    from aegis.agents.shared.observability import METRICS
    METRICS.set("aegis_license_peak_eps_24h", meter.peak_eps_24h)
    METRICS.set("aegis_license_devices_seen", float(meter.devices_seen))


class StormControl:
    """When the loop cannot keep up, keep the fast paths flowing and spill everything else to disk.

    Storm = receiver queue above ``AEGIS_STORM_QUEUE_PCT`` (80 %) of capacity, or the last cycle handled more
    than ``AEGIS_STORM_ALERTS`` (500) alerts, or took longer than ``AEGIS_STORM_CYCLE_S`` (the poll interval).
    It ends when the queue is below half that and the last cycle was small; deferred alerts are then re-fed
    ``AEGIS_STORM_DRAIN`` (200) per cycle, oldest first. Nothing is dropped; the spill file is bounded."""

    def __init__(self, queue: "DeferredQueue", stream: Any, interval_s: float):
        self.queue, self.stream = queue, stream
        self.active = False
        self.since = 0.0
        self.pct = _envf("AEGIS_STORM_QUEUE_PCT", 80.0) / 100.0
        self.alerts = int(_envf("AEGIS_STORM_ALERTS", 500))
        self.cycle_s = _envf("AEGIS_STORM_CYCLE_S", interval_s)
        self.drain = int(_envf("AEGIS_STORM_DRAIN", 200))

    def occupancy(self) -> float:
        try:
            return len(self.stream) / float(self.stream.capacity) if self.stream is not None and self.stream.capacity else 0.0
        except Exception:  # noqa: BLE001
            return 0.0

    def update(self, last: "CycleStats | None") -> bool:
        occ = self.occupancy()
        big = last is not None and (last.alerts >= self.alerts or last.seconds >= self.cycle_s)
        if not self.active and (occ >= self.pct or big):
            self.active, self.since = True, time.time()
            logger.warning("[service] STORM MODE on: queue %.0f%% full, last cycle %s alerts in %.1fs — model-bound alerts are deferred to %s, "
                           "fast paths keep running", occ * 100, last.alerts if last else 0, last.seconds if last else 0, self.queue.path)
        elif self.active and occ < self.pct / 2 and not big:
            self.active = False
            logger.warning("[service] storm mode off after %.0fs; %d alert(s) deferred, draining %d per cycle",
                           time.time() - self.since, self.queue.pending(), self.drain)
        return self.active

    def redeliver(self) -> list[dict]:
        return [] if self.active else self.queue.pop(self.drain)


class Service:
    """Poll loop with graceful stop (SIGTERM/SIGINT → finish the cycle, exit)."""

    def __init__(self, pipeline: Pipeline, *, interval: float = 60.0, max_alerts: int = 0):
        self.p = pipeline
        self.interval = max(1.0, float(interval))
        self.max_alerts = max_alerts
        self.cycles = 0
        self.stream_cycles = 0
        self.history: list[CycleStats] = []
        self._stop = False
        from aegis.ops.deferred import default_spill
        self.storm = StormControl(default_spill(pipeline.audit_path), pipeline.stream, self.interval)

    def stop(self, *_: Any) -> None:
        self._stop = True

    _last_contrib: float = 0.0
    _last_heartbeat: float = 0.0

    _hb_thread: "threading.Thread | None" = None

    def _maybe_heartbeat_and_renew(self) -> None:
        """Once per AEGIS_HEARTBEAT_INTERVAL_S (86400): re-evaluate the licence (expiry and grace are clock-driven —
        a service that runs for months must notice them), heartbeat (counts + code fingerprint + effective flags,
        never event data), pull model updates, and roll the token when fewer than AEGIS_LICENSE_RENEW_DAYS (7) remain.
        The service re-issues only while the installation is in good standing. The network work (heartbeat,
        a multi-GB model download) runs in a daemon thread so the cycle loop keeps answering the systemd watchdog."""
        every = _envf("AEGIS_HEARTBEAT_INTERVAL_S", 86400)
        if time.time() - self._last_heartbeat < every:
            return
        if self._hb_thread is not None and self._hb_thread.is_alive():
            return                                                  # the previous one (a long download) is still going
        self._last_heartbeat = time.time()
        if os.environ.get("AEGIS_HEARTBEAT_INLINE", "").strip() in ("1", "true"):   # tests / --once
            self._heartbeat_and_renew()
            return
        self._hb_thread = threading.Thread(target=self._heartbeat_and_renew, name="aegis-heartbeat", daemon=True)
        self._hb_thread.start()

    def _heartbeat_and_renew(self) -> None:
        from aegis import license as licensing
        lic = self.p.license
        if lic is not None:
            fresh = licensing.check(over_limit=(lic.status == "over_limit"))
            if fresh.status != lic.status or fresh.enforce != lic.enforce:
                logger.info("[license] state %s → %s", lic.status, fresh.status)
                self.p.set_license(fresh)
            else:
                self.p.license = fresh                            # same status, fresher days_left
                if self.p._license_holder is not None:
                    self.p._license_holder["state"] = fresh
                _license_metrics(fresh)
            lic = fresh
        server = os.environ.get("AEGIS_LICENSE_SERVER", "").strip()
        if not server or lic is None:
            return
        token, _ = licensing._read_token(os.environ)
        if not token:
            return
        counters = {"cycles": self.cycles, "alerts": sum(h.alerts for h in self.history), "executed": sum(h.executed for h in self.history),
                    "hitl_queued": sum(h.hitl_queued for h in self.history), "decisions": sum(h.decisions for h in self.history)}
        try:
            from aegis.dataset.contrib import read_cursor
            cur = read_cursor(Path(os.environ.get("AEGIS_CONTRIB_CURSOR", str(self.p.audit_path.parent / ".contrib.cursor"))))
            res = licensing.heartbeat(server, token, licensing.heartbeat_payload(
                installation_id=lic.installation_id, audit_path=self.p.audit_path, counters=counters, contrib_cursor=cur))
            if res.get("attestation") == "unknown":
                logger.warning("[license] the licence service does not recognise this install's code fingerprint — "
                               "a modified install will not be renewed")
            if res.get("standing") and res["standing"] != "good":
                logger.warning("[license] standing with the licence service: %s — %s", res["standing"], res.get("reason", ""))
            else:
                logger.info("[license] heartbeat ok: standing=%s attestation=%s", res.get("standing", "?"), res.get("attestation", "?"))
        except Exception as e:  # noqa: BLE001 — a heartbeat failure never affects the SOC
            logger.warning("[license] heartbeat failed: %s", str(e)[:200])
        # model updates — the brain ships like antivirus definitions: pull, verify the signed manifest, point, hot-reload
        try:
            from aegis import model_updates
            if model_updates.enabled() and lic.licensed:
                r = model_updates.update_once(server=server, token=token, installation_id=lic.installation_id)
                if r.get("updated"):
                    hot = os.environ.get("AEGIS_HOT_RELOAD", "").lower() in ("1", "true", "yes", "on")
                    logger.info("[model_updates] %s → %s installed; %s", r.get("previous") or "base", r["version"],
                                "hot-reloading" if hot else "applies at the next restart (set AEGIS_HOT_RELOAD=1 for an in-place swap on vLLM)")
                    from aegis.agents.shared.observability import METRICS
                    METRICS.inc("aegis_model_updates_total")
                    if hot:
                        self.p.hot_reload_from_pointer()
        except Exception as e:  # noqa: BLE001
            logger.warning("[model_updates] %s", str(e)[:200])
        try:
            if lic.license is not None and lic.days_left is not None and lic.days_left < _envf("AEGIS_LICENSE_RENEW_DAYS", 7):
                res = licensing.renew(server, token)
                dest = licensing.token_path()
                if dest is not None:
                    licensing.install_token(res["token"], dest)              # verified + atomic; the old file is kept as .prev
                    self.p.set_license(licensing.check())
                    logger.info("[license] token renewed until %s", time.strftime("%Y-%m-%d", time.gmtime(float(res.get("expires", 0)))))
                else:
                    logger.warning("[license] renewed token received but AEGIS_LICENSE is inline — set it to the new value: %s…", res["token"][:24])
        except Exception as e:  # noqa: BLE001
            logger.warning("[license] renewal failed: %s", str(e)[:200])

    def _maybe_contribute(self) -> None:
        """Community licence (``AEGIS_CONTRIB=1``): every ``AEGIS_CONTRIB_INTERVAL_S`` (3600) build the scrubbed
        bundle of new chains + analyst decisions and push it to ``AEGIS_LICENSE_SERVER`` (or write it to
        ``AEGIS_CONTRIB_OUT`` on an air-gapped host). A refused bundle leaves nothing; a failed push retries next time."""
        if os.environ.get("AEGIS_CONTRIB", "0").strip().lower() not in ("1", "true", "yes", "on"):
            return
        every = _envf("AEGIS_CONTRIB_INTERVAL_S", 3600)
        if time.time() - self._last_contrib < every:
            return
        self._last_contrib = time.time()
        try:
            from aegis.dataset.contrib import contribute
            from aegis.license import _read_token
            token, _ = _read_token(os.environ)
            if os.environ.get("AEGIS_LICENSE_SERVER", "").strip() and not token and not os.environ.get("AEGIS_CONTRIB_OUT", "").strip():
                if not getattr(self, "_contrib_no_token_noted", False):
                    self._contrib_no_token_noted = True
                    logger.warning("[contrib] AEGIS_CONTRIB=1 but no licence token (AEGIS_LICENSE) — contributions are off until one is installed")
                return
            lic = self.p.license
            res = contribute(audit_path=self.p.audit_path, installation_id=lic.installation_id if lic else "unknown",
                             license_token=token, license_id=(lic.license.license_id if lic and lic.license else ""),
                             hitl_dir=os.environ.get("AEGIS_HITL_DIR") or None,
                             cursor_path=os.environ.get("AEGIS_CONTRIB_CURSOR", str(self.p.audit_path.parent / ".contrib.cursor")),
                             server=os.environ.get("AEGIS_LICENSE_SERVER", "").strip(),
                             out=(os.environ.get("AEGIS_CONTRIB_OUT", "").strip() and
                                  str(Path(os.environ["AEGIS_CONTRIB_OUT"]) / f"contrib-{int(time.time())}.json.gz")) or None)
            if res.get("sent") or res.get("file"):
                logger.info("[contrib] %d record(s) (%d with analyst decisions) %s", res["records"], res["counts"]["human_decided"],
                            "pushed" if res.get("sent") else f"written to {res['file']}")
            elif res.get("reason") == "privacy gate":
                logger.error("[contrib] bundle refused by the privacy gate — nothing left this host (%d finding(s))", len(res["findings"]))
            from aegis.agents.shared.observability import METRICS
            METRICS.inc("aegis_contrib_records_total", res.get("records", 0))
            METRICS.set("aegis_contrib_last_ok", 1.0 if res.get("sent") or res.get("file") or res.get("reason") == "nothing new" else 0.0)
        except Exception as e:  # noqa: BLE001 — contribution must never take the SOC down
            logger.warning("[contrib] failed: %s", str(e)[:200])

    def run(self, *, once: bool = False, max_cycles: int = 0) -> int:
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, self.stop)
            except (ValueError, OSError):   # not the main thread (tests)
                pass
        logger.info("[service] AEGIS SOC service — %s", self.p.banner())
        if self.p.rules_report is not None:
            r = self.p.rules_report
            logger.info("[service] rule feed %s: %d applied, %d already, %d rejected",
                        r.version, len(r.applied), len(r.already), len(r.rejected))
        stream = self.p.stream
        hot_reload = os.environ.get("AEGIS_HOT_RELOAD", "").strip().lower() in ("1", "true", "yes", "on")
        sdnotify.ready(f"AEGIS up: {self.p.banner()[:120]}")
        wd = sdnotify.watchdog_interval_s()
        if wd:
            logger.info("[service] systemd watchdog armed: pinging every ≤%.0fs", wd)
        while not self._stop:
            try:
                stats = run_cycle(self.p, max_alerts=self.max_alerts, storm=self.storm)
            except Exception:  # noqa: BLE001 — the loop is the service; log, count, and keep going
                logger.exception("[service] cycle %d crashed", self.cycles + 1)
                stats = CycleStats(); stats.errors += 1
            self.cycles += 1
            self.storm.update(stats)
            budget = time.time() + self.interval * 0.5          # drain the backlog in batches, up to half the poll interval
            while not self._stop and time.time() < budget:
                pend = self.storm.redeliver()
                if not pend:
                    break
                try:
                    st2 = run_cycle(self.p, alerts=iter(pend), sweep=False, hitl=False, storm=self.storm)
                except Exception:  # noqa: BLE001
                    logger.exception("[service] re-feed cycle crashed")
                    break
                self.storm.queue.ack()                              # processed (or re-spilled): commit the cursor
                if st2.audit_failures:                              # still failing: stop, or the re-parked rows loop
                    stats.errors += st2.errors
                    break
                stats.redelivered += st2.alerts
                stats.executed += st2.executed
                sdnotify.watchdog()
                logger.info("[service] re-fed %d deferred alert(s): %s (%d still pending)", st2.alerts, st2.line(), self.storm.queue.pending())
                if self.storm.update(st2):                          # the backlog itself must not restart the storm
                    break
            sdnotify.watchdog()
            sdnotify.status(f"cycle {self.cycles}: {stats.alerts} alerts, {stats.errors} errors" + (" · STORM" if self.storm.active else ""))
            try:
                checkpoint_shared_detector()                       # netops links + open incidents survive a restart
            except Exception as e:  # noqa: BLE001
                logger.warning("[service] netops checkpoint failed: %s", str(e)[:200])
            self._maybe_contribute()
            self._maybe_heartbeat_and_renew()                      # runs in a side thread; the loop keeps pinging the watchdog
            self.history.append(stats)
            del self.history[:-100]
            if stats.alerts or stats.errors or stats.redelivered or self.cycles % 60 == 1:
                logger.info("[service] cycle %d: %s%s", self.cycles, stats.line(),
                            f" deferred_dropped={self.storm.queue.dropped}" if getattr(self.storm.queue, "dropped", 0) else "")
            else:
                logger.debug("[service] cycle %d: %s", self.cycles, stats.line())
            if self.p.watchdog is not None:
                # pushed/streamed vendors are counted from the cumulative queue stats; then
                # evaluate every armed feed so a source gone quiet raises an alert this cycle
                try:
                    self.p.watchdog.sync_stream(stream.stats.by_source if stream is not None else {})
                    self.p.watchdog.sweep()
                except Exception as e:  # noqa: BLE001 — watchdog health must never take the SOC down
                    logger.warning("[service] feed watchdog sweep failed: %s", str(e)[:200])
            if hot_reload:
                # apply a human-approved promotion the moment `retrain sync` updates the pointer,
                # without waiting for a restart (vllm backend); cheap no-op when nothing changed
                try:
                    self.p.hot_reload_from_pointer()
                except Exception as e:  # noqa: BLE001 — a reload hiccup must never take the SOC down
                    logger.warning("[service] hot-reload check failed: %s", str(e)[:200])
            if once or (max_cycles and self.cycles >= max_cycles):
                break
            deadline = time.time() + self.interval
            while not self._stop and time.time() < deadline:
                remaining = deadline - time.time()
                # wake the moment a receiver queues something: pushed events get a verdict in
                # milliseconds instead of waiting for the next poll
                sdnotify.watchdog()
                if stream is not None and stream.enabled:
                    if stream.wait(min(1.0, remaining)):
                        self.storm.update(self.history[-1] if self.history else None)
                        st = run_cycle(self.p, alerts=_stream_alerts(self.p), max_alerts=self.max_alerts,
                                       sweep=False, hitl=False, storm=self.storm)
                        self.stream_cycles += 1
                        self.history.append(st)
                        del self.history[:-100]
                        logger.info("[service] stream pass %d: %s", self.stream_cycles, st.line())
                else:
                    time.sleep(min(1.0, remaining))
        if self.p.persist_sink is not None:
            self.p.persist_sink.flush()
        sdnotify.stopping()
        self.p.close()
        checkpoint_shared_detector(force=True)                 # final checkpoint on clean shutdown
        logger.info("[service] stopped after %d cycle(s), %d stream pass(es)", self.cycles, self.stream_cycles)
        return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--once", action="store_true", help="one cycle, then exit (smoke test)")
    ap.add_argument("--status", action="store_true", help="print the running service's health (from its receiver) and exit")
    ap.add_argument("--interval", type=float, default=float(os.environ.get("AEGIS_POLL_SECONDS", "60")))
    ap.add_argument("--max-alerts", type=int, default=int(os.environ.get("AEGIS_MAX_ALERTS_PER_CYCLE", "0")),
                    help="cap alerts handled per cycle (0 = all)")
    ap.add_argument("--audit", default=str(DEFAULT_AUDIT), help="append-only audit log path")
    ap.add_argument("--log-level", default=os.environ.get("AEGIS_LOG_LEVEL", "INFO"))
    args = ap.parse_args(argv)
    if args.status:
        return status_main(args.audit)
    logging.basicConfig(level=getattr(logging, str(args.log_level).upper(), logging.INFO),
                        format="%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)
    pipeline = build_pipeline(args.audit)
    if args.once:
        os.environ.setdefault("AEGIS_HEARTBEAT_INLINE", "1")        # a one-shot run must finish its heartbeat before exiting
    return Service(pipeline, interval=args.interval, max_alerts=args.max_alerts).run(once=args.once)


def status_main(audit: str) -> int:
    """``--status``: one screen for the operator — receiver health (incl. audit + checkpoint state), the audit chain's
    tail, deferred backlog — without touching the running service's state."""
    import json
    import urllib.request
    bind = os.environ.get("AEGIS_INGEST_BIND", "127.0.0.1:8787").strip()
    host, _, port = bind.rpartition(":")
    url = f"http://{'127.0.0.1' if host in ('', '0.0.0.0') else host}:{port or 8787}/healthz"
    ok = True
    try:
        with urllib.request.urlopen(url, timeout=5) as r:  # noqa: S310 — loopback
            h = json.loads(r.read())
            code = r.status
    except Exception as e:  # noqa: BLE001
        print(f"receiver   {url}: unreachable ({str(e)[:80]}) — service down or AEGIS_INGEST_HTTP off")
        h, code, ok = {}, 0, False
    if h:
        a = h.get("audit") or {}
        print(f"receiver   {url}: HTTP {code} · queue {h.get('queue', '?')} · received {h.get('received', '?')} · rejected_full {h.get('rejected_full', 0)}")
        print(f"audit      {'DEGRADED — ' + str(a.get('last_error')) if a.get('degraded') else 'writable'} · tail {a.get('tail', '?')}")
        if h.get("netops_checkpoint_age_s") is not None:
            print(f"netops     checkpoint {h['netops_checkpoint_age_s']}s old")
        lic = h.get("license") or {}
        if lic:
            print(f"licence    {lic.get('status')} · {lic.get('days_left')} days left")
        ok = ok and not h.get("degraded")
    p = Path(audit)
    if p.exists():
        from aegis.agents.shared.audit import AuditLog
        rep = AuditLog(p, repair=False).verify_report(all_files=False)
        print(f"chain      {p}: {'intact' if rep['ok'] else 'BROKEN at ' + str(rep['broken_at'])} · {rep['entries']} entries in the live segment")
        ok = ok and rep["ok"]
    from aegis.ops.deferred import default_spill
    spill = default_spill(p)
    n = spill.pending()
    if n:
        fb = spill.fallback.pending() if spill.fallback is not None else 0
        print(f"deferred   {n} alert(s) waiting (storm / audit backlog)" + (f", {fb} on the fallback {spill.fallback.path}" if fb else ""))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
