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
        return (f"[{self.edition}] LLM backend: {self.primary_name} ({self.primary_model})"
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
    audit = AuditLog(audit_path, sink=persist_sink)
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
    push_server = push_server_from_env(blocklist=lambda: connectors.active_receipts, audit_path=audit_path)
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
                 metrics_server=metrics_server)
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
        return (f"alerts={self.alerts} executed={self.executed} hitl_queued={self.hitl_queued} "
                f"decisions={self.decisions} rolled_back={self.rolled_back} errors={self.errors} "
                f"{self.seconds:.1f}s{lag} {v}".rstrip())


def _alerts_from_env(watchdog: Any = None) -> Iterator[dict]:
    from aegis.ingest import sources_from_env
    for name, it in sources_from_env():
        if watchdog is None:
            yield from it
        else:
            # attribute each polled alert to its ingest source for liveness; pushed/streamed
            # vendors are counted from StreamQueue.stats.by_source in the service loop instead
            for alert in it:
                watchdog.record(name)
                yield alert


def _stream_alerts(p: Pipeline) -> Iterator[dict]:
    """Only what the receivers have queued — the fast path between polls."""
    from aegis.ingest import AlertCheckpoint, StreamConsumer
    cp = AlertCheckpoint(Path(os.environ.get("AEGIS_CHECKPOINT", ".aegis-ingest.json")))
    yield from StreamConsumer(queue=p.stream, checkpoint=cp).iter_alerts()


def run_cycle(p: Pipeline, alerts: Iterator[dict] | None = None, *, max_alerts: int = 0,
              sweep: bool = True, hitl: bool = True) -> CycleStats:
    """One pass: new alerts → orchestrator → response; then HITL sync, TTL sweep, flush.
    ``hitl=False`` / ``sweep=False`` make the short stream-triggered pass between polls skip
    the dashboard round-trips; the interval cycle still does them."""
    stats = CycleStats()
    t0 = time.time()
    for alert in (alerts if alerts is not None else _alerts_from_env(p.watchdog)):
        if max_alerts and stats.alerts >= max_alerts:
            break
        stats.alerts += 1
        try:
            chain = p.orch.handle(alert)
            summary = p.response.execute(chain)
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
    if p.persist_sink is not None:
        p.persist_sink.flush()
    stats.seconds = time.time() - t0
    return stats


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

    def stop(self, *_: Any) -> None:
        self._stop = True

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
        while not self._stop:
            stats = run_cycle(self.p, max_alerts=self.max_alerts)
            self.cycles += 1
            self.history.append(stats)
            del self.history[:-100]
            logger.info("[service] cycle %d: %s", self.cycles, stats.line())
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
                if stream is not None and stream.enabled:
                    if stream.wait(min(1.0, remaining)):
                        st = run_cycle(self.p, alerts=_stream_alerts(self.p), max_alerts=self.max_alerts,
                                       sweep=False, hitl=False)
                        self.stream_cycles += 1
                        self.history.append(st)
                        del self.history[:-100]
                        logger.info("[service] stream pass %d: %s", self.stream_cycles, st.line())
                else:
                    time.sleep(min(1.0, remaining))
        if self.p.persist_sink is not None:
            self.p.persist_sink.flush()
        self.p.close()
        logger.info("[service] stopped after %d cycle(s), %d stream pass(es)", self.cycles, self.stream_cycles)
        return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--once", action="store_true", help="one cycle, then exit (smoke test)")
    ap.add_argument("--interval", type=float, default=float(os.environ.get("AEGIS_POLL_SECONDS", "60")))
    ap.add_argument("--max-alerts", type=int, default=int(os.environ.get("AEGIS_MAX_ALERTS_PER_CYCLE", "0")),
                    help="cap alerts handled per cycle (0 = all)")
    ap.add_argument("--audit", default=str(DEFAULT_AUDIT), help="append-only audit log path")
    ap.add_argument("--log-level", default=os.environ.get("AEGIS_LOG_LEVEL", "INFO"))
    args = ap.parse_args(argv)
    logging.basicConfig(level=getattr(logging, str(args.log_level).upper(), logging.INFO),
                        format="%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)
    pipeline = build_pipeline(args.audit)
    return Service(pipeline, interval=args.interval, max_alerts=args.max_alerts).run(once=args.once)


if __name__ == "__main__":
    sys.exit(main())
