"""Observability — traces + metrics for the agentic layer itself.

Production: OpenTelemetry SDK exporting to a collector that ships to
the bank's observability stack (Honeycomb / Datadog / Tempo + Mimir).
Walking-skeleton: lightweight OTel-shaped wrappers that work even
when the OTel SDK isn't installed, so the demo runs offline. If the
SDK is present, real spans get emitted; otherwise we fall back to
zero-overhead stubs that still update internal counters.

Why bother: the AEGIS layer is itself a high-value workload. Auth
agent (#9 in the manifest) watches the workload identities of OTHER
agents — that detection requires metrics on what they're doing.
Without observability, the "self-monitoring" hardening in the plan is
text-only.

Counters exposed (Prometheus naming convention):
  - aegis_alerts_processed_total{specialist}
  - aegis_verdicts_total{verdict, specialist}
  - aegis_actions_proposed_total{action_type, hitl}
  - aegis_actions_hitl_queued_total
  - aegis_actions_executed_total
  - aegis_audit_integrity (gauge: 1=ok 0=fail)
  - aegis_token_budget_consumed_input
  - aegis_token_budget_consumed_output
  - aegis_token_budget_consumed_cost_cents

Spans:
  - aegis.orchestrator.handle  (per alert; tags: alert_id, verdict)
  - aegis.specialist.investigate  (per dispatch; tags: specialist, alert_id)
  - aegis.response.execute  (per chain; tags: actions_count, hitl_count)
"""
from __future__ import annotations

import contextlib
import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


_log = logging.getLogger("aegis.observability")


# ---- In-process metric registry --------------------------------------

@dataclass
class _MetricRegistry:
    counters: dict[tuple[str, frozenset], float] = field(default_factory=lambda: defaultdict(float))
    gauges: dict[tuple[str, frozenset], float] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def inc(self, name: str, value: float = 1.0, **labels: Any) -> None:
        key = (name, frozenset(labels.items()))
        with self._lock:
            self.counters[key] += value

    def set(self, name: str, value: float, **labels: Any) -> None:
        key = (name, frozenset(labels.items()))
        with self._lock:
            self.gauges[key] = value

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "counters": [
                    {"name": name, "labels": dict(lbls), "value": val}
                    for (name, lbls), val in self.counters.items()
                ],
                "gauges": [
                    {"name": name, "labels": dict(lbls), "value": val}
                    for (name, lbls), val in self.gauges.items()
                ],
            }

    def prometheus_text(self) -> str:
        """Render in Prometheus exposition format for scraping."""
        lines: list[str] = []
        seen_help: set[str] = set()
        with self._lock:
            for (name, lbls), val in sorted(self.counters.items()):
                if name not in seen_help:
                    lines.append(f"# TYPE {name} counter")
                    seen_help.add(name)
                lbl_str = ",".join(f'{k}="{v}"' for k, v in sorted(dict(lbls).items()))
                lines.append(f'{name}{{{lbl_str}}} {val}' if lbl_str else f"{name} {val}")
            for (name, lbls), val in sorted(self.gauges.items()):
                if name not in seen_help:
                    lines.append(f"# TYPE {name} gauge")
                    seen_help.add(name)
                lbl_str = ",".join(f'{k}="{v}"' for k, v in sorted(dict(lbls).items()))
                lines.append(f'{name}{{{lbl_str}}} {val}' if lbl_str else f"{name} {val}")
        return "\n".join(lines) + "\n"


METRICS = _MetricRegistry()


# ---- Span wrapper (OTel if available, else internal) ---------------

_OTEL_TRACER = None
try:
    from opentelemetry import trace as _otel_trace  # type: ignore
    _OTEL_TRACER = _otel_trace.get_tracer("aegis")
except ImportError:
    _OTEL_TRACER = None


@dataclass
class _SpanRecord:
    name: str
    started_at: float
    attributes: dict[str, Any] = field(default_factory=dict)
    duration_ms: float | None = None


_SPAN_LOG: list[_SpanRecord] = []
_SPAN_LOG_LOCK = threading.Lock()


@contextlib.contextmanager
def span(name: str, **attributes: Any):
    """Trace span; emits to OTel SDK if installed, else logs locally."""
    record = _SpanRecord(name=name, started_at=time.time(), attributes=dict(attributes))
    if _OTEL_TRACER is not None:
        with _OTEL_TRACER.start_as_current_span(name) as otel_span:
            for k, v in attributes.items():
                try:
                    otel_span.set_attribute(k, v)
                except Exception:  # noqa: BLE001, S110 — an unserialisable span attribute is dropped, the span is kept
                    pass
            try:
                yield record
            finally:
                record.duration_ms = (time.time() - record.started_at) * 1000.0
                with _SPAN_LOG_LOCK:
                    _SPAN_LOG.append(record)
        return
    try:
        yield record
    finally:
        record.duration_ms = (time.time() - record.started_at) * 1000.0
        with _SPAN_LOG_LOCK:
            _SPAN_LOG.append(record)


def recent_spans(limit: int = 50) -> list[_SpanRecord]:
    with _SPAN_LOG_LOCK:
        return list(_SPAN_LOG[-limit:])


# ---- Convenience helpers used by the agent layer ----------------------

def record_alert_processed(specialist: str) -> None:
    METRICS.inc("aegis_alerts_processed_total", specialist=specialist)


def record_verdict(verdict: str, specialist: str) -> None:
    METRICS.inc("aegis_verdicts_total", verdict=verdict, specialist=specialist)


def record_action_proposed(action_type: str, hitl: bool) -> None:
    METRICS.inc("aegis_actions_proposed_total",
                action_type=action_type, hitl=str(hitl).lower())


def record_action_hitl_queued() -> None:
    METRICS.inc("aegis_actions_hitl_queued_total")


def record_action_executed() -> None:
    METRICS.inc("aegis_actions_executed_total")


def record_audit_integrity(ok: bool) -> None:
    METRICS.set("aegis_audit_integrity", 1.0 if ok else 0.0)


def record_token_usage(*, input_tokens: int = 0, output_tokens: int = 0,
                      cost_cents: float = 0.0) -> None:
    if input_tokens:
        METRICS.inc("aegis_token_budget_consumed_input", value=float(input_tokens))
    if output_tokens:
        METRICS.inc("aegis_token_budget_consumed_output", value=float(output_tokens))
    if cost_cents:
        METRICS.inc("aegis_token_budget_consumed_cost_cents", value=float(cost_cents))


def dump_summary(stream=None) -> str:
    """Render a human-readable summary (used by main.py at end-of-run)."""
    snap = METRICS.snapshot()
    spans = recent_spans()
    lines: list[str] = ["[observability] metric snapshot"]
    lines.append(f"  counters: {len(snap['counters'])}")
    for c in sorted(snap["counters"], key=lambda x: -x["value"])[:15]:
        lbl_str = ",".join(f"{k}={v}" for k, v in c["labels"].items())
        lines.append(f"    {c['name']}{{{lbl_str}}} = {c['value']:.0f}")
    lines.append(f"  gauges: {len(snap['gauges'])}")
    for g in snap["gauges"]:
        lbl_str = ",".join(f"{k}={v}" for k, v in g["labels"].items())
        lines.append(f"    {g['name']}{{{lbl_str}}} = {g['value']}")
    lines.append(f"  recent spans: {len(spans)} (showing last 5)")
    for sp in spans[-5:]:
        attr_str = " ".join(f"{k}={v}" for k, v in sp.attributes.items())
        lines.append(f"    {sp.name}  {sp.duration_ms:.1f}ms  {attr_str}")
    text = "\n".join(lines)
    if stream is not None:
        print(text, file=stream)
    return text
