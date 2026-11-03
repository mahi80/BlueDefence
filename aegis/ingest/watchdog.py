"""Feed-liveness watchdog — turn a silent ingest feed into an alert.

A push feed that dies looks exactly like "no attacks": AEGIS receives nothing and
notices nothing. A SOC must not sit blind because a Cloudflare Logpush job stopped,
a syslog relay fell over or a Sentinel poll started returning empty. This watchdog
tracks, per source, *when AEGIS last saw an event*, and raises an alert when a source
that was producing goes quiet past its expected window — then clears it when the feed
recovers.

It is opt-in (``AEGIS_FEED_WATCHDOG=1``) and reads only counters the ingest layer
already emits: ``StreamQueue.stats.by_source`` for pushed/streamed vendors, and the
poll path records each alert as it is yielded. Nothing here touches the orchestrator
or the LLM — it is pure plumbing health, so a dead feed pages someone instead of
hiding as silence.

Two ways a source is watched:
  * **armed on first event** (default) — once a source has produced one event it is
    expected to keep producing; this is the "it was alive, now it's silent" detector.
  * **expected from boot** (``AEGIS_FEED_EXPECT``) — armed before any event, so a feed
    that never connects at all is caught too, after a boot grace period.

Env:
    AEGIS_FEED_WATCHDOG=1               enable (default off)
    AEGIS_FEED_SILENCE_SECONDS=900      default silence window before a feed is "silent"
    AEGIS_FEED_SILENCE_<SOURCE>=600     per-source override (SOURCE upper-cased, '-'→'_')
    AEGIS_FEED_EXPECT=sentinel,cloudflare   arm these from boot (catch "never connected")
    AEGIS_FEED_BOOT_GRACE_SECONDS=1800  grace before a boot-armed, never-seen source alarms
                                        (default = that source's silence window)

Metrics (shared METRICS registry, scraped on /metrics):
    aegis_feed_events_total{source}            counter — events attributed to the source
    aegis_feed_last_event_age_seconds{source}  gauge   — seconds since its last event
    aegis_feed_silent{source}                  gauge   — 1 silent, 0 live
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

try:
    from aegis.agents.shared.observability import METRICS
except Exception:  # noqa: BLE001 — observability is optional plumbing; the watchdog still works without metrics
    METRICS = None  # type: ignore

logger = logging.getLogger("aegis.ingest.watchdog")

#: sources that are drain placeholders / demo, never liveness-watched
_MAX_FEEDS = 256                    # distinct feed names watched; the rest fold into "other"
_IGNORED_SOURCES = frozenset({"stream", "sample"})

DEFAULT_SILENCE_SECONDS = 900.0


@dataclass
class FeedAlert:
    """Emitted on a liveness transition. ``state`` is 'silent' or 'recovered'."""

    source: str
    state: str
    age_seconds: float
    silence_window: float
    last_event_at: Optional[float]
    at: float

    def line(self) -> str:
        if self.state == "silent":
            seen = "never seen" if not self.last_event_at else f"{self.age_seconds:.0f}s since last event"
            return (f"feed '{self.source}' SILENT — {seen} "
                    f"(window {self.silence_window:.0f}s); a dead feed is not 'no attacks'")
        return f"feed '{self.source}' recovered after {self.age_seconds:.0f}s silent"


def _metric_inc(name: str, value: float = 1.0, **labels: Any) -> None:
    if METRICS is not None:
        try:
            METRICS.inc(name, value=value, **labels)
        except Exception:  # noqa: BLE001 — a metrics backend hiccup must never break ingestion
            pass


def _metric_set(name: str, value: float, **labels: Any) -> None:
    if METRICS is not None:
        try:
            METRICS.set(name, value, **labels)
        except Exception:  # noqa: BLE001
            pass


def _default_on_alert(alert: FeedAlert) -> None:
    if alert.state == "silent":
        logger.error("[ingest:watchdog] %s", alert.line())
    else:
        logger.info("[ingest:watchdog] %s", alert.line())


class FeedWatchdog:
    """Per-source liveness tracker. Thread-unsafe by design — driven from the single
    service loop (``record`` on the poll path, ``sync_stream`` + ``sweep`` per interval)."""

    def __init__(self, *, default_silence_s: float = DEFAULT_SILENCE_SECONDS,
                 per_source: Optional[dict[str, float]] = None, expect: Iterable[str] = (),
                 boot_grace_s: Optional[float] = None,
                 clock: Callable[[], float] = time.time,
                 on_alert: Optional[Callable[[FeedAlert], None]] = None):
        self.default_silence_s = float(default_silence_s)
        self.per_source = {str(k).lower(): float(v) for k, v in (per_source or {}).items()}
        self.boot_grace_s = float(boot_grace_s) if boot_grace_s is not None else None
        self._clock = clock
        self._on_alert = on_alert or _default_on_alert
        self._started_at = clock()

        self._count: dict[str, int] = {}
        self._last_event_at: dict[str, float] = {}
        self._armed: set[str] = set()
        self._boot_armed: set[str] = set()
        self._silent: set[str] = set()
        self._stream_seen: dict[str, int] = {}          # last cumulative by_source snapshot
        self.history: list[FeedAlert] = []

        for s in expect:
            s = str(s).strip().lower()
            if s and s not in _IGNORED_SOURCES:
                self._armed.add(s)
                self._boot_armed.add(s)
                _metric_set("aegis_feed_silent", 0.0, source=s)

    # -- window selection
    def window_for(self, source: str) -> float:
        return self.per_source.get(source, self.default_silence_s)

    def _effective_window(self, source: str) -> float:
        """A boot-armed source that has never produced an event gets a longer first window
        (boot grace) so start-up ordering doesn't trip a false silent."""
        window = self.window_for(source)
        if source in self._boot_armed and source not in self._last_event_at:
            grace = self.boot_grace_s if self.boot_grace_s is not None else window
            return max(window, grace)
        return window

    def _reference(self, source: str) -> float:
        """The instant silence is measured from: last event, or boot for a never-seen feed."""
        return self._last_event_at.get(source, self._started_at)

    # -- event attribution
    def record(self, source: str, n: int = 1, *, now: Optional[float] = None) -> None:
        """Attribute ``n`` events to ``source`` (poll path: one alert at a time)."""
        source = str(source).strip().lower()
        if not source or source in _IGNORED_SOURCES or n <= 0:
            return
        now = self._clock() if now is None else now
        if source not in self._count and len(self._count) >= _MAX_FEEDS and not self._make_room(now):
            # feed names come from free-text ?source= / headers; an unbounded set of armed feeds would each
            # later page "SILENT" and grow memory and metric cardinality without limit
            source = "other"
        self._count[source] = self._count.get(source, 0) + n
        self._last_event_at[source] = now
        self._armed.add(source)
        _metric_inc("aegis_feed_events_total", value=float(n), source=source)
        _metric_set("aegis_feed_last_event_age_seconds", 0.0, source=source)
        if source in self._silent:
            self._recover(source, now)

    def _make_room(self, now: float) -> bool:
        """Forget the feed idle longest (over a day) that the operator did not configure, so a real feed first
        seen after 256 junk names is still watched (review round 3 R3-15). Configured and expected feeds stay."""
        keep = set(self.per_source) | self._boot_armed | {"other"}
        cand = [s for s in self._count if s not in keep and now - self._last_event_at.get(s, 0.0) > 86400]
        if not cand:
            return False
        old = min(cand, key=lambda s: self._last_event_at.get(s, 0.0))
        for d in (self._count, self._last_event_at, self._stream_seen):
            d.pop(old, None)
        self._armed.discard(old)
        self._silent.discard(old)
        return True

    def sync_stream(self, by_source: dict[str, int], *, now: Optional[float] = None) -> None:
        """Attribute pushed/streamed events from the cumulative ``StreamQueue.stats.by_source``.
        Diffs against the previous snapshot so only *new* events count as liveness."""
        now = self._clock() if now is None else now
        for source, total in (by_source or {}).items():
            src = str(source).strip().lower()
            if src in _IGNORED_SOURCES:
                continue
            if src not in self._stream_seen and len(self._stream_seen) >= _MAX_FEEDS and not self._make_room(now):
                continue
            prev = self._stream_seen.get(src, 0)
            # a name the stream expired and saw again restarts its count: a smaller total is a reset, not nothing
            delta = int(total) - prev if int(total) >= prev else int(total)
            if delta > 0:
                self.record(src, delta, now=now)
            self._stream_seen[src] = int(total)

    # -- periodic evaluation
    def sweep(self, *, now: Optional[float] = None) -> list[FeedAlert]:
        """Evaluate every armed source; emit on new silence. Returns alerts fired this sweep."""
        now = self._clock() if now is None else now
        fired: list[FeedAlert] = []
        for source in sorted(self._armed):
            age = now - self._reference(source)
            _metric_set("aegis_feed_last_event_age_seconds", max(0.0, age), source=source)
            if source in self._silent:
                continue
            if age > self._effective_window(source):
                fired.append(self._go_silent(source, age, now))
        return fired

    def _go_silent(self, source: str, age: float, now: float) -> FeedAlert:
        self._silent.add(source)
        _metric_set("aegis_feed_silent", 1.0, source=source)
        alert = FeedAlert(source=source, state="silent", age_seconds=age,
                          silence_window=self._effective_window(source),
                          last_event_at=self._last_event_at.get(source), at=now)
        self._emit(alert)
        return alert

    def _recover(self, source: str, now: float) -> FeedAlert:
        age = now - self._reference(source)
        self._silent.discard(source)
        _metric_set("aegis_feed_silent", 0.0, source=source)
        alert = FeedAlert(source=source, state="recovered", age_seconds=age,
                          silence_window=self._effective_window(source),
                          last_event_at=self._last_event_at.get(source), at=now)
        self._emit(alert)
        return alert

    def _emit(self, alert: FeedAlert) -> None:
        self.history.append(alert)
        del self.history[:-200]
        try:
            self._on_alert(alert)
        except Exception as e:  # noqa: BLE001 — a bad alert sink must not break the loop
            logger.warning("[ingest:watchdog] on_alert failed: %s", str(e)[:160])

    # -- introspection (for /healthz, tests)
    def status(self, *, now: Optional[float] = None) -> dict:
        now = self._clock() if now is None else now
        feeds = []
        for source in sorted(self._armed):
            feeds.append({
                "source": source,
                "events": self._count.get(source, 0),
                "age_seconds": round(now - self._reference(source), 1),
                "window_seconds": self._effective_window(source),
                "silent": source in self._silent,
                "ever_seen": source in self._last_event_at,
            })
        return {"enabled": True, "silent_count": len(self._silent), "feeds": feeds}


def _parse_per_source(environ: dict[str, str]) -> dict[str, float]:
    """``AEGIS_FEED_SILENCE_<SOURCE>`` → {source: seconds}; ``AEGIS_FEED_SILENCE_SECONDS`` is the
    global default and is *not* a per-source entry."""
    out: dict[str, float] = {}
    for key, val in environ.items():
        if not key.startswith("AEGIS_FEED_SILENCE_") or key == "AEGIS_FEED_SILENCE_SECONDS":
            continue
        source = key[len("AEGIS_FEED_SILENCE_"):].strip().lower().replace("_", "-")
        if not source:
            continue
        try:
            out[source] = float(val)
        except (TypeError, ValueError):
            logger.warning("[ingest:watchdog] %s=%r is not a number; ignored", key, val)
    return out


def feed_watchdog_from_env(*, clock: Callable[[], float] = time.time,
                           on_alert: Optional[Callable[[FeedAlert], None]] = None,
                           environ: Optional[dict[str, str]] = None) -> Optional[FeedWatchdog]:
    """Build the watchdog when ``AEGIS_FEED_WATCHDOG`` is truthy, else ``None``."""
    env = dict(os.environ if environ is None else environ)
    if env.get("AEGIS_FEED_WATCHDOG", "").strip().lower() not in {"1", "true", "yes", "on"}:
        return None
    try:
        default_s = float(env.get("AEGIS_FEED_SILENCE_SECONDS", str(DEFAULT_SILENCE_SECONDS)))
    except (TypeError, ValueError):
        default_s = DEFAULT_SILENCE_SECONDS
    boot_grace: Optional[float] = None
    if env.get("AEGIS_FEED_BOOT_GRACE_SECONDS", "").strip():
        try:
            boot_grace = float(env["AEGIS_FEED_BOOT_GRACE_SECONDS"])
        except (TypeError, ValueError):
            boot_grace = None
    expect = [s.strip().lower() for s in env.get("AEGIS_FEED_EXPECT", "").split(",") if s.strip()]
    wd = FeedWatchdog(default_silence_s=default_s, per_source=_parse_per_source(env),
                      expect=expect, boot_grace_s=boot_grace, clock=clock, on_alert=on_alert)
    logger.info("[ingest:watchdog] on — default silence %.0fs, %d per-source override(s), expect-from-boot: %s",
                default_s, len(wd.per_source), ",".join(expect) or "(none)")
    return wd


__all__ = ["FeedWatchdog", "FeedAlert", "feed_watchdog_from_env", "DEFAULT_SILENCE_SECONDS"]
