"""Shared consumer plumbing: checkpoints, de-duplication, severity mapping."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, Iterator, Optional

logger = logging.getLogger("aegis.ingest")

_SEVERITY_SCORE = {
    "informational": 0.1, "info": 0.1, "low": 0.3, "medium": 0.6, "moderate": 0.6,
    "high": 0.85, "critical": 0.95, "severe": 0.95,
}
_SEVERITY_NORMAL = {
    "informational": "low", "info": "low", "low": "low", "medium": "medium", "moderate": "medium",
    "high": "high", "critical": "critical", "severe": "critical",
    # F5 ASM / syslog levels
    "emergency": "critical", "alert": "critical", "error": "high", "warning": "medium", "notice": "low",
    "debug": "low",
}


def normalize_severity(raw: Any) -> str:
    """Vendor severities (words, 0-10 CEF numbers, 1-5 F5 levels) → low|medium|high|critical."""
    if raw is None:
        return "medium"
    s = str(raw).strip().lower()
    if s in _SEVERITY_NORMAL:
        return _SEVERITY_NORMAL[s]
    try:
        n = float(s)
    except ValueError:
        return "medium"
    if n <= 3:
        return "low"
    if n <= 6:
        return "medium"
    if n <= 8:
        return "high"
    return "critical"


def severity_to_score(raw: Any) -> float:
    return _SEVERITY_SCORE.get(normalize_severity(raw), 0.6)


class AlertCheckpoint:
    """Per-source watermark + recently-seen ids, persisted to a small JSON file.

    Keeps a bounded LRU of ids so an at-least-once source (Sentinel polling
    windows overlap on purpose; syslog replays) never yields the same alert
    twice to the orchestrator.
    """

    def __init__(self, path: Optional[Path] = None, *, max_ids: int = 5000):
        self.path = Path(path) if path else None
        self.max_ids = max_ids
        self._lock = threading.Lock()
        self._state: dict[str, Any] = {"watermark": {}, "seen": []}
        # one LRU per source: a single shared LRU let a noisy feed evict a quiet feed's ids, which were then
        # re-delivered as new (review round 3 G4-6)
        self._seen: dict[str, OrderedDict[str, None]] = {}
        self._dirty = 0
        self._last_flush = time.monotonic()
        try:
            self.flush_s = float(os.environ.get("AEGIS_CHECKPOINT_FLUSH_S", "1") or 1)
        except ValueError:
            self.flush_s = 1.0
        if self.path and self.path.exists():
            try:
                self._state = json.loads(self.path.read_text(encoding="utf-8"))
                for k in self._state.get("seen", []):
                    self._lru(k)[k] = None
                for lru in self._seen.values():
                    while len(lru) > self.max_ids:
                        lru.popitem(last=False)
            except Exception as e:  # noqa: BLE001 — a corrupt checkpoint just means a clean start
                logger.warning("[ingest] checkpoint %s unreadable (%s); starting fresh", self.path, e)
                self._state = {"watermark": {}, "seen": []}
                self._seen = {}

    def _lru(self, key: str) -> OrderedDict[str, None]:
        src = key.split(":", 1)[0] if ":" in key else ""
        lru = self._seen.get(src)
        if lru is None:
            lru = self._seen[src] = OrderedDict()
        return lru

    def watermark(self, source: str) -> Optional[str]:
        return self._state.get("watermark", {}).get(source)

    def advance(self, source: str, value: str) -> None:
        with self._lock:
            cur = self._state.setdefault("watermark", {}).get(source)
            if cur is None or _later(value, cur):
                self._state["watermark"][source] = value
                self._dirty += 1
            self._maybe_flush()

    def seen(self, key: str) -> bool:
        with self._lock:
            return key in self._lru(key)

    def mark(self, key: str) -> bool:
        """Record ``key``; returns False when it was already seen."""
        with self._lock:
            lru = self._lru(key)
            if key in lru:
                return False
            lru[key] = None
            while len(lru) > self.max_ids:
                lru.popitem(last=False)
            self._dirty += 1
            self._maybe_flush()
            return True

    # ---- crash loops (review round 3 G4-13) -------------------------------------------------------------------
    # Ingest is at-least-once: an alert is marked seen only after it was handled. An alert that CRASHES the
    # process is therefore re-delivered on every restart, forever, and stateful detectors count it again each
    # time. A tiny side file names the alert being handled; after AEGIS_INGEST_POISON_MAX starts that never
    # finished, it is skipped and set aside.
    def _inflight_path(self) -> Path | None:
        return self.path.with_name(self.path.name + ".inflight") if self.path else None

    def begin(self, key: str) -> bool:
        """About to hand ``key`` to the caller. False when it has crashed the process too often: skip it."""
        p = self._inflight_path()
        if p is None:
            return True
        attempts = 0
        try:
            prev = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
            if prev.get("key") == key:
                attempts = int(prev.get("attempts") or 0)
        except (OSError, ValueError):
            attempts = 0
        try:
            limit = int(os.environ.get("AEGIS_INGEST_POISON_MAX", "3") or 3)
        except ValueError:
            limit = 3
        if attempts >= limit:
            logger.error("[ingest] %s did not finish in %d attempts (each one ended the process) — skipped; "
                         "re-send it once the cause is fixed", key, attempts)
            self.mark(key)
            self.done()
            return False
        try:
            p.write_text(json.dumps({"key": key, "attempts": attempts + 1}), encoding="utf-8")
        except OSError:
            pass
        return True

    def done(self) -> None:
        p = self._inflight_path()
        if p is not None:
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass

    def flush(self) -> None:
        """Write the checkpoint now (end of a batch, shutdown)."""
        with self._lock:
            if self._dirty:
                self._flush()

    def _maybe_flush(self) -> None:
        # The whole state was re-serialised and renamed into place twice per alert — a ~290 alerts/s ceiling on
        # ingest (review round 3 G4-6). Now at most every AEGIS_CHECKPOINT_FLUSH_S (1 s) or 500 changes, and at
        # the end of every consumer pass. A crash re-delivers at most that much (ingest is at-least-once).
        if self._dirty >= 500 or time.monotonic() - self._last_flush >= self.flush_s:
            self._flush()

    def _flush(self) -> None:
        self._state["seen"] = [k for lru in self._seen.values() for k in lru]
        self._dirty = 0
        self._last_flush = time.monotonic()
        if not self.path:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(json.dumps(self._state), encoding="utf-8")
            tmp.replace(self.path)
        except Exception as e:  # noqa: BLE001
            logger.warning("[ingest] checkpoint write failed: %s", e)


def _when(v: str) -> float | None:
    s = str(v).strip()
    try:
        f = float(s)
        return f / 1000.0 if f > 1e11 else f
    except ValueError:
        pass
    try:
        from datetime import UTC, datetime
        d = datetime.fromisoformat(s)
        return (d if d.tzinfo else d.replace(tzinfo=UTC)).timestamp()
    except ValueError:
        return None


def _later(a: str, b: str) -> bool:
    """Is watermark ``a`` after ``b``? Compared as times when both parse: as strings, epoch "999" sorted after
    "1000" and "+05:30" times against "Z" ones, so the watermark could move backwards or stick (review round 3
    I3-15)."""
    ta, tb = _when(a), _when(b)
    if ta is not None and tb is not None:
        return ta > tb
    return str(a) > str(b)


#: returned by ``normalize`` when a record was consumed but produced no alert *yet* (a stateful
#: detector below its threshold) — not counted as invalid
CONSUMED: dict = {}


class BaseConsumer:
    """Common loop: fetch raw records → normalize → dedupe → yield."""

    name = "base"

    def __init__(self, checkpoint: Optional[AlertCheckpoint] = None):
        self.checkpoint = checkpoint or AlertCheckpoint()
        self.yielded = 0
        self.skipped_duplicates = 0
        self.skipped_invalid = 0

    # subclasses implement
    def fetch(self, **kwargs) -> Iterator[Any]:
        raise NotImplementedError

    def normalize(self, record: Any) -> Optional[dict]:
        raise NotImplementedError

    # a poisoned feed must not turn into a million WARNING lines: the first few per minute are logged,
    # the rest are counted and summarised when the window rolls over
    _DROP_LOG_BURST = 5

    def _drop_log(self, why: str) -> None:
        now = time.time()
        win = getattr(self, "_drop_win", 0.0)
        if now - win >= 60:
            n = getattr(self, "_drop_suppressed", 0)
            if n:
                logger.warning("[ingest:%s] %d more records dropped in the last minute (same cause)", self.name, n)
            self._drop_win, self._drop_n, self._drop_suppressed = now, 0, 0
        self._drop_n = getattr(self, "_drop_n", 0) + 1
        if self._drop_n <= self._DROP_LOG_BURST:
            logger.warning("[ingest:%s] record dropped: %s", self.name, why)
        else:
            self._drop_suppressed = getattr(self, "_drop_suppressed", 0) + 1

    def iter_alerts(self, **kwargs) -> Iterator[dict]:
        try:
            yield from self._iter_alerts(**kwargs)
        finally:
            # closed or finished normally (a caller stopping at max_alerts, a shutdown): not a crash, so the
            # alert in hand is not counted as one that killed the process
            for name in ("done", "flush"):
                fn = getattr(self.checkpoint, name, None)
                if callable(fn):
                    fn()

    def _iter_alerts(self, **kwargs) -> Iterator[dict]:
        for record in self.fetch(**kwargs):
            try:
                alert = self.normalize(record)
            except Exception as e:  # noqa: BLE001 — one bad record must not stop the stream
                self.skipped_invalid += 1
                self._drop_log(str(e)[:160])
                continue
            if alert is CONSUMED:
                continue
            # a stateful detector (object walk, NDR egress) may emit several findings for one
            # event, or none: a list is yielded item by item, an empty list is "consumed"
            for one in (alert if isinstance(alert, list) else [alert]):
                if not one or not one.get("id"):
                    self.skipped_invalid += 1
                    continue
                key = f"{self.name}:{one['id']}"
                if self.checkpoint.seen(key):
                    self.skipped_duplicates += 1
                    continue
                begin = getattr(self.checkpoint, "begin", None)
                if callable(begin) and not begin(key):
                    self.skipped_invalid += 1
                    continue
                self.yielded += 1
                yield one
                # Marked only once the caller asks for the next alert, i.e. after it handled this one. Marking before
                # the yield made ingest at-most-once: a crash mid-handling, or a caller stopping at max_alerts with
                # the alert already fetched, lost it for good (code review 2026-11-03 E15). Now at-least-once; the
                # audit / HITL layers already dedupe on the alert id.
                self.checkpoint.mark(key)
                done = getattr(self.checkpoint, "done", None)
                if callable(done):
                    done()
                ts = one.get("timestamp")
                if ts:
                    self.checkpoint.advance(self.name, str(ts))

    @property
    def stats(self) -> dict:
        return {"source": self.name, "yielded": self.yielded,
                "duplicates": self.skipped_duplicates, "invalid": self.skipped_invalid}
