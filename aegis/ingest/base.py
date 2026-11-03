"""Shared consumer plumbing: checkpoints, de-duplication, severity mapping."""

from __future__ import annotations

import gzip
import json
import logging
import os
import re
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


def _feed_family(source: Any) -> str:
    """The feed a pushed record came through (``edr``, ``cloudflare``, ``waf``, ``alerts`` …), not the free-text
    ``?source=`` / ``?collector=`` suffix: two HA relays (``edr-relay-a`` / ``edr-relay-b``) carrying the same
    alert are one feed, and a sender varying the suffix must not create a dedupe bucket per name (round 5 Y5-12)."""
    m = re.match(r"[a-z]+", str(source or "").strip().lower())
    return m.group(0)[:32] if m else ""


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

    MAX_BUCKETS = 64

    def _lru(self, key: str) -> OrderedDict[str, None]:
        # every pushed feed is consumed as "stream": its LRU is per pushed source (stream:<ingest_source>:id), so a
        # WAF flood cannot evict an EDR alert's id (review round 4 I4-9)
        parts = key.split(":", 2)
        src = (f"{parts[0]}:{parts[1]}" if parts[0] == "stream" and len(parts) == 3 else parts[0]) if ":" in key else ""
        lru = self._seen.get(src)
        if lru is None:
            if len(self._seen) >= self.MAX_BUCKETS:
                # bounded: a sender varying ?source= cannot grow the checkpoint without limit (round 5 Y5-12)
                src = "overflow"
                lru = self._seen.get(src)
                if lru is not None:
                    return lru
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

    def _read_inflight(self, p: Path) -> dict:
        try:
            st = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
        except (OSError, ValueError):
            return {}
        if not isinstance(st, dict):
            return {}
        if "key" in st and "attempts" in st and not isinstance(st.get("attempts"), dict):   # the round-3 format
            st = {"current": st.get("key"), "attempts": {str(st.get("key")): int(st.get("attempts") or 0)}}
        att = st.get("attempts")
        st["attempts"] = {str(k): int(v) for k, v in att.items() if isinstance(v, (int, float))} \
            if isinstance(att, dict) else {}
        return st

    def begin(self, key: str, alert: Any = None) -> bool:
        """About to hand ``key`` to the caller. False when it has crashed the process too often: skip it (and set it
        aside in the dead-letter file). Attempts are kept per key for the last few alerts begun: with one key, any
        other alert begun first after a restart reset the crasher's count, so it never reached the limit, and a
        skipped alert's body was lost (review round 4 I4-6 / X4-10)."""
        p = self._inflight_path()
        if p is None:
            return True
        st = self._read_inflight(p)
        attempts = st["attempts"].get(key, 0)
        try:
            limit = int(os.environ.get("AEGIS_INGEST_POISON_MAX", "3") or 3)
        except ValueError:
            limit = 3
        if attempts >= limit:
            logger.error("[ingest] %s did not finish in %d attempts (each one ended the process) — skipped and set "
                         "aside in the dead-letter file", key, attempts)
            if alert is not None:
                from ..ops import dead_letter
                dead_letter.write(alert, f"ended the process {attempts} times while being handled (poison alert)")
            self.mark(key)
            st["attempts"].pop(key, None)
            self._write_inflight(p, {"current": None, "attempts": st["attempts"]})
            return False
        st["attempts"][key] = attempts + 1
        while len(st["attempts"]) > 64:                   # bounded: the oldest unfinished keys fall off
            st["attempts"].pop(next(iter(st["attempts"])))
        self._write_inflight(p, {"current": key, "attempts": st["attempts"]})
        return True

    def _write_inflight(self, p: Path, st: dict) -> None:
        try:
            if not st.get("attempts") and not st.get("current"):
                p.unlink(missing_ok=True)
                return
            tmp = p.with_name(p.name + ".tmp")
            tmp.write_text(json.dumps(st), encoding="utf-8")
            tmp.replace(p)
        except OSError:
            pass

    def done(self) -> None:
        """The alert in hand finished (or the caller stopped cleanly): it is not a crasher."""
        p = self._inflight_path()
        if p is None or not p.exists():
            return
        st = self._read_inflight(p)
        cur = st.get("current")
        if cur is not None:
            st["attempts"].pop(str(cur), None)
        self._write_inflight(p, {"current": None, "attempts": st["attempts"]})

    # ---- file sources (review round 4 I4-3) -----------------------------------------------------------------------
    # WAF / API-gateway / NDR / netops exports were re-read from the start every cycle: every record went through the
    # stateful detectors again and only the per-source id LRU kept old alerts out — past its size, nothing did.
    def tail_lines(self, path: str | Path) -> Iterator[str]:
        """Complete lines appended to ``path`` since the last cycle. A rotated or truncated file starts over; a
        ``.gz`` export is read whole only when it changed. The offset moves past a line only when the caller asks
        for the next one (at-least-once, like ``mark``)."""
        p = Path(path)
        try:
            st = p.stat()
        except OSError:
            return
        key = str(p.resolve())
        with self._lock:
            files = self._state.setdefault("files", {})
            prev = files.get(key) if isinstance(files.get(key), dict) else {}
        if p.suffix == ".gz":
            sig = [st.st_ino, st.st_size, int(st.st_mtime)]
            if prev.get("sig") == sig:
                return
            with gzip.open(p, "rt", encoding="utf-8", errors="replace") as fh:
                yield from fh
            with self._lock:
                self._state.setdefault("files", {})[key] = {"sig": sig}
                self._dirty += 1
                self._maybe_flush()
            return
        with p.open("rb") as fh:
            prev_head = str(prev.get("head") or "")
            # same file (inode), not shorter, and the same first bytes — a file rewritten in place starts over
            same = (prev.get("ino") == st.st_ino and int(prev.get("off") or 0) <= st.st_size
                    and fh.read(len(prev_head) // 2).hex() == prev_head)
            off = int(prev.get("off") or 0) if same else 0
            fh.seek(0)
            head = fh.read(64).hex()
            fh.seek(off)
            while True:
                raw = fh.readline()
                if not raw or not raw.endswith(b"\n"):
                    break                                   # a line still being written: next cycle
                yield raw.decode("utf-8", "replace")
                off += len(raw)
                with self._lock:
                    self._state.setdefault("files", {})[key] = {"ino": st.st_ino, "off": off,
                                                                "head": head[:2 * min(64, off)]}
                    self._dirty += 1
                    self._maybe_flush()

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
                src = _feed_family(one.get("ingest_source")) if self.name == "stream" else ""
                key = f"{self.name}:{src}:{one['id']}" if src else f"{self.name}:{one['id']}"
                if self.checkpoint.seen(key):
                    self.skipped_duplicates += 1
                    continue
                begin = getattr(self.checkpoint, "begin", None)
                if callable(begin) and not begin(key, one):
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
