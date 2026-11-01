"""Shared consumer plumbing: checkpoints, de-duplication, severity mapping."""

from __future__ import annotations

import json
import logging
import time
import threading
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
        self._seen: "OrderedDict[str, None]" = OrderedDict()
        if self.path and self.path.exists():
            try:
                self._state = json.loads(self.path.read_text(encoding="utf-8"))
                for k in self._state.get("seen", [])[-max_ids:]:
                    self._seen[k] = None
            except Exception as e:  # noqa: BLE001 — a corrupt checkpoint just means a clean start
                logger.warning("[ingest] checkpoint %s unreadable (%s); starting fresh", self.path, e)
                self._state = {"watermark": {}, "seen": []}

    def watermark(self, source: str) -> Optional[str]:
        return self._state.get("watermark", {}).get(source)

    def advance(self, source: str, value: str) -> None:
        with self._lock:
            cur = self._state.setdefault("watermark", {}).get(source)
            if cur is None or value > cur:
                self._state["watermark"][source] = value
            self._flush()

    def seen(self, key: str) -> bool:
        with self._lock:
            return key in self._seen

    def mark(self, key: str) -> bool:
        """Record ``key``; returns False when it was already seen."""
        with self._lock:
            if key in self._seen:
                return False
            self._seen[key] = None
            while len(self._seen) > self.max_ids:
                self._seen.popitem(last=False)
            self._state["seen"] = list(self._seen.keys())
            self._flush()
            return True

    def _flush(self) -> None:
        if not self.path:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(json.dumps(self._state), encoding="utf-8")
            tmp.replace(self.path)
        except Exception as e:  # noqa: BLE001
            logger.warning("[ingest] checkpoint write failed: %s", e)


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
                if not self.checkpoint.mark(key):
                    self.skipped_duplicates += 1
                    continue
                ts = one.get("timestamp")
                if ts:
                    self.checkpoint.advance(self.name, str(ts))
                self.yielded += 1
                yield one

    @property
    def stats(self) -> dict:
        return {"source": self.name, "yielded": self.yielded,
                "duplicates": self.skipped_duplicates, "invalid": self.skipped_invalid}
