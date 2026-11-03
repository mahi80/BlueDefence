"""Storm-mode deferred queue: a bounded, append-only JSONL spill file for alerts that need the model while the
loop is saturated (and, since review round 2, for alerts whose evidence could not be written). Fast paths keep
running; nothing is dropped silently — deferred alerts are re-fed to the pipeline in bounded batches once the
storm drains, oldest first, with ``deferred_at`` / ``deferred_by`` stamped on.

Delivery is at-least-once: ``pop(n)`` hands out a batch, the caller processes it and then calls ``ack()``;
only ``ack`` moves the on-disk cursor, so a crash between the two re-delivers the batch (dedupe is on the
alert id downstream). A torn last line (crash mid-append) is cut off at open so the next ``push`` cannot merge
with it; the fragment is logged and counted in ``dropped``.
"""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

logger = logging.getLogger("aegis.ops.deferred")


class DeferredQueue:
    def __init__(self, path: Path | str, *, max_bytes: int = 512 * 1024 * 1024):
        self.path = Path(path)
        self.max_bytes = max_bytes
        self._read_pos = 0           # committed (acked) position
        self._inflight_pos = 0       # position after the last pop, committed by ack()
        self.dropped = 0
        self.path.parent.mkdir(parents=True, exist_ok=True)
        cur = self._cursor_path()
        try:
            self._read_pos = int(cur.read_text().strip())
            # A cursor with no spill file (a crash between ack()'s two unlinks, an operator deleting the file)
            # or past its end is stale: honouring it hid every newly parked alert until the file outgrew it.
            if not self.path.exists() or self._read_pos > self.path.stat().st_size:
                if self._read_pos:
                    logger.warning("[deferred] stale cursor %d for %s (file %s) — starting from the beginning",
                                   self._read_pos, self.path, "missing" if not self.path.exists() else "shorter")
                self._read_pos = 0
                cur.unlink(missing_ok=True)
        except (OSError, ValueError):
            self._read_pos = 0
        self._inflight_pos = self._read_pos
        self._trim_torn_tail()

    def _cursor_path(self) -> Path:
        return self.path.with_suffix(".cursor")

    def _trim_torn_tail(self) -> None:
        try:
            if not self.path.exists():
                return
            size = self.path.stat().st_size
            if size == 0:
                return
            with self.path.open("rb") as fh:
                fh.seek(max(0, size - 1024 * 1024))
                tail = fh.read()
            if tail.endswith(b"\n"):
                return
            nl = tail.rfind(b"\n")
            cut = size - len(tail) + (nl + 1 if nl >= 0 else 0)
            with self.path.open("r+b") as fh:
                fh.truncate(cut)
            self.dropped += 1
            logger.warning("[deferred] %s had a torn last line (%d bytes) — dropped; one alert may need re-delivery from its source",
                           self.path.name, size - cut)
            if self._read_pos > cut:
                self._read_pos = self._inflight_pos = cut
        except OSError as e:
            logger.warning("[deferred] could not inspect %s: %s", self.path, e)

    def push(self, alert: dict, reason: str = "storm") -> bool:
        """Spill one alert. False (and counted) only when the spill file itself is at its cap or unwritable."""
        try:
            if self.path.exists() and self.path.stat().st_size >= self.max_bytes:
                self.dropped += 1
                if self.dropped in (1, 10, 100) or self.dropped % 1000 == 0:
                    logger.error("[deferred] spill file %s at its %d MB cap — %d alert(s) dropped", self.path.name,
                                 self.max_bytes // (1024 * 1024), self.dropped)
                return False
            # the spill is a store like any other: credentials are redacted before they touch disk
            from ..agents.shared.redact import redact
            row = redact(dict(alert))
            row["deferred_at"] = time.time()
            row["deferred_by"] = reason
            with self.path.open("ab") as fh:
                fh.write((json.dumps(row, separators=(",", ":"), default=str) + "\n").encode())
            return True
        except OSError as e:
            self.dropped += 1
            if self.dropped in (1, 10, 100) or self.dropped % 1000 == 0:
                logger.error("[deferred] cannot write %s: %s — %d alert(s) dropped", self.path, e, self.dropped)
            return False

    def pending(self) -> int:
        try:
            if not self.path.exists():
                return 0
            with self.path.open("rb") as fh:
                fh.seek(self._read_pos)
                return sum(1 for line in fh if line.strip())
        except OSError:
            return 0

    def pop(self, n: int) -> list[dict]:
        """Up to ``n`` oldest deferred alerts from the committed cursor. Call ``ack()`` once they are processed;
        until then the on-disk cursor does not move, so a crash re-delivers them."""
        out: list[dict] = []
        if n <= 0 or not self.path.exists():
            return out
        try:
            with self.path.open("rb") as fh:
                fh.seek(self._read_pos)
                pos = self._read_pos
                while len(out) < n:
                    line = fh.readline()
                    if not line or not line.endswith(b"\n"):
                        break
                    pos += len(line)
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        self.dropped += 1
                        logger.warning("[deferred] unparseable row skipped at offset %d of %s", pos - len(line), self.path.name)
                        continue
                self._inflight_pos = pos
        except OSError as e:
            logger.warning("[deferred] cannot read %s: %s", self.path, e)
        return out

    def ack(self) -> None:
        """Commit the last popped batch: advance the cursor on disk; recycle the file once fully drained."""
        if self._inflight_pos <= self._read_pos:
            return
        self._read_pos = self._inflight_pos
        try:
            cur = self._cursor_path()
            tmp = cur.with_suffix(".cursor.tmp")
            tmp.write_text(str(self._read_pos))
            os.replace(tmp, cur)
            if self.path.exists() and self._read_pos >= self.path.stat().st_size:   # fully drained: start the file over
                cur.unlink(missing_ok=True)          # cursor first: a crash in between leaves a file and no cursor (safe)
                self.path.unlink(missing_ok=True)
                self._read_pos = self._inflight_pos = 0
        except OSError as e:
            logger.warning("[deferred] cursor not persisted: %s — the batch may be re-delivered after a restart", e)


__all__ = ["DeferredQueue"]
