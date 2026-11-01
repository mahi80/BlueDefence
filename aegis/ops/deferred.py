"""Storm-mode deferred queue: a bounded, append-only JSONL spill file for alerts that need the model while the
loop is saturated. Fast paths keep running; nothing is dropped — deferred alerts are re-fed to the pipeline
in bounded batches once the storm drains, oldest first, with ``deferred_at`` / ``deferred_by`` stamped on.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path


class DeferredQueue:
    def __init__(self, path: Path | str, *, max_bytes: int = 512 * 1024 * 1024):
        self.path = Path(path)
        self.max_bytes = max_bytes
        self._read_pos = 0
        self.dropped = 0
        self.path.parent.mkdir(parents=True, exist_ok=True)
        cur = self.path.with_suffix(".cursor")
        try:
            self._read_pos = int(cur.read_text().strip())
            if self.path.exists() and self._read_pos > self.path.stat().st_size:
                self._read_pos = 0
        except (OSError, ValueError):
            self._read_pos = 0

    def push(self, alert: dict, reason: str = "storm") -> bool:
        """Spill one alert. False (and counted) only when the spill file itself is at its cap."""
        try:
            if self.path.exists() and self.path.stat().st_size >= self.max_bytes:
                self.dropped += 1
                return False
            row = dict(alert)
            row["deferred_at"] = time.time()
            row["deferred_by"] = reason
            with self.path.open("ab") as fh:
                fh.write((json.dumps(row, separators=(",", ":"), default=str) + "\n").encode())
            return True
        except OSError:
            self.dropped += 1
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
        """Up to ``n`` oldest deferred alerts; the cursor advances only after they are handed out, so a crash
        between pop and processing re-delivers them (dedupe is on the alert id downstream)."""
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
                        continue
                self._read_pos = pos
            self.path.with_suffix(".cursor").write_text(str(self._read_pos))
            if self._read_pos >= self.path.stat().st_size:          # fully drained: start the file over
                self.path.unlink(missing_ok=True)
                self.path.with_suffix(".cursor").unlink(missing_ok=True)
                self._read_pos = 0
        except OSError:
            pass
        return out
