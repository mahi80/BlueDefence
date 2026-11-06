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

import contextlib
import json
import logging
import os
import time
from pathlib import Path

logger = logging.getLogger("aegis.ops.deferred")


def _restrict_to_owner(fd: int, path: Path) -> None:
    """Best-effort 0600 on an already-open spill file. Windows has no ``os.fchmod``; there the file was
    created 0600 by ``os.open`` and ``os.chmod`` only toggles the read-only bit, so fall back to the path."""
    chmod = getattr(os, "fchmod", None)
    with contextlib.suppress(OSError):
        if chmod is not None:
            chmod(fd, 0o600)
        else:
            os.chmod(path, 0o600)


class DeferredQueue:
    def __init__(self, path: Path | str, *, max_bytes: int = 512 * 1024 * 1024):
        self.path = Path(path)
        self.max_bytes = max_bytes
        self._read_pos = 0           # committed (acked) position
        self._inflight_pos = 0       # position after the last pop, committed by ack()
        self._inflight_rows = 0      # rows in the last pop, subtracted from the count by ack()
        self._pending: int | None = None   # running count of rows not yet acked (None: count on first ask)
        self.dropped = 0
        self.path.parent.mkdir(parents=True, exist_ok=True)
        cur = self._cursor_path()
        drained = self._drained_path()
        if drained.exists():
            # a crash inside ack()'s recycle: the cursor belongs to the drained file, not to anything after it
            cur.unlink(missing_ok=True)
            drained.unlink(missing_ok=True)
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

    def _drained_path(self) -> Path:
        return self.path.with_suffix(".drained")

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
            # The spill is a QUEUE of alerts still to be analysed, not a record: it is written as received. Redacting it
            # stripped the very credential a re-fed secret-leak alert is about, so it came back with no evidence
            # (review round 3 G4-12). The file is private to the service user instead (0600, never through a
            # symlink), and the audit record of the analysis is redacted as always.
            row = dict(alert)
            row["deferred_at"] = time.time()
            row["deferred_by"] = reason
            data = (json.dumps(row, separators=(",", ":"), default=str) + "\n").encode()
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(self.path, flags, 0o600)
            try:
                # a file left by an older build may be 0644, and it now receives unredacted rows (round 4 X4-9)
                _restrict_to_owner(fd, self.path)
                start = os.lseek(fd, 0, os.SEEK_END)
                try:
                    view = memoryview(data)
                    while view:
                        view = view[os.write(fd, view):]
                except OSError:
                    # ENOSPC mid-write leaves a fragment; the next push would merge into it and both rows would be
                    # lost (code review 2026-11-03 E8). A raw fd has nothing buffered, so this cut really removes
                    # it (the buffered writer re-flushed and failed again, leaving the fragment: round 4 I4-4).
                    with contextlib.suppress(OSError):
                        os.ftruncate(fd, start)
                    raise
            finally:
                os.close(fd)
            if self._pending is not None:
                self._pending += 1
            return True
        except OSError as e:
            self.dropped += 1
            if self.dropped in (1, 10, 100) or self.dropped % 1000 == 0:
                logger.error("[deferred] cannot write %s: %s — %d alert(s) dropped", self.path, e, self.dropped)
            return False

    def pending(self) -> int:
        """Rows not yet acked. Counted from the file once, then kept as a running total: a full scan per call made
        draining a large spill quadratic (review round 4 I4-14)."""
        if self._pending is None:
            self._pending = self._count()
        return max(0, self._pending)

    def _count(self) -> int:
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
                rows = 0
                while len(out) < n:
                    line = fh.readline()
                    if not line or not line.endswith(b"\n"):
                        break
                    pos += len(line)
                    rows += 1 if line.strip() else 0
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        self.dropped += 1
                        logger.warning("[deferred] unparseable row skipped at offset %d of %s", pos - len(line), self.path.name)
                        continue
                self._inflight_pos = pos
                self._inflight_rows = rows
        except OSError as e:
            logger.warning("[deferred] cannot read %s: %s", self.path, e)
        return out

    def ack(self) -> None:
        """Commit the last popped batch: advance the cursor on disk; recycle the file once fully drained."""
        if self._inflight_pos <= self._read_pos:
            return
        self._read_pos = self._inflight_pos
        if self._pending is not None:
            self._pending -= self._inflight_rows
        self._inflight_rows = 0
        try:
            cur = self._cursor_path()
            tmp = cur.with_suffix(".cursor.tmp")
            tmp.write_text(str(self._read_pos))
            os.replace(tmp, cur)
            if self.path.exists() and self._read_pos >= self.path.stat().st_size:   # fully drained: start the file over
                # Data aside first, then the cursor: resetting the cursor first meant a crash in between re-delivered
                # the whole handled file (round 4 I4-10). A ``.drained`` file on start says the cursor is stale.
                drained = self._drained_path()
                os.replace(self.path, drained)
                cur.unlink(missing_ok=True)
                drained.unlink(missing_ok=True)
                self._read_pos = self._inflight_pos = 0
        except OSError as e:
            logger.warning("[deferred] cursor not persisted: %s — the batch may be re-delivered after a restart", e)


class SpillQueue:
    """A primary deferred queue plus a fallback on another volume (code review 2026-11-03 E2).

    The default spill sat next to the audit log, so when the audit disk filled up — the very case
    ``audit_deferred`` parking exists for — the spill failed too and the alert was dropped. A push that the
    primary refuses goes to the fallback; ``pop`` drains the primary first, then the fallback. Same interface
    as :class:`DeferredQueue`."""

    def __init__(self, primary: DeferredQueue, fallback: DeferredQueue | None = None):
        self.primary, self.fallback = primary, fallback
        self._popped: DeferredQueue | None = None
        self.path = primary.path
        self._warned = False

    @property
    def dropped(self) -> int:
        """Alerts neither queue could hold (a fallback that took the row means nothing was lost)."""
        return self.fallback.dropped if self.fallback is not None else self.primary.dropped

    def push(self, alert: dict, reason: str = "storm") -> bool:
        if self.primary.push(alert, reason):
            return True
        if self.fallback is None:
            return False
        ok = self.fallback.push(alert, reason)
        if ok and not self._warned:
            # once, not by counting the fallback's lines on every push — that re-read the whole file each time
            # (quadratic under the very disk-full storm it exists for; review round 3 G4-10)
            self._warned = True
            logger.error("[deferred] primary spill %s refused a row — spilling to %s", self.primary.path, self.fallback.path)
        return ok

    def pending(self) -> int:
        return self.primary.pending() + (self.fallback.pending() if self.fallback is not None else 0)

    def pop(self, n: int) -> list[dict]:
        for q in (self.primary, self.fallback):
            if q is None:
                continue
            out = q.pop(n)
            if out:
                self._popped = q
                return out
        self._popped = None
        return []

    def ack(self) -> None:
        if self._popped is not None:
            self._popped.ack()
            self._popped = None


def _private_state_dir() -> Path:
    """A directory only this user can write, that survives a service restart: systemd's ``$STATE_DIRECTORY``, else
    ``$XDG_STATE_HOME/aegis``, else ``~/.local/state/aegis``. The fallback used to sit at a predictable name in the
    shared temp dir — another local user could pre-create it as a symlink or inject rows into it, and
    ``PrivateTmp`` wiped it on every restart (review round 3 G4-9)."""
    # os.pathsep: a Windows drive letter ("C:\…") is not a list separator, as ":" would make it
    base = (os.environ.get("STATE_DIRECTORY", "").split(os.pathsep)[0].strip()
            or os.path.join(os.environ.get("XDG_STATE_HOME", "") or os.path.join(os.path.expanduser("~"), ".local", "state"), "aegis"))
    d = Path(base)
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    if d.is_symlink() or (hasattr(os, "getuid") and d.stat().st_uid != os.getuid()):
        raise OSError(f"{d} is not a private directory of this user")
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


def default_spill(audit_path: Path | str) -> SpillQueue:
    """``AEGIS_DEFERRED_PATH`` (default: beside the audit log) with ``AEGIS_DEFERRED_FALLBACK`` (default: a private
    state directory, see :func:`_private_state_dir`) behind it. Set the fallback to ``off`` to disable it."""
    primary = os.environ.get("AEGIS_DEFERRED_PATH", "").strip() or str(Path(audit_path).parent / "deferred.jsonl")
    fb = os.environ.get("AEGIS_DEFERRED_FALLBACK", "").strip()
    if fb.lower() in ("off", "0", "none"):
        return SpillQueue(DeferredQueue(primary))
    if not fb:
        try:
            fb = str(_private_state_dir() / "deferred-fallback.jsonl")
        except OSError as e:
            logger.warning("[deferred] no private state directory for the fallback spill (%s) — primary only", e)
            return SpillQueue(DeferredQueue(primary))
    if Path(fb).is_symlink():
        logger.warning("[deferred] fallback spill %s is a symlink — refusing it, primary only", fb)
        return SpillQueue(DeferredQueue(primary))
    if Path(fb).resolve() == Path(primary).resolve():
        return SpillQueue(DeferredQueue(primary))
    try:
        return SpillQueue(DeferredQueue(primary), DeferredQueue(fb))
    except OSError as e:
        logger.warning("[deferred] fallback spill %s unusable (%s) — primary only", fb, e)
        return SpillQueue(DeferredQueue(primary))


__all__ = ["DeferredQueue", "SpillQueue", "default_spill"]
