"""Tamper-evident audit log for agent decisions.

Production: append-only WORM bucket / Splunk Frozen / S3 Object Lock.
Walking skeleton: append-only JSONL file with hash-chained entries
so any modification of an earlier entry breaks the chain.

Durability (what an on-prem box does to a log file):
- every append is flushed and fsynced (``AEGIS_AUDIT_FSYNC=0`` to disable on fast SSD/WORM mounts);
- a torn last line (crash mid-write) is detected at start, moved aside as ``<path>.torn-<ts>`` and the
  chain resumes from the last intact entry — the service never refuses to start over a half-written row;
- a write that fails (disk full, read-only mount) raises ``AuditWriteError``: the caller must not execute
  an irreversible action it cannot evidence; the log stays consistent (nothing half-written is chained);
- rotation at ``AEGIS_AUDIT_MAX_MB`` (default 512): the file is renamed ``<path>.<utc-ts>`` and the next
  entry chains from the previous tail hash, so ``verify(all_files=True)`` walks every rotated file as
  one unbroken chain.
"""
from __future__ import annotations

import errno
import logging
import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Iterator, Optional

from .evidence_chain import EvidenceChain

logger = logging.getLogger("aegis.audit")


_LOCK = threading.Lock()
GENESIS = "0" * 64


class AuditWriteError(RuntimeError):
    """The audit log could not be written (disk full, read-only, permissions). ``errno`` is set when known."""

    def __init__(self, msg: str, errno_: int | None = None):
        super().__init__(msg)
        self.errno = errno_


def _env_flag(name: str, default: bool) -> bool:
    v = os.environ.get(name, "").strip().lower()
    return default if not v else v in ("1", "true", "yes", "on")


class AuditLog:
    def __init__(self, path: Path, sink=None, *, max_bytes: int | None = None, fsync: bool | None = None):
        """``sink``: optional ``aegis.persist.DashboardSink`` — every appended
        chain is also shipped to the dashboard (roadmap 0.3). The JSONL file
        stays the local source of truth; the sink never blocks or raises."""
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes = int(max_bytes if max_bytes is not None else float(os.environ.get("AEGIS_AUDIT_MAX_MB", "512") or 512) * 1024 * 1024)
        self.fsync = _env_flag("AEGIS_AUDIT_FSYNC", True) if fsync is None else fsync
        self._sink = sink
        self.write_failures = 0
        self.last_error: str = ""
        self._repair_torn_tail()
        self._tail_hash = self._compute_tail_hash()

    # ------------------------------------------------------------ recovery --
    def _repair_torn_tail(self) -> None:
        """A crash between write and fsync can leave a partial last line. Keep everything before it, move the
        fragment aside for forensics, and carry on — otherwise one torn byte stops the SOC from starting."""
        if not self.path.exists() or self.path.stat().st_size == 0:
            return
        good_end = 0
        torn = b""
        with self.path.open("rb") as fh:
            while True:
                pos = fh.tell()
                line = fh.readline()
                if not line:
                    break
                ok = line.endswith(b"\n")
                if ok:
                    try:
                        json.loads(line)
                    except ValueError:
                        ok = False
                if ok:
                    good_end = pos + len(line)
                else:
                    torn = line + fh.read()
                    break
        if not torn:
            return
        aside = self.path.with_name(f"{self.path.name}.torn-{int(time.time())}")
        aside.write_bytes(torn)
        with self.path.open("r+b") as fh:
            fh.truncate(good_end)
            fh.flush()
            os.fsync(fh.fileno())
        logger.warning("[audit] repaired a torn tail in %s: %d byte(s) moved to %s; chain resumes from the last intact entry",
                       self.path, len(torn), aside.name)

    def _compute_tail_hash(self) -> str:
        last: Optional[dict] = None
        for f in (self.path, *self.rotated_files()[::-1]):
            if not f.exists():
                continue
            with f.open("r", encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        last = json.loads(line)
            if last:
                return str(last["integrity_hash"])
        return GENESIS

    def rotated_files(self) -> list[Path]:
        """Older segments, oldest first (``audit.jsonl.<utc-ts>``)."""
        return sorted(p for p in self.path.parent.glob(self.path.name + ".*") if p.name[len(self.path.name) + 1:].isdigit())

    # -------------------------------------------------------------- append --
    def append(self, chain: EvidenceChain) -> EvidenceChain:
        with _LOCK:
            chain.finalize()
            payload = chain.model_dump(mode="json", exclude={"integrity_hash"})
            serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            h = hashlib.sha256((self._tail_hash + serialized).encode("utf-8")).hexdigest()
            chain.integrity_hash = h
            row = (json.dumps(chain.model_dump(mode="json")) + "\n").encode("utf-8")
            try:
                self._rotate_if_needed(len(row))
                with self.path.open("ab") as fh:
                    fh.write(row)
                    fh.flush()
                    if self.fsync:
                        os.fsync(fh.fileno())
            except OSError as e:
                # nothing is chained until the row is durable: the next append retries against the same tail
                chain.integrity_hash = ""
                self.write_failures += 1
                self.last_error = f"{e.strerror or e} ({self.path})"
                if self.write_failures in (1, 10, 100) or self.write_failures % 1000 == 0:
                    logger.critical("[audit] cannot write %s: %s — %d failure(s); irreversible actions are held until the log is writable",
                                    self.path, e.strerror or e, self.write_failures)
                raise AuditWriteError(f"audit log not writable: {e.strerror or e}", e.errno) from e
            prev = self._tail_hash
            self._tail_hash = h
            if self.write_failures:
                logger.info("[audit] %s writable again after %d failure(s)", self.path, self.write_failures)
                self.write_failures = 0
                self.last_error = ""
        if self._sink is not None:
            try:
                self._sink.ship_chain(chain, prev_hash=prev)
            except Exception as exc:  # noqa: BLE001 — persistence must never break the investigation
                logger.warning("[audit] chain %s not shipped to the dashboard (%s: %s); local audit log is still authoritative", getattr(chain, "alert_id", "?"), type(exc).__name__, str(exc)[:120])
        return chain

    def _rotate_if_needed(self, incoming: int) -> None:
        if self.max_bytes <= 0 or not self.path.exists():
            return
        if self.path.stat().st_size + incoming <= self.max_bytes:
            return
        target = self.path.with_name(f"{self.path.name}.{int(time.time() * 1000)}")
        while target.exists():
            target = self.path.with_name(f"{target.name}1")
        os.replace(self.path, target)
        logger.info("[audit] rotated %s → %s (%d bytes); the chain continues across files", self.path.name, target.name, target.stat().st_size)

    @property
    def degraded(self) -> bool:
        return self.write_failures > 0

    @property
    def tail_hash(self) -> str:
        return self._tail_hash

    # -------------------------------------------------------------- verify --
    def _iter_entries(self, all_files: bool) -> Iterator[tuple[Path, int, dict]]:
        files = (self.rotated_files() + [self.path]) if all_files else [self.path]
        for f in files:
            if not f.exists():
                continue
            with f.open("r", encoding="utf-8") as fh:
                for n, line in enumerate(fh, 1):
                    if line.strip():
                        yield f, n, json.loads(line)

    def verify(self, *, all_files: bool = False) -> bool:
        return self.verify_report(all_files=all_files)["ok"]

    def verify_report(self, *, all_files: bool = False) -> dict:
        """Walk the chain; ``{"ok", "entries", "files", "broken_at": (file, line) | None}``. With ``all_files``
        the rotated segments are verified in order as one chain (the first entry of each segment chains from the
        previous segment's tail)."""
        prev = GENESIS
        entries, files = 0, set()
        try:
            for f, n, entry in self._iter_entries(all_files):
                files.add(f.name)
                claimed = entry.pop("integrity_hash", "")
                serialized = json.dumps(entry, sort_keys=True, separators=(",", ":"))
                actual = hashlib.sha256((prev + serialized).encode("utf-8")).hexdigest()
                if actual != claimed:
                    return {"ok": False, "entries": entries, "files": sorted(files), "broken_at": (f.name, n)}
                prev = claimed
                entries += 1
        except ValueError as e:
            return {"ok": False, "entries": entries, "files": sorted(files), "broken_at": ("<unparseable>", str(e)[:80])}
        return {"ok": True, "entries": entries, "files": sorted(files), "broken_at": None, "tail": prev}
