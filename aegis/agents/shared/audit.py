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

import contextlib
import errno
import logging
import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Iterator, Optional

try:                                    # POSIX (the supported server platform)
    import fcntl
except ImportError:                     # pragma: no cover - Windows dev boxes
    fcntl = None                            # type: ignore[assignment]
try:
    import msvcrt
except ImportError:                     # pragma: no cover - Linux
    msvcrt = None                           # type: ignore[assignment]

from .evidence_chain import EvidenceChain
from .redact import redact_chain

logger = logging.getLogger("aegis.audit")


_LOCK = threading.RLock()          # reentrant: the cross-process wrapper and the append body both hold it
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
    def __init__(self, path: Path, sink=None, *, max_bytes: int | None = None, fsync: bool | None = None,
                 repair: bool = True, index=None):
        """``sink``: optional ``aegis.persist.DashboardSink`` — every appended
        chain is also shipped to the dashboard (roadmap 0.3). The JSONL file
        stays the local source of truth; the sink never blocks or raises.
        ``repair=False`` for read-only tools (``--status``, ``verify``, reports) run beside a live
        service: they must never truncate a row the service is in the middle of writing."""
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes = int(max_bytes if max_bytes is not None else float(os.environ.get("AEGIS_AUDIT_MAX_MB", "512") or 512) * 1024 * 1024)
        self.fsync = _env_flag("AEGIS_AUDIT_FSYNC", True) if fsync is None else fsync
        self._sink = sink
        self._index = index                      # aegis.store.IndexStore: derived, queryable copy; never raises
        self.write_failures = 0
        self.last_error: str = ""
        if repair:
            with self._file_lock():
                self._repair_torn_tail()
        self._tail_hash = self._compute_tail_hash()
        self._appended = 0
        self._seen_sig: tuple[int, int, int] | None = None    # forces one tail sync on the first append

    # --------------------------------------------------------- writer lock --
    @contextlib.contextmanager
    def _file_lock(self):
        """Serialise appends across processes, not just threads.

        A compliance report / ``python -m aegis.audit`` / ``--once`` run used to build its own AuditLog,
        chain from its own ``_tail_hash`` and fork the log. The lock file lives beside the log and is
        created 0600; when the platform has no advisory lock it degrades to the in-process lock only.
        """
        if fcntl is None and msvcrt is None:        # pragma: no cover - exotic platform
            yield
            return
        lock_path = self.path.with_name(self.path.name + ".lock")
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            else:                                    # pragma: no cover - Windows dev boxes
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                else:                                # pragma: no cover
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        finally:
            os.close(fd)

    def _last_hash_in(self, f: Path) -> Optional[str]:
        """The last complete row's hash in ``f`` (bounded read; ``None`` when the window has no row)."""
        try:
            size = f.stat().st_size
        except OSError:
            return None
        if not size:
            return None
        with f.open("rb") as fh:
            fh.seek(max(0, size - 4 * 1024 * 1024))
            data = fh.read()
        for raw in reversed(data.split(b"\n")):
            if not raw.strip():
                continue
            try:
                row = json.loads(raw)
            except ValueError:
                continue
            if isinstance(row, dict) and row.get("integrity_hash"):
                return str(row["integrity_hash"])
        return None

    def _disk_tail(self) -> str:
        if self.path.exists() and self.path.stat().st_size:
            h = self._last_hash_in(self.path)
            return h if h is not None else self._compute_tail_hash()
        # the live file is empty: the chain continues from the newest rotated segment
        return self._live_segment_seed()

    def _stat_sig(self) -> tuple[int, int, int]:
        """(size, mtime_ns, inode): cheap evidence that this writer last saw the current file."""
        try:
            st = self.path.stat()
            return (st.st_size, st.st_mtime_ns, st.st_ino)
        except OSError:
            return (0, 0, 0)

    def _sync_tail(self) -> None:
        """Adopt a tail another process appended (or rotated) while this instance was idle."""
        sig = self._stat_sig()
        if sig == self._seen_sig:
            return
        size = sig[0]
        if size:
            with self.path.open("rb") as fh:
                fh.seek(-1, os.SEEK_END)
                if fh.read(1) != b"\n":
                    self._repair_torn_tail()         # a crashed writer left a partial row; we hold the lock
                    size = self._stat_sig()[0]
        disk = self._disk_tail()
        if disk != self._tail_hash:
            logger.info("[audit] another writer advanced %s; chaining from %s", self.path, disk[:12])
            self._tail_hash = disk
        self._seen_sig = self._stat_sig()

    # ------------------------------------------------------------- anchor --
    @staticmethod
    def anchor_path() -> Path | None:
        """``AEGIS_AUDIT_ANCHOR``: an append-only file OUTSIDE the audit volume (another disk, a WORM share, a
        syslog-shipped file). A hash chain alone cannot see its own tail being cut off — truncating the last N
        rows leaves a chain that verifies (review round 3 G7-17). Anchored tail hashes can be checked against."""
        v = os.environ.get("AEGIS_AUDIT_ANCHOR", "").strip()
        return Path(v) if v and v.lower() not in ("off", "0", "none") else None

    def _maybe_anchor(self) -> None:
        p = self.anchor_path()
        if p is None:
            return
        try:
            every = max(1, int(os.environ.get("AEGIS_AUDIT_ANCHOR_EVERY", "100") or 100))
        except ValueError:
            every = 100
        if self._appended % every:
            return
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"ts": time.time(), "hash": self._tail_hash, "log": str(self.path.resolve())}) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as e:
            logger.warning("[audit] anchor %s not written: %s", p, e.strerror or e)

    def _anchors(self) -> set[str]:
        p = self.anchor_path()
        out: set[str] = set()
        if p is None or not p.exists():
            return out
        try:
            with p.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    try:
                        row = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(row, dict) and row.get("hash") and row.get("log", str(self.path.resolve())) == str(self.path.resolve()):
                        out.add(str(row["hash"]))
        except OSError:
            pass
        return out

    # ------------------------------------------------------------ recovery --
    def _repair_torn_tail(self) -> None:
        """A crash between write and fsync can leave a partial LAST line. Keep everything before it, move the
        fragment aside for forensics, and carry on — otherwise one torn byte stops the SOC from starting.
        Only the trailing fragment is touched: a bad line in the middle of the file is corruption, not a torn
        write, and is left for ``verify`` to report (``broken_at``) rather than silently discarding every
        intact row after it."""
        if not self.path.exists() or self.path.stat().st_size == 0:
            return
        size = self.path.stat().st_size
        with self.path.open("rb") as fh:
            fh.seek(max(0, size - 1024 * 1024))
            tail = fh.read()
        base = size - len(tail)
        if tail.endswith(b"\n"):
            # last line complete; it may still be garbage if the crash hit mid-write of a longer row — check it
            body = tail.rstrip(b"\n")
            nl = body.rfind(b"\n")
            last = body[nl + 1:]
            try:
                json.loads(last)
                return
            except ValueError:
                if nl < 0 and base > 0:
                    return                       # the row is longer than the window; leave it to verify
                good_end = base + nl + 1 if nl >= 0 else 0
                torn = tail[nl + 1:] if nl >= 0 else tail
        else:
            nl = tail.rfind(b"\n")
            if nl < 0 and base > 0:
                return
            good_end = base + nl + 1 if nl >= 0 else 0
            torn = tail[nl + 1:] if nl >= 0 else tail
        aside = self.path.with_name(f"{self.path.name}.torn-{int(time.time() * 1000)}")
        n = 0
        while aside.exists():
            n += 1
            aside = self.path.with_name(f"{self.path.name}.torn-{int(time.time() * 1000)}-{n}")
        aside.write_bytes(torn)
        with self.path.open("r+b") as fh:
            fh.truncate(good_end)
            fh.flush()
            os.fsync(fh.fileno())
        logger.warning("[audit] repaired a torn tail in %s: %d byte(s) moved to %s; chain resumes from the last intact entry",
                       self.path, len(torn), aside.name)

    def _compute_tail_hash(self) -> str:
        for f in (self.path, *self.rotated_files()[::-1]):
            if not f.exists():
                continue
            last: Optional[dict] = None
            bad = 0
            with f.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    try:
                        row = json.loads(line)
                    except ValueError:
                        bad += 1
                        continue
                    if isinstance(row, dict) and row.get("integrity_hash"):
                        last = row
            if bad:
                logger.warning("[audit] %s: %d unparseable line(s) skipped while locating the chain tail — run `python -m aegis.audit verify --all`", f.name, bad)
            if last:
                return str(last["integrity_hash"])
        # every segment retired (and the live file empty or absent): the next row chains from the checkpoint's seed,
        # not GENESIS — otherwise the first row after a full retention broke verify --all (review round 8 R8-7)
        return self.chain_seed()

    # ----------------------------------------------------------- retention --
    # Retention drops whole rotated segments. Without a record of what was dropped, ``verify --all`` started from
    # GENESIS and every anchor in a dropped segment read as "the log was truncated" — the documented retention
    # procedure broke verification for good (review round 7 R-12). ``retire_segments`` writes a checkpoint first:
    # the hash the first kept row chains from, the anchors that went with the dropped rows, and (when a decision
    # key is configured) an HMAC so the checkpoint cannot be edited to hide a cut.
    def retention_path(self) -> Path:
        return self.path.with_name(self.path.name + ".retention")

    # The checkpoint key (review round 8 R8-3): a dedicated audit key, never the console token. The console token is
    # rotated like any API key and lives on the console host; deriving the retention signature from it meant a token
    # rotation broke ``verify --all`` for good and anyone holding the console key could re-sign a cut. Order:
    # ``AEGIS_AUDIT_KEY``, else ``AEGIS_DECISION_KEY``. Rotation: set the new key in ``AEGIS_AUDIT_KEY`` and the old one
    # in ``AEGIS_AUDIT_KEY_PREVIOUS`` (comma-separated; ``console:<token>`` names a pre-round-8 checkpoint that was
    # signed with the key derived from that console token), then ``python -m aegis.audit resign`` — checkpoints signed
    # by a listed previous key keep verifying until then, and the next retire/resign signs with the current key.
    @staticmethod
    def _audit_key() -> bytes | None:
        for var in ("AEGIS_AUDIT_KEY", "AEGIS_DECISION_KEY"):
            v = os.environ.get(var, "").strip()
            if v:
                return v.encode()
        return None

    @staticmethod
    def _previous_audit_keys() -> list[bytes]:
        import hmac as _hmac
        out: list[bytes] = []
        for item in os.environ.get("AEGIS_AUDIT_KEY_PREVIOUS", "").split(","):
            item = item.strip()
            if not item:
                continue
            if item.startswith("console:"):
                out.append(_hmac.new(item[len("console:"):].encode(), b"aegis-decision-signing-v1", hashlib.sha256).digest())
            else:
                out.append(item.encode())
        return out

    @staticmethod
    def _key_id(key: bytes) -> str:
        return hashlib.sha256(b"aegis-audit-kid|" + key).hexdigest()[:16]

    @staticmethod
    def _retention_sig(body: dict, key: bytes | None = None) -> str:
        key = AuditLog._audit_key() if key is None else key
        if key is None:
            return ""
        import hmac as _hmac
        payload = json.dumps({k: body[k] for k in ("seed", "dropped", "anchors_retired", "entries_retired")},
                             sort_keys=True, separators=(",", ":")).encode()
        return _hmac.new(key, b"aegis-audit-retention-v1|" + payload, hashlib.sha256).hexdigest()

    def _read_retention(self) -> tuple[dict | None, str]:
        """The checkpoint as stored, signature NOT checked: (checkpoint, problem)."""
        p = self.retention_path()
        if not p.exists():
            return None, ""
        try:
            cp = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            return None, f"retention checkpoint unreadable: {e}"
        if not isinstance(cp, dict) or not isinstance(cp.get("seed"), str):
            return None, "retention checkpoint malformed"
        return cp, ""

    def retention(self) -> tuple[dict | None, str]:
        """(checkpoint, problem). No checkpoint → (None, ""). A checkpoint that fails its signature → (None, why).
        With no audit key configured a checkpoint cannot be checked at all → (None, "unverifiable: no key …"): an
        unsigned or hand-written checkpoint used to be accepted as-is and turned a deleted segment green (R8-4)."""
        cp, problem = self._read_retention()
        if cp is None:
            return None, problem
        current = self._audit_key()
        keys = ([current] if current is not None else []) + self._previous_audit_keys()
        if not keys:
            return None, ("unverifiable: no key — the retention checkpoint cannot be checked; set AEGIS_AUDIT_KEY "
                          "(or AEGIS_DECISION_KEY) to the key the service signs with")
        got = str(cp.get("sig") or "")
        import hmac as _hmac
        if not got or not any(_hmac.compare_digest(self._retention_sig(cp, k), got) for k in keys):
            return None, "retention checkpoint signature does not match (edited, or signed with another key)"
        return cp, ""

    def chain_seed(self) -> str:
        """What the oldest retained row chains from: the retention checkpoint's seed, else GENESIS. The stored seed
        is used even when the signature cannot be checked here — chaining from GENESIS instead would fork the log;
        whether the checkpoint is genuine is ``verify``'s question, not the writer's."""
        cp, _ = self._read_retention()
        return str(cp["seed"]) if cp else GENESIS

    def _write_retention(self, body: dict) -> None:
        tmp = self.retention_path().with_name(self.retention_path().name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(body, indent=1))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.retention_path())

    def resign_retention(self, *, trust_unverified: bool = False) -> dict:
        """Key rotation: re-sign the checkpoint with the current key after it verified under a listed key.
        ``trust_unverified`` is the one-off migration for a checkpoint written unsigned (before round 8) or under a
        key nobody has any more: the operator vouches for it, and the checkpoint records that it was re-signed
        without verification (``vouched_at``) so an auditor can see it."""
        with _LOCK:
            key = self._audit_key()
            if key is None:
                return {"ok": False, "error": "no audit key: set AEGIS_AUDIT_KEY before re-signing"}
            cp, problem = self.retention()
            vouched = False
            if problem:
                raw, unreadable = self._read_retention()
                if not trust_unverified or raw is None:
                    return {"ok": False, "error": unreadable or problem}
                cp, vouched = raw, True
            if cp is None:
                return {"ok": True, "resigned": False, "note": "no retention checkpoint"}
            cp = {**cp, "kid": self._key_id(key)}
            if vouched:
                cp["vouched_at"] = time.time()
                logger.warning("[audit] retention checkpoint %s re-signed WITHOUT verification (operator vouched)", self.retention_path())
            cp["sig"] = self._retention_sig(cp, key)
            self._write_retention(cp)
            return {"ok": True, "resigned": True, "kid": cp["kid"], "vouched": vouched}

    def retire_segments(self, count: int) -> dict:
        """Drop the ``count`` oldest rotated segments, after verifying them and recording a retention checkpoint.
        Never drops the live file. Refuses (nothing deleted) when the segments to drop do not verify."""
        with _LOCK:
            segments = self.rotated_files()
            count = max(0, min(int(count), len(segments)))
            if count == 0:
                return {"ok": True, "dropped": [], "seed": self.chain_seed()}
            key = self._audit_key()
            if key is None:
                # an unsigned checkpoint is indistinguishable from a forged one (R8-3/R8-4): never delete without one
                return {"ok": False, "error": "no audit key: set AEGIS_AUDIT_KEY (or AEGIS_DECISION_KEY) — the same value the "
                                              "service runs with — before retiring segments; nothing was deleted"}
            cp, problem = self.retention()
            if problem:
                return {"ok": False, "error": problem}
            prev = str(cp["seed"]) if cp else GENESIS
            anchors = self._anchors()
            retired_anchors = set(cp.get("anchors_retired", [])) if cp else set()
            entries = int(cp.get("entries_retired", 0)) if cp else 0
            for seg in segments[:count]:
                with seg.open("r", encoding="utf-8", errors="replace") as fh:
                    for n, line in enumerate(fh, 1):
                        if not line.strip():
                            continue
                        try:
                            entry = json.loads(line)
                        except ValueError:
                            return {"ok": False, "error": f"{seg.name}:{n} unparseable — not retiring"}
                        claimed = entry.pop("integrity_hash", "")
                        actual = hashlib.sha256((prev + json.dumps(entry, sort_keys=True, separators=(",", ":"))).encode()).hexdigest()
                        if actual != claimed:
                            return {"ok": False, "error": f"{seg.name}:{n} breaks the chain — not retiring"}
                        if claimed in anchors:
                            retired_anchors.add(claimed)
                        prev = claimed
                        entries += 1
            body = {"seed": prev, "dropped": (list(cp.get("dropped", [])) if cp else []) + [s.name for s in segments[:count]],
                    "anchors_retired": sorted(retired_anchors), "entries_retired": entries, "ts": time.time(),
                    "kid": self._key_id(key)}
            body["sig"] = self._retention_sig(body, key)
            self._write_retention(body)
            for seg in segments[:count]:
                seg.unlink()
            logger.info("[audit] retired %d segment(s); the chain now starts from %s", count, prev[:16])
            return {"ok": True, "dropped": [s.name for s in segments[:count]], "seed": prev, "signed": bool(body["sig"])}

    def rotated_files(self) -> list[Path]:
        """Older segments, oldest first (``audit.jsonl.<utc-ts>``)."""
        return sorted(p for p in self.path.parent.glob(self.path.name + ".*") if p.name[len(self.path.name) + 1:].isdigit())

    # -------------------------------------------------------------- append --
    def append(self, chain: EvidenceChain) -> EvidenceChain:
        """Append under the in-process lock AND an OS file lock, after adopting any tail another writer added."""
        with _LOCK, self._file_lock():
            self._sync_tail()
            try:
                return self._append_locked(chain)
            finally:
                self._seen_sig = self._stat_sig()

    def _append_locked(self, chain: EvidenceChain) -> EvidenceChain:
        with _LOCK:
            chain.finalize()
            # credentials never enter the sealed record (audit file, index, dashboard row all come from here)
            redact_chain(chain)
            payload = chain.model_dump(mode="json", exclude={"integrity_hash"})
            serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            h = hashlib.sha256((self._tail_hash + serialized).encode("utf-8")).hexdigest()
            chain.integrity_hash = h
            row = (json.dumps(chain.model_dump(mode="json")) + "\n").encode("utf-8")
            start = -1
            try:
                self._rotate_if_needed(len(row))
                with self.path.open("ab") as fh:
                    start = fh.tell()
                    fh.write(row)
                    fh.flush()
                    if self.fsync:
                        os.fsync(fh.fileno())
            except OSError as e:
                # nothing is chained until the row is durable: the next append retries against the same tail.
                # If the bytes did land before fsync failed, take them back so the file matches _tail_hash.
                if start >= 0:
                    try:
                        with self.path.open("r+b") as fh:
                            fh.truncate(start)
                    except OSError as e2:
                        logger.critical("[audit] could not roll back a half-durable row in %s (%s); chain may need verify", self.path, e2.strerror or e2)
                chain.integrity_hash = ""
                self.write_failures += 1
                self.last_error = f"{e.strerror or e} ({self.path})"
                if self.write_failures in (1, 10, 100) or self.write_failures % 1000 == 0:
                    logger.critical("[audit] cannot write %s: %s — %d failure(s); irreversible actions are held until the log is writable",
                                    self.path, e.strerror or e, self.write_failures)
                raise AuditWriteError(f"audit log not writable: {e.strerror or e}", e.errno) from e
            prev = self._tail_hash
            self._tail_hash = h
            self._appended += 1
            self._maybe_anchor()
            if self.write_failures:
                logger.info("[audit] %s writable again after %d failure(s)", self.path, self.write_failures)
                self.write_failures = 0
                self.last_error = ""
            if self._index is not None:
                try:
                    seg = str(self.path.stat().st_ino)
                except OSError:
                    seg = self.path.name
                try:
                    self._index.index_chain(chain.model_dump(mode="json"), prev_hash=prev, segment=seg, offset=start)
                except Exception as exc:  # noqa: BLE001 — the store already swallows; belt and braces
                    logger.warning("[audit] index insert failed: %s", str(exc)[:120])
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
            with f.open("r", encoding="utf-8", errors="replace") as fh:
                for n, line in enumerate(fh, 1):
                    if not line.strip():
                        continue
                    if f == self.path and not line.endswith("\n"):
                        break                       # the row the live service is writing right now: not part of the chain yet
                    try:
                        yield f, n, json.loads(line)
                    except ValueError as e:
                        raise ValueError(f"{f.name}:{n}: {str(e)[:60]}") from e

    def _live_segment_seed(self) -> str:
        """The hash the live segment's first row chains from: the last row of the newest rotated segment
        (GENESIS when the log has never rotated). Verifying the live file from GENESIS reported an intact log
        as "chain BROKEN at (audit.jsonl, 1)" after the first rotation, and the compliance report failed."""
        rotated = self.rotated_files()
        if not rotated:
            return self.chain_seed()
        last = ""
        try:
            with rotated[-1].open("rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                fh.seek(max(0, size - 1_048_576))       # the last row of a segment is well under 1 MiB
                tail = fh.read().decode("utf-8", "replace").rstrip("\n").rsplit("\n", 1)[-1]
            last = str(json.loads(tail).get("integrity_hash") or "")
        except (OSError, ValueError):
            last = ""
        return last or GENESIS

    def verify(self, *, all_files: bool = False) -> bool:
        return self.verify_report(all_files=all_files)["ok"]

    def verify_report(self, *, all_files: bool = False) -> dict:
        """Walk the chain; ``{"ok", "entries", "files", "broken_at": (file, line) | None}``. With ``all_files``
        the rotated segments are verified in order as one chain (the first entry of each segment chains from the
        previous segment's tail)."""
        cp, problem = self.retention()
        if problem:
            # including "unverifiable: no key" — never green on a checkpoint nobody could check, and the anchors it
            # claims to retire are not silently dropped (R8-4)
            return {"ok": False, "entries": 0, "files": [], "broken_at": ("<retention>", problem),
                    "unverifiable": problem.startswith("unverifiable")}
        prev = (str(cp["seed"]) if cp else GENESIS) if all_files else self._live_segment_seed()
        entries, files = 0, set()
        anchors = (self._anchors() - set(cp.get("anchors_retired", []) if cp else ())) if all_files else set()
        try:
            for f, n, entry in self._iter_entries(all_files):
                files.add(f.name)
                claimed = entry.pop("integrity_hash", "")
                serialized = json.dumps(entry, sort_keys=True, separators=(",", ":"))
                actual = hashlib.sha256((prev + serialized).encode("utf-8")).hexdigest()
                if actual != claimed:
                    return {"ok": False, "entries": entries, "files": sorted(files), "broken_at": (f.name, n)}
                prev = claimed
                anchors.discard(claimed)
                entries += 1
        except ValueError as e:
            return {"ok": False, "entries": entries, "files": sorted(files), "broken_at": ("<unparseable>", str(e)[:80])}
        if anchors:
            # an anchored row is no longer in the chain: the log was cut back past it
            return {"ok": False, "entries": entries, "files": sorted(files),
                    "broken_at": ("<anchor>", f"{len(anchors)} anchored entr{'y' if len(anchors) == 1 else 'ies'} missing — the log was truncated"),
                    "tail": prev}
        return {"ok": True, "entries": entries, "files": sorted(files), "broken_at": None, "tail": prev}
