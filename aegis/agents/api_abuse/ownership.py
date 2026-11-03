"""Object ownership — who owns account 1002? The one fact a gateway log never carries.

Broken object-level authorisation (BOLA / IDOR) is a principal reading or changing an object
it does not own. The gateway log says *who* called (the token's subject) and *which* object
(the id in the path); only the bank's systems of record know the owner. ``OwnershipSource``
is that lookup, supplied by the bank:

    file   ``AEGIS_OWNERSHIP_FILE`` — CSV or JSONL export: object_type, object_id, owner (or owners,
           ``|``-separated for joint accounts). Read once, refreshed when the file changes.
    http   ``AEGIS_OWNERSHIP_URL`` — ``GET {url}?type=<object_type>&id=<object_id>`` →
           ``{"owners": [...]}`` (or ``{"owner": ...}``), ``AEGIS_OWNERSHIP_TOKEN`` as bearer;
           cached (LRU + TTL), short timeout, a failure is "unknown" — never "mismatch".
    none   no source: the detector still works on behaviour alone (distinct objects, sequential
           ids, not-found ratio) but can only say *suspicious*, never *confirmed*.

The owner identifier must be in the same namespace as the principal the gateway logs (the
JWT ``sub`` / CIF / consumer id). ``AEGIS_BOLA_EXEMPT_PRINCIPALS`` lists staff tools and
service principals that legitimately read other customers' objects.
"""

from __future__ import annotations

import csv
import fnmatch
import json
import logging
import os
import threading
import time
import urllib.parse
import urllib.request
from collections import OrderedDict
from pathlib import Path
from typing import Callable, Optional, Protocol

logger = logging.getLogger("aegis.api_abuse.ownership")


class OwnershipSource(Protocol):
    name: str

    def owners_of(self, object_type: str, object_id: str) -> Optional[frozenset[str]]:
        """Owners of the object, or ``None`` when unknown (never guessed)."""
        ...


class NoOwnership:
    name = "none"

    def owners_of(self, object_type: str, object_id: str) -> Optional[frozenset[str]]:
        return None


def _norm_type(t: str) -> str:
    t = str(t or "").strip().lower()
    return t[:-1] if t.endswith("s") and len(t) > 3 else t


class FileOwnership:
    """CSV (header: object_type, object_id, owner|owners) or JSONL with the same keys."""

    name = "file"

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._map: dict[tuple[str, str], frozenset[str]] = {}
        self._mtime = -1.0
        self._lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        try:
            mtime = self.path.stat().st_mtime
        except OSError as e:
            logger.warning("[ownership] %s unreadable (%s); owners unknown", self.path, e)
            return
        if mtime == self._mtime:
            return
        rows: dict[tuple[str, str], frozenset[str]] = {}
        bad = 0
        text = self.path.read_text(encoding="utf-8")
        if self.path.suffix.lower() in (".jsonl", ".json", ".ndjson"):
            records = []
            for line in text.splitlines():
                if line.strip():
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        bad += 1
        else:
            records = list(csv.DictReader(text.splitlines()))
        for r in records:
            if not isinstance(r, dict):
                bad += 1
                continue
            t, oid = r.get("object_type"), r.get("object_id")
            owners = r.get("owners") or r.get("owner")
            if isinstance(owners, str):
                owners = [o for o in owners.split("|") if o.strip()]
            if not (t and oid and owners):
                bad += 1
                continue
            rows[(_norm_type(t), str(oid).strip())] = frozenset(str(o).strip() for o in owners)
        with self._lock:
            self._map, self._mtime = rows, mtime
        if bad:
            logger.warning("[ownership] %s: %d malformed row(s) skipped", self.path, bad)
        logger.info("[ownership] %d object(s) loaded from %s", len(rows), self.path)

    def owners_of(self, object_type: str, object_id: str) -> Optional[frozenset[str]]:
        self._load()
        with self._lock:
            return self._map.get((_norm_type(object_type), str(object_id)))


class HttpOwnership:
    """Bank-provided lookup endpoint, cached. Failures are 'unknown', logged once a minute."""

    name = "http"

    def __init__(self, url: str, *, token: str = "", timeout: float = 1.5, ttl_s: float = 600.0, max_entries: int = 50_000,
                 fetch: Optional[Callable[[str, dict, float], dict]] = None, clock: Callable[[], float] = time.time):
        self.url = url.rstrip("?")
        self._headers = {"Authorization": f"Bearer {token}"} if token else {}
        self.timeout, self.ttl_s, self.max_entries = timeout, ttl_s, max_entries
        self._fetch = fetch or _http_get
        self._clock = clock
        self._cache: "OrderedDict[tuple[str, str], tuple[float, Optional[frozenset[str]]]]" = OrderedDict()
        self._lock = threading.Lock()
        self._last_warn = 0.0
        self.lookups = self.failures = 0
        # circuit breaker (review round 3 S3-20): while the resolver is down every gateway event waited up to
        # `timeout` per object on the ingest thread. After 3 failures in a row it is not called for 30 s (doubling
        # to 5 min); owners are "unknown" meanwhile, exactly as for a single failed lookup.
        self._fail_streak = 0
        self._open_until = 0.0
        self.skipped = 0

    def owners_of(self, object_type: str, object_id: str) -> Optional[frozenset[str]]:
        key = (_norm_type(object_type), str(object_id))
        now = self._clock()
        with self._lock:
            hit = self._cache.get(key)
            if hit and now - hit[0] < self.ttl_s:
                self._cache.move_to_end(key)
                return hit[1]
            if now < self._open_until:
                self.skipped += 1
                return None
        self.lookups += 1
        owners: Optional[frozenset[str]] = None
        try:
            q = urllib.parse.urlencode({"type": key[0], "id": key[1]})
            data = self._fetch(f"{self.url}?{q}", self._headers, self.timeout)
            raw = data.get("owners") if isinstance(data, dict) else None
            if raw is None and isinstance(data, dict) and data.get("owner"):
                raw = [data["owner"]]
            owners = frozenset(str(o) for o in raw) if raw else None
        except Exception as e:  # noqa: BLE001 — a slow or down resolver means "unknown", never a false mismatch
            self.failures += 1
            with self._lock:
                self._fail_streak += 1
                if self._fail_streak >= 3:
                    self._open_until = now + min(300.0, 30.0 * 2 ** (self._fail_streak - 3))
            if now - self._last_warn > 60:
                self._last_warn = now
                logger.warning("[ownership] lookup failed (%s: %s); treating owners as unknown%s", type(e).__name__,
                               str(e)[:120], " — resolver paused" if self._fail_streak >= 3 else "")
            return None
        with self._lock:
            self._fail_streak = 0
            self._cache[key] = (now, owners)
            while len(self._cache) > self.max_entries:
                self._cache.popitem(last=False)
        return owners


def _http_get(url: str, headers: dict, timeout: float) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json", **headers})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 — operator-configured resolver
        return json.loads(r.read() or b"{}")


class DictOwnership:
    """In-memory map — tests, the purple-team harness, small pilots."""

    name = "dict"

    def __init__(self, mapping: dict[tuple[str, str], str | list[str]]):
        self._map = {(_norm_type(t), str(i)): frozenset([o] if isinstance(o, str) else o) for (t, i), o in mapping.items()}

    def owners_of(self, object_type: str, object_id: str) -> Optional[frozenset[str]]:
        return self._map.get((_norm_type(object_type), str(object_id)))


def ownership_from_env() -> OwnershipSource:
    path = os.environ.get("AEGIS_OWNERSHIP_FILE", "").strip()
    url = os.environ.get("AEGIS_OWNERSHIP_URL", "").strip()
    if path:
        return FileOwnership(path)
    if url:
        return HttpOwnership(url, token=os.environ.get("AEGIS_OWNERSHIP_TOKEN", ""))
    return NoOwnership()


def exempt_principals() -> list[str]:
    """``AEGIS_BOLA_EXEMPT_PRINCIPALS`` — staff tools / service principals (globs allowed)."""
    return [p.strip() for p in os.environ.get("AEGIS_BOLA_EXEMPT_PRINCIPALS", "").split(",") if p.strip()]


def is_exempt(principal: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(principal, p) for p in patterns)


__all__ = ["OwnershipSource", "NoOwnership", "FileOwnership", "HttpOwnership", "DictOwnership", "ownership_from_env",
           "exempt_principals", "is_exempt"]
