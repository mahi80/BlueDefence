"""In-memory IOC store — the read side of the Threat Intel agent.

Other AEGIS agents already have local IOC matchers for performance
(perimeter/tools.py _KNOWN_BAD, edr/tools.py _IOC_HASHES /
_IOC_DOMAINS / _IOC_IPS). The Threat Intel agent's job is to keep
those local lists fresh by pulling from STIX/TAXII feeds, peer-bank
exchanges (FS-ISAC), and CISA KEV — and to provide a centralized
lookup_ioc() the LLM specialists can call.

The store is intentionally simple: an in-memory dict keyed by
(kind, value). Production swaps in:
  - Redis for shared state across multiple AEGIS instances
  - pgvector for similarity search on hash fragments
  - per-tenant namespaces if AEGIS is multi-tenant

Thread-safe under GIL semantics for the dict; concurrent updates use
a coarse lock since the IOC count is small (thousands, not millions).
"""
from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field, replace
from typing import Iterable, Literal, Optional

from .validate import clamp_confidence, normalise

_log = logging.getLogger("aegis.threat_intel")


IocKind = Literal[
    "ip", "domain", "url", "hash_md5", "hash_sha256",
    "email", "asn", "cve", "config",
]


@dataclass(frozen=True)
class IOC:
    kind: IocKind
    value: str
    confidence: float = 0.85   # 0-1; how sure are we this is malicious
    source: str = "unknown"    # feed identifier
    first_seen: float = 0.0    # epoch seconds
    last_seen: float = 0.0
    tags: tuple[str, ...] = ()
    ttl_seconds: int = 86400 * 14   # default 14-day expiry


@dataclass
class IOCStoreStats:
    by_kind: dict[str, int] = field(default_factory=dict)
    by_source: dict[str, int] = field(default_factory=dict)
    expired: int = 0
    total: int = 0


LLM_TAG = "llm-extracted"


class IOCStore:
    def __init__(self):
        self._iocs: dict[tuple[str, str], IOC] = {}
        self._lock = threading.Lock()
        self.rejected = 0
        # what this store pushed into the peer agents' matchers, so expired / removed entries can be taken back
        # out (the seed entries those modules ship with are never touched)
        self._pushed_perimeter: set[str] = set()
        self._pushed_edr: dict[str, set[str]] = {"hash_md5": set(), "domain": set(), "ip": set()}

    def add(self, ioc: IOC) -> bool:
        """Validate, normalise and store. Returns False (and stores nothing) for a rejected indicator: an
        unknown kind, a malformed value, or the bank's own address space / domains — see ``validate.py``."""
        value, why = normalise(ioc.kind, ioc.value)
        conf = clamp_confidence(ioc.confidence)
        if value is None or conf is None:
            self.rejected += 1
            _log.info("[threat_intel] rejected IOC %s %r from %s: %s", ioc.kind, str(ioc.value)[:80], ioc.source,
                      why or "confidence is not a number")
            return False
        ttl = max(60, min(int(ioc.ttl_seconds or 0) or 86400 * 14, 86400 * 365))
        ioc = replace(ioc, value=value, confidence=conf, ttl_seconds=ttl)
        with self._lock:
            key = (ioc.kind, ioc.value)
            existing = self._iocs.get(key)
            now = time.time()
            if existing is not None:
                # Merge: keep the higher confidence + extend last_seen
                merged = IOC(
                    kind=ioc.kind, value=ioc.value,
                    confidence=max(ioc.confidence, existing.confidence),
                    source=ioc.source if ioc.confidence > existing.confidence else existing.source,
                    first_seen=existing.first_seen or now,
                    last_seen=now,
                    tags=tuple(set(existing.tags) | set(ioc.tags)),
                    ttl_seconds=max(ioc.ttl_seconds, existing.ttl_seconds),
                )
                self._iocs[key] = merged
            else:
                self._iocs[key] = IOC(
                    kind=ioc.kind, value=ioc.value,
                    confidence=ioc.confidence, source=ioc.source,
                    first_seen=ioc.first_seen or now,
                    last_seen=ioc.last_seen or now,
                    tags=ioc.tags, ttl_seconds=ioc.ttl_seconds,
                )
        return True

    def add_many(self, iocs: Iterable[IOC]) -> int:
        """Returns how many were accepted."""
        return sum(1 for ioc in iocs if self.add(ioc))

    def lookup(self, value: str, kind: Optional[IocKind] = None) -> Optional[IOC]:
        """Return the IOC if present and not expired. Honors TTL."""
        now = time.time()
        if kind is not None:
            value = normalise(kind, value)[0] or value          # same canonical form the store keeps
        with self._lock:
            if kind is not None:
                ioc = self._iocs.get((kind, value))
                if ioc and (now - ioc.last_seen) < ioc.ttl_seconds:
                    return ioc
                return None
            # No kind specified — search across all kinds
            for (k, v), ioc in self._iocs.items():
                if v == value and (now - ioc.last_seen) < ioc.ttl_seconds:
                    return ioc
        return None

    def all_active(self) -> list[IOC]:
        now = time.time()
        with self._lock:
            return [
                ioc for ioc in self._iocs.values()
                if (now - ioc.last_seen) < ioc.ttl_seconds
            ]

    def prune(self) -> int:
        """Drop expired entries. Returns count removed."""
        now = time.time()
        with self._lock:
            stale = [
                key for key, ioc in self._iocs.items()
                if (now - ioc.last_seen) >= ioc.ttl_seconds
            ]
            for k in stale:
                del self._iocs[k]
            return len(stale)

    def stats(self) -> IOCStoreStats:
        s = IOCStoreStats()
        now = time.time()
        with self._lock:
            for ioc in self._iocs.values():
                if (now - ioc.last_seen) >= ioc.ttl_seconds:
                    s.expired += 1
                    continue
                s.total += 1
                s.by_kind[ioc.kind] = s.by_kind.get(ioc.kind, 0) + 1
                s.by_source[ioc.source] = s.by_source.get(ioc.source, 0) + 1
        return s

    # ---- distribution to peer agents -----------------------------------

    def _distributable(self) -> list[IOC]:
        """Active IOCs that may reach the hot-path matchers. LLM-extracted indicators (read from untrusted
        advisory text) stay in the store as evidence for lookups but are not pushed into blocklist-style
        matchers unless the operator opts in with ``AEGIS_TI_MERGE_LLM_IOCS=1``."""
        allow_llm = os.environ.get("AEGIS_TI_MERGE_LLM_IOCS", "0") == "1"
        self.prune()
        return [i for i in self.all_active() if allow_llm or LLM_TAG not in i.tags]

    def merge_into_perimeter(self) -> int:
        """Sync 'ip' IOCs into perimeter/tools._KNOWN_BAD so the perimeter agent's hot-path matcher sees
        fresh IPs without calling back here. Entries this store pushed earlier that have since expired are
        removed again. Returns count added."""
        from aegis.agents.perimeter import tools as p

        want = {i.value: i for i in self._distributable() if i.kind == "ip"}
        merged = 0
        for ip in list(self._pushed_perimeter - set(want)):
            p._KNOWN_BAD.pop(ip, None)
            self._pushed_perimeter.discard(ip)
        for ip, ioc in want.items():
            if ip in p._KNOWN_BAD and ip not in self._pushed_perimeter:
                continue                                     # a seed / operator entry: leave it alone
            if ip not in p._KNOWN_BAD:
                merged += 1
            p._KNOWN_BAD[ip] = {
                "abuse_score": int(ioc.confidence * 100),
                "categories": [t for t in ioc.tags if t != LLM_TAG] or ["threat-intel"],
                "tor_exit": False,
            }
            self._pushed_perimeter.add(ip)
        return merged

    def merge_into_edr(self) -> int:
        """Sync hash + domain + ip IOCs into edr/tools.* matchers, removing ones this store pushed that have
        since expired. Returns count added."""
        from aegis.agents.edr import tools as e

        want: dict[str, dict[str, IOC]] = {"hash_md5": {}, "domain": {}, "ip": {}}
        for ioc in self._distributable():
            if ioc.kind in want:
                want[ioc.kind][ioc.value] = ioc
        targets = {"hash_md5": e._IOC_HASHES, "domain": e._IOC_DOMAINS, "ip": e._IOC_IPS}
        merged = 0
        for kind, target in targets.items():
            pushed = self._pushed_edr[kind]
            for v in list(pushed - set(want[kind])):
                if isinstance(target, dict):
                    target.pop(v, None)
                else:
                    target.discard(v)
                pushed.discard(v)
            for v, ioc in want[kind].items():
                if v in target and v not in pushed:
                    continue
                if v not in target:
                    merged += 1
                if isinstance(target, dict):
                    target[v] = ", ".join(t for t in ioc.tags if t != LLM_TAG) or ioc.source
                else:
                    target.add(v)
                pushed.add(v)
        return merged
