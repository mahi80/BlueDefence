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

import threading
import time
from dataclasses import dataclass, field
from typing import Iterable, Literal, Optional


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


class IOCStore:
    def __init__(self):
        self._iocs: dict[tuple[str, str], IOC] = {}
        self._lock = threading.Lock()

    def add(self, ioc: IOC) -> None:
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

    def add_many(self, iocs: Iterable[IOC]) -> int:
        n = 0
        for ioc in iocs:
            self.add(ioc)
            n += 1
        return n

    def lookup(self, value: str, kind: Optional[IocKind] = None) -> Optional[IOC]:
        """Return the IOC if present and not expired. Honors TTL."""
        now = time.time()
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

    def merge_into_perimeter(self) -> int:
        """Push 'ip' IOCs into perimeter/tools._KNOWN_BAD so the
        perimeter agent's hot-path matcher sees fresh IPs without needing
        to call back here. Returns count merged.
        """
        from aegis.agents.perimeter import tools as p

        merged = 0
        for ioc in self.all_active():
            if ioc.kind == "ip" and ioc.value not in p._KNOWN_BAD:
                p._KNOWN_BAD[ioc.value] = {
                    "abuse_score": int(ioc.confidence * 100),
                    "categories": list(ioc.tags) or ["threat-intel"],
                    "tor_exit": False,
                }
                merged += 1
        return merged

    def merge_into_edr(self) -> int:
        """Push hash + domain + ip IOCs into edr/tools.* matchers."""
        from aegis.agents.edr import tools as e

        merged = 0
        for ioc in self.all_active():
            if ioc.kind == "hash_md5" and ioc.value not in e._IOC_HASHES:
                e._IOC_HASHES[ioc.value] = ", ".join(ioc.tags) or ioc.source
                merged += 1
            elif ioc.kind == "domain" and ioc.value not in e._IOC_DOMAINS:
                e._IOC_DOMAINS.add(ioc.value)
                merged += 1
            elif ioc.kind == "ip" and ioc.value not in e._IOC_IPS:
                e._IOC_IPS.add(ioc.value)
                merged += 1
        return merged
