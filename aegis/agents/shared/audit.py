"""Tamper-evident audit log for agent decisions.

Production: append-only WORM bucket / Splunk Frozen / S3 Object Lock.
Walking skeleton: append-only JSONL file with hash-chained entries
so any modification of an earlier entry breaks the chain.
"""
from __future__ import annotations

import logging
import hashlib
import json
import threading
from pathlib import Path
from typing import Optional

from .evidence_chain import EvidenceChain

logger = logging.getLogger("aegis.audit")


_LOCK = threading.Lock()


class AuditLog:
    def __init__(self, path: Path, sink=None):
        """``sink``: optional ``aegis.persist.DashboardSink`` — every appended
        chain is also shipped to the dashboard (roadmap 0.3). The JSONL file
        stays the local source of truth; the sink never blocks or raises."""
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._tail_hash = self._compute_tail_hash()
        self._sink = sink

    def _compute_tail_hash(self) -> str:
        if not self.path.exists():
            return "0" * 64
        last: Optional[dict] = None
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = json.loads(line)
        return last["integrity_hash"] if last else "0" * 64

    def append(self, chain: EvidenceChain) -> EvidenceChain:
        with _LOCK:
            chain.finalize()
            payload = chain.model_dump(mode="json", exclude={"integrity_hash"})
            serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            h = hashlib.sha256((self._tail_hash + serialized).encode("utf-8")).hexdigest()
            chain.integrity_hash = h
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(chain.model_dump(mode="json")) + "\n")
            prev = self._tail_hash
            self._tail_hash = h
        if self._sink is not None:
            try:
                self._sink.ship_chain(chain, prev_hash=prev)
            except Exception as exc:  # noqa: BLE001 — persistence must never break the investigation
                logger.warning("[audit] chain %s not shipped to the dashboard (%s: %s); local audit log is still authoritative", getattr(chain, "alert_id", "?"), type(exc).__name__, str(exc)[:120])
        return chain

    def verify(self) -> bool:
        prev = "0" * 64
        if not self.path.exists():
            return True
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                entry = json.loads(line)
                claimed = entry.pop("integrity_hash")
                serialized = json.dumps(entry, sort_keys=True, separators=(",", ":"))
                actual = hashlib.sha256((prev + serialized).encode("utf-8")).hexdigest()
                if actual != claimed:
                    return False
                prev = claimed
        return True
