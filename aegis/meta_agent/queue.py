"""Hash-chained JSONL queue for meta-agent proposals.

Same tamper-evident pattern as aegis/agents/shared/audit.py. Every
queued proposal includes the proposal payload + the validator's
measurement, joined by a SHA-256 hash chain so any after-the-fact
tampering breaks integrity.

This is the ONLY artifact the meta-agent writes. Humans review entries
here and either accept (apply the change to the repo via PR) or
archive (mark the entry rejected with a reason).
"""
from __future__ import annotations

import logging
import hashlib
import json
import threading
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from .proposer import Proposal
from .validator import ValidationResult

logger = logging.getLogger("aegis.meta_agent.queue")


_LOCK = threading.Lock()


class ProposalQueue:
    def __init__(self, path: Path, sink=None):
        """``sink``: optional ``aegis.persist.DashboardSink`` — every queued
        entry is also shipped to the dashboard (roadmap 0.3) where the HITL
        decision is taken and audited. The JSONL file stays the local record."""
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

    def append(self, proposal: Proposal, validation: ValidationResult) -> str:
        with _LOCK:
            entry = {
                "proposal": asdict(proposal),
                "validation": asdict(validation),
                "status": "pending_hitl",
            }
            serialized = json.dumps(entry, sort_keys=True, separators=(",", ":"))
            h = hashlib.sha256((self._tail_hash + serialized).encode("utf-8")).hexdigest()
            entry["integrity_hash"] = h
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
            prev = self._tail_hash
            self._tail_hash = h
        if self._sink is not None:
            try:
                self._sink.ship_proposal(proposal, validation, h, prev_hash=prev, status="pending_hitl")
            except Exception as exc:  # noqa: BLE001 — persistence must never break the meta-agent run
                logger.warning("[meta_agent] proposal %s not shipped to the dashboard (%s: %s)", h[:12], type(exc).__name__, str(exc)[:120])
        return h

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

    def list_pending(self) -> list[dict]:
        if not self.path.exists():
            return []
        with self.path.open("r", encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]
