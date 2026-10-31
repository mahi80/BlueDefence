"""HITL over two JSONL files — the no-dependency transport for AEGIS External, air-gapped hosts and tests.

    cards.jsonl      one line per approval request (what the analyst sees)
    decisions.jsonl  the analyst (or any ticketing glue) appends ``{"approval_id": ..., "status": "approved"|"rejected",
                     "decided_by": ..., "reason": ...}``; the next cycle executes approved ones
    cards.jsonl is also appended with ``{"kind": "investigation", ...}`` when the async tier finishes

Optional Slack notification per card (``AEGIS_SLACK_WEBHOOK``) — notify-only; decisions still come
from the file (or ServiceNow), never from chat.

    AEGIS_HITL_TRANSPORT=file   AEGIS_HITL_DIR=/var/lib/aegis/hitl
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.request
from pathlib import Path
from typing import Any, Callable, Optional

from .base import BaseHITL, PendingApproval

logger = logging.getLogger("aegis.hitl.file")


def _slack_post(url: str, payload: dict, timeout: float) -> None:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout):  # noqa: S310 — operator-configured webhook
        pass


class FileHITL(BaseHITL):
    name = "file"

    def __init__(self, directory: Optional[str | Path] = None, *, slack_webhook: Optional[str] = None,
                 slack_post: Optional[Callable[[str, dict, float], None]] = None, timeout: float = 5.0,
                 state_path: Optional[str | Path] = None):
        super().__init__(state_path=state_path)
        self.dir = Path(directory or os.environ.get("AEGIS_HITL_DIR") or Path.cwd() / ".aegis-hitl")
        self.cards = self.dir / "cards.jsonl"
        self.decisions_file = self.dir / "decisions.jsonl"
        self.slack_webhook = slack_webhook if slack_webhook is not None else os.environ.get("AEGIS_SLACK_WEBHOOK", "")
        self._slack = slack_post or _slack_post
        self.timeout = timeout
        self._consumed = 0          # byte offset into decisions.jsonl

    def _journal_dir(self) -> Optional[Path]:
        return self.dir

    def _append(self, path: Path, row: dict) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    def _file(self, card: dict) -> Optional[str]:
        self._append(self.cards, {"kind": "approval", "ts": time.time(), **card})
        if self.slack_webhook:
            a = card["args"]
            try:
                self._slack(self.slack_webhook, {"text": (f":rotating_light: AEGIS needs a decision — *{card['action']}* on alert `{a['alert_id']}` "
                                                          f"({a['verdict']}, conf {a['chain_confidence']}). {a['reasoning'][:200]}\n"
                                                          f"Approve/reject: append to {self.decisions_file} with approval_id `{card['id']}`")}, self.timeout)
            except Exception as e:  # noqa: BLE001 — Slack is notify-only; the card is already on disk
                logger.warning("[hitl:file] slack notify failed for %s: %s", card["id"], str(e)[:120])
        return card["id"]

    def _read_new_decisions(self) -> dict[str, dict]:
        out: dict[str, dict] = {}
        if not self.decisions_file.exists():
            return out
        with self.decisions_file.open("r", encoding="utf-8") as f:
            f.seek(self._consumed)
            for line in f:
                if not line.strip():
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    logger.warning("[hitl:file] malformed decision line skipped: %s", line[:80]); continue
                if isinstance(d, dict) and d.get("approval_id"):
                    out[str(d["approval_id"])] = d
            self._consumed = f.tell()
        self._buffered = {**getattr(self, "_buffered", {}), **out}
        return self._buffered

    def _poll(self, p: PendingApproval) -> Optional[tuple[str, str, str]]:
        d = self._read_new_decisions().pop(p.approval_id, None)
        if not d:
            return None
        status = str(d.get("status", "")).lower()
        if status not in ("approved", "rejected"):
            logger.warning("[hitl:file] decision for %s has unknown status %r; ignored", p.approval_id, status); return None
        return status, str(d.get("decided_by") or "file"), str(d.get("reason") or "")[:500]

    def _annotate(self, p: PendingApproval, card: dict) -> bool:
        self._append(self.cards, {"kind": "investigation", "ts": time.time(), "approval_id": p.approval_id, "alert_id": p.alert_id, "investigation": card})
        return True


__all__ = ["FileHITL"]
