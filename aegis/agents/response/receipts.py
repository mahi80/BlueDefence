"""Receipt log — every enforcement receipt, locally and (optionally) in the dashboard.

Roadmap 1.5: shadow mode only means something if the "would have done"
receipts are kept somewhere they can be compared with what the SOC actually
decided. ``ReceiptLog`` subscribes to the ``ConnectorRegistry`` and appends one
JSONL line per receipt event (``apply`` / ``rollback`` / ``expired``) on the
agent host; with a ``DashboardSink`` it also ships each event to
``POST /api/soc/receipts`` (upsert on ``receipt_id``). ``python -m aegis.shadow``
reads either side and builds the comparison.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

from .connectors.base import Receipt

logger = logging.getLogger("aegis.receipts")

DEFAULT_RECEIPTS_FILENAME = "_receipts.jsonl"


def receipt_mode(receipt: Receipt | dict) -> str:
    """``log`` (logging fallback, touches nothing) · ``shadow`` (vendor connector, dry-run) · ``live`` ·
    ``auto-shadow`` (a block tiered autonomy would have run on its own — scored against the human's call)."""
    connector = receipt.connector if isinstance(receipt, Receipt) else str(receipt.get("connector", ""))
    dry_run = receipt.dry_run if isinstance(receipt, Receipt) else bool(receipt.get("dry_run"))
    approver = receipt.approver if isinstance(receipt, Receipt) else str(receipt.get("approver", ""))
    if connector == "log":
        return "log"
    if approver == "aegis:auto-shadow":
        return "auto-shadow"       # what tiered autonomy would have auto-blocked (scored separately)
    return "shadow" if dry_run else "live"


class ReceiptLog:
    """Append-only JSONL of receipt events; optional dashboard sink."""

    def __init__(self, path: Path | str, sink: Any = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._sink = sink
        self._lock = threading.Lock()
        self.events = 0
        self.shipped = 0

    def __call__(self, event: str, receipt: Receipt) -> None:
        entry = {"event": event, "recorded_at": time.time(), "mode": receipt_mode(receipt), **receipt.to_dict()}
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
            self.events += 1
        if self._sink is not None and getattr(self._sink, "enabled", False):
            try:
                self._sink.ship_receipt(receipt, event)
                self.shipped += 1
            except Exception as e:  # noqa: BLE001 — the local line is the record of truth
                logger.warning("[receipts] ship failed: %s", str(e)[:120])

    @staticmethod
    def read(path: Path | str) -> Iterator[dict]:
        p = Path(path)
        if not p.exists():
            return iter(())
        return _iter_jsonl(p)

    @staticmethod
    def latest_per_receipt(entries: Iterable[dict]) -> list[dict]:
        """Collapse the event stream to the last known state of each receipt."""
        latest: dict[str, dict] = {}
        order: list[str] = []
        for e in entries:
            rid = str(e.get("receipt_id") or "")
            if not rid:
                continue
            if rid not in latest:
                order.append(rid)
            latest[rid] = e
        return [latest[r] for r in order]


def _iter_jsonl(p: Path) -> Iterator[dict]:
    with p.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def receipt_log_from_env(default_dir: Path | str, sink: Any = None) -> Optional[ReceiptLog]:
    """``AEGIS_RECEIPTS=0`` disables; ``AEGIS_RECEIPTS_PATH`` overrides the file (default ``<dir>/_receipts.jsonl``)."""
    if os.environ.get("AEGIS_RECEIPTS", "1").strip().lower() in {"0", "false", "no", "off"}:
        return None
    path = os.environ.get("AEGIS_RECEIPTS_PATH", "").strip() or str(Path(default_dir) / DEFAULT_RECEIPTS_FILENAME)
    return ReceiptLog(path, sink=sink)
