"""Alerts set aside for a person: they could not be handled for a reason that will not clear by itself.

One writer for every place that gives up on an alert (an alert that cannot be sealed, an alert that crashed the
process too often, a handler bug). Each used to log the id and drop the body, or write next to the process's
working directory. The file is private (0600, never through a symlink) because rows are kept as received —
re-sending one needs the original alert, credentials included.

``AEGIS_DEAD_LETTER``: the file. Default: beside ``AEGIS_CHECKPOINT`` when that is set, else the private state
directory (``$STATE_DIRECTORY`` / ``~/.local/state/aegis``) — never the working directory.
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any

from .deferred import _restrict_to_owner

logger = logging.getLogger("aegis.ops.dead_letter")
_lock = threading.Lock()
written = 0


def path() -> Path:
    v = os.environ.get("AEGIS_DEAD_LETTER", "").strip()
    if v:
        return Path(v)
    cp = os.environ.get("AEGIS_CHECKPOINT", "").strip()
    if cp:
        return Path(cp).parent / "dead-letter.jsonl"
    from .deferred import _private_state_dir
    return _private_state_dir() / "dead-letter.jsonl"


def write(alert: Any, reason: str) -> bool:
    """Append ``alert`` with why it was set aside. True when it is on disk."""
    global written
    try:
        p = path()
        p.parent.mkdir(parents=True, exist_ok=True)
        row = {**(alert if isinstance(alert, dict) else {"raw": str(alert)[:100_000]}),
               "dead_lettered_at": time.time(), "dead_letter_reason": str(reason)[:300]}
        data = (json.dumps(row, default=str) + "\n").encode()
        with _lock:
            fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                _restrict_to_owner(fd, p)
                start = os.lseek(fd, 0, os.SEEK_END)
                try:
                    view = memoryview(data)
                    while view:
                        view = view[os.write(fd, view):]
                except OSError:
                    with contextlib.suppress(OSError):
                        os.ftruncate(fd, start)
                    raise
            finally:
                os.close(fd)
            written += 1
        logger.error("[dead-letter] alert %s set aside in %s: %s", row.get("id"), p, str(reason)[:160])
        return True
    except OSError as e:
        logger.error("[dead-letter] alert %s could not be set aside (%s): %s — re-send it from its source",
                     alert.get("id") if isinstance(alert, dict) else "?", e, str(reason)[:120])
        return False
