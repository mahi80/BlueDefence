"""systemd ``sd_notify`` without the C library: READY / WATCHDOG / STOPPING over NOTIFY_SOCKET.

With ``Type=notify`` and ``WatchdogSec=`` in the unit, systemd restarts the service if it stops pinging — a
hung model call or a deadlocked loop no longer looks "active (running)" forever. Every call is a no-op when
NOTIFY_SOCKET is unset (dev, docker, the smoke test), and never raises.
"""
from __future__ import annotations

import os
import socket
import time

_sock: socket.socket | None = None
_last = 0.0


def enabled() -> bool:
    return bool(os.environ.get("NOTIFY_SOCKET"))


def _send(msg: str) -> bool:
    global _sock
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return False
    try:
        if _sock is None:
            _sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        _sock.sendto(msg.encode(), ("\0" + addr[1:]) if addr.startswith("@") else addr)
        return True
    except OSError:
        return False


def ready(status: str = "") -> bool:
    return _send("READY=1" + (f"\nSTATUS={status}" if status else ""))


def status(text: str) -> bool:
    return _send(f"STATUS={text[:200]}")


def stopping() -> bool:
    return _send("STOPPING=1")


def watchdog(min_interval_s: float = 1.0) -> bool:
    """Ping at most every ``min_interval_s`` (cheap enough to call from any loop)."""
    global _last
    now = time.time()
    if now - _last < min_interval_s:
        return False
    _last = now
    return _send("WATCHDOG=1")


def watchdog_interval_s() -> float | None:
    """Half of WatchdogSec (systemd's recommendation) when the unit set one, else None."""
    usec = os.environ.get("WATCHDOG_USEC")
    try:
        return int(usec) / 1_000_000 / 2 if usec else None
    except ValueError:
        return None
