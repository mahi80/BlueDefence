"""Tiered autonomy — which blocks run without waiting for a human.

Against an automated attacker, minutes of approval latency is the whole fight. But a
wrong block on a bank's customer is expensive. The middle ground: a **short, self-expiring**
block on a narrow, external target runs at machine speed when the evidence is strong; anything
wide, internal, protected, low-confidence or disputed still waits for a human.

A ``block`` runs automatically only when **all** hold:
    verdict ``malicious`` and chain confidence ≥ ``AEGIS_AUTO_BLOCK_MIN_CONF`` (0.90)
    the independent voter did not dissent (``metadata.vote_concur`` is not False)
    target is a public IP, a CIDR no wider than /24 (IPv4) or /48 (IPv6), or a TLS
        fingerprint **paired with an exact, non-browser user agent** (a bare JA4, or one
        with a ``Mozilla/`` user agent, is never auto-blocked — it could be customers)
    target is not in ``AEGIS_PROTECTED_TARGETS`` and the fingerprint not in ``AEGIS_FP_ALLOW``
    fewer than ``AEGIS_AUTO_BLOCK_MAX_PER_HOUR`` (50) auto-blocks in the last hour
and it is applied with TTL ``AEGIS_AUTO_BLOCK_TTL`` (900 s) — the connector rolls it back.

``AEGIS_AUTO_BLOCK`` has its own mode, separate from ``AEGIS_ENFORCEMENT_MODE`` (flipping
challenge / throttle live must not silently make blocks autonomous):
    off     blocks always wait for a human
    shadow  (default) an eligible block is recorded as a "would have auto-blocked" receipt and
            still goes to a human — the shadow report scores auto-block against their decisions
    live    an eligible block runs now with the TTL (still dry-run if the connector is in shadow)
Containment (isolate, revoke, lock, rotate) is never in scope here — always a human.
"""

from __future__ import annotations

import ipaddress
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable

from ..shared.fingerprint import allowed_fingerprints, is_fingerprint_target, parse_target


def _flag(name: str, default: str) -> str:
    return os.environ.get(name, default).strip()


@dataclass
class AutonomyPolicy:
    mode: str = "shadow"            # off | shadow | live
    min_confidence: float = 0.90
    ttl_sec: int = 900
    max_per_hour: int = 50
    clock: Callable[[], float] = time.time
    _recent: deque = field(default_factory=deque)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @classmethod
    def from_env(cls) -> "AutonomyPolicy":
        raw = _flag("AEGIS_AUTO_BLOCK", "shadow").lower()
        mode = "off" if raw in ("0", "false", "off", "no") else "live" if raw in ("live", "1", "on", "true") else "shadow"
        return cls(mode=mode,
                   min_confidence=float(_flag("AEGIS_AUTO_BLOCK_MIN_CONF", "0.90")),
                   ttl_sec=int(_flag("AEGIS_AUTO_BLOCK_TTL", "900")),
                   max_per_hour=int(_flag("AEGIS_AUTO_BLOCK_MAX_PER_HOUR", "50")))

    def check(self, action: Any, chain: Any, *, protected: Callable[[str], bool]) -> tuple[bool, str]:
        """(eligible, reason). Does not consume budget — call ``take()`` when acting."""
        if self.mode == "off":
            return False, "auto-block off"
        if action.action_type != "block":
            return False, "only block is in scope"
        if chain.verdict != "malicious" or chain.confidence < self.min_confidence:
            return False, f"needs malicious ≥ {self.min_confidence:.2f} (got {chain.verdict} {chain.confidence:.2f})"
        if (chain.metadata or {}).get("vote_concur") is False:
            return False, "independent reviewer dissented"
        target = str(action.target)
        ok, why = _narrow_external(target)
        if not ok:
            return False, why
        if protected(target):
            return False, "protected target"
        with self._lock:
            self._expire()
            if len(self._recent) >= self.max_per_hour:
                return False, f"auto-block budget spent ({self.max_per_hour}/h)"
        return True, f"auto-block ({self.mode}), TTL {self.ttl_sec}s"

    def take(self) -> None:
        with self._lock:
            self._recent.append(self.clock())

    def _expire(self) -> None:
        cutoff = self.clock() - 3600
        while self._recent and self._recent[0] < cutoff:
            self._recent.popleft()


#: never auto-blocked: the bank's own and carrier-internal space. (Python's ``is_global`` would also
#: exclude the RFC 5737 documentation ranges, which the sandbox fixtures use; those never appear in
#: real traffic, so they are treated as external here.)
_INTERNAL = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4", "::1/128", "::/128", "fc00::/7", "fe80::/10", "ff00::/8")]


def _internal(net) -> bool:
    return any(net.version == n.version and net.subnet_of(n) for n in _INTERNAL)


def _narrow_external(target: str) -> tuple[bool, str]:
    if is_fingerprint_target(target):
        try:
            kind, value, ua = parse_target(target)
        except ValueError:
            return False, "malformed fingerprint target"
        if kind not in ("ja4", "ja3"):
            return False, "header fingerprints are correlation-only"
        if not ua:
            return False, "a bare TLS fingerprint is shared by real browsers — challenge it, never auto-block"
        if value in allowed_fingerprints():
            return False, "fingerprint on AEGIS_FP_ALLOW"
        if ua.startswith("Mozilla/"):
            return False, "browser user agent — a fingerprint block could hit customers"
        return True, ""
    try:
        net = ipaddress.ip_network(target.strip(), strict=False)
    except ValueError:
        return False, "not an IP, CIDR or fingerprint"
    if _internal(net):
        return False, "internal / reserved address — never auto-blocked"
    if net.prefixlen < (24 if net.version == 4 else 48):
        return False, f"/{net.prefixlen} is wider than auto-block allows"
    return True, ""


__all__ = ["AutonomyPolicy"]
