"""Outflow circuit breaker — the one payment hold that does not wait for a human.

A drain by a compromised payment signer moves at machine speed (the Oct 2026 Binance outflows: ~USD
6.3B in ~20 minutes). ``hold`` is always human-approved, and that is right for a single suspicious
transfer. It is wrong for a drain already in progress: by the time an analyst opens the card, the
money is gone. The breaker is the narrow exception, built like tiered auto-block
(``autonomy.py``): a ``hold`` runs without waiting only when **all** hold:

    the outflow guard saw a burst — AEGIS_OUTFLOW_BURST_N high-value transfers to new beneficiaries
        from one sender inside the window (``metadata.outflow_breaker``) — not a single transfer
    the target is ``outbound:<sender>`` — a hold on the sender's further payments, nothing wider
    verdict ``malicious`` and confidence >= AEGIS_OUTFLOW_BREAKER_MIN_CONF (0.90)
    the independent voter did not dissent (``metadata.vote_concur`` is True, or the chain came from a deterministic builder with no model to vote on)
    fewer than AEGIS_OUTFLOW_BREAKER_MAX_PER_HOUR (5) breaker holds in the last hour

and it is applied with TTL ``AEGIS_OUTFLOW_BREAKER_TTL`` (3600 s). The human still gets the card —
to keep the hold or release it — and the fraud team still gets the recall escalation.

``AEGIS_OUTFLOW_BREAKER``:
    off     every hold waits for a human
    shadow  (default) an eligible hold is recorded as a "would have held" receipt and still goes to a
            human — the shadow window measures the breaker before anyone trusts it
    live    an eligible hold runs now (still dry-run if the connector is in shadow)
"""

from __future__ import annotations

import math
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable


def _flag(name: str, default: str) -> str:
    return os.environ.get(name, default).strip()



def _concurred(chain: Any) -> bool:
    """The voter concurred, or no model decided this chain (a deterministic fast-path builder). A model chain with
    no vote on record is not consent (review round 3 G1-15)."""
    from .contracts import DETERMINISTIC_BUILDERS
    md = getattr(chain, "metadata", None) or {}
    if md.get("vote_concur") is True:
        return True
    return md.get("vote_concur") is None and (md.get("deterministic") is True
                                              or str(getattr(chain, "investigated_by", "")) in DETERMINISTIC_BUILDERS)


def _min_conf(raw: str) -> float:
    """The breaker's floor: never below 0.85 (the moderate floor), never NaN — ``nan`` or ``0`` used to let a hold
    run at confidence 0.30 (review round 4 X4-6)."""
    try:
        v = float(raw)
    except (TypeError, ValueError):
        return 0.90
    return 0.90 if not math.isfinite(v) else min(1.0, max(0.85, v))


@dataclass
class OutflowBreaker:
    mode: str = "shadow"            # off | shadow | live
    min_confidence: float = 0.90
    ttl_sec: int = 3600
    max_per_hour: int = 5
    clock: Callable[[], float] = time.time
    _recent: deque = field(default_factory=deque)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @classmethod
    def from_env(cls) -> "OutflowBreaker":
        raw = _flag("AEGIS_OUTFLOW_BREAKER", "shadow").lower()
        mode = "off" if raw in ("0", "false", "off", "no") else "live" if raw in ("live", "1", "on", "true") else "shadow"
        return cls(mode=mode,
                   min_confidence=_min_conf(_flag("AEGIS_OUTFLOW_BREAKER_MIN_CONF", "0.90")),
                   ttl_sec=int(_flag("AEGIS_OUTFLOW_BREAKER_TTL", "3600")),
                   max_per_hour=int(_flag("AEGIS_OUTFLOW_BREAKER_MAX_PER_HOUR", "5")))

    def check(self, action: Any, chain: Any) -> tuple[bool, str]:
        """(eligible, reason). Does not consume budget — call ``take()`` when acting."""
        if self.mode == "off":
            return False, "outflow breaker off"
        if action.action_type != "hold":
            return False, "only hold is in scope"
        md = chain.metadata or {}
        if not md.get("outflow_breaker"):
            return False, "not a drain burst"
        if not str(action.target).startswith("outbound:"):
            return False, "only a hold on a sender's outbound payments is in scope"
        if chain.verdict != "malicious" or chain.confidence < self.min_confidence:
            return False, f"needs malicious ≥ {self.min_confidence:.2f} (got {chain.verdict} {chain.confidence:.2f})"
        if not _concurred(chain):
            return False, "independent reviewer dissented"
        with self._lock:
            self._expire()
            if len(self._recent) >= self.max_per_hour:
                return False, f"breaker budget spent ({self.max_per_hour}/h)"
        return True, f"outflow breaker ({self.mode}), TTL {self.ttl_sec}s"

    def take(self) -> None:
        with self._lock:
            self._recent.append(self.clock())

    def _expire(self) -> None:
        cutoff = self.clock() - 3600
        while self._recent and self._recent[0] < cutoff:
            self._recent.popleft()


__all__ = ["OutflowBreaker"]
