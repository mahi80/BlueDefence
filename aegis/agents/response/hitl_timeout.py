"""Timeout policy for pending HITL approvals — the few-analyst fallback.

When a containment action has been waiting on a human longer than its window and no
decision has come, this decides what happens. The rule is **tally x reversibility**,
tuned so a short-staffed SOC keeps moving without a human rubber-stamping the
irreversible calls:

  * a REVERSIBLE action (block / block_egress / throttle / challenge) AND the reviewer
    panel reached a majority concur (``chain.metadata.vote_concur`` is not ``False``)
    AND confidence >= floor  ->  auto-execute on timeout;
  * anything else — an irreversible / high-blast action (isolate, revoke_sessions,
    lock_account, rotate_credential, kill_process, ...), a tie or majority-dissent
    vote, or low confidence  ->  HOLD and escalate; never auto-executed without a human.

So unanimity/clear cases keep moving and only genuine disagreement — or an action you
cannot take back — reaches an analyst. This is the time-triggered complement to
``autonomy.py`` (which auto-blocks at detection time); it reuses the same posture that
containment is never auto, and the same reversible-only, shadow-first discipline.

Modes mirror ``AEGIS_AUTO_BLOCK`` and default **off**, so nothing changes unless armed:
    off     (default) a timed-out approval expires as before — dropped, and a human
            stays the only way it runs;
    shadow  an eligible action is logged as "would auto-execute on timeout" and still
            held for a human — the shadow log scores the policy against their calls;
    live    an eligible action runs now through ``ResponseAgent.approve`` (which still
            applies the never-block guard, the two-person rule on protected targets and
            the high-impact rate cap), dry-run if the connector itself is in shadow.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Callable


# Reversible, low-blast containment that is safe to auto-apply on a timeout — each is
# undoable (an edge/IP block, egress block, throttle or challenge can be lifted).
# Deliberately NOT here: isolate, revoke_sessions, lock_account, rotate_credential,
# kill_process, force_logout, quarantine_* and the rest — those hold for a human even on
# timeout, matching autonomy.py ("containment ... always a human").
_REVERSIBLE = frozenset({"block", "block_egress", "throttle", "challenge"})

# evaluate() outcomes
HOLD = "hold"        # keep waiting / escalate — never auto-acts
SHADOW = "shadow"    # eligible, but record-only; still held for a human
EXECUTE = "execute"  # eligible and armed — run it now


def _flag(name: str, default: str) -> str:
    return os.environ.get(name, default).strip()


@dataclass
class HitlTimeoutPolicy:
    mode: str = "off"            # off | shadow | live
    wait_sec: int = 120          # how long an action waits before the fallback can fire
    min_confidence: float = 0.6
    clock: Callable[[], float] = time.time

    @classmethod
    def from_env(cls) -> "HitlTimeoutPolicy":
        raw = _flag("AEGIS_HITL_TIMEOUT", "off").lower()
        mode = ("off" if raw in ("0", "false", "off", "no", "")
                else "live" if raw in ("live", "1", "on", "true")
                else "shadow")
        return cls(mode=mode,
                   wait_sec=int(_flag("AEGIS_HITL_TIMEOUT_SEC", "120")),
                   min_confidence=float(_flag("AEGIS_HITL_TIMEOUT_MIN_CONF", "0.6")))

    def evaluate(self, action: Any, chain: Any, *, age_sec: float) -> tuple[str, str]:
        """Return ``(decision, reason)`` — decision is HOLD, SHADOW or EXECUTE.

        HOLD means keep waiting for a human (and, on hard expiry, escalate); the action
        is never auto-executed. Only a reversible action, past its wait window, with a
        majority-concur vote and adequate confidence, is eligible.
        """
        if self.mode == "off":
            return HOLD, "timeout policy off"
        if age_sec < self.wait_sec:
            return HOLD, f"within the {self.wait_sec}s wait window"

        atype = str(getattr(action, "action_type", ""))
        if atype not in _REVERSIBLE:
            return HOLD, f"{atype or 'action'} is irreversible / high-blast — holds for a human even on timeout"

        md = getattr(chain, "metadata", {}) or {}
        if md.get("vote_concur") is not True:
            # tie, majority dissent, or no recorded vote at all (a card restored from an old journal, a verdict
            # the swarm raised without a fresh concur) -> a human, not a timer
            tally = md.get("vote_tally")
            why = "no concurring vote on record" if md.get("vote_concur") is None else "reviewer panel did not reach a majority concur"
            return HOLD, f"{why}{f' ({tally})' if tally else ''} — escalate, don't auto-act"

        conf = float(getattr(chain, "confidence", 0.0) or 0.0)
        if conf < self.min_confidence:
            return HOLD, f"confidence {conf:.2f} below the {self.min_confidence:.2f} floor"

        if self.mode == "shadow":
            return SHADOW, f"would auto-execute {atype} on timeout ({int(age_sec)}s, no human)"
        return EXECUTE, f"auto-executing reversible {atype} on HITL timeout ({int(age_sec)}s, no human)"


__all__ = ["HitlTimeoutPolicy", "HOLD", "SHADOW", "EXECUTE"]
