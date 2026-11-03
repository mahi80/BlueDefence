"""One contract per action type: what it can break, whether it can be undone, and who may run it.

Idea taken from AiSOC's capability contracts + approval matrix (MIT), written for this code base.

Before this, three hand-kept sets in ``agent.py`` decided everything — auto-safe, always-HITL, and "unknown
→ human" — and nothing tied them to each other or to the action list in ``evidence_chain.ActionType``. A
review found members of the always-HITL set that no test would miss (code review 2026-11-03, T7), and a
gate that judged an action by its type alone: a 40 %-confidence guess and a corroborated finding got the
same answer.

Now:

* every ``ActionType`` has a contract here (the test suite fails if one is missing), and the agent's
  auto-safe and always-HITL sets are *derived* from the contracts;
* an action that would run with no human must clear **all** of: its impact is within the operator's
  autonomy tier (``AEGIS_AUTONOMY_TIER``, L0–L4), the chain's confidence reaches the floor for that
  impact, and a protected target raises the impact one rank. Each input can only make the answer stricter.

The default tier is L4, which keeps today's behaviour; an operator dials autonomy *down* with it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, get_args


class Impact(IntEnum):
    READ_ONLY = 0      # changes nothing (allow, monitor)
    LOW = 1            # friction a customer clears themselves (challenge, throttle)
    MODERATE = 2       # interrupts one session / message, undone by the user or a TTL
    HIGH = 3           # cuts a person, payment or destination off until someone acts
    SEVERE = 4         # takes a host, port or credential out of service
    IRREVERSIBLE = 5   # cannot be undone (a killed process, a recalled message, a rotated key)


@dataclass(frozen=True)
class ActionContract:
    action_type: str
    impact: Impact
    undo: str                    # "ttl" (rolled back automatically) | "vendor" (a person releases it) | "none"
    hitl_by_policy: bool = False # a human always decides, whatever the impact (auditable / another team's change)
    hand_off: bool = False       # routes work to people; there is nothing to execute


_C = ActionContract
CONTRACTS: dict[str, ActionContract] = {c.action_type: c for c in (
    _C("allow", Impact.READ_ONLY, "none"),
    _C("monitor", Impact.READ_ONLY, "none"),
    _C("escalate", Impact.READ_ONLY, "none", hand_off=True),
    _C("notify_user", Impact.LOW, "none"),
    _C("challenge", Impact.LOW, "ttl"),
    _C("throttle", Impact.LOW, "ttl"),
    _C("redact", Impact.LOW, "none"),
    _C("force_logout", Impact.MODERATE, "none"),
    _C("quarantine_message", Impact.MODERATE, "vendor"),
    _C("block", Impact.MODERATE, "ttl", hitl_by_policy=True),          # tiered auto-block is the only exception
    _C("snapshot_forensic", Impact.LOW, "none", hitl_by_policy=True),  # auditable evidence capture
    _C("hold", Impact.HIGH, "ttl"),                                    # payments; the outflow breaker may hold
    _C("block_egress", Impact.HIGH, "vendor"),
    _C("block_export", Impact.HIGH, "vendor"),
    _C("lock_account", Impact.HIGH, "vendor"),
    _C("revoke_sessions", Impact.HIGH, "none"),
    _C("quarantine_file", Impact.HIGH, "vendor"),
    _C("escalate_to_fraud_team", Impact.HIGH, "none", hand_off=True),
    _C("isolate", Impact.SEVERE, "vendor"),
    _C("trigger_self_heal", Impact.SEVERE, "none"),
    _C("interface_shutdown", Impact.SEVERE, "vendor"),
    _C("config_rollback", Impact.SEVERE, "vendor"),
    _C("escalate_to_hr", Impact.SEVERE, "none", hand_off=True),
    _C("kill_process", Impact.IRREVERSIBLE, "none"),
    _C("recall_message", Impact.IRREVERSIBLE, "none"),
    _C("rotate_credential", Impact.IRREVERSIBLE, "none"),
)}


#: fast-path builders that decide with no model in the loop (no vote is taken on their chains)
DETERMINISTIC_BUILDERS = frozenset({
    "adaptive_attacker", "auth_burst", "object_walk", "control_plane", "egress", "low_and_slow", "model_pull",
    "netops", "privileged", "pxe_firmware", "spoofed_client", "treasury", "deception"})


def contract(action_type: str) -> ActionContract | None:
    return CONTRACTS.get(str(action_type))


def always_hitl() -> frozenset[str]:
    """Actions a human always decides: high impact or above, or HITL by policy."""
    return frozenset(a for a, c in CONTRACTS.items() if c.impact >= Impact.HIGH or c.hitl_by_policy)


def auto_safe() -> frozenset[str]:
    """Actions that may run with no human (still subject to ``gate`` and grounding)."""
    return frozenset(a for a, c in CONTRACTS.items()
                     if c.impact <= Impact.MODERATE and not c.hitl_by_policy and not c.hand_off)


# ---------------------------------------------------------------- the unattended gate --

TIERS = ("L0", "L1", "L2", "L3", "L4")
#: the highest impact each tier lets run with no human (READ_ONLY always may: it changes nothing)
TIER_CEILING: dict[str, Impact] = {"L0": Impact.READ_ONLY, "L1": Impact.READ_ONLY, "L2": Impact.LOW,
                                   "L3": Impact.MODERATE, "L4": Impact.HIGH}
#: chain confidence an unattended action needs, per impact (env: AEGIS_AUTONOMY_FLOOR_LOW, …)
DEFAULT_FLOOR: dict[Impact, float] = {Impact.READ_ONLY: 0.0, Impact.LOW: 0.70, Impact.MODERATE: 0.85,
                                      Impact.HIGH: 0.95}


def tier() -> str:
    t = os.environ.get("AEGIS_AUTONOMY_TIER", "L4").strip().upper()[:2]
    return t if t in TIERS else "L0"          # an unreadable tier is the most restrictive, never the loosest


def floor(impact: Impact) -> float:
    raw = os.environ.get(f"AEGIS_AUTONOMY_FLOOR_{impact.name}", "")
    try:
        return min(1.0, max(0.0, float(raw))) if raw else DEFAULT_FLOOR.get(impact, 1.01)
    except ValueError:
        return DEFAULT_FLOOR.get(impact, 1.01)


def gate(action: Any, chain: Any, *, protected: bool = False) -> tuple[bool, str]:
    """May this action run with no human? The strictest of contract, tier and confidence wins."""
    at = str(getattr(action, "action_type", ""))
    c = contract(at)
    if c is None:
        return False, f"{at or 'action'} has no contract — a human decides"
    if c.hand_off:
        return False, f"{at} hands work to people — nothing to execute"
    if c.hitl_by_policy and at != "block":          # block: only tiered auto-block, which has its own checks
        return False, f"{at} is decided by a human by policy"
    impact = c.impact
    if protected and impact < Impact.IRREVERSIBLE:
        impact = Impact(impact + 1)           # a protected asset raises the stakes one rank
    if impact >= Impact.SEVERE:
        return False, f"{at} is {impact.name.lower()} impact — never runs without a human"
    t = tier()
    if impact > TIER_CEILING[t] and impact > Impact.READ_ONLY:
        return False, f"{at} ({impact.name.lower()}) is above the autonomy tier {t} — a human decides"
    conf = float(getattr(chain, "confidence", 0.0) or 0.0)
    need = floor(impact)
    if conf < need:
        return False, f"confidence {conf:.2f} is below the {need:.2f} an unattended {impact.name.lower()} action needs"
    return True, ""


def missing_contracts() -> list[str]:
    """ActionType values with no contract (the test suite and CI fail on any)."""
    from ..shared.evidence_chain import ActionType
    return sorted(set(get_args(ActionType)) - set(CONTRACTS))


__all__ = ["CONTRACTS", "DETERMINISTIC_BUILDERS", "TIERS", "ActionContract", "Impact", "always_hitl", "auto_safe", "contract", "floor",
           "gate", "missing_contracts", "tier"]
