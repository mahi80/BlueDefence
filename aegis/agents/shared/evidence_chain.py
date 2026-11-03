"""Structured evidence chain — the spine of every agent decision.

Every agent verdict produces one of these. Stored to WORM audit log.
Auditors / regulators / SOC analysts read these to understand 'why did
the agent decide what it decided'.
"""
from __future__ import annotations

import math

from datetime import datetime, timezone
from typing import Literal, Optional, get_args

from pydantic import BaseModel, ConfigDict, Field, field_validator


Verdict = Literal["benign", "suspicious", "malicious", "uncertain"]
Weight = Literal["low", "medium", "high"]
ActionType = Literal[
    "allow",
    "monitor",
    "challenge",
    "throttle",
    "block",
    "isolate",
    "escalate",
    "notify_user",
    "lock_account",
    "revoke_sessions",
    "kill_process",
    "quarantine_file",
    "trigger_self_heal",
    "escalate_to_fraud_team",
    "hold",
    "redact",
    "block_export",
    "quarantine_message",
    "recall_message",
    "force_logout",
    "rotate_credential",
    "escalate_to_hr",
    "snapshot_forensic",
    "block_egress",
    "config_rollback",       # network: revert a device to its golden / last-known-good configuration
    "interface_shutdown",    # network: administratively shut a flapping or error-storming port
]

# Valid values derived from the Literals above so the defensive coercion
# validators below stay in sync automatically if an enum ever changes.
_VALID_VERDICTS = frozenset(get_args(Verdict))
_VALID_WEIGHTS = frozenset(get_args(Weight))
_VALID_ACTION_TYPES = frozenset(get_args(ActionType))


def _clamp_confidence(v: object) -> object:
    """Live models write confidence as 0.93, "0.93", "93%" or 93 — keep the
    chain constructible and clamp into [0, 1] instead of raising."""
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if isinstance(v, str):
        text = v.strip()
        pct = text.endswith("%")
        try:
            f = float(text.rstrip("%").strip())
        except ValueError:
            return 0.5
        v = f / 100.0 if pct else f
    if isinstance(v, (int, float)):
        f = float(v)
        if not math.isfinite(f):
            return 0.0                      # min(1.0, nan) is 1.0: a model writing NaN got full confidence (G1-13)
        if f > 1.0:
            f = f / 100.0 if f <= 100.0 else 1.0
        return max(0.0, min(1.0, f))
    return v


def _coerce_enum(value: object, allowed: frozenset[str], fallback: str) -> str:
    """Return ``value`` if it is one of ``allowed`` (case/space-insensitive),
    else ``fallback``.

    A live LLM routinely emits a label just outside a strict enum — a rationale
    sentence in ``verdict`` ("Low-severity alert, consistent with baseline"), or
    an action word not on the list ("alert"). Without this, constructing the
    pydantic model raises a ValidationError and crashes the agent. The
    deterministic stub hid this because it only ever emits valid enum values.
    Fallbacks are chosen to *fail safe* (escalate to a human / mark uncertain),
    never to silently downgrade a security response.
    """
    if isinstance(value, str):
        s = value.strip().lower()
        if s in allowed:
            return s
    return fallback


class EvidenceItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    signal: str
    weight: Weight
    raw_data: dict = Field(default_factory=dict)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("weight", mode="before")
    @classmethod
    def _coerce_weight(cls, v):
        # Fail safe to the lowest weight if a live LLM emits something odd —
        # don't let garbage inflate evidence weight.
        return _coerce_enum(v, _VALID_WEIGHTS, "low")


class ReasoningStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    step: int
    action: str
    observation: str
    conclusion: Optional[str] = None


class RecommendedAction(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    action_type: ActionType
    target: str
    reasoning: str
    requires_hitl: bool
    confidence: float = Field(ge=0.0, le=1.0)

    @field_validator("confidence", mode="before")
    @classmethod
    def _clamp(cls, v):
        return _clamp_confidence(v)

    @field_validator("action_type", mode="before")
    @classmethod
    def _coerce_action_type(cls, v):
        # Fail safe to "escalate" (route to a human) when a live LLM emits an
        # action outside the enum — never silently drop to a passive "monitor".
        return _coerce_enum(v, _VALID_ACTION_TYPES, "escalate")


class EvidenceChain(BaseModel):
    # validate_assignment: every specialist does ``chain.verdict = parsed["verdict"]``
    # after the LLM call — without it a rationale sentence or a 93 % confidence
    # landed in the sealed chain unchecked (dashboard ingest then refused the
    # row). Found on the first live-model timing run (2026-10-21).
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    alert_id: str
    investigated_by: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[EvidenceItem] = Field(default_factory=list)

    @field_validator("verdict", mode="before")
    @classmethod
    def _coerce_verdict(cls, v):
        # Fail safe to "uncertain" (escalate for review) when a live LLM returns
        # a rationale sentence instead of one of the four verdict literals.
        return _coerce_enum(v, _VALID_VERDICTS, "uncertain")

    @field_validator("confidence", mode="before")
    @classmethod
    def _clamp(cls, v):
        return _clamp_confidence(v)
    reasoning: list[ReasoningStep] = Field(default_factory=list)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    specialist_invocations: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)
    integrity_hash: Optional[str] = None

    def finalize(self) -> "EvidenceChain":
        if self.completed_at is None:
            self.completed_at = datetime.now(timezone.utc)
        return self
