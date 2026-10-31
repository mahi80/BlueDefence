"""Reward specification for the AEGIS Tier-0/1 traffic policy.

Why a schema and not free-form Python:

The plan's safety constraint for the meta-agent generating RL components
says "validate in simulator before any deploy" and "the meta-agent
proposes; humans gatekeep deployment." If the meta-agent emitted
arbitrary Python code as a reward function, prompt injection from the
attacker stream could surface as malicious code in the generated
reward — defeating the whole sandbox premise.

Solution: the meta-agent emits a fixed-schema dict (RewardSpec). The
interpreter is in this module, fully audited. The LLM picks numbers,
not code.

This is the **production-feasible** end of the Eureka-style reward
generation pattern: the LLM still does the design (proposing weights
that match a threat description), but the surface area it can mutate
is bounded.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from typing import Any


# Action indices match aegis/rl/env.py: 0=allow, 1=escalate, 2=block
@dataclass(frozen=True)
class RewardSpec:
    """All weights in real units of "perceived analyst-time / revenue cost"
    so they're comparable. Default values match the original env.py.
    """

    # Core 6 outcomes
    allow_benign: float = 1.0           # correct allow
    allow_malicious: float = -50.0      # security failure
    escalate_benign: float = -2.0       # unnecessary escalation cost
    escalate_malicious: float = 5.0     # correct escalation
    block_benign: float = -10.0         # FP costs revenue (recoverable)
    block_malicious: float = 10.0       # correct block

    # Behavioral shaping
    confidence_calibration_bonus: float = 0.0   # bonus * (confidence) on correct decisions
    rapid_decision_penalty: float = 0.0         # penalty for switching from escalate->allow rapidly

    # Safety bounds — values outside these are clamped before use.
    # The meta-agent proposer SHOULD respect these, but we enforce defensively.
    @staticmethod
    def safety_bounds() -> dict[str, tuple[float, float]]:
        return {
            "allow_benign":          (0.5, 5.0),
            "allow_malicious":       (-200.0, -10.0),
            "escalate_benign":       (-10.0, 0.0),
            "escalate_malicious":    (0.0, 20.0),
            "block_benign":          (-50.0, 0.0),
            "block_malicious":       (1.0, 50.0),
            "confidence_calibration_bonus": (0.0, 5.0),
            "rapid_decision_penalty":       (-5.0, 0.0),
        }

    def clamp(self) -> "RewardSpec":
        bounds = self.safety_bounds()
        clamped: dict[str, float] = {}
        for field_name, (lo, hi) in bounds.items():
            val = getattr(self, field_name)
            clamped[field_name] = max(lo, min(hi, float(val)))
        return RewardSpec(**clamped)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), indent=2)


def reward(spec: RewardSpec, action: int, is_attack: bool, *,
           confidence: float = 0.0, prev_action: int | None = None) -> float:
    """Compute the per-step reward for a (action, ground-truth) pair."""
    base = 0.0
    if is_attack:
        if action == 0:    base = spec.allow_malicious
        elif action == 1:  base = spec.escalate_malicious
        else:              base = spec.block_malicious
    else:
        if action == 0:    base = spec.allow_benign
        elif action == 1:  base = spec.escalate_benign
        else:              base = spec.block_benign

    correct = (
        (is_attack and action != 0) or (not is_attack and action == 0)
    )
    if correct and spec.confidence_calibration_bonus:
        base += spec.confidence_calibration_bonus * max(0.0, min(1.0, confidence))

    if prev_action is not None and prev_action == 1 and action == 0 and spec.rapid_decision_penalty:
        # Punish "escalate -> allow" thrashing, which produces churn for analysts
        base += spec.rapid_decision_penalty

    return base


def parse_spec_json(text: str) -> RewardSpec:
    """Parse a RewardSpec from a JSON object. Unknown fields ignored."""
    data = json.loads(text) if isinstance(text, str) else text
    if not isinstance(data, dict):
        raise ValueError("RewardSpec JSON must be an object")
    fields = {f for f in RewardSpec().as_dict()}
    filtered = {k: float(v) for k, v in data.items() if k in fields and isinstance(v, (int, float))}
    return RewardSpec(**filtered).clamp()


def diff(a: RewardSpec, b: RewardSpec) -> dict[str, tuple[float, float]]:
    """Return {field: (a_val, b_val)} for fields that differ."""
    out: dict[str, tuple[float, float]] = {}
    for k, av in a.as_dict().items():
        bv = b.as_dict()[k]
        if av != bv:
            out[k] = (av, bv)
    return out
