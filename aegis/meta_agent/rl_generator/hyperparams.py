"""PPO hyperparameter spec for the AEGIS Tier-0/1 traffic policy.

Same safety pattern as RewardSpec: schema, not arbitrary code. The
meta-agent picks numbers within bounded ranges, the trainer applies
them.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class PPOHyperparams:
    learning_rate: float = 3e-4
    n_steps: int = 2048
    batch_size: int = 64
    n_epochs: int = 10
    gamma: float = 0.99           # discount factor
    gae_lambda: float = 0.95      # GAE smoothing
    clip_range: float = 0.2       # PPO clip
    ent_coef: float = 0.0         # entropy bonus (encourages exploration)
    vf_coef: float = 0.5          # value-function loss coefficient
    max_grad_norm: float = 0.5    # gradient clipping

    @staticmethod
    def safety_bounds() -> dict[str, tuple[float, float]]:
        return {
            "learning_rate":  (1e-5, 1e-2),
            "n_steps":        (256, 8192),
            "batch_size":     (16, 512),
            "n_epochs":       (1, 30),
            "gamma":          (0.9, 0.999),
            "gae_lambda":     (0.8, 1.0),
            "clip_range":     (0.05, 0.4),
            "ent_coef":       (0.0, 0.1),
            "vf_coef":        (0.1, 1.0),
            "max_grad_norm":  (0.1, 5.0),
        }

    def clamp(self) -> "PPOHyperparams":
        bounds = self.safety_bounds()
        clamped: dict[str, Any] = {}
        for name, (lo, hi) in bounds.items():
            val = getattr(self, name)
            clamped[name] = max(lo, min(hi, float(val)))
            # int-typed fields keep their type
            if name in ("n_steps", "batch_size", "n_epochs"):
                clamped[name] = int(round(clamped[name]))
        return PPOHyperparams(**clamped)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), indent=2)


def parse_hyperparams_json(text: str) -> PPOHyperparams:
    data = json.loads(text) if isinstance(text, str) else text
    if not isinstance(data, dict):
        raise ValueError("PPOHyperparams JSON must be an object")
    fields = set(PPOHyperparams().as_dict())
    filtered = {k: v for k, v in data.items() if k in fields and isinstance(v, (int, float))}
    return PPOHyperparams(**filtered).clamp()
