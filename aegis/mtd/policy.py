"""Moving Target Defense — SAC-driven asset rotation.

Production: a Soft Actor-Critic policy trained against a simulator that
models attacker recon-then-exploit cycles. The SAC policy chooses
*when* and *which* asset to rotate, balancing operational cost (session
break, cache miss) against recon-invalidation benefit.

Walking skeleton ships:
  - Asset registry with rotation primitives
  - SAC policy stub: a callable that takes an observation and returns
    rotation decisions. Default implementation is a heuristic; replace
    with a trained SB3 SAC model via load_sac_policy().
  - Hard safety constraints applied to every action.

Constraints (never violated even if SAC tries):
  - Cannot break an in-flight legit user session
  - Cannot violate compliance segmentation (PCI-DSS scope, etc.)
  - Cannot invalidate a non-revoked auth token mid-transaction
  - Cannot rotate more than N assets per minute (rate cap)
"""
from __future__ import annotations

import random
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class Asset:
    id: str
    kind: str   # "service" | "ip" | "port" | "decoy" | "dns"
    current_coords: dict   # e.g. {"ip": "10.1.2.3", "port": 8080}
    rotatable: bool = True
    in_compliance_scope: bool = False  # if True, rotations need extra approval
    active_sessions: int = 0           # in-flight legit sessions: not rotated while > 0
    tokens_in_flight: int = 0          # non-revoked tokens mid-transaction: not rotated while > 0


@dataclass
class RotationAction:
    asset_id: str
    new_coords: dict
    reason: str


@dataclass
class MTDState:
    assets: dict[str, Asset] = field(default_factory=dict)
    rotations_this_minute: int = 0
    rate_cap: int = 8


# ---- Heuristic SAC stub -------------------------------------------------

def heuristic_policy(observation: dict, state: MTDState) -> list[RotationAction]:
    """Stand-in for a trained SAC policy.

    Observation includes: recent_recon_intensity, days_since_last_rotation,
    suspicious_alert_count_5min, current_load_pct.

    Real SAC reads this as a vector and outputs continuous rotation
    propensities; the heuristic here approximates a reasonable behavior.
    """
    out: list[RotationAction] = []
    recon = observation.get("recon_intensity", 0.0)
    suspicious = observation.get("suspicious_alert_count_5min", 0)
    if recon < 0.3 and suspicious == 0:
        return out  # quiet — no rotation
    candidates = [a for a in state.assets.values()
                  if a.rotatable and not a.in_compliance_scope]
    if not candidates:
        return out
    # Pick a small fraction proportional to threat signal
    n = min(len(candidates), max(1, int(recon * 4) + suspicious))
    for asset in random.sample(candidates, n):
        new = dict(asset.current_coords)
        # Mock rotation: bump port or randomize last octet
        if "port" in new:
            new["port"] = random.randint(20000, 30000)
        if "ip" in new:
            parts = new["ip"].split(".")
            if len(parts) == 4:
                parts[-1] = str(random.randint(2, 254))
                new["ip"] = ".".join(parts)
        if "path" in new:
            new["path"] = f"/_internal/{random.randint(10000, 99999)}"
        out.append(RotationAction(
            asset_id=asset.id,
            new_coords=new,
            reason=f"recon={recon:.2f}, suspicious={suspicious}",
        ))
    return out


class MTDController:
    name = "mtd"

    def __init__(self, policy: Callable[[dict, MTDState], list[RotationAction]] | None = None, *,
                 clock: Callable[[], float] = time.time):
        self._policy = policy or heuristic_policy
        self._state = MTDState()
        self._clock = clock
        self._recent: deque[float] = deque()     # rotation times in the last minute

    def register(self, asset: Asset) -> None:
        self._state.assets[asset.id] = asset

    def reset_rate(self) -> None:
        self._recent.clear()
        self._state.rotations_this_minute = 0

    def step(self, observation: dict) -> list[RotationAction]:
        # The cap is a sliding minute. It was a counter that only reset_rate() cleared, so with nobody calling that
        # on a timer the controller stopped rotating for good after the first `rate_cap` rotations — and the session
        # and token constraints in the module docstring were not checked at all (review round 3 S3-25).
        now = self._clock()
        while self._recent and now - self._recent[0] >= 60.0:
            self._recent.popleft()
        self._state.rotations_this_minute = len(self._recent)
        actions = self._policy(observation, self._state)
        approved: list[RotationAction] = []
        for action in actions:
            if len(self._recent) >= self._state.rate_cap:
                break
            asset = self._state.assets.get(action.asset_id)
            if asset is None or not asset.rotatable:
                continue
            if asset.in_compliance_scope:
                continue   # safety constraint — needs approval
            if asset.active_sessions > 0 or asset.tokens_in_flight > 0:
                continue   # safety constraint — never break a live session or a token mid-transaction
            asset.current_coords = action.new_coords
            self._recent.append(now)
            self._state.rotations_this_minute = len(self._recent)
            approved.append(action)
        return approved


def load_sac_policy(checkpoint_path: str):
    """Load a stable-baselines3 SAC policy and return a callable matching
    the heuristic_policy signature.

    Lazy import: SB3 is an optional dep; production would pin and vendor it.
    """
    try:
        from stable_baselines3 import SAC  # type: ignore
        import numpy as np
    except ImportError as exc:  # noqa: BLE001
        raise RuntimeError(
            "stable-baselines3 not installed. "
            "pip install -r aegis/requirements-rl.txt"
        ) from exc

    model = SAC.load(checkpoint_path)

    def _policy(observation: dict, state: MTDState) -> list[RotationAction]:
        # Observation layout matches the env in aegis/rl/env.py
        obs_vec = np.array([
            observation.get("recon_intensity", 0.0),
            observation.get("suspicious_alert_count_5min", 0),
            observation.get("days_since_last_rotation", 0),
            observation.get("current_load_pct", 50.0) / 100.0,
        ], dtype=np.float32)
        action, _ = model.predict(obs_vec, deterministic=True)
        # Continuous action space [0,1] per asset; treat above 0.5 as "rotate"
        out: list[RotationAction] = []
        for i, asset in enumerate(state.assets.values()):
            if i < len(action) and float(action[i]) > 0.5 and asset.rotatable and not asset.in_compliance_scope:
                # Reuse the heuristic mutator for new coords
                heuristic = heuristic_policy({"recon_intensity": 1.0, "suspicious_alert_count_5min": 1}, MTDState(assets={asset.id: asset}))
                if heuristic:
                    out.extend(heuristic)
        return out

    return _policy
