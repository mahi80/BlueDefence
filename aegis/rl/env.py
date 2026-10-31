"""Gymnasium environment — defender training against a synthetic
attacker traffic stream.

Observation space (4-dim):
  - primitive_count          (0..5+)        attack primitives in payload
  - ip_known_bad             (0|1)
  - anomaly_score            (0.0..1.0)
  - user_baseline_match      (0|1)

Action space (Discrete 3):
  - 0 = allow
  - 1 = escalate (route to LLM tier — costs token money but bounded)
  - 2 = block

Reward (asymmetric per the plan — FP costs less than FN):
  - allow benign:           +1
  - allow malicious:        -50 (security failure)
  - escalate benign:        -2 (escalation cost)
  - escalate malicious:     +5 (correct triage)
  - block benign:           -10 (FP costs revenue, but recoverable)
  - block malicious:        +10
"""
from __future__ import annotations

import random
from typing import Optional


def _try_import_gym():
    try:
        import gymnasium as gym
        from gymnasium import spaces
        import numpy as np
        return gym, spaces, np
    except ImportError as exc:  # noqa: BLE001
        raise RuntimeError(
            "RL deps missing. Install with: pip install -r aegis/requirements-rl.txt"
        ) from exc


def make_env(*, seed: Optional[int] = None, max_steps: int = 1000):
    gym, spaces, np = _try_import_gym()

    class AEGISTrafficEnv(gym.Env):
        metadata = {"render_modes": []}

        def __init__(self):
            super().__init__()
            self.observation_space = spaces.Box(
                low=np.array([0.0, 0.0, 0.0, 0.0], dtype=np.float32),
                high=np.array([10.0, 1.0, 1.0, 1.0], dtype=np.float32),
                dtype=np.float32,
            )
            self.action_space = spaces.Discrete(3)
            self._max_steps = max_steps
            self._step = 0
            self._is_attack = False
            self._rng = random.Random(seed)

        def _sample_event(self):
            # 70% benign, 30% malicious — calibrated to bank traffic mix.
            self._is_attack = self._rng.random() < 0.30
            if self._is_attack:
                primitives = self._rng.choice([1, 2, 3, 4])
                ip_bad = 1.0 if self._rng.random() < 0.6 else 0.0
                anom = self._rng.uniform(0.6, 1.0)
                baseline_match = 0.0
            else:
                primitives = 0 if self._rng.random() < 0.85 else 1  # occasional borderline
                ip_bad = 0.0
                anom = self._rng.uniform(0.0, 0.4)
                baseline_match = 1.0 if self._rng.random() < 0.85 else 0.0
            return np.array([primitives, ip_bad, anom, baseline_match], dtype=np.float32)

        def reset(self, *, seed: Optional[int] = None, options: Optional[dict] = None):
            if seed is not None:
                self._rng = random.Random(seed)
            self._step = 0
            obs = self._sample_event()
            return obs, {}

        def step(self, action: int):
            if self._is_attack:
                # malicious request
                if action == 0:    reward = -50.0   # missed attack
                elif action == 1:  reward = +5.0    # escalate -> LLM
                else:              reward = +10.0   # block correct
            else:
                # benign request
                if action == 0:    reward = +1.0    # correct allow
                elif action == 1:  reward = -2.0    # unnecessary escalation
                else:              reward = -10.0   # blocked legit user

            self._step += 1
            terminated = False
            truncated = self._step >= self._max_steps
            obs = self._sample_event()
            info = {"is_attack": self._is_attack}
            return obs, reward, terminated, truncated, info

        def render(self):
            return None

    return AEGISTrafficEnv()
