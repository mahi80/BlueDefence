"""PPO trainer for the AEGIS Tier-0/1 traffic policy.

Trains a PPO policy on the synthetic AEGISTrafficEnv. Saves the
checkpoint to `runs/ppo_baseline.zip`. To export for the Go Tier-0
filter as a linear-features JSON (skeleton format), run
aegis/rl/export_policy.py.

Usage:
  pip install -r aegis/requirements-rl.txt
  python -m aegis.rl.train --steps 50000

Note: this is the offline pipeline only. The plan calls for periodic
retrain with curated logs from the LLM tier; that scheduler isn't in
the walking skeleton.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from .env import make_env


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--steps", type=int, default=50_000)
    p.add_argument("--out", default="runs/ppo_baseline.zip")
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args()

    try:
        from stable_baselines3 import PPO
        from stable_baselines3.common.vec_env import DummyVecEnv
    except ImportError as exc:  # noqa: BLE001
        print(f"stable-baselines3 not installed: {exc}")
        print("Install with: pip install -r aegis/requirements-rl.txt")
        return 2

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    env = DummyVecEnv([lambda: make_env(seed=args.seed)])
    model = PPO("MlpPolicy", env, seed=args.seed, verbose=1, tensorboard_log=None)
    model.learn(total_timesteps=args.steps)
    model.save(str(out_path))
    print(f"Saved to {out_path}")

    # Quick eval
    eval_env = make_env(seed=args.seed + 1)
    obs, _ = eval_env.reset()
    correct = 0
    rewards = 0.0
    n = 1000
    for _ in range(n):
        action, _ = model.predict(obs, deterministic=True)
        obs, r, terminated, truncated, info = eval_env.step(int(action))
        rewards += r
        # Correct = block on attack, allow on benign, or escalate (always partially correct)
        if info["is_attack"] and action != 0:
            correct += 1
        elif not info["is_attack"] and action == 0:
            correct += 1
        if terminated or truncated:
            obs, _ = eval_env.reset()
    print(f"Eval accuracy ~{correct/n:.2%}  Avg reward {rewards/n:.2f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
