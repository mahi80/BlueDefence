"""Export a trained PPO policy to a linear-features JSON the Go
Tier-0 filter can load.

This is a *lossy* export: it fits a linear surrogate to the policy's
behavior on the env's observation distribution. Useful for a hot-path
deployment where ONNX inference is overkill or not permitted in-line.
For full-fidelity inference, export to ONNX instead and load via
ONNX Runtime in the Go filter.

Usage:
  python -m aegis.rl.export_policy --checkpoint runs/ppo_baseline.zip --out aegis/rl/policy.json
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .env import make_env


_FEATURE_NAMES = ["primitive_count", "ip_known_bad", "anomaly_score", "user_baseline_match"]


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--checkpoint", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--samples", type=int, default=4000)
    p.add_argument("--block-gate", type=float, default=0.85,
                   help="Refuse to auto-block below this confidence in the Go filter")
    args = p.parse_args()

    try:
        from stable_baselines3 import PPO
        import numpy as np
        from sklearn.linear_model import LogisticRegression
    except ImportError as exc:  # noqa: BLE001
        print(f"Missing dep: {exc}")
        print("Install with: pip install -r aegis/requirements-rl.txt")
        return 2

    model = PPO.load(args.checkpoint)
    env = make_env(seed=123)

    # Sample observations + policy actions
    X = []
    y = []
    obs, _ = env.reset()
    for _ in range(args.samples):
        action, _ = model.predict(obs, deterministic=True)
        X.append(obs.copy())
        y.append(int(action))
        obs, _, term, trunc, _ = env.step(int(action))
        if term or trunc:
            obs, _ = env.reset()
    X = np.array(X, dtype=np.float32)
    y = np.array(y, dtype=np.int64)

    # Fit a 3-class logistic regression as the Tier-0 surrogate
    if len(set(y)) < 2:
        print("Warning: PPO collapses to one class — train longer.")
    clf = LogisticRegression(max_iter=500)
    clf.fit(X, y)

    # Map back to {allow, escalate, block} = {0, 1, 2}
    classes_ = list(clf.classes_)
    full = {0: 0, 1: 0, 2: 0}
    weights = [[0.0] * 3 for _ in range(len(_FEATURE_NAMES))]
    bias = [0.0, 0.0, 0.0]
    for cls_idx, cls in enumerate(classes_):
        coef = clf.coef_[cls_idx]
        intercept = clf.intercept_[cls_idx]
        for f_idx, w in enumerate(coef):
            weights[f_idx][int(cls)] = float(w)
        bias[int(cls)] = float(intercept)
        full[int(cls)] = 1
    if not all(full.values()):
        print("Note: some action classes had zero training signal; their logits are 0.")

    out = {
        "version": "ppo-surrogate-1",
        "feature_map": {name: i for i, name in enumerate(_FEATURE_NAMES)},
        "weights": weights,
        "bias": bias,
        "block_gate": args.block_gate,
    }
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"Wrote {out_path} ({len(_FEATURE_NAMES)} features, block_gate={args.block_gate})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
