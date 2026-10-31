"""sklearn-only baseline trainer.

Trains a 3-class classifier (allow/escalate/block) on synthetic labeled
traffic with the same distribution as the gymnasium env (70/30 mix,
asymmetric reward calibration). Exports policy.json that the Go Tier-0
filter can consume.

Why this exists alongside aegis/rl/train.py (PPO):
  - PPO needs torch + stable-baselines3 (~2GB install).
  - This baseline uses scikit-learn only (~50MB) — runs anywhere.
  - The PPO policy outperforms this baseline on borderline cases, but
    the baseline is a real classifier, not a hand-coded heuristic, so
    the Tier-0 filter has something live to load while waiting for
    PPO training to converge.
  - Same JSON format as export_policy.py — drop-in replacement.

Run:
  python -m aegis.rl.baseline --out aegis/rl/policy.json
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

_FEATURE_NAMES = ["primitive_count", "ip_known_bad", "anomaly_score", "user_baseline_match"]
# Action indices: 0 = allow, 1 = escalate, 2 = block


def _generate_dataset(n: int, seed: int = 42) -> tuple[list[list[float]], list[int]]:
    """Synthesize the same distribution as aegis/rl/env.py without
    needing gymnasium.
    """
    rng = random.Random(seed)
    X: list[list[float]] = []
    y: list[int] = []
    for _ in range(n):
        is_attack = rng.random() < 0.30
        if is_attack:
            primitives = rng.choice([1, 2, 3, 4])
            ip_bad = 1.0 if rng.random() < 0.6 else 0.0
            anom = rng.uniform(0.6, 1.0)
            baseline_match = 0.0
            # Optimal action for an attack — block when strong evidence,
            # escalate when borderline.
            strong = primitives >= 3 or (ip_bad and primitives >= 2)
            label = 2 if strong else 1
        else:
            primitives = 0 if rng.random() < 0.85 else 1
            ip_bad = 0.0
            anom = rng.uniform(0.0, 0.4)
            baseline_match = 1.0 if rng.random() < 0.85 else 0.0
            # Optimal action for benign — allow most, escalate on the borderline 1-primitive case
            label = 1 if primitives == 1 else 0
        X.append([float(primitives), ip_bad, anom, baseline_match])
        y.append(label)
    return X, y


def _eval(clf, X: list[list[float]], y: list[int]) -> dict:
    correct = 0
    n = len(X)
    cm = {(a, b): 0 for a in range(3) for b in range(3)}
    pred = clf.predict(X)
    for predicted, actual in zip(pred, y):
        if predicted == actual:
            correct += 1
        cm[(int(actual), int(predicted))] += 1
    return {
        "accuracy": correct / n,
        "n": n,
        "confusion": {f"true_{a}_pred_{b}": cm[(a, b)] for a, b in cm},
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="aegis/rl/policy.json")
    p.add_argument("--samples", type=int, default=10_000)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--block-gate", type=float, default=0.85)
    args = p.parse_args()

    try:
        from sklearn.linear_model import LogisticRegression
    except ImportError as exc:  # noqa: BLE001
        print(f"scikit-learn not installed: {exc}")
        print("pip install scikit-learn")
        return 2

    X, y = _generate_dataset(args.samples, seed=args.seed)
    Xv, yv = _generate_dataset(args.samples // 4, seed=args.seed + 1)

    # sklearn 1.7+ defaults to multinomial for multi-class; the explicit
    # multi_class kwarg was removed. We pass max_iter for convergence.
    clf = LogisticRegression(max_iter=500)
    clf.fit(X, y)
    metrics = _eval(clf, Xv, yv)
    print(f"Validation accuracy: {metrics['accuracy']:.3f} on n={metrics['n']}")
    for k, v in metrics["confusion"].items():
        print(f"  {k}: {v}")

    # Export — match policy.json schema consumed by aegis/edge/tier0.go
    classes = list(clf.classes_)
    weights: list[list[float]] = [[0.0] * 3 for _ in range(len(_FEATURE_NAMES))]
    bias: list[float] = [0.0, 0.0, 0.0]
    for cls_idx, cls in enumerate(classes):
        coef = clf.coef_[cls_idx]
        intercept = clf.intercept_[cls_idx]
        for f_idx, w in enumerate(coef):
            weights[f_idx][int(cls)] = float(w)
        bias[int(cls)] = float(intercept)

    out = {
        "version": "sklearn-baseline-1",
        "feature_map": {name: i for i, name in enumerate(_FEATURE_NAMES)},
        "weights": weights,
        "bias": bias,
        "block_gate": args.block_gate,
    }
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"\nPolicy written to {out_path}")
    print(f"  weights[primitive_count]      = {weights[0]}")
    print(f"  weights[ip_known_bad]         = {weights[1]}")
    print(f"  weights[anomaly_score]        = {weights[2]}")
    print(f"  weights[user_baseline_match]  = {weights[3]}")
    print(f"  bias                          = {bias}")
    print(f"  block_gate                    = {args.block_gate}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
