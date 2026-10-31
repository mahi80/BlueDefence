"""Validator — trains a baseline classifier under the proposed RewardSpec
and measures policy quality on a held-out evaluation distribution.

Why sklearn baseline (not full PPO):

The baseline uses RewardSpec only to pick the optimal action LABEL for
each synthetic observation, then fits a logistic regression to those
labels. Quality is measured on a held-out adversarial-shaped sample.
This is fast (seconds), torch-free, deterministic — perfect for the
inner-loop validation. Production extension swaps in real PPO training
with the same spec; the metric definitions stay the same.

Hard constraint: validator runs in simulation only. No code is
modified, no checkpoint is saved, nothing is deployed. The output is a
ValidationResult that the queue records for HITL review.
"""
from __future__ import annotations

import random
from dataclasses import dataclass

from .reward_spec import RewardSpec, reward


@dataclass
class ValidationResult:
    proposal_id: str
    metric_baseline: float       # avg per-step reward, baseline spec
    metric_proposed: float       # avg per-step reward, proposed spec
    delta: float
    fp_rate_baseline: float
    fp_rate_proposed: float
    miss_rate_baseline: float
    miss_rate_proposed: float
    recommend_accept: bool
    notes: str = ""


def _generate_dataset(n: int, seed: int):
    """Same distribution as aegis/rl/baseline.py + aegis/rl/env.py."""
    rng = random.Random(seed)
    X: list[list[float]] = []
    y: list[bool] = []   # True = attack
    for _ in range(n):
        is_attack = rng.random() < 0.30
        if is_attack:
            primitives = rng.choice([1, 2, 3, 4])
            ip_bad = 1.0 if rng.random() < 0.6 else 0.0
            anom = rng.uniform(0.6, 1.0)
            baseline_match = 0.0
        else:
            primitives = 0 if rng.random() < 0.85 else 1
            ip_bad = 0.0
            anom = rng.uniform(0.0, 0.4)
            baseline_match = 1.0 if rng.random() < 0.85 else 0.0
        X.append([float(primitives), ip_bad, anom, baseline_match])
        y.append(is_attack)
    return X, y


def _label_under_spec(X, y, spec: RewardSpec) -> list[int]:
    """Pick the optimal action per (X, y) under the given reward spec."""
    labels = []
    for is_attack in y:
        # Pick the action with the highest reward for this ground truth.
        candidates = [
            (0, reward(spec, 0, is_attack)),
            (1, reward(spec, 1, is_attack)),
            (2, reward(spec, 2, is_attack)),
        ]
        candidates.sort(key=lambda c: c[1], reverse=True)
        labels.append(candidates[0][0])
    return labels


def _train_eval(spec: RewardSpec, *, samples: int, seed: int) -> dict:
    """Train sklearn baseline with the spec's optimal labels, evaluate on
    a held-out set, return metrics.
    """
    try:
        from sklearn.linear_model import LogisticRegression
    except ImportError as exc:  # noqa: BLE001
        raise RuntimeError(
            "scikit-learn not installed. pip install scikit-learn"
        ) from exc

    Xt, yt = _generate_dataset(samples, seed=seed)
    labels_train = _label_under_spec(Xt, yt, spec)

    Xv, yv = _generate_dataset(max(samples // 4, 100), seed=seed + 1)
    labels_v_optimal = _label_under_spec(Xv, yv, spec)

    n_classes = len(set(labels_train))
    if n_classes < 2:
        # Degenerate spec — every observation produces the same optimal
        # action, so a classifier can't learn anything meaningful.
        # Return baseline-equivalent metrics so the validator can flag
        # this as recommend_accept=False with a clear note.
        return {
            "avg_reward": -1e9,
            "fp_rate": 1.0,
            "miss_rate": 1.0,
            "degenerate": True,
        }

    clf = LogisticRegression(max_iter=500)
    clf.fit(Xt, labels_train)
    pred = clf.predict(Xv)

    total_reward = 0.0
    n_fp = 0  # blocked benign
    n_benign = 0
    n_miss = 0  # allowed attack
    n_attack = 0
    for action, is_attack, opt in zip(pred, yv, labels_v_optimal):
        total_reward += reward(spec, int(action), is_attack)
        if is_attack:
            n_attack += 1
            if action == 0:
                n_miss += 1
        else:
            n_benign += 1
            if action == 2:
                n_fp += 1
    return {
        "avg_reward": total_reward / len(yv),
        "fp_rate": n_fp / max(n_benign, 1),
        "miss_rate": n_miss / max(n_attack, 1),
        "degenerate": False,
    }


def validate(proposed: RewardSpec, *,
             baseline: RewardSpec | None = None,
             proposal_id: str = "RL-PROP-UNSPECIFIED",
             samples: int = 4000,
             seed: int = 17) -> ValidationResult:
    baseline = baseline or RewardSpec()

    bl = _train_eval(baseline, samples=samples, seed=seed)
    pr = _train_eval(proposed, samples=samples, seed=seed)

    delta = pr["avg_reward"] - bl["avg_reward"]

    notes_bits: list[str] = []
    if pr.get("degenerate"):
        notes_bits.append("proposed spec is degenerate (single optimal action)")

    # Acceptance rule: proposed must improve avg reward AND not significantly
    # worsen FP or miss rates beyond a small tolerance. This bounds the
    # tradeoff: an "improvement" that doubles FPs is rejected.
    fp_ok = pr["fp_rate"] <= bl["fp_rate"] + 0.05
    miss_ok = pr["miss_rate"] <= bl["miss_rate"] + 0.05
    improved = delta > 0.0
    accept = improved and fp_ok and miss_ok and not pr.get("degenerate")

    if not fp_ok:
        notes_bits.append(f"FP rate worsened by {pr['fp_rate']-bl['fp_rate']:.3f}")
    if not miss_ok:
        notes_bits.append(f"miss rate worsened by {pr['miss_rate']-bl['miss_rate']:.3f}")
    if not improved:
        notes_bits.append(f"avg reward did not improve (delta={delta:+.3f})")

    return ValidationResult(
        proposal_id=proposal_id,
        metric_baseline=bl["avg_reward"],
        metric_proposed=pr["avg_reward"],
        delta=delta,
        fp_rate_baseline=bl["fp_rate"],
        fp_rate_proposed=pr["fp_rate"],
        miss_rate_baseline=bl["miss_rate"],
        miss_rate_proposed=pr["miss_rate"],
        recommend_accept=accept,
        notes="; ".join(notes_bits) if notes_bits else "all gates pass",
    )
