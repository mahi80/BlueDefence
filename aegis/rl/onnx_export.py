"""ONNX export — sklearn baseline OR PPO checkpoint -> .onnx file.

The Go Tier-0 filter consumes either:
  - policy.json  (linear features, fast path, what aegis/edge/tier0.go reads today)
  - policy.onnx  (full neural net, recommended for production PPO models)

ONNX is the right deployment format for non-trivial policies because:
  - One file, no Python runtime in the data plane
  - Multiple Go ONNX runtimes available (yalue/onnxruntime_go cgo
    binding to Microsoft's ONNX Runtime is the most-used)
  - Versioning + signing pipelines already exist for ONNX in regulated
    environments

Usage:
  # Export the sklearn baseline classifier as ONNX:
  python -m aegis.rl.onnx_export --from sklearn --out aegis/rl/policy.onnx

  # Export a trained SB3 PPO model as ONNX (requires torch + onnx):
  python -m aegis.rl.onnx_export --from ppo --checkpoint runs/ppo_baseline.zip --out aegis/rl/policy.onnx
"""
from __future__ import annotations

import argparse
from pathlib import Path

from .baseline import _generate_dataset, _FEATURE_NAMES


def export_sklearn(out_path: Path, samples: int, seed: int) -> int:
    try:
        from sklearn.linear_model import LogisticRegression
        from skl2onnx import to_onnx
        import numpy as np
    except ImportError as exc:  # noqa: BLE001
        print(f"Missing deps: {exc}")
        print("pip install scikit-learn skl2onnx numpy")
        return 2

    X, y = _generate_dataset(samples, seed=seed)
    clf = LogisticRegression(max_iter=500)
    clf.fit(X, y)
    X_arr = np.array(X, dtype=np.float32)
    onnx_model = to_onnx(clf, X_arr[:1], target_opset=15)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(onnx_model.SerializeToString())
    print(f"Wrote {out_path}  ({len(_FEATURE_NAMES)} features, 3 classes, opset 15)")
    return 0


def export_ppo(checkpoint: Path, out_path: Path) -> int:
    try:
        from stable_baselines3 import PPO
        import torch
    except ImportError as exc:  # noqa: BLE001
        print(f"Missing deps: {exc}")
        print("pip install stable-baselines3 torch onnx")
        return 2

    model = PPO.load(str(checkpoint))
    obs_dim = model.observation_space.shape[0]
    dummy = torch.zeros(1, obs_dim, dtype=torch.float32)

    class PolicyWrapper(torch.nn.Module):
        def __init__(self, policy):
            super().__init__()
            self.policy = policy

        def forward(self, obs):
            features = self.policy.extract_features(obs, self.policy.pi_features_extractor)
            latent = self.policy.mlp_extractor.forward_actor(features)
            return self.policy.action_net(latent)

    wrapper = PolicyWrapper(model.policy)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    torch.onnx.export(
        wrapper, dummy, str(out_path),
        input_names=["features"], output_names=["logits"],
        opset_version=15,
    )
    print(f"Wrote {out_path}  (from PPO checkpoint {checkpoint})")
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--from", dest="src", choices=["sklearn", "ppo"], required=True)
    p.add_argument("--out", default="aegis/rl/policy.onnx")
    p.add_argument("--checkpoint", help="Required for --from ppo")
    p.add_argument("--samples", type=int, default=10_000)
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args()

    out = Path(args.out)
    if args.src == "sklearn":
        return export_sklearn(out, args.samples, args.seed)
    if args.src == "ppo":
        if not args.checkpoint:
            print("--checkpoint is required for --from ppo")
            return 2
        return export_ppo(Path(args.checkpoint), out)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
