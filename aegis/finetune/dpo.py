"""Preference-tune (DPO) the triage judge on analyst-overruled decisions — the learning loop.

    # plan only, no GPU / no torch / no trl needed — validates the pairs and prints the plan
    python -m aegis.finetune.dpo --data datasets/triage-v1 --dry-run --vram 8

The approvals queue is the supervision signal: every time an analyst overrules the model at the
HITL card (``human_corrected`` → a different verdict; ``human_disputed`` → an auto-run action held
for a human), ``aegis.dataset export --dpo`` turns it into a (chosen, rejected) pair. DPO nudges the
judge toward the analyst's call and away from the one it overruled, so detection sharpens with every
decision and needs fewer of them over time.

The real run uses TRL's ``DPOTrainer`` on top of the SFT adapter; that import is deferred so this
module and ``--dry-run`` work anywhere (CI included). The gate afterwards is the same held-out eval
as SFT — a preference-tuned adapter still has to clear ``aegis.finetune.gate``.
"""

from __future__ import annotations

import argparse
import sys

from .config import DEFAULT, get_preset, preset_for_vram
from .data import is_non_analyst
from .dpo_data import load_dpo, split_prefs


def _plan(args: argparse.Namespace, preset, n_train: int, n_val: int) -> str:
    return (
        f"  base model      {preset.model}\n"
        f"  SFT adapter     {args.adapter or '(none — DPO on the base model)'}\n"
        f"  method          DPO (beta={args.beta})\n"
        f"  preference pairs train={n_train}  val={n_val}\n"
        f"  epochs / lr     {args.epochs} / {args.lr}\n"
        f"  output adapter  {args.out}\n"
        f"  gate            python -m aegis.finetune.gate --adapter {args.out}  (same held-out eval as SFT)"
    )


def main(argv: list[str] | None = None) -> int:
    from aegis.license import allows
    if not allows("dpo"):
        print("DPO retraining is not included in this installation's licence (feature 'dpo'); community installations get the pooled brain as model updates instead.", file=sys.stderr)
        return 2
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", required=True, help="dataset dir or dpo/preferences.jsonl")
    ap.add_argument("--out", default="runs/triage-dpo", help="adapter output dir")
    ap.add_argument("--adapter", default="", help="SFT adapter to preference-tune on top of (recommended)")
    ap.add_argument("--preset", default="", help=f"model preset (default: auto from --vram; else {DEFAULT})")
    ap.add_argument("--vram", type=float, default=8, help="GPU VRAM in GB, used to auto-pick the preset")
    ap.add_argument("--beta", type=float, default=0.1, help="DPO beta (KL penalty strength)")
    ap.add_argument("--epochs", type=float, default=1.0)
    ap.add_argument("--lr", type=float, default=5e-6, help="DPO uses a smaller LR than SFT")
    ap.add_argument("--allow-synthetic", action="store_true",
                    help="permit non-analyst pairs (there are normally none; DPO pairs are analyst-sourced)")
    ap.add_argument("--dry-run", action="store_true", help="validate the pairs, print the plan, and exit; no GPU needed")
    args = ap.parse_args(argv)

    try:
        rows = load_dpo(args.data, allow_synthetic=args.allow_synthetic)
    except Exception as e:  # noqa: BLE001
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    train, val = split_prefs(rows)
    if not train:
        print(f"ERROR: {len(rows)} pair(s) loaded but none in the train split — nothing to train on "
              "(re-export with more decisions, or check --val-pct)", file=sys.stderr)
        return 2
    syn = sum(1 for r in rows if is_non_analyst(r.label_source))
    preset = get_preset(args.preset) if args.preset else preset_for_vram(args.vram)

    by_src: dict[str, int] = {}
    for r in rows:
        by_src[r.label_source] = by_src.get(r.label_source, 0) + 1
    print(f"loaded {len(rows)} preference pairs ({', '.join(f'{k}={v}' for k, v in sorted(by_src.items()))})")
    print(f"\nplan:\n{_plan(args, preset, len(train), len(val))}")
    if syn:
        print(f"\n  ⚠ {syn} pair(s) are non-analyst — preference tuning should run on analyst decisions only.")
    if not val:
        print("\n  ⚠ no validation pairs — the run has no held-out loss to watch; the eval gate is the only check.")
    if args.dry_run:
        print("\n--dry-run: nothing trained. Install the GPU deps (+ trl) and drop --dry-run to run for real.")
        return 0

    try:
        import torch  # noqa: F401
        from trl import DPOTrainer  # noqa: F401
    except Exception as e:  # noqa: BLE001
        print(f"\nERROR: DPO needs torch + trl — {type(e).__name__}: {e}\n"
              "  pip install -r aegis/requirements-finetune.txt trl", file=sys.stderr)
        return 3
    print("\nDPO training backend not wired in this scaffold — run with --dry-run, or wire DPOTrainer here.",
          file=sys.stderr)
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
