#!/usr/bin/env bash
# One-command triage fine-tune on a local NVIDIA GPU (roadmap 3.3).
#
# Run inside WSL Ubuntu (or any Linux box with CUDA + an NVIDIA GPU):
#     bash aegis/finetune/run_local.sh
#
# Defaults target an RTX 4080 Laptop (12 GB) -> Qwen3-8B QLoRA. Override:
#     PRESET=gemma3-4b bash aegis/finetune/run_local.sh      # the lighter, zero-plumbing model
#     N=600 EPOCHS=3 bash aegis/finetune/run_local.sh
#     DATA=~/aegis-runs/public-v1 MAX_ROWS=10000 EPOCHS=1 bash aegis/finetune/run_local.sh   # realistic public set, 1 h
#     RESUME=1 DATA=... OUT=... bash aegis/finetune/run_local.sh                               # a run died: continue from its last checkpoint
#
# It trains on SYNTHETIC data (the pipeline scaffold) unless you point DATA at a real export.
# A synthetic-trained model only proves the pipeline runs on your card; the numbers mean nothing
# until you retrain on real analyst-labelled rows from a live dashboard.
set -euo pipefail

PRESET="${PRESET:-qwen3-8b}"
N="${N:-600}"
EPOCHS="${EPOCHS:-3}"
MAX_ROWS="${MAX_ROWS:-0}"        # 0 = all rows; set e.g. 10000 for a 1-hour run on a 50k set
RESUME="${RESUME:-}"             # RESUME=1 continues from the latest checkpoint-N under $OUT (same DATA + preset!)
REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
VENV="${VENV:-$HOME/.venvs/aegis-ft}"
RUNS="${RUNS:-$HOME/aegis-runs}"
DATA="${DATA:-$RUNS/synth-$PRESET}"
OUT="${OUT:-$RUNS/triage-$PRESET}"

say(){ printf '\n\033[1;36m== %s\033[0m\n' "$*"; }

say "GPU"
nvidia-smi --query-gpu=name,memory.total,memory.used --format=csv || {
  echo "nvidia-smi failed. In WSL you need CUDA for WSL installed and a recent NVIDIA driver on Windows."; exit 1; }

say "repo @ $REPO"
cd "$REPO"
if [ -d .git ]; then
  git pull --ff-only origin main 2>/dev/null || echo "  (couldn't fast-forward; make sure this checkout has aegis/finetune — the #118 merge)"
fi
[ -d aegis/finetune ] || { echo "ERROR: aegis/finetune not found here. Pull latest main first."; exit 1; }

say "python env (native fs for speed): $VENV"
python3 -m venv "$VENV"
# shellcheck disable=SC1091
source "$VENV/bin/activate"
pip install -q --upgrade pip
pip install -q -r aegis/requirements-finetune.txt

say "CUDA / driver check"
# torch gets pulled for some CUDA build (e.g. cu130). If that is newer than the installed
# NVIDIA driver supports, torch.cuda.is_available() is False even though nvidia-smi sees the GPU.
# Catch it here with a clear fix, before the long training step.
if ! python - <<'PY'
import sys, re, subprocess
import torch
built = getattr(torch.version, "cuda", None)          # CUDA the torch wheel was built for, e.g. "13.0"
ok = torch.cuda.is_available()
drv = ""
try:
    out = subprocess.check_output(["nvidia-smi", "--query-gpu=driver_version", "--format=csv,noheader"], text=True).strip().splitlines()[0]
    drv = out
except Exception:
    pass
print(f"  torch {torch.__version__} (built for CUDA {built}) · driver {drv or '?'} · cuda_available={ok}")
if ok:
    sys.exit(0)
print("\n  torch cannot see the GPU — almost always a CUDA build newer than your NVIDIA driver supports.")
print("  Fix (cleanest): update the Windows NVIDIA driver (GeForce Experience → Drivers, or nvidia.com/Download),")
print("  reboot Windows, then re-run this script — it reuses this venv and jumps straight to training.")
print("  Faster alt (no reboot): reinstall torch for your driver's CUDA, e.g.")
print("      pip install --force-reinstall torch --index-url https://download.pytorch.org/whl/cu124")
sys.exit(3)
PY
then
  echo "Stopping before training. Fix the driver/torch mismatch above, then re-run: bash aegis/finetune/run_local.sh"
  exit 3
fi

if [ -f "$DATA/sft/triage.jsonl" ]; then
  say "data: existing -> $DATA ($(wc -l < "$DATA/sft/triage.jsonl") rows)"
else
  say "data: synthetic scaffold -> $DATA"
  python -m aegis.dataset synth --out "$DATA" --n "$N" --seed 7
fi

say "plan"
python -m aegis.finetune.train --data "$DATA" --preset "$PRESET" --allow-synthetic --dry-run

say "train ($PRESET, QLoRA, $EPOCHS epochs) -> $OUT"
python -m aegis.finetune.train --data "$DATA" --preset "$PRESET" --epochs "$EPOCHS" --max-rows "$MAX_ROWS" --allow-synthetic --out "$OUT" ${RESUME:+--resume}

say "gate (held-out eval: misses <= 5, 0 injection leaks)"
python -m aegis.finetune.gate --adapter "$OUT" || true

say "done"
echo "adapter: $OUT"
echo "use it in AEGIS:  LLM_BACKEND=local AEGIS_LOCAL_4BIT=1 AEGIS_MODEL=$OUT  (triage first-pass; frontier model stays the judge)"
echo "NOTE: trained on SYNTHETIC data — retrain on a real export once v60.28 is live and analysts have labelled alerts."
