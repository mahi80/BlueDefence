"""Fine-tune a small open LLM as the Tier-1 triage first-pass (roadmap 3.3).

Pipeline (one place each):
    data.py   load sft/triage.jsonl → prompt/response pairs; refuse synthetic unless allowed; split
    config.py VRAM-aware model + QLoRA presets (RTX 40-laptop friendly; Gemma 3 4B default)
    train.py  QLoRA trainer (unsloth-first, transformers+peft fallback); --dry-run prints the plan
    gate.py   run the held-out eval cases through the tuned model; misses must beat the baseline

The tuned model slots into AEGIS as the triage first-pass behind the frontier judge:
``LLM_BACKEND=local`` with ``AEGIS_MODEL=<adapter dir>`` loads the base named in ``adapter_config.json`` + the LoRA adapter (4-bit by default when bitsandbytes is present) in the service.
"""

from .config import PRESETS, Preset, preset_for_vram
from .data import DataError, load_sft, split_rows

__all__ = ["PRESETS", "DataError", "Preset", "load_sft", "preset_for_vram", "split_rows"]
