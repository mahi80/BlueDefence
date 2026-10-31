"""QLoRA trainer for the triage first-pass (roadmap 3.3).

    # on the GPU box (WSL2 + CUDA), after: pip install -r aegis/requirements-finetune.txt
    python -m aegis.finetune.train --data datasets/aegis-triage-v1 --out runs/triage-gemma3-4b

    # plan only, no GPU / no torch needed — prints the VRAM-aware config and the exact commands
    python -m aegis.finetune.train --data datasets/synth-v1 --dry-run --vram 8 --allow-synthetic

Unsloth is used when importable (≈2× faster, ~half the VRAM on consumer cards); otherwise it
falls back to transformers + peft + bitsandbytes. The step that needs a GPU is import-guarded,
so this module imports and ``--dry-run`` works anywhere (CI included).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import DEFAULT, get_preset, preset_for_vram
from .data import is_non_analyst, load_sft, split_rows


def _plan(args, preset, n_train, n_val) -> str:
    return (
        f"model           {preset.model}  ({preset.key})\n"
        f"quantization    4-bit nf4 QLoRA + grad checkpointing\n"
        f"max_seq_len     {preset.max_seq_len}\n"
        f"batch / accum   {preset.batch_size} × {preset.grad_accum}  (effective {preset.effective_batch})\n"
        f"lora r / alpha  {preset.lora_r} / {preset.lora_alpha}  (q,k,v,o,gate,up,down)\n"
        f"epochs / lr     {args.epochs} / {args.lr}\n"
        f"data            {n_train} train + {n_val} val rows\n"
        f"out             {args.out}\n"
        f"backend         {'unsloth' if _have('unsloth') else 'transformers+peft' if _have('peft') else 'NONE — pip install -r aegis/requirements-finetune.txt'}\n"
        f"note            {preset.note}"
    )


def _have(mod: str) -> bool:
    import importlib.util
    return importlib.util.find_spec(mod) is not None


def _formatting(examples, tokenizer) -> list[str]:
    """Render each example with the model's chat template (non-thinking mode, same as the gate);
    the assistant JSON is the completion."""
    from .gate import render_prompt
    texts = []
    for ex in examples:
        msgs = [{"role": "user", "content": ex.prompt}, {"role": "assistant", "content": ex.response}]
        texts.append(render_prompt(tokenizer, msgs, add_generation_prompt=False))
    return texts


def run(args) -> int:
    rows = load_sft(args.data, allow_synthetic=args.allow_synthetic)
    if args.max_rows and len(rows) > args.max_rows:
        import random
        random.Random(args.seed).shuffle(rows)
        rows = rows[:args.max_rows]
    train, val = split_rows(rows)
    preset = get_preset(args.preset) if args.preset else preset_for_vram(args.vram)
    syn = sum(1 for r in train + val if is_non_analyst(r.label_source))
    print(f"\nplan:\n{_plan(args, preset, len(train), len(val))}")
    if syn:
        print(f"\n  ⚠ {syn} rows are synthetic / public-corpus (not analyst-labelled) — pre-training only; not a bank model.")
    if args.dry_run:
        print("\n--dry-run: nothing trained. Install the GPU deps and drop --dry-run to run for real.")
        return 0

    backend = "unsloth" if _have("unsloth") else "peft" if _have("peft") else None
    if backend is None:
        print("\nERROR: neither unsloth nor peft installed — pip install -r aegis/requirements-finetune.txt",
              file=sys.stderr)
        return 2
    try:
        # unsloth must be imported BEFORE torch / transformers / peft or it cannot patch them.
        if backend == "unsloth":
            import unsloth  # noqa: F401
        import torch
    except Exception as e:  # noqa: BLE001 — surface the real import error instead of masking it
        import traceback
        print(f"\nERROR importing the {backend} backend: {type(e).__name__}: {e}", file=sys.stderr)
        traceback.print_exc()
        print("Reinstall the GPU deps: pip install -r aegis/requirements-finetune.txt", file=sys.stderr)
        return 2
    if not torch.cuda.is_available():
        print("\nERROR: torch is installed but torch.cuda.is_available() is False — the torch CUDA build does "
              "not match your NVIDIA driver (see README 'CUDA/driver gotcha').", file=sys.stderr)
        return 2

    Path(args.out).mkdir(parents=True, exist_ok=True)
    if backend == "unsloth":
        _train_unsloth(args, preset, train, val)
    else:
        _train_peft(args, preset, train, val)
    (Path(args.out) / "aegis-finetune.json").write_text(json.dumps({
        "model": preset.model, "preset": preset.key, "train": len(train), "val": len(val),
        "synthetic_rows": syn, "epochs": args.epochs, "lr": args.lr,
    }, indent=2) + "\n", encoding="utf-8")
    print(f"\nadapter written to {args.out}. Next: python -m aegis.finetune.gate --adapter {args.out}")
    return 0


def _train_unsloth(args, preset, train, val):  # pragma: no cover — needs a GPU
    from datasets import Dataset
    from trl import SFTConfig, SFTTrainer
    from unsloth import FastLanguageModel  # first, before trl/transformers/datasets
    model, tok = FastLanguageModel.from_pretrained(preset.model, max_seq_length=preset.max_seq_len,
                                                    load_in_4bit=True, dtype=None)
    model = FastLanguageModel.get_peft_model(model, r=preset.lora_r, lora_alpha=preset.lora_alpha,
                                             target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                                                             "gate_proj", "up_proj", "down_proj"],
                                             use_gradient_checkpointing="unsloth")
    ds = Dataset.from_dict({"text": _formatting(train, tok)})
    vds = Dataset.from_dict({"text": _formatting(val, tok)}) if val else None
    trainer = SFTTrainer(model=model, tokenizer=tok, train_dataset=ds, eval_dataset=vds,
                         args=SFTConfig(output_dir=args.out, per_device_train_batch_size=preset.batch_size,
                                        gradient_accumulation_steps=preset.grad_accum, num_train_epochs=args.epochs,
                                        learning_rate=args.lr, bf16=True, logging_steps=10, dataset_text_field="text",
                                        max_seq_length=preset.max_seq_len))
    trainer.train(resume_from_checkpoint=_resume_path(args))
    model.save_pretrained(args.out); tok.save_pretrained(args.out)


def _resume_path(args):
    """``--resume`` → the latest ``checkpoint-N`` under ``--out`` (or an explicit path); None otherwise."""
    if not getattr(args, "resume", None):
        return None
    if args.resume not in ("auto", "latest", "1", "true"):
        return args.resume
    cps = sorted((p for p in Path(args.out).glob("checkpoint-*") if p.is_dir()),
                 key=lambda p: int(p.name.split("-")[-1]) if p.name.split("-")[-1].isdigit() else -1)
    if not cps:
        print("  --resume: no checkpoint found under", args.out, "— starting fresh")
        return None
    print(f"  --resume: continuing from {cps[-1]}")
    return str(cps[-1])


def _train_peft(args, preset, train, val):  # pragma: no cover — needs a GPU
    import torch
    from datasets import Dataset
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        BitsAndBytesConfig,
        TrainingArguments,
    )
    from trl import SFTTrainer
    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_compute_dtype=torch.bfloat16,
                             bnb_4bit_use_double_quant=True)
    tok = AutoTokenizer.from_pretrained(preset.model)
    model = AutoModelForCausalLM.from_pretrained(preset.model, quantization_config=bnb, device_map="auto")
    model = prepare_model_for_kbit_training(model)
    model = get_peft_model(model, LoraConfig(r=preset.lora_r, lora_alpha=preset.lora_alpha, lora_dropout=.05,
                                             bias="none", task_type="CAUSAL_LM",
                                             target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                                                             "gate_proj", "up_proj", "down_proj"]))
    ds = Dataset.from_dict({"text": _formatting(train, tok)})
    vds = Dataset.from_dict({"text": _formatting(val, tok)}) if val else None
    trainer = SFTTrainer(model=model, tokenizer=tok, train_dataset=ds, eval_dataset=vds,
                         args=TrainingArguments(output_dir=args.out, per_device_train_batch_size=preset.batch_size,
                                                gradient_accumulation_steps=preset.grad_accum, num_train_epochs=args.epochs,
                                                learning_rate=args.lr, bf16=True, logging_steps=10,
                                                gradient_checkpointing=True))
    trainer.train(resume_from_checkpoint=_resume_path(args))
    model.save_pretrained(args.out); tok.save_pretrained(args.out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", required=True, help="dataset dir or sft/triage.jsonl")
    ap.add_argument("--out", default="runs/triage", help="adapter output dir")
    ap.add_argument("--preset", default="", help=f"model preset (default: auto from --vram; else {DEFAULT})")
    ap.add_argument("--vram", type=float, default=8, help="GPU VRAM in GB, used to auto-pick the preset")
    ap.add_argument("--epochs", type=float, default=3.0)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--allow-synthetic", action="store_true", help="permit synthetic / public-corpus rows (not analyst-labelled)")
    ap.add_argument("--max-rows", type=int, default=0, help="train on a random subset of this size (0 = all)")
    ap.add_argument("--resume", nargs="?", const="auto", default=None,
                    help="continue from the latest checkpoint-N under --out (or a given checkpoint path)")
    ap.add_argument("--seed", type=int, default=7, help="seed for --max-rows sampling")
    ap.add_argument("--dry-run", action="store_true", help="print the plan and exit; no GPU needed")
    args = ap.parse_args(argv)
    try:
        return run(args)
    except Exception as e:  # noqa: BLE001
        print(f"ERROR: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
