"""VRAM-aware presets for QLoRA triage fine-tuning.

Numbers are for 4-bit QLoRA (bitsandbytes nf4) with gradient checkpointing, the setup that
fits a triage fine-tune on a consumer RTX 40-laptop GPU. `preset_for_vram(gb)` picks the
largest model that trains comfortably in the detected VRAM; the default stays Gemma 3 4B
because AEGIS already has a `GemmaClient` backend and the voter is designed to be a different
model family from the frontier judge, so a tuned Gemma drops in with no new plumbing.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Preset:
    key: str
    model: str                 # HF repo id
    min_vram_gb: int           # 4-bit QLoRA + grad-checkpointing headroom
    max_seq_len: int
    batch_size: int
    grad_accum: int
    lora_r: int
    lora_alpha: int
    note: str

    @property
    def effective_batch(self) -> int:
        return self.batch_size * self.grad_accum


# Ordered small → large. A triage alert+verdict is short, so 2k context is ample.
PRESETS: list[Preset] = [
    Preset("gemma3-1b", "google/gemma-3-1b-it", 6, 2048, 8, 2, 16, 32,
           "smallest; fast iteration or <8 GB cards"),
    Preset("gemma3-4b", "google/gemma-3-4b-it", 8, 2048, 4, 4, 16, 32,
           "default — pairs with AEGIS's existing Gemma backend; trains on 8 GB"),
    Preset("qwen3-4b", "Qwen/Qwen3-4B", 8, 2048, 4, 4, 16, 32,
           "strong 4B alternative to Gemma; 8 GB"),
    Preset("qwen3-8b", "Qwen/Qwen3-8B", 12, 2048, 2, 8, 16, 32,
           "stronger triage model; needs 12 GB+"),
    Preset("llama3.1-8b", "meta-llama/Llama-3.1-8B-Instruct", 12, 2048, 2, 8, 16, 32,
           "8B alternative; gated repo, needs HF access"),
    Preset("gemma3-12b", "google/gemma-3-12b-it", 16, 1536, 1, 16, 16, 32,
           "largest that fits a 16 GB laptop (RTX 4090 mobile), tight"),
    Preset("mistral-7b-v0.3", "mistralai/Mistral-7B-Instruct-v0.3", 12, 2048, 2, 8, 16, 32,
           "Apache-2.0, ungated; 32k vocab = light logits; independent family for the judge/voter"),
]

DEFAULT = "gemma3-4b"
_BY_KEY = {p.key: p for p in PRESETS}


def get_preset(key: str) -> Preset:
    if key not in _BY_KEY:
        raise KeyError(f"unknown preset {key!r}; choose from {', '.join(_BY_KEY)}")
    return _BY_KEY[key]


def preset_for_vram(gb: float, *, prefer_family: str = "gemma") -> Preset:
    """Largest preset whose min_vram_gb ≤ gb; ties broken toward prefer_family, then the default."""
    fits = [p for p in PRESETS if p.min_vram_gb <= gb]
    if not fits:
        return _BY_KEY["gemma3-1b"]
    best = max(p.min_vram_gb for p in fits)
    tier = [p for p in fits if p.min_vram_gb == best]
    for p in tier:
        if prefer_family in p.key:
            return p
    return tier[0]
