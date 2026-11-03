"""Hot adapter-reload — apply a human-approved model promotion at runtime, no restart.

The retrain pipeline (``retrain.py``) already exports → trains → gates → shadow-compares →
ships a ``model_promotion`` proposal → an analyst approves it → ``retrain sync`` writes the
promotion pointer (``AEGIS_MODEL_POINTER`` → ``current.json``). The one thing missing was that
the pointer only took effect at the **next process restart**: ``get_client()`` resolves the
promoted adapter exactly once, in ``build_pipeline``.

This module closes that gap. Every specialist and the orchestrator share the *one* primary
client instance ``build_pipeline`` constructed, so for the **vllm backend** a single in-place
``set_model(<served adapter name>)`` on that shared client swaps the whole pipeline with no
restart (vLLM routes a request to a loaded LoRA by the ``model`` field — the ``set_model``
primitive shipped with the vllm backend). The ``local``/GemmaClient backend has no in-place
swap (a PEFT reload re-reads GPU weights), so there a promotion still applies at restart; the
reload reports that rather than pretending it swapped.

Everything here is pure control-plane: it reads a small JSON pointer and calls ``set_model``.
No GPU, no training, no network — fully unit-tested. The GPU-side step that registers a
promoted LoRA with the vLLM server so ``set_model(name)`` resolves is the serving-side half of
C3 and lives with the trainer/deploy wiring, not here.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Optional

logger = logging.getLogger("aegis.finetune.hot_reload")


@dataclass
class ReloadResult:
    """What a reload attempt did. ``changed`` is True only when the live model actually swapped."""
    changed: bool
    mode: str = "noop"            # set_model | restart_required | refused | noop
    run: str = ""
    adapter: str = ""
    served_model: str = ""
    key: str = ""                 # the change-key the caller should store (compare against next time)
    detail: str = ""


def read_pointer(path: Optional[str] = None) -> Optional[dict]:
    """The promotion pointer dict (``current.json``), or None when unset/unreadable.

    Mirrors ``_promoted_model``'s fail-quiet contract: a bad pointer never raises."""
    ptr = path if path is not None else os.environ.get("AEGIS_MODEL_POINTER", "")
    if not ptr:
        return None
    try:
        with open(ptr, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except FileNotFoundError:
        logger.debug("[hot_reload] no promotion pointer at %s yet", ptr)       # normal before the first model release lands
        return None
    except Exception as exc:  # noqa: BLE001 — a bad pointer keeps the running model, never crashes the SOC
        logger.warning("[hot_reload] pointer %s unreadable (%s)", ptr, str(exc)[:160])
        return None


def pointer_key(ptr: dict) -> str:
    """Change-detection key for a promotion: content digest if present, else run, else adapter."""
    return str((ptr or {}).get("sha256") or (ptr or {}).get("run") or (ptr or {}).get("adapter") or "")


def served_name(ptr: dict) -> str:
    """The vLLM-registered adapter name for this promotion.

    Prefers an explicit ``served_model`` (set by the GPU-side register step); falls back to the
    ``run`` name, which is the convention that step uses when it registers the adapter."""
    return str((ptr or {}).get("served_model") or (ptr or {}).get("run") or "")


def unwrap(client: Any) -> Any:
    """Reach the real backend client under the PII-tokenizing wrapper (``_inner``)."""
    return getattr(client, "_inner", client)


def swap_in_place(primary: Any, served: str) -> bool:
    """vLLM fast path: mutate the shared client's served adapter in place.

    Because every specialist holds this same instance, the swap reaches all of them with no
    reassignment. Returns True when the backend supports ``set_model`` (vllm), False otherwise."""
    inner = unwrap(primary)
    setter = getattr(inner, "set_model", None)
    if not callable(setter):
        return False
    setter(served)
    # keep the wrapper's label in sync so the banner / primary_model report the live adapter
    if primary is not inner and hasattr(primary, "model"):
        try:
            primary.model = served
        except Exception:  # noqa: BLE001
            pass
    return True


def _unverified(ptr: dict, adapter: str, run: str) -> str:
    """Why this pointer may not be swapped in ("" = it may). The adapter must carry a recorded digest; when its
    directory is on this host the digest is checked here, otherwise the GPU-side register step checks it
    (``vllm_registry.register_promoted_adapter``), which loads only an adapter whose digest matches. The
    pointer file itself must be writable only by the promotion step. ``AEGIS_ALLOW_UNVERIFIED_MODEL=1`` is the
    explicit operator override for a lab."""
    if os.environ.get("AEGIS_ALLOW_UNVERIFIED_MODEL", "") == "1":
        return ""
    sha = str(ptr.get("sha256") or "")
    if not sha:
        return "the promotion pointer carries no adapter digest"
    if adapter and os.path.isdir(adapter):
        from aegis.finetune.digest import verify_adapter
        ok, why = verify_adapter(adapter, sha)
        return "" if ok else why
    return ""


def apply_reload(primary: Any, prev_key: str, ptr: Optional[dict]) -> ReloadResult:
    """Decide and perform a reload. Pure except for the in-place ``set_model`` on ``primary``.

    - no pointer, or the pointer is unchanged since ``prev_key`` → noop
    - pointer changed and the backend supports in-place swap (vllm) → set_model, changed
    - pointer changed but the backend has no in-place swap (local) → restart_required
    """
    if not ptr:
        return ReloadResult(changed=False, mode="noop", detail="no promotion pointer")
    key = pointer_key(ptr)
    run = str(ptr.get("run", ""))
    adapter = str(ptr.get("adapter", ""))
    if key and key == prev_key:
        return ReloadResult(changed=False, mode="noop", run=run, adapter=adapter, key=key, detail="unchanged")
    why = _unverified(ptr, adapter, run)
    if why:                          # tampered, swapped after approval, or never fingerprinted: keep the running model
        logger.error("[hot_reload] promotion run=%s refused: %s", run, why)
        return ReloadResult(changed=False, mode="refused", run=run, adapter=adapter, key=key, detail=why)
    served = served_name(ptr)
    if served and swap_in_place(primary, served):
        logger.info("[hot_reload] swapped triage model → run=%s served=%s (no restart)", run, served)
        return ReloadResult(changed=True, mode="set_model", run=run, adapter=adapter, served_model=served, key=key)
    logger.warning("[hot_reload] promotion run=%s detected but backend has no in-place swap; "
                   "it applies at the next restart", run)
    return ReloadResult(changed=False, mode="restart_required", run=run, adapter=adapter, served_model=served,
                        key=key, detail="backend has no set_model")


__all__ = ["ReloadResult", "read_pointer", "pointer_key", "served_name", "unwrap", "swap_in_place", "apply_reload"]
