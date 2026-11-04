"""One trust check for promotion pointers (``current.json``), used by every path that acts on one.

A pointer names the adapter the SOC triages with. Four readers act on it — startup (``llm_client._promoted_model``),
hot-reload (``hot_reload.apply_reload``), the GPU-side vLLM register step (``vllm_registry.register_promoted_adapter``)
and the vendor-release writer (``model_updates``). Round 6 J-3 added an HMAC over the pointer but only startup checked
it, and vendor releases were never signed, so a signed host refused every legitimate release while hot-reload and the
register step served a forged pointer (review round 7 T-3 / R-1 / R-8). Every reader now calls :func:`verify_pointer`.

Checked here: the ``role`` matches the slot, the signature is valid when a signing key is configured
(``AEGIS_DECISION_KEY`` / ``AEGIS_CONSOLE_TOKEN``; ``AEGIS_ALLOW_UNVERIFIED_MODEL=1`` is the lab override), and a
vendor release is not one an operator rolled back on this host (``<AEGIS_MODEL_DIR>/denied.json``). The adapter
digest is checked by each reader where the bytes are (``digest.verify_adapter``).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from pathlib import Path

logger = logging.getLogger("aegis.finetune.pointer_trust")

POINTER_SIGNED = ("run", "role", "adapter", "sha256", "approved_by", "promoted_at")
RELEASE_APPROVER = "bluedefence-release"


def pointer_signature(cur: dict) -> str | None:
    """HMAC over a promotion pointer's identity fields, with the decision-signing key. None when no key is set.

    ``served_model`` is deliberately outside the signature: the register step stamps it after loading the verified
    bytes, and it is never used as the served name (``hot_reload.served_name`` uses ``run``)."""
    from aegis.hitl.signing import _key
    k = _key()
    if k is None:
        return None
    body = json.dumps({f: cur.get(f) for f in POINTER_SIGNED}, sort_keys=True, separators=(",", ":"), default=str)
    return hmac.new(k, b"aegis-model-pointer-v1|" + body.encode(), hashlib.sha256).hexdigest()


def sign_pointer(cur: dict) -> dict:
    """``cur`` with ``sig`` set (or removed when no key is configured)."""
    out = dict(cur)
    sig = pointer_signature(out)
    if sig:
        out["sig"] = sig
    else:
        out.pop("sig", None)
    return out


def _allow_unverified() -> bool:
    return os.environ.get("AEGIS_ALLOW_UNVERIFIED_MODEL", "") == "1"


def _release_denied(run: str) -> str:
    """Why a vendor release may not be served on this host ("" = it may)."""
    p = Path(os.environ.get("AEGIS_MODEL_DIR", "").strip() or "/var/lib/aegis/models") / "denied.json"
    if not p.exists():
        return ""
    try:
        v = json.loads(p.read_text())
        if not isinstance(v, list):
            raise TypeError("not a list")
    except (OSError, ValueError, TypeError) as e:
        return f"{p} is unreadable ({e}) — no vendor release is served until it is fixed"
    if run in {str(x) for x in v}:
        return f"release {run} was rolled back on this host (denied.json)"
    return ""


def verify_pointer(cur: dict, *, role_wanted: str = "triage", label: str = "pointer") -> tuple[bool, str]:
    """(ok, why). Role, signature and the release deny list; never the adapter bytes (callers check those)."""
    if not isinstance(cur, dict):
        return False, "not a pointer object"
    role = str(cur.get("role") or "triage")
    if role != role_wanted:
        return False, f"{label} is a {role} pointer, not {role_wanted} (one pointer per role)"
    want = pointer_signature(cur)
    if want is None:
        logger.warning("promotion pointers are not signed (set AEGIS_DECISION_KEY or AEGIS_CONSOLE_TOKEN): anything "
                       "that can write %s can choose the model", label)
    elif not hmac.compare_digest(str(cur.get("sig") or ""), want):
        if not _allow_unverified():
            return False, f"{label} is not signed by this installation's promotion key"
        logger.warning("%s unsigned / bad signature, accepted anyway (AEGIS_ALLOW_UNVERIFIED_MODEL=1)", label)
    if str(cur.get("approved_by") or "") == RELEASE_APPROVER:
        why = _release_denied(str(cur.get("run") or ""))
        if why:
            return False, why
    return True, ""


__all__ = ["POINTER_SIGNED", "RELEASE_APPROVER", "pointer_signature", "sign_pointer", "verify_pointer"]
