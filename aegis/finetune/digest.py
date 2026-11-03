"""Content digest of a fine-tuned adapter directory, recorded at training time and checked again at promote
and at load, so the weights a human approved are the weights that run.

``v2:`` digests hash every file in the directory in full (relative path + size + bytes, streamed). Older
digests (no prefix) hashed only the first 4 MiB of ``.safetensors/.json/.bin`` files, so a change past
4 MiB in a tens-of-MB LoRA file went unseen; they are still verified with the old rule so existing runs
keep working, and new runs get ``v2:``.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

_V2 = "v2:"
_CHUNK = 1 << 20


def adapter_digest(d: str | Path) -> str:
    """Full-content digest of an adapter directory (``v2:`` + 32 hex chars)."""
    root = Path(d)
    h = hashlib.sha256()
    for p in sorted(x for x in root.rglob("*") if x.is_file()):
        rel = p.relative_to(root).as_posix()
        h.update(rel.encode("utf-8") + b"\0" + str(p.stat().st_size).encode() + b"\0")
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(_CHUNK), b""):
                h.update(chunk)
    return _V2 + h.hexdigest()[:32]


def _legacy_digest(d: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(d.rglob("*")):
        if p.is_file() and p.suffix in (".safetensors", ".json", ".bin"):
            h.update(p.name.encode())
            with open(p, "rb") as fh:
                h.update(fh.read(4 << 20))
    return h.hexdigest()[:16]


def verify_adapter(d: str | Path, expected: str | None) -> tuple[bool, str]:
    """(ok, reason). A missing directory or a mismatch is a failure; no recorded digest is a failure too —
    an adapter nobody fingerprinted cannot be shown to be the one that was approved."""
    root = Path(d)
    if not expected:
        return False, "no recorded digest"
    if not root.is_dir():
        return False, f"adapter directory {root} is missing"
    actual = adapter_digest(root) if expected.startswith(_V2) else _legacy_digest(root)
    if actual != expected:
        return False, f"adapter digest {actual} does not match the approved {expected}"
    return True, ""


__all__ = ["adapter_digest", "verify_adapter"]
