"""One trust check for promotion pointers (``current.json``), used by every path that acts on one.

A pointer names the adapter the SOC triages with. Four readers act on it — startup (``llm_client._promoted_model``),
hot-reload (``hot_reload.apply_reload``), the GPU-side vLLM register step (``vllm_registry.register_promoted_adapter``)
and the vendor-release writer (``model_updates``). Round 6 J-3 added an HMAC over the pointer but only startup checked
it, and vendor releases were never signed, so a signed host refused every legitimate release while hot-reload and the
register step served a forged pointer (review round 7 T-3 / R-1 / R-8). Every reader now calls :func:`verify_pointer`.

Checked here: the ``role`` matches the slot, the signature is valid when a signing key is configured
(``AEGIS_DECISION_KEY`` / ``AEGIS_CONSOLE_TOKEN``; ``AEGIS_ALLOW_UNVERIFIED_MODEL=1`` is the lab override), and the
pointer is the **latest** one this installation wrote and not one an operator rolled back. The adapter digest is
checked by each reader where the bytes are (``digest.verify_adapter``).

Anti-replay (review round 8 T8-1 / T8-4). A signature alone proved only that the pointer was written here *at some
point*: restoring an old signed ``current.json`` after ``retrain rollback`` (or after deleting ``denied.json``)
served the rolled-back model again. Every pointer now carries a monotonic ``seq`` inside its signed fields, and the
writer keeps a signed high-water record next to it (``pointer-state.json``: per role, the last ``seq`` written, the
runs/releases rolled back and the adapter digest of every vendor release installed). A reader accepts a pointer only
when its ``seq`` equals the record's — an older one is a replay — and its ``run`` is not in the record's deny list.
A missing or unsigned record next to a signed pointer is tamper, not "nothing denied". The pointer and its record
are written by :func:`commit_pointer` only (the promote and rollback paths), never by a routine state save (T8-2).

Limits: an attacker who can restore *both* files from the same earlier moment is caught only by a running process
(it remembers the highest ``seq`` it accepted); keep the pointer directory writable by the promotion step only, and
copy ``pointer-state.json`` with ``current.json`` when the pointer is shipped to another host. Pointers signed before
this change (``aegis-model-pointer-v1``) are refused; an operator re-adopts one after checking it with
``python -m aegis.finetune.pointer_trust adopt --pointer <current.json>``.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import logging
import os
import sys
import threading
from pathlib import Path

logger = logging.getLogger("aegis.finetune.pointer_trust")

POINTER_SIGNED = ("run", "role", "adapter", "sha256", "approved_by", "promoted_at", "seq", "previous")
_POINTER_SIGNED_V1 = ("run", "role", "adapter", "sha256", "approved_by", "promoted_at")
RELEASE_APPROVER = "bluedefence-release"
STATE_NAME = "pointer-state.json"

_SEEN: dict[tuple[str, str], int] = {}          # (record file, role) → highest seq this process accepted
_SEEN_LOCK = threading.Lock()


class PointerStateError(RuntimeError):
    """The signed high-water record next to a pointer is missing, unsigned or altered: nothing is written."""


def _key() -> bytes | None:
    from aegis.hitl.signing import _key as k
    return k()


def _canon(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), default=str).encode()


def pointer_signature(cur: dict) -> str | None:
    """HMAC over a promotion pointer's identity fields (incl. ``seq`` and ``previous``), with the decision-signing
    key. None when no key is set.

    ``served_model`` is deliberately outside the signature: the register step stamps it after loading the verified
    bytes, and it is never used as the served name (``hot_reload.served_name`` uses ``run``)."""
    k = _key()
    if k is None:
        return None
    body = _canon({f: cur.get(f) for f in POINTER_SIGNED})
    return hmac.new(k, b"aegis-model-pointer-v2|" + body, hashlib.sha256).hexdigest()


def _legacy_signature(cur: dict) -> str | None:
    k = _key()
    if k is None:
        return None
    body = _canon({f: cur.get(f) for f in _POINTER_SIGNED_V1})
    return hmac.new(k, b"aegis-model-pointer-v1|" + body, hashlib.sha256).hexdigest()


def sign_pointer(cur: dict) -> dict:
    """``cur`` with ``sig`` set (or removed when no key is configured). Writers go through :func:`commit_pointer`,
    which also assigns ``seq`` and advances the high-water record; a pointer signed here alone is refused by
    :func:`verify_pointer` unless its ``seq`` is the recorded one."""
    out = dict(cur)
    sig = pointer_signature(out)
    if sig:
        out["sig"] = sig
    else:
        out.pop("sig", None)
    return out


def signature_ok(cur: dict) -> bool:
    """True when ``cur`` carries a valid signature over every signed field (or no key is configured)."""
    want = pointer_signature(cur)
    return want is None or hmac.compare_digest(str(cur.get("sig") or ""), want)


def _allow_unverified() -> bool:
    return os.environ.get("AEGIS_ALLOW_UNVERIFIED_MODEL", "") == "1"


# ----------------------------------------------------------------------------------------- high-water record --

def default_pointer_path(role: str = "triage") -> Path:
    var = "AEGIS_VOTER_POINTER" if role == "judge" else "AEGIS_MODEL_POINTER"
    raw = os.environ.get(var, "").strip()
    if raw:
        return Path(raw)
    return Path(os.environ.get("AEGIS_MODEL_DIR", "").strip() or "/var/lib/aegis/models") / "current.json"


def state_path_for(pointer: str | Path) -> Path:
    return Path(pointer).parent / STATE_NAME


def _state_sig(body: dict, k: bytes) -> str:
    return hmac.new(k, b"aegis-pointer-state-v1|" + _canon(body), hashlib.sha256).hexdigest()


def load_state(pointer: str | Path) -> tuple[dict | None, str]:
    """(record, problem). ``(None, "")`` = no record yet; a record that is unreadable — or unsigned / altered on a
    host with a key — is ``(None, why)``."""
    p = state_path_for(pointer)
    try:
        raw = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, ""
    except OSError as e:
        return None, f"{p} is unreadable ({e})"
    try:
        d = json.loads(raw)
        if not isinstance(d, dict) or not isinstance(d.get("roles", {}), dict):
            raise TypeError("not a pointer-state object")
    except (ValueError, TypeError) as e:
        return None, f"{p} is unreadable ({e})"
    body = {k: v for k, v in d.items() if k != "sig"}
    k = _key()
    if k is not None and not hmac.compare_digest(str(d.get("sig") or ""), _state_sig(body, k)):
        return None, f"{p} is not signed by this installation's promotion key"
    return body, ""


def _role_entry(state: dict | None, role: str) -> dict:
    e = ((state or {}).get("roles") or {}).get(role) or {}
    return e if isinstance(e, dict) else {}


def _legacy_denied(pointer: str | Path) -> tuple[set[str], str]:
    """``<AEGIS_MODEL_DIR>/denied.json`` (vendor rollbacks recorded before T8-4) and the retrain loop's own
    ``state.json`` next to the pointer (rolled-back local runs, T8-1). Both are additive only — their absence denies
    nothing extra; the signed record is the authority."""
    out: set[str] = set()
    dp = Path(os.environ.get("AEGIS_MODEL_DIR", "").strip() or "/var/lib/aegis/models") / "denied.json"
    if dp.exists():
        try:
            v = json.loads(dp.read_text())
            if not isinstance(v, list):
                raise TypeError("not a list")
            out |= {str(x) for x in v}
        except (OSError, ValueError, TypeError) as e:
            return out, f"{dp} is unreadable ({e}) — no model pointer is served until it is fixed"
    sp = Path(pointer).parent / "state.json"
    if sp.exists():
        try:
            from aegis.finetune.retrain import read_signed_state
            d = read_signed_state(sp)
            out |= {r for r, i in (d.get("runs") or {}).items() if isinstance(i, dict) and i.get("denied")}
        except Exception as e:  # noqa: BLE001 — an altered retrain state cannot vouch for anything
            return out, f"{sp} cannot be trusted ({str(e)[:160]})"
    return out, ""


def denied_runs(pointer: str | Path, role: str = "triage") -> tuple[set[str], str]:
    """Runs/releases rolled back for ``role`` at this pointer location (signed record ∪ legacy deny files), and a
    problem string when any of them cannot be trusted (callers then refuse everything)."""
    st, why = load_state(pointer)
    if why:
        return set(), why
    legacy, lwhy = _legacy_denied(pointer)
    return {str(x) for x in _role_entry(st, role).get("denied") or []} | legacy, lwhy


def _write_atomic(p: Path, data: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(data, encoding="utf-8")
    os.replace(tmp, p)


def commit_pointer(pointer: str | Path, cur: dict | None, *, role: str = "triage",
                   deny: tuple[str, ...] | list[str] = (), releases: dict[str, str] | None = None,
                   keep_served: bool = True) -> dict | None:
    """The only writer of a pointer: advance the signed high-water record (``seq + 1``, ``deny`` added), then write
    ``cur`` signed with that ``seq`` — or remove the pointer when ``cur`` is None (rolled back to the base model).

    ``releases`` maps a vendor version to the adapter digest installed for it (checked again on rollback, T8-3).
    Raises :class:`PointerStateError` when the existing record is altered, or is missing while a sequenced pointer
    exists (somebody deleted it to forget a rollback)."""
    pointer = Path(pointer)
    st, why = load_state(pointer)
    if why:
        raise PointerStateError(why + " — refusing to write a promotion pointer (restore it, or re-adopt the pointer "
                                      "with `python -m aegis.finetune.pointer_trust adopt`)")
    on_disk: dict | None = None
    try:
        v = json.loads(pointer.read_text(encoding="utf-8"))
        on_disk = v if isinstance(v, dict) else None
    except (OSError, ValueError):
        on_disk = None
    if st is None and on_disk and on_disk.get("seq") is not None and \
            os.environ.get("AEGIS_POINTER_STATE_RESET", "") != "1":
        raise PointerStateError(f"{state_path_for(pointer)} is missing but {pointer} is a sequenced pointer — the "
                                "rollback record was deleted; refusing (AEGIS_POINTER_STATE_RESET=1 after review)")
    roles = dict((st or {}).get("roles") or {})
    e = dict(_role_entry(st, role))
    seq = int(e.get("seq") or 0) + 1
    e["seq"] = seq
    e["denied"] = sorted({str(x) for x in (e.get("denied") or [])} | {str(x) for x in deny if x})
    if releases:
        e["releases"] = {**(e.get("releases") or {}), **{str(k): str(v) for k, v in releases.items()}}
    e["current"] = cur.get("run") if cur else None
    roles[role] = e
    body = {"v": 1, "roles": roles}
    k = _key()
    rec = {**body, "sig": _state_sig(body, k)} if k is not None else body
    _write_atomic(state_path_for(pointer), json.dumps(rec, indent=1, sort_keys=True))
    if cur is None:
        pointer.unlink(missing_ok=True)
        return None
    out = {kk: vv for kk, vv in cur.items() if kk not in ("sig", "served_model")}
    out["role"] = out.get("role") or role
    out["seq"] = seq
    out.setdefault("previous", None)
    out = sign_pointer(out)
    if keep_served and isinstance(on_disk, dict) and on_disk.get("served_model") and \
            on_disk.get("run") == out.get("run") and on_disk.get("sha256") == out.get("sha256"):
        out["served_model"] = on_disk["served_model"]          # the GPU register step's stamp survives (D4-15)
    _write_atomic(pointer, json.dumps(out, indent=1))
    return out


def recorded_release_digest(pointer: str | Path, version: str, role: str = "triage") -> tuple[str | None, str]:
    """The adapter digest the record holds for an installed vendor release (None when it was never recorded)."""
    st, why = load_state(pointer)
    if why:
        return None, why
    return (_role_entry(st, role).get("releases") or {}).get(str(version)), ""


# ----------------------------------------------------------------------------------------------- the verifier --

def verify_pointer(cur: dict, *, role_wanted: str = "triage", label: str = "pointer",
                   path: str | Path | None = None) -> tuple[bool, str]:
    """(ok, why). Role, signature, sequence (anti-replay) and the deny list; never the adapter bytes (callers check
    those). ``path`` is where the pointer was read from — its high-water record sits next to it; default
    ``AEGIS_MODEL_POINTER`` / ``AEGIS_VOTER_POINTER`` / ``<AEGIS_MODEL_DIR>/current.json``."""
    if not isinstance(cur, dict):
        return False, "not a pointer object"
    role = str(cur.get("role") or "triage")
    if role != role_wanted:
        return False, f"{label} is a {role} pointer, not {role_wanted} (one pointer per role)"
    pointer = Path(path) if path else default_pointer_path(role_wanted)
    key = _key()
    lab = _allow_unverified()
    if key is None:
        logger.warning("promotion pointers are not signed (set AEGIS_DECISION_KEY or AEGIS_CONSOLE_TOKEN): anything "
                       "that can write %s can choose the model", label)
    elif not signature_ok(cur):
        legacy = _legacy_signature(cur)
        hint = (" (signed by an older release — check it and re-adopt it with `python -m aegis.finetune.pointer_trust "
                f"adopt --pointer {pointer}`)") if legacy and hmac.compare_digest(str(cur.get("sig") or ""), legacy) else ""
        if not lab:
            return False, f"{label} is not signed by this installation's promotion key{hint}"
        logger.warning("%s unsigned / bad signature, accepted anyway (AEGIS_ALLOW_UNVERIFIED_MODEL=1)", label)
    st, why = load_state(pointer)
    if why and not lab:
        return False, f"{label}: {why}"
    if st is None and key is not None and not lab:
        return False, (f"{label}: no signed pointer record at {state_path_for(pointer)} — a pointer is served only "
                       "alongside the record its writer keeps (deleting it must not forget a rollback)")
    entry = _role_entry(st, role_wanted)
    try:
        got = int(cur["seq"]) if cur.get("seq") is not None else 0
    except (TypeError, ValueError):
        got = -1
    if st is not None and not lab:
        want = int(entry.get("seq") or 0)
        if got < want:
            return False, f"{label} is an old pointer (seq {got} < {want}): a replay of a superseded promotion"
        if got > want:
            return False, f"{label} is newer (seq {got}) than its record (seq {want}): the record was rolled back"
    run = str(cur.get("run") or "")
    legacy, lwhy = _legacy_denied(pointer)
    if lwhy and not lab:
        return False, lwhy
    if run and run in {str(x) for x in entry.get("denied") or []}:
        return False, f"{run} was rolled back on this host"
    if run and run in legacy:
        return False, f"release {run} was rolled back on this host (denied.json / retrain state)"
    if not lab:
        try:
            cache = (str(state_path_for(pointer).resolve()), role_wanted)
        except OSError:
            cache = (str(state_path_for(pointer)), role_wanted)
        with _SEEN_LOCK:
            if got < _SEEN.get(cache, 0):
                return False, f"{label} is older (seq {got}) than one this process already served: a replay"
            _SEEN[cache] = max(got, _SEEN.get(cache, 0))
    return True, ""


# ----------------------------------------------------------------------------------------- operator adoption --

def adopt(pointer: str | Path, *, role: str = "triage") -> tuple[bool, str]:
    """Re-sign a pointer an older release wrote (v1 signature, no ``seq``) after checking it: valid v1 signature,
    no high-water record yet, adapter digest matches, not rolled back. Writes the record (seq 1, legacy deny lists
    carried in) and the v2 pointer."""
    pointer = Path(pointer)
    if _key() is None:
        return False, "no signing key configured (AEGIS_DECISION_KEY / AEGIS_CONSOLE_TOKEN)"
    try:
        cur = json.loads(pointer.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return False, f"{pointer} unreadable ({e})"
    if not isinstance(cur, dict):
        return False, "not a pointer object"
    if state_path_for(pointer).exists():
        return False, f"{state_path_for(pointer)} already exists; adopt is only for pointers written before it"
    legacy = _legacy_signature(cur)
    if not legacy or not hmac.compare_digest(str(cur.get("sig") or ""), legacy):
        return False, "the pointer does not carry a valid older-release signature"
    if str(cur.get("role") or "triage") != role:
        return False, f"pointer role {cur.get('role')!r} is not {role}"
    from aegis.finetune.digest import verify_adapter
    ok, why = verify_adapter(str(cur.get("adapter") or ""), cur.get("sha256"))
    if not ok:
        return False, why
    denied, dwhy = _legacy_denied(pointer)
    if dwhy:
        return False, dwhy
    if str(cur.get("run") or "") in denied:
        return False, f"{cur.get('run')} was rolled back on this host"
    commit_pointer(pointer, cur, role=role, deny=sorted(denied))
    return True, ""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m aegis.finetune.pointer_trust")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("adopt", help="re-sign a pointer written by an older release (after checking it)")
    a.add_argument("--pointer", required=True)
    a.add_argument("--role", default="triage", choices=("triage", "judge"))
    v = sub.add_parser("verify", help="check a pointer the way the SOC will")
    v.add_argument("--pointer", required=True)
    v.add_argument("--role", default="triage", choices=("triage", "judge"))
    args = ap.parse_args(argv)
    if args.cmd == "adopt":
        ok, why = adopt(args.pointer, role=args.role)
    else:
        try:
            cur = json.loads(Path(args.pointer).read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            print(f"unreadable: {e}")
            return 1
        ok, why = verify_pointer(cur, role_wanted=args.role, label=args.pointer, path=args.pointer)
    print("ok" if ok else f"refused: {why}")
    return 0 if ok else 1


__all__ = ["POINTER_SIGNED", "RELEASE_APPROVER", "STATE_NAME", "PointerStateError", "adopt", "commit_pointer",
           "default_pointer_path", "denied_runs", "load_state", "pointer_signature", "recorded_release_digest",
           "sign_pointer", "signature_ok", "state_path_for", "verify_pointer"]


if __name__ == "__main__":
    sys.exit(main())
