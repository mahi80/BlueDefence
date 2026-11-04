"""Model updates — the brain ships to every installation like antivirus definitions.

BlueDefence trains on the pooled Community data, gates the adapter (``aegis.finetune.gate``) and
**publishes** it; every installation **pulls** it on its daily licence heartbeat, verifies it, and
hot-swaps (vLLM) or applies it at the next restart (local backend). The bank never has to do
anything; the weights come to them.

    publisher (you)        python -m aegis.finetune.publish --adapter runs/…/adapter --version 2026.11.1 --channel stable
                           → tar.gz + sha256 → POST /releases (admin) → presigned S3 PUT → POST /releases/{v}/publish
                           → the service signs a release MANIFEST (RS256, same issuer key as the licence)

    installation           GET /updates?channel=stable&base=<base model>&current=<version>   (bearer = licence)
                           → {manifest_token, url}  → download → sha256 matches the SIGNED manifest → verify signature
                           against aegis/keys → extract to AEGIS_MODEL_DIR/<version>/ → write the promotion pointer
                           (current.json) → aegis.finetune.hot_reload applies it (set_model / restart_required)

Two signatures stand between an attacker and a bank's brain: TLS to the licence service, and the
manifest signed with the issuer key the image already trusts for licences. A download whose sha256
does not match the signed manifest is deleted. Staged rollout: ``rollout_pct`` on a release gates by a
stable hash of the installation id, so a bad adapter reaches 10 % of the fleet, not all of it.
Rollback: the previous version stays on disk; ``python -m aegis.model_updates rollback`` repoints.

Env: ``AEGIS_MODEL_UPDATES`` (default 1 when ``AEGIS_LICENSE_SERVER`` is set; a pointer approved by the bank's
own retrain loop is never replaced unless ``AEGIS_MODEL_UPDATES_REPLACE_LOCAL=1``), ``AEGIS_MODEL_CHANNEL``
(stable | beta), ``AEGIS_MODEL_DIR`` (/var/lib/aegis/models), ``AEGIS_MODEL_POINTER`` (the pointer file
``hot_reload`` reads; defaults to ``<AEGIS_MODEL_DIR>/current.json``), ``AEGIS_MODEL_BASE`` (which base
the installation runs — only releases for that base are offered).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import shutil
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from aegis import license as licensing

logger = logging.getLogger("aegis.model_updates")

DEFAULT_DIR = "/var/lib/aegis/models"
MANIFEST_TYP = "AEGIS-MODEL-RELEASE"
MANIFEST_FILE = "manifest.jwt"


# ---------------------------------------------------------------- manifest --

def sign_manifest(rel: dict, *, n: int, d: int, kid: str) -> str:
    """Server side: ``<header>.<payload>.<sig>`` with ``typ`` = AEGIS-MODEL-RELEASE (never confusable with a licence)."""
    header = licensing._b64u(json.dumps({"alg": "RS256", "typ": MANIFEST_TYP, "kid": kid}, separators=(",", ":")).encode())
    body = licensing._b64u(json.dumps(rel, sort_keys=True, separators=(",", ":")).encode())
    sig = licensing.rsa_sign(f"{header}.{body}".encode(), n, d)
    return f"{header}.{body}.{licensing._b64u(sig)}"


def verify_manifest(token: str, keys: dict[str, tuple[int, int]] | None = None) -> tuple[dict | None, str]:
    """Installation side: the release dict on a good signature, else ``(None, reason)``."""
    keys = keys if keys is not None else licensing.load_public_keys()
    try:
        h, b, s = token.strip().split(".")
        header = json.loads(licensing._unb64u(h))
        if header.get("alg") != "RS256" or header.get("typ") != MANIFEST_TYP:
            return None, "not a model-release manifest"
        kid = str(header.get("kid", ""))
        if kid not in keys:
            return None, f"unknown signing key '{kid}'"
        n, e = keys[kid]
        if not licensing.rsa_verify(f"{h}.{b}".encode(), licensing._unb64u(s), n, e):
            return None, "manifest signature does not verify"
        rel = json.loads(licensing._unb64u(b))
        for k in ("version", "channel", "base_model", "sha256", "size"):
            if k not in rel:
                return None, f"manifest lacks {k}"
        return rel, ""
    except (ValueError, TypeError, KeyError) as exc:
        return None, f"malformed manifest ({type(exc).__name__})"


def _vkey(v: str) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return (0,)


def in_rollout(installation_id: str, pct: int) -> bool:
    """Stable bucket 0..99 from the installation id; a release at rollout_pct=10 reaches the same 10 % every day."""
    if pct >= 100:
        return True
    if pct <= 0:
        return False
    bucket = int(hashlib.sha256(installation_id.encode()).hexdigest()[:8], 16) % 100
    return bucket < pct


# ------------------------------------------------------------------- state --

def model_dir(env: dict | None = None) -> Path:
    env = os.environ if env is None else env
    return Path(env.get("AEGIS_MODEL_DIR", DEFAULT_DIR))


def pointer_path(env: dict | None = None) -> Path:
    env = os.environ if env is None else env
    return Path(env.get("AEGIS_MODEL_POINTER") or (model_dir(env) / "current.json"))


def current_version(env: dict | None = None) -> str:
    try:
        return str(json.loads(pointer_path(env).read_text()).get("run", ""))
    except (OSError, ValueError):
        return ""


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


_VERSION_RX = re.compile(r"^[0-9]{4}\.[0-9]{1,2}\.[0-9]{1,3}$")
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024 * 1024      # an adapter is tens of MB; a manifest asking for more is wrong


def _safe_extract(tar: tarfile.TarFile, dest: Path) -> None:
    root = dest.resolve()
    for m in tar.getmembers():
        target = (dest / m.name).resolve()
        if not (target == root or target.is_relative_to(root)) or m.issym() or m.islnk() or m.isdev():
            raise RuntimeError(f"unsafe member in release archive: {m.name}")
    if not hasattr(tarfile, "data_filter"):
        raise RuntimeError("this Python lacks tarfile.data_filter (needs 3.11.4+/3.12) — refusing to extract a downloaded archive")
    tar.extractall(dest, filter="data")   # strips absolute paths, links, device nodes, odd modes


# ---------------------------------------------------------------- client --

def check(server: str, token: str, *, channel: str, base_model: str, current: str, timeout: float = 20.0) -> dict | None:
    """Ask the service for the latest release; ``None`` when there is nothing newer for this installation."""
    from aegis.license import _require_https
    _require_https(server)                                   # bearer token on the request
    q = f"/updates?channel={channel}&base={urllib.request.quote(base_model, safe='')}&current={urllib.request.quote(current, safe='')}"
    req = urllib.request.Request(server.rstrip("/") + q, headers={"Authorization": "Bearer " + token.strip(), "User-Agent": "aegis-model-updates/1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            res = json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        if e.code == 204:
            return None
        try:
            msg = json.loads(e.read()).get("error", "")
        except Exception:  # noqa: BLE001
            msg = ""
        raise licensing.LicenseError(f"/updates refused ({e.code}): {msg or e.reason}") from None
    return res if res.get("manifest_token") else None


def download_and_install(res: dict, *, dest_root: Path, keys: dict | None = None, timeout: float = 600.0) -> dict:
    """Verify the signed manifest, fetch the archive, verify sha256 + size, extract to ``<dest_root>/<version>/``.
    Returns the release dict with ``adapter`` (the directory). Anything failing verification is deleted."""
    rel, why = verify_manifest(res["manifest_token"], keys)
    if rel is None:
        raise RuntimeError(f"release manifest rejected: {why}")
    version = str(rel["version"])
    if not _VERSION_RX.match(version):
        raise RuntimeError(f"release version {version!r} is not a valid version string")
    if not 0 < int(rel["size"]) <= MAX_ARCHIVE_BYTES:
        raise RuntimeError(f"manifest size {rel['size']} is out of range")
    target = dest_root / version
    if (target / ".complete").exists():
        return {**rel, "adapter": str(target), "already": True}
    dest_root.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=dest_root, suffix=".part", delete=False) as tmp:
        tmp_path = Path(tmp.name)
        try:
            from aegis.license import _require_https
            _require_https(str(res["url"]))                  # a signed manifest still must not be fetched over plain http
            req = urllib.request.Request(res["url"], headers={"User-Agent": "aegis-model-updates/1"})
            got_bytes = 0
            with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 — URL came from the verified service response
                for chunk in iter(lambda: r.read(1 << 20), b""):
                    got_bytes += len(chunk)
                    if got_bytes > int(rel["size"]):
                        raise RuntimeError(f"download exceeds the manifest size {rel['size']}")
                    tmp.write(chunk)
        except Exception:
            tmp_path.unlink(missing_ok=True)
            raise
    try:
        if tmp_path.stat().st_size != int(rel["size"]):
            raise RuntimeError(f"size mismatch: got {tmp_path.stat().st_size}, manifest says {rel['size']}")
        got = _sha256_file(tmp_path)
        if got != rel["sha256"]:
            raise RuntimeError(f"sha256 mismatch: archive {got[:16]}… ≠ signed manifest {rel['sha256'][:16]}…")
        if target.exists():
            shutil.rmtree(target)
        target.mkdir(parents=True)
        with tarfile.open(tmp_path, "r:gz") as tar:
            _safe_extract(tar, target)
        if not (target / "adapter_config.json").exists():
            raise RuntimeError("archive holds no adapter_config.json")
        (target / "release.json").write_text(json.dumps(rel, indent=1))
        # the signed manifest stays with the release: a rollback to it re-verifies the directory against it (T8-3)
        (target / MANIFEST_FILE).write_text(str(res["manifest_token"]).strip())
        (target / ".complete").write_text(str(int(time.time())))
    except Exception:
        shutil.rmtree(target, ignore_errors=True)
        raise
    finally:
        tmp_path.unlink(missing_ok=True)
    return {**rel, "adapter": str(target)}


def write_pointer(rel: dict, *, pointer: Path, previous: str = "", served: bool = False) -> dict:
    """The promotion pointer ``aegis.finetune.hot_reload`` reads, signed with the installation's promotion key and
    ``role: triage`` so every reader's trust check accepts it (review round 7 T-3 / R-8: an unsigned release pointer
    was refused at startup on a signed host, while hot-reload served forged ones).

    Written through ``pointer_trust.commit_pointer``: ``seq`` and ``previous`` are inside the signature and the
    signed record next to the pointer remembers this release's adapter digest, so a rollback can re-check the
    directory and an old pointer cannot be replayed (round 8 T8-1 / T8-3).

    ``served_model`` is stamped only when ``served`` — the adapter really was loaded into vLLM under the version
    name. Pre-stamping it made the GPU-side register step skip a rolled-back release as "already registered"
    (round 7 R-9); it is outside the signature, so the register step may stamp it later."""
    # sha256 in the pointer is the ADAPTER digest that load and hot-reload re-check (finetune/digest.py); the
    # release archive's sha256 (already checked against the signed manifest) is kept as archive_sha256. Writing
    # the archive hash here made every signed release fail the adapter check after #66.
    return _commit_release(rel, pointer=pointer, previous=previous, served=served)


def _commit_release(rel: dict, *, pointer: Path, previous: str = "", served: bool = False,
                    deny: tuple[str, ...] = ()) -> dict:
    from aegis.finetune.digest import adapter_digest
    from aegis.finetune.pointer_trust import RELEASE_APPROVER, commit_pointer
    digest = adapter_digest(rel["adapter"])
    ptr = {"run": str(rel["version"]), "role": "triage", "adapter": rel["adapter"], "sha256": digest,
           "archive_sha256": rel["sha256"],
           "base_model": rel["base_model"], "channel": rel["channel"], "promoted_at": int(time.time()), "approved_by": RELEASE_APPROVER,
           "notes": rel.get("notes", ""), "previous": str(previous or "")}
    out = commit_pointer(pointer, ptr, role="triage", deny=deny, releases={str(rel["version"]): digest},
                         keep_served=False)
    assert out is not None
    if served:
        out["served_model"] = str(rel["version"])             # outside the signature (stamped after a real load)
        tmp = pointer.with_name(pointer.name + ".tmp")
        tmp.write_text(json.dumps(out, indent=1))
        os.replace(tmp, pointer)                   # atomic: hot_reload / current_version never see a torn pointer
    return out


def _load_into_vllm(rel: dict, env: dict) -> bool:
    """On the vLLM backend the adapter has to be registered with the server before the pointer flips, or every
    triage would 404 against a LoRA name vLLM has never heard of. Raises on failure (the pointer is then not written).
    Returns True when it was loaded into vLLM, False on a backend that needs no registration."""
    backend = (env.get("LLM_BACKEND") or env.get("AEGIS_LLM_BACKEND") or "").strip().lower()
    if backend != "vllm":
        return False
    from aegis.finetune.vllm_registry import VLLMAdapterRegistry
    ok, how = VLLMAdapterRegistry().load(str(rel["version"]), str(rel["adapter"]))
    if not ok:
        raise RuntimeError(f"vLLM refused to load adapter {rel['version']} ({how}); keeping the current model")
    logger.info("[model_updates] vLLM %s adapter %s", how, rel["version"])
    return True


def update_once(*, server: str, token: str, installation_id: str, env: dict | None = None) -> dict:
    """One check → (download → verify → install → point) cycle. Never raises; returns what happened."""
    env = os.environ if env is None else env
    channel = env.get("AEGIS_MODEL_CHANNEL", "stable").strip() or "stable"
    base = env.get("AEGIS_MODEL_BASE", "").strip() or env.get("AEGIS_MODEL", "").strip()
    cur = current_version(env)
    if not base:
        return {"updated": False, "reason": "AEGIS_MODEL_BASE (or AEGIS_MODEL) is not set — an adapter is only safe on the base it was "
                                           "trained for, so no release is requested", "current": cur}
    try:
        res = check(server, token, channel=channel, base_model=base, current=cur)
        if res is None:
            return {"updated": False, "reason": "up to date", "current": cur}
        rel, why = verify_manifest(res["manifest_token"])
        if rel is None:
            return {"updated": False, "reason": f"release manifest rejected: {why}", "current": cur}
        if str(rel.get("channel")) != channel or rel.get("base_model") not in (base, "any"):
            return {"updated": False, "reason": f"release {rel.get('version')} is for {rel.get('channel')}/{rel.get('base_model')}, not {channel}/{base}", "current": cur}
        denied = _denied(env)
        if _ALL in denied:
            return {"updated": False, "reason": "the rollback record (pointer-state.json / denied.json) cannot be trusted — no "
                                                "update is applied until it is fixed",
                    "current": cur}
        if str(rel.get("version")) in denied:
            return {"updated": False, "reason": f"release {rel.get('version')} was rolled back on this host — not re-applied "
                                                 "(it is in this host's signed rollback record)", "current": cur}
        local = _local_model(env)
        if local:
            # the pointer names a model this bank trained and a person here approved (aegis.finetune.retrain): a
            # vendor release must not replace it silently (review round 4 D4-9)
            return {"updated": False, "reason": f"the current model {cur or '?'} is the bank's own ({local}); set "
                                                 "AEGIS_MODEL_UPDATES_REPLACE_LOCAL=1 to let releases replace it",
                    "current": cur, "offered": rel.get("version")}
        if cur and _vkey(str(rel.get("version"))) <= _vkey(cur):
            return {"updated": False, "reason": f"offered {rel.get('version')} is not newer than {cur} (downgrade refused)", "current": cur}
        if not in_rollout(installation_id, int(rel.get("rollout_pct", 100))):
            return {"updated": False, "reason": "not in this release's rollout yet", "current": cur, "offered": rel.get("version")}
        installed = download_and_install(res, dest_root=model_dir(env))
        loaded = _load_into_vllm(installed, env)
        write_pointer(installed, pointer=pointer_path(env), previous=cur, served=loaded)
        logger.info("[model_updates] installed %s (%s, %s) → %s; hot-reload applies it", installed["version"], installed["channel"],
                    installed["base_model"], installed["adapter"])
        _prune(model_dir(env), keep={installed["version"], cur})
        return {"updated": True, "version": installed["version"], "previous": cur, "adapter": installed["adapter"]}
    except Exception as e:  # noqa: BLE001 — a failed update never affects the running SOC
        logger.warning("[model_updates] update failed: %s", str(e)[:200])
        return {"updated": False, "reason": str(e)[:200], "current": cur}


def _local_model(env: dict) -> str:
    """Who approved the current pointer, when it is not a BlueDefence release (else "")."""
    if str(env.get("AEGIS_MODEL_UPDATES_REPLACE_LOCAL", "")).strip().lower() in ("1", "true", "yes", "on"):
        return ""
    try:
        ptr = json.loads(pointer_path(env).read_text())
    except (OSError, ValueError):
        return ""
    if not isinstance(ptr, dict) or not ptr.get("run"):
        return ""
    who = str(ptr.get("approved_by") or "")
    return "" if who == "bluedefence-release" else f"approved by {who or 'an operator'}"


def _prune(root: Path, keep: set[str], max_keep: int = 3) -> None:
    """Keep the current, the previous and the newest few complete releases; delete the rest."""
    done = sorted((p for p in root.iterdir() if p.is_dir() and (p / ".complete").exists()),
                  key=lambda p: (p / ".complete").stat().st_mtime, reverse=True)
    for p in done[max_keep:]:
        if p.name not in keep:
            shutil.rmtree(p, ignore_errors=True)
    for part in root.glob("*.part"):                          # a download that died mid-way
        try:
            if time.time() - part.stat().st_mtime > 3600:
                part.unlink()
        except OSError:
            pass


def _verify_release_dir(prev: str, env: dict, keys: dict | None) -> tuple[dict | None, str]:
    """The release directory a rollback would point at, checked the way an install is (round 8 T8-3): the name is a
    version string inside the model directory, the directory holds the manifest the vendor signed for that version,
    ``release.json`` agrees with it, and the adapter bytes match the digest recorded when it was installed."""
    if not _VERSION_RX.match(prev):
        return None, f"previous release {prev!r} is not a version string"
    root = model_dir(env).resolve()
    prev_dir = (model_dir(env) / prev).resolve()
    if not prev_dir.is_relative_to(root) or prev_dir == root or prev_dir.parent != root:
        return None, f"previous release {prev!r} is outside {root}"
    if not (prev_dir / ".complete").exists():
        return None, "no previous release on disk"
    try:
        token = (prev_dir / MANIFEST_FILE).read_text().strip()
    except OSError:
        return None, (f"previous release {prev} has no signed manifest on disk (installed by an older release) — "
                      "re-install it with `apply` instead of rolling back to it")
    rel, why = verify_manifest(token, keys)
    if rel is None:
        return None, f"previous release {prev}: {why}"
    if str(rel.get("version")) != prev:
        return None, f"previous release directory {prev} holds the manifest for {rel.get('version')}"
    try:
        local = json.loads((prev_dir / "release.json").read_text())
    except (OSError, ValueError):
        local = {}
    if any(str(local.get(k)) != str(rel.get(k)) for k in ("version", "channel", "base_model", "sha256")):
        return None, f"previous release {prev}: release.json does not match its signed manifest"
    from aegis.finetune.digest import verify_adapter
    from aegis.finetune.pointer_trust import _key, recorded_release_digest
    want, rwhy = recorded_release_digest(pointer_path(env), prev)
    if rwhy:
        return None, rwhy
    if want:
        ok, vwhy = verify_adapter(prev_dir, want)
        if not ok:
            return None, f"previous release {prev}: {vwhy}"
    elif _key() is not None:
        return None, f"previous release {prev}: no adapter digest was recorded for it on this host"
    return {**rel, "adapter": str(prev_dir)}, ""


def rollback(env: dict | None = None, *, keys: dict | None = None) -> dict:
    env = os.environ if env is None else env
    ptr_path = pointer_path(env)
    try:
        ptr = json.loads(ptr_path.read_text())
    except (OSError, ValueError):
        return {"ok": False, "reason": "no pointer"}
    from aegis.finetune.pointer_trust import PointerStateError, signature_ok
    if not isinstance(ptr, dict) or not signature_ok(ptr):
        # `previous` is inside the signature now: an edited pointer cannot steer the rollback (round 8 T8-3)
        return {"ok": False, "reason": "the current pointer is not signed by this installation — not following its "
                                       "`previous` field"}
    prev = str(ptr.get("previous") or "")
    if not prev:
        return {"ok": False, "reason": "no previous release on disk"}
    rel, why = _verify_release_dir(prev, env, keys)
    if rel is None:
        return {"ok": False, "reason": why}
    # vLLM forgets LoRAs on restart and may never have held the previous one: register it before the pointer flips,
    # or triage 404s / the register step skips it (review round 7 R-9). A refusal keeps the current pointer.
    try:
        loaded = _load_into_vllm(rel, env)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "reason": str(e)[:200]}
    bad = str(ptr.get("run") or "")
    try:
        # the version rolled away from must not come back at the next heartbeat (review round 3 G5-4), and its old
        # signed pointer must not verify again — the deny lives in the signed record, not in a deletable file (T8-4)
        _commit_release(rel, pointer=ptr_path, previous="", served=loaded, deny=(bad,) if bad else ())
    except PointerStateError as e:
        return {"ok": False, "reason": str(e)[:300]}
    return {"ok": True, "version": prev, "adapter": rel["adapter"], "denied": bad, "loaded_into_vllm": loaded}


def _denied_path(env: dict) -> Path:
    return model_dir(env) / "denied.json"


_ALL = "*"


def _denied(env: dict) -> set[str]:
    """Versions rolled back on this host: the signed pointer record (authoritative since T8-4 — deleting a file no
    longer forgets a rollback) plus the legacy ``denied.json``. A record or deny file that exists but cannot be
    trusted refuses every update (``*``): an empty set re-offered the release an operator had rolled back (D4-10)."""
    from aegis.finetune.pointer_trust import denied_runs
    out, why = denied_runs(pointer_path(env), "triage")
    if why:
        logger.error("[model_updates] %s — refusing every model update until it is fixed", why)
        return {_ALL}
    p = _denied_path(env)
    if not p.exists():
        return out
    try:
        v = json.loads(p.read_text())
        if not isinstance(v, list):
            raise TypeError("denied.json is not a list")
        return out | {str(x) for x in v}
    except (OSError, ValueError, TypeError) as e:
        logger.error("[model_updates] %s is unreadable (%s) — refusing every model update until it is fixed", p, e)
        return {_ALL}


def enabled(env: dict | None = None) -> bool:
    env = os.environ if env is None else env
    v = env.get("AEGIS_MODEL_UPDATES", "").strip().lower()
    if v:
        return v in ("1", "true", "yes", "on")
    return bool(env.get("AEGIS_LICENSE_SERVER", "").strip())


# ------------------------------------------------------------------- CLI --

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m aegis.model_updates", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("check", "apply"):
        c = sub.add_parser(name, help="check for a newer release" + (" and install it" if name == "apply" else ""))
        c.add_argument("--server", default=os.environ.get("AEGIS_LICENSE_SERVER", ""))
    sub.add_parser("status", help="current release and what is on disk")
    sub.add_parser("rollback", help="repoint to the previous release")
    a = ap.parse_args(argv)
    if a.cmd == "status":
        print(f"current: {current_version() or '(none — base model / AEGIS_MODEL)'}  pointer: {pointer_path()}")
        root = model_dir()
        if root.exists():
            for p in sorted(root.iterdir()):
                if p.is_dir():
                    print(f"  {p.name:20s} {'complete' if (p / '.complete').exists() else 'partial'}")
        return 0
    if a.cmd == "rollback":
        r = rollback()
        print(r)
        return 0 if r.get("ok") else 1
    if not a.server:
        ap.error("--server (or AEGIS_LICENSE_SERVER) is required")
    token, why = licensing._read_token(os.environ)
    if not token:
        ap.error(why)
    st = licensing.check()
    if a.cmd == "check":
        res = check(a.server, token, channel=os.environ.get("AEGIS_MODEL_CHANNEL", "stable"),
                    base_model=os.environ.get("AEGIS_MODEL_BASE", "") or os.environ.get("AEGIS_MODEL", "") or "any", current=current_version())
        print("up to date" if res is None else json.dumps(res.get("release"), indent=1))
        return 0
    r = update_once(server=a.server, token=token, installation_id=st.installation_id)
    print(json.dumps(r, indent=1))
    return 0 if r.get("updated") or r.get("reason", "").startswith(("up to date", "not in")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
