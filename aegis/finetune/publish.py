"""Publish a gated adapter as a model release — the "definitions update" every installation pulls.

    python -m aegis.finetune.publish --adapter runs/triage-2026-11/adapter --version 2026.11.1 \\
        --channel stable --base-model Qwen/Qwen3-8B --rollout-pct 10 --notes "community-v1 DPO, 1,900 analyst pairs" \\
        --server https://…/prod --admin-key $ADMIN

Steps: tar.gz the adapter directory (adapter_config.json + weights) → sha256 → ``POST /releases`` (admin) registers
the release and returns a presigned S3 PUT → upload → ``POST /releases/{version}/publish`` makes it live; the
service signs the manifest with the issuer key, which is what installations verify. Refuses to publish an
adapter that has not passed ``aegis.finetune.gate`` unless ``--skip-gate-check`` (the gate writes ``gate.json``
next to the adapter).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path


def _tar_adapter(adapter: Path, out: Path) -> tuple[str, int]:
    # dereference: HF caches symlink weight files, and every installation's extractor refuses link members
    with tarfile.open(out, "w:gz", dereference=True) as tar:
        root = adapter.resolve()
        for p in sorted(adapter.iterdir()):
            if p.name in ("gate.json", ".complete") or p.name.startswith("."):
                continue
            # dereferencing follows symlinks anywhere: a stray link would ship host files to every installation.
            # Links are followed only when they resolve inside the adapter dir or the HF cache (review round 3).
            real = p.resolve()
            if p.is_symlink() and not (real.is_relative_to(root) or "huggingface" in real.parts):
                raise SystemExit(f"{p.name} links outside the adapter directory ({real}) — refusing to publish it")
            tar.add(p, arcname=p.name)
    # self-check: the archive must pass exactly the member test the installations apply
    with tarfile.open(out, "r:gz") as tar:
        for m in tar.getmembers():
            if m.issym() or m.islnk() or m.isdev() or m.name.startswith(("/", "..")) or "/../" in m.name:
                raise SystemExit(f"archive member {m.name!r} would be refused by installations — fix the adapter directory")
    h = hashlib.sha256()
    with out.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest(), out.stat().st_size


def _call(server: str, path: str, admin_key: str, body: dict | None, method: str = "POST") -> dict:
    req = urllib.request.Request(server.rstrip("/") + path, data=json.dumps(body).encode() if body is not None else None, method=method,
                                 headers={"x-admin-key": admin_key, "Content-Type": "application/json", "User-Agent": "aegis-publish/1"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("error", "")
        except Exception:  # noqa: BLE001
            msg = ""
        raise SystemExit(f"{path} failed ({e.code}): {msg or e.reason}")


def _put(url: str, path: Path) -> None:
    data = path.read_bytes()
    req = urllib.request.Request(url, data=data, method="PUT", headers={"Content-Type": "application/gzip", "Content-Length": str(len(data))})
    with urllib.request.urlopen(req, timeout=1800) as r:  # noqa: S310 — presigned URL from our own service
        if r.status not in (200, 201):
            raise SystemExit(f"upload failed: HTTP {r.status}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m aegis.finetune.publish", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--adapter", required=True, help="LoRA adapter directory (adapter_config.json + weights)")
    ap.add_argument("--version", required=True, help="e.g. 2026.11.1 — sorts lexically; installations only move forward")
    ap.add_argument("--channel", default="stable", choices=("stable", "beta"))
    ap.add_argument("--base-model", default="", help="base the adapter was trained on (default: adapter_config.json base_model_name_or_path)")
    ap.add_argument("--rollout-pct", type=int, default=100, help="staged rollout: share of installations offered this release")
    ap.add_argument("--min-aegis", default="", help="minimum AEGIS version (free text, informational)")
    ap.add_argument("--notes", default="")
    ap.add_argument("--server", default=os.environ.get("AEGIS_LICENSE_SERVER", ""), required=False)
    ap.add_argument("--admin-key", default=os.environ.get("AEGIS_LICENSE_ADMIN_KEY", ""))
    ap.add_argument("--skip-gate-check", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="build the archive and print the manifest body; do not upload")
    a = ap.parse_args(argv)

    adapter = Path(a.adapter)
    if not (adapter / "adapter_config.json").exists():
        ap.error(f"{adapter} has no adapter_config.json")
    cfg = json.loads((adapter / "adapter_config.json").read_text())
    base = a.base_model or str(cfg.get("base_model_name_or_path", "")) or "unknown"
    from .gate import gate_report_path
    gate = gate_report_path(adapter)
    if not gate.exists() and (adapter / "gate.json").exists():
        gate = adapter / "gate.json"                     # a report from before the gate wrote it beside the adapter
    if not a.skip_gate_check:
        if not gate.exists():
            ap.error(f"no gate.json next to the adapter — run python -m aegis.finetune.gate first (or --skip-gate-check)")
        g = json.loads(gate.read_text())
        if not (g.get("passes") or g.get("passed") or g.get("ok")):
            ap.error("gate.json says the adapter did NOT pass — refusing to publish")
    with tempfile.TemporaryDirectory() as td:
        archive = Path(td) / f"{a.version}.tar.gz"
        sha, size = _tar_adapter(adapter, archive)
        body = {"version": a.version, "channel": a.channel, "base_model": base, "sha256": sha, "size": size,
                "rollout_pct": a.rollout_pct, "min_aegis": a.min_aegis, "notes": a.notes[:500]}
        print(f"release {a.version} ({a.channel}) base={base} size={size / 1e6:.1f} MB sha256={sha[:16]}…")
        if a.dry_run:
            print(json.dumps(body, indent=1))
            return 0
        if not a.server or not a.admin_key:
            ap.error("--server and --admin-key (or AEGIS_LICENSE_SERVER / AEGIS_LICENSE_ADMIN_KEY) are required")
        reg = _call(a.server, "/releases", a.admin_key, body)
        print(f"registered; uploading to S3 ({reg.get('key')}) …")
        _put(reg["upload_url"], archive)
        pub = _call(a.server, f"/releases/{a.version}/publish", a.admin_key, {})
        print(f"published: {pub.get('version')} on {pub.get('channel')} at rollout {pub.get('rollout_pct')}% — "
              f"installations pick it up on their next daily check; manifest kid {pub.get('kid')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
