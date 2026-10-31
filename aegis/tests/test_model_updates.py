"""Model updates: signed manifests, staged rollout, verified download + install + pointer, rollback."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from aegis import license as L
from aegis import model_updates as mu


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    d = tmp_path_factory.mktemp("k")
    _, priv = L.write_keypair(d, "rel-kid", bits=1024)
    k = json.loads(priv.read_text())
    return {"n": int(k["n"], 16), "d": int(k["d"], 16), "pub": {"rel-kid": (int(k["n"], 16), 65537)}}


def _archive(version: str, extra: dict | None = None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in {"adapter_config.json": json.dumps({"base_model_name_or_path": "Qwen/Qwen3-8B", "peft_type": "LORA"}),
                              "adapter_model.safetensors": "weights-" + version, **(extra or {})}.items():
            data = content.encode()
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def _serve(blobs: dict[str, bytes]):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            data = blobs.get(self.path)
            if data is None:
                self.send_response(404); self.end_headers(); return
            self.send_response(200); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    httpd = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}"


def _manifest(keys, version: str, data: bytes, **over) -> str:
    rel = {"version": version, "channel": "stable", "base_model": "Qwen/Qwen3-8B", "sha256": hashlib.sha256(data).hexdigest(),
           "size": len(data), "rollout_pct": 100, "notes": "t", "published_at": 1, **over}
    return mu.sign_manifest(rel, n=keys["n"], d=keys["d"], kid="rel-kid")


def test_rollout_buckets_are_stable_and_proportional():
    ids = [f"bd-{i:04x}" for i in range(2000)]
    assert all(mu.in_rollout(i, 100) for i in ids) and not any(mu.in_rollout(i, 0) for i in ids)
    share = sum(mu.in_rollout(i, 10) for i in ids) / len(ids)
    assert 0.07 < share < 0.13
    assert mu.in_rollout("bd-abc", 10) == mu.in_rollout("bd-abc", 10)
    assert all(mu.in_rollout(i, 50) for i in ids if mu.in_rollout(i, 10))        # widening never drops anyone


def test_install_verifies_then_points_then_rolls_back(tmp_path, keys):
    v1, v2 = _archive("2026.11.1"), _archive("2026.11.2")
    httpd, url = _serve({"/v1.tgz": v1, "/v2.tgz": v2, "/bad.tgz": v2[:-10] + b"xxxxxxxxxx"})
    env = {"AEGIS_MODEL_DIR": str(tmp_path / "models"), "AEGIS_MODEL_POINTER": str(tmp_path / "models" / "current.json")}
    try:
        r1 = mu.download_and_install({"manifest_token": _manifest(keys, "2026.11.1", v1), "url": url + "/v1.tgz"}, dest_root=mu.model_dir(env), keys=keys["pub"])
        assert Path(r1["adapter"]).name == "2026.11.1" and (Path(r1["adapter"]) / "adapter_config.json").exists()
        ptr = mu.write_pointer(r1, pointer=mu.pointer_path(env))
        assert ptr["run"] == "2026.11.1" and ptr["served_model"] == "2026.11.1" and mu.current_version(env) == "2026.11.1"
        # tampered archive (sha mismatch against the signed manifest) → nothing installed
        with pytest.raises(RuntimeError, match="sha256 mismatch|size mismatch"):
            mu.download_and_install({"manifest_token": _manifest(keys, "2026.11.2", v2), "url": url + "/bad.tgz"}, dest_root=mu.model_dir(env), keys=keys["pub"])
        assert not (mu.model_dir(env) / "2026.11.2").exists()
        # forged manifest (wrong key) → rejected before any download
        other = L.write_keypair(tmp_path / "ok", "other", bits=1024)[1]
        ok = json.loads(other.read_text())
        forged = mu.sign_manifest({"version": "2026.11.9", "channel": "stable", "base_model": "x", "sha256": "0" * 64, "size": 1}, n=int(ok["n"], 16), d=int(ok["d"], 16), kid="rel-kid")
        with pytest.raises(RuntimeError, match="manifest rejected"):
            mu.download_and_install({"manifest_token": forged, "url": url + "/v2.tgz"}, dest_root=mu.model_dir(env), keys=keys["pub"])
        # a good v2 → installed, pointer moves, previous kept; rollback returns to v1
        r2 = mu.download_and_install({"manifest_token": _manifest(keys, "2026.11.2", v2), "url": url + "/v2.tgz"}, dest_root=mu.model_dir(env), keys=keys["pub"])
        mu.write_pointer(r2, pointer=mu.pointer_path(env), previous="2026.11.1")
        assert mu.current_version(env) == "2026.11.2"
        rb = mu.rollback(env)
        assert rb["ok"] and mu.current_version(env) == "2026.11.1"
        # the pointer is what hot_reload consumes
        from aegis.finetune.hot_reload import pointer_key, read_pointer, served_name
        p = read_pointer(str(mu.pointer_path(env)))
        assert served_name(p) == "2026.11.1" and pointer_key(p) == r1["sha256"]
    finally:
        httpd.shutdown()


def test_unsafe_archive_is_refused(tmp_path, keys):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        ti = tarfile.TarInfo("../../etc/evil"); ti.size = 1; tar.addfile(ti, io.BytesIO(b"x"))
    data = buf.getvalue()
    httpd, url = _serve({"/e.tgz": data})
    try:
        with pytest.raises(RuntimeError, match="unsafe member"):
            mu.download_and_install({"manifest_token": _manifest(keys, "2026.12.1", data), "url": url + "/e.tgz"}, dest_root=tmp_path / "m", keys=keys["pub"])
        assert not (tmp_path / "m" / "2026.12.1").exists()
    finally:
        httpd.shutdown()


def test_publish_dry_run_builds_a_manifest(tmp_path, capsys):
    from aegis.finetune import publish
    ad = tmp_path / "adapter"; ad.mkdir()
    (ad / "adapter_config.json").write_text(json.dumps({"base_model_name_or_path": "Qwen/Qwen3-8B"}))
    (ad / "adapter_model.safetensors").write_bytes(b"w" * 100)
    (ad / "gate.json").write_text(json.dumps({"passes": True}))
    assert publish.main(["--adapter", str(ad), "--version", "2026.11.1", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "base=Qwen/Qwen3-8B" in out and '"rollout_pct": 100' in out
    (ad / "gate.json").write_text(json.dumps({"passes": False}))
    with pytest.raises(SystemExit):
        publish.main(["--adapter", str(ad), "--version", "2026.11.1", "--dry-run"])
