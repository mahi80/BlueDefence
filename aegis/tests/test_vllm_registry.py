"""vLLM adapter registry: load a promoted LoRA into vLLM and stamp the pointer, no server needed.

The HTTP transport and the registry are injected, so nothing here reaches a real vLLM server."""

from __future__ import annotations

import json
import urllib.error
from pathlib import Path

from aegis.finetune.vllm_registry import VLLMAdapterRegistry, register_promoted_adapter


class FakeTransport:
    def __init__(self, status=200, text="Success"):
        self.status, self.text = status, text
        self.calls: list = []

    def __call__(self, path, body):
        self.calls.append((path, body))
        return self.status, self.text


class FakeRegistry:
    """Stands in for VLLMAdapterRegistry for testing the register_promoted_adapter bridge."""
    def __init__(self, result=(True, "loaded")):
        self.result = result
        self.loads: list = []

    def load(self, name, path):
        self.loads.append((name, path))
        return self.result


def _pointer(tmp_path: Path, **kw) -> str:
    p = tmp_path / "current.json"
    p.write_text(json.dumps(kw), encoding="utf-8")
    return str(p)


# -- the registry client -----------------------------------------------------

def test_load_ok_already_and_error():
    t = FakeTransport(200, "Success: LoRA added")
    reg = VLLMAdapterRegistry(base_url="http://gpu:8000/v1", transport=t)
    assert reg.load("qwen-v5", "/a") == (True, "loaded")
    assert t.calls[0] == ("/load_lora_adapter", {"lora_name": "qwen-v5", "lora_path": "/a"})

    reg2 = VLLMAdapterRegistry(transport=FakeTransport(400, "LoRA qwen-v5 already loaded"))
    assert reg2.load("qwen-v5", "/a") == (True, "already")      # already-loaded counts as success

    reg3 = VLLMAdapterRegistry(transport=FakeTransport(500, "boom"))
    assert reg3.load("qwen-v5", "/a") == (False, "error")


def test_unload():
    assert VLLMAdapterRegistry(transport=FakeTransport(200)).unload("qwen-v5") is True
    assert VLLMAdapterRegistry(transport=FakeTransport(404, "no such")).unload("qwen-v5") is False


def test_http_transport_status_mapping(monkeypatch):
    reg = VLLMAdapterRegistry(base_url="http://gpu:8000/v1")

    def ok(req, timeout=None):
        class R:
            status = 200
            def read(self): return b"Success"
            def __enter__(self): return self
            def __exit__(self, *a): return False
        return R()
    monkeypatch.setattr("aegis.finetune.vllm_registry.urllib.request.urlopen", ok)
    assert reg._http("/load_lora_adapter", {}) == (200, "Success")

    def http400(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 400, "bad", {}, None)
    monkeypatch.setattr("aegis.finetune.vllm_registry.urllib.request.urlopen", http400)
    status, _ = reg._http("/load_lora_adapter", {})
    assert status == 400

    def urlerr(req, timeout=None):
        raise urllib.error.URLError("refused")
    monkeypatch.setattr("aegis.finetune.vllm_registry.urllib.request.urlopen", urlerr)
    assert reg._http("/load_lora_adapter", {})[0] == 0


# -- the register bridge -----------------------------------------------------

def _adapter(tmp_path):
    from aegis.finetune.digest import adapter_digest
    d = tmp_path / "retrain-1" / "adapter"
    d.mkdir(parents=True)
    (d / "adapter_model.safetensors").write_bytes(b"w" * 32)
    return str(d), adapter_digest(d)


def test_register_loads_and_stamps_served_model(tmp_path):
    ad, sha = _adapter(tmp_path)
    ptr = _pointer(tmp_path, run="retrain-1", adapter=ad, sha256=sha)
    reg = FakeRegistry((True, "loaded"))
    res = register_promoted_adapter(reg, pointer_path=ptr)
    assert res.ok and res.action == "loaded" and res.served_model == "retrain-1"
    assert reg.loads == [("retrain-1", ad)]
    # served_model is stamped back so hot-reload resolves it
    assert json.loads(Path(ptr).read_text())["served_model"] == "retrain-1"


def test_register_is_idempotent_once_stamped(tmp_path):
    ad, sha = _adapter(tmp_path)
    ptr = _pointer(tmp_path, run="retrain-1", adapter=ad, sha256=sha, served_model="retrain-1")
    reg = FakeRegistry()
    res = register_promoted_adapter(reg, pointer_path=ptr)
    assert res.action == "skipped" and reg.loads == []        # already registered → no vLLM call


def test_register_force_reregisters(tmp_path):
    ad, sha = _adapter(tmp_path)
    ptr = _pointer(tmp_path, run="retrain-1", adapter=ad, sha256=sha, served_model="retrain-1")
    reg = FakeRegistry((True, "already"))
    res = register_promoted_adapter(reg, pointer_path=ptr, force=True)   # daemon start / vLLM restart
    assert res.ok and reg.loads == [("retrain-1", ad)]


def test_register_refuses_remote_or_renamed_adapters(tmp_path):
    """Round 3 G5-2: a hub repo id is never loaded unchecked, and the served name is the run, not the pointer's."""
    reg = FakeRegistry((True, "loaded"))
    ptr = _pointer(tmp_path, run="r", adapter="attacker/evil-lora", sha256="v2:000")
    assert register_promoted_adapter(reg, pointer_path=ptr).ok is False and reg.loads == []
    ad, sha = _adapter(tmp_path)
    ptr = _pointer(tmp_path, run="retrain-1", adapter=ad, sha256=sha, served_model="attacker-lora")
    res = register_promoted_adapter(reg, pointer_path=ptr)
    assert res.served_model == "retrain-1" and reg.loads == [("retrain-1", ad)]


def test_register_noop_without_pointer(tmp_path, monkeypatch):
    monkeypatch.delenv("AEGIS_MODEL_POINTER", raising=False)
    assert register_promoted_adapter(FakeRegistry()).action == "noop"
    assert register_promoted_adapter(FakeRegistry(), pointer_path=str(tmp_path / "nope.json")).action == "noop"


def test_register_error_does_not_stamp(tmp_path):
    ptr = _pointer(tmp_path, run="retrain-1", adapter="/a")
    reg = FakeRegistry((False, "error"))
    res = register_promoted_adapter(reg, pointer_path=ptr)
    assert res.ok is False and res.action == "error"
    assert "served_model" not in json.loads(Path(ptr).read_text())      # not stamped on failure


def test_register_error_when_pointer_lacks_adapter(tmp_path):
    ptr = _pointer(tmp_path, run="retrain-1")      # no adapter
    res = register_promoted_adapter(FakeRegistry(), pointer_path=ptr)
    assert res.ok is False and res.action == "error"
