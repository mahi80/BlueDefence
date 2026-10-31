"""Hot adapter-reload: a human-approved promotion swaps the live triage model with no restart
(vllm backend) and is a cheap no-op otherwise. All CI-safe — no GPU, no server, no training."""

from __future__ import annotations

import json
from pathlib import Path

from aegis.finetune.hot_reload import (
    ReloadResult, apply_reload, pointer_key, read_pointer, served_name, swap_in_place, unwrap,
)


class FakeVLLM:
    """Stands in for VLLMClient: records set_model calls."""
    def __init__(self, model="base"):
        self.model = model
        self.swaps: list[str] = []

    def set_model(self, model: str) -> None:
        self.model = model
        self.swaps.append(model)


class FakeLocal:
    """Stands in for GemmaClient: no set_model (in-place swap impossible)."""
    def __init__(self, model="base"):
        self.model = model


class Wrapper:
    """Stands in for TokenizingLLMClient: holds the real client as _inner."""
    def __init__(self, inner):
        self._inner = inner
        self.model = inner.model


def _pointer(tmp_path: Path, **kw) -> str:
    p = tmp_path / "current.json"
    p.write_text(json.dumps(kw), encoding="utf-8")
    return str(p)


# -- pointer parsing ---------------------------------------------------------

def test_read_pointer_roundtrip_and_missing(tmp_path):
    path = _pointer(tmp_path, run="r1", adapter="/a", sha256="deadbeef")
    assert read_pointer(path)["run"] == "r1"
    assert read_pointer(str(tmp_path / "nope.json")) is None
    assert read_pointer("") is None
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert read_pointer(str(bad)) is None


def test_pointer_key_prefers_sha_then_run_then_adapter():
    assert pointer_key({"sha256": "s", "run": "r", "adapter": "/a"}) == "s"
    assert pointer_key({"run": "r", "adapter": "/a"}) == "r"
    assert pointer_key({"adapter": "/a"}) == "/a"
    assert pointer_key({}) == ""


def test_served_name_prefers_explicit_then_run():
    assert served_name({"served_model": "qwen-v5", "run": "r"}) == "qwen-v5"
    assert served_name({"run": "retrain-2026"}) == "retrain-2026"
    assert served_name({}) == ""


# -- the swap primitive ------------------------------------------------------

def test_unwrap_reaches_inner():
    inner = FakeVLLM()
    assert unwrap(Wrapper(inner)) is inner
    assert unwrap(inner) is inner


def test_swap_in_place_vllm_updates_inner_and_wrapper():
    inner = FakeVLLM(model="base")
    wrapped = Wrapper(inner)
    assert swap_in_place(wrapped, "qwen-v5") is True
    assert inner.model == "qwen-v5" and inner.swaps == ["qwen-v5"]
    assert wrapped.model == "qwen-v5"          # label kept in sync for the banner


def test_swap_in_place_local_returns_false():
    assert swap_in_place(Wrapper(FakeLocal()), "qwen-v5") is False


# -- the decision ------------------------------------------------------------

def test_apply_reload_noop_without_pointer():
    r = apply_reload(Wrapper(FakeVLLM()), "", None)
    assert r.changed is False and r.mode == "noop"


def test_apply_reload_noop_when_unchanged():
    inner = FakeVLLM()
    ptr = {"run": "r1", "sha256": "abc", "served_model": "qwen-v5"}
    r = apply_reload(Wrapper(inner), "abc", ptr)       # prev_key already == sha256
    assert r.changed is False and r.mode == "noop" and inner.swaps == []
    assert r.key == "abc"


def test_apply_reload_swaps_on_change_vllm():
    inner = FakeVLLM(model="base")
    ptr = {"run": "retrain-2026-10-29", "adapter": "/runs/x/adapter",
           "sha256": "newsha", "served_model": "qwen-v5"}
    r = apply_reload(Wrapper(inner), "oldsha", ptr)
    assert r.changed is True and r.mode == "set_model"
    assert r.served_model == "qwen-v5" and r.key == "newsha" and r.run == "retrain-2026-10-29"
    assert inner.swaps == ["qwen-v5"]


def test_apply_reload_served_falls_back_to_run():
    inner = FakeVLLM()
    ptr = {"run": "retrain-2026-10-29", "sha256": "newsha"}      # no served_model
    r = apply_reload(Wrapper(inner), "old", ptr)
    assert r.changed is True and inner.swaps == ["retrain-2026-10-29"]


def test_apply_reload_local_is_restart_required():
    local = FakeLocal()
    ptr = {"run": "r1", "sha256": "newsha", "served_model": "qwen-v5"}
    r = apply_reload(Wrapper(local), "old", ptr)
    assert r.changed is False and r.mode == "restart_required" and r.key == "newsha"


# -- Pipeline integration (through the real Service.Pipeline) ----------------

def _pipeline(primary):
    from aegis.service import Pipeline
    orch = type("Orch", (), {"_primary": primary})()
    return Pipeline(orch=orch, response=None, audit=None, audit_path=Path("/tmp/x"),
                    threat_intel=None, connectors=None, primary_model="old-model")


def test_pipeline_hot_reload_applies_then_is_idempotent(tmp_path, monkeypatch):
    inner = FakeVLLM(model="base")
    p = _pipeline(Wrapper(inner))
    monkeypatch.setenv("AEGIS_MODEL_POINTER",
                       _pointer(tmp_path, run="retrain-1", sha256="sha-1", served_model="qwen-v5"))

    r1 = p.hot_reload_from_pointer()
    assert r1.changed is True and inner.model == "qwen-v5"
    assert p.model_key == "sha-1" and p.primary_model == "qwen-v5"

    r2 = p.hot_reload_from_pointer()        # same pointer → no second swap
    assert r2.changed is False and r2.mode == "noop" and inner.swaps == ["qwen-v5"]


def test_pipeline_hot_reload_picks_up_a_new_promotion(tmp_path, monkeypatch):
    inner = FakeVLLM(model="base")
    p = _pipeline(Wrapper(inner))
    ptr_path = _pointer(tmp_path, run="retrain-1", sha256="sha-1", served_model="qwen-v5")
    monkeypatch.setenv("AEGIS_MODEL_POINTER", ptr_path)
    p.hot_reload_from_pointer()

    # a later approved promotion rewrites the pointer in place
    Path(ptr_path).write_text(json.dumps({"run": "retrain-2", "sha256": "sha-2",
                                          "served_model": "qwen-v6"}), encoding="utf-8")
    r = p.hot_reload_from_pointer()
    assert r.changed is True and inner.model == "qwen-v6" and p.model_key == "sha-2"


def test_reload_result_defaults():
    assert ReloadResult(changed=False).mode == "noop"
