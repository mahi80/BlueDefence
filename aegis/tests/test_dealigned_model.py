"""Dealigned ("uncensored" / abliterated) models: the supply-chain policy and the proxy-log fast path."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from aegis.agents.orchestrator.model_pull import is_dealigned_model_pull, model_pull_chain
from aegis.agents.vuln_discovery.model_supply_chain import (
    dealigned_markers, evaluate_model_load, model_from_hf_url,
)

REPO = "dealignai/DeepSeek-V4.1-Flash-UNCENSORED-FP8"


# ---- markers -------------------------------------------------------------

@pytest.mark.parametrize("model, expect", [
    (REPO, {"dealigned", "uncensored"}),
    ("someone/Llama-3.1-8B-Instruct-abliterated", {"abliterated"}),
    ("x/qwen3_8b.Heretic", {"heretic"}),
    ("x/Mistral-No_Guardrails", {"no-guardrails"}),
    ("dealignai/Qwen3-8B", {"dealigned"}),            # the publisher alone is enough
])
def test_markers_found(model, expect):
    assert set(dealigned_markers(model)) == expect


@pytest.mark.parametrize("model", ["deepseek-ai/DeepSeek-V4.1-Flash", "Qwen/Qwen3-8B", "meta-llama/Llama-Guard-3-8B",
                                   "google/gemma-3-4b-it", "BAAI/bge-m3", "", None])
def test_ordinary_models_carry_no_markers(model):
    assert dealigned_markers(model) == []


def test_markers_from_tags_only():
    assert dealigned_markers("someone/innocuous-name", ["text-generation", "Abliterated"]) == ["abliterated"]


# ---- policy --------------------------------------------------------------

def _controls(findings):
    return {f.control: f.severity for f in findings}


def test_dealigned_load_is_high_and_other_controls_still_apply():
    c = _controls(evaluate_model_load({"model": REPO, "trust_remote_code": True, "auto_map": True}))
    assert c["DEALIGNED_MODEL"] == "high"
    assert c["UNVETTED_PUBLISHER"] == "high" and c["UNPINNED_REVISION"] == "high"
    assert c["UNREVIEWED_REMOTE_CODE"] == "critical"


def test_reviewed_red_team_exception_drops_to_medium_but_is_never_silent():
    c = _controls(evaluate_model_load({"model": REPO, "revision": "a1b2c3", "reviewed": True}))
    assert c == {"DEALIGNED_MODEL": "medium"}


def test_even_an_allowlisted_org_is_flagged_when_dealigned():
    c = _controls(evaluate_model_load({"model": "deepseek-ai/whatever-uncensored", "revision": "a1b2c3"}))
    assert c == {"DEALIGNED_MODEL": "high"}


def test_official_model_is_clean():
    assert evaluate_model_load({"model": "deepseek-ai/DeepSeek-V4.1-Flash", "revision": "a1b2c3"}) == []


# ---- URL parsing ---------------------------------------------------------

@pytest.mark.parametrize("url, model, kind, rev", [
    (f"https://huggingface.co/{REPO}", REPO, "page", ""),
    (f"huggingface.co/{REPO}/resolve/main/model-00001-of-00072.safetensors", REPO, "weights", "main"),
    (f"https://www.huggingface.co/{REPO}/resolve/9af1/modeling_deepseek.py", REPO, "code", "9af1"),
    (f"https://hf.co/{REPO}/resolve/main/config.json", REPO, "file", "main"),
    (f"https://huggingface.co/api/models/{REPO}/revision/main", REPO, "api", "main"),
    (f"https://huggingface.co/{REPO}/tree/main", REPO, "page", "main"),
    ("https://huggingface.co/x/y%20z/resolve/main/w.gguf", "x/y z", "weights", "main"),
])
def test_model_urls_parse(url, model, kind, rev):
    p = model_from_hf_url(url)
    assert p and p["model"] == model and p["kind"] == kind and p["revision"] == rev


@pytest.mark.parametrize("url", [
    "https://huggingface.co/datasets/someone/uncensored-chats",      # a dataset, not a model
    "https://huggingface.co/spaces/someone/uncensored-demo",         # a Space
    "https://huggingface.co/blog/mlabonne/abliteration",             # an article about it
    "https://huggingface.co/models?search=uncensored",                # a search
    "https://cdn-lfs.huggingface.co/repos/ab/cd/0123abcd",           # CDN: content hash only
    f"https://evil.example/{REPO}",                                   # not Hugging Face
    "https://huggingface.co/",
    "", None,
])
def test_non_model_urls_are_ignored(url):
    assert model_from_hf_url(url) is None


# ---- fast path -----------------------------------------------------------

def test_weights_pull_from_proxy_log_is_a_high_severity_shadow_ai_chain():
    alert = {"id": "PX-1", "source": "Zscaler", "source_ip": "10.20.4.17", "user": "rkumar",
             "url": f"https://huggingface.co/{REPO}/resolve/main/model-00001-of-00072.safetensors"}
    assert is_dealigned_model_pull(alert)
    c = model_pull_chain(alert)
    assert (c.investigated_by, c.verdict, c.confidence) == ("model_pull", "suspicious", 0.85)
    acts = {(a.action_type, a.requires_hitl, a.target) for a in c.recommended_actions}
    assert ("escalate", True, "PX-1") in acts
    assert ("block_egress", True, f"huggingface.co/{REPO}") in acts        # the repo path, not all of HF
    assert ("monitor", False, "10.20.4.17") in acts
    assert all(a.action_type == "monitor" or a.requires_hitl for a in c.recommended_actions)
    sa = c.metadata["shadow_ai"]
    assert sa["severity"] == "high" and sa["status"] == "dealigned_model" and sa["kind"] == "weights"
    assert {f["control"] for f in c.metadata["model_supply_chain"]} >= {"DEALIGNED_MODEL", "UNVETTED_PUBLISHER", "UNPINNED_REVISION"}


def test_page_view_is_lower_confidence_and_host_plus_path_fields_work():
    alert = {"id": "PX-2", "src_ip": "10.20.4.18", "host": "huggingface.co", "path": f"/{REPO}"}
    assert is_dealigned_model_pull(alert)
    c = model_pull_chain(alert)
    assert c.confidence == 0.65 and c.metadata["shadow_ai"]["kind"] == "page"


def test_loader_code_fetch_adds_remote_code_evidence():
    c = model_pull_chain({"id": "PX-3", "source_ip": "10.1.1.1",
                          "url": f"https://huggingface.co/{REPO}/resolve/main/modeling_deepseek.py"})
    assert c.confidence == 0.85 and any("trust_remote_code" in e.signal for e in c.evidence)


@pytest.mark.parametrize("alert", [
    {"id": "n1", "source_ip": "10.0.0.1", "url": "https://huggingface.co/Qwen/Qwen3-8B/resolve/main/model.safetensors"},
    {"id": "n2", "source": "F5 ASM", "host": "netbanking.bank.example", "uri": f"/search?q=huggingface.co/{REPO}"},
    {"id": "n3", "source_ip": "10.0.0.1", "url": "https://huggingface.co/datasets/x/uncensored"},
    {"id": "n4", "source": "Okta", "user_id": "u_1"},
])
def test_ordinary_pulls_and_other_alerts_are_not_routed_here(alert):
    assert not is_dealigned_model_pull(alert)


def test_end_to_end_through_the_orchestrator(monkeypatch):
    monkeypatch.setenv("ACP_HOME", tempfile.mkdtemp())
    monkeypatch.setenv("AEGIS_SWARM", "0")
    from aegis.eval.run import _build_orchestrator
    with tempfile.TemporaryDirectory() as td:
        orch = _build_orchestrator(Path(td) / "audit.jsonl")
        chain = orch.handle({"id": "PX-E2E", "source": "Zscaler", "source_ip": "10.20.4.17",
                             "url": f"https://huggingface.co/{REPO}/resolve/main/model-00001-of-00072.safetensors"})
        assert chain.investigated_by == "model_pull" and chain.verdict == "suspicious"
        assert orch._audit.verify()
        # an ordinary download is left to the normal path
        plain = orch.handle({"id": "PX-PLAIN", "source": "Zscaler", "source_ip": "10.20.4.17",
                             "url": "https://huggingface.co/Qwen/Qwen3-8B/resolve/main/model.safetensors"})
        assert plain.investigated_by != "model_pull"
