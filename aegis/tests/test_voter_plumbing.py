"""Plumbing for running an independent fine-tuned voter:

- the ``mistral-7b-v0.3`` preset (so the judge is reproducible from the repo), and
- ``AEGIS_VOTER_MODEL`` threading so the voter loads a DIFFERENT adapter than the
  primary (``AEGIS_MODEL``) instead of silently reusing it — which would collapse
  the two independent signals into one.

The voter tests monkeypatch ``get_client`` so nothing loads a real model (CI has no GPU);
they assert only that the right ``prefer`` / ``model`` are threaded through.
"""
import aegis.agents.shared.llm_client as llm
from aegis.finetune.config import get_preset


# ---- preset ------------------------------------------------------------

def test_mistral_preset_present_and_fits_12gb():
    p = get_preset("mistral-7b-v0.3")
    assert p.model == "mistralai/Mistral-7B-Instruct-v0.3"
    assert p.min_vram_gb <= 12            # must fit the 12 GB judge box
    assert p.max_seq_len == 2048


# ---- AEGIS_VOTER_MODEL threading --------------------------------------

def _capture_get_client(monkeypatch):
    calls = {}

    def fake_get_client(*, prefer=None, budget=None, model=None, stream=False):
        calls["prefer"] = prefer
        calls["model"] = model
        return object()  # stand-in client; get_voter_client returns it as-is on the pref branch

    monkeypatch.setattr(llm, "get_client", fake_get_client)
    return calls


def test_voter_backend_threads_voter_model(monkeypatch):
    calls = _capture_get_client(monkeypatch)
    monkeypatch.setenv("AEGIS_VOTER_BACKEND", "local")
    monkeypatch.setenv("AEGIS_VOTER_MODEL", "/home/mahi/aegis-runs/judge-mistral7b-public")
    llm.get_voter_client()
    assert calls["prefer"] == "local"
    # the voter must NOT fall back to AEGIS_MODEL (the primary) — it loads its own adapter
    assert calls["model"] == "/home/mahi/aegis-runs/judge-mistral7b-public"


def test_voter_model_absent_passes_none(monkeypatch):
    calls = _capture_get_client(monkeypatch)
    monkeypatch.setenv("AEGIS_VOTER_BACKEND", "vllm")
    monkeypatch.delenv("AEGIS_VOTER_MODEL", raising=False)
    llm.get_voter_client()
    assert calls["prefer"] == "vllm"
    assert calls["model"] is None         # backend default applies; unchanged behaviour


def test_voter_model_blank_is_treated_as_unset(monkeypatch):
    calls = _capture_get_client(monkeypatch)
    monkeypatch.setenv("AEGIS_VOTER_BACKEND", "local")
    monkeypatch.setenv("AEGIS_VOTER_MODEL", "   ")
    llm.get_voter_client()
    assert calls["model"] is None
