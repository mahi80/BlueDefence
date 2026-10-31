"""build_pipeline wires the majority-vote ensemble's extra voters (AEGIS_VOTER_MODELS)
only when AEGIS_ENSEMBLE_VOTE is on — closing the gap where the flag couldn't fire in
the live pipeline because only one voter was ever constructed.
"""
from __future__ import annotations

import pytest

from aegis.service import build_pipeline
from aegis.agents.shared.llm_client import get_extra_voter_clients


@pytest.fixture(autouse=True)
def _raw_orch(monkeypatch):
    # no swarm / campaign wrapper, so pipeline.orch is the raw SOCOrchestrator
    monkeypatch.setenv("AEGIS_SWARM", "0")
    monkeypatch.setenv("AEGIS_CAMPAIGN_CONTEXT", "0")


def test_flag_off_builds_no_extra_voters(monkeypatch, tmp_path):
    monkeypatch.delenv("AEGIS_ENSEMBLE_VOTE", raising=False)
    monkeypatch.setenv("AEGIS_VOTER_MODELS", "mock:a, mock:b")   # set, but flag off -> ignored
    p = build_pipeline(tmp_path / "a.jsonl", fresh=True)
    assert p.orch._extra_voters == []                            # single-voter path, unchanged


def test_flag_on_builds_extra_voters_so_ensemble_is_reachable(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_ENSEMBLE_VOTE", "1")
    monkeypatch.setenv("AEGIS_VOTER_MODELS", "mock:a, mock:b")
    p = build_pipeline(tmp_path / "b.jsonl", fresh=True)
    assert len(p.orch._extra_voters) == 2
    # live panel = primary voter + extras; >=2 means vote_best runs the ensemble
    assert 1 + len(p.orch._extra_voters) >= 3


def test_flag_on_without_voter_models_stays_single(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_ENSEMBLE_VOTE", "1")
    monkeypatch.delenv("AEGIS_VOTER_MODELS", raising=False)
    p = build_pipeline(tmp_path / "c.jsonl", fresh=True)
    assert p.orch._extra_voters == []                            # nothing to add -> single voter


# ---- the factory itself -------------------------------------------------

def test_factory_empty_when_unset(monkeypatch):
    monkeypatch.delenv("AEGIS_VOTER_MODELS", raising=False)
    assert get_extra_voter_clients() == []


def test_factory_parses_specs_and_count(monkeypatch):
    monkeypatch.setenv("AEGIS_VOTER_MODELS", "mock:x, mock:y, mock:z")
    voters = get_extra_voter_clients()
    assert len(voters) == 3
    assert all(hasattr(v, "complete") for v in voters)


def test_factory_skips_blank_entries(monkeypatch):
    monkeypatch.setenv("AEGIS_VOTER_MODELS", "mock:x, , mock:y,")
    assert len(get_extra_voter_clients()) == 2


def test_factory_drops_bad_specs_instead_of_seating_mock_dissenters(monkeypatch):
    """get_client never raises — it falls back to MockClient, whose vote has no ``concur`` and
    so dissents every time. A malformed or unavailable spec must be dropped, not seated: one
    seated mock voter means the panel can never be unanimous and every irreversible action is
    HITL-forced forever."""
    from aegis.agents.shared.llm_client import MockClient, _innermost
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("AEGIS_VOTER_BACKEND", raising=False)
    # malformed (empty half), unknown backend, and a backend that silently falls back to mock here
    # (a declared-but-unreachable vLLM is seated on purpose: it fails loudly at vote time, not silently)
    monkeypatch.setenv("AEGIS_VOTER_MODELS", "vllm:, :model, bogus:x, anthropic:claude-x")
    assert get_extra_voter_clients() == []
    # bare model with no creds resolves to mock on the auto backend -> dropped too
    monkeypatch.setenv("AEGIS_VOTER_MODELS", "some-model")
    assert get_extra_voter_clients() == []
    # an explicitly requested mock is honoured (tests / demos), and the good ones survive the bad
    monkeypatch.setenv("AEGIS_VOTER_MODELS", "mock:a, bogus:x, mock:b")
    voters = get_extra_voter_clients()
    assert len(voters) == 2 and all(isinstance(_innermost(v), MockClient) for v in voters)


def test_factory_does_not_double_wrap_the_pii_tokenizer(monkeypatch):
    from aegis.agents.shared.pii_tokenizing_client import TokenizingLLMClient
    monkeypatch.setenv("AEGIS_VOTER_MODELS", "mock:a")
    (v,) = get_extra_voter_clients()
    assert isinstance(v, TokenizingLLMClient)                       # get_client's own wrapper …
    assert not isinstance(getattr(v, "_inner", None), TokenizingLLMClient)   # … applied exactly once
