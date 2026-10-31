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
