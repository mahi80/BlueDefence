"""3-model majority-vote ensemble (AEGIS_ENSEMBLE_VOTE).

The design intent, for a SOC with few analysts: UNANIMITY buys autonomy and a
SPLIT buys a human. The orchestrator forces HITL on `not unanimous`, so these
tests pin exactly when a verdict is unanimous vs split, and that the flag keeps
the single-voter path byte-for-byte when off.
"""
from __future__ import annotations

import json
import types

from aegis.agents.orchestrator.voting import (
    vote, vote_ensemble, vote_best, VoteResult)
from aegis.agents.shared.evidence_chain import EvidenceChain


class StubVoter:
    """A reviewer whose JSON reply is fixed; counts its calls."""
    def __init__(self, concur: bool, reason: str = "ok"):
        self._concur = concur
        self._reason = reason
        self.calls = 0

    def complete(self, system, user, max_tokens=2048):
        self.calls += 1
        return types.SimpleNamespace(text=json.dumps({"concur": self._concur, "reason": self._reason}))


class BoomVoter:
    """An unreachable reviewer — must be read as a dissent, never a crash."""
    def __init__(self):
        self.calls = 0

    def complete(self, system, user, max_tokens=2048):
        self.calls += 1
        raise RuntimeError("voter down")


def _chain(conf: float = 0.9, verdict: str = "malicious") -> EvidenceChain:
    return EvidenceChain(alert_id="a1", investigated_by="test", verdict=verdict, confidence=conf)


# ---- single-voter back-compat (unanimous == concur) --------------------

def test_single_concur_keeps_confidence_and_is_unanimous():
    v = vote(StubVoter(True), _chain(0.9))
    assert v.concur and v.unanimous and v.final_confidence == 0.9
    assert (v.n_concur, v.n_voters) == (1, 1)


def test_single_dissent_caps_and_is_not_unanimous():
    v = vote(StubVoter(False), _chain(0.9))
    assert not v.concur and not v.unanimous and v.final_confidence == 0.6


# ---- ensemble majority logic ------------------------------------------

def test_ensemble_unanimous_concur_keeps_confidence():
    v = vote_ensemble([StubVoter(True), StubVoter(True), StubVoter(True)], _chain(0.92))
    assert v.unanimous and v.concur
    assert v.final_confidence == 0.92            # clear case -> full autonomy
    assert (v.n_concur, v.n_voters) == (3, 3)


def test_ensemble_split_majority_concur_caps_at_075_and_not_unanimous():
    v = vote_ensemble([StubVoter(True), StubVoter(True), StubVoter(False)], _chain(0.95))
    assert v.concur and not v.unanimous          # majority concurs, but a split -> HITL
    assert v.final_confidence == 0.75
    assert (v.n_concur, v.n_voters) == (2, 3)


def test_ensemble_majority_dissent_caps_at_06():
    v = vote_ensemble([StubVoter(True), StubVoter(False), StubVoter(False)], _chain(0.95))
    assert not v.concur and not v.unanimous
    assert v.final_confidence == 0.6


def test_ensemble_tie_is_not_a_concur():
    # 1/2 is not a strict majority -> treated as dissent, capped hard.
    v = vote_ensemble([StubVoter(True), StubVoter(False)], _chain(0.9))
    assert not v.concur and not v.unanimous and v.final_confidence == 0.6


def test_ensemble_unreachable_voter_counts_as_dissent():
    cc, boom = StubVoter(True), BoomVoter()
    v = vote_ensemble([cc, boom], _chain(0.9))
    assert boom.calls == 1                        # it was asked
    assert not v.concur and v.final_confidence == 0.6   # its failure dissented


def test_ensemble_never_raises_confidence_above_original():
    v = vote_ensemble([StubVoter(True), StubVoter(True)], _chain(0.4))
    assert v.final_confidence == 0.4


# ---- vote_best gate: flag + voter count --------------------------------

def test_vote_best_flag_off_uses_single_path_even_with_two_voters(monkeypatch):
    monkeypatch.delenv("AEGIS_ENSEMBLE_VOTE", raising=False)
    a, b = StubVoter(True), StubVoter(False)
    v = vote_best([a, b], _chain(0.9))
    assert a.calls == 1 and b.calls == 0          # only the first voter ran
    assert v.unanimous == v.concur == True        # == single-voter semantics


def test_vote_best_flag_on_runs_ensemble(monkeypatch):
    monkeypatch.setenv("AEGIS_ENSEMBLE_VOTE", "1")
    a, b, c = StubVoter(True), StubVoter(True), StubVoter(False)
    v = vote_best([a, b, c], _chain(0.9))
    assert a.calls == b.calls == c.calls == 1     # all three weighed in
    assert (v.n_concur, v.n_voters) == (2, 3) and not v.unanimous


def test_vote_best_flag_on_single_voter_still_single(monkeypatch):
    monkeypatch.setenv("AEGIS_ENSEMBLE_VOTE", "true")
    a = StubVoter(True)
    v = vote_best([a], _chain(0.9))
    assert a.calls == 1 and v.unanimous and v.final_confidence == 0.9


def test_vote_best_no_voters_fails_safe_to_dissent(monkeypatch):
    monkeypatch.setenv("AEGIS_ENSEMBLE_VOTE", "1")
    v = vote_best([], _chain(0.9))
    assert not v.concur and not v.unanimous and v.final_confidence == 0.6
    assert (v.n_concur, v.n_voters) == (0, 0)


def test_vote_best_filters_none_voters(monkeypatch):
    monkeypatch.setenv("AEGIS_ENSEMBLE_VOTE", "1")
    a = StubVoter(True)
    v = vote_best([a, None], _chain(0.9))         # one live voter -> single path
    assert a.calls == 1 and v.unanimous
