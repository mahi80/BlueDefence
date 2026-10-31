"""The SOC demo's state machine: beats reveal the campaign, an approval contains it, and every
served object matches the console's shape. Headless — no HTTP, no console."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import soc_demo  # noqa: E402
from soc_demo import SocDemo  # noqa: E402

_CHAIN_KEYS = {"chain_id", "alert_id", "source", "verdict", "confidence", "specialists", "action_types",
               "evidence_count", "governance_blocked", "started_at", "integrity_hash", "recommended_actions"}


def test_beats_advance_and_clamp():
    d = SocDemo()
    assert d.beat == 0
    for _ in range(20):
        d.advance()
    assert d.beat == d.max_beat == len(soc_demo.BEATS) - 1


def test_visibility_grows_with_beats():
    d = SocDemo()
    ids0 = {c["chain_id"] for c in d.chains()}
    assert ids0 == {"chn_2203", "chn_2204"}          # baseline noise only
    assert "chn_2201" not in ids0                     # the headline is not out yet
    d.goto_end()
    idsN = {c["chain_id"] for c in d.chains()}
    assert {"chn_2201", "chn_2202", "chn_2203", "chn_2204"} <= idsN
    # the headline (prompt-injection + ledger pivot) appears from beat 2
    d.reset(); d.advance(); d.advance()
    assert "chn_2201" in {c["chain_id"] for c in d.chains()}


def test_served_objects_match_console_shape_and_hide_private_keys():
    d = SocDemo(); d.goto_end()
    for c in d.chains():
        assert _CHAIN_KEYS <= set(c) and "_beat" not in c
        for n in c["investigation"]["blast_radius"]["nodes"]:
            assert {"id", "label", "kind"} <= set(n)
    for a in d.approvals():
        assert {"id", "status", "action_type", "target"} <= set(a) and "_beat" not in a
    for p in d.proposals():
        assert {"id", "change_type", "status", "summary"} <= set(p) and "_beat" not in p


def test_headline_note_names_the_caught_injection():
    d = SocDemo(); d.goto_end()
    headline = d.chain("chn_2201")
    assert headline and "did NOT obey" in headline["note"] and "ledger" in headline["note"].lower()


def test_approve_contains_the_campaign():
    d = SocDemo(); d.goto_end()
    assert d.decide("appr_01", "approve", rationale="contain it") is True
    appr = next(a for a in d.approvals() if a["id"] == "appr_01")
    assert appr["status"] == "approved" and appr["rationale"] == "contain it" and appr["decided_by"]
    headline = d.chain("chn_2201")
    assert "CONTAINED" in headline["note"] and "ledger is protected" in headline["note"]


def test_approving_the_isolate_jumps_to_the_containment_beat():
    d = SocDemo()                      # beat 0
    d.decide("appr_01", "approve")
    assert d.beat >= 4                 # the demo advances to the containment beat


def test_reject_records_a_rejection():
    d = SocDemo(); d.goto_end()
    d.decide("appr_02", "reject", rationale="hold")
    appr = next(a for a in d.approvals() if a["id"] == "appr_02")
    assert appr["status"] == "rejected" and appr["rationale"] == "hold"


def test_unknown_approval_is_rejected():
    assert SocDemo().decide("nope", "approve") is False


def test_reset_clears_everything():
    d = SocDemo(); d.goto_end(); d.decide("appr_01", "approve")
    d.reset()
    assert d.beat == 0 and not d._contained
    assert all(a["status"] == "pending" for a in d.approvals() if a["id"] in {"appr_01", "appr_02", "appr_03"})


def test_learning_proposal_appears_at_the_end():
    d = SocDemo(); d.goto_end()
    props = {p["id"]: p for p in d.proposals()}
    assert props["prop_01"]["change_type"] == "model_promotion" and props["prop_01"]["status"] == "pending"
