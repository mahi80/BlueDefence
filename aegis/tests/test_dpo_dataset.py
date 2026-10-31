"""DPO preference pairs are built only from analyst decisions that overruled the model."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from aegis.dataset import BuildOptions, DatasetBuilder, HumanDecision, Scrubber, record_from_chain
from aegis.dataset.export import verify_dataset


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("ACP_HOME", tempfile.mkdtemp())
    yield


def _rec(sc, *, alert_id, verdict, actions, human, alert_src="waf"):
    ch = {
        "alert_id": alert_id, "verdict": verdict, "confidence": 0.9,
        "evidence": [{"source": alert_src, "signal": f"signal for {alert_id}", "weight": "high"}],
        "recommended_actions": actions,
        "integrity_hash": f"h-{alert_id}",
    }
    return record_from_chain(ch, alert={"id": alert_id, "source": alert_src},
                             origin="dashboard_chain", scrubber=sc, human=human)


def _hd(action_type, target, decision, corrected=""):
    return HumanDecision("ap-" + target, action_type, target, decision, "soc_analyst", "rationale", None, corrected)


def _build(records, tmp_path, **opts):
    out = tmp_path / "ds"
    DatasetBuilder(out, BuildOptions(name="t", dpo=True, **opts)).add(records).build()
    rows = [json.loads(l) for l in (out / "dpo" / "preferences.jsonl").read_text().splitlines() if l.strip()]
    return out, {r["id"]: r for r in rows}, rows


def test_human_corrected_makes_a_verdict_contrast_pair(tmp_path):
    sc = Scrubber(salt="k")
    # model said malicious; analyst rejected and corrected to benign
    rec = _rec(sc, alert_id="A1", verdict="malicious",
               actions=[{"action_type": "isolate", "target": "app-07", "requires_hitl": True}],
               human=[_hd("isolate", "app-07", "rejected", corrected="benign")])
    assert rec.label["source"] == "human_corrected"
    out, by_id, rows = _build([rec], tmp_path)
    assert len(rows) == 1
    pair = by_id[rec.record_id]
    chosen, rejected = json.loads(pair["chosen"]), json.loads(pair["rejected"])
    assert chosen["verdict"] == "benign"           # the analyst's call
    assert rejected["verdict"] == "malicious"       # the one the model was overruled on
    assert pair["label_source"] == "human_corrected"
    # prompt is the same system+user shape the SFT judge trains on
    assert [m["role"] for m in pair["prompt"]] == ["system", "user"]
    assert json.loads(pair["prompt"][1]["content"])["id"] == "A1"
    ok, problems = verify_dataset(out)
    assert ok, problems


def test_human_disputed_makes_an_action_contrast_pair(tmp_path):
    sc = Scrubber(salt="k")
    # analyst rejected an auto-run block but named no verdict → hold that action for a human
    rec = _rec(sc, alert_id="A2", verdict="malicious",
               actions=[{"action_type": "block", "target": "10.0.0.9", "requires_hitl": False}],
               human=[_hd("block", "10.0.0.9", "rejected")])
    assert rec.label["source"] == "human_disputed"
    _out, by_id, rows = _build([rec], tmp_path)
    assert len(rows) == 1
    chosen, rejected = json.loads(by_id[rec.record_id]["chosen"]), json.loads(by_id[rec.record_id]["rejected"])
    chosen_block = next(a for a in chosen["recommended_actions"] if a["target"] == "10.0.0.9")
    rejected_block = next(a for a in rejected["recommended_actions"] if a["target"] == "10.0.0.9")
    assert chosen_block["requires_hitl"] is True    # chosen holds it for a human
    assert rejected_block["requires_hitl"] is False  # the overruled auto-run


def test_disputed_pair_survives_an_identity_shaped_target(tmp_path):
    """The analyst rejected an auto-run on a USER ID. The chain target gets pseudonymised by the
    scrubber while the decision's target is what the analyst clicked; matching after scrubbing
    would silently drop exactly these account-level disputes. The match is made on the raw
    chain by index, so the pair is emitted and the chosen side holds the action."""
    sc = Scrubber(salt="k")
    ch = {
        "alert_id": "A6", "verdict": "malicious", "confidence": 0.9,
        "evidence": [{"source": "auth", "signal": "impossible travel", "weight": "high"}],
        "recommended_actions": [{"action_type": "disable_account", "target": "u_42891", "requires_hitl": False},
                                {"action_type": "monitor", "target": "u_42891", "requires_hitl": False}],
        "integrity_hash": "h6",
    }
    rec = record_from_chain(ch, alert={"id": "A6", "source": "auth", "user_id": "u_42891"}, origin="dashboard_chain",
                            scrubber=sc, human=[_hd("disable_account", "u_42891", "rejected")])
    assert rec.label["source"] == "human_disputed"
    acts = rec.chain["recommended_actions"]
    assert acts[0]["target"] != "u_42891" and "u_42891" not in json.dumps(rec.to_dict())   # scrubbed everywhere
    assert acts[0].get("human_rejected") is True and acts[1].get("human_rejected") is None  # flagged by index
    _out, by_id, rows = _build([rec], tmp_path)
    assert len(rows) == 1
    chosen, rejected = json.loads(by_id[rec.record_id]["chosen"]), json.loads(by_id[rec.record_id]["rejected"])
    assert chosen["recommended_actions"][0]["requires_hitl"] is True      # the overruled auto-run is held …
    assert chosen["recommended_actions"][1]["requires_hitl"] is False     # … and only that one
    assert rejected["recommended_actions"][0]["requires_hitl"] is False
    assert "u_42891" not in by_id[rec.record_id]["chosen"]


def test_corrected_pair_holds_the_rejected_action_and_keeps_confidence_neutral(tmp_path):
    """A corrected verdict must not keep rewarding the very action the analyst rejected, and
    the confidence — which the analyst never gave — is identical on both sides so DPO gets no
    preference signal from it."""
    sc = Scrubber(salt="k")
    rec = _rec(sc, alert_id="A7", verdict="malicious",
               actions=[{"action_type": "block", "target": "203.0.113.9", "requires_hitl": False}],
               human=[_hd("block", "203.0.113.9", "rejected", corrected="benign")])
    assert rec.label["source"] == "human_corrected"
    _out, by_id, rows = _build([rec], tmp_path)
    chosen, rejected = json.loads(by_id[rec.record_id]["chosen"]), json.loads(by_id[rec.record_id]["rejected"])
    assert chosen["verdict"] == "benign" and rejected["verdict"] == "malicious"
    assert chosen["recommended_actions"][0]["requires_hitl"] is True      # held, not rewarded
    assert rejected["recommended_actions"][0]["requires_hitl"] is False
    assert chosen["confidence"] == rejected["confidence"]                 # no invented confidence signal


def test_confirmations_agreements_and_synthetic_make_no_pair(tmp_path):
    sc = Scrubber(salt="k")
    confirmed = _rec(sc, alert_id="A3", verdict="malicious",
                     actions=[{"action_type": "isolate", "target": "app-09", "requires_hitl": True}],
                     human=[_hd("isolate", "app-09", "approved")])              # human_confirmed → no contrast
    model_only = _rec(sc, alert_id="A4", verdict="suspicious",
                      actions=[{"action_type": "monitor", "target": "app-10", "requires_hitl": False}],
                      human=[])                                                  # label.source == "model"
    assert confirmed.label["source"] == "human_confirmed"
    assert model_only.label["source"] == "model"
    _out, _by_id, rows = _build([confirmed, model_only], tmp_path)
    assert rows == []


def test_no_dpo_file_without_the_flag(tmp_path):
    sc = Scrubber(salt="k")
    rec = _rec(sc, alert_id="A5", verdict="malicious",
               actions=[{"action_type": "isolate", "target": "app-07", "requires_hitl": True}],
               human=[_hd("isolate", "app-07", "rejected", corrected="benign")])
    out = tmp_path / "ds_nodpo"
    manifest = DatasetBuilder(out, BuildOptions(name="t")).add([rec]).build()   # dpo defaults off
    assert not (out / "dpo").exists()
    assert "dpo/preferences.jsonl" not in manifest["files"]
    assert "dpo_pairs" not in manifest["counts"]
