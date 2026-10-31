"""load_dpo enforces the same analyst-only safety as load_sft; the DPO dry-run runs offline."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.finetune.dpo import main as dpo_main
from aegis.finetune.dpo_data import DataError, load_dpo, split_prefs

_SYS = "triage system prompt"


def _pair(rid, split, src="human_corrected", chosen=None, rejected=None, alert=None):
    chosen = chosen or {"verdict": "benign", "confidence": 0.3, "recommended_actions": []}
    rejected = rejected or {"verdict": "malicious", "confidence": 0.9, "recommended_actions": []}
    return {
        "id": rid, "split": split, "label_source": src, "origin": "dashboard_chain",
        "prompt": [{"role": "system", "content": _SYS},
                   {"role": "user", "content": json.dumps(alert or {"id": rid})}],
        "chosen": json.dumps(chosen), "rejected": json.dumps(rejected),
    }


def _write(tmp_path, rows) -> Path:
    d = tmp_path / "ds" / "dpo"
    d.mkdir(parents=True)
    (d / "preferences.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return tmp_path / "ds"


def test_load_and_split(tmp_path):
    ds = _write(tmp_path, [_pair("a", "train"), _pair("b", "train"), _pair("c", "val"),
                           _pair("d", "test")])
    rows = load_dpo(ds)                        # default keeps train+val, never test
    assert {r.id for r in rows} == {"a", "b", "c"}
    train, val = split_prefs(rows)
    assert {r.id for r in train} == {"a", "b"} and {r.id for r in val} == {"c"}
    assert rows[0].prompt.startswith(_SYS)


def test_identical_chosen_rejected_is_rejected(tmp_path):
    same = {"verdict": "benign", "confidence": 0.3, "recommended_actions": []}
    ds = _write(tmp_path, [_pair("a", "train", chosen=same, rejected=same)])
    with pytest.raises(DataError, match="identical"):
        load_dpo(ds)


def test_bad_prompt_shape_is_rejected(tmp_path):
    row = _pair("a", "train")
    row["prompt"] = [{"role": "user", "content": "{}"}]          # missing system turn
    ds = _write(tmp_path, [row])
    with pytest.raises(DataError, match="prompt"):
        load_dpo(ds)


def test_bad_chosen_verdict_is_rejected(tmp_path):
    ds = _write(tmp_path, [_pair("a", "train", chosen={"verdict": "nonsense"})])
    with pytest.raises(DataError, match="verdict"):
        load_dpo(ds)


def test_non_analyst_rows_refused_unless_allowed(tmp_path):
    ds = _write(tmp_path, [_pair("a", "train", src="synthetic")])
    with pytest.raises(DataError):
        load_dpo(ds)                           # all rows non-analyst → nothing usable
    assert load_dpo(ds, allow_synthetic=True)[0].id == "a"


def test_dry_run_plan_runs_offline(tmp_path, capsys):
    ds = _write(tmp_path, [_pair("a", "train"), _pair("b", "val")])
    rc = dpo_main(["--data", str(ds), "--dry-run", "--vram", "8"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "preference pairs" in out and "DPO" in out and "--dry-run: nothing trained" in out


def test_missing_file_errors_clearly(tmp_path):
    with pytest.raises(DataError, match="no dpo/preferences.jsonl"):
        load_dpo(tmp_path / "empty")


def test_split_never_empties_train_and_plan_refuses_an_empty_train(tmp_path):
    # one training row: nothing to hold out, so it stays in train
    from aegis.finetune.dpo_data import Preference
    only = Preference("a", "train", "human_corrected", "o", _SYS, "{}", '{"verdict":"benign"}', '{"verdict":"malicious"}')
    train, val = split_prefs([only])
    assert len(train) == 1 and val == []
    # every pair in val -> the plan refuses rather than planning a run on nothing
    ds = _write(tmp_path, [_pair("a", "val"), _pair("b", "val")])
    assert dpo_main(["--data", str(ds), "--dry-run"]) == 2
