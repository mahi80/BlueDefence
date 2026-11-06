"""Round-3 review, group G5: training data and the model supply chain."""

from __future__ import annotations

import gzip
import json
import os
import types
from pathlib import Path

import pytest

from aegis.dataset.contrib import BUNDLE_SCHEMA, records_from_bundles
from aegis.dataset.schema import HumanDecision, _label_from_human


def _row(i, *, verdict="malicious", label=("benign", "ground_truth"), split="train", human=None):
    return {"record_id": f"r{i}", "kind": "triage", "origin": "attacker_says", "split": split,
            "fingerprint": f"{i:032x}", "alert": {"id": f"a{i}", "path": f"/login?id={i}' OR 1=1--"},   # distinct content: the fingerprint is recomputed
            "label": {"verdict": label[0], "source": label[1]}, "chain": {"verdict": verdict},
            "rationale": "r", "techniques": [], "human": human or [], "tags": ["eval_holdout"]}


def _bundle(tmp_path, rows, inst="inst-evil"):
    d = tmp_path / "bundles"; d.mkdir(exist_ok=True)
    p = d / f"{inst}.json.gz"
    with gzip.open(p, "wt") as fh:
        json.dump({"schema": BUNDLE_SCHEMA, "installation_id": inst, "records": rows}, fh)
    return d


# ---- G5-1: a community bundle cannot set its own labels, split or origin ------------------------------------

def test_contributor_labels_are_not_trusted(tmp_path):
    rows = [_row(i) for i in range(30)]                     # 30 SQLi labelled benign/ground_truth, no decisions
    recs, rep = records_from_bundles(_bundle(tmp_path, rows), gate=False)
    assert recs == [] and rep["unlabelled"] == 30           # a label with no analyst decision teaches nothing


def test_contributed_records_get_labels_from_decisions_and_fresh_splits(tmp_path):
    approve = {"approval_id": "x", "action_type": "block", "target": "1.2.3.4", "decision": "approved", "decided_by": "ciso:a"}
    timer = {**approve, "decided_by": "aegis:hitl-timeout"}
    rows = [_row(1, human=[approve], split="test"), _row(2, human=[timer])]
    recs, rep = records_from_bundles(_bundle(tmp_path, rows), gate=False)
    assert len(recs) == 1 and rep["unlabelled"] == 1        # the timer's approval is not a label
    r = recs[0]
    assert r.label == {"verdict": "malicious", "source": "human_confirmed"}
    assert r.origin == "community_contrib" and r.split == "" and "community" in r.tags
    assert not any(t.startswith("eval") for t in r.tags)


def test_contributions_are_capped_per_installation(tmp_path):
    ok = {"approval_id": "x", "action_type": "block", "target": "t", "decision": "approved", "decided_by": "ciso:a"}
    rows = [_row(i, human=[ok]) for i in range(50)]
    recs, rep = records_from_bundles(_bundle(tmp_path, rows), gate=False, max_per_installation=10)
    assert len(recs) == 10 and rep["capped"] == 40


def test_timeout_approval_is_not_a_human_label():
    h = HumanDecision(approval_id="x", action_type="block", target="t", decision="approved", decided_by="aegis:hitl-timeout")
    assert _label_from_human("malicious", [h])[1] == "model"


# ---- G5-3 / G5-5 / G5-6: the gate -------------------------------------------------------------------------

def test_gate_report_does_not_change_the_adapter_digest(tmp_path):
    from aegis.finetune.digest import adapter_digest, verify_adapter
    from aegis.finetune.gate import gate_report_path
    ad = tmp_path / "adapter"; ad.mkdir()
    (ad / "adapter_model.safetensors").write_bytes(b"w" * 64)
    before = adapter_digest(ad)
    gate_report_path(ad).write_text(json.dumps({"passes": True}))
    assert gate_report_path(ad).parent == tmp_path and verify_adapter(ad, before)[0]


def test_empty_gate_is_not_a_pass():
    from aegis.finetune.gate import GateResult
    r = GateResult(historical_total=0, historical_misses=[], injection_total=0, injection_leaks=[])
    assert r.passes() is False
    assert GateResult(historical_total=37, historical_misses=[], injection_total=9, injection_leaks=[]).passes()


def test_stale_gate_report_does_not_pass_a_crashed_gate(tmp_path):
    from aegis.finetune import retrain as rt
    from aegis.finetune.gate import gate_report_path
    ad = tmp_path / "adapter"; ad.mkdir()
    gate_report_path(ad).write_text(json.dumps({"passes": True, "summary": "old PASS"}))
    g = rt.gate_stage(ad, dry_run=False, runner=lambda cmd, dry_run: 1)       # crashed before writing
    assert g["passes"] is False


# ---- G5-7: promotion needs a shadow verdict of ready ---------------------------------------------------------

def test_only_a_ready_shadow_can_be_promoted(tmp_path):
    from aegis.finetune import retrain as rt
    from aegis.finetune.digest import adapter_digest
    ad = tmp_path / "ad"; ad.mkdir(); (ad / "adapter_model.safetensors").write_bytes(b"w")
    runs = tmp_path / "runs"; st = rt.State.load(runs)
    st.runs["worse"] = {"stage": "shadowed", "adapter": str(ad), "sha256": adapter_digest(ad),
                        "stages": {"shadowed": {"verdict": "worse"}}}
    st.runs["gated"] = {"stage": "gated", "adapter": str(ad), "sha256": adapter_digest(ad)}
    st.save()
    a = types.SimpleNamespace(runs=str(runs), dry_run=False)
    assert rt.cmd_sync(a, accepted=lambda d: [{"change": {"run": "worse"}, "decided_by": "ciso"}]) == 1
    for run in ("worse", "gated"):
        p = types.SimpleNamespace(runs=str(runs), run=run, approved_by="ciso", rationale="x")
        assert rt.cmd_promote(p) == 1
    assert rt.State.load(runs).current is None


# ---- G5-4: a rolled-back release is not re-applied -----------------------------------------------------------

def test_rolled_back_version_is_denied(tmp_path):
    from aegis import license as L
    from aegis import model_updates as mu
    env = {"AEGIS_MODEL_DIR": str(tmp_path / "models"), "AEGIS_MODEL_POINTER": str(tmp_path / "current.json")}
    _, priv = L.write_keypair(tmp_path, "rel-kid", bits=1024)
    k = json.loads(priv.read_text())
    for v in ("2026.10.1", "2026.11.1"):
        d = Path(env["AEGIS_MODEL_DIR"]) / v; d.mkdir(parents=True)
        (d / "adapter_model.safetensors").write_bytes(v.encode())
        rel = {"version": v, "sha256": "x", "base_model": "b", "channel": "stable", "size": 1}
        (d / "release.json").write_text(json.dumps(rel))
        (d / mu.MANIFEST_FILE).write_text(mu.sign_manifest(rel, n=int(k["n"], 16), d=int(k["d"], 16), kid="rel-kid"))
        (d / ".complete").write_text("")
        mu.write_pointer({**rel, "adapter": str(d)}, pointer=Path(env["AEGIS_MODEL_POINTER"]),
                         previous="2026.10.1" if v == "2026.11.1" else "")
    out = mu.rollback(env, keys={"rel-kid": (int(k["n"], 16), 65537)})
    assert out["ok"] and out["denied"] == "2026.11.1" and "2026.11.1" in mu._denied(env)


# ---- publish never ships files from outside the adapter -------------------------------------------------------

@pytest.mark.skipif(os.name == "nt", reason="creating symlinks needs a privilege Windows CI does not grant")
def test_publish_refuses_links_outside_the_adapter(tmp_path):
    from aegis.finetune.publish import _tar_adapter
    ad = tmp_path / "ad"; ad.mkdir()
    (ad / "adapter_model.safetensors").write_bytes(b"w")
    secret = tmp_path / "secret.txt"; secret.write_text("host secret")
    (ad / "notes.txt").symlink_to(secret)
    with pytest.raises(SystemExit, match="outside the adapter"):
        _tar_adapter(ad, tmp_path / "out.tar.gz")
