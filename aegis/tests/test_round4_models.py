"""Round-4 review, group H5: training data and the model supply chain."""

from __future__ import annotations

import gzip
import json
import os
import types

import pytest

from aegis.dataset.contrib import BUNDLE_SCHEMA, records_from_bundles


def _row(i, *, kind="triage", decision="rejected", corrected="benign", verdict="malicious", path=None):
    return {"record_id": f"r{i}", "kind": kind, "origin": "x", "split": "train", "fingerprint": "f" * 64,
            "alert": {"alert_type": "waf", "uri": path or f"/login?id={i}' UNION SELECT password FROM users--"},
            "label": {"verdict": "malicious", "source": "ground_truth"}, "chain": {"verdict": verdict},
            "rationale": "x", "techniques": [],
            "human": [{"approval_id": "a", "action_type": "block", "target": "t", "decision": decision,
                       "decided_by_role": "ciso", "rationale": "", "decided_at": None, "corrected_verdict": corrected,
                       "decided_by": "ciso:r.verma"}]}


def _bundles(tmp_path, groups):
    d = tmp_path / "b"
    d.mkdir()
    for inst, rows in groups.items():
        with gzip.open(d / f"{inst}.json.gz", "wt") as fh:
            json.dump({"schema": BUNDLE_SCHEMA, "installation_id": inst, "records": rows}, fh)
    return d


# ---- D4-1: community bundles cannot set labels, kinds or their own cap ---------------------------------------------

def test_forged_corrections_and_proposal_rows_are_not_imported(tmp_path):
    rows = [_row(i) for i in range(6)] + [_row(99, kind="proposal", decision="approved", corrected="")]
    recs, rep = records_from_bundles(_bundles(tmp_path, {"i1": rows}), gate=False)
    assert recs == [] and rep["unverified_correction"] == 6 and rep["wrong_kind"] == 1


def test_benign_confirmation_on_an_attack_is_dropped(tmp_path):
    rows = [_row(1, decision="approved", corrected="", verdict="benign")]
    recs, rep = records_from_bundles(_bundles(tmp_path, {"i1": rows}), gate=False)
    assert recs == [] and rep["benign_on_attack"] == 1


def test_rotating_installation_ids_hits_the_total_cap(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_CONTRIB_MAX_TOTAL", "5")
    groups = {f"inst-{k}": [_row(k * 10 + j, decision="approved", corrected="") for j in range(3)] for k in range(4)}
    recs, rep = records_from_bundles(_bundles(tmp_path, groups), gate=False, max_per_installation=3)
    assert len(recs) == 5 and rep["capped"] == 7


# ---- D4-12: what leaves the bank -------------------------------------------------------------------------------------

def test_bundle_drops_analyst_names_and_scrubber_handles_keys_and_url_users(tmp_path, monkeypatch):
    from aegis.dataset.contrib import build_bundle
    from aegis.dataset.scrub import Scrubber
    monkeypatch.setenv("AEGIS_DATASET_SALT", "s")
    audit = tmp_path / "audit.jsonl"
    audit.write_text(json.dumps({"alert_id": "A1", "verdict": "malicious", "confidence": 0.9, "evidence": [],
                                 "recommended_actions": []}) + "\n")
    from aegis.dataset import contrib
    from aegis.dataset.schema import HumanDecision
    monkeypatch.setattr(contrib, "_decisions", lambda d: {"A1": [HumanDecision(
        approval_id="x", action_type="block", target="t", decision="approved", decided_by_role="ciso",
        rationale="checked with rajesh.kumar", decided_at=None, corrected_verdict="", decided_by="ciso:r.verma")]})
    bundle, _ = build_bundle(audit, installation_id="inst-1", license_id="L", hitl_dir=tmp_path)
    hs = [h for r in bundle["records"] for h in r.get("human") or []]
    assert hs and all(h["decided_by"] == "" and h["rationale"] == "" and h["decided_by_role"] == "ciso" for h in hs)
    out = Scrubber(salt="s").scrub({"failed_by_user": {"r.verma@sbi.co.in": 1, "9876543210": 2},
                                    "conn": "postgresql://acpadmin:pw@db.internal:5432/acp"})
    keys = list(out["failed_by_user"])
    assert "r.verma" not in json.dumps(keys) and "9876543210" not in keys
    assert "acpadmin" not in out["conn"] and "pw@" not in out["conn"]


def test_export_privacy_gate_holds_back_leaky_records():
    from aegis.dataset.__main__ import _privacy_gated
    clean = types.SimpleNamespace(to_dict=lambda: {"alert": {"src_ip": "203.0.113.9", "user": "user_ab12cd34ef"}})
    leaky = types.SimpleNamespace(to_dict=lambda: {"alert": {"note": "call 9876543210"}})
    assert _privacy_gated([clean, leaky], scrub_ips=False, where="t") == [clean]


# ---- D4-11: eval alerts never train ---------------------------------------------------------------------------------

def test_eval_alerts_from_any_source_go_to_test(tmp_path):
    from aegis.dataset.export import BuildOptions, DatasetBuilder
    from aegis.dataset.schema import TriageRecord
    from aegis.eval.run import HERE
    case = json.loads((HERE / "historical_alerts" / "cases.json").read_text())[0]
    rec = TriageRecord(record_id="c1", kind="triage", origin="community_contrib", split="", fingerprint="0" * 64,
                       alert=case["alert"], label={"verdict": case["expected_verdict"], "source": "human_confirmed"},
                       chain={"verdict": case["expected_verdict"]}, rationale="", techniques=[])
    m = DatasetBuilder(tmp_path / "ds", BuildOptions(name="t")).add([rec]).build()
    assert m["counts"]["by_split"].get("test") == 1


# ---- D4-2 / D4-3 / D4-4: the gate and publish -------------------------------------------------------------------------

def test_benign_on_every_injection_case_fails_the_gate():
    from aegis.eval.run import HERE
    from aegis.finetune.gate import evaluate
    exp = {}
    for name in ("historical_alerts", "agentic_chains", "endpoint_chains", "tls_chains", "network_chains"):
        for c in json.loads((HERE / name / "cases.json").read_text()):
            exp[c["alert"]["id"]] = c["expected_verdict"]
    res = evaluate(lambda a: exp.get(a["id"], "benign"), actions=lambda a: [])
    assert res.n_inj_leak == res.injection_total and not res.passes()


def _adapter(tmp_path):
    ad = tmp_path / "adapter"
    ad.mkdir()
    (ad / "adapter_config.json").write_text(json.dumps({"base_model_name_or_path": "Qwen/Qwen3-8B"}))
    (ad / "adapter_model.safetensors").write_bytes(b"w" * 64)
    return ad


@pytest.mark.skipif(os.name == "nt", reason="creating symlinks needs a privilege Windows CI does not grant")
def test_nested_symlink_out_of_the_adapter_is_refused(tmp_path):
    from aegis.finetune import publish
    ad = _adapter(tmp_path)
    (tmp_path / "secret").write_text("aws creds")
    (ad / "checkpoint-10").mkdir()
    (ad / "checkpoint-10" / "trainer_state.json").symlink_to(tmp_path / "secret")
    with pytest.raises(SystemExit, match="links outside"):
        publish.check_links(ad)
    hf = tmp_path / "huggingface"
    hf.mkdir()
    (hf / "token").write_text("hf_x")
    (ad / "checkpoint-10" / "trainer_state.json").unlink()
    (ad / "tok.json").symlink_to(hf / "token")
    with pytest.raises(SystemExit, match="links outside"):
        publish.check_links(ad)


def test_stale_gate_report_does_not_publish_new_weights(tmp_path):
    from aegis.finetune import publish
    from aegis.finetune.digest import adapter_digest
    from aegis.finetune.gate import gate_report_path
    ad = _adapter(tmp_path)
    gate_report_path(ad).write_text(json.dumps({"passes": True, "adapter_digest": adapter_digest(ad)}))
    assert publish.main(["--adapter", str(ad), "--version", "2026.11.1", "--dry-run"]) == 0
    (ad / "adapter_model.safetensors").write_bytes(b"x" * 64)         # retrained into the same --out
    with pytest.raises(SystemExit):
        publish.main(["--adapter", str(ad), "--version", "2026.11.1", "--dry-run"])


# ---- D4-8: retrain rollback sticks --------------------------------------------------------------------------------------

def test_retrain_rollback_is_not_undone_by_sync(tmp_path):
    from aegis.finetune import retrain
    from aegis.finetune.digest import adapter_digest
    runs = tmp_path
    st = retrain.State(runs / "retrain" / "state.json")
    for r in ("good", "bad"):
        (runs / r / "adapter").mkdir(parents=True)
        (runs / r / "adapter" / "adapter_config.json").write_text(r)
        st.runs[r] = {"adapter": str(runs / r / "adapter"), "sha256": adapter_digest(runs / r / "adapter"),
                      "stage": "shadowed", "stages": {"shadowed": {"verdict": "ready"}}}
    retrain._promote(st, "good", approved_by="a", rationale="", proposal_id=None)
    retrain._promote(st, "bad", approved_by="a", rationale="", proposal_id=None)
    st.save()
    a = types.SimpleNamespace(runs=str(runs), approved_by="ciso:b", rationale="bad model", dry_run=False,
                              dashboard=False, hitl_dir=str(runs / "hitl"), run="bad")
    assert retrain.cmd_rollback(a) == 0
    cur = runs / "retrain" / "current.json"
    assert json.loads(cur.read_text())["run"] == "good"
    accepted = [{"change": {"run": "bad", "sha256": st.runs["bad"]["sha256"]}}]
    retrain.cmd_sync(a, accepted=lambda d: accepted)
    assert json.loads(cur.read_text())["run"] == "good"
    assert retrain.cmd_promote(a) == 1


# ---- D4-9 / D4-10: fleet updates ----------------------------------------------------------------------------------------

def test_unreadable_deny_file_refuses_updates(tmp_path):
    from aegis import model_updates as mu
    env = {"AEGIS_MODEL_DIR": str(tmp_path)}
    (tmp_path / "denied.json").write_text("[1, 2")
    assert mu._ALL in mu._denied(env)


def test_release_never_silently_replaces_the_banks_own_model(tmp_path):
    from aegis import model_updates as mu
    ptr = tmp_path / "current.json"
    ptr.write_text(json.dumps({"run": "retrain-2026-11-02", "approved_by": "ciso:r"}))
    env = {"AEGIS_MODEL_POINTER": str(ptr), "AEGIS_MODEL_DIR": str(tmp_path)}
    assert mu._local_model(env)
    assert not mu._local_model({**env, "AEGIS_MODEL_UPDATES_REPLACE_LOCAL": "1"})
    ptr.write_text(json.dumps({"run": "2026.11.1", "approved_by": "bluedefence-release"}))
    assert not mu._local_model(env)


# ---- D4-15: a refused pointer is looked at again ------------------------------------------------------------------------

def test_refused_pointer_is_not_stored_as_seen():
    from aegis.finetune.hot_reload import apply_reload
    r = apply_reload(None, "", {"run": "r1", "adapter": "/gpu/r1", "sha256": "v2:" + "a" * 32})
    assert r.mode == "refused" and r.key == ""


# ---- X4-3 / D4-14: polynomial ReDoS ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("rx", [r"\w+\d+\w+\d+=", r"\s*\s*\s*\s*\s*=zq"])
def test_polynomial_backtracking_regex_is_refused(rx):
    from aegis.evolve.registry import validate_regex
    assert "ReDoS" in (validate_regex(rx, 300) or "")


def test_ordinary_regex_still_passes():
    from aegis.evolve.registry import validate_regex
    assert validate_regex(r"certutil\s+-urlcache", 300) is None
