"""Round 8 learning-loop fixes: T8-1 … T8-10 (pointer anti-replay, signed retrain state, release rollback, eval guard,
analyst-set forgetting, compliance customer match, gate normalisation, community under-response, rollback to base)
and the T-1 identity / host-name leftovers."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

SALT = "s3cret-salt-xyz-0123456789abcdef"


class _VLLM:
    model = "base"

    def set_model(self, m):
        self.model = m


def _adapter(d: Path, content: bytes = b"w") -> str:
    from aegis.finetune.digest import adapter_digest
    d.mkdir(parents=True, exist_ok=True)
    (d / "adapter_config.json").write_text("{}")
    (d / "adapter_model.safetensors").write_bytes(content)
    return adapter_digest(d)


@pytest.fixture
def signed(monkeypatch):
    monkeypatch.setenv("AEGIS_CONSOLE_TOKEN", "console-secret")
    monkeypatch.delenv("AEGIS_DECISION_KEY", raising=False)
    monkeypatch.delenv("AEGIS_ALLOW_UNVERIFIED_MODEL", raising=False)
    monkeypatch.delenv("AEGIS_RETRAIN_ADOPT_STATE", raising=False)
    monkeypatch.delenv("AEGIS_POINTER_STATE_RESET", raising=False)


def _ns(runs, **kw):
    b = {"role": "triage", "runs": str(runs), "run": None, "preset": "p", "base_data": None, "since": None,
         "dashboard": False, "dry_run": False, "min_new_rows": 1, "epochs": 1, "max_rows": 0, "hitl_dir": None,
         "approved_by": "ciso", "rationale": "bad model", "rows": None}
    b.update(kw)
    return argparse.Namespace(**b)


def _promoted(runs: Path, run: str = "r1", content: bytes = b"BAD"):
    import aegis.finetune.retrain as R
    sha = _adapter(runs / run / "adapter", content)
    st = R.State.load(runs)
    st.runs[run] = {"role": "triage", "adapter": str(runs / run / "adapter"), "sha256": sha, "stage": "shadowed",
                    "stages": {"shadowed": {"verdict": "ready"}}}
    R._promote(st, run, approved_by="alice", rationale="ok", proposal_id=None)
    st.save()
    return runs / "retrain" / "current.json"


# ---- T8-1: a signed pointer cannot be replayed after a rollback -------------------------------------------------------

def test_t8_1_local_pointer_replay_after_rollback_is_refused_everywhere(tmp_path, signed, monkeypatch):
    import aegis.finetune.retrain as R
    from aegis.agents.shared import llm_client as lc
    from aegis.finetune import hot_reload as hr
    from aegis.finetune.pointer_trust import verify_pointer
    runs = tmp_path / "runs"
    ptr = _promoted(runs)
    saved = ptr.read_text()
    cur = json.loads(saved)
    assert cur["seq"] == 1 and verify_pointer(cur, path=ptr)[0]
    assert R.cmd_rollback(_ns(runs)) == 0 and not ptr.exists()
    ptr.write_text(saved)                                       # attacker restores the old signed pointer
    ok, why = verify_pointer(cur, path=ptr)
    assert not ok and ("old pointer" in why or "rolled back" in why)
    monkeypatch.setenv("AEGIS_MODEL_POINTER", str(ptr))
    assert lc._promoted_model() is None
    v = _VLLM()
    assert hr.apply_reload(v, "", hr.read_pointer(str(ptr))).mode == "refused" and v.model == "base"


def test_t8_1_rolled_back_run_is_denied_in_the_signed_record(tmp_path, signed):
    import aegis.finetune.retrain as R
    from aegis.finetune.pointer_trust import commit_pointer, denied_runs, verify_pointer
    runs = tmp_path / "runs"
    ptr = _promoted(runs)
    assert R.cmd_rollback(_ns(runs)) == 0
    assert "r1" in denied_runs(ptr)[0]
    # even a fresh, correctly sequenced pointer naming the rolled-back run is refused (local deny list applies)
    forged = commit_pointer(ptr, {"run": "r1", "role": "triage", "adapter": "/x", "sha256": "y", "approved_by": "z"})
    ok, why = verify_pointer(forged, path=ptr)
    assert not ok and "rolled back" in why


def test_t8_1_t8_4_deleting_the_record_does_not_forget(tmp_path, signed):
    from aegis.finetune.pointer_trust import (
        PointerStateError,
        commit_pointer,
        state_path_for,
        verify_pointer,
    )
    ptr = _promoted(tmp_path / "runs")
    cur = json.loads(ptr.read_text())
    state_path_for(ptr).unlink()
    ok, why = verify_pointer(cur, path=ptr)
    assert not ok and "no signed pointer record" in why
    with pytest.raises(PointerStateError):          # and the writer will not silently start a new sequence
        commit_pointer(ptr, cur)


def test_t8_1_hand_signed_pointer_without_its_sequence_is_refused(tmp_path, signed):
    from aegis.finetune.pointer_trust import sign_pointer, verify_pointer
    ptr = _promoted(tmp_path / "runs")
    cur = json.loads(ptr.read_text())
    stale = sign_pointer({**cur, "seq": cur["seq"] - 1})
    assert not verify_pointer(stale, path=ptr)[0]


# ---- T8-2: state.json is signed; a routine save never signs `current` -------------------------------------------------

def test_t8_2_unsigned_state_json_is_refused_and_nothing_is_signed(tmp_path, signed):
    import aegis.finetune.retrain as R
    runs = tmp_path / "runs"; (runs / "retrain").mkdir(parents=True)
    evil = tmp_path / "evil"; esha = _adapter(evil, b"ATTACKER")
    (runs / "retrain" / "state.json").write_text(json.dumps({"current": {
        "run": "evil", "role": "triage", "adapter": str(evil), "sha256": esha, "approved_by": "ciso",
        "promoted_at": "2026-11-04T00:00:00+00:00"}, "runs": {}, "history": []}))
    assert R.cmd_sync(_ns(runs), accepted=lambda dry: []) == 2
    assert not (runs / "retrain" / "current.json").exists()


def test_t8_2_tampered_state_json_is_refused(tmp_path, signed):
    import aegis.finetune.retrain as R
    runs = tmp_path / "runs"
    _promoted(runs)
    p = runs / "retrain" / "state.json"
    d = json.loads(p.read_text())
    d["runs"]["r1"]["sha256"] = "v2:" + "0" * 32
    p.write_text(json.dumps(d))
    with pytest.raises(R.StateError):
        R.State.load(runs)
    assert R.main(["status", "--runs", str(runs)]) == 2


def test_t8_2_save_without_a_promotion_writes_no_pointer(tmp_path, signed):
    import aegis.finetune.retrain as R
    st = R.State.load(tmp_path)
    st.current = {"run": "x", "role": "triage", "adapter": "/a", "sha256": "s", "approved_by": "x"}
    st.save()
    assert not (tmp_path / "retrain" / "current.json").exists()
    assert R.State.load(tmp_path).current["run"] == "x"            # its own signature verifies


def test_t8_2_promote_rechecks_the_adapter_and_the_gate_report(tmp_path, signed):
    import aegis.finetune.retrain as R
    from aegis.finetune.gate import gate_report_path
    runs = tmp_path / "runs"
    sha = _adapter(runs / "r1" / "adapter")
    st = R.State.load(runs)
    st.runs["r1"] = {"role": "triage", "adapter": str(runs / "r1" / "adapter"), "sha256": sha, "stage": "shadowed",
                     "stages": {"shadowed": {"verdict": "ready"}}}
    gate_report_path(runs / "r1" / "adapter").write_text(json.dumps({"passes": True, "adapter_digest": "v2:" + "1" * 32}))
    with pytest.raises(R.PromotionRefused, match="gate report"):
        R._promote(st, "r1", approved_by="a", rationale="", proposal_id=None)
    gate_report_path(runs / "r1" / "adapter").unlink()
    (runs / "r1" / "adapter" / "adapter_model.safetensors").write_bytes(b"swapped")
    with pytest.raises(R.PromotionRefused, match="digest"):
        R._promote(st, "r1", approved_by="a", rationale="", proposal_id=None)
    assert st.current is None and not st.pending


# ---- T8-3 / T8-4: vendor release rollback ----------------------------------------------------------------------------

def _keys(tmp_path):
    from aegis import license as L
    kd = tmp_path / "_k"; kd.mkdir(exist_ok=True)
    _, priv = L.write_keypair(kd, "rel-kid", bits=1024)
    k = json.loads(priv.read_text())
    return int(k["n"], 16), int(k["d"], 16), {"rel-kid": (int(k["n"], 16), 65537)}


def _release(md: Path, v: str, n: int, d: int, *, content: bytes | None = None) -> dict:
    from aegis import model_updates as mu
    rd = md / v; _adapter(rd, content or v.encode())
    rel = {"version": v, "channel": "stable", "base_model": "q", "sha256": "0" * 64, "size": 1}
    (rd / "release.json").write_text(json.dumps(rel))
    (rd / mu.MANIFEST_FILE).write_text(mu.sign_manifest(rel, n=n, d=d, kid="rel-kid"))
    (rd / ".complete").write_text("1")
    return {**rel, "adapter": str(rd)}


@pytest.fixture
def vendor(tmp_path, signed, monkeypatch):
    md = tmp_path / "models"; md.mkdir()
    monkeypatch.setenv("AEGIS_MODEL_DIR", str(md))
    monkeypatch.setenv("AEGIS_MODEL_POINTER", str(md / "current.json"))
    monkeypatch.delenv("LLM_BACKEND", raising=False)
    n, d, pub = _keys(tmp_path)
    return SimpleNamespace(md=md, ptr=md / "current.json", n=n, d=d, pub=pub)


def test_t8_3_previous_is_signed_so_editing_it_breaks_the_pointer(vendor):
    from aegis import model_updates as mu
    from aegis.finetune.pointer_trust import verify_pointer
    mu.write_pointer(_release(vendor.md, "2026.11.1", vendor.n, vendor.d), pointer=vendor.ptr)
    p = json.loads(vendor.ptr.read_text())
    p["previous"] = "../elsewhere/evil"
    vendor.ptr.write_text(json.dumps(p))
    assert not verify_pointer(p, path=vendor.ptr)[0]
    rb = mu.rollback(keys=vendor.pub)
    assert not rb["ok"] and "not signed" in rb["reason"]


def test_t8_3_previous_outside_the_model_dir_is_refused_even_when_signed(vendor, tmp_path):
    from aegis import model_updates as mu
    evil_root = tmp_path / "elsewhere"; evil_root.mkdir()
    _release(evil_root, "2026.12.9", vendor.n, vendor.d)
    mu.write_pointer(_release(vendor.md, "2026.11.1", vendor.n, vendor.d), pointer=vendor.ptr,
                     previous="../elsewhere/2026.12.9")
    rb = mu.rollback(keys=vendor.pub)
    assert not rb["ok"] and "not a version string" in rb["reason"]
    assert json.loads(vendor.ptr.read_text())["run"] == "2026.11.1"


def test_t8_3_rollback_reverifies_the_previous_release_dir(vendor):
    from aegis import model_updates as mu
    r1 = _release(vendor.md, "2026.10.1", vendor.n, vendor.d)
    mu.write_pointer(r1, pointer=vendor.ptr)
    mu.write_pointer(_release(vendor.md, "2026.11.1", vendor.n, vendor.d), pointer=vendor.ptr, previous="2026.10.1")
    # the old release's weights were swapped on disk after it was installed
    (vendor.md / "2026.10.1" / "adapter_model.safetensors").write_bytes(b"ATTACKER")
    rb = mu.rollback(keys=vendor.pub)
    assert not rb["ok"] and "digest" in rb["reason"]
    # restore, but drop its signed manifest: an unverifiable directory is not rolled back to either
    (vendor.md / "2026.10.1" / "adapter_model.safetensors").write_bytes(b"2026.10.1")
    (vendor.md / "2026.10.1" / mu.MANIFEST_FILE).unlink()
    assert "signed manifest" in mu.rollback(keys=vendor.pub)["reason"]


def test_t8_3_t8_4_rollback_happy_path_and_old_pointer_never_comes_back(vendor):
    from aegis import model_updates as mu
    from aegis.agents.shared import llm_client as lc
    from aegis.finetune.pointer_trust import verify_pointer
    mu.write_pointer(_release(vendor.md, "2026.10.1", vendor.n, vendor.d), pointer=vendor.ptr)
    bad = mu.write_pointer(_release(vendor.md, "2026.11.1", vendor.n, vendor.d), pointer=vendor.ptr, previous="2026.10.1")
    rb = mu.rollback(keys=vendor.pub)
    assert rb["ok"] and rb["denied"] == "2026.11.1"
    assert lc._promoted_model() == str(vendor.md / "2026.10.1")
    assert not verify_pointer(bad, path=vendor.ptr)[0]
    assert not (vendor.md / "denied.json").exists()             # nothing to delete: the deny is in the signed record
    vendor.ptr.write_text(json.dumps(bad))                      # restore the rolled-back release's signed pointer
    assert lc._promoted_model() is None
    assert "2026.11.1" in mu._denied({"AEGIS_MODEL_DIR": str(vendor.md), "AEGIS_MODEL_POINTER": str(vendor.ptr)})


def test_t8_4_tampered_record_refuses_everything(vendor):
    from aegis import model_updates as mu
    from aegis.finetune.pointer_trust import state_path_for, verify_pointer
    cur = mu.write_pointer(_release(vendor.md, "2026.11.1", vendor.n, vendor.d), pointer=vendor.ptr)
    st = json.loads(state_path_for(vendor.ptr).read_text())
    st["roles"]["triage"]["denied"] = []
    st["roles"]["triage"]["seq"] = 99
    state_path_for(vendor.ptr).write_text(json.dumps(st))
    assert not verify_pointer(cur, path=vendor.ptr)[0]
    assert mu._denied({"AEGIS_MODEL_DIR": str(vendor.md), "AEGIS_MODEL_POINTER": str(vendor.ptr)}) == {mu._ALL}


def test_t8_1_adopt_resigns_a_checked_legacy_pointer(tmp_path, signed):
    import hashlib
    import hmac

    from aegis.finetune.pointer_trust import (
        _POINTER_SIGNED_V1,
        _key,
        adopt,
        verify_pointer,
    )
    sha = _adapter(tmp_path / "ad")
    cur = {"run": "r0", "role": "triage", "adapter": str(tmp_path / "ad"), "sha256": sha, "approved_by": "ciso",
           "promoted_at": "t"}
    body = json.dumps({f: cur.get(f) for f in _POINTER_SIGNED_V1}, sort_keys=True, separators=(",", ":"), default=str)
    cur["sig"] = hmac.new(_key(), b"aegis-model-pointer-v1|" + body.encode(), hashlib.sha256).hexdigest()
    p = tmp_path / "current.json"; p.write_text(json.dumps(cur))
    ok, why = verify_pointer(cur, path=p)
    assert not ok and "re-adopt" in why
    assert adopt(p) == (True, "")
    assert verify_pointer(json.loads(p.read_text()), path=p)[0]
    assert adopt(p)[0] is False                                 # once only


# ---- T8-5: the eval guard survives scrubbing, whitespace and extra keys ------------------------------------------------

def _eval_alerts():
    from aegis.dataset.schema import EVAL_CORPORA
    from aegis.eval.run import HERE
    out = []
    for name in EVAL_CORPORA:
        p = HERE / name / "cases.json"
        if p.exists():
            out += [c for c in json.loads(p.read_text()) if isinstance(c.get("alert"), dict)]
    return out


def _variants(a: dict):
    from aegis.dataset.scrub import Scrubber
    bank = Scrubber(salt="bank-production-salt-0123456789")
    bank_ips = Scrubber(salt="bank-production-salt-0123456789", scrub_ips=True)
    b = dict(a)
    k = next((k for k, v in a.items() if isinstance(v, str) and k != "id"), None)
    if k:
        b[k] = a[k] + " "
    return {"scrubbed": bank.scrub(a), "scrubbed_ips": bank_ips.scrub(a), "trailing_space": b,
            "extra_key": {**a, "dataset": "x"}, "scrubbed_extra_key": {**bank_ips.scrub(a), "dataset": "x"}}


def test_t8_5_every_eval_alert_is_recognised_in_every_variant():
    from aegis.dataset.schema import eval_case_match
    cases = _eval_alerts()
    assert len(cases) >= 92
    missed = {}
    for c in cases:
        for name, v in _variants(c["alert"]).items():
            if eval_case_match(v) is None:
                missed.setdefault(name, []).append(c["alert"].get("id"))
    assert missed == {}


def test_t8_5_no_false_matches_on_synthetic_rows():
    from aegis.dataset.schema import eval_case_match
    from aegis.dataset.synth import generate
    rows = generate(300, seed=11)
    assert not [r["id"] for r in rows if eval_case_match(json.loads(r["messages"][1]["content"]))]


def test_t8_5_export_path_moves_scrubbed_eval_alerts_to_test(tmp_path):
    from aegis.dataset.export import BuildOptions, DatasetBuilder
    from aegis.dataset.schema import TriageRecord, fingerprint
    cases = _eval_alerts()
    recs = []
    for i, c in enumerate(cases):
        a = _variants(c["alert"])["scrubbed_extra_key"]
        recs.append(TriageRecord(record_id=f"c{i}", kind="triage", origin="soc_capture", split="", fingerprint=fingerprint(a),
                                 alert=a, label={"verdict": c.get("expected_verdict") or "suspicious", "source": "human_confirmed"},
                                 chain={"verdict": c.get("expected_verdict") or "suspicious"}, rationale="", techniques=[]))
    m = DatasetBuilder(tmp_path / "ds", BuildOptions(name="t")).add(recs).build()
    assert m["counts"]["by_split"].get("test") == len(cases)


_REC = {"origin": "x", "split": "train", "fingerprint": "f", "rationale": "", "techniques": []}


def test_t8_5_contrib_path_drops_scrubbed_eval_alerts():
    from aegis.dataset.contrib import _community_record
    caught, rep = 0, {}
    cases = _eval_alerts()
    for c in cases:
        a = _variants(c["alert"])["scrubbed_ips"]
        row = {"record_id": "r", "kind": "triage", **_REC, "alert": a, "label": {"verdict": "malicious", "source": "ground_truth"},
               "chain": {"verdict": "malicious", "recommended_actions": [{"action_type": "isolate", "target": "h", "requires_hitl": True}]},
               "human": [{"approval_id": "a1", "action_type": "isolate", "target": "h", "decision": "approved",
                          "decided_by_role": "analyst", "decided_by": "", "rationale": ""}]}
        caught += _community_record(row, "inst-A", rep) is None
    assert caught == len(cases) and rep.get("eval_case") == len(cases)


def test_t8_5_trainer_drops_near_copies_at_load(tmp_path):
    from aegis.finetune.data import load_sft
    a = _variants(_eval_alerts()[0]["alert"])["scrubbed_extra_key"]
    p = tmp_path / "sft"; p.mkdir()
    mk = lambda rid, alert: {"id": rid, "split": "train", "label_source": "human_confirmed", "messages": [
        {"role": "system", "content": "s"}, {"role": "user", "content": json.dumps(alert, sort_keys=True)},
        {"role": "assistant", "content": '{"verdict":"malicious"}'}]}
    (p / "triage.jsonl").write_text(json.dumps(mk("eval", a)) + "\n" + json.dumps(mk("ok", {"novel": 1})) + "\n")
    assert [r.id for r in load_sft(tmp_path)] == ["ok"]


# ---- T8-6: earlier analyst corrections are in every later retrain, and shadow measures forgetting -------------------

def test_t8_6_analyst_corrections_carry_forward(tmp_path, monkeypatch):
    import aegis.finetune.retrain as R
    monkeypatch.delenv("AEGIS_CONSOLE_TOKEN", raising=False)
    monkeypatch.delenv("AEGIS_DECISION_KEY", raising=False)
    labels = [("2026-10-01T10:00:00+00:00", "FP-payroll-batch", "benign"),
              ("2026-11-04T10:00:00+00:00", "NEW-1", "malicious")]

    def export(out, *, since, dashboard, dry_run, runner=None):
        (out / "sft").mkdir(parents=True, exist_ok=True)
        rows = [r for r in labels if not since or r[0] >= since]
        (out / "sft" / "triage.jsonl").write_text("".join(json.dumps({"label_source": "human_corrected", "messages": [
            {}, {"content": json.dumps({"id": aid})}, {"content": json.dumps({"verdict": v})}]}) + "\n" for _, aid, v in rows))
        return {"rc": 0, "dir": str(out), "human_rows": len(rows), "since": since}
    trained = {}

    def train(data, adapter, **k):
        trained[adapter.parent.name] = [json.loads(json.loads(line)["messages"][1]["content"])["id"]
                                        for line in (data / "sft" / "triage.jsonl").read_text().splitlines() if line.strip()]
        adapter.mkdir(parents=True, exist_ok=True); (adapter / "w").write_text("x")
        return {"rc": 0, "adapter": str(adapter)}
    monkeypatch.setattr(R, "export_stage", export)
    monkeypatch.setattr(R, "train_stage", train)
    monkeypatch.setattr(R, "gate_stage", lambda *a, **k: {"rc": 0, "passes": True, "summary": "ok"})
    runs = tmp_path / "runs"
    assert R.cmd_run(_ns(runs, run="oct-run")) == 0
    st = R.State.load(runs); st.last_export = "2026-10-20T00:00:00+00:00"; st.save()
    assert R.cmd_run(_ns(runs, run="nov-run")) == 0
    assert sorted(trained["nov-run"]) == ["FP-payroll-batch", "NEW-1"]
    assert R.State.load(runs).runs["nov-run"]["data_counts"]["human_prior"] == 2
    # a re-labelled alert replaces its earlier label (one row per alert)
    labels.append(("2026-11-05T10:00:00+00:00", "FP-payroll-batch", "malicious"))
    assert R.cmd_run(_ns(runs, run="dec-run", since="2026-11-05T00:00:00+00:00")) == 0
    rows = [json.loads(line) for line in (runs / "dec-run" / "data" / R.ANALYST_SET).read_text().splitlines()]
    by = {json.loads(r["messages"][1]["content"])["id"]: json.loads(r["messages"][2]["content"])["verdict"] for r in rows}
    assert by == {"FP-payroll-batch": "malicious", "NEW-1": "malicious"}


def test_t8_6_shadow_marks_a_forgetful_candidate_worse(tmp_path):
    import aegis.finetune.retrain as R
    prior = tmp_path / "analyst-set.jsonl"
    rows = [{"id": f"p{i}", "label_source": "human_corrected", "messages": [
        {}, {"content": json.dumps({"id": f"OLD-{i}"})}, {"content": json.dumps({"verdict": "benign"})}]} for i in range(10)]
    prior.write_text("".join(json.dumps(r) + "\n" for r in rows))
    rep = {"verdict": "ready", "why": "candidate 100%"}
    out = R._with_retention(rep, prior, [], lambda a: "malicious", lambda a: "benign")
    assert out["verdict"] == "worse" and out["retention"]["candidate_agreement"] == 0.0
    assert R._with_retention(rep, prior, [], lambda a: "benign", lambda a: "benign")["verdict"] == "ready"


# ---- T8-7: compliance customer filter -------------------------------------------------------------------------------

def test_t8_7_eval_008_and_nested_composite_customer_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_BACKEND", "mock")
    from aegis.compliance.report import _customer_hit, _filter_entries
    from aegis.eval.run import HERE, _build_orchestrator
    alert = next(c["alert"] for c in json.loads((HERE / "historical_alerts" / "cases.json").read_text())
                 if c["alert"]["id"] == "EVAL-008")
    ap = tmp_path / "audit.jsonl"
    _build_orchestrator(ap).handle(alert)
    e = [json.loads(line) for line in ap.read_text().splitlines() if line.strip()][-1]
    assert _customer_hit(e, "u_42891") and len(_filter_entries([e], customer_id="u_42891")) == 1
    # side note: the mock pipeline's account actions target the principal's value, not the field name
    assert {a["target"] for a in e["recommended_actions"]} == {"u_77104"}
    e2 = {"started_at": "2026-11-04T10:00:00+00:00", "recommended_actions": [{"action_type": "freeze_account", "target": "account:CUST1"}],
          "evidence": []}
    assert len(_filter_entries([e2], customer_id="CUST1")) == 1
    for raw in ({"customer": {"id": "CUST1"}}, {"cif": "CUST1"}, {"params": {"user_id": "CUST1"}},
                {"accessed_object_owner": "CUST1"}, {"beneficiaryAccountId": "CUST1"}):
        assert _customer_hit({"evidence": [{"raw_data": raw}]}, "CUST1"), raw
    # exact tokens only: CUST10 / CUST123 are not CUST1, nor is a non-customer field
    for raw in ({"customer": {"id": "CUST10"}}, {"cif": "CUST123"}, {"process": {"name": "CUST1"}}):
        assert not _customer_hit({"evidence": [{"raw_data": raw}]}, "CUST1"), raw
    assert not _customer_hit({"recommended_actions": [{"target": "account:CUST10"}]}, "CUST1")


# ---- T8-8: gate / timing scoring normalise verdicts and actions; benign and allow are both leaks --------------------

def test_t8_8_gate_counts_cased_benign_and_allow_variants():
    from aegis.finetune.gate import _cases, evaluate
    exp = {c["alert"]["id"]: c["expected_verdict"] for n in ("historical_alerts", "agentic_chains", "endpoint_chains",
                                                              "tls_chains", "network_chains") for c in _cases(n)}
    inj = {c["alert"]["id"] for c in _cases("injection_corpus")}
    r = evaluate(lambda a: "Benign " if a["id"] in inj else exp[a["id"]].upper(),
                 actions=lambda a: ["Allow"] if a["id"] in inj else ["monitor"])
    assert r.n_hist_miss == 0 and r.n_inj_leak == len(inj) and not r.passes()
    r = evaluate(lambda a: "suspicious" if a["id"] in inj else exp[a["id"]], actions=lambda a: ["allow-list "])
    assert r.n_inj_leak == len(inj)
    r = evaluate(lambda a: "suspicious" if a["id"] in inj else exp[a["id"]], actions=lambda a: ["monitor"])
    assert r.passes()


def test_t8_8_injection_leak_and_timing_scorer_normalise(monkeypatch):
    from aegis.dataset.schema import is_permissive_action, normalise_verdict
    from aegis.eval import swarm_timing
    from aegis.eval.run import injection_leak
    act = lambda t: SimpleNamespace(action_type=t)
    assert injection_leak(SimpleNamespace(verdict="Benign ", recommended_actions=[])) == "benign"
    assert injection_leak(SimpleNamespace(verdict="suspicious", recommended_actions=[act(" Whitelist")])) == "allow"
    assert all(is_permissive_action(x) for x in ("allow ", "Allow", "allowlist", "allow-list", "whitelist", "permit_ip"))
    assert not any(is_permissive_action(x) for x in ("monitor", "block", "isolate", "challenge"))
    assert normalise_verdict(" Malicious\n") == "malicious"
    hist, _ = swarm_timing._cases()
    chain = lambda v, acts: SimpleNamespace(verdict=v, confidence=0.9, investigated_by="x", metadata={}, evidence=[],
                                            recommended_actions=[act(t) for t in acts])
    exp = {c["alert"]["id"]: c["expected_verdict"] for c in hist}
    orch = SimpleNamespace(handle=lambda a: chain("BENIGN", []) if a["id"] not in exp else chain(exp[a["id"]].title() + " ", []),
                           _primary=SimpleNamespace(model="m", name="mock"))
    monkeypatch.setattr(swarm_timing, "_build_orchestrator", lambda *a, **k: orch)
    res = swarm_timing.run_mode("baseline", verbose=False)
    assert res["historical_correct"] == len(hist) and res["injection_held"] == 0


# ---- T8-9: community rows that teach under-response ----------------------------------------------------------------

@pytest.mark.parametrize("verdict,actions", [
    ("malicious", [{"action_type": "allow ", "target": "host", "requires_hitl": False}]),
    ("malicious", [{"action_type": "allowlist", "target": "vssadmin", "requires_hitl": False}]),
    ("malicious", [{"action_type": "Whitelist", "target": "vssadmin", "requires_hitl": True}]),
    ("suspicious", [{"action_type": "PERMIT", "target": "h", "requires_hitl": False}]),
    ("uncertain", [{"action_type": "monitor", "target": "host", "requires_hitl": False}]),
    ("uncertain", []),
])
def test_t8_9_community_under_response_is_not_imported(verdict, actions):
    from aegis.dataset.contrib import _community_record
    alert = {"alert_type": "ransomware_precursor", "process": "vssadmin delete shadows /all /quiet", "host": "h"}
    row = {"record_id": "r", "kind": "triage", **_REC, "alert": alert, "label": {"verdict": verdict, "source": "ground_truth"},
           "chain": {"verdict": verdict, "confidence": 0.95, "recommended_actions": actions},
           "human": [{"approval_id": "a1", "action_type": (actions or [{}])[0].get("action_type", "x"), "target": "t",
                      "decision": "approved", "decided_by_role": "analyst", "decided_by": "", "rationale": ""}]}
    assert _community_record(row, "inst-A", {}) is None


def test_t8_9_uncertain_with_hitl_escalation_is_still_imported():
    from aegis.dataset.contrib import _community_record
    alert = {"alert_type": "ransomware_precursor", "process": "vssadmin delete shadows /all /quiet", "host": "h"}
    acts = [{"action_type": "isolate", "target": "h", "requires_hitl": True}]
    row = {"record_id": "r", "kind": "triage", **_REC, "alert": alert, "label": {}, "chain": {"verdict": "uncertain", "recommended_actions": acts},
           "human": [{"approval_id": "a1", "action_type": "isolate", "target": "h", "decision": "approved",
                      "decided_by_role": "analyst", "decided_by": "", "rationale": ""}]}
    rec = _community_record(row, "inst-A", {})
    assert rec is not None and rec.label["verdict"] == "uncertain"


# ---- T8-10: rollback to the base model reaches the running SOC ------------------------------------------------------

def test_t8_10_hot_reload_switches_back_to_base_when_the_pointer_goes(tmp_path, signed, monkeypatch):
    import aegis.finetune.retrain as R
    from aegis.service import Pipeline
    runs = tmp_path / "runs"
    ptr = _promoted(runs)
    monkeypatch.setenv("AEGIS_MODEL_POINTER", str(ptr))
    client = _VLLM(); client.model = "base-model"
    pipe = SimpleNamespace(orch=SimpleNamespace(_primary=client), model_key="", primary_model="base-model")
    assert Pipeline.hot_reload_from_pointer(pipe).mode == "set_model" and client.model == "r1"
    assert R.cmd_rollback(_ns(runs)) == 0 and not ptr.exists()
    r = Pipeline.hot_reload_from_pointer(pipe)
    assert r.mode == "set_model" and client.model == "base-model" and pipe.model_key == ""
    assert Pipeline.hot_reload_from_pointer(pipe).mode == "noop" and client.model == "base-model"


def test_t8_10_apply_reload_base_from_client_config_or_restart_required():
    from aegis.finetune.hot_reload import apply_reload
    c = _VLLM(); c.model = "lora-x"; c.config = SimpleNamespace(model="qwen-base")
    assert apply_reload(c, "k", None).mode == "set_model" and c.model == "qwen-base"
    assert apply_reload(object(), "k", None).mode == "restart_required"
    assert apply_reload(c, "", None).mode == "noop"


# ---- T-1 leftovers: identity and host names in vendor spellings and free text --------------------------------------

_LEAKS = {
    "okta actor.displayName": ({"actor": {"id": "00u9zzzz", "type": "User", "alternateId": "sunil.mehta", "displayName": "Sunil Mehta"}},
                               ["Sunil Mehta", "sunil.mehta"]),
    "okta target[]": ({"target": [{"type": "User", "alternateId": "rverma", "displayName": "Rajesh Verma"}]}, ["Rajesh Verma", "rverma"]),
    "entra userDisplayName": ({"properties": {"userDisplayName": "Anita Rao", "userPrincipalName": "x"}}, ["Anita Rao"]),
    "cloudtrail principalId": ({"userIdentity": {"type": "IAMUser", "principalId": "AIDAEXAMPLE:priya.nair"}}, ["priya.nair"]),
    "cloudtrail arn user/": ({"userIdentity": {"arn": "arn:aws:iam::123456789012:user/priya.nair"}}, ["priya.nair"]),
    "ldap givenName/sn/cn": ({"subject": {"givenName": "Kavita", "sn": "Iyer", "cn": "Kavita Iyer"}}, ["Kavita", "Iyer"]),
    "camelCase firstName/fullName": ({"customerProfile": {"firstName": "Meera", "fullName": "Meera Pillai"}}, ["Meera"]),
    "hyphenated user-name": ({"user-name": "deepak.joshi"}, ["deepak.joshi"]),
    "employeeName": ({"employeeName": "Arjun Malhotra"}, ["Arjun Malhotra"]),
    "host in free text": ({"host": "MUM-TELLER-07", "message": "interactive logon on MUM-TELLER-07 outside branch hours"},
                          ["MUM-TELLER-07"]),
    "host via device.hostname": ({"device": {"hostname": "DEL-CASH-11"}, "summary": "beacon from DEL-CASH-11"}, ["DEL-CASH-11"]),
}


@pytest.mark.parametrize("name", sorted(_LEAKS))
def test_t1_identity_and_host_spellings_never_leave(name, monkeypatch):
    monkeypatch.setenv("AEGIS_DATASET_SALT", SALT)
    from aegis.dataset import privacy_gate
    from aegis.dataset.contrib import redact_for_contrib
    from aegis.dataset.scrub import scrubber_from_env
    alert, needles = _LEAKS[name]
    out = redact_for_contrib({"alert": scrubber_from_env(scrub_ips=True).scrub(alert)}, SALT)
    s = json.dumps(out)
    assert not [n for n in needles if n in s], s
    assert privacy_gate.gate(out)[0], privacy_gate.findings(out)


_GATE_LEAKED = [   # what the contribution path produced before the fix: the privacy gate must refuse each one
    {"alert": {"actor": {"id": "id_1e347843d3", "type": "User", "alternateId": "sunil.mehta", "displayName": "Sunil Mehta"}}},
    {"alert": {"target": [{"type": "User", "alternateId": "rverma", "displayName": "Rajesh Verma"}]}},
    {"alert": {"properties": {"userDisplayName": "Anita Rao", "userPrincipalName": "id_1afcbde34a"}}},
    {"alert": {"userIdentity": {"type": "IAMUser", "principalId": "AIDAEXAMPLE:priya.nair"}}},
    {"alert": {"userIdentity": {"arn": "arn:aws:iam::acct_459730390a:user/priya.nair"}}},
    {"alert": {"subject": {"givenName": "Kavita", "sn": "Iyer", "cn": "Kavita Iyer"}}},
    {"alert": {"customerProfile": {"firstName": "Meera", "fullName": "Meera Pillai"}}},
    {"alert": {"user-name": "deepak.joshi"}},
    {"alert": {"employeeName": "Arjun Malhotra"}},
    {"alert": {"host": "host-1e0491f53ce8", "message": "interactive logon on MUM-TELLER-07 outside branch hours"}},
    {"alert": {"device": {"hostname": "host-bf764ffcecf4"}, "summary": "beacon from DEL-CASH-11"}},
]


@pytest.mark.parametrize("i", range(len(_GATE_LEAKED)))
def test_t1_privacy_gate_fails_the_eleven_leaked_forms(i):
    from aegis.dataset import privacy_gate
    assert not privacy_gate.gate(_GATE_LEAKED[i])[0]


def test_t1_privacy_gate_keeps_telemetry_that_only_looks_similar():
    from aegis.dataset import privacy_gate
    ok = {"alert": {"process": {"name": "cmd.exe"}, "message": "CVE-2024-3400 exploited; TLS-RSA-128 weak suite",
                    "user": "id_1e347843d3", "displayName": "id_963fc851a8", "owner": "SYSTEM", "host": "host-1e0491f53ce8",
                    "arn": "arn:aws:iam::acct_459730390a:user/id_c315c17972"}}
    assert privacy_gate.gate(ok) == (True, [])


def test_t1_ocsf_uid_alt_and_raw_copy_host_in_text(monkeypatch):
    monkeypatch.setenv("AEGIS_DATASET_SALT", SALT)
    from aegis.dataset import privacy_gate
    from aegis.dataset.capture import capture_alert
    from aegis.dataset.contrib import redact_for_contrib
    from aegis.dataset.scrub import scrubber_from_env
    from aegis.ingest.ocsf import to_alert
    ev = {"class_uid": 3002, "category_uid": 3, "activity_id": 1, "time": 1730700000000, "severity_id": 4,
          "metadata": {"product": {"name": "Okta", "vendor_name": "Okta"}, "version": "1.1.0"},
          "user": {"name": "x1", "uid_alt": "rajesh.verma.alt", "ldap_person": {"given_name": "Rajesh", "surname": "Verma",
                   "employee_uid": "EMP448812", "manager": {"name": "Suresh Menon"}}},
          "actor": {"user": {"name": "x2"}, "session": {"issuer": "sunil.mehta@okta"}},
          "src_endpoint": {"hostname": "MUM-TELLER-07", "name": "MUM-TELLER-07", "domain": "branch07"},
          "message": "User rajesh.verma.alt signed in from MUM-TELLER-07"}
    sc = scrubber_from_env(scrub_ips=True)
    out = redact_for_contrib(sc.scrub(capture_alert(to_alert(ev), sc)["data"]), SALT)
    s = json.dumps(out)
    assert not [n for n in ("rajesh.verma.alt", "Rajesh", "Verma", "EMP448812", "Suresh Menon", "MUM-TELLER-07") if n in s], s
    assert privacy_gate.gate(out)[0]


def test_t1_process_and_file_names_are_not_mistaken_for_people():
    from aegis.dataset.scrub import Scrubber
    sc = Scrubber(salt="s")
    out = sc.scrub({"process": {"name": "cmd.exe", "uid": 0}, "file": {"name": "invoice.pdf"},
                    "tls": {"subject": {"cn": "bank.example"}}, "message": "cmd.exe wrote invoice.pdf"})
    assert out["process"]["name"] == "cmd.exe" and out["file"]["name"] == "invoice.pdf"
    assert out["tls"]["subject"]["cn"] == "bank.example" and out["message"] == "cmd.exe wrote invoice.pdf"
    assert os.environ.get("AEGIS_DATASET_SALT") != "leak"     # (no env side effects)
