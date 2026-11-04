"""Round 7 learning-loop fixes: T-1 … T-9 (dataset / finetune / compliance / eval) and R-1, R-8, R-9 (pointer trust,
signed release pointers, rollback into vLLM)."""

from __future__ import annotations

import argparse
import gzip
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

SALT = "s3cret-salt-xyz-0123456789abcdef"


# ---- T-1: OCSF / ECS identities and host names never leave in a contribution --------------------------------------

def test_t1_ocsf_actor_user_and_device_hostname_are_scrubbed(monkeypatch):
    monkeypatch.setenv("AEGIS_DATASET_SALT", SALT)
    from aegis.dataset import privacy_gate
    from aegis.dataset.capture import capture_alert
    from aegis.dataset.contrib import redact_for_contrib
    from aegis.dataset.scrub import scrubber_from_env
    from aegis.ingest.ocsf import to_alert
    ev = {"class_uid": 3001, "category_uid": 3, "activity_id": 4, "time": 1730700000000, "severity_id": 4,
          "metadata": {"product": {"name": "Okta", "vendor_name": "Okta"}, "version": "1.1.0"},
          "user": {"name": "rajesh.verma", "uid": "00u1abcd", "full_name": "Rajesh Kumar Verma"},
          "actor": {"user": {"name": "sunil.mehta", "uid": "00u9zzzz", "full_name": "Sunil Mehta"}},
          "device": {"hostname": "MUM-TELLER-07"}}
    sc = scrubber_from_env(scrub_ips=True)
    out = redact_for_contrib(sc.scrub(capture_alert(to_alert(ev), sc)["data"]), SALT)
    s = json.dumps(out)
    for needle in ("sunil.mehta", "Sunil Mehta", "Rajesh Kumar Verma", "00u9zzzz", "MUM-TELLER-07", "rajesh.verma"):
        assert needle not in s, needle
    assert privacy_gate.gate(out)[0]


def test_t1_identity_keys_by_path_and_dotted_suffix():
    from aegis.dataset.scrub import Scrubber
    sc = Scrubber(salt=SALT)
    out = sc.scrub({"target_user": {"name": "anita.rao", "email_addr": "anita@corp.example"},
                    "user.full_name": "Anita Rao", "owner": {"display_name": "Anita Rao"},
                    "process": {"name": "powershell.exe"}})
    s = json.dumps(out)
    assert "anita.rao" not in s and "Anita Rao" not in s
    assert out["process"]["name"] == "powershell.exe"          # a leaf under a non-identity parent is telemetry


def test_t1_host_keys_tokenised_and_evidence_raw_kept_for_the_gate():
    from aegis.dataset.contrib import redact_for_contrib
    out = redact_for_contrib({"alert": {"host": {"name": "MUM-TELLER-07"}, "raw": {"secret": "x"}, "ocsf": {"a": 1}},
                              "chain": {"evidence": [{"raw": {"note": "n"}}]}}, SALT)
    assert out["alert"]["host"]["name"].startswith("host-")
    assert "raw" not in out["alert"] and "ocsf" not in out["alert"]
    assert out["chain"]["evidence"][0]["raw"] == {"note": "n"}  # evidence summary stays; the privacy gate checks it


# ---- T-4: community benign / allow labels never become analyst-confirmed training rows ----------------------------

def _bundle(td: Path, inst: str, verdict: str, action: str, *, received: str | None = None) -> None:
    from aegis.dataset.contrib import BUNDLE_SCHEMA
    rows = []
    for i in range(3):
        alert = {"alert_type": "impossible_travel", "src_country": "RU", "minutes_between": 4 + i, "mfa": "bypassed"}
        rows.append({"record_id": f"{inst}{i}", "kind": "triage", "origin": "x", "split": "train", "fingerprint": "f",
                     "alert": alert, "label": {"verdict": verdict, "source": "ground_truth"},
                     "chain": {"verdict": verdict, "confidence": 0.95, "evidence": [], "reasoning": [],
                               "recommended_actions": [{"action_type": action, "target": "session", "requires_hitl": True}]},
                     "rationale": "", "techniques": [],
                     "human": [{"approval_id": f"a{inst}{i}", "action_type": action, "target": "session",
                                "decision": "approved", "decided_by_role": "analyst", "rationale": "", "decided_by": ""}]})
    b = {"schema": BUNDLE_SCHEMA, "installation_id": inst, "records": rows}
    if received:
        b["_received_installation"] = received
    (td / f"{inst}.json.gz").write_bytes(gzip.compress(json.dumps(b).encode()))


def test_t4_community_benign_and_allow_are_not_imported(tmp_path):
    from aegis.dataset.contrib import records_from_bundles
    for inst in ("inst-0", "inst-1", "inst-2"):
        _bundle(tmp_path, inst, "benign", "allow")
    recs, rep = records_from_bundles(tmp_path)
    assert recs == []
    assert rep.get("community_benign", 0) + rep.get("benign_on_attack", 0) == 9


def test_t4_cap_uses_the_received_installation_not_the_bundle_claim(tmp_path, monkeypatch):
    from aegis.dataset.contrib import records_from_bundles
    monkeypatch.setenv("AEGIS_CONTRIB_MAX_PER_INSTALL", "2")
    for inst in ("rot-0", "rot-1", "rot-2"):          # one uploader rotating its claimed id
        _bundle(tmp_path, inst, "malicious", "block_ip", received="lic-123")
    recs, rep = records_from_bundles(tmp_path)
    assert len(recs) <= 2 and set(rep["by_installation"]) == {"lic-123"}


# ---- T-6: the scrubber's token map is bounded ----------------------------------------------------------------------

def test_t6_token_map_is_lru_bounded_and_distinct_count_survives(monkeypatch):
    from aegis.dataset import scrub
    monkeypatch.setattr(scrub, "_MAX_TOKEN_CACHE", 50)
    sc = scrub.Scrubber(salt=SALT)
    toks = [sc.token("user", f"u{i}") for i in range(200)]
    assert len(sc._map) <= 50 and sc.distinct_identities == 200
    assert sc.token("user", "u0") == toks[0]          # an evicted value re-derives the same token (salted hash)


# ---- T-2: run names are unique; an existing run / non-empty --out is refused --------------------------------------

def _ns(td, **kw):
    base = {"role": "triage", "runs": str(td), "run": None, "preset": "p", "base_data": None, "since": None,
            "dashboard": False, "dry_run": False, "min_new_rows": 1, "epochs": 1, "max_rows": 0, "hitl_dir": None,
            "approved_by": "ciso", "rationale": "ok"}
    base.update(kw)
    return argparse.Namespace(**base)


@pytest.fixture
def fake_retrain(monkeypatch):
    import aegis.finetune.retrain as R
    monkeypatch.setattr(R, "export_stage", lambda out, **k: {"rc": 0, "dir": str(out), "human_rows": 100, "since": k.get("since")})
    monkeypatch.setattr(R, "build_stage", lambda *a, **k: {"dir": "x", "base": 0, "human": 100, "human_oversampled": 100})

    def train(data, adapter, **k):
        adapter.mkdir(parents=True, exist_ok=True)
        (adapter / "adapter_model.safetensors").write_bytes(b"w")
        return {"rc": 0, "adapter": str(adapter)}
    monkeypatch.setattr(R, "train_stage", train)
    monkeypatch.setattr(R, "gate_stage", lambda *a, **k: {"rc": 0, "passes": True, "summary": "ok"})
    return R


def test_t2_two_runs_the_same_day_get_distinct_names(tmp_path, fake_retrain):
    R = fake_retrain
    assert R.cmd_run(_ns(tmp_path)) == 0
    assert R.cmd_run(_ns(tmp_path)) == 0
    st = R.State.load(tmp_path)
    assert len(st.runs) == 2 and all(r.startswith("retrain-triage-") for r in st.runs)


def test_t2_explicit_existing_run_is_refused(tmp_path, fake_retrain):
    R = fake_retrain
    assert R.cmd_run(_ns(tmp_path, run="r1")) == 0
    assert R.cmd_run(_ns(tmp_path, run="r1")) == 2


def test_t2_train_refuses_a_non_empty_out(tmp_path):
    from aegis.finetune.train import _out_conflict
    out = tmp_path / "adapter"; out.mkdir(); (out / "adapter_model.safetensors").write_bytes(b"approved")
    args = SimpleNamespace(out=str(out), dry_run=False, resume=None, overwrite=False)
    assert _out_conflict(args)
    assert _out_conflict(SimpleNamespace(**{**vars(args), "resume": "auto"})) is None
    assert _out_conflict(SimpleNamespace(**{**vars(args), "overwrite": True})) is None
    assert _out_conflict(SimpleNamespace(**{**vars(args), "out": str(tmp_path / "fresh")})) is None


# ---- T-5: watermark = export time, re-read window, one row per alert ----------------------------------------------

def test_t5_watermark_is_export_time_and_next_export_reads_a_trailing_window(tmp_path, monkeypatch, fake_retrain):
    R = fake_retrain
    now = ["2026-11-02T02:00:00+00:00"]
    monkeypatch.setattr(R, "_now", lambda: now[0])
    seen = []
    monkeypatch.setattr(R, "export_stage", lambda out, **k: seen.append(k.get("since")) or
                        {"rc": 0, "dir": str(out), "human_rows": 100, "since": k.get("since")})
    real_train = R.train_stage

    def slow_train(*a, **k):
        now[0] = "2026-11-02T09:30:00+00:00"           # hours of training
        return real_train(*a, **k)
    monkeypatch.setattr(R, "train_stage", slow_train)
    monkeypatch.setenv("AEGIS_RETRAIN_RELABEL_DAYS", "7")
    R.cmd_run(_ns(tmp_path, run="r1"))
    assert R.State.load(tmp_path).last_export == "2026-11-02T02:00:00+00:00"
    R.cmd_run(_ns(tmp_path, run="r2"))
    assert seen[-1].startswith("2026-10-26T02:00:00")


def test_t5_build_stage_keeps_one_row_per_alert(tmp_path):
    from aegis.finetune.retrain import build_stage
    exp = tmp_path / "export" / "sft"; exp.mkdir(parents=True)
    row = {"id": "a", "split": "train", "label_source": "human_confirmed",
           "messages": [{"role": "system", "content": "s"}, {"role": "user", "content": '{"id":"A1"}'},
                        {"role": "assistant", "content": "{}"}]}
    (exp / "triage.jsonl").write_text(json.dumps(row) + "\n" + json.dumps({**row, "id": "b"}) + "\n")
    res = build_stage(tmp_path / "data", None, tmp_path / "export", dry_run=False)
    assert res["human"] == 1


# ---- T-3 / R-1 / R-8 / R-9: one pointer verifier; signed release pointers; rollback loads into vLLM ---------------

class _VLLM:
    model = "base"

    def set_model(self, m):
        self.model = m


def _forged(tmp_path):
    from aegis.finetune.digest import adapter_digest
    evil = tmp_path / "evil"; evil.mkdir(); (evil / "adapter_config.json").write_text('{"evil":1}')
    p = tmp_path / "current.json"
    p.write_text(json.dumps({"run": "evil", "role": "triage", "adapter": str(evil), "sha256": adapter_digest(evil),
                             "approved_by": "x"}))
    return p


def test_t3_r1_forged_pointer_refused_by_startup_hot_reload_and_register(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_CONSOLE_TOKEN", "console-secret")
    monkeypatch.delenv("AEGIS_ALLOW_UNVERIFIED_MODEL", raising=False)
    from aegis.agents.shared import llm_client as lc
    from aegis.finetune import hot_reload as hr
    from aegis.finetune import vllm_registry as vr
    p = _forged(tmp_path)
    monkeypatch.setenv("AEGIS_MODEL_POINTER", str(p))
    assert lc._promoted_model() is None
    v = _VLLM()
    r = hr.apply_reload(v, "", hr.read_pointer(str(p)))
    assert r.mode == "refused" and v.model == "base"
    loaded = []
    reg = SimpleNamespace(load=lambda name, path: loaded.append(name) or (True, "loaded"))
    assert vr.register_promoted_adapter(reg, pointer_path=str(p)).action == "error" and loaded == []


def test_r8_release_pointer_is_signed_and_accepted_everywhere(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_CONSOLE_TOKEN", "console-secret")
    monkeypatch.setenv("AEGIS_MODEL_DIR", str(tmp_path))
    monkeypatch.delenv("AEGIS_ALLOW_UNVERIFIED_MODEL", raising=False)
    from aegis import model_updates as mu
    from aegis.agents.shared import llm_client as lc
    from aegis.finetune import hot_reload as hr
    ad = tmp_path / "2026.11.1"; ad.mkdir(); (ad / "adapter_config.json").write_text("{}")
    p = tmp_path / "current.json"
    ptr = mu.write_pointer({"version": "2026.11.1", "channel": "stable", "base_model": "q", "sha256": "ab" * 32,
                            "adapter": str(ad)}, pointer=p)
    assert ptr["sig"] and ptr["role"] == "triage" and "served_model" not in ptr
    monkeypatch.setenv("AEGIS_MODEL_POINTER", str(p))
    assert lc._promoted_model() == str(ad)
    assert hr.apply_reload(_VLLM(), "", hr.read_pointer(str(p))).mode == "set_model"


def test_r8_rolled_back_release_refused_by_the_verifier(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_CONSOLE_TOKEN", "console-secret")
    monkeypatch.setenv("AEGIS_MODEL_DIR", str(tmp_path))
    from aegis import model_updates as mu
    from aegis.finetune.pointer_trust import verify_pointer
    ad = tmp_path / "2026.11.1"; ad.mkdir(); (ad / "adapter_config.json").write_text("{}")
    ptr = mu.write_pointer({"version": "2026.11.1", "channel": "stable", "base_model": "q", "sha256": "0" * 64,
                            "adapter": str(ad)}, pointer=tmp_path / "current.json")
    assert verify_pointer(ptr)[0]
    (tmp_path / "denied.json").write_text('["2026.11.1"]')
    ok, why = verify_pointer(ptr)
    assert not ok and "rolled back" in why
    assert not verify_pointer(ptr, role_wanted="judge")[0]


def _release_dirs(tmp_path, versions=("2026.10.1", "2026.11.1")):
    """Release directories as an install leaves them: release.json + the signed manifest + .complete (round 8 T8-3
    re-verifies a rollback target against its manifest). Returns the public keys that verify them."""
    from aegis import license as L
    from aegis import model_updates as mu
    kd = tmp_path / "_keys"; kd.mkdir(exist_ok=True)
    _, priv = L.write_keypair(kd, "rel-kid", bits=1024)
    k = json.loads(priv.read_text())
    n, d_ = int(k["n"], 16), int(k["d"], 16)
    for v in versions:
        d = tmp_path / v; d.mkdir(); (d / "adapter_config.json").write_text(v)
        rel = {"version": v, "channel": "stable", "base_model": "q", "sha256": "0" * 64, "size": 1}
        (d / "release.json").write_text(json.dumps(rel))
        (d / mu.MANIFEST_FILE).write_text(mu.sign_manifest(rel, n=n, d=d_, kid="rel-kid"))
        (d / ".complete").write_text("1")
    return {"rel-kid": (n, 65537)}


def test_r9_rollback_loads_previous_into_vllm_and_register_does_not_skip(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_MODEL_DIR", str(tmp_path))
    monkeypatch.setenv("AEGIS_MODEL_POINTER", str(tmp_path / "current.json"))
    monkeypatch.setenv("LLM_BACKEND", "vllm")
    monkeypatch.delenv("AEGIS_CONSOLE_TOKEN", raising=False)
    monkeypatch.delenv("AEGIS_DECISION_KEY", raising=False)
    from aegis import model_updates as mu
    from aegis.finetune import vllm_registry as vr
    keys = _release_dirs(tmp_path)
    for v in ("2026.10.1", "2026.11.1"):     # each was current once, so the record holds its adapter digest
        mu.write_pointer({"version": v, "channel": "stable", "base_model": "q", "sha256": "0" * 64,
                          "adapter": str(tmp_path / v)}, pointer=tmp_path / "current.json",
                         previous="2026.10.1" if v == "2026.11.1" else "")
    loaded = []

    class Reg:
        def load(self, name, path):
            loaded.append(name)
            return True, "loaded"
    monkeypatch.setattr(vr, "VLLMAdapterRegistry", Reg)
    rb = mu.rollback(keys=keys)
    assert rb["ok"] and rb["loaded_into_vllm"] and loaded == ["2026.10.1"]
    cur = json.loads((tmp_path / "current.json").read_text())
    assert cur["run"] == "2026.10.1" and cur["served_model"] == "2026.10.1"


def test_r9_rollback_refused_by_vllm_keeps_the_current_pointer(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_MODEL_DIR", str(tmp_path))
    monkeypatch.setenv("AEGIS_MODEL_POINTER", str(tmp_path / "current.json"))
    monkeypatch.setenv("LLM_BACKEND", "vllm")
    from aegis import model_updates as mu
    from aegis.finetune import vllm_registry as vr
    keys = _release_dirs(tmp_path)
    for v in ("2026.10.1", "2026.11.1"):     # each was current once, so the record holds its adapter digest
        mu.write_pointer({"version": v, "channel": "stable", "base_model": "q", "sha256": "0" * 64,
                          "adapter": str(tmp_path / v)}, pointer=tmp_path / "current.json",
                         previous="2026.10.1" if v == "2026.11.1" else "")
    monkeypatch.setattr(vr, "VLLMAdapterRegistry", lambda: SimpleNamespace(load=lambda n, p: (False, "error")))
    assert not mu.rollback(keys=keys)["ok"]
    assert json.loads((tmp_path / "current.json").read_text())["run"] == "2026.11.1"
    assert not (tmp_path / "denied.json").exists()


# ---- T-7: compliance filters ----------------------------------------------------------------------------------------

def test_t7_until_is_end_of_day_customer_exact_undated_excluded():
    from aegis.compliance.report import _filter_entries, _parse_date
    E = [{"alert_id": "A1", "started_at": "2026-11-03T14:22:00+00:00", "verdict": "malicious",
          "recommended_actions": [{"action_type": "lock_account", "target": "CUST1"}]},
         {"alert_id": "A2", "started_at": "2026-11-02T10:00:00+00:00", "verdict": "benign",
          "recommended_actions": [{"action_type": "monitor", "target": "CUST10"}]},
         {"alert_id": "A3", "started_at": "2026-11-02T10:00:00+00:00", "verdict": "benign",
          "evidence": [{"raw_data": {"user_id": "CUST123"}}]},
         {"alert_id": "A4", "verdict": "benign"}]
    ids = lambda xs: [e["alert_id"] for e in xs]
    assert ids(_filter_entries(E, until=_parse_date("2026-11-03", end_of_day=True))) == ["A1", "A2", "A3"]
    assert ids(_filter_entries(E, customer_id="CUST1")) == ["A1"]
    assert ids(_filter_entries(E, customer_id="CUST123")) == ["A3"]
    assert "A4" in ids(_filter_entries(E)) and "A4" not in ids(_filter_entries(E, since=_parse_date("2026-01-01")))


# ---- T-8: load_sft drops held-out eval alerts and refuses an empty guard ------------------------------------------

def _sft(tmp_path, alert):
    p = tmp_path / "sft"; p.mkdir(exist_ok=True)
    row = {"id": "x", "split": "train", "label_source": "human_confirmed",
           "messages": [{"role": "system", "content": "s"}, {"role": "user", "content": json.dumps(alert, sort_keys=True)},
                        {"role": "assistant", "content": '{"verdict":"malicious"}'}]}
    ok = {**row, "id": "ok", "messages": [row["messages"][0], {"role": "user", "content": '{"novel": 1}'}, row["messages"][2]]}
    (p / "triage.jsonl").write_text(json.dumps(row) + "\n" + json.dumps(ok) + "\n")
    return tmp_path


def test_t8_eval_alert_is_dropped_at_load(tmp_path):
    from aegis.eval.run import HERE
    from aegis.finetune.data import load_sft
    case = json.loads((HERE / "historical_alerts" / "cases.json").read_text())[0]["alert"]
    rows = load_sft(_sft(tmp_path, case))
    assert [r.id for r in rows] == ["ok"]


def test_t8_empty_guard_refuses(tmp_path, monkeypatch):
    from aegis.finetune import data
    monkeypatch.setattr(data, "_eval_guard", lambda: set())
    with pytest.raises(data.DataError, match="guard is empty"):
        data.load_sft(_sft(tmp_path, {"a": 1}))
    assert len(data.load_sft(_sft(tmp_path, {"a": 1}), eval_guard=False)) == 2


# ---- T-9: a benign verdict on an injection case is a leak ---------------------------------------------------------

def test_t9_benign_on_injection_is_a_leak():
    from aegis.eval.run import injection_leak
    act = lambda t: SimpleNamespace(action_type=t)
    assert injection_leak(SimpleNamespace(verdict="benign", recommended_actions=[act("monitor")])) == "benign"
    assert injection_leak(SimpleNamespace(verdict=SimpleNamespace(value="benign"), recommended_actions=[])) == "benign"
    assert injection_leak(SimpleNamespace(verdict="suspicious", recommended_actions=[act("allow")])) == "allow"
    assert injection_leak(SimpleNamespace(verdict="suspicious", recommended_actions=[act("monitor")])) is None


def test_t9_observer_counts_benign_injection(monkeypatch):
    from aegis.meta_agent import observer
    orch = SimpleNamespace(handle=lambda alert: SimpleNamespace(verdict="benign", recommended_actions=[], confidence=0.9))
    fails = observer._run_injection(orch)
    assert fails and all(f.got == "benign" for f in fails)


# ---- #126 follow-up: `aegis.dataset contrib --push` finds the licence where the licence check does ----------------

def test_contrib_push_uses_the_licence_lookup(monkeypatch):
    from aegis import license as licensing
    from aegis.dataset import __main__ as dm
    from aegis.dataset import contrib
    seen = {}
    monkeypatch.setattr(licensing, "_read_token", lambda env: ("tok.from.varlib", ""))
    monkeypatch.setattr(licensing, "check", lambda *a, **k: SimpleNamespace(installation_id="bd-x", license=None))
    monkeypatch.setattr(contrib, "contribute", lambda **k: seen.update(k) or {"records": 0, "reason": "nothing new"})
    args = SimpleNamespace(push="https://lic.example", audit="a", hitl_dir=None, cursor="c", out=None, min_records=1)
    dm.cmd_contrib(args)
    assert seen["license_token"] == "tok.from.varlib"
