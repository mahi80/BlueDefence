"""Roadmap 3.5 retrain pipeline — no GPU: stages are driven through injected runners."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from aegis.finetune import retrain as rt


def _row(i, src, verdict="malicious"):
    return json.dumps({"id": f"r{i}", "split": "train", "label_source": src, "origin": "dashboard",
                       "messages": [{"role": "system", "content": "s"},
                                    {"role": "user", "content": json.dumps({"id": f"a{i}", "source": "Okta", "k": i})},
                                    {"role": "assistant", "content": json.dumps({"verdict": verdict})}]})


def _export(d: Path, n_human=60, n_model=5, verdict="malicious"):
    (d / "sft").mkdir(parents=True, exist_ok=True)
    lines = [_row(i, "human_confirmed", verdict) for i in range(n_human)] + [_row(1000 + i, "model") for i in range(n_model)]
    (d / "sft" / "triage.jsonl").write_text("\n".join(lines) + "\n")


def _base(d: Path, n=3000):
    (d / "sft").mkdir(parents=True, exist_ok=True)
    (d / "sft" / "triage.jsonl").write_text("\n".join(_row(50000 + i, "public:sigma") for i in range(n)) + "\n")


def _fake_sh(calls, *, gate_pass=True, export_rows=60):
    def runner(cmd, *, dry_run, cwd=None):
        calls.append(cmd)
        if "aegis.dataset" in cmd:
            _export(Path(cmd[cmd.index("--out") + 1]), n_human=export_rows)
        elif "aegis.finetune.train" in cmd:
            out = Path(cmd[cmd.index("--out") + 1]); out.mkdir(parents=True, exist_ok=True)
            (out / "adapter_config.json").write_text('{"base_model_name_or_path": "x"}')
        elif "aegis.finetune.gate" in cmd:
            out = Path(cmd[cmd.index("--adapter") + 1])
            (out / "gate.json").write_text(json.dumps({"passes": gate_pass, "summary": "historical 34/37; injection 9/9; " + ("PASS" if gate_pass else "FAIL")}))
            return 0 if gate_pass else 1
        return 0
    return runner


def test_run_exports_builds_trains_gates_and_records_state(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(rt, "_sh", _fake_sh(calls))
    base = tmp_path / "public"; _base(base)
    rc = rt.main(["run", "--runs", str(tmp_path / "runs"), "--base-data", str(base), "--run", "r1", "--epochs", "1"])
    assert rc == 0
    st = rt.State.load(tmp_path / "runs")
    info = st.runs["r1"]
    assert info["stage"] == "gated" and info["stages"]["gated"]["passes"]
    assert info["data_counts"]["human"] == 60 and info["data_counts"]["human_oversampled"] == 180      # ×3 against a 3000-row base
    merged = (tmp_path / "runs" / "r1" / "data" / "sft" / "triage.jsonl").read_text().splitlines()
    assert len(merged) == 3000 + 180 and not any('"label_source": "model"' in l for l in merged)      # model-labelled rows never train
    assert st.last_export is not None
    assert [c[2] for c in calls] == ["aegis.dataset", "aegis.finetune.train", "aegis.finetune.gate"]
    assert "--allow-synthetic" in calls[1]                                                              # base set is public:* rows


def test_gate_fail_keeps_last_good_model(tmp_path, monkeypatch):
    monkeypatch.setattr(rt, "_sh", _fake_sh([], gate_pass=False))
    runs = tmp_path / "runs"
    st = rt.State(runs / "retrain" / "state.json"); st.current = {"run": "r0", "adapter": "/good"}; st.save()
    rc = rt.main(["run", "--runs", str(runs), "--run", "r1"])
    assert rc == 1
    st = rt.State.load(runs)
    assert st.runs["r1"]["stage"] == "failed" and "gate FAIL" in st.runs["r1"]["stages"]["failed"]["reason"]
    assert st.current["run"] == "r0" and st.last_export is None


def test_too_few_new_rows_skips(tmp_path, monkeypatch):
    monkeypatch.setattr(rt, "_sh", _fake_sh([], export_rows=5))
    rc = rt.main(["run", "--runs", str(tmp_path / "runs"), "--run", "r1"])
    assert rc == 0 and rt.State.load(tmp_path / "runs").runs["r1"]["stage"] == "skipped"


def test_shadow_compare_thresholds():
    rows = [{"id": f"r{i}", "alert": {"i": i}, "analyst_verdict": "malicious" if i % 2 else "benign"} for i in range(40)]
    good = lambda a: "malicious" if a["i"] % 2 else "benign"               # noqa: E731
    worse = lambda a: "malicious" if a["i"] % 2 or a["i"] % 10 == 0 else "benign"   # noqa: E731
    rep = rt.shadow_compare(rows, good, worse)
    assert rep["verdict"] == "ready" and rep["candidate_agreement"] == 1.0 and rep["current_agreement"] == 0.9
    rep = rt.shadow_compare(rows, worse, good)
    assert rep["verdict"] == "worse" and len(rep["disagreements"]) == 4
    assert rt.shadow_compare(rows[:10], good, good)["verdict"] == "not_yet"
    assert rt.shadow_compare(rows, good, None)["verdict"] == "ready"      # first model: nothing to trail
    err = lambda a: (_ for _ in ()).throw(RuntimeError("boom"))           # noqa: E731
    assert rt.shadow_compare(rows, err, None)["candidate_agreement"] == 0.0


def _adapter(d: Path, payload: bytes = b"w" * 64) -> tuple[str, str]:
    """A real adapter directory and its recorded digest."""
    from aegis.finetune.digest import adapter_digest
    d.mkdir(parents=True, exist_ok=True)
    (d / "adapter_config.json").write_text('{"r": 16}')
    (d / "adapter_model.safetensors").write_bytes(payload)
    return str(d), adapter_digest(d)


def test_shadow_propose_sync_promote_flow(tmp_path):
    runs = tmp_path / "runs"; st = rt.State(runs / "retrain" / "state.json")
    ad, sha = _adapter(tmp_path / "ad")
    st.runs["r1"] = {"stage": "gated", "adapter": ad, "sha256": sha, "data_counts": {"human": 60},
                     "stages": {"exported": {"ts": "2026-10-20T00:00:00+00:00"}, "gated": {"summary": "34/37 PASS", "passes": True}}}
    st.save()
    newer = tmp_path / "newer"; _export(newer, n_human=30, verdict="benign")
    good = lambda a: "benign"            # noqa: E731
    a = SimpleNamespace(runs=str(runs), run="r1", rows=str(newer), dashboard=False, dry_run=False)
    assert rt.cmd_shadow(a, candidate_loader=lambda p: good, current_loader=lambda p: good) == 0
    st = rt.State.load(runs)
    assert st.runs["r1"]["stage"] == "shadowed" and st.runs["r1"]["stages"]["shadowed"]["verdict"] == "ready"
    shipped = []
    assert rt.cmd_propose(a, ship=lambda p, d: shipped.append(p) or {"status": "created"}) == 0
    p = shipped[0]
    assert p["change_type"] == "model_promotion" and p["change"]["run"] == "r1" and "34/37" in p["rationale"]
    # nothing promoted until a human accepts it in the dashboard
    assert rt.State.load(runs).current is None
    rt.cmd_sync(a, accepted=lambda d: [])
    assert rt.State.load(runs).current is None
    rt.cmd_sync(a, accepted=lambda d: [{"change_type": "model_promotion", "change": {"run": "r1"}, "decided_by": "ciso@bank",
                                        "decision_rationale": "shadow ready", "proposal_id": "model-promotion:r1"}])
    st = rt.State.load(runs)
    assert st.current["run"] == "r1" and st.current["approved_by"] == "ciso@bank" and st.runs["r1"]["stage"] == "promoted"
    assert json.loads((runs / "retrain" / "current.json").read_text())["adapter"] == str(tmp_path / "ad")
    # idempotent: a second sync with the same accepted rule changes nothing
    rt.cmd_sync(a, accepted=lambda d: [{"change_type": "model_promotion", "change": {"run": "r1"}}])
    assert rt.State.load(runs).current["approved_by"] == "ciso@bank"


def test_propose_refuses_a_worse_candidate(tmp_path):
    runs = tmp_path / "runs"; st = rt.State(runs / "retrain" / "state.json")
    st.runs["r1"] = {"stage": "shadowed", "adapter": "x", "stages": {"shadowed": {"verdict": "worse"}}}; st.save()
    a = SimpleNamespace(runs=str(runs), run="r1", dashboard=False, dry_run=False)
    assert rt.cmd_propose(a, ship=lambda p, d: pytest.fail("must not ship")) == 1


def test_offline_promote_records_approver_and_previous(tmp_path):
    runs = tmp_path / "runs"; st = rt.State(runs / "retrain" / "state.json")
    st.current = {"run": "r0", "adapter": "/a0", "sha256": "0"}
    ad, sha = _adapter(tmp_path / "a1")
    st.runs["r1"] = {"stage": "shadowed", "adapter": ad, "sha256": sha}; st.runs["r2"] = {"stage": "trained", "adapter": "/a2"}
    st.save()
    assert rt.main(["promote", "--runs", str(runs), "--run", "r2", "--approved-by", "x", "--rationale", "y"]) == 1   # not gated
    assert rt.main(["promote", "--runs", str(runs), "--run", "r1", "--approved-by", "ciso", "--rationale", "ok"]) == 0
    cur = rt.State.load(runs).current
    assert cur["run"] == "r1" and cur["previous"]["run"] == "r0" and cur["approved_by"] == "ciso"
    assert rt.main(["status", "--runs", str(runs)]) == 0


def test_dry_run_touches_nothing_on_the_gpu(tmp_path, capsys):
    assert rt.main(["run", "--runs", str(tmp_path / "runs"), "--run", "r1", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "aegis.finetune.train" in out and "aegis.finetune.gate" in out
    assert not (tmp_path / "runs" / "r1" / "adapter").exists()


def test_model_pointer_resolves_promoted_adapter(tmp_path, monkeypatch):
    from aegis.agents.shared import llm_client as lc
    ad = tmp_path / "ad"; ad.mkdir()
    ptr = tmp_path / "current.json"; ptr.write_text(json.dumps({"run": "r1", "adapter": str(ad), "approved_by": "ciso"}))
    monkeypatch.setenv("AEGIS_MODEL_POINTER", str(ptr))
    assert lc._promoted_model() == str(ad)
    ptr.write_text(json.dumps({"run": "r1", "adapter": str(tmp_path / "gone")}))
    assert lc._promoted_model() is None                       # missing dir → fall back to AEGIS_MODEL
    ptr.write_text("not json")
    assert lc._promoted_model() is None
    monkeypatch.delenv("AEGIS_MODEL_POINTER")
    assert lc._promoted_model() is None


def test_tampered_adapter_is_never_promoted_or_loaded(tmp_path, monkeypatch):
    from aegis.agents.shared import llm_client as lc
    from aegis.finetune.hot_reload import apply_reload
    runs = tmp_path / "runs"; st = rt.State(runs / "retrain" / "state.json")
    payload = bytearray(b"\0" * (6 << 20))                       # 6 MiB: bigger than the old 4 MiB digest window
    ad, sha = _adapter(tmp_path / "ad", bytes(payload))
    st.runs["r1"] = {"stage": "shadowed", "adapter": ad, "sha256": sha}; st.save()
    payload[5 << 20] = 1                                          # one byte flipped past 4 MiB after approval
    (Path(ad) / "adapter_model.safetensors").write_bytes(bytes(payload))
    assert rt.main(["promote", "--runs", str(runs), "--run", "r1", "--approved-by", "ciso", "--rationale", "ok"]) == 1
    a = SimpleNamespace(runs=str(runs), run=None, dashboard=False, dry_run=False)
    rt.cmd_sync(a, accepted=lambda d: [{"change_type": "model_promotion", "change": {"run": "r1", "sha256": sha}}])
    assert rt.State.load(runs).current is None
    ptr = tmp_path / "current.json"; ptr.write_text(json.dumps({"run": "r1", "adapter": ad, "sha256": sha}))
    monkeypatch.setenv("AEGIS_MODEL_POINTER", str(ptr))
    assert lc._promoted_model() is None                           # falls back to AEGIS_MODEL
    swapped = []
    primary = SimpleNamespace(set_model=swapped.append)
    res = apply_reload(primary, "", {"run": "r1", "adapter": ad, "sha256": sha})
    assert res.mode == "refused" and not res.changed and swapped == []


def test_legacy_digest_still_verifies(tmp_path):
    import hashlib

    from aegis.finetune.digest import verify_adapter
    ad, _ = _adapter(tmp_path / "ad")
    h = hashlib.sha256()
    for f in sorted(Path(ad).rglob("*")):
        h.update(f.name.encode()); h.update(f.read_bytes()[: 4 << 20])
    assert verify_adapter(ad, h.hexdigest()[:16]) == (True, "")
    assert not verify_adapter(ad, "deadbeefdeadbeef")[0]
