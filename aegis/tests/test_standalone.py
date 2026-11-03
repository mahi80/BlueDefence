"""Standalone BlueDefence: its own console + this host's API, no ACP dashboard.

The console's approve route reaches the host's ConsoleAPI, which appends to decisions.jsonl — the queue the
file transport executes from. These tests run that whole loop without any dashboard."""

from __future__ import annotations

import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import yaml

from aegis.edition import apply_edition, current
from aegis.finetune import retrain as rt
from aegis.hitl import FileHITL
from aegis.ingest.console_api import ConsoleAPI
from aegis.posture import runner

S = Path(__file__).resolve().parents[1] / "exposure" / "samples"
T0 = datetime(2026, 11, 2, 9, 0, tzinfo=UTC)


def test_standalone_is_the_default_edition():
    env: dict[str, str] = {}
    ed = apply_edition(env)
    assert ed.name == "external" and env["AEGIS_HITL_TRANSPORT"] == "file" and env["ACP_GOVERN"] == "0"
    assert current({"ACP_DASHBOARD_URL": "https://dash"}).name == "full"     # integrated installs unchanged


def test_exposure_proposal_approved_in_the_console_with_no_dashboard(tmp_path):
    ws = tmp_path / "s"
    shutil.copytree(S, ws)
    cfg_raw = yaml.safe_load((ws / "posture_exposure.yaml").read_text())
    cfg_raw["store"] = str(tmp_path / "store")
    (ws / "posture_exposure.yaml").write_text(yaml.safe_dump(cfg_raw))
    cfg = runner.load_config(ws / "posture_exposure.yaml")
    hitl_dir = tmp_path / "hitl"

    r1 = runner.run_once(cfg, now=T0, hitl=FileHITL(hitl_dir))
    prop = next(p for p in r1["remediation"]["proposals"] if p["component"] == "ops-bastion:22")
    assert prop["transport"] == "file"

    api = ConsoleAPI(None, hitl_dir)                       # what the console reads and writes through
    card = next(a for a in api.approvals()["approvals"] if a["id"] == prop["approval_id"])
    assert card["status"] == "pending"
    code, body = api.decide(prop["approval_id"], "approved", decided_by="ciso:asha", reason="close SSH today")
    assert code == 200 and body["ok"]

    r2 = runner.run_once(cfg, now=T0 + timedelta(hours=1), hitl=FileHITL(hitl_dir))
    after = next(p for p in r2["remediation"]["proposals"] if p["component"] == "ops-bastion:22")
    assert after["status"] == "approved" and after["decided_by"] == "ciso:asha"


def test_model_promotion_round_trip_through_the_local_queue(tmp_path):
    runs = tmp_path / "runs"
    st = rt.State(runs / "retrain" / "state.json")
    from aegis.finetune.digest import adapter_digest
    (tmp_path / "ad").mkdir()
    (tmp_path / "ad" / "adapter_model.safetensors").write_bytes(b"w" * 64)
    st.runs["r1"] = {"stage": "shadowed", "adapter": str(tmp_path / "ad"), "sha256": adapter_digest(tmp_path / "ad"),
                     "stages": {"gated": {"summary": "ok"}, "shadowed": {"verdict": "ready", "n": 40, "why": "better"}}}
    st.runs["r0-failed"] = {"stage": "trained", "adapter": "bad", "stages": {"gated": {"summary": "FAIL"}}}
    st.save()
    hitl_dir = tmp_path / "hitl"
    a = SimpleNamespace(runs=str(runs), run="r1", dashboard=False, dry_run=False, hitl_dir=str(hitl_dir))
    assert rt.cmd_propose(a) == 0
    api = ConsoleAPI(None, hitl_dir)
    (row,) = api.proposals()["proposals"]
    assert row["id"] == "model-promotion:r1" and row["status"] == "pending_hitl"
    rt.cmd_sync(a)
    assert rt.State.load(runs).current is None                      # nothing until a human accepts
    assert api.decide_proposal(row["id"], "accept", decided_by="ciso:asha", rationale="shadow ready")[0] == 200
    rt.cmd_sync(a)
    cur = rt.State.load(runs).current
    assert cur["run"] == "r1" and cur["approved_by"] == "ciso:asha"


def test_sync_refuses_a_run_that_did_not_pass_its_gate(tmp_path, capsys):
    runs = tmp_path / "runs"
    st = rt.State(runs / "retrain" / "state.json")
    st.runs["bad"] = {"stage": "trained", "adapter": "x", "stages": {"gated": {"summary": "FAIL"}}}
    st.runs["moved"] = {"stage": "shadowed", "adapter": "y", "sha256": "new", "stages": {}}
    st.save()
    a = SimpleNamespace(runs=str(runs), run=None, dashboard=False, dry_run=False, hitl_dir=str(tmp_path / "h"))
    rt.cmd_sync(a, accepted=lambda d: [{"change_type": "model_promotion", "change": {"run": "bad"}},
                                       {"change_type": "model_promotion", "change": {"run": "moved", "sha256": "old"}}])
    assert rt.State.load(runs).current is None
    out = capsys.readouterr().out
    assert "refused bad" in out and "refused moved" in out
