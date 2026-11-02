"""The VAPT loop: every scan on a schedule, findings tracked over time, SLA, waivers, report."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from aegis.posture import runner, sources
from aegis.posture.__main__ import main as cli

SAMPLES = Path(__file__).resolve().parents[1] / "posture" / "samples"
T0 = datetime(2026, 11, 2, 9, 0, tzinfo=UTC)


@pytest.fixture
def ws(tmp_path):
    """A copy of the samples plus a posture.yaml whose store is inside tmp_path."""
    d = tmp_path / "samples"
    shutil.copytree(SAMPLES, d)
    cfg = yaml.safe_load((d / "posture.yaml").read_text())
    cfg["store"] = str(tmp_path / "store")
    (d / "posture.yaml").write_text(yaml.safe_dump(cfg))
    return d


def load(ws, **edit):
    cfg = runner.load_config(ws / "posture.yaml")
    for k, v in edit.items():
        setattr(cfg, k, v)
    return cfg


def by_scan(rec, scan):
    return [o for o in rec["open"] if o["scan"] == scan]


def test_first_run_everything_new(ws):
    r = runner.run_once(load(ws), now=T0)
    assert [s["status"] for s in r["scans"]] == ["ok"] * 4
    assert r["counts"]["open"] == 86 and r["counts"]["new"] == 86 and r["counts"]["resolved"] == 0
    assert r["counts"]["waived"] == 1 and r["waived"][0]["waiver"]["approved_by"] == "ciso"
    assert r["open"][0]["severity"] == "critical"
    store = Path(load(ws).store)
    assert (store / "latest.json").exists() and (store / "state.json").exists()
    assert (store / "runs" / f"{r['run_id']}.md").read_text().startswith("# Posture assessment")


def test_second_run_still_open_keeps_first_seen_and_ages(ws):
    cfg = load(ws)
    runner.run_once(cfg, now=T0)
    r = runner.run_once(cfg, now=T0 + timedelta(days=3))
    assert r["counts"]["new"] == 0 and r["counts"]["open"] == 86
    assert all(o["first_seen"].startswith("2026-11-02") and o["age_days"] == 3 for o in r["open"])


def test_sla_breach(ws):
    cfg = load(ws)
    runner.run_once(cfg, now=T0)
    r = runner.run_once(cfg, now=T0 + timedelta(days=8))  # critical SLA 7d, high 30d
    over = {o["severity"] for o in r["open"] if o["overdue"]}
    assert over == {"critical"} and r["counts"]["overdue"] == r["summary"]["critical"]
    assert r["open"][0]["overdue"]  # overdue criticals lead the list
    r = runner.run_once(cfg, now=T0 + timedelta(days=31))
    assert {o["severity"] for o in r["open"] if o["overdue"]} == {"critical", "high"}


def test_fixed_finding_resolves_and_returns_as_new(ws):
    cfg = load(ws)
    runner.run_once(cfg, now=T0)
    bundle = json.loads((ws / "aws_cspm_bundle.json").read_text())
    full = json.loads(json.dumps(bundle))
    bundle["db_instances"] = [d for d in bundle["db_instances"] if d["DBInstanceIdentifier"] != "core-ledger"]
    (ws / "aws_cspm_bundle.json").write_text(json.dumps(bundle))
    r = runner.run_once(cfg, now=T0 + timedelta(days=1))
    assert sorted(x["id"] for x in r["resolved"]) == ["CSPM-RDS-NO-BACKUPS", "CSPM-RDS-NO-DELETION-PROTECTION",
                                                       "CSPM-RDS-PUBLIC", "CSPM-RDS-UNENCRYPTED"]
    (ws / "aws_cspm_bundle.json").write_text(json.dumps(full))
    r = runner.run_once(cfg, now=T0 + timedelta(days=20))
    back = [o for o in r["open"] if o["id"] == "CSPM-RDS-PUBLIC" and o["scan"] == "aws-prod-ap-south-1"]
    assert back[0]["new"] and back[0]["age_days"] == 0  # regression is new, with a fresh SLA


def test_failed_scan_is_stale_not_resolved(ws):
    cfg = load(ws)
    first = runner.run_once(cfg, now=T0)
    (ws / "k8s_cluster_export.json").unlink()
    r = runner.run_once(cfg, now=T0 + timedelta(days=1))
    k8s = next(s for s in r["scans"] if s["name"] == "eks-payments")
    assert k8s["status"] == "error" and "not found" in k8s["error"]
    assert r["counts"]["resolved"] == 0 and r["counts"]["scans_failed"] == 1
    stale = by_scan(r, "eks-payments")
    assert len(stale) == len(by_scan(first, "eks-payments")) and all(o["stale"] for o in stale)
    assert "stale: this scan failed" in (Path(cfg.store) / "runs" / f"{r['run_id']}.md").read_text()


def test_unreadable_waiver_register_fails_safe(ws):
    (ws / "iac" / "waivers.yaml").write_text("waivers:\n  - {id: X}\n")  # invalid entry
    r = runner.run_once(load(ws), now=T0)
    assert r["counts"]["waived"] == 0 and r["counts"]["open"] == 87  # the bastion finding is visible again
    assert any("WAIVER REGISTER NOT APPLIED" in n for n in r["notes"])


def test_expired_waiver_keeps_true_first_seen(ws):
    cfg = load(ws)
    runner.run_once(cfg, now=T0)  # bastion waived (expires 2026-12-31)
    r = runner.run_once(cfg, now=datetime(2027, 1, 2, tzinfo=UTC))
    bastion = [o for o in r["open"] if o["id"] == "CSPM-SG-ADMIN-PORT-OPEN" and o["scan"] == "infra-repo-main"]
    assert bastion and bastion[0]["first_seen"].startswith("2026-11-02") and bastion[0]["overdue"]  # high, 61 days
    assert any("expired" in n for n in r["notes"])


def test_run_ids_never_collide_and_old_runs_are_pruned(ws):
    cfg = load(ws, keep_runs=2)
    ids = [runner.run_once(cfg, now=T0)["run_id"] for _ in range(3)]
    assert len(set(ids)) == 3
    assert sorted(p.stem for p in (Path(cfg.store) / "runs").glob("*.json")) == sorted(ids)[-2:]


@pytest.mark.parametrize("body,msg", [
    ("scans: []", "no scans"),
    ("scans: [{name: a, type: nope}]", "type"),
    ("scans: [{name: a, type: iam, auth_details: x}, {name: a, type: iam, auth_details: y}]", "duplicate"),
])
def test_bad_config(tmp_path, body, msg):
    p = tmp_path / "p.yaml"
    p.write_text(body)
    with pytest.raises(sources.PostureSourceError, match=msg):
        runner.load_config(p)


def test_paths_resolve_relative_to_config_and_sla_override(ws):
    cfg = runner.load_config(ws / "posture.yaml")
    assert cfg.scans[0].opts["auth_details"] == ws / "aws_iam_auth_details.json"
    assert cfg.waivers == ws / "iac" / "waivers.yaml"
    (ws / "posture.yaml").write_text((ws / "posture.yaml").read_text().replace("critical: 7", "critical: 1"))
    assert runner.load_config(ws / "posture.yaml").sla_days["critical"] == 1


def test_live_scan_in_config_respects_the_flag(ws, monkeypatch):
    monkeypatch.delenv("AEGIS_POSTURE_LIVE", raising=False)
    cfg = load(ws)
    cfg.scans[1].opts = {"live": True, "region": "ap-south-1"}
    r = runner.run_once(cfg, now=T0)
    s = r["scans"][1]
    assert s["status"] == "error" and "AEGIS_POSTURE_LIVE" in s["error"] and s["live"]


def test_cli_run(ws, capsys):
    assert cli(["run", "--config", str(ws / "posture.yaml")]) == 0
    out = capsys.readouterr().out
    assert "86 open" in out and "report:" in out
    assert cli(["run", "--config", str(ws / "posture.yaml"), "--fail-on", "critical"]) == 1
    assert cli(["run", "--config", str(ws / "posture.yaml"), "--fail-on-overdue"]) == 0
    assert cli(["run", "--config", str(ws / "missing.yaml")]) == 2


def test_loop_stops(ws):
    import threading
    stop = threading.Event()
    stop.set()
    runner.loop(load(ws), stop=stop)  # one run, then the stop event ends it
    assert (Path(load(ws).store) / "latest.json").exists()
