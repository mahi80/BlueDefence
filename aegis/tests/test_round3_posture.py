"""Round-3 review, group G6: posture, exposure and compliance never report a broken input as clean."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from aegis.posture import runner, sources

SAMPLES = Path(__file__).resolve().parents[1] / "posture" / "samples"
EXPOSURE = Path(__file__).resolve().parents[1] / "exposure" / "samples"
T0 = datetime(2026, 11, 2, 9, 0, tzinfo=UTC)


@pytest.fixture
def ws(tmp_path):
    d = tmp_path / "samples"
    shutil.copytree(SAMPLES, d)
    cfg = yaml.safe_load((d / "posture.yaml").read_text())
    cfg["store"] = str(tmp_path / "store")
    (d / "posture.yaml").write_text(yaml.safe_dump(cfg))
    return d


# ---- G6-1: an empty or wrong export is a failed scan, not "all resolved" --------------------------------------------

@pytest.mark.parametrize("file,content", [("aws_cspm_bundle.json", {}), ("aws_iam_auth_details.json", {"wrong": 1}),
                                          ("k8s_cluster_export.json", {"items": []})])
def test_empty_export_fails_the_scan_and_resolves_nothing(ws, file, content):
    cfg = runner.load_config(ws / "posture.yaml")
    first = runner.run_once(cfg, now=T0)
    (ws / file).write_text(json.dumps(content))
    second = runner.run_once(cfg, now=T0 + timedelta(days=1))
    assert second["counts"]["scans_failed"] == 1 and second["counts"]["resolved"] == 0
    assert second["counts"]["open"] == first["counts"]["open"] and second["counts"]["stale"] > 0


# ---- G6-4: a bad waiver date does not crash the run ------------------------------------------------------------------

def test_bad_waiver_date_is_a_note_not_a_crash(ws):
    cfg = runner.load_config(ws / "posture.yaml")
    wpath = cfg.waivers
    w = yaml.safe_load(wpath.read_text())
    w["waivers"][0]["expires"] = "2026-13-45"
    wpath.write_text(yaml.safe_dump(w))
    r = runner.run_once(cfg, now=T0)
    assert any("WAIVER REGISTER NOT APPLIED" in n for n in r["notes"]) and r["counts"]["waived"] == 0


# ---- G6-2 / G6-5: exposure ------------------------------------------------------------------------------------------

def test_empty_asset_model_fails_the_exposure_scan(tmp_path):
    from aegis.exposure.scan import run_scan
    inv = tmp_path / "inv.csv"
    inv.write_text((EXPOSURE / "inventory.csv").read_text().splitlines()[0] + "\n")     # header, no assets
    with pytest.raises(sources.PostureSourceError, match="asset model is empty|gave no assets"):
        run_scan({"vulns": [EXPOSURE / "tenable_vulns.json"], "inventory": inv})


def test_corrupt_proposal_ledger_is_refused(tmp_path):
    from aegis.exposure import remediation
    (tmp_path / "proposals.json").write_text("{half")
    with pytest.raises(sources.PostureSourceError, match="refusing to reset"):
        remediation.load(tmp_path)
    assert remediation.load(tmp_path / "nowhere") == {}


# ---- G6-3: the compliance report ------------------------------------------------------------------------------------

def test_compliance_report_refuses_a_missing_audit_log(tmp_path):
    r = subprocess.run([sys.executable, "-m", "aegis.compliance.report", "--audit", str(tmp_path / "nope.jsonl"),
                        "--out-json", str(tmp_path / "r.json"), "--out-md", str(tmp_path / "r.md")],
                       capture_output=True, text=True, check=False, cwd=Path(__file__).resolve().parents[2])
    assert r.returncode == 2 and not (tmp_path / "r.json").exists()


def test_compliance_report_checks_rotated_segments(tmp_path, monkeypatch):
    from aegis.agents.shared.audit import AuditLog
    from aegis.agents.shared.evidence_chain import EvidenceChain
    from aegis.compliance import report
    log = AuditLog(tmp_path / "audit.jsonl")
    for i in range(3):
        log.append(EvidenceChain(alert_id=f"A{i}", investigated_by="t", verdict="benign", confidence=0.9).finalize())
    seg = tmp_path / "audit.jsonl.20261101000000"           # what rotation leaves behind: the old segment
    (tmp_path / "audit.jsonl").rename(seg)
    AuditLog(tmp_path / "audit.jsonl").append(
        EvidenceChain(alert_id="A9", investigated_by="t", verdict="benign", confidence=0.9).finalize())
    assert AuditLog(tmp_path / "audit.jsonl", repair=False).verify_report(all_files=True)["ok"]
    rows = seg.read_text().splitlines()
    rows[1] = rows[1].replace('"benign"', '"malicious"')                 # rewrite history in the old segment
    seg.write_text("\n".join(rows) + "\n")
    monkeypatch.setattr(sys, "argv", ["report", "--audit", str(tmp_path / "audit.jsonl"),
                                      "--out-json", str(tmp_path / "r.json"), "--out-md", str(tmp_path / "r.md")])
    assert report.main() == 1
