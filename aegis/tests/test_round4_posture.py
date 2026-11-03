"""Round-4 review, group H6: posture, exposure and the audit CLI never report a partial input as clean."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aegis.posture import sources
from aegis.posture.runner import RunnerConfig, ScanConfig, run_once

SAMPLES = Path(__file__).resolve().parents[1] / "posture" / "samples"
EXPOSURE = Path(__file__).resolve().parents[1] / "exposure" / "samples"
T0 = datetime(2026, 11, 1, tzinfo=UTC)


def _by(r):
    return {s: sum(1 for o in r["open"] if o["scan"] == s) for s in ("iam", "tf")}


# ---- D4-6: a partial IAM export / an empty IaC plan -----------------------------------------------------------------

def test_partial_iam_export_and_empty_plan_resolve_nothing(tmp_path):
    iam = tmp_path / "iam.json"
    shutil.copy(SAMPLES / "aws_iam_auth_details.json", iam)
    plan = tmp_path / "plan.json"
    shutil.copy(min((SAMPLES / "iac").rglob("*.json")), plan)
    cfg = RunnerConfig(store=tmp_path / "store", scans=[ScanConfig("iam", "iam", {"auth_details": iam}),
                                                        ScanConfig("tf", "iac", {"plan": plan})])
    r1 = run_once(cfg, now=T0, hitl=None)
    before = _by(r1)
    assert before["iam"] > 1 and before["tf"] > 0
    iam.write_text(json.dumps({"Policies": json.loads(iam.read_text()).get("Policies", [])}))
    plan.write_text(json.dumps({"format_version": "1.2", "resource_changes": []}))
    r2 = run_once(cfg, now=T0 + timedelta(days=1), hitl=None)
    assert _by(r2) == before and r2["counts"]["resolved"] == 0


def test_iac_plan_that_is_not_a_plan_fails(tmp_path):
    from aegis.posture.runner import execute
    p = tmp_path / "plan.json"
    p.write_text(json.dumps({"values": {}}))
    with pytest.raises(sources.PostureSourceError, match="resource_changes"):
        execute(ScanConfig("tf", "iac", {"plan": p}))
    d = tmp_path / "k8s"
    d.mkdir()
    with pytest.raises(sources.PostureSourceError, match="no Kubernetes manifests"):
        execute(ScanConfig("tf", "iac", {"k8s": [d]}))


# ---- D4-5: one empty asset source fails the exposure scan ---------------------------------------------------------------

def test_one_empty_asset_source_fails_the_exposure_scan(tmp_path):
    from aegis.exposure.scan import run_scan
    empty = tmp_path / "aws.json"
    empty.write_text("{}")
    with pytest.raises(sources.PostureSourceError, match="gave no assets"):
        run_scan({"vulns": [EXPOSURE / "tenable_vulns.json"], "aws_bundles": [empty],
                  "inventory": EXPOSURE / "inventory.csv"})


# ---- D4-13: the audit CLI ------------------------------------------------------------------------------------------------

def test_audit_verify_checks_anchors_and_refuses_a_missing_file(tmp_path, monkeypatch, capsys):
    from aegis.agents.shared.audit import AuditLog
    from aegis.agents.shared.evidence_chain import EvidenceChain
    from aegis.audit.__main__ import main
    audit, anchor = tmp_path / "audit.jsonl", tmp_path / "anchor.jsonl"
    monkeypatch.setenv("AEGIS_AUDIT_ANCHOR", str(anchor))
    monkeypatch.setenv("AEGIS_AUDIT_ANCHOR_EVERY", "1")
    log = AuditLog(audit)
    for i in range(5):
        log.append(EvidenceChain(alert_id=f"a{i}", investigated_by="t", verdict="malicious", confidence=0.9))
    assert main(["verify", "--audit", str(audit)]) == 0
    audit.write_text("\n".join(audit.read_text().splitlines()[:2]) + "\n")      # the tail is cut off
    assert main(["verify", "--audit", str(audit)]) == 1
    assert main(["verify", "--audit", str(tmp_path / "typo.jsonl")]) == 2
