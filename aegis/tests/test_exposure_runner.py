"""The exposure engine inside the VAPT loop: tiers as severities, history across tier changes, funnel in the report."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from aegis.exposure.scan import SEVERITY, run_scan
from aegis.posture import runner
from aegis.posture.sources import PostureSourceError

S = Path(__file__).resolve().parents[1] / "exposure" / "samples"
T0 = datetime(2026, 11, 2, 9, 0, tzinfo=UTC)


@pytest.fixture
def ws(tmp_path):
    d = tmp_path / "s"
    shutil.copytree(S, d)
    cfg = yaml.safe_load((d / "posture_exposure.yaml").read_text())
    cfg["store"] = str(tmp_path / "store")
    (d / "posture_exposure.yaml").write_text(yaml.safe_dump(cfg))
    return d


def test_run_once_tracks_exposures(ws):
    cfg = runner.load_config(ws / "posture_exposure.yaml")
    r = runner.run_once(cfg, now=T0)
    (sc,) = r["scans"]
    assert sc["status"] == "ok" and sc["meta"]["funnel"]["act_now"] == 3 and sc["meta"]["monitor_only"] == 1
    assert r["summary"] == {"critical": 2, "high": 2, "medium": 6, "low": 2, "info": 0}   # vsftpd ACT_NOW is waived
    assert [w["id"] for w in r["waived"]] == ["CVE-2011-2523"] and r["waived"][0]["extra"]["tier"] == "ACT_NOW"
    log4 = next(o for o in r["open"] if o["id"] == "CVE-2021-44228")
    assert log4["severity"] == "critical" and log4["extra"]["reach"] == "internet" and len(log4["extra"]["reasons"]) == 4
    assert log4["affected_component"] == "legacy-reports:8080" and "Patch CVE-2021-44228" in log4["recommended_remediation"]
    md = (Path(cfg.store) / "runs" / f"{r['run_id']}.md").read_text()
    assert "Exposure funnel — exposure-sample-bank: 14 findings → 10 exploitable" in md and "monitor mode do not count" in md


def test_tier_change_keeps_history(ws):
    """A blocking virtual patch moves Log4Shell from ACT_NOW to SCHEDULE: same finding, first-seen kept."""
    cfg = runner.load_config(ws / "posture_exposure.yaml")
    runner.run_once(cfg, now=T0)
    cov = json.loads((ws / "waf_coverage.json").read_text())
    cov["protections"][1]["mode"] = "block"                      # reports.bank.example switched to blocking
    (ws / "waf_coverage.json").write_text(json.dumps(cov))
    r = runner.run_once(cfg, now=T0 + timedelta(days=3))
    log4 = next(o for o in r["open"] if o["id"] == "CVE-2021-44228")
    assert log4["severity"] == "medium" and log4["extra"]["tier"] == "SCHEDULE" and log4["extra"]["defended"] == "full"
    assert log4["first_seen"].startswith("2026-11-02") and not log4["new"] and r["counts"]["resolved"] == 0


def test_act_now_past_sla(ws):
    cfg = runner.load_config(ws / "posture_exposure.yaml")
    runner.run_once(cfg, now=T0)
    r = runner.run_once(cfg, now=T0 + timedelta(days=8))
    assert {o["id"] for o in r["open"] if o["overdue"]} == {"CVE-2021-44228", "CVE-2024-6387"}


def test_patched_asset_resolves(ws):
    cfg = runner.load_config(ws / "posture_exposure.yaml")
    runner.run_once(cfg, now=T0)
    recs = [x for x in json.loads((ws / "tenable_vulns.json").read_text()) if x["asset"]["hostname"] != "legacy-reports"]
    (ws / "tenable_vulns.json").write_text(json.dumps(recs))
    r = runner.run_once(cfg, now=T0 + timedelta(days=1))
    assert [x["id"] for x in r["resolved"]] == ["CVE-2021-44228"]


def test_directory_of_exports_and_k8s(tmp_path):
    R = S / "reach"
    d = tmp_path / "trivy"
    d.mkdir()
    for f in R.glob("trivy_*.json"):
        shutil.copy(f, d / f.name)
    findings, _notes, meta = run_scan({"vulns": [d], "k8s_exports": [f"prod-aks={R / 'k8s_export.json'}"], "kev": S / "kev_sample.json"})
    assert meta["funnel"]["raw"] == 3 and {f.affected_component for f in findings} >= {"Deployment/web/legacy-api (image)"}
    assert {f.severity for f in findings} <= set(SEVERITY.values())


def test_missing_inputs():
    with pytest.raises(PostureSourceError, match="vulns"):
        run_scan({})
    with pytest.raises(PostureSourceError, match="asset model"):
        run_scan({"vulns": [S / "tenable_vulns.json"]})


def test_config_paths_resolve(ws):
    cfg = runner.load_config(ws / "posture_exposure.yaml")
    (sc,) = cfg.scans
    assert sc.opts["vulns"] == [ws / "tenable_vulns.json"] and sc.opts["inventory"] == ws / "inventory.csv"
    assert sc.opts["waf_coverage"] == [ws / "waf_coverage.json"]
