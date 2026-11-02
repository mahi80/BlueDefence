"""ACT NOW → remediation proposal through the approval queue → the next run verifies the path closed."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from aegis.exposure import remediation
from aegis.exposure.engine import Asset, Settings, Vuln, assess
from aegis.exposure.scan import to_finding
from aegis.hitl.filequeue import FileHITL
from aegis.posture import runner

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


def _hitl(tmp_path) -> FileHITL:
    # a fresh transport each run, as the timer service does: pending cards survive through the journal
    return FileHITL(tmp_path / "hitl")


def _decide(tmp_path, approval_id: str, status: str = "approved", who: str = "ciso:asha") -> None:
    with (tmp_path / "hitl" / "decisions.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps({"approval_id": approval_id, "status": status, "decided_by": who}) + "\n")


def _by_asset(r: dict) -> dict[str, dict]:
    return {p["component"]: p for p in r["remediation"]["proposals"]}


def test_act_now_files_proposals_with_exact_commands(ws, tmp_path):
    cfg = runner.load_config(ws / "posture_exposure.yaml")
    r = runner.run_once(cfg, now=T0, hitl=_hitl(tmp_path))
    props = _by_asset(r)
    assert set(props) == {"legacy-reports:8080", "ops-bastion:22"}      # vsftpd is waived: no proposal
    log4 = props["legacy-reports:8080"]
    assert log4["status"] == "awaiting_approval" and log4["approval_id"] and log4["transport"] == "file"
    kinds = [o["kind"] for o in log4["options"]]
    assert kinds == ["virtual_patch", "cut_path", "patch"]
    vp = log4["options"][0]
    assert "monitor to block" in vp["steps"][0] and "imperva" in vp["owner"]
    cut = log4["options"][1]
    assert cut["commands"][0] == "aws ec2 revoke-security-group-ingress --group-id sg-legacy --protocol tcp --port 8080 --cidr 0.0.0.0/0"
    # SSH: a WAF cannot virtual-patch it, so no such option is offered
    assert [o["kind"] for o in props["ops-bastion:22"]["options"]] == ["cut_path", "patch"]
    card = json.loads((tmp_path / "hitl" / "cards.jsonl").read_text().splitlines()[0])
    assert card["args"]["alert_id"].startswith("exposure:") and "nothing is applied automatically" in card["args"]["reasoning"]
    saved = json.loads((Path(cfg.store) / "proposals.json").read_text())
    assert len(saved) == 2
    md = (Path(cfg.store) / "runs" / f"{r['run_id']}.md").read_text()
    assert "## Remediation proposals (ACT NOW)" in md and "awaiting approval" in md


def test_rerun_does_not_refile(ws, tmp_path):
    cfg = runner.load_config(ws / "posture_exposure.yaml")
    r1 = runner.run_once(cfg, now=T0, hitl=_hitl(tmp_path))
    r2 = runner.run_once(cfg, now=T0 + timedelta(hours=1), hitl=_hitl(tmp_path))
    assert [p["approval_id"] for p in r1["remediation"]["proposals"]] == [p["approval_id"] for p in r2["remediation"]["proposals"]]
    cards = [json.loads(x) for x in (tmp_path / "hitl" / "cards.jsonl").read_text().splitlines()]
    assert sum(c["kind"] == "approval" for c in cards) == 2


def test_approved_and_closed_is_verified_approved_but_open_is_flagged(ws, tmp_path):
    cfg = runner.load_config(ws / "posture_exposure.yaml")
    r1 = runner.run_once(cfg, now=T0, hitl=_hitl(tmp_path))
    p1 = _by_asset(r1)
    _decide(tmp_path, p1["legacy-reports:8080"]["approval_id"])
    _decide(tmp_path, p1["ops-bastion:22"]["approval_id"], who="ciso:ravi")

    r2 = runner.run_once(cfg, now=T0 + timedelta(hours=1), hitl=_hitl(tmp_path))
    p2 = _by_asset(r2)
    assert p2["legacy-reports:8080"]["status"] == "approved" and p2["legacy-reports:8080"]["decided_by"] == "ciso:asha"

    # the network team applies the approved change to legacy-reports only: sg-legacy no longer admits 8080 from the internet
    b = json.loads((ws / "aws_bundle.json").read_text())
    for g in b["security_groups"]:
        if g["GroupId"] == "sg-legacy":
            for perm in g["IpPermissions"]:
                perm["IpRanges"] = [x for x in perm.get("IpRanges", []) if x.get("CidrIp") != "0.0.0.0/0"]
                perm["Ipv6Ranges"] = []
    (ws / "aws_bundle.json").write_text(json.dumps(b))

    r3 = runner.run_once(cfg, now=T0 + timedelta(days=2), hitl=_hitl(tmp_path))
    p3 = _by_asset(r3)
    closed, still = p3["legacy-reports:8080"], p3["ops-bastion:22"]
    assert closed["status"] == "verified_closed" and closed["closed_at"]
    assert closed["verification"].startswith("Now in ") and "Act now" not in closed["verification"]
    assert [h["status"] for h in closed["history"]] == ["proposed", "awaiting_approval", "approved", "verified_closed"]
    assert still["status"] == "approved_still_open" and "still open" in still["verification"] and "port 22" in still["verification"]
    assert r3["remediation"]["counts"] == {"verified_closed": 1, "approved_still_open": 1}
    md = (Path(cfg.store) / "runs" / f"{r3['run_id']}.md").read_text()
    assert "APPROVED, STILL OPEN" in md and "verified closed" in md


def test_rejected_is_recorded_and_not_refiled(ws, tmp_path):
    cfg = runner.load_config(ws / "posture_exposure.yaml")
    r1 = runner.run_once(cfg, now=T0, hitl=_hitl(tmp_path))
    aid = _by_asset(r1)["ops-bastion:22"]["approval_id"]
    _decide(tmp_path, aid, "rejected")
    r2 = runner.run_once(cfg, now=T0 + timedelta(hours=1), hitl=_hitl(tmp_path))
    r3 = runner.run_once(cfg, now=T0 + timedelta(hours=2), hitl=_hitl(tmp_path))
    assert _by_asset(r2)["ops-bastion:22"]["status"] == "rejected"
    assert _by_asset(r3)["ops-bastion:22"]["approval_id"] == aid


def test_closed_before_decision_and_waived(ws, tmp_path):
    cfg = runner.load_config(ws / "posture_exposure.yaml")
    runner.run_once(cfg, now=T0, hitl=_hitl(tmp_path))
    cov = json.loads((ws / "waf_coverage.json").read_text())
    cov["protections"][1]["mode"] = "block"                      # WAF team switches reports.bank.example to blocking
    (ws / "waf_coverage.json").write_text(json.dumps(cov))
    w = yaml.safe_load((ws / "waivers.yaml").read_text())
    w["waivers"].append({"id": "CVE-2024-6387", "resource": "*", "reason": "bastion retiring this week",
                         "approved_by": "ciso", "expires": "2026-11-20"})
    (ws / "waivers.yaml").write_text(yaml.safe_dump(w))
    r = runner.run_once(cfg, now=T0 + timedelta(days=1), hitl=_hitl(tmp_path))
    p = _by_asset(r)
    assert p["legacy-reports:8080"]["status"] == "closed_before_decision"
    assert "virtual-patch" in p["legacy-reports:8080"]["verification"]
    assert p["ops-bastion:22"]["status"] == "accepted_risk"


def test_no_channel_still_records_proposals(ws):
    cfg = runner.load_config(ws / "posture_exposure.yaml")
    r = runner.run_once(cfg, now=T0, hitl=None)
    assert {p["status"] for p in r["remediation"]["proposals"]} == {"proposed"}
    assert r["remediation"]["channel"] is None


def test_disabled_in_config(ws):
    cfg = runner.load_config(ws / "posture_exposure.yaml")
    cfg.remediation = {"enabled": False}
    r = runner.run_once(cfg, now=T0, hitl=None)
    assert "remediation" not in r


def test_channel_failure_is_a_note_not_a_crash(ws):
    class Down:
        name = "dashboard"

        def request(self, action, chain):
            raise RuntimeError("dashboard 503")

        def sync(self, agent):
            raise RuntimeError("dashboard 503")

    cfg = runner.load_config(ws / "posture_exposure.yaml")
    r = runner.run_once(cfg, now=T0, hitl=Down())
    assert {p["status"] for p in r["remediation"]["proposals"]} == {"proposed"}
    assert any("could not file remediation proposal" in n for n in r["notes"])


def test_approval_records_a_commitment_never_a_change():
    out = remediation._CommitmentRecorder().approve(object(), approver="ciso:asha", source_alert_id="exposure:x")
    assert out["applied"] is False and out["recorded"] is True


def _row(asset: Asset, vuln: Vuln, settings: Settings | None = None) -> dict:
    (e,), _ = assess([vuln], [asset], settings)
    f = to_finding(e)
    return {**f.as_dict(), "fingerprint": "fp", "scan": "t"}


def test_azure_option_denies_on_the_exact_nsg():
    nsg = "/subscriptions/s/resourcegroups/rg-net/providers/microsoft.network/networksecuritygroups/vm-web-nsg"
    a = Asset(id="vm-web", name="vm-web", public=True, internet_ports=[(3389, 3389)], opened_by={(3389, 3389): {nsg}}, source="azure")
    row = _row(a, Vuln(asset="vm-web", cve="CVE-2019-0708", title="BlueKeep", port=3389, kev=True))
    (cut, patch) = remediation.build_options(row)
    assert cut["commands"] == [("az network nsg rule create -g rg-net --nsg-name vm-web-nsg -n aegis-deny-internet-3389 --priority 100 "
                                "--direction Inbound --access Deny --protocol Tcp --source-address-prefixes Internet "
                                "--destination-port-ranges 3389")]
    assert patch["kind"] == "patch"


def test_range_rule_and_onprem_options():
    a = Asset(id="i-1", name="app", public=True, internet_ports=[(8000, 8100)], opened_by={(8000, 8100): {"sg-wide"}}, source="aws")
    cut = remediation.build_options(_row(a, Vuln(asset="i-1", cve="CVE-2023-1", title="x", port=8080, kev=True)))[1]
    assert any("8000-8100" in s for s in cut["steps"])
    b = Asset(id="dc-ftp", name="dc-ftp", public=True, internet_ports=[(21, 21)], source="inventory")
    opts = remediation.build_options(_row(b, Vuln(asset="dc-ftp", cve="CVE-2011-2523", title="vsftpd", port=21, kev=True)))
    assert opts[0]["kind"] == "cut_path" and opts[0]["steps"][0].startswith("Firewall change request: deny inbound tcp/21")
