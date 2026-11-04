"""Integration plan #6: native Qualys / Rapid7 / Wiz / Defender VM / Prisma exports into the exposure engine."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.exposure import assess, loaders
from aegis.exposure.engine import ANY_PORT
from aegis.exposure.scanners import from_csv, from_json
from aegis.posture.sources import PostureSourceError, load_json

S = Path(__file__).resolve().parents[1] / "exposure" / "samples"
SC = S / "scanners"


def _by(vulns, cve):
    return [v for v in vulns if v.cve == cve]


def test_qualys_report_skips_preamble_info_and_dedupes_cves():
    vulns = loaders.load_vulns(SC / "qualys_report.csv")
    assert {v.cve for v in vulns} == {"CVE-2012-1675", "CVE-2011-2523", "CVE-2022-0778"}   # the Ig row is dropped
    (tns,) = _by(vulns, "CVE-2012-1675")
    assert tns.asset == "cbs-db01.dc.bank" and "10.50.1.10" in tns.asset_alt and tns.port == 1521
    assert tns.cvss == 7.5 and tns.poc and tns.source == "qualys:19824"
    assert len(_by(vulns, "CVE-2022-0778")) == 1 and not _by(vulns, "CVE-2022-0778")[0].poc


def test_rapid7_drops_not_vulnerable_and_reads_exploits():
    vulns = loaders.load_vulns(SC / "rapid7_vulns.csv")
    assert {v.cve for v in vulns} == {"CVE-2017-5638", "CVE-2023-34362"}
    (struts,) = _by(vulns, "CVE-2017-5638")
    assert struts.asset == "ib.bank.example" and struts.port == 443 and struts.poc and struts.cvss == 10.0


def test_wiz_graphql_nodes_are_package_findings_keyed_by_instance():
    vulns = loaders.load_vulns(SC / "wiz_findings.json")
    assert {v.cve for v in vulns} == {"CVE-2021-44228", "CVE-2023-38545"}               # RESOLVED dropped
    (l4j,) = _by(vulns, "CVE-2021-44228")
    assert l4j.asset == "i-0legacy" and "legacy-reports" in l4j.asset_alt and l4j.port == ANY_PORT
    assert l4j.kev and l4j.poc and l4j.epss == 0.975


def test_defender_vm_api_response():
    vulns = loaders.load_vulns(SC / "defender_vm.json")
    (tns,) = _by(vulns, "CVE-2012-1675")
    assert tns.asset == "cbs-db01.dc.bank" and tns.poc and not tns.kev and tns.port == ANY_PORT
    (ssl,) = _by(vulns, "CVE-2022-0778")
    assert not ssl.poc


def test_prisma_hosts_and_images():
    vulns = loaders.load_vulns(SC / "prisma_hosts.json")
    (ssh,) = _by(vulns, "CVE-2024-6387")
    assert ssh.asset == "i-0bastion" and "ops-bastion" in ssh.asset_alt and ssh.poc and not ssh.kev
    (spring,) = _by(vulns, "CVE-2022-22965")
    assert spring.asset == "registry.bank.local/payments/api:2.4.1" and "api:2.4.1" in spring.asset_alt
    assert spring.kev and spring.poc


def test_scanner_findings_join_the_bank_assets():
    assets = loaders.merge_assets(loaders.assets_from_aws(load_json(S / "aws_bundle.json")),
                                  loaders.assets_from_inventory(S / "inventory.csv"))
    vulns = [v for f in ("qualys_report.csv", "rapid7_vulns.csv", "wiz_findings.json", "defender_vm.json",
                         "prisma_hosts.json") for v in loaders.load_vulns(SC / f)]
    loaders.apply_intel(vulns, kev=S / "kev_sample.json", epss=S / "epss_sample.csv")
    ex, _notes = assess(vulns, assets, loaders.load_settings(S / "exposure.yaml"))
    matched = {(e.cve, e.asset_name or e.asset) for e in ex}
    assert any(c == "CVE-2011-2523" for c, _ in matched)                  # Qualys dmz-ftp by DNS / IP
    assert any(c == "CVE-2017-5638" for c, _ in matched)                  # Rapid7 ib-portal
    assert any(c == "CVE-2021-44228" for c, _ in matched)                 # Wiz by instance id
    assert any(c == "CVE-2024-6387" for c, _ in matched)                  # Prisma by instance id


def test_unknown_csv_is_still_refused(tmp_path):
    p = tmp_path / "x.csv"
    p.write_text("host,vuln\na,b\n")
    with pytest.raises(PostureSourceError, match="recognised scanner format"):
        loaders.load_vulns(p)


def test_detectors_reject_lookalikes():
    assert from_json({"value": []}) is None and from_json([{"hostname": "h"}]) is None
    assert from_json({"data": {"vulnerabilityFindings": {"nodes": []}}}) == ("wiz", [])
    assert from_csv("a,b\n1,2\n") is None
    assert json.loads((SC / "wiz_findings.json").read_text())                  # valid sample


# ---------------------------------------------------------------------------------------------------- round 6 --

def test_qualys_practice_is_a_potential_vulnerability_not_info(tmp_path):
    """X-1: Type "Practice" (potential) is kept; only "Ig" is information gathered."""
    p = tmp_path / "q.csv"
    p.write_text('"IP","DNS","QID","Title","Type","Severity","Port","Protocol","CVE ID","CVSS3.1 Base"\n'
                 '"10.0.0.5","web.bank","11827","Apache path traversal","Practice","5","443","tcp","CVE-2021-41773","9.8"\n'
                 '"10.0.0.5","web.bank","45038","Host Scan Time","Ig","1","0","","",""\n')
    assert [v.cve for v in loaders.load_vulns(p)] == ["CVE-2021-41773"]


def test_scan_refuses_an_empty_native_export_beside_others(tmp_path):
    """X-1: one scanner's empty export would resolve every exposure on its assets."""
    from aegis.exposure.scan import run_scan
    empty = tmp_path / "rapid7.csv"
    empty.write_text("Asset IP Address,Asset Names,Vulnerability ID,Vulnerability CVE IDs,Vulnerability Test Result Code\n")
    with pytest.raises(PostureSourceError, match="rapid7 export"):
        run_scan({"vulns": [str(SC / "qualys_report.csv"), str(empty)], "inventory": str(S / "inventory.csv")})


def test_partial_paged_exports_are_refused(tmp_path):
    """X-2."""
    d = tmp_path / "d.json"
    d.write_text(json.dumps({"value": [{"deviceName": "h", "cveId": "CVE-2024-10001"}],
                             "@odata.nextLink": "https://api.securitycenter.microsoft.com/api/...&$skip=50000"}))
    with pytest.raises(PostureSourceError, match="one page"):
        loaders.load_vulns(d)
    w = tmp_path / "w.json"
    w.write_text(json.dumps({"data": {"vulnerabilityFindings": {
        "nodes": [{"name": "CVE-2024-10002", "vulnerableAsset": {"name": "h"}}], "pageInfo": {"hasNextPage": True}}}}))
    with pytest.raises(PostureSourceError, match="one page"):
        loaders.load_vulns(w)


def test_defender_fixed_rows_skipped_and_kev_left_to_the_feed(tmp_path):
    """X-3."""
    d = tmp_path / "d.json"
    d.write_text(json.dumps({"value": [
        {"deviceName": "h1", "cveId": "CVE-2024-10001", "exploitabilityLevel": "ExploitIsVerified"},
        {"deviceName": "h2", "cveId": "CVE-2024-10003", "exploitabilityLevel": "ExploitIsInKit", "status": "Fixed"}]}))
    (v,) = loaders.load_vulns(d)
    assert v.cve == "CVE-2024-10001" and v.poc and not v.kev


def test_rapid7_keeps_only_vulnerable_result_codes(tmp_path):
    """X-4."""
    p = tmp_path / "r.csv"
    p.write_text("Asset IP Address,Asset Names,Vulnerability ID,Vulnerability CVE IDs,Vulnerability CVSSv3 Score,"
                 "Service Port,Exploit Count,Vulnerability Test Result Code\n"
                 "10.0.0.1,a,v1,CVE-2024-10001,9.8,443,1,VE\n10.0.0.1,a,v2,CVE-2024-10002,9.8,443,1,VP\n"
                 "10.0.0.1,a,v3,CVE-2024-10003,10,443,1,ER\n10.0.0.1,a,v4,CVE-2024-10004,10,443,1,DS\n"
                 "10.0.0.1,a,v5,CVE-2024-10005,10,443,1,EE\n10.0.0.1,a,v6,CVE-2024-10006,10,443,1,UK\n")
    assert sorted(v.cve for v in loaders.load_vulns(p)) == ["CVE-2024-10001", "CVE-2024-10002"]


def test_malformed_shapes_are_parse_errors_not_crashes(tmp_path):
    """X-5."""
    for doc in ({"data": {"vulnerabilityFindings": {"nodes": [{"name": "CVE-2024-10001", "vulnerableAsset": "h"}]}}},
                [{"hostname": "h", "vulnerabilities": ["CVE-2024-10001"]}],
                {"nodes": ["x"]}):
        p = tmp_path / "m.json"
        p.write_text(json.dumps(doc))
        try:
            loaders.load_vulns(p)
        except PostureSourceError:
            pass                                       # a parse error is fine; an AttributeError / TypeError is not


def test_bom_exports_load(tmp_path):
    """X-6."""
    j = tmp_path / "b.json"
    j.write_bytes(b"\xef\xbb\xbf" + json.dumps({"value": [{"deviceName": "h", "cveId": "CVE-2024-10001"}]}).encode())
    assert [v.cve for v in loaders.load_vulns(j)] == ["CVE-2024-10001"]
    c = tmp_path / "b.csv"
    c.write_bytes(b"\xef\xbb\xbfasset,cve,title,port\nh,CVE-2024-10002,x,443\n")
    assert [v.cve for v in loaders.load_vulns(c)] == ["CVE-2024-10002"]


def test_prisma_fix_available_is_still_open(tmp_path):
    """X-7."""
    p = tmp_path / "p.json"
    p.write_text(json.dumps([{"hostname": "h", "vulnerabilities": [
        {"cve": "CVE-2024-6387", "packageName": "openssh", "status": "fixed in 9.8p1"}]}]))
    assert [v.cve for v in loaders.load_vulns(p)] == ["CVE-2024-6387"]


def test_wiz_csv_finding_status_wins_over_resource_status(tmp_path):
    """X-8."""
    p = tmp_path / "w.csv"
    p.write_text("Name,Has Exploit,Resource Name,Status,FindingStatus\n"
                 "CVE-2024-10001,true,h,Active,RESOLVED\nCVE-2024-10002,false,h,Active,OPEN\n")
    assert [v.cve for v in loaders.load_vulns(p)] == ["CVE-2024-10002"]
