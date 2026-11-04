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
