"""Exposure prioritisation: exploitable × reachable × undefended, with the reason for every tier."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.exposure import Asset, Settings, Vuln, assess, funnel, loaders, summarize
from aegis.exposure.__main__ import main as cli
from aegis.exposure.engine import ALL_PORTS
from aegis.posture.sources import PostureSourceError, load_json

S = Path(__file__).resolve().parents[1] / "exposure" / "samples"


@pytest.fixture
def sample():
    vulns = loaders.load_vulns(S / "tenable_vulns.json")
    loaders.apply_intel(vulns, kev=S / "kev_sample.json", epss=S / "epss_sample.csv")
    assets = loaders.merge_assets(loaders.assets_from_aws(load_json(S / "aws_bundle.json")),
                                  loaders.assets_from_inventory(S / "inventory.csv"))
    ex, notes = assess(vulns, assets, loaders.load_settings(S / "exposure.yaml"))
    return vulns, assets, ex, notes


def pick(ex, cve, asset):
    (e,) = [x for x in ex if x.cve == cve and asset in (x.asset, x.asset_name)]
    return e


def test_sample_funnel_and_tiers(sample):
    vulns, assets, ex, notes = sample
    assert len(vulns) == 14 and len(assets) == 9
    assert funnel(ex, len(vulns)) == {"raw": 14, "scored": 13, "exploitable": 10, "reachable": 7, "undefended": 5, "act_now": 3}
    assert summarize(ex) == {"ACT_NOW": 3, "ACT": 3, "SCHEDULE": 5, "MONITOR": 2}
    assert [e.tier for e in ex] == sorted([e.tier for e in ex], key=["ACT_NOW", "ACT", "SCHEDULE", "MONITOR"].index)
    assert any("unknown-host" in n for n in notes)


@pytest.mark.parametrize("cve,asset,tier,reach,defended", [
    ("CVE-2021-44228", "legacy-reports", "ACT_NOW", "internet", "none"),
    ("CVE-2024-6387", "ops-bastion", "ACT_NOW", "internet", "none"),          # EDR does not lower the tier
    ("CVE-2011-2523", "dmz-ftp", "ACT_NOW", "internet", "none"),
    ("CVE-2022-22965", "payments-api", "ACT", "one_hop", "none"),
    ("CVE-2023-44487", "netbanking-web", "ACT", "internet", "partial"),       # WAF on 443
    ("CVE-2023-34362", "dmz-ftp", "ACT", "one_hop", "none"),
    ("CVE-2017-5638", "ib-portal", "SCHEDULE", "internet", "full"),          # virtual patch
    ("CVE-2012-1675", "cbs-db01", "SCHEDULE", "isolated", "none"),
    ("CVE-2024-6387", "nightly-batch", "SCHEDULE", "isolated", "none"),
    ("CVE-2024-99001", "netbanking-web", "SCHEDULE", "internet", "partial"),  # unexploited critical, internet-facing
    ("CVE-2023-38545", "payments-api", "MONITOR", "local", "none"),
])
def test_each_tier_and_reason(sample, cve, asset, tier, reach, defended):
    e = pick(sample[2], cve, asset)
    assert (e.tier, e.reach, e.defended) == (tier, reach, defended)
    assert len(e.reasons) == 4


def test_security_group_reference_limits_one_hop_sources(sample):
    e = pick(sample[2], "CVE-2022-22965", "payments-api")
    assert "from internet-facing netbanking-web" in e.reasons[1]
    assert "legacy-reports" not in e.reasons[1] and "ops-bastion" not in e.reasons[1]


def test_edr_is_reported_but_never_a_defence(sample):
    e = pick(sample[2], "CVE-2024-6387", "ops-bastion")
    assert "detection, not prevention" in e.reasons[2] and e.defended == "none"


def test_crown_jewel_distance(sample):
    ex = sample[2]
    assert pick(ex, "CVE-2012-1675", "cbs-db01").crown_distance == 0
    assert pick(ex, "CVE-2021-44228", "legacy-reports").crown_distance == 1
    assert pick(ex, "CVE-2024-6387", "nightly-batch").crown_distance is None


def test_fixed_and_info_records_skipped_and_unmatched_reported(sample):
    vulns, _, ex, notes = sample
    assert not any(v.title in ("Already fixed", "Informational banner") for v in vulns)
    assert not any(e.asset_name == "unknown-host" for e in ex)
    assert "1 findings on 1 assets" in notes[0]


def _asset(**kw):
    base = {"id": "a", "name": "a", "keys": {"a"}, "zone": "z", "public": True, "internet_ports": [(443, 443)]}
    return Asset(**{**base, **kw})


def test_isolated_when_port_not_exposed():
    (e,), _ = assess([Vuln(asset="a", cve="C", title="t", port=22, kev=True)], [_asset()])
    assert (e.reach, e.tier) == ("isolated", "SCHEDULE")


def test_one_hop_needs_an_allowed_source():
    web = _asset(id="web", keys={"web"}, groups=frozenset({"sg-web"}))
    db = _asset(id="db", keys={"db"}, public=False, internet_ports=[], lateral=[(5432, 5432, frozenset({"sg-app"}))])
    (e,), _ = assess([Vuln(asset="db", cve="C", title="t", port=5432, kev=True)], [web, db])
    assert e.reach == "isolated" and "not allowed to reach it" in e.reasons[1]
    db.lateral = [(5432, 5432, frozenset({"sg-web"}))]
    (e,), _ = assess([Vuln(asset="db", cve="C", title="t", port=5432, kev=True)], [web, db])
    assert e.reach == "one_hop" and e.tier == "ACT"


def test_epss_threshold_is_configurable():
    v = Vuln(asset="a", cve="C", title="t", port=443, epss=0.05)
    (e,), _ = assess([v], [_asset()])
    assert not e.exploitable
    (e,), _ = assess([v], [_asset()], Settings(epss_threshold=0.05))
    assert e.exploitable and e.tier == "ACT_NOW"


def test_wildcard_virtual_patch():
    (e,), _ = assess([Vuln(asset="a", cve="C", title="t", port=443, kev=True)], [_asset()],
                     Settings(virtual_patches={"C": ["*"]}))
    assert (e.defended, e.tier) == ("full", "SCHEDULE")


def test_matching_by_alternate_identifier():
    v = Vuln(asset="does-not-match", asset_alt=["10.0.0.5"], cve="C", title="t", port=443, kev=True)
    (e,), _ = assess([v], [_asset(keys={"a", "10.0.0.5"})])
    assert e.tier == "ACT_NOW"


def test_all_ports_rule_from_aws_bundle():
    b = {"security_groups": [{"GroupId": "sg", "IpPermissions": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}],
         "instances": [{"InstanceId": "i", "State": {"Name": "running"}, "VpcId": "v", "PublicIpAddress": "1.2.3.4",
                        "SecurityGroups": [{"GroupId": "sg"}]}]}
    (a,) = loaders.assets_from_aws(b)
    assert a.internet_ports == ALL_PORTS and a.open_to_internet(31337)


def test_stopped_instances_and_private_without_public_ip_are_not_internet_facing():
    b = {"security_groups": [{"GroupId": "sg", "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                                                                   "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}],
         "instances": [{"InstanceId": "i1", "State": {"Name": "stopped"}, "PublicIpAddress": "1.1.1.1", "SecurityGroups": [{"GroupId": "sg"}]},
                       {"InstanceId": "i2", "State": {"Name": "running"}, "SecurityGroups": [{"GroupId": "sg"}]}]}
    (a,) = loaders.assets_from_aws(b)
    assert a.id == "i2" and not a.open_to_internet(443)


def test_inventory_overrides_cloud_role_and_coverage(tmp_path):
    inv = tmp_path / "inv.csv"
    inv.write_text("asset,ips,role,waf,edr\ni-0legacy,10.0.1.30,payment_api,yes,yes\n")
    assets = loaders.merge_assets(loaders.assets_from_aws(load_json(S / "aws_bundle.json")), loaders.assets_from_inventory(inv))
    (legacy,) = [a for a in assets if a.id == "i-0legacy"]
    assert legacy.role == "payment_api" and legacy.waf and legacy.edr and len(assets) == 5


def test_csv_vulns_and_epss_comment_line(tmp_path):
    p = tmp_path / "v.csv"
    p.write_text("asset,cve,title,port,cvss,epss,kev,poc\nweb1,CVE-1,t,443,9.8,,no,no\n")
    vulns = loaders.load_vulns(p)
    loaders.apply_intel(vulns, epss=S / "epss_sample.csv")  # #model_version line must be skipped
    assert vulns[0].port == 443 and vulns[0].epss is None and not vulns[0].kev


def test_jsonl_tenable_export(tmp_path):
    recs = json.loads((S / "tenable_vulns.json").read_text())
    p = tmp_path / "v.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in recs))
    assert len(loaders.load_vulns(p)) == 14


def test_bad_inputs(tmp_path):
    with pytest.raises(PostureSourceError, match="not found"):
        loaders.load_vulns(tmp_path / "missing.json")
    bad = tmp_path / "bad.csv"
    bad.write_text("nope\n1\n")
    with pytest.raises(PostureSourceError, match="no 'asset' column"):    # used to read as zero findings
        loaders.load_vulns(bad)
    with pytest.raises(PostureSourceError, match="KEV"):
        loaders.apply_intel([], kev=tmp_path / "missing.json")


def test_cli(capsys):
    base = ["--vulns", str(S / "tenable_vulns.json"), "--aws-bundle", str(S / "aws_bundle.json"),
            "--inventory", str(S / "inventory.csv"), "--kev", str(S / "kev_sample.json"),
            "--epss", str(S / "epss_sample.csv"), "--settings", str(S / "exposure.yaml")]
    assert cli(base) == 0
    out = capsys.readouterr().out
    assert out.startswith("funnel: 14 findings → 10 exploitable → 7 reachable → 5 undefended → 3 ACT NOW")
    assert cli(base + ["--json", "--fail-on-act-now"]) == 1
    rep = json.loads(capsys.readouterr().out)
    assert rep["tiers"]["ACT_NOW"] == 3 and rep["exposures"][0]["reasons"]
    assert cli(["--vulns", str(S / "tenable_vulns.json")]) == 2  # no asset model
    assert "asset model" in capsys.readouterr().err
