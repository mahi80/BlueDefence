"""WAF / virtual-patch coverage: blocking vs monitor mode, CVE virtual patches, and the vendor exporters."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.agents.response.connectors.http import HttpResult
from aegis.exposure import assess, loaders
from aegis.exposure.__main__ import main as cli
from aegis.exposure.coverage import (
    Protection,
    cves_in,
    dump,
    from_cloudflare,
    from_edge,
    from_f5,
    from_imperva,
    load_coverage,
)
from aegis.exposure.engine import ANY_PORT, Asset, Settings, Vuln
from aegis.posture.sources import PostureSourceError, load_json

S = Path(__file__).resolve().parents[1] / "exposure" / "samples"
R = S / "reach"


def asset(**kw):
    base = {"id": "a", "name": "a", "keys": {"a", "10.0.0.5"}, "zone": "z", "public": True, "internet_ports": [(443, 443), (22, 22)]}
    return Asset(**{**base, **kw})


def one(v, a, cov):
    (e,), _ = assess([v], [a], Settings(coverage=cov))
    return e


KEV443 = Vuln(asset="a", cve="CVE-2021-44228", title="t", port=443, kev=True)


# ---- engine semantics -----------------------------------------------------------------------------

def test_monitor_mode_waf_is_not_a_defence_and_says_so():
    e = one(KEV443, asset(), [Protection("site", "imperva", "monitor", [{"host": "10.0.0.5", "port": None}], ["CVE-2021-44228"])])
    assert (e.defended, e.tier) == ("none", "ACT_NOW") and "MONITOR mode" in e.reasons[2]


def test_blocking_waf_is_partial_on_web_ports_only():
    cov = [Protection("site", "f5", "block", [{"host": "10.0.0.5", "port": None}])]
    assert one(KEV443, asset(), cov).defended == "partial"
    ssh = Vuln(asset="a", cve="CVE-2024-6387", title="t", port=22, kev=True)
    assert one(ssh, asset(), cov).defended == "none"


def test_virtual_patch_needs_blocking_mode_and_matching_cve():
    block = [Protection("site", "imperva", "block", [{"host": "a", "port": 443}], ["CVE-2021-44228"])]
    e = one(KEV443, asset(), block)
    assert e.defended == "full" and "blocking mode" in e.reasons[2] and e.tier == "SCHEDULE"
    other = Vuln(asset="a", cve="CVE-2022-22965", title="t", port=443, kev=True)
    assert one(other, asset(), block).defended == "partial"


def test_port_specific_front_does_not_cover_other_ports():
    cov = [Protection("site", "imperva", "block", [{"host": "a", "port": 8443}], ["CVE-2021-44228"])]
    assert one(KEV443, asset(), cov).defended == "none"


def test_package_findings_match_any_front_port():
    v = Vuln(asset="a", cve="CVE-2021-44228", title="t", port=ANY_PORT, kev=True)
    cov = [Protection("site", "cloudflare", "block", [{"host": "a", "port": 443}], ["CVE-2021-44228"])]
    assert one(v, asset(), cov).defended == "full"


def test_sample_bank_story():
    vulns = loaders.load_vulns(S / "tenable_vulns.json")
    loaders.apply_intel(vulns, kev=S / "kev_sample.json", epss=S / "epss_sample.csv")
    assets = loaders.merge_assets(loaders.assets_from_aws(load_json(S / "aws_bundle.json")), loaders.assets_from_inventory(S / "inventory.csv"))
    settings = loaders.with_coverage(loaders.load_settings(S / "exposure.yaml"), [S / "waf_coverage.json"])
    ex = {(e.cve, e.asset_name): e for e in assess(vulns, assets, settings)[0]}
    log4 = ex[("CVE-2021-44228", "legacy-reports")]
    assert log4.tier == "ACT_NOW" and "MONITOR mode" in log4.reasons[2]          # has a WAF, it only logs
    assert ex[("CVE-2023-44487", "netbanking-web")].defended == "full"           # blocking virtual patch
    assert "edge" not in ex[("CVE-2017-5638", "Internet banking portal (on-prem DMZ)")].reasons[2]  # yaml virtual patch still wins


def test_lb_name_front_covers_targets():
    vulns = loaders.load_vulns(R / "aws_lb_vulns.csv")
    assets = loaders.assets_from_aws(load_json(R / "aws_lb_bundle.json"))
    cov = [Protection("cf", "cloudflare", "block", [{"host": "alb-netbanking", "port": None}], ["CVE-2022-22965"])]
    ex = {e.asset_name: e for e in assess(vulns, assets, Settings(coverage=cov))[0]}
    assert ex["netbanking-app"].defended == "full" and ex["payments-mq"].defended == "none"


def test_ingress_host_front_covers_workload():
    from aegis.exposure.k8s_reach import assets_from_k8s
    assets = assets_from_k8s(load_json(R / "k8s_export.json"))
    v = Vuln(asset="registry.bank/netbanking:4.2", cve="CVE-2022-22965", title="t", port=ANY_PORT, kev=True)
    cov = [Protection("cf", "cloudflare", "block", [{"host": "netbanking.bank.example", "port": None}], ["CVE-2022-22965"])]
    (e,), _ = assess([v], assets, Settings(coverage=cov))
    assert e.defended == "full"


def test_load_coverage_validates(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"protections": [{"name": "x", "mode": "learning", "fronts": [{"host": "a"}]}]}))
    with pytest.raises(PostureSourceError, match="block\\|monitor"):
        load_coverage(p)
    p.write_text(dump([Protection("x", "f5", "block", [{"host": "a", "port": 443}], ["cve-2021-44228"])], "test"))
    (prot,) = load_coverage(p)
    assert prot.virtual_patches == ["CVE-2021-44228"]
    with pytest.raises(PostureSourceError, match="not found"):
        load_coverage(tmp_path / "missing.json")


def test_cves_in():
    assert cves_in("VP Log4Shell cve-2021-44228 + CVE-2021-45046", None, "nothing") == ["CVE-2021-44228", "CVE-2021-45046"]


# ---- exporters against fake vendor APIs -----------------------------------------------------------

class Fake:
    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def __call__(self, method, url, json_body, headers, timeout):
        self.calls.append((method, url))
        for (m, frag), body in self.routes.items():
            if m == method and frag in url:
                return body if isinstance(body, HttpResult) else HttpResult(200, body)
        return HttpResult(404, {"errors": ["not found"]})


def test_edge_exporter_live_inline_blocks_shadow_monitors():
    t = Fake({("GET", "edge-a/__edge/health"): {"mode": "live", "inline_waf": True, "upstream": "http://10.0.1.10:8080", "asset": "edge-a"},
              ("GET", "edge-b/__edge/health"): {"mode": "shadow", "inline_waf": True, "upstream": "https://app.bank:443", "asset": "edge-b"}})
    a, b = from_edge(["http://edge-a", "http://edge-b"], t)
    assert (a.mode, a.fronts) == ("block", [{"host": "10.0.1.10", "port": 8080}])
    assert (b.mode, b.fronts) == ("monitor", [{"host": "app.bank", "port": 443}])


def test_cloudflare_exporter():
    t = Fake({
        ("GET", "/zones/z1/dns_records"): {"result": [
            {"type": "A", "name": "netbanking.bank.example", "content": "13.0.0.10", "proxied": True},
            {"type": "A", "name": "direct.bank.example", "content": "13.0.0.99", "proxied": False}]},
        ("GET", "/zones/z1/rulesets/phases/http_request_firewall_managed/entrypoint"): {"result": {"rules": [
            {"action": "execute", "enabled": True, "description": "Cloudflare Managed Ruleset"}]}},
        ("GET", "/zones/z1/rulesets/phases/http_request_firewall_custom/entrypoint"): {"result": {"rules": [
            {"action": "block", "enabled": True, "description": "VP CVE-2021-44228 jndi", "expression": "..."},
            {"action": "log", "enabled": True, "description": "watch CVE-2022-22965"},
            {"action": "block", "enabled": False, "description": "old CVE-2017-5638"}]}},
        ("GET", "/zones/z2/dns_records"): {"result": [{"type": "CNAME", "name": "api.bank.example", "content": "alb-1.elb.amazonaws.com", "proxied": True}]},
    })
    p1, p2 = from_cloudflare(["z1", "z2"], "tok", t)
    assert p1.mode == "block" and p1.virtual_patches == ["CVE-2021-44228"]
    assert {"host": "13.0.0.99", "port": None} not in p1.fronts and {"host": "13.0.0.10", "port": None} in p1.fronts
    assert p2.mode == "monitor" and {"host": "alb-1.elb.amazonaws.com", "port": None} in p2.fronts   # no rulesets (404)
    assert all(m == "GET" for m, _ in t.calls)


def test_imperva_exporter():
    t = Fake({
        ("POST", "/api/prov/v1/sites/list"): {"sites": [
            {"site_id": 1, "domain": "netbanking.bank.example", "ips": ["13.0.0.10"],
             "security": {"waf": {"rules": [{"id": "api.threats.sql_injection", "action": "api.threats.action.block_request"}]}}},
            {"site_id": 2, "domain": "reports.bank.example", "ips": ["13.0.0.30"],
             "security": {"waf": {"rules": [{"id": "api.threats.sql_injection", "action": "api.threats.action.alert"}]}}}]},
        ("GET", "/sites/1/rules"): {"data": [{"name": "VP CVE-2023-44487 rapid reset", "action": "RULE_ACTION_BLOCK", "enabled": True},
                                             {"name": "rate limit", "action": "RULE_ACTION_RATE"}]},
        ("GET", "/sites/2/rules"): {"data": []},
    })
    a, b = from_imperva("id", "key", t)
    assert (a.mode, a.virtual_patches) == ("block", ["CVE-2023-44487"]) and {"host": "13.0.0.10", "port": None} in a.fronts
    assert b.mode == "monitor"
    # the only POST is the read-only site listing
    assert [u for m, u in t.calls if m == "POST"] == ["https://my.imperva.com/api/prov/v1/sites/list"]


def test_f5_exporter():
    t = Fake({
        ("GET", "/mgmt/tm/asm/signatures"): {"items": [{"name": "VP_CVE-2021-44228_jndi", "signatureId": 300000001, "references": []}]},
        # round 7 G-7: the CVE signature counts only on the policy it is assigned to, enabled and out of staging
        ("GET", "/mgmt/tm/asm/policies/P1/signatures"): {"items": [
            {"enabled": True, "performStaging": False, "block": True, "signatureReference": {"signatureId": 300000001}}]},
        ("GET", "/mgmt/tm/asm/policies/P2/signatures"): {"items": []},
        ("GET", "/mgmt/tm/ltm/virtual"): {"items": [
            {"fullPath": "/Common/vs_netbanking", "destination": "/Common/203.0.113.10:443", "pool": "/Common/p_netbanking"},
            {"fullPath": "/Common/vs_reports", "destination": "/Common/203.0.113.30:443", "pool": ""}]},
        ("GET", "/mgmt/tm/ltm/pool/~Common~p_netbanking/members"): {"items": [{"address": "10.0.1.10", "name": "/Common/10.0.1.10:8080"}]},
        ("GET", "/mgmt/tm/asm/policies"): {"items": [
            {"id": "P1", "name": "netbanking", "enforcementMode": "blocking", "virtualServers": ["/Common/vs_netbanking"]},
            {"id": "P2", "name": "reports", "enforcementMode": "transparent", "virtualServers": ["/Common/vs_reports"]}]},
    })
    nb, rep = from_f5("https://bigip", t, token="tok")
    assert nb.mode == "block" and nb.virtual_patches == ["CVE-2021-44228"]
    assert {"host": "10.0.1.10", "port": 8080} in nb.fronts and {"host": "203.0.113.10", "port": 443} in nb.fronts
    assert rep.mode == "monitor" and rep.virtual_patches == []          # transparent policy: no virtual patch credit


def test_cli_uses_coverage(capsys):
    args = ["--vulns", str(S / "tenable_vulns.json"), "--aws-bundle", str(S / "aws_bundle.json"), "--inventory", str(S / "inventory.csv"),
            "--kev", str(S / "kev_sample.json"), "--epss", str(S / "epss_sample.csv"), "--settings", str(S / "exposure.yaml"),
            "--waf-coverage", str(S / "waf_coverage.json"), "--json"]
    assert cli(args) == 0
    rep = json.loads(capsys.readouterr().out)
    log4 = next(e for e in rep["exposures"] if e["cve"] == "CVE-2021-44228")
    assert log4["tier"] == "ACT_NOW" and "MONITOR mode" in log4["reasons"][2]
