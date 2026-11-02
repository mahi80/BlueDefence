"""Exposure reachability through load balancers (AWS, Azure), Azure NSGs and Kubernetes Services / Ingress."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegis.exposure import assess, loaders
from aegis.exposure.__main__ import main as cli
from aegis.exposure.azure_reach import assets_from_azure, nsg_allowed
from aegis.exposure.engine import ANY_PORT, Asset, Vuln
from aegis.exposure.k8s_reach import assets_from_k8s
from aegis.posture.sources import load_json

R = Path(__file__).resolve().parents[1] / "exposure" / "samples" / "reach"
KEV = R.parent / "kev_sample.json"


def run(vulns, assets, **kw):
    ex, _ = assess(vulns, assets, **kw)
    return {(e.asset_name, e.port): e for e in ex}


# ---- AWS load balancers ---------------------------------------------------------------------------

@pytest.fixture
def aws():
    return run(loaders.load_vulns(R / "aws_lb_vulns.csv"), loaders.assets_from_aws(load_json(R / "aws_lb_bundle.json")))


def test_private_instance_behind_public_nlb_is_internet_facing(aws):
    e = aws[("payments-mq", 5672)]
    assert (e.tier, e.reach) == ("ACT_NOW", "internet") and "via load balancer nlb-mq" in e.reasons[1]


def test_alb_target_port_and_aws_waf(aws):
    e = aws[("netbanking-app", 8080)]
    assert (e.tier, e.defended) == ("ACT", "partial") and "listener 443 → port 8080" in e.reasons[1]


def test_internal_alb_does_not_expose(aws):
    e = aws[("ops-admin", 8443)]
    assert e.reach == "one_hop" and "load balancer" not in e.reasons[1]


def test_alb_listener_blocked_by_its_security_group():
    b = load_json(R / "aws_lb_bundle.json")
    b["load_balancers"][0]["listeners"] = [{"Port": 8443}]   # sg-alb only allows 443
    (app,) = [a for a in loaders.assets_from_aws(b) if a.id == "i-app"]
    assert not app.public and not app.internet_ports


# ---- Azure NSGs + load balancer ---------------------------------------------------------------------

@pytest.fixture
def azure():
    return run(loaders.load_vulns(R / "azure_vulns.csv"), assets_from_azure(load_json(R / "azure_bundle.json")))


def test_subnet_and_nic_nsg_must_both_allow(azure):
    assert azure[("vm-web", 443)].reach == "internet"
    rdp = azure[("vm-web", 3389)]
    assert rdp.reach == "one_hop" and "port 3389 is reachable from the internet" not in rdp.reasons[1]


def test_public_lb_exposes_only_ports_the_backend_nsg_admits(azure):
    assert azure[("vm-api", 8080)].tier == "ACT_NOW" and "via load balancer lb-api (frontend :80 → port 8080)" in azure[("vm-api", 8080)].reasons[1]
    assert azure[("vm-api", 8443)].reach == "one_hop"   # 443→8443 rule exists, subnet NSG does not admit 8443


def test_zone_label_is_the_vnet_name(azure):
    assert "zone vnet-bank from" in azure[("vm-db", 1433)].reasons[1]


def test_nsg_priority_first_match_wins():
    nsg = {"securityRules": [
        {"name": "deny22", "priority": 100, "direction": "Inbound", "access": "Deny", "sourceAddressPrefix": "*", "destinationPortRange": "22"},
        {"name": "allow", "priority": 200, "direction": "Inbound", "access": "Allow", "sourceAddressPrefix": "Internet", "destinationPortRange": "20-25"},
        {"name": "outbound", "priority": 50, "direction": "Outbound", "access": "Allow", "sourceAddressPrefix": "*", "destinationPortRange": "*"}]}
    assert nsg_allowed(nsg, "internet") == [(20, 21), (23, 25)]
    assert nsg_allowed(None, "internet") is None


def test_default_rules_allow_vnet_and_deny_internet():
    assert nsg_allowed({"securityRules": []}, "internet") == []
    assert nsg_allowed({"securityRules": []}, "vnet") == [(0, 65535)]


def test_no_nsg_and_public_ip_is_closed_to_internet():
    b = load_json(R / "azure_bundle.json")
    b["network_security_groups"], b["virtual_networks"] = [], []
    (web,) = [a for a in assets_from_azure(b) if a.name == "vm-web"]
    assert web.internet_ports == [] and web.lateral == [(0, 65535, frozenset({"*"}))]


# ---- Kubernetes -------------------------------------------------------------------------------------

@pytest.fixture
def k8s_assets():
    return assets_from_k8s(load_json(R / "k8s_export.json"), cluster="prod-aks")


def by_name(assets, ref):
    (a,) = [x for x in assets if x.id == ref]
    return a


def test_loadbalancer_service_exposes_target_port(k8s_assets):
    a = by_name(k8s_assets, "Deployment/web/legacy-api")
    assert a.public and a.internet_ports == [(9443, 9443)] and "LoadBalancer :443 → 9443" in a.internet_via[(9443, 9443)]


def test_ingress_resolves_named_target_port_and_waf(k8s_assets):
    a = by_name(k8s_assets, "Deployment/web/netbanking")
    assert a.internet_ports == [(8080, 8080)] and a.waf and "Ingress web/netbanking" in a.internet_via[(8080, 8080)]


def test_internal_lb_nodeport_and_policed_namespace(k8s_assets):
    assert not by_name(k8s_assets, "Deployment/web/admin").public          # internal LB annotation
    assert not by_name(k8s_assets, "Deployment/web/debug").public          # NodePort, nodes private
    ledger = by_name(k8s_assets, "Deployment/core/ledger")
    assert not ledger.public and ledger.lateral == [] and ledger.role == "core_banking_db"


def test_nodeport_with_public_nodes():
    a = by_name(assets_from_k8s(load_json(R / "k8s_export.json"), public_nodes=True), "Deployment/web/debug")
    assert a.internet_ports == [(22, 22)] and "NodePort 30022" in a.internet_via[(22, 22)]


def test_internal_ingress_is_ignored():
    exp = load_json(R / "k8s_export.json")
    for o in exp["items"]:
        if o["kind"] == "Ingress":
            o["metadata"]["annotations"]["alb.ingress.kubernetes.io/scheme"] = "internal"
    assert not by_name(assets_from_k8s(exp), "Deployment/web/netbanking").public


def test_trivy_findings_land_on_workloads_and_are_capped(k8s_assets):
    vulns = [v for f in ("trivy_legacy_api.json", "trivy_netbanking.json", "trivy_ledger.json") for v in loaders.load_vulns(R / f)]
    assert len(vulns) == 3 and all(v.port == ANY_PORT for v in vulns)        # LOW zlib finding dropped
    loaders.apply_intel(vulns, kev=KEV)
    ex = {e.asset_name: e for e in assess(vulns, k8s_assets)[0]}
    assert ex["Deployment/web/legacy-api"].tier == "ACT" and "capped at ACT" in ex["Deployment/web/legacy-api"].reasons[1]
    assert ex["Deployment/web/netbanking"].defended == "partial"
    assert ex["Deployment/core/ledger"].reach == "isolated"


def test_image_short_name_matches():
    a = Asset(id="w", keys={"registry.bank/team/app:1.2", "app:1.2"}, zone="z", public=True, internet_ports=[(443, 443)])
    (e,), _ = assess([Vuln(asset="app:1.2", cve="C", title="t", port=ANY_PORT, kev=True)], [a])
    assert e.reach == "internet"


def test_export_kinds_include_services_and_ingresses():
    from aegis.posture.k8s_posture import EXPORT_COMMAND, EXPORT_KINDS
    assert "services" in EXPORT_KINDS and "ingresses" in EXPORT_KINDS and "secrets" not in EXPORT_COMMAND


# ---- CLI --------------------------------------------------------------------------------------------

def test_cli_all_three(capsys):
    assert cli(["--vulns", str(R / "aws_lb_vulns.csv"), "--aws-bundle", str(R / "aws_lb_bundle.json"),
                "--vulns", str(R / "azure_vulns.csv"), "--azure-bundle", str(R / "azure_bundle.json"),
                "--vulns", str(R / "trivy_legacy_api.json"), "--k8s-export", f"prod-aks={R / 'k8s_export.json'}",
                "--kev", str(KEV)]) == 0
    out = capsys.readouterr().out
    assert "→ 3 ACT NOW" in out and "Deployment/web/legacy-api (image)" in out
