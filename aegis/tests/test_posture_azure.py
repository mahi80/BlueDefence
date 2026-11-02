"""Azure posture: one subscription from an export bundle or live read-only `az`, plus the azurerm IaC gate."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from aegis.posture import azure_cspm as az
from aegis.posture import iac_policy, sources, summarize
from aegis.posture.__main__ import main as cli

SAMPLES = Path(__file__).resolve().parents[1] / "posture" / "samples"
SUB = "/subscriptions/00000000-1111-2222-3333-444444444444"


@pytest.fixture
def bundle():
    return sources.load_json(SAMPLES / "azure_bundle.json")


def where(f, fid):
    return sorted(x.affected_component for x in f if x.id == fid)


def test_sample_subscription(bundle):
    f = az.scan(bundle)
    assert summarize(f) == {"critical": 4, "high": 7, "medium": 10, "low": 2, "info": 0}
    assert all(x.scanner == "azure_cspm" and x.risk_score for x in f)


def test_clean_resources_are_not_flagged(bundle):
    comps = " ".join(x.affected_component for x in az.scan(bundle))
    for clean in ("wbledgerbackup", "nsg-web", "sql-cards", "kv-core", "aks-core", "sp-terraform", "anita.dba", "VM Operator"):
        assert clean not in comps, clean


def test_internet_open_databases(bundle):
    f = az.scan(bundle)
    assert where(f, "AZ-SQL-OPEN-TO-INTERNET") == ["sql-loans"]
    assert where(f, "AZ-POSTGRES-OPEN-TO-INTERNET") == ["pg-upi-switch"]
    assert where(f, "AZ-SQL-ALLOW-ALL-AZURE") == ["sql-loans"]
    assert where(f, "AZ-NSG-DB-PORT-OPEN") == ["nsg-core-db (rg-core) rule allow-sql"]


def test_public_network_disabled_overrides_firewall_rules():
    s = {"name": "s", "publicNetworkAccess": "Disabled",
         "firewall_rules": [{"name": "all", "startIpAddress": "0.0.0.0", "endIpAddress": "255.255.255.255"}]}
    assert az.scan({"sql_servers": [s]}) == []


def test_narrow_firewall_range_is_fine():
    s = {"name": "s", "firewall_rules": [{"name": "office", "startIpAddress": "203.0.113.0", "endIpAddress": "203.0.113.255"}]}
    assert az.scan({"sql_servers": [s]}) == []


@pytest.mark.parametrize("rule,expect", [
    ({"access": "Allow", "direction": "Inbound", "sourceAddressPrefix": "Internet", "destinationPortRange": "*"}, "AZ-NSG-ALL-PORTS-OPEN"),
    ({"access": "Allow", "direction": "Inbound", "sourceAddressPrefix": "*", "destinationPortRange": "6000-6500"}, "AZ-NSG-DB-PORT-OPEN"),  # Redis 6379
    ({"access": "Allow", "direction": "Inbound", "sourceAddressPrefixes": ["10.0.0.0/8", "0.0.0.0/0"], "destinationPortRanges": ["22"]}, "AZ-NSG-ADMIN-PORT-OPEN"),
    ({"access": "Deny", "direction": "Inbound", "sourceAddressPrefix": "*", "destinationPortRange": "*"}, None),
    ({"access": "Allow", "direction": "Outbound", "sourceAddressPrefix": "*", "destinationPortRange": "*"}, None),
    ({"access": "Allow", "direction": "Inbound", "sourceAddressPrefix": "VirtualNetwork", "destinationPortRange": "3389"}, None),
])
def test_nsg_rules(rule, expect):
    f = az.scan({"network_security_groups": [{"name": "n", "securityRules": [{"name": "r", **rule}]}]})
    assert [x.id for x in f] == ([expect] if expect else [])


def test_az_properties_nesting_is_read():
    nsg = {"name": "n", "properties": {"securityRules": [{"name": "r", "properties": {
        "access": "Allow", "direction": "Inbound", "sourceAddressPrefix": "*", "destinationPortRange": "22"}}]}}
    assert [x.id for x in az.scan({"network_security_groups": [nsg]})] == ["AZ-NSG-ADMIN-PORT-OPEN"]


def test_aks_rbac_off_is_critical():
    (f,) = [x for x in az.scan({"aks_clusters": [{"name": "c", "enableRbac": False, "disableLocalAccounts": True,
                                                  "apiServerAccessProfile": {"enablePrivateCluster": True},
                                                  "networkProfile": {"networkPolicy": "azure"}}]})]
    assert (f.id, f.severity) == ("AZ-AKS-RBAC-OFF", "critical")


def test_authorized_ip_ranges_close_the_public_api():
    c = {"name": "c", "apiServerAccessProfile": {"authorizedIpRanges": ["203.0.113.0/24"]}, "disableLocalAccounts": True,
         "networkProfile": {"networkPolicy": "calico"}}
    assert az.scan({"aks_clusters": [c]}) == []


def test_standing_privilege_only_for_users_at_subscription_scope(bundle):
    assert where(az.scan(bundle), "AZ-RBAC-STANDING-PRIVILEGE") == ["ravi.ops@bank.example — Owner"]


def test_logging_and_defender(bundle):
    ids = {x.id for x in az.scan(bundle)}
    assert {"AZ-ACTIVITY-LOG-NOT-EXPORTED", "AZ-DEFENDER-PLANS-OFF"} <= ids
    bundle["activity_log_diagnostics"] = [{"name": "to-law", "logs": [{"category": "Administrative", "enabled": True}]}]
    bundle["defender_plans"] = [{"name": n, "pricingTier": "Standard"} for n in az.DEFENDER_PLANS]
    ids = {x.id for x in az.scan(bundle)}
    assert not {"AZ-ACTIVITY-LOG-NOT-EXPORTED", "AZ-DEFENDER-PLANS-OFF"} & ids


def test_all_logs_category_group_counts_as_exported():
    b = {"activity_log_diagnostics": [{"name": "x", "logs": [{"categoryGroup": "allLogs", "enabled": True}]}]}
    assert az.scan(b) == []


def test_gaps_always_name_entra_id():
    gaps = az.coverage_gaps({"subscription": {}})
    assert gaps[-1].startswith("entra_id") and "storage_accounts" in gaps


# ---- live / export via the az CLI ---------------------------------------------------------------

def fake_az(bundle, calls, fail=None):
    sub = bundle["subscription"]
    table = {
        ("account", "show"): {"id": sub["id"], "name": sub["name"], "tenantId": "t"},
        ("storage", "account", "list"): bundle["storage_accounts"],
        ("network", "nsg", "list"): bundle["network_security_groups"],
        ("sql", "server", "list"): [{k: v for k, v in s.items() if k not in ("firewall_rules", "audit_state")} for s in bundle["sql_servers"]],
        ("postgres", "flexible-server", "list"): [{k: v for k, v in s.items() if k != "firewall_rules"} for s in bundle["postgres_servers"]],
        ("mysql", "flexible-server", "list"): [],
        ("keyvault", "list"): [{"name": v["name"], "resourceGroup": v["resourceGroup"]} for v in bundle["key_vaults"]],
        ("aks", "list"): bundle["aks_clusters"],
        ("security", "pricing", "list"): {"value": bundle["defender_plans"]},
        ("monitor", "diagnostic-settings", "subscription"): {"value": []},
        ("role", "assignment", "list"): bundle["role_assignments"],
        ("role", "definition", "list"): bundle["custom_roles"],
        ("vm", "list"): [], ("network", "nic", "list"): [], ("network", "vnet", "list"): [], ("network", "lb", "list"): [],
    }

    def run(cmd, **kw):
        args = [a for a in cmd[1:] if a not in ("--only-show-errors", "-o", "json")]
        calls.append(args)
        if fail and fail in " ".join(args):
            return subprocess.CompletedProcess(cmd, 1, "", "AuthorizationFailed: no read permission")
        key = tuple(args[:3]) if tuple(args[:3]) in table else tuple(args[:2])
        if args[:4] == ["sql", "server", "firewall-rule", "list"]:
            out = next(s["firewall_rules"] for s in bundle["sql_servers"] if s["name"] == args[args.index("--server") + 1])
        elif args[:4] == ["sql", "server", "audit-policy", "show"]:
            out = {"state": next(s["audit_state"] for s in bundle["sql_servers"] if s["name"] == args[args.index("--name") + 1])}
        elif args[1:4] == ["flexible-server", "firewall-rule", "list"]:
            out = next(s["firewall_rules"] for s in bundle["postgres_servers"] if s["name"] == args[args.index("--name") + 1])
        elif args[:2] == ["keyvault", "show"]:
            out = next(v for v in bundle["key_vaults"] if v["name"] == args[args.index("--name") + 1])
        else:
            out = table[key]
        return subprocess.CompletedProcess(cmd, 0, json.dumps(out), "")
    return run


@pytest.fixture
def az_cli(monkeypatch, bundle):
    calls: list[list[str]] = []
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/az")
    monkeypatch.setattr(subprocess, "run", fake_az(bundle, calls))
    return calls


def test_live_needs_flag(monkeypatch, az_cli):
    monkeypatch.delenv("AEGIS_POSTURE_LIVE", raising=False)
    with pytest.raises(sources.PostureSourceError, match="AEGIS_POSTURE_LIVE"):
        sources.collect_azure()


def test_collected_bundle_matches_export_and_is_read_only(monkeypatch, az_cli, bundle):
    monkeypatch.setenv("AEGIS_POSTURE_LIVE", "1")
    b = sources.collect_azure("bank-prod-centralindia")
    assert summarize(az.scan(b)) == summarize(az.scan(bundle))
    verbs = {next((a for a in c if a in ("list", "show")), c[0]) for c in az_cli}
    assert verbs == {"list", "show"}                       # nothing but list / show
    assert all(c[-2:] == ["--subscription", "bank-prod-centralindia"] for c in az_cli)


def test_az_permission_error_drops_one_section(monkeypatch, bundle):
    monkeypatch.setenv("AEGIS_POSTURE_LIVE", "1")
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/az")
    monkeypatch.setattr(subprocess, "run", fake_az(bundle, [], fail="role assignment"))
    b = sources.collect_azure()
    assert "role_assignments" not in b and "AuthorizationFailed" in b["collection_errors"]["role_assignments"]
    ids = {f.id for f in az.scan(b)}
    assert "AZ-RBAC-STANDING-PRIVILEGE" not in ids and "AZ-SQL-OPEN-TO-INTERNET" in ids
    assert any(g.startswith("role_assignments (access denied") for g in az.coverage_gaps(b))


def test_az_account_show_failure_stops_the_collection(monkeypatch, bundle):
    monkeypatch.setenv("AEGIS_POSTURE_LIVE", "1")
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/az")
    monkeypatch.setattr(subprocess, "run", fake_az(bundle, [], fail="account show"))
    with pytest.raises(sources.PostureSourceError, match="AuthorizationFailed"):
        sources.collect_azure()


def test_missing_az_cli(monkeypatch):
    monkeypatch.setenv("AEGIS_POSTURE_LIVE", "1")
    monkeypatch.setattr("shutil.which", lambda _: None)
    with pytest.raises(sources.PostureSourceError, match="az CLI"):
        sources.collect_azure()


def test_export_then_scan_via_cli(monkeypatch, az_cli, tmp_path, capsys):
    monkeypatch.delenv("AEGIS_POSTURE_LIVE", raising=False)
    out = tmp_path / "az.json"
    assert cli(["export-azure", "--out", str(out)]) == 0
    assert "bank-prod-centralindia" in capsys.readouterr().out
    assert cli(["azure", "--bundle", str(out), "--json", "--fail-on", "critical"]) == 1
    rep = json.loads(capsys.readouterr().out)
    assert rep["scan"] == "azure" and rep["summary"]["critical"] == 4 and "entra_id" in rep["notes"][0]
    assert cli(["azure"]) == 2


# ---- azurerm through the policy-as-code gate ----------------------------------------------------

def rc(addr, typ, after):
    return {"resource_changes": [{"address": addr, "type": typ, "change": {"actions": ["create"], "after": after}}]}


@pytest.mark.parametrize("typ,after,expect", [
    ("azurerm_storage_account", {"allow_nested_items_to_be_public": True, "https_traffic_only_enabled": True,
                                 "shared_access_key_enabled": False, "network_rules": [{"default_action": "Deny"}]}, "AZ-STORAGE-PUBLIC-BLOB"),
    ("azurerm_storage_account", {"allow_nested_items_to_be_public": False, "enable_https_traffic_only": False,
                                 "shared_access_key_enabled": False, "network_rules": [{"default_action": "Deny"}]}, "AZ-STORAGE-HTTP-ALLOWED"),
    ("azurerm_network_security_rule", {"name": "r", "access": "Allow", "direction": "Inbound", "source_address_prefix": "*",
                                       "destination_port_range": "5432"}, "AZ-NSG-DB-PORT-OPEN"),
    ("azurerm_network_security_group", {"security_rule": [{"name": "rdp", "access": "Allow", "direction": "Inbound",
                                                           "source_address_prefix": "Internet", "destination_port_range": "3389"}]}, "AZ-NSG-ADMIN-PORT-OPEN"),
    ("azurerm_mssql_firewall_rule", {"name": "all", "start_ip_address": "0.0.0.0", "end_ip_address": "255.255.255.255"}, "AZ-SQL-OPEN-TO-INTERNET"),
    ("azurerm_postgresql_flexible_server_firewall_rule", {"name": "all", "start_ip_address": "0.0.0.0", "end_ip_address": "255.255.255.255"}, "AZ-POSTGRES-OPEN-TO-INTERNET"),
    ("azurerm_mssql_server", {"minimum_tls_version": "1.0", "public_network_access_enabled": False}, "AZ-SQL-WEAK-TLS"),
    ("azurerm_key_vault", {"purge_protection_enabled": False, "rbac_authorization_enabled": True, "public_network_access_enabled": False}, "AZ-KEYVAULT-NO-PURGE-PROTECTION"),
    ("azurerm_kubernetes_cluster", {"private_cluster_enabled": False, "local_account_disabled": True,
                                    "network_profile": [{"network_policy": "azure"}]}, "AZ-AKS-PUBLIC-API"),
    ("azurerm_role_definition", {"name": "super", "permissions": [{"actions": ["*"]}], "assignable_scopes": [SUB]}, "AZ-CUSTOM-OWNER-ROLE"),
    ("azurerm_role_assignment", {"principal_id": "u1", "principal_type": "User", "role_definition_name": "Owner", "scope": SUB}, "AZ-RBAC-STANDING-PRIVILEGE"),
    ("azurerm_security_center_subscription_pricing", {"tier": "Free", "resource_type": "SqlServers"}, "AZ-DEFENDER-PLANS-OFF"),
])
def test_azurerm_rules(typ, after, expect):
    f = iac_policy.scan_plan(rc(f"{typ}.x", typ, after))
    assert [x.id for x in f] == [expect] and f[0].resource == f"{typ}.x" and f[0].scanner == "iac_policy"


@pytest.mark.parametrize("typ,after", [
    ("azurerm_storage_account", {"allow_nested_items_to_be_public": False, "https_traffic_only_enabled": True, "min_tls_version": "TLS1_2",
                                 "shared_access_key_enabled": False, "public_network_access_enabled": False}),
    ("azurerm_network_security_rule", {"name": "r", "access": "Allow", "direction": "Inbound", "source_address_prefix": "10.0.0.0/8",
                                       "destination_port_range": "22"}),
    ("azurerm_mssql_firewall_rule", {"name": "office", "start_ip_address": "203.0.113.10", "end_ip_address": "203.0.113.20"}),
    ("azurerm_key_vault", {"purge_protection_enabled": True, "rbac_authorization_enabled": True, "public_network_access_enabled": False}),
    ("azurerm_kubernetes_cluster", {"private_cluster_enabled": True, "local_account_disabled": True, "network_profile": [{"network_policy": "cilium"}]}),
    ("azurerm_role_assignment", {"principal_id": "sp", "principal_type": "ServicePrincipal", "role_definition_name": "Owner", "scope": SUB}),
])
def test_azurerm_safe(typ, after):
    assert iac_policy.scan_plan(rc(f"{typ}.x", typ, after)) == []


def test_separate_storage_network_rules_resource_defers_the_network_check():
    sa = {"allow_nested_items_to_be_public": False, "https_traffic_only_enabled": True, "shared_access_key_enabled": False}
    alone = rc("azurerm_storage_account.a", "azurerm_storage_account", sa)
    assert [x.id for x in iac_policy.scan_plan(alone)] == ["AZ-STORAGE-OPEN-NETWORK"]
    alone["resource_changes"].append({"address": "azurerm_storage_account_network_rules.a", "type": "azurerm_storage_account_network_rules",
                                      "change": {"actions": ["create"], "after": {"default_action": "Deny"}}})
    assert iac_policy.scan_plan(alone) == []


def test_runner_azure_scan(tmp_path):
    from datetime import UTC, datetime

    from aegis.posture import runner
    cfg = tmp_path / "posture.yaml"
    cfg.write_text(f"store: {tmp_path / 'store'}\nscans:\n  - name: azure-prod\n    type: azure\n"
                   f"    bundle: {SAMPLES / 'azure_bundle.json'}\n")
    r = runner.run_once(runner.load_config(cfg), now=datetime(2026, 11, 2, tzinfo=UTC))
    (sc,) = r["scans"]
    assert sc["status"] == "ok" and sc["summary"]["critical"] == 4 and any("entra_id" in n for n in sc["notes"])
    assert r["counts"]["open"] == 23
