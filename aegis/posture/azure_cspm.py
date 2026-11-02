"""Azure posture — standing misconfigurations in one subscription.

Same contract as the AWS CSPM: one JSON bundle (see ``BUNDLE_KEYS``), produced by the bank with
``python -m aegis.posture export-azure`` under its own ``az login`` (Reader + Security Reader is
enough), or collected by AEGIS with the same read-only ``az`` calls when ``AEGIS_POSTURE_LIVE=1``.
A missing section is reported as *not checked*, never as clean.

Entra ID (MFA, guest users, conditional access) needs Microsoft Graph and is not covered here; the
report says so.

Control references follow the CIS Microsoft Azure Foundations Benchmark topics; section numbers
differ between benchmark versions, so the topic is cited rather than the number.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from .base import PostureFinding, sort_findings
from .cspm import ADMIN_PORTS, DATA_PORTS

CIS = "CIS Microsoft Azure Foundations"

BUNDLE_KEYS = (
    "storage_accounts",          # az storage account list
    "network_security_groups",   # az network nsg list
    "sql_servers",               # az sql server list + firewall-rule list + audit-policy show, merged
    "postgres_servers",          # az postgres flexible-server list + firewall-rule list, merged
    "mysql_servers",             # az mysql flexible-server list + firewall-rule list, merged
    "key_vaults",                # az keyvault show per vault
    "aks_clusters",              # az aks list
    "defender_plans",            # az security pricing list
    "activity_log_diagnostics",  # az monitor diagnostic-settings subscription list
    "role_assignments",          # az role assignment list --all
    "custom_roles",              # az role definition list --custom-role-only true
)

INTERNET = {"*", "internet", "any", "0.0.0.0/0", "0.0.0.0", "::/0"}
PRIVILEGED_ROLES = {"Owner", "Contributor", "User Access Administrator", "Role Based Access Control Administrator"}
DEFENDER_PLANS = ("VirtualMachines", "SqlServers", "StorageAccounts", "KeyVaults", "Containers", "Arm",
                  "OpenSourceRelationalDatabases", "AppServices")


def _f(**kw: Any) -> PostureFinding:
    kw.setdefault("confidence", 0.95)
    kw.setdefault("category", "misconfig")
    return PostureFinding(scanner="azure_cspm", **kw)


def _p(o: dict) -> dict:
    """az returns some resources flat and some under ``properties``; read both."""
    return {**o, **(o.get("properties") or {})}


def _name(o: dict) -> str:
    return o.get("name") or (o.get("id") or "?").rsplit("/", 1)[-1]


def _sub_scope(scope: str) -> bool:
    parts = [x for x in (scope or "").split("/") if x]
    return len(parts) == 2 and parts[0].lower() == "subscriptions" or scope in ("/",)


# ---- network --------------------------------------------------------------------------------------

def _port_ranges(rule: dict) -> list[tuple[int, int]] | None:
    """None means all ports."""
    vals = [rule.get("destinationPortRange")] + list(rule.get("destinationPortRanges") or [])
    out = []
    for v in vals:
        if v in (None, ""):
            continue
        v = str(v)
        if v == "*":
            return None
        lo, _, hi = v.partition("-")
        try:
            out.append((int(lo), int(hi or lo)))
        except ValueError:
            continue
    return out


def _internet_sources(rule: dict) -> list[str]:
    vals = [rule.get("sourceAddressPrefix")] + list(rule.get("sourceAddressPrefixes") or [])
    return [str(v) for v in vals if v is not None and str(v).lower() in INTERNET]


def _nsg_findings(nsg: dict, sub: str) -> list[PostureFinding]:
    out: list[PostureFinding] = []
    n = _p(nsg)
    label = f"{_name(nsg)} ({n.get('resourceGroup', '?')})"
    for r in n.get("securityRules") or []:
        r = _p(r)
        if str(r.get("direction", "")).lower() != "inbound" or str(r.get("access", "")).lower() != "allow":
            continue
        srcs = _internet_sources(r)
        if not srcs:
            continue
        src, rname = ", ".join(srcs), r.get("name", "?")
        rid = r.get("id") or f"{nsg.get('id', label)}/securityRules/{rname}"
        ranges = _port_ranges(r)
        if ranges is None:
            out.append(_f(id="AZ-NSG-ALL-PORTS-OPEN", severity="critical", resource=rid, affected_component=f"{label} rule {rname}",
                          control=f"{CIS} — Networking", evidence=f"inbound rule allows all ports from {src}",
                          recommended_remediation="Remove the any-port rule; allow only the ports the workload serves, from known ranges"))
            continue
        hits = lambda ports, rr=ranges: [f"{nm} {p}" for p, nm in ports.items() if any(lo <= p <= hi for lo, hi in rr)]
        if data := hits(DATA_PORTS):
            out.append(_f(id="AZ-NSG-DB-PORT-OPEN", severity="critical", resource=rid, affected_component=f"{label} rule {rname}",
                          evidence=f"data-store port(s) open to {src}: {', '.join(data)}",
                          recommended_remediation="Never expose databases to the internet; use Private Endpoints and allow only the app subnet"))
        if admin := hits(ADMIN_PORTS):
            out.append(_f(id="AZ-NSG-ADMIN-PORT-OPEN", severity="high", resource=rid, affected_component=f"{label} rule {rname}",
                          control=f"{CIS} — Networking (RDP / SSH from the internet)",
                          evidence=f"remote-admin port(s) open to {src}: {', '.join(admin)}",
                          recommended_remediation="Close RDP/SSH to the internet; use Azure Bastion or just-in-time VM access"))
    return out


# ---- data stores ----------------------------------------------------------------------------------

def _open_firewall(rules: list[dict]) -> tuple[list[str], list[str]]:
    """(rules allowing the whole internet, rules allowing all Azure services)."""
    world, azure = [], []
    for r in rules or []:
        r = _p(r)
        start, end = str(r.get("startIpAddress", "")), str(r.get("endIpAddress", ""))
        name = r.get("name", "?")
        if start == "0.0.0.0" and end == "0.0.0.0":
            azure.append(name)
            continue
        try:
            span = int(ipaddress.ip_address(end)) - int(ipaddress.ip_address(start))
        except ValueError:
            continue
        if span >= 2 ** 24 or (start == "0.0.0.0" and end == "255.255.255.255"):
            world.append(f"{name} ({start}–{end})")
    return world, azure


def _db_findings(servers: list[dict], kind: str, label: str) -> list[PostureFinding]:
    out: list[PostureFinding] = []
    for s in servers:
        p = _p(s)
        nm, rid = _name(s), s.get("id") or _name(s)
        net = p.get("network") or {}
        public = str(p.get("publicNetworkAccess") or net.get("publicNetworkAccess") or "Enabled").lower() == "enabled"
        world, azure = _open_firewall(s.get("firewall_rules") or [])
        if public and world:
            out.append(_f(id=f"AZ-{kind}-OPEN-TO-INTERNET", severity="critical", resource=rid, affected_component=nm,
                          control=f"{CIS} — Database services",
                          evidence=f"{label} accepts connections from the internet: firewall rule {', '.join(world)}",
                          recommended_remediation="Delete the rule; disable public network access and use a Private Endpoint"))
        if public and azure:
            out.append(_f(id=f"AZ-{kind}-ALLOW-ALL-AZURE", severity="medium", resource=rid, affected_component=nm,
                          control=f"{CIS} — Database services",
                          evidence=f"'Allow Azure services' is on ({', '.join(azure)}): any Azure tenant's resources can reach it",
                          recommended_remediation="Turn off 'Allow Azure services and resources'; allow specific VNets or Private Endpoints"))
        tls = str(p.get("minimalTlsVersion") or p.get("minimumTlsVersion") or "")
        if tls and tls.replace("TLS", "").replace("_", ".").strip(".") in ("1.0", "1.1"):
            out.append(_f(id=f"AZ-{kind}-WEAK-TLS", severity="medium", resource=rid, affected_component=nm,
                          evidence=f"minimum TLS version is {tls}", recommended_remediation="Require TLS 1.2 or later"))
        if kind == "SQL" and str(s.get("audit_state", "")).lower() == "disabled":
            out.append(_f(id="AZ-SQL-AUDITING-OFF", severity="medium", resource=rid, affected_component=nm,
                          control=f"{CIS} — Database services (auditing)", evidence="server auditing is disabled",
                          recommended_remediation="Enable server auditing to Log Analytics or a locked-down storage account (90+ days)"))
    return out


# ---- the scan -------------------------------------------------------------------------------------

def scan(bundle: dict) -> list[PostureFinding]:
    out: list[PostureFinding] = []
    sub = (bundle.get("subscription") or {}).get("id", "?")
    sub_label = (bundle.get("subscription") or {}).get("name") or sub

    for sa in bundle.get("storage_accounts", []):
        p, nm, rid = _p(sa), _name(sa), sa.get("id") or _name(sa)
        acl = p.get("networkRuleSet") or p.get("networkAcls") or {}
        if p.get("allowBlobPublicAccess") is True:
            out.append(_f(id="AZ-STORAGE-PUBLIC-BLOB", severity="high", resource=rid, affected_component=nm,
                          control=f"{CIS} — Storage accounts", evidence="anonymous public read is allowed on blob containers",
                          recommended_remediation="Set allowBlobPublicAccess=false; serve public content through a CDN"))
        if p.get("enableHttpsTrafficOnly") is False:
            out.append(_f(id="AZ-STORAGE-HTTP-ALLOWED", severity="high", resource=rid, affected_component=nm,
                          control=f"{CIS} — Storage accounts (secure transfer)", evidence="secure transfer (HTTPS only) is off",
                          recommended_remediation="Enable 'Secure transfer required'"))
        if str(p.get("minimumTlsVersion", "TLS1_2")) in ("TLS1_0", "TLS1_1"):
            out.append(_f(id="AZ-STORAGE-WEAK-TLS", severity="medium", resource=rid, affected_component=nm,
                          evidence=f"minimum TLS version is {p.get('minimumTlsVersion')}", recommended_remediation="Set minimum TLS to 1.2"))
        if str(acl.get("defaultAction", "Allow")).lower() == "allow" and str(p.get("publicNetworkAccess", "Enabled")).lower() != "disabled":
            out.append(_f(id="AZ-STORAGE-OPEN-NETWORK", severity="medium", resource=rid, affected_component=nm,
                          control=f"{CIS} — Storage accounts (default network access)",
                          evidence="storage firewall default action is Allow: reachable from any network",
                          recommended_remediation="Set the default action to Deny; allow selected VNets / Private Endpoints"))
        if p.get("allowSharedKeyAccess") is not False and "allowSharedKeyAccess" in p:
            out.append(_f(id="AZ-STORAGE-SHARED-KEY", severity="low", resource=rid, affected_component=nm,
                          evidence="shared-key (account key) authorization is allowed",
                          recommended_remediation="Disable shared-key access; use Entra ID authorization"))

    for nsg in bundle.get("network_security_groups", []):
        out.extend(_nsg_findings(nsg, sub))

    out.extend(_db_findings(bundle.get("sql_servers", []), "SQL", "Azure SQL server"))
    out.extend(_db_findings(bundle.get("postgres_servers", []), "POSTGRES", "PostgreSQL flexible server"))
    out.extend(_db_findings(bundle.get("mysql_servers", []), "MYSQL", "MySQL flexible server"))

    for kv in bundle.get("key_vaults", []):
        p, nm, rid = _p(kv), _name(kv), kv.get("id") or _name(kv)
        if p.get("enableSoftDelete") is False or p.get("enablePurgeProtection") is not True:
            out.append(_f(id="AZ-KEYVAULT-NO-PURGE-PROTECTION", severity="medium", resource=rid, affected_component=nm,
                          control=f"{CIS} — Key Vault (recoverable)",
                          evidence="purge protection is off: a compromised admin can permanently destroy keys and secrets",
                          recommended_remediation="Enable soft delete and purge protection"))
        acls = p.get("networkAcls") or {}
        if str(p.get("publicNetworkAccess", "Enabled")).lower() == "enabled" and str(acls.get("defaultAction", "Allow")).lower() == "allow":
            out.append(_f(id="AZ-KEYVAULT-OPEN-NETWORK", severity="medium", resource=rid, affected_component=nm,
                          evidence="Key Vault is reachable from any network",
                          recommended_remediation="Set the firewall default action to Deny; use a Private Endpoint"))
        if p.get("enableRbacAuthorization") is False:
            out.append(_f(id="AZ-KEYVAULT-ACCESS-POLICIES", severity="low", resource=rid, affected_component=nm,
                          control=f"{CIS} — Key Vault (RBAC)", evidence="uses legacy access policies instead of Azure RBAC",
                          recommended_remediation="Switch the vault to the Azure RBAC permission model"))

    for aks in bundle.get("aks_clusters", []):
        p, nm, rid = _p(aks), _name(aks), aks.get("id") or _name(aks)
        api = p.get("apiServerAccessProfile") or {}
        if not api.get("enablePrivateCluster") and not (api.get("authorizedIpRanges") or []):
            out.append(_f(id="AZ-AKS-PUBLIC-API", severity="high", resource=rid, affected_component=nm,
                          evidence="AKS API server is reachable from the whole internet (no private cluster, no authorized IP ranges)",
                          recommended_remediation="Use a private cluster, or restrict authorizedIpRanges to office / VPN ranges"))
        if p.get("enableRbac") is False or p.get("enableRBAC") is False:
            out.append(_f(id="AZ-AKS-RBAC-OFF", severity="critical", resource=rid, affected_component=nm,
                          evidence="Kubernetes RBAC is disabled", recommended_remediation="Recreate the cluster with RBAC enabled"))
        if not p.get("disableLocalAccounts"):
            out.append(_f(id="AZ-AKS-LOCAL-ACCOUNTS", severity="medium", resource=rid, affected_component=nm,
                          evidence="local cluster-admin accounts are enabled (static kubeconfig bypasses Entra ID)",
                          recommended_remediation="Enable Entra ID integration and disableLocalAccounts"))
        if not ((p.get("networkProfile") or {}).get("networkPolicy")):
            out.append(_f(id="AZ-AKS-NO-NETWORK-POLICY", severity="medium", resource=rid, affected_component=nm,
                          evidence="no network policy engine: pod-to-pod traffic cannot be restricted",
                          recommended_remediation="Enable Azure / Calico / Cilium network policy and add default-deny policies"))

    if "defender_plans" in bundle:
        plans = {_name(x): _p(x) for x in bundle.get("defender_plans") or []}
        off = [n for n in DEFENDER_PLANS if n in plans and str(plans[n].get("pricingTier", "")).lower() == "free"]
        if off:
            out.append(_f(id="AZ-DEFENDER-PLANS-OFF", severity="medium", resource=f"/subscriptions/{sub}/defender",
                          affected_component=f"subscription {sub_label}", control=f"{CIS} — Microsoft Defender for Cloud",
                          evidence=f"Defender plans on Free tier: {', '.join(off)}",
                          recommended_remediation="Enable the Defender plans for the resource types in use and forward alerts to AEGIS"))

    if "activity_log_diagnostics" in bundle:
        exported = False
        for d in bundle.get("activity_log_diagnostics") or []:
            logs = (_p(d).get("logs") or [])
            if any(lg.get("enabled") and lg.get("category") in ("Administrative", None) for lg in logs) or \
               any(lg.get("enabled") and lg.get("categoryGroup") == "allLogs" for lg in logs):
                exported = True
        if not exported:
            out.append(_f(id="AZ-ACTIVITY-LOG-NOT-EXPORTED", severity="high", resource=f"/subscriptions/{sub}/activitylog",
                          affected_component=f"subscription {sub_label}", control=f"{CIS} — Logging and monitoring",
                          evidence="the subscription Activity Log (Administrative) is not exported: control-plane history is kept only 90 days",
                          recommended_remediation="Add a subscription diagnostic setting sending Administrative + Security logs to Log Analytics / storage"))

    for ra in bundle.get("role_assignments", []):
        p = _p(ra)
        role = p.get("roleDefinitionName", "")
        if role in PRIVILEGED_ROLES and str(p.get("principalType", "")).lower() == "user" and _sub_scope(p.get("scope", "")):
            who = p.get("principalName") or p.get("principalId", "?")
            out.append(_f(id="AZ-RBAC-STANDING-PRIVILEGE", severity="high", resource=p.get("id") or f"{p.get('scope')}/{who}/{role}",
                          affected_component=f"{who} — {role}", confidence=0.85,
                          evidence=f"user holds standing {role} on the whole subscription",
                          recommended_remediation="Make it eligible through Privileged Identity Management (just-in-time, approval, MFA) instead of permanent"))

    for cr in bundle.get("custom_roles", []):
        p = _p(cr)
        actions = {a for perm in p.get("permissions") or [] for a in (perm.get("actions") or [])}
        if "*" in actions and any(_sub_scope(s) for s in p.get("assignableScopes") or []):
            nm = p.get("roleName") or _name(cr)
            out.append(_f(id="AZ-CUSTOM-OWNER-ROLE", severity="high", resource=cr.get("id") or nm, affected_component=nm,
                          control=f"{CIS} — Identity (no custom subscription administrator roles)",
                          evidence="custom role grants '*' actions at subscription scope (an unofficial Owner)",
                          recommended_remediation="Delete the role; use built-in roles with the narrowest scope"))

    return sort_findings(out)


def coverage_gaps(bundle: dict) -> list[str]:
    errs = bundle.get("collection_errors") or {}
    gaps = [f"{k} (access denied or failed: {errs[k]})" if k in errs else k for k in BUNDLE_KEYS if k not in bundle]
    return gaps + ["entra_id (MFA, guests, conditional access — needs Microsoft Graph, not collected)"]
