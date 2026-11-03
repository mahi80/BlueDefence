"""Policy-as-code — stop the misconfiguration in the pull request, not in production.

The same rules that flag a resource at runtime are run against the *intended* state before deploy:

* **Terraform** — ``terraform show -json plan.out``. AWS resources are translated into the shapes the
  CSPM and IAM scanners already judge (security groups, RDS, EC2/launch templates, EBS, S3 public
  access, IAM policies and trust), so a rule has one definition and one ID whether it fires in a PR or
  on the live account. Findings carry the Terraform address.
* **Kubernetes YAML** — manifests (files or directories, multi-document) go through ``k8s_posture``.

Exceptions are governed, not ad hoc: a waiver file (``waivers.yaml``) must give each exception a
reason, an approver and an expiry date. Expired or malformed waivers do not suppress anything, and
every applied waiver is listed in the report so the exception register is auditable.

There is no live mode here: this is the pre-deploy gate. The live side is ``cspm`` / ``k8s``.
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import yaml

from . import azure_cspm, cspm, k8s_posture
from .base import PostureFinding, sort_findings
from .iam_review import ADMIN_POLICY_ARN, _as_list, _is_full_admin, _privesc_actions
from .sources import PostureSourceError

S3_PUBLIC_ACLS = {"public-read", "public-read-write", "authenticated-read"}


def _f(**kw: Any) -> PostureFinding:
    kw.setdefault("confidence", 0.95)
    kw.setdefault("category", "misconfig")
    return PostureFinding(scanner="iac_policy", **kw)


def _rehome(findings: list[PostureFinding], address: str) -> list[PostureFinding]:
    """Findings from a reused scanner, pointed at the Terraform address."""
    for f in findings:
        f.scanner, f.resource, f.affected_component = "iac_policy", address, address
    return findings


def _json(v: Any) -> dict:
    if isinstance(v, dict):
        return v
    if isinstance(v, str) and v.strip():
        try:
            return json.loads(v)
        except json.JSONDecodeError:
            return {}
    return {}


# ---- Terraform plan -------------------------------------------------------------------------------

def plan_resources(plan: dict, *, changed_only: bool = False) -> list[tuple[str, str, dict]]:
    """(address, type, after-values) for every resource the plan will create or keep.

    Deletes are skipped (nothing will exist to misconfigure). With ``changed_only`` the no-op
    resources are skipped too, so a gate only judges what the PR touches."""
    out = []
    for rc in plan.get("resource_changes", []):
        actions = set((rc.get("change") or {}).get("actions") or [])
        if actions == {"delete"} or (changed_only and actions <= {"no-op", "read"}):
            continue
        after = (rc.get("change") or {}).get("after")
        if isinstance(after, dict):
            out.append((rc.get("address", "?"), rc.get("type", ""), after))
    return out


def _sg_perm(proto: Any, lo: Any, hi: Any, v4: list, v6: list) -> dict:
    proto = "-1" if str(proto).lower() in ("-1", "all") else str(proto)
    return {"IpProtocol": proto, "FromPort": lo, "ToPort": hi,
            "IpRanges": [{"CidrIp": c} for c in v4 or []], "Ipv6Ranges": [{"CidrIpv6": c} for c in v6 or []]}


def _terraform(address: str, rtype: str, a: dict) -> list[PostureFinding]:
    sg = lambda perms: _rehome(cspm.scan({"security_groups": [{"GroupId": address, "GroupName": address, "IpPermissions": perms}]}), address)

    if rtype == "aws_security_group":
        return sg([_sg_perm(r.get("protocol"), r.get("from_port"), r.get("to_port"), r.get("cidr_blocks"), r.get("ipv6_cidr_blocks"))
                   for r in a.get("ingress") or []])
    if rtype == "aws_security_group_rule" and a.get("type") == "ingress":
        return sg([_sg_perm(a.get("protocol"), a.get("from_port"), a.get("to_port"), a.get("cidr_blocks"), a.get("ipv6_cidr_blocks"))])
    if rtype == "aws_vpc_security_group_ingress_rule":
        return sg([_sg_perm(a.get("ip_protocol"), a.get("from_port"), a.get("to_port"),
                            [a["cidr_ipv4"]] if a.get("cidr_ipv4") else [], [a["cidr_ipv6"]] if a.get("cidr_ipv6") else [])])

    if rtype == "aws_db_instance":
        return _rehome(cspm.scan({"db_instances": [{
            "DBInstanceIdentifier": address, "Engine": a.get("engine"),
            "PubliclyAccessible": bool(a.get("publicly_accessible")),
            "StorageEncrypted": bool(a.get("storage_encrypted")),
            "BackupRetentionPeriod": a.get("backup_retention_period"),
            "DeletionProtection": bool(a.get("deletion_protection"))}]}), address)

    if rtype in ("aws_instance", "aws_launch_template"):
        md = (a.get("metadata_options") or [{}])
        md = md[0] if isinstance(md, list) and md else md if isinstance(md, dict) else {}
        public = bool(a.get("associate_public_ip_address"))
        return _rehome(cspm.scan({"instances": [{"InstanceId": address, "PublicIpAddress": "planned" if public else None,
                                                 "MetadataOptions": {"HttpTokens": md.get("http_tokens") or "optional"}}]}), address)

    if rtype == "aws_ebs_volume" and a.get("encrypted") is False:
        return _rehome(cspm.scan({"volumes": [{"VolumeId": address, "Encrypted": False}]}), address)
    if rtype == "aws_ebs_encryption_by_default" and a.get("enabled") is False:
        return _rehome(cspm.scan({"ebs_encryption_by_default": False}), address)

    if rtype == "aws_kms_key" and not a.get("enable_key_rotation") and a.get("customer_master_key_spec", "SYMMETRIC_DEFAULT") == "SYMMETRIC_DEFAULT":
        return _rehome(cspm.scan({"kms_keys": [{"KeyId": address, "KeyManager": "CUSTOMER", "KeyState": "Enabled",
                                                "KeySpec": "SYMMETRIC_DEFAULT", "KeyRotationEnabled": False}]}), address)

    if rtype == "aws_cloudtrail" and a.get("enable_log_file_validation") is False:
        return _rehome(cspm.scan({"trails": [{"Name": address, "IsMultiRegionTrail": True, "IsLogging": True,
                                              "LogFileValidationEnabled": False}]}), address)

    if rtype in ("aws_s3_bucket_public_access_block", "aws_s3_account_public_access_block"):
        off = [k for k in ("block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets") if a.get(k) is False]
        if off:
            return [_f(id="CSPM-S3-ACCOUNT-BPA-OFF" if rtype.startswith("aws_s3_account") else "IAC-S3-BPA-WEAKENED",
                       severity="high", resource=address, affected_component=address, control=f"{cspm.CIS} — S3 Block Public Access",
                       evidence=f"Block Public Access disabled: {', '.join(off)}",
                       recommended_remediation="Keep all four Block Public Access settings true; serve public content via CloudFront")]
    if rtype in ("aws_s3_bucket_acl", "aws_s3_bucket") and a.get("acl") in S3_PUBLIC_ACLS:
        return [_f(id="CSPM-S3-PUBLIC-BUCKET", severity="critical", resource=address, affected_component=address,
                   control=f"{cspm.CIS} — S3 Block Public Access", evidence=f"bucket ACL is '{a.get('acl')}'",
                   recommended_remediation="Use a private ACL (or BucketOwnerEnforced object ownership) and Block Public Access")]
    if rtype == "aws_s3_bucket_policy":
        for st in _as_list(_json(a.get("policy")).get("Statement")):
            p = st.get("Principal") if isinstance(st, dict) else None
            if st.get("Effect") == "Allow" and (p == "*" or (isinstance(p, dict) and "*" in _as_list(p.get("AWS")))) and not st.get("Condition"):
                return [_f(id="CSPM-S3-PUBLIC-BUCKET", severity="critical", resource=address, affected_component=address,
                           control=f"{cspm.CIS} — S3 Block Public Access", evidence="bucket policy allows Principal \"*\" with no Condition",
                           recommended_remediation="Restrict the policy to named principals or a CloudFront origin access control")]

    if rtype in ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"):
        doc = _json(a.get("policy"))
        if _is_full_admin(doc):
            return [_f(id="IAM-POLICY-FULL-ADMIN", severity="high", resource=address, affected_component=address,
                       control="CIS AWS Foundations v2.0 1.16", evidence='policy allows Action "*" on Resource "*"',
                       recommended_remediation="Write least-privilege statements scoped to the actions and resources needed")]
        if pe := _privesc_actions(doc):
            return [_f(id="IAM-POLICY-PRIVESC", severity="high", resource=address, affected_component=address, confidence=0.85,
                       evidence=f"policy allows privilege-escalation actions on Resource \"*\": {', '.join(sorted(pe))}",
                       recommended_remediation="Scope these actions to specific resources")]
    if rtype in ("aws_iam_user_policy_attachment", "aws_iam_group_policy_attachment") and a.get("policy_arn") == ADMIN_POLICY_ARN:
        return [_f(id="IAM-USER-ADMIN", severity="high", resource=address, affected_component=address,
                   evidence="attaches AdministratorAccess to a user or group",
                   recommended_remediation="Grant admin through a role assumed with MFA, not standing user/group attachment")]
    if rtype == "aws_iam_role":
        for st in _as_list(_json(a.get("assume_role_policy")).get("Statement")):
            p = st.get("Principal") if isinstance(st, dict) else None
            if st.get("Effect") == "Allow" and (p == "*" or (isinstance(p, dict) and "*" in _as_list(p.get("AWS")))):
                return [_f(id="IAM-ROLE-TRUST-ANYONE", severity="high" if st.get("Condition") else "critical",
                           resource=address, affected_component=address, evidence="role trust policy allows Principal \"*\"",
                           recommended_remediation="Trust named principals only; add aws:PrincipalOrgID or sts:ExternalId conditions")]

    if rtype == "aws_eks_cluster":
        vpc = (a.get("vpc_config") or [{}])
        vpc = vpc[0] if isinstance(vpc, list) and vpc else {}
        if vpc.get("endpoint_public_access", True) and "0.0.0.0/0" in (vpc.get("public_access_cidrs") or ["0.0.0.0/0"]):
            return [_f(id="IAC-EKS-PUBLIC-API", severity="high", resource=address, affected_component=address,
                       evidence="EKS API server endpoint is reachable from the whole internet",
                       recommended_remediation="Disable the public endpoint, or restrict public_access_cidrs to office / VPN ranges")]
    return []


# ---- azurerm: translated into the Azure posture bundle shape, judged by azure_cspm ---------------

def _first(v: Any) -> dict:
    return v[0] if isinstance(v, list) and v and isinstance(v[0], dict) else v if isinstance(v, dict) else {}


def _nsg_rule(r: dict) -> dict:
    return {"name": r.get("name"), "access": r.get("access"), "direction": r.get("direction"),
            "sourceAddressPrefix": r.get("source_address_prefix"), "sourceAddressPrefixes": r.get("source_address_prefixes") or [],
            "destinationPortRange": r.get("destination_port_range"), "destinationPortRanges": r.get("destination_port_ranges") or []}


def _azurerm(address: str, rtype: str, a: dict, *, separate_storage_rules: bool) -> list[PostureFinding]:
    b: dict[str, Any] = {}
    if rtype == "azurerm_storage_account":
        nr = _first(a.get("network_rules"))
        sa = {"name": address, "allowBlobPublicAccess": a.get("allow_nested_items_to_be_public"),
              "enableHttpsTrafficOnly": a.get("https_traffic_only_enabled", a.get("enable_https_traffic_only")),
              "minimumTlsVersion": a.get("min_tls_version") or "TLS1_2",
              "publicNetworkAccess": "Disabled" if a.get("public_network_access_enabled") is False else "Enabled"}
        if "shared_access_key_enabled" in a:
            sa["allowSharedKeyAccess"] = a.get("shared_access_key_enabled")
        # network rules may live in a separate azurerm_storage_account_network_rules resource; when the plan
        # has one we cannot tie it to this account by reference, so the open-network check is left to runtime
        sa["networkRuleSet"] = {"defaultAction": nr.get("default_action") or ("Deny" if separate_storage_rules else "Allow")}
        b["storage_accounts"] = [sa]
    elif rtype == "azurerm_network_security_group":
        b["network_security_groups"] = [{"name": address, "securityRules": [_nsg_rule(r) for r in a.get("security_rule") or []]}]
    elif rtype == "azurerm_network_security_rule":
        b["network_security_groups"] = [{"name": address, "securityRules": [_nsg_rule(a)]}]
    elif rtype in ("azurerm_mssql_server", "azurerm_sql_server"):
        b["sql_servers"] = [{"name": address, "minimalTlsVersion": a.get("minimum_tls_version"),
                             "publicNetworkAccess": "Disabled" if a.get("public_network_access_enabled") is False else "Enabled"}]
    elif rtype in ("azurerm_mssql_firewall_rule", "azurerm_sql_firewall_rule"):
        b["sql_servers"] = [{"name": address, "firewall_rules": [{"name": a.get("name"), "startIpAddress": a.get("start_ip_address"),
                                                                  "endIpAddress": a.get("end_ip_address")}]}]
    elif rtype in ("azurerm_postgresql_flexible_server_firewall_rule", "azurerm_mysql_flexible_server_firewall_rule"):
        key = "postgres_servers" if "postgresql" in rtype else "mysql_servers"
        b[key] = [{"name": address, "firewall_rules": [{"name": a.get("name"), "startIpAddress": a.get("start_ip_address"),
                                                        "endIpAddress": a.get("end_ip_address")}]}]
    elif rtype == "azurerm_key_vault":
        acl = _first(a.get("network_acls"))
        b["key_vaults"] = [{"name": address, "properties": {
            "enableSoftDelete": True, "enablePurgeProtection": bool(a.get("purge_protection_enabled")),
            "enableRbacAuthorization": a.get("rbac_authorization_enabled", a.get("enable_rbac_authorization")),
            "publicNetworkAccess": "Disabled" if a.get("public_network_access_enabled") is False else "Enabled",
            "networkAcls": {"defaultAction": acl.get("default_action") or "Allow"}}}]
    elif rtype == "azurerm_kubernetes_cluster":
        api = _first(a.get("api_server_access_profile"))
        ranges = api.get("authorized_ip_ranges") or a.get("api_server_authorized_ip_ranges") or []
        b["aks_clusters"] = [{"name": address, "apiServerAccessProfile": {"enablePrivateCluster": bool(a.get("private_cluster_enabled")),
                                                                          "authorizedIpRanges": ranges},
                              "enableRbac": a.get("role_based_access_control_enabled", True),
                              "disableLocalAccounts": bool(a.get("local_account_disabled")),
                              "networkProfile": {"networkPolicy": _first(a.get("network_profile")).get("network_policy")}}]
    elif rtype == "azurerm_role_definition":
        b["custom_roles"] = [{"roleName": a.get("name") or address,
                              "permissions": [{"actions": p.get("actions") or []} for p in a.get("permissions") or []],
                              "assignableScopes": a.get("assignable_scopes") or ([a["scope"]] if a.get("scope") else [])}]
    elif rtype == "azurerm_role_assignment" and str(a.get("principal_type", "")).lower() == "user":
        b["role_assignments"] = [{"principalName": a.get("principal_id"), "principalType": "User",
                                  "roleDefinitionName": a.get("role_definition_name"), "scope": a.get("scope", "")}]
    elif rtype == "azurerm_security_center_subscription_pricing" and str(a.get("tier", "")).lower() == "free":
        b["defender_plans"] = [{"name": a.get("resource_type") or "VirtualMachines", "pricingTier": "Free"}]
    return _rehome(azure_cspm.scan(b), address) if b else []


def scan_plan(plan: dict, *, changed_only: bool = False) -> list[PostureFinding]:
    out: list[PostureFinding] = []
    resources = plan_resources(plan, changed_only=changed_only)
    separate_rules = any(t == "azurerm_storage_account_network_rules" for _, t, _ in resources)
    for address, rtype, after in resources:
        if rtype.startswith("azurerm_"):
            out.extend(_azurerm(address, rtype, after, separate_storage_rules=separate_rules))
        else:
            out.extend(_terraform(address, rtype, after))
    return sort_findings(out)


# ---- Kubernetes manifests -------------------------------------------------------------------------

def load_manifests(paths: list[str | Path]) -> list[dict]:
    docs: list[dict] = []
    for p in map(Path, paths):
        files = sorted(x for x in p.rglob("*") if x.suffix in (".yaml", ".yml", ".json")) if p.is_dir() else [p]
        for f in files:
            try:
                text = f.read_text(encoding="utf-8")
                loaded = [json.loads(text)] if f.suffix == ".json" else list(yaml.safe_load_all(text))
            except (OSError, ValueError, yaml.YAMLError) as e:
                raise PostureSourceError(f"cannot parse {f}: {e}") from e
            for d in loaded:
                if isinstance(d, dict) and d.get("kind") == "List":
                    docs.extend(x for x in d.get("items", []) if isinstance(x, dict))
                elif isinstance(d, dict) and d.get("kind"):
                    docs.append(d)
    return docs


def scan_manifests(docs: list[dict]) -> list[PostureFinding]:
    # Pre-deploy: judge only what the manifests define. Namespace-level checks (no NetworkPolicy, no
    # PSA label) depend on what already exists in the cluster, so they belong to the live k8s scan.
    findings = k8s_posture.scan(docs, include_system=True)
    kept = [f for f in findings if f.id not in ("K8S-NO-NETWORKPOLICY", "K8S-NO-POD-SECURITY-ADMISSION", "K8S-DEFAULT-NAMESPACE-USED")]
    for f in kept:
        f.scanner = "iac_policy"
    return kept


def _today() -> date:
    """Expiry is judged on the UTC calendar day, so the gate gives the same answer on any runner."""
    return datetime.now(UTC).date()


# ---- waivers --------------------------------------------------------------------------------------

@dataclass
class Waiver:
    id: str
    resource: str
    reason: str
    approved_by: str
    expires: date
    used: int = field(default=0, compare=False)

    def matches(self, f: PostureFinding) -> bool:
        return fnmatch.fnmatchcase(f.id, self.id) and fnmatch.fnmatchcase(f.resource or "", self.resource)


def load_waivers(path: str | Path) -> list[Waiver]:
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as e:
        raise PostureSourceError(f"cannot read waivers {path}: {e}") from e
    if not isinstance(raw, dict) or not isinstance(raw.get("waivers") or [], list):
        raise PostureSourceError(f"waivers {path}: expected a mapping with a `waivers:` list")
    out = []
    for i, w in enumerate(raw.get("waivers") or [], 1):
        if not isinstance(w, dict):
            raise PostureSourceError(f"waiver #{i} is not a mapping")
        missing = [k for k in ("id", "resource", "reason", "approved_by", "expires") if not w.get(k)]
        if missing:
            raise PostureSourceError(f"waiver #{i} is missing {', '.join(missing)}: every exception needs a reason, an approver and an expiry")
        try:
            exp = w["expires"] if isinstance(w["expires"], date) else date.fromisoformat(str(w["expires"]))
        except ValueError as e:
            # a typo'd date raised ValueError, which nothing caught: every posture run crashed and the console kept
            # showing the previous run (review round 3 G6-4). It is a register problem, applied fail-safe.
            raise PostureSourceError(f"waiver #{i} ({w.get('id')}) has an unreadable expiry {w['expires']!r}: {e}") from e
        out.append(Waiver(str(w["id"]), str(w["resource"]), str(w["reason"]), str(w["approved_by"]), exp))
    return out


def apply_waivers(findings: list[PostureFinding], waivers: list[Waiver], *, today: date | None = None
                  ) -> tuple[list[PostureFinding], list[tuple[PostureFinding, Waiver]], list[str]]:
    """Split findings into (still failing, waived). Expired waivers suppress nothing and are reported."""
    today = today or _today()
    active = [w for w in waivers if w.expires >= today]
    notes = [f"waiver for {w.id} on {w.resource} expired {w.expires.isoformat()} (approved by {w.approved_by}); not applied"
             for w in waivers if w.expires < today]
    kept, waived = [], []
    for f in findings:
        w = next((w for w in active if w.matches(f)), None)
        if w:
            w.used += 1
            waived.append((f, w))
        else:
            kept.append(f)
    notes += [f"waiver for {w.id} on {w.resource} matched nothing; remove it from the register" for w in active if not w.used]
    return kept, waived, notes
