"""Tools for the Cloud Control-Plane specialist.

Five posture-aware checks against cloud control-plane events. Inputs
are either CloudTrail-shaped (eventName, requestParameters,
userIdentity) or Azure-Activity-shaped (operationName, properties,
caller). The checks abstract over the source so the agent can reason
about both with one toolkit.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

from ..shared.tool_guard import isolated


@dataclass
class ToolResult:
    name: str
    data: dict
    weight: str


# ---- IAM change check -----------------------------------------------

# Action prefixes that are inherently risky when not bounded.
_HIGH_RISK_IAM_ACTIONS = {
    # AWS
    "iam:CreateAccessKey",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:CreateLoginProfile",
    "iam:UpdateAssumeRolePolicy",
    "iam:CreatePolicyVersion",
    "sts:AssumeRole",
    # Azure
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.Authorization/roleDefinitions/write",
    # GCP
    "google.iam.admin.v1.SetIAMPolicy",
    # OpenStack Keystone (identity.* events)
    "identity.role_assignment.created",
    "identity.user.created",
    "identity.role.granted",
    "identity.application_credential.created",
    "identity.token.issued",
}

# Roles that should never be granted broadly.
_DANGEROUS_ROLES = {
    # AWS managed policies
    "AdministratorAccess", "PowerUserAccess",
    # Azure roles
    "Owner", "Contributor", "User Access Administrator",
    # GCP
    "roles/owner", "roles/iam.securityAdmin",
    # Azure built-in role definition ids — what a real roleAssignments/write event carries, not the name
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",   # Owner
    "b24988ac-6180-42a0-ab88-20f7382dd24c",   # Contributor
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",   # User Access Administrator
    "f58310d9-a9f6-439a-9e8d-f62e7b41a168",   # Role Based Access Control Administrator
}
# CloudTrail names the service in eventSource and the call in eventName WITHOUT a prefix
# ("AttachUserPolicy", eventSource "iam.amazonaws.com"); the check used to need "iam" in the eventName.
_SERVICE_PREFIX = {"iam.amazonaws.com": "iam:", "sts.amazonaws.com": "sts:"}
_WILDCARD_RX = re.compile(r'"(?:Action|NotAction|Resource|actions)"\s*:\s*(?:"\*"|\[[^\]]*"\*"[^\]]*\])', re.IGNORECASE)


def _raw_action(event: dict) -> str:
    raw = event.get("eventName") or event.get("operationName") or event.get("event_type") or ""
    if isinstance(raw, dict):
        # Azure Activity Log exports operationName as {"value": "...", "localizedValue": "..."}: str() of the dict
        # matched nothing, and `.startswith` on it crashed (review round 3 G7-5)
        raw = raw.get("value") or raw.get("localizedValue") or ""
    return str(raw).strip()


def _action(event: dict, *, prefix: str = "") -> str:
    """The event's operation in the spelling this module's tables use. Azure and GCP do not keep one case
    (``MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE`` in Activity Log exports), and every table compared
    case-sensitively, so the same grant was high risk or invisible depending on the exporter (round 3 G7-5)."""
    s = _raw_action(event)
    if prefix and ":" not in s:
        s = prefix + s
    return _CANON.get(s.lower(), s)


def _params(event: dict) -> dict:
    """requestParameters / properties, with an Azure ``requestbody`` (a JSON string) merged in: the role
    definition id and NSG rule of a real Activity Log event live only there."""
    params = event.get("requestParameters") or event.get("properties") or event.get("payload") or {}
    if not isinstance(params, dict):
        return {}
    body = params.get("requestbody") or params.get("requestBody")
    if isinstance(body, str) and body.strip().startswith("{"):
        try:
            import json as _json
            parsed = _json.loads(body)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            inner = parsed.get("properties") if isinstance(parsed.get("properties"), dict) else {}
            return {**params, **parsed, **inner}
    return params


def iam_change_check(event: dict | None) -> ToolResult:
    """Inspect an IAM-domain control-plane event for posture-weakening
    patterns: wildcard policies, dangerous role grants, new long-lived
    credentials on service principals.
    """
    if not event:
        return ToolResult(name="iam_change", data={"verdict": "no_event"}, weight="low")

    # OpenStack Keystone events use `event_type` instead of eventName.
    action = _action(event, prefix=_SERVICE_PREFIX.get(str(event.get("eventSource") or "").lower(), ""))
    is_iam_action = (
        action in _HIGH_RISK_IAM_ACTIONS
        or "iam" in action.lower()
        or "roleassignment" in action.lower()
        or action.startswith("identity.")
    )
    if not is_iam_action:
        return ToolResult(name="iam_change", data={
            "action": action, "is_iam": False,
        }, weight="low")

    params = _params(event)
    # Wildcard scan in policy document
    from urllib.parse import unquote
    doc = params.get("policyDocument") or params.get("roleDefinition") or ""
    policy_text = unquote(doc if isinstance(doc, str) else __import__("json").dumps(doc))
    # the policy ARN (AttachUserPolicy / AttachRolePolicy) and the Azure role definition id name the grant
    grant_text = " ".join(str(params.get(k) or "") for k in ("policyArn", "roleDefinitionId", "role", "roleName"))
    stmts = _statements(doc)
    has_wildcard = (any(_has_star(st.get(k)) for st in stmts for k in ("Action", "NotAction", "Resource", "actions"))
                    if stmts is not None else bool(_WILDCARD_RX.search(policy_text)))
    has_dangerous_role = any(role.lower() in (policy_text + " " + grant_text).lower() for role in _DANGEROUS_ROLES)
    # Was a long-lived access key created for a service principal?
    user_type = (event.get("userIdentity") or {}).get("type", "")
    is_service_principal = user_type in ("AssumedRole", "ServicePrincipal", "Application")
    creates_access_key = action == "iam:CreateAccessKey" and is_service_principal

    risk = sum([has_wildcard, has_dangerous_role, creates_access_key])
    if risk >= 2:
        weight = "high"
    elif risk >= 1:
        weight = "medium"
    else:
        weight = "low"

    return ToolResult(name="iam_change", data={
        "action": action,
        "has_wildcard_policy": has_wildcard,
        "has_dangerous_role_grant": has_dangerous_role,
        "long_lived_key_for_service_principal": creates_access_key,
        "risk_score": risk,
    }, weight=weight)


# ---- Resource policy / S3-bucket-policy check -----------------------

def _statements(doc: Any) -> list[dict] | None:
    """A policy document's statements, parsed (``None`` when it is not a policy we can read). A regex over the
    raw text missed ``"Action":"\\u002a"`` and Python-repr'd dicts (round 4 S4-5 / S4-12)."""
    import json
    from urllib.parse import unquote
    if isinstance(doc, str):
        try:
            doc = json.loads(unquote(doc))
        except ValueError:
            try:
                doc = json.loads(doc)
            except ValueError:
                return None
    if isinstance(doc, dict) and "properties" in doc and "Statement" not in doc and isinstance(doc["properties"], dict):
        perms = doc["properties"].get("permissions")
        if isinstance(perms, list):                     # Azure role definition: permissions[].actions
            return [p for p in perms if isinstance(p, dict)]
    if not isinstance(doc, dict):
        return None
    st = doc.get("Statement", doc.get("statement"))
    if isinstance(st, dict):
        st = [st]
    if not isinstance(st, list):
        return [] if st is None else None
    return [x for x in st if isinstance(x, dict)]


def _has_star(v: Any) -> bool:
    if isinstance(v, str):
        return v.strip() == "*"
    if isinstance(v, (list, tuple)):
        return any(isinstance(x, str) and x.strip() == "*" for x in v)
    return False


def _public_principal(p: Any) -> bool:
    if _has_star(p):
        return True
    if isinstance(p, dict):
        return any(_has_star(v) for v in p.values())
    return False


def _ci(d: Any, *keys: str) -> Any:
    """``d[key]`` matched case-insensitively (CloudTrail writes ``PublicAccessBlockConfiguration``)."""
    if not isinstance(d, dict):
        return None
    low = {str(k).lower(): v for k, v in d.items()}
    for k in keys:
        if k.lower() in low:
            return low[k.lower()]
    return None


def _truthy(v: Any) -> bool:
    return v is True or (isinstance(v, str) and v.strip().lower() == "true")


_PUBLIC_PRINCIPAL_RX = re.compile(r'"Principal"\s*:\s*"\*"|"Principal"\s*:\s*\{\s*"AWS"\s*:\s*"\*"\s*\}')


def resource_policy_check(event: dict | None) -> ToolResult:
    """Detects bucket-policy / blob-container-ACL / KMS-key-policy
    changes that grant public access or remove encryption.
    """
    if not event:
        return ToolResult(name="resource_policy", data={"verdict": "no_event"}, weight="low")

    action = _action(event)
    params = _params(event)

    if action in ("PutBucketPolicy", "s3:PutBucketPolicy",
                  "Microsoft.Storage/storageAccounts/write"):
        raw = params.get("bucketPolicy") or params.get("policy")
        stmts = _statements(raw) if raw else []
        if stmts is not None:
            is_public = any(str(_ci(st, "Effect") or "").lower() == "allow" and _public_principal(_ci(st, "Principal"))
                            for st in stmts)
        else:
            policy = str(raw or "")
            is_public = bool(_PUBLIC_PRINCIPAL_RX.search(policy)) or ('"Effect": "Allow"' in policy and '"*"' in policy)
        # Azure storage account opened to the internet: publicNetworkAccess "Enabled" / allowBlobPublicAccess true,
        # at the top of the request or under properties (the old test compared against '"Enabled"' with quotes)
        props = params.get("properties") if isinstance(params.get("properties"), dict) else {}
        for src in (params, props):
            if str(_ci(src, "publicNetworkAccess") or "").strip().lower() == "enabled" \
                    or _truthy(_ci(src, "allowBlobPublicAccess")):
                is_public = True
        return ToolResult(name="resource_policy", data={
            "action": action, "grants_public": is_public,
        }, weight="high" if is_public else "low")

    if action in ("PutBucketEncryption", "DeleteBucketEncryption"):
        removed = action == "DeleteBucketEncryption"
        return ToolResult(name="resource_policy", data={
            "action": action, "encryption_removed": removed,
        }, weight="high" if removed else "low")

    if action in ("PutBucketPublicAccessBlock",):
        block = _ci(params, "publicAccessBlockConfiguration", "PublicAccessBlockConfiguration") or {}
        weakened = not all(_truthy(_ci(block, k)) if _ci(block, k) is not None else True for k in [
            "blockPublicAcls", "ignorePublicAcls", "blockPublicPolicy", "restrictPublicBuckets",
        ])
        return ToolResult(name="resource_policy", data={
            "action": action, "public_access_block_weakened": weakened,
        }, weight="high" if weakened else "low")

    return ToolResult(name="resource_policy", data={
        "action": action, "tracked": False,
    }, weight="low")


# ---- Network change check (security groups, NSG, peering) -----------

_INTERNET_CIDR = "0.0.0.0/0"
_SENSITIVE_PORTS = {22, 23, 3389, 1433, 3306, 5432, 6379, 27017, 9200}


def network_change_check(event: dict | None) -> ToolResult:
    """Detects network-policy changes that widen ingress (0.0.0.0/0
    on sensitive ports), VPC peering with unknown accounts, or VPN
    endpoint additions outside change-window context.
    """
    if not event:
        return ToolResult(name="network_change", data={"verdict": "no_event"}, weight="low")

    action = _action(event)
    params = _params(event)

    # OpenStack Neutron security-group rule create — equivalent of AWS
    # AuthorizeSecurityGroupIngress / Azure NSG rule write.
    if action in ("network.security_group_rule.create.end",
                  "network.security_group_rule.created"):
        rule = params.get("security_group_rule") or {}
        cidr = rule.get("remote_ip_prefix") or ""
        port = rule.get("port_range_max") or rule.get("port_range_min") or 0
        try:
            port_n = int(port) if str(port).isdigit() else 0
        except (TypeError, ValueError):
            port_n = 0
        opens_internet = cidr in (_INTERNET_CIDR, "::/0")
        sensitive = port_n in _SENSITIVE_PORTS
        if opens_internet and sensitive:
            return ToolResult(name="network_change", data={
                "action": action, "cidr": cidr, "port": port,
                "opens_internet_to_sensitive_port": True,
            }, weight="high")
        if opens_internet:
            return ToolResult(name="network_change", data={
                "action": action, "cidr": cidr, "port": port,
                "opens_internet": True,
            }, weight="medium")
        return ToolResult(name="network_change", data={
            "action": action, "cidr": cidr, "port": port,
            "opens_internet": False,
        }, weight="low")

    if action in ("AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules",
                  "Microsoft.Network/networkSecurityGroups/securityRules/write",
                  "Microsoft.Network/networkSecurityGroups/write"):
        # every rule of the change, not the first: CloudTrail nests them as ipPermissions.items[].ipRanges.items[]
        # and the old reader saw no CIDR at all (SSH to the world scored low); Azure writes "*" / "Any" /
        # "Internet" for the internet and port ranges like "20-30" (review round 3 G7-4)
        rules = _ingress_rules(params)
        hits = [(c, lo, hi) for c, lo, hi in rules if _is_internet(c)]
        opens_internet = bool(hits)
        sensitive = any(lo <= p <= hi for _, lo, hi in hits for p in _SENSITIVE_PORTS)
        cidr = hits[0][0] if hits else (rules[0][0] if rules else "")
        port = (f"{hits[0][1]}-{hits[0][2]}" if hits and hits[0][1] != hits[0][2] else (hits[0][1] if hits else 0))
        if opens_internet and sensitive:
            return ToolResult(name="network_change", data={
                "action": action, "cidr": cidr, "port": port,
                "opens_internet_to_sensitive_port": True,
            }, weight="high")
        if opens_internet:
            return ToolResult(name="network_change", data={
                "action": action, "cidr": cidr, "port": port,
                "opens_internet": True,
            }, weight="medium")
        return ToolResult(name="network_change", data={
            "action": action, "cidr": cidr, "port": port,
            "opens_internet": False,
        }, weight="low")

    if action in ("CreateVpcPeeringConnection", "AcceptVpcPeeringConnection"):
        peer_account = (params.get("vpcPeeringConnection") or {}).get("accepterVpcInfo", {}).get("ownerId", "")
        known_accounts = (event.get("knownPeerAccounts") or [])
        unknown = peer_account and peer_account not in known_accounts
        return ToolResult(name="network_change", data={
            "action": action, "peer_account": peer_account, "unknown_peer": unknown,
        }, weight="high" if unknown else "medium")

    if action in ("CreateVpnConnection", "CreateClientVpnEndpoint",
                  "Microsoft.Network/virtualNetworkGateways/write"):
        return ToolResult(name="network_change", data={
            "action": action, "vpn_change": True,
        }, weight="medium")

    return ToolResult(name="network_change", data={
        "action": action, "tracked": False,
    }, weight="low")


# ---- KMS / secrets change check -------------------------------------

_KMS_HIGH = {
    "DisableKey", "ScheduleKeyDeletion", "kms:DisableKey", "kms:ScheduleKeyDeletion",
    "Microsoft.KeyVault/vaults/keys/delete",
    "Microsoft.KeyVault/vaults/secrets/delete",
    "DeleteSecret", "secretsmanager:DeleteSecret",
    "google.cloud.kms.v1.KeyManagementService.DestroyCryptoKeyVersion",
}
_KMS_MEDIUM = {
    "CreateGrant", "kms:CreateGrant",
    "GetSecretValue",  # only medium because routine — frequency comes from agent's reasoning
}


def secrets_or_kms_change_check(event: dict | None) -> ToolResult:
    """Detects key disable/delete and secret rotation/exfil-shape
    operations on KMS / Key Vault / Secret Manager.
    """
    if not event:
        return ToolResult(name="secrets_kms_change", data={"verdict": "no_event"}, weight="low")

    action = _action(event)
    high_risk = action in _KMS_HIGH
    medium_risk = action in _KMS_MEDIUM
    if high_risk:
        return ToolResult(name="secrets_kms_change", data={
            "action": action, "high_risk": True,
        }, weight="high")
    if medium_risk:
        return ToolResult(name="secrets_kms_change", data={
            "action": action, "high_risk": False,
        }, weight="medium")
    return ToolResult(name="secrets_kms_change", data={
        "action": action, "tracked": False,
    }, weight="low")


# ---- Logging-disable check (the attacker's first move) --------------

_LOG_DISABLE_ACTIONS = {
    "StopLogging", "DeleteTrail",
    "cloudtrail:StopLogging", "cloudtrail:DeleteTrail",
    "PutEventSelectors",  # could be narrowing scope — treat as suspicious
    "UpdateTrail",        # can point the trail at another bucket or drop regions
    # the other detective controls an attacker switches off (review round 3 G7-6)
    "DeleteDetector", "UpdateDetector", "DisassociateFromMasterAccount", "DisassociateMembers",
    "guardduty:DeleteDetector", "guardduty:UpdateDetector",
    "StopConfigurationRecorder", "DeleteConfigurationRecorder", "DeleteDeliveryChannel",
    "config:StopConfigurationRecorder", "config:DeleteConfigurationRecorder",
    "DeleteFlowLogs", "ec2:DeleteFlowLogs",
    "DisableSecurityHub", "BatchDisableStandards", "securityhub:DisableSecurityHub",
    "DeleteLogGroup", "DeleteLogStream",
    "Microsoft.Insights/diagnosticSettings/delete",
    "Microsoft.OperationalInsights/workspaces/delete",
    "google.cloud.logging.v2.ConfigServiceV2.DeleteSink",
    # Network device parity (Panorama / Checkpoint / Juniper)
    "panorama:disable-log-forwarding",
    "checkpoint:disable-audit-log",
    "juniper:set-system-syslog-disable",
    # OpenStack: ceilometer/audit-middleware disable
    "compute.audit.disable",
    "identity.audit.disable",
}


def logging_disable_check(event: dict | None) -> ToolResult:
    """Detects audit-log / diagnostic-settings disable operations.
    First move of any half-competent attacker once they have the
    creds — disable the log so the rest of the campaign is invisible.
    """
    if not event:
        return ToolResult(name="logging_disable", data={"verdict": "no_event"}, weight="low")

    action = _action(event)
    if action in _LOG_DISABLE_ACTIONS:
        return ToolResult(name="logging_disable", data={
            "action": action, "logging_disabled": True,
        }, weight="high")
    return ToolResult(name="logging_disable", data={
        "action": action, "logging_disabled": False,
    }, weight="low")


# ---- Network device audit (Panorama / Checkpoint / Juniper) ---------

_FIREWALL_WEAKENING_ACTIONS = {
    "panorama:add-rule",
    "panorama:disable-ips-profile",
    "panorama:disable-url-filtering",
    "panorama:disable-spyware-profile",
    "checkpoint:install-policy",
    "checkpoint:disable-rule",
    "juniper:delete-security-policy",
    "juniper:set-security-policies-from-zone-to-zone-default-permit",
}


def firewall_audit_check(event: dict | None) -> ToolResult:
    """Reasons about whether a network-device admin change weakens
    posture: ANY-ANY rule additions, disabled IPS/URL-filtering
    profiles, default-permit zone policy.

    Source events come from Panorama API (`<show><audit></audit></show>`),
    Checkpoint Mgmt Server SmartConsole audit log, or Juniper Space
    audit log. The agent abstracts over all three with this tool.
    """
    if not event:
        return ToolResult(name="firewall_audit", data={"verdict": "no_event"}, weight="low")

    action = _action(event)
    rule = _params(event)
    src = str(rule.get("source") or rule.get("src_zone") or "")
    dst = str(rule.get("destination") or rule.get("dst_zone") or "")
    svc = str(rule.get("service") or rule.get("application") or "")
    action_kind = str(rule.get("action") or rule.get("rule_action") or "")

    is_any_any = src.lower() in ("any", "*") and dst.lower() in ("any", "*")
    is_permit = action_kind.lower() in ("allow", "permit", "accept")
    services_any = svc.lower() in ("any", "*", "")

    if action in _FIREWALL_WEAKENING_ACTIONS or (is_any_any and is_permit and services_any):
        return ToolResult(name="firewall_audit", data={
            "action": action, "src": src, "dst": dst, "service": svc,
            "rule_action": action_kind, "any_any_permit": is_any_any and is_permit,
            "weakens_posture": True,
        }, weight="high")
    if action.startswith(("panorama:", "checkpoint:", "juniper:")):
        return ToolResult(name="firewall_audit", data={
            "action": action, "src": src, "dst": dst, "service": svc,
            "weakens_posture": False,
        }, weight="medium")

    return ToolResult(name="firewall_audit", data={
        "action": action, "tracked": False,
    }, weight="low")


# ---- K8s Audit-API check -------------------------------------------

# K8s verbs / resources the attacker uses post-compromise
_K8S_HIGH_RISK_VERBS_RESOURCES = {
    ("create", "pods/exec"),
    ("create", "pods/attach"),
    ("create", "pods/portforward"),
    ("create", "tokenrequests"),
    ("delete", "events"),
    ("delete", "audit"),
}

_K8S_DANGEROUS_POD_FEATURES = {
    "privileged", "hostNetwork", "hostPID", "hostIPC",
    "runAsRoot", "hostPath",
}


def k8s_audit_check(event: dict | None) -> ToolResult:
    """K8s Audit API event reasoning: kubectl exec into prod pods,
    privileged-container creation, hostPath mounts, RBAC drift, audit
    sink deletion.
    """
    if not event:
        return ToolResult(name="k8s_audit", data={"verdict": "no_event"}, weight="low")

    # K8s audit events use `verb` + `objectRef` rather than eventName.
    verb = event.get("verb")
    obj_ref = event.get("objectRef") or {}
    resource = obj_ref.get("resource", "")
    sub = obj_ref.get("subresource", "")
    full_resource = f"{resource}/{sub}" if sub else resource
    if not verb:
        # Could be the wrapper-shape from the orchestrator path
        return ToolResult(name="k8s_audit", data={
            "tracked": False, "action": event.get("eventName", ""),
        }, weight="low")

    # kubectl exec over WebSocket is a `get` on pods/exec (the upgrade request), not a `create`
    high_risk_combo = ((verb, full_resource) in _K8S_HIGH_RISK_VERBS_RESOURCES
                       or (verb == "get" and full_resource in ("pods/exec", "pods/attach", "pods/portforward")))

    # Privileged container creation
    pod_features: list[str] = []
    if verb in ("create", "update", "patch") and resource in ("pods", "deployments", "daemonsets", "statefulsets",
                                                             "replicasets", "jobs", "cronjobs"):
        ro = event.get("requestObject") or {}
        spec = ro.get("spec") or {}
        for _ in range(3):                                   # Deployment → template → spec (CronJob nests one deeper)
            tpl = spec.get("template") or (spec.get("jobTemplate") or {}).get("spec", {}).get("template")
            if not isinstance(tpl, dict):
                break
            spec = tpl.get("spec") or {}
        sec = spec.get("securityContext") or {}
        # `privileged` is a CONTAINER setting; the pod-level read never fired (review round 3 G7-6)
        containers = [c for k in ("containers", "initContainers", "ephemeralContainers")
                      for c in (spec.get(k) or []) if isinstance(c, dict)]
        if sec.get("privileged") or any((c.get("securityContext") or {}).get("privileged") for c in containers):
            pod_features.append("privileged")
        if spec.get("hostNetwork"):
            pod_features.append("hostNetwork")
        if spec.get("hostPID"):
            pod_features.append("hostPID")
        if spec.get("hostIPC"):
            pod_features.append("hostIPC")
        for vol in (spec.get("volumes") or []):
            if isinstance(vol, dict) and "hostPath" in vol:
                pod_features.append("hostPath")
                break

    # RBAC widening: ClusterRoleBinding to cluster-admin
    rbac_widened = False
    if verb in ("create", "update", "patch") and resource in ("clusterrolebindings", "rolebindings"):
        ro = event.get("requestObject") or {}
        role_ref = ro.get("roleRef") or {}
        if role_ref.get("name") in ("cluster-admin", "admin", "edit"):
            rbac_widened = True

    risk = sum([high_risk_combo, len(pod_features) >= 1, rbac_widened])
    if risk >= 2 or rbac_widened:
        weight = "high"
    elif risk == 1:
        weight = "medium"
    else:
        weight = "low"

    return ToolResult(name="k8s_audit", data={
        "verb": verb, "resource": full_resource,
        "exec_or_portforward": high_risk_combo,
        "dangerous_pod_features": pod_features,
        "rbac_widened_to_admin": rbac_widened,
        "risk_score": risk,
    }, weight=weight)


# ---- Resource-burst / cost-abuse check ------------------------------

# Rates the attacker uses post-compromise to spin up crypto-mining or
# data-egress capacity. Action set is provider-specific.
_RESOURCE_CREATE_ACTIONS = {
    # AWS
    "RunInstances", "ec2:RunInstances",
    "CreateLaunchConfiguration",
    "CreateAutoScalingGroup",
    # Azure
    "Microsoft.Compute/virtualMachines/write",
    "Microsoft.Compute/virtualMachineScaleSets/write",
    # GCP
    "v1.compute.instances.insert",
    # OpenStack
    "compute.instance.create.end",
}


def resource_burst_check(event: dict | None) -> ToolResult:
    """Detects compute spin-up bursts that exceed normal admin
    workflow — the standard post-compromise signal for crypto-mining,
    botnet build-out, or large-scale data-egress capacity.

    Reads `recent_creates_5min` from the event (the orchestrator's
    feature pipeline pre-aggregates this from CloudTrail/Activity Log
    in production; here it's directly on the alert for testability).
    """
    if not event:
        return ToolResult(name="resource_burst", data={"verdict": "no_event"}, weight="low")
    action = _action(event)
    if action not in _RESOURCE_CREATE_ACTIONS:
        return ToolResult(name="resource_burst", data={
            "action": action, "tracked": False,
        }, weight="low")
    recent = int(event.get("recent_creates_5min", 0) or 0)
    instance_type = (event.get("requestParameters") or {}).get("instanceType", "")
    is_gpu = any(g in instance_type.lower() for g in ("p4", "p5", "g4", "g5", "a100", "h100", "ndv4"))
    # GPU instances + burst = crypto-mining shape
    if is_gpu and recent >= 5:
        weight = "high"
    elif recent >= 50:
        weight = "high"
    elif recent >= 10:
        weight = "medium"
    else:
        weight = "low"
    return ToolResult(name="resource_burst", data={
        "action": action, "instance_type": instance_type,
        "is_gpu_instance": is_gpu,
        "recent_creates_5min": recent,
        "burst_pattern": recent >= 10,
    }, weight=weight)


# ---- On-prem HSM audit-log check (Thales / nCipher) -----------------

# Distinct from cloud KMS — banks usually have on-prem HSMs for
# ATM-PIN, payment-rail, and root-CA keys. Audit logs come over a
# separate channel (syslog from the HSM appliance).
_HSM_HIGH_RISK_OPERATIONS = {
    "thales:export-key",
    "thales:delete-key",
    "thales:disable-audit",
    "ncipher:export-cardset",
    "ncipher:delete-cardset",
    "ncipher:disable-audit",
    "luna:partition-zeroize",
    "luna:disable-audit",
}


def hsm_audit_check(event: dict | None) -> ToolResult:
    """Detects HSM operations that should never happen outside a
    formal key-ceremony (export, delete, audit-disable). Treat
    ANY of these as malicious-grade evidence — legitimate ceremonies
    have a paper trail, multi-person presence, and pre-scheduled
    change windows the orchestrator is aware of.
    """
    if not event:
        return ToolResult(name="hsm_audit", data={"verdict": "no_event"}, weight="low")
    action = _action(event)
    if action in _HSM_HIGH_RISK_OPERATIONS:
        return ToolResult(name="hsm_audit", data={
            "action": action, "high_risk": True,
        }, weight="high")
    if action.startswith(("thales:", "ncipher:", "luna:")):
        return ToolResult(name="hsm_audit", data={
            "action": action, "high_risk": False,
        }, weight="medium")
    return ToolResult(name="hsm_audit", data={
        "action": action, "tracked": False,
    }, weight="low")


_EXTRA_NAMES = (
    "PutBucketPolicy", "s3:PutBucketPolicy", "Microsoft.Storage/storageAccounts/write", "PutBucketEncryption",
    "DeleteBucketEncryption", "PutBucketPublicAccessBlock", "AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules",
    "Microsoft.Network/networkSecurityGroups/securityRules/write", "Microsoft.Network/networkSecurityGroups/write",
    "CreateVpcPeeringConnection", "AcceptVpcPeeringConnection", "CreateVpnConnection", "CreateClientVpnEndpoint",
    "Microsoft.Network/virtualNetworkGateways/write", "network.security_group_rule.create.end",
    "network.security_group_rule.created",
)
_CANON: dict[str, str] = {n.lower(): n for group in (
    _HIGH_RISK_IAM_ACTIONS, _KMS_HIGH, _KMS_MEDIUM, _LOG_DISABLE_ACTIONS, _FIREWALL_WEAKENING_ACTIONS,
    _RESOURCE_CREATE_ACTIONS, _HSM_HIGH_RISK_OPERATIONS, _EXTRA_NAMES) for n in group}

_ANY_SOURCE = {"*", "any", "internet", "0.0.0.0/0", "::/0", "0.0.0.0", "all"}


def _is_internet(cidr: str) -> bool:
    """Any source, or a public range of /8 or wider: ``0.0.0.0/1`` + ``128.0.0.0/1`` is the whole internet in two
    rules, and only the exact ``0.0.0.0/0`` string used to count (round 4 S4-12)."""
    c = str(cidr).strip().lower()
    if c in _ANY_SOURCE:
        return True
    try:
        net = ipaddress.ip_network(c, strict=False)
    except ValueError:
        return False
    wide = net.prefixlen <= (8 if net.version == 4 else 16)
    return wide and not (net.is_private or net.is_loopback or net.is_link_local or net.is_multicast)


def _items(v) -> list:
    if isinstance(v, dict) and "items" in v:
        v = v["items"]
    if isinstance(v, dict):
        return [v]
    return list(v) if isinstance(v, (list, tuple)) else ([] if v in (None, "") else [v])


def _ports(lo, hi, proto="") -> tuple[int, int]:
    if str(proto) in ("-1", "all", "*") or str(lo).strip().lower() in ("*", "any", "-1"):
        return 0, 65535
    if isinstance(lo, str) and "-" in lo:
        a, _, b = lo.partition("-")
        lo, hi = a, b
    try:
        lo_n = int(lo)
    except (TypeError, ValueError):
        return (0, 65535) if lo in (None, "") and hi in (None, "") else (0, 0)
    try:
        hi_n = int(hi) if hi not in (None, "") else lo_n
    except (TypeError, ValueError):
        hi_n = lo_n
    return (lo_n, hi_n) if lo_n <= hi_n else (hi_n, lo_n)


def _ingress_rules(params: dict) -> list[tuple[str, int, int]]:
    """Every (source, port-low, port-high) a security-group / NSG change opens — CloudTrail
    (``ipPermissions.items[].ipRanges.items[].cidrIp``, IPv6, the flat ``cidrIp``/``fromPort``/``toPort``
    form, ``ModifySecurityGroupRules``) and Azure (``securityRules[].properties``, ``sourceAddressPrefix(es)``,
    ``destinationPortRange(s)``)."""
    out: list[tuple[str, int, int]] = []
    perms = _items(params.get("ipPermissions"))
    for p in perms:
        if not isinstance(p, dict):
            continue
        lo, hi = _ports(p.get("fromPort"), p.get("toPort"), p.get("ipProtocol", ""))
        cidrs = [r.get("cidrIp") for r in _items(p.get("ipRanges")) if isinstance(r, dict)]
        cidrs += [r.get("cidrIpv6") for r in _items(p.get("ipv6Ranges")) if isinstance(r, dict)]
        cidrs += [p.get("cidrIp")] if p.get("cidrIp") else []
        out += [(str(c), lo, hi) for c in cidrs if c]
    for r in _items((params.get("ModifySecurityGroupRulesRequest") or {}).get("SecurityGroupRule")) + _items(params.get("securityGroupRules")):
        if isinstance(r, dict):
            body = r.get("SecurityGroupRule") if isinstance(r.get("SecurityGroupRule"), dict) else r
            lo, hi = _ports(body.get("FromPort"), body.get("ToPort"), body.get("IpProtocol", ""))
            for c in (body.get("CidrIpv4"), body.get("CidrIpv6")):
                if c:
                    out.append((str(c), lo, hi))
    if params.get("cidrIp") and not perms:
        lo, hi = _ports(params.get("fromPort"), params.get("toPort"), params.get("ipProtocol", ""))
        out.append((str(params["cidrIp"]), lo, hi))
    az = [r.get("properties", r) for r in _items(params.get("securityRules")) if isinstance(r, dict)]
    if params.get("sourceAddressPrefix") or params.get("sourceAddressPrefixes"):
        az.append(params)
    for r in az:
        if str(r.get("direction") or "Inbound").lower() != "inbound" or str(r.get("access") or "Allow").lower() != "allow":
            continue
        srcs = [r.get("sourceAddressPrefix")] + list(r.get("sourceAddressPrefixes") or [])
        ranges = [r.get("destinationPortRange")] + list(r.get("destinationPortRanges") or [])
        for c in (x for x in srcs if x):
            for pr in (x for x in ranges if x not in (None, "")):
                lo, hi = _ports(pr, None)
                out.append((str(c), lo, hi))
    return out


def run_all_tools(alert: dict) -> list[ToolResult]:
    event = alert.get("event") or alert
    return [
        isolated(lambda: iam_change_check(event), "iam_change_check", ToolResult),
        isolated(lambda: resource_policy_check(event), "resource_policy_check", ToolResult),
        isolated(lambda: network_change_check(event), "network_change_check", ToolResult),
        isolated(lambda: secrets_or_kms_change_check(event), "secrets_or_kms_change_check", ToolResult),
        isolated(lambda: logging_disable_check(event), "logging_disable_check", ToolResult),
        isolated(lambda: firewall_audit_check(event), "firewall_audit_check", ToolResult),
        isolated(lambda: k8s_audit_check(event), "k8s_audit_check", ToolResult),
        isolated(lambda: resource_burst_check(event), "resource_burst_check", ToolResult),
        isolated(lambda: hsm_audit_check(event), "hsm_audit_check", ToolResult),
    ]
