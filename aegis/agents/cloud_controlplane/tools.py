"""Tools for the Cloud Control-Plane specialist.

Five posture-aware checks against cloud control-plane events. Inputs
are either CloudTrail-shaped (eventName, requestParameters,
userIdentity) or Azure-Activity-shaped (operationName, properties,
caller). The checks abstract over the source so the agent can reason
about both with one toolkit.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


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
}


def iam_change_check(event: dict | None) -> ToolResult:
    """Inspect an IAM-domain control-plane event for posture-weakening
    patterns: wildcard policies, dangerous role grants, new long-lived
    credentials on service principals.
    """
    if not event:
        return ToolResult(name="iam_change", data={"verdict": "no_event"}, weight="low")

    # OpenStack Keystone events use `event_type` instead of eventName.
    action = (event.get("eventName")
              or event.get("operationName")
              or event.get("event_type")
              or "")
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

    params = event.get("requestParameters") or event.get("properties") or {}
    # Wildcard scan in policy document
    policy_text = str(params.get("policyDocument") or params.get("roleDefinition") or "")
    has_wildcard = '"Action": "*"' in policy_text or '"Resource": "*"' in policy_text or '"actions": ["*"]' in policy_text
    has_dangerous_role = any(role in policy_text for role in _DANGEROUS_ROLES)
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

_PUBLIC_PRINCIPAL_RX = re.compile(r'"Principal"\s*:\s*"\*"|"Principal"\s*:\s*\{\s*"AWS"\s*:\s*"\*"\s*\}')


def resource_policy_check(event: dict | None) -> ToolResult:
    """Detects bucket-policy / blob-container-ACL / KMS-key-policy
    changes that grant public access or remove encryption.
    """
    if not event:
        return ToolResult(name="resource_policy", data={"verdict": "no_event"}, weight="low")

    action = event.get("eventName") or event.get("operationName") or ""
    params = event.get("requestParameters") or event.get("properties") or {}

    if action in ("PutBucketPolicy", "s3:PutBucketPolicy",
                  "Microsoft.Storage/storageAccounts/write"):
        policy = str(params.get("bucketPolicy") or params.get("policy") or params.get("publicNetworkAccess") or "")
        is_public = bool(_PUBLIC_PRINCIPAL_RX.search(policy)) or '"Effect": "Allow"' in policy and '"*"' in policy or '"Enabled"' in policy
        return ToolResult(name="resource_policy", data={
            "action": action, "grants_public": is_public,
        }, weight="high" if is_public else "low")

    if action in ("PutBucketEncryption", "DeleteBucketEncryption"):
        removed = action == "DeleteBucketEncryption"
        return ToolResult(name="resource_policy", data={
            "action": action, "encryption_removed": removed,
        }, weight="high" if removed else "low")

    if action in ("PutBucketPublicAccessBlock",):
        block = (params.get("publicAccessBlockConfiguration") or {})
        weakened = not all(block.get(k, True) for k in [
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

    action = (event.get("eventName")
              or event.get("operationName")
              or event.get("event_type")
              or "")
    params = event.get("requestParameters") or event.get("properties") or event.get("payload") or {}

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

    if action in ("AuthorizeSecurityGroupIngress",
                  "Microsoft.Network/networkSecurityGroups/securityRules/write"):
        cidr = ""
        for rule_key in ("ipPermissions", "securityRules", "rules"):
            rules = params.get(rule_key) or []
            if isinstance(rules, list) and rules:
                first = rules[0] or {}
                cidr = (first.get("cidrIp") or first.get("sourceAddressPrefix")
                        or (first.get("ipRanges") or [{}])[0].get("cidrIp", "")) if isinstance(first, dict) else ""
                break
        cidr = cidr or str(params.get("cidrIp") or params.get("sourceAddressPrefix") or "")
        port = params.get("toPort") or params.get("destinationPortRange") or 0
        try:
            port_n = int(port) if str(port).isdigit() else 0
        except (TypeError, ValueError):
            port_n = 0
        opens_internet = _INTERNET_CIDR in cidr or "Internet" in cidr
        sensitive = port_n in _SENSITIVE_PORTS or str(port) in {"*", "any"}
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

def secrets_or_kms_change_check(event: dict | None) -> ToolResult:
    """Detects key disable/delete and secret rotation/exfil-shape
    operations on KMS / Key Vault / Secret Manager.
    """
    if not event:
        return ToolResult(name="secrets_kms_change", data={"verdict": "no_event"}, weight="low")

    action = event.get("eventName") or event.get("operationName") or ""
    high_risk = action in {
        "DisableKey", "ScheduleKeyDeletion", "kms:DisableKey", "kms:ScheduleKeyDeletion",
        "Microsoft.KeyVault/vaults/keys/delete",
        "Microsoft.KeyVault/vaults/secrets/delete",
        "DeleteSecret", "secretsmanager:DeleteSecret",
        "google.cloud.kms.v1.KeyManagementService.DestroyCryptoKeyVersion",
    }
    medium_risk = action in {
        "CreateGrant", "kms:CreateGrant",
        "GetSecretValue",  # only medium because routine — frequency comes from agent's reasoning
    }
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
    "Microsoft.Insights/diagnosticSettings/delete",
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

    action = (event.get("eventName")
              or event.get("operationName")
              or event.get("event_type")
              or "")
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

    action = event.get("eventName") or event.get("operationName") or ""
    rule = event.get("requestParameters") or event.get("properties") or {}
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

    high_risk_combo = (verb, full_resource) in _K8S_HIGH_RISK_VERBS_RESOURCES

    # Privileged container creation
    pod_features: list[str] = []
    if verb == "create" and resource == "pods":
        spec = ((event.get("requestObject") or {}).get("spec") or {})
        sec = spec.get("securityContext") or {}
        if sec.get("privileged"):
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
    action = (event.get("eventName")
              or event.get("operationName")
              or event.get("event_type")
              or "")
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
    action = (event.get("eventName")
              or event.get("operationName")
              or event.get("event_type")
              or "")
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


def run_all_tools(alert: dict) -> list[ToolResult]:
    event = alert.get("event") or alert
    return [
        iam_change_check(event),
        resource_policy_check(event),
        network_change_check(event),
        secrets_or_kms_change_check(event),
        logging_disable_check(event),
        firewall_audit_check(event),
        k8s_audit_check(event),
        resource_burst_check(event),
        hsm_audit_check(event),
    ]
