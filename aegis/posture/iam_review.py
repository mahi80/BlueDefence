"""IAM review — every identity in the account, not just the ones that changed today.

Inputs (the same shape offline or live, see ``sources.py``):

* ``auth_details`` — ``aws iam get-account-authorization-details`` output
  (UserDetailList / GroupDetailList / RoleDetailList / Policies).
* ``credential_report`` — rows of the IAM credential report (MFA, password and key age/use, root).
  Optional: without it the credential-hygiene checks are skipped and the report says so.

The runtime ``cloud_controlplane.iam_change_check`` catches a risky IAM *change* as it happens; this
finds the standing risk: the admin user nobody removed, the key that is two years old, the role any
AWS account can assume.

Checks map to CIS AWS Foundations Benchmark v2.0 where one exists.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote

from .base import PostureFinding, sort_findings

CIS = "CIS AWS Foundations v2.0"
ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"

# Actions that let a principal grant itself more access — any of these on Resource "*" is a
# privilege-escalation path even without "*:*".
PRIVESC_ACTIONS = {
    "iam:*", "iam:passrole", "iam:createpolicyversion", "iam:setdefaultpolicyversion",
    "iam:attachuserpolicy", "iam:attachrolepolicy", "iam:attachgrouppolicy",
    "iam:putuserpolicy", "iam:putrolepolicy", "iam:putgrouppolicy",
    "iam:createaccesskey", "iam:updateassumerolepolicy", "iam:createloginprofile",
    "iam:updateloginprofile", "sts:assumerole",
}


def _f(**kw: Any) -> PostureFinding:
    kw.setdefault("confidence", 0.95)
    kw.setdefault("category", "misconfig")
    return PostureFinding(scanner="iam_review", **kw)


# ---- policy helpers -------------------------------------------------------------------------------

def _doc(raw: Any) -> dict:
    """Policy documents arrive as dicts (CLI/boto3) or URL-encoded JSON strings (raw API)."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(unquote(raw))
        except json.JSONDecodeError:
            return {}
    return {}


def _as_list(v: Any) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _allow_statements(doc: dict) -> Iterable[dict]:
    for st in _as_list(doc.get("Statement")):
        if isinstance(st, dict) and st.get("Effect") == "Allow":
            yield st


def _is_full_admin(doc: dict) -> bool:
    for st in _allow_statements(doc):
        actions = {str(a).lower() for a in _as_list(st.get("Action"))}
        if ("*" in actions or "*:*" in actions) and "*" in _as_list(st.get("Resource")):
            return True
    return False


def _privesc_actions(doc: dict) -> set[str]:
    hits: set[str] = set()
    for st in _allow_statements(doc):
        if "*" not in _as_list(st.get("Resource")):
            continue
        for a in _as_list(st.get("Action")):
            a = str(a).lower()
            if a in PRIVESC_ACTIONS:
                hits.add(a)
    return hits


def _default_version_doc(policy: dict) -> dict:
    for v in policy.get("PolicyVersionList", []):
        if v.get("IsDefaultVersion"):
            return _doc(v.get("Document"))
    return {}


# ---- credential-report helpers --------------------------------------------------------------------

def _ts(v: str | None) -> datetime | None:
    if not v or v in ("N/A", "not_supported", "no_information"):
        return None
    try:
        return datetime.fromisoformat(v)
    except ValueError:
        return None


def _days(since: datetime | None, now: datetime) -> int | None:
    return None if since is None else (now - since).days


def _true(v: str | None) -> bool:
    return str(v).lower() == "true"


# ---- the review -----------------------------------------------------------------------------------

def review(
    auth_details: dict,
    credential_report: list[dict[str, str]] | None = None,
    *,
    now: datetime | None = None,
    trusted_accounts: Iterable[str] = (),
    unused_days: int = 45,
    rotate_days: int = 90,
) -> list[PostureFinding]:
    """Return IAM posture findings, most severe first."""
    now = now or datetime.now(UTC)
    trusted = {str(a) for a in trusted_accounts}
    out: list[PostureFinding] = []

    policies = {p.get("Arn"): p for p in auth_details.get("Policies", [])}
    groups = {g.get("GroupName"): g for g in auth_details.get("GroupDetailList", [])}

    def managed_is_admin(arn: str) -> bool:
        return arn == ADMIN_POLICY_ARN or (arn in policies and _is_full_admin(_default_version_doc(policies[arn])))

    # 1. Customer-managed policies that grant full admin or a privilege-escalation path (CIS 1.16).
    for arn, p in policies.items():
        if arn.startswith("arn:aws:iam::aws:policy/") or not p.get("AttachmentCount", 1):
            continue  # AWS-managed policies are judged where they are attached; unattached ones are inert
        doc = _default_version_doc(p)
        if _is_full_admin(doc):
            out.append(_f(id="IAM-POLICY-FULL-ADMIN", severity="high", resource=arn, control=f"{CIS} 1.16",
                          affected_component=p.get("PolicyName", arn),
                          evidence='customer-managed policy allows Action "*" on Resource "*"',
                          recommended_remediation="Replace with least-privilege statements scoped to the actions and resources the role needs"))
        elif (pe := _privesc_actions(doc)):
            out.append(_f(id="IAM-POLICY-PRIVESC", severity="high", resource=arn, confidence=0.85,
                          affected_component=p.get("PolicyName", arn),
                          evidence=f"policy allows privilege-escalation actions on Resource \"*\": {', '.join(sorted(pe))}",
                          recommended_remediation="Scope these actions to specific resources, or move them behind a break-glass role"))

    # 2. Users: admin rights, direct attachment, inline wildcards.
    for u in auth_details.get("UserDetailList", []):
        name, arn = u.get("UserName", "?"), u.get("Arn")
        direct = [a.get("PolicyArn", "") for a in u.get("AttachedManagedPolicies", [])]
        via_group = [a.get("PolicyArn", "") for g in u.get("GroupList", []) for a in groups.get(g, {}).get("AttachedManagedPolicies", [])]
        inline = [_doc(p.get("PolicyDocument")) for p in u.get("UserPolicyList", [])]
        inline += [_doc(p.get("PolicyDocument")) for g in u.get("GroupList", []) for p in groups.get(g, {}).get("GroupPolicyList", [])]

        if any(managed_is_admin(a) for a in direct + via_group) or any(_is_full_admin(d) for d in inline):
            out.append(_f(id="IAM-USER-ADMIN", severity="high", resource=arn, affected_component=name,
                          evidence="IAM user holds full administrator rights (directly, via a group, or inline)",
                          recommended_remediation="Remove standing admin from users; grant it through a role assumed with MFA and logged"))
        if direct or u.get("UserPolicyList"):
            out.append(_f(id="IAM-USER-DIRECT-POLICY", severity="low", resource=arn, affected_component=name, control=f"{CIS} 1.15",
                          evidence=f"{len(direct)} managed + {len(u.get('UserPolicyList', []))} inline policies attached directly to the user",
                          recommended_remediation="Attach permissions to groups or roles and add the user to the group"))

    # 3. Roles: who can assume them.
    for r in auth_details.get("RoleDetailList", []):
        name, arn = r.get("RoleName", "?"), r.get("Arn")
        if r.get("Path", "").startswith("/aws-service-role/"):
            continue
        trust = _doc(r.get("AssumeRolePolicyDocument"))
        for st in _allow_statements(trust):
            principals = st.get("Principal")
            aws = principals if principals == "*" else _as_list((principals or {}).get("AWS")) if isinstance(principals, dict) else []
            cond = st.get("Condition") or {}
            if principals == "*" or "*" in aws:
                out.append(_f(id="IAM-ROLE-TRUST-ANYONE", severity="high" if cond else "critical", resource=arn, affected_component=name,
                              evidence="role trust policy allows Principal \"*\"" + (" (with a Condition)" if cond else " with no Condition — any AWS account can assume it"),
                              recommended_remediation="Restrict the trust policy to named principals; add aws:PrincipalOrgID or sts:ExternalId conditions"))
                continue
            for p in aws:
                acct = p.split(":")[4] if str(p).startswith("arn:aws:") else str(p)
                if acct.isdigit() and acct not in trusted and acct != arn.split(":")[4]:
                    has_ext_id = "sts:ExternalId" in json.dumps(cond)
                    out.append(_f(id="IAM-ROLE-CROSS-ACCOUNT", severity="medium" if has_ext_id else "high", resource=arn,
                                  affected_component=name, confidence=0.8,
                                  evidence=f"role is assumable from external account {acct}" + ("" if has_ext_id else " without an sts:ExternalId condition"),
                                  recommended_remediation=f"Confirm account {acct} is an approved vendor; add it to trusted accounts or require sts:ExternalId"))
        inline = [_doc(p.get("PolicyDocument")) for p in r.get("RolePolicyList", [])]
        if any(_is_full_admin(d) for d in inline):
            out.append(_f(id="IAM-ROLE-INLINE-ADMIN", severity="high", resource=arn, affected_component=name, control=f"{CIS} 1.16",
                          evidence="role has an inline policy allowing Action \"*\" on Resource \"*\"",
                          recommended_remediation="Replace the inline wildcard with a scoped managed policy"))

    # 4. Credential hygiene from the credential report.
    for row in credential_report or []:
        user = row.get("user", "?")
        arn = row.get("arn")
        if user == "<root_account>":
            if _true(row.get("access_key_1_active")) or _true(row.get("access_key_2_active")):
                out.append(_f(id="IAM-ROOT-ACCESS-KEY", severity="critical", resource=arn, affected_component="root", control=f"{CIS} 1.4",
                              evidence="the root account has an active access key",
                              recommended_remediation="Delete root access keys; use IAM roles for all programmatic access"))
            if not _true(row.get("mfa_active")):
                out.append(_f(id="IAM-ROOT-NO-MFA", severity="critical", resource=arn, affected_component="root", control=f"{CIS} 1.5",
                              evidence="the root account has no MFA device",
                              recommended_remediation="Enable hardware MFA on the root account and lock the device away"))
            continue

        if _true(row.get("password_enabled")) and not _true(row.get("mfa_active")):
            out.append(_f(id="IAM-USER-NO-MFA", severity="high", resource=arn, affected_component=user, control=f"{CIS} 1.10",
                          evidence="console password enabled but no MFA device",
                          recommended_remediation="Enforce MFA for every console user (deny-without-MFA policy)"))

        pw_idle = _days(_ts(row.get("password_last_used")), now) if _true(row.get("password_enabled")) else None
        if pw_idle is not None and pw_idle > unused_days:
            out.append(_f(id="IAM-USER-INACTIVE-PASSWORD", severity="medium", resource=arn, affected_component=user, control=f"{CIS} 1.12",
                          evidence=f"console password unused for {pw_idle} days",
                          recommended_remediation="Disable the console password; remove the user if it is no longer needed"))

        active_keys = 0
        for n in ("1", "2"):
            if not _true(row.get(f"access_key_{n}_active")):
                continue
            active_keys += 1
            age = _days(_ts(row.get(f"access_key_{n}_last_rotated")), now)
            used = _days(_ts(row.get(f"access_key_{n}_last_used_date")), now)
            if age is not None and age > rotate_days:
                out.append(_f(id="IAM-KEY-NOT-ROTATED", severity="medium", resource=arn, affected_component=f"{user} key {n}", control=f"{CIS} 1.14",
                              evidence=f"access key {n} is {age} days old",
                              recommended_remediation=f"Rotate keys at least every {rotate_days} days, or replace with role-based access"))
            idle = used if used is not None else age
            if idle is not None and idle > unused_days:
                out.append(_f(id="IAM-KEY-UNUSED", severity="medium", resource=arn, affected_component=f"{user} key {n}", control=f"{CIS} 1.12",
                              evidence=f"access key {n} " + ("never used" if used is None else f"unused for {used} days") + f" ({age} days old)",
                              recommended_remediation="Deactivate the key; delete it after a grace period if nothing breaks"))
        if active_keys > 1:
            out.append(_f(id="IAM-USER-TWO-KEYS", severity="low", resource=arn, affected_component=user, control=f"{CIS} 1.13",
                          evidence="user has two active access keys",
                          recommended_remediation="Keep one active key per user; delete the other once rotation is done"))

    return sort_findings(out)


def coverage_note(credential_report: list | None) -> str | None:
    if credential_report is None:
        return "credential report not supplied: MFA, root-account, key-age and inactivity checks were skipped"
    return None
