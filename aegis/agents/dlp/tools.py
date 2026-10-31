"""Tools for the DLP / data-exfiltration specialist.

Five checks against egress / bulk-read / HR-signal events. Designed to
fire BOTH on compromised-admin smash-grab and on insider exfiltration
with valid credentials.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class ToolResult:
    name: str
    data: dict
    weight: str


# ---- Bulk-read check (record / row count + table sensitivity) -------

# Per-table sensitivity. Production: pull from a data-classification
# layer (Microsoft Purview, BigID, in-house tagging).
_TABLE_SENSITIVITY = {
    "customers":          {"sensitivity": "high",     "max_normal_rows_per_session": 200},
    "customer_kyc":       {"sensitivity": "critical", "max_normal_rows_per_session": 50},
    "transactions":       {"sensitivity": "high",     "max_normal_rows_per_session": 500},
    "loan_applications":  {"sensitivity": "high",     "max_normal_rows_per_session": 100},
    "employee_payroll":   {"sensitivity": "high",     "max_normal_rows_per_session": 50},
    "audit_log":          {"sensitivity": "medium",   "max_normal_rows_per_session": 10000},
    "products":           {"sensitivity": "low",      "max_normal_rows_per_session": 10000},
    "rates":              {"sensitivity": "low",      "max_normal_rows_per_session": 10000},
}


def bulk_read_check(table: str | None, rows_returned: int | None,
                    queries_per_session: int | None = None) -> ToolResult:
    if not table or rows_returned is None:
        return ToolResult(name="bulk_read", data={"verdict": "insufficient_data"}, weight="low")
    info = _TABLE_SENSITIVITY.get(table, {"sensitivity": "medium", "max_normal_rows_per_session": 1000})
    threshold = info["max_normal_rows_per_session"]
    ratio = rows_returned / threshold if threshold > 0 else 0.0
    sensitivity = info["sensitivity"]

    if sensitivity in ("critical", "high") and ratio >= 5.0:
        weight = "high"
    elif sensitivity == "critical" and ratio >= 2.0:
        weight = "high"
    elif ratio >= 5.0:
        weight = "medium"
    elif ratio >= 2.0:
        weight = "medium"
    else:
        weight = "low"
    return ToolResult(name="bulk_read", data={
        "table": table, "rows_returned": rows_returned,
        "max_normal": threshold, "ratio_over_baseline": round(ratio, 2),
        "sensitivity": sensitivity,
        "queries_per_session": queries_per_session,
        "is_bulk_anomaly": ratio >= 2.0,
    }, weight=weight)


# ---- Sensitive-data pattern check (PII / PCI / source-code) ---------

# Lightweight detectors. Production: regex+ML (Microsoft Purview,
# Google DLP API) and a centralized taxonomy.
_SENSITIVE_RX = {
    "aadhaar":          re.compile(r"\b\d{4}\s\d{4}\s\d{4}\b"),
    "pan_in":           re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
    "credit_card":      re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "ifsc":             re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
    "account_number":   re.compile(r"\b(?:ACC|ACCT)[-_]?\d{8,12}\b"),
    "swift_bic":        re.compile(r"\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b"),
    "private_key":      re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    "aws_key":          re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_token":     re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
}


def sensitive_data_pattern_check(payload: str | None,
                                 context: str = "data") -> ToolResult:
    if not payload:
        return ToolResult(name="sensitive_pattern", data={"verdict": "no_payload"}, weight="low")
    findings: dict[str, int] = {}
    for kind, rx in _SENSITIVE_RX.items():
        matches = rx.findall(payload)
        if matches:
            findings[kind] = len(matches)
    if not findings:
        return ToolResult(name="sensitive_pattern", data={
            "context": context, "findings": {},
        }, weight="low")
    crit_kinds = {"private_key", "aws_key", "github_token"}
    critical_hit = any(k in findings for k in crit_kinds)
    pii_count = sum(findings.get(k, 0) for k in ("aadhaar", "pan_in", "credit_card", "ifsc", "account_number"))
    if critical_hit:
        weight = "high"
    elif pii_count >= 50:
        weight = "high"
    elif pii_count >= 5:
        weight = "medium"
    else:
        weight = "low"
    return ToolResult(name="sensitive_pattern", data={
        "context": context, "findings": findings,
        "critical_secret": critical_hit, "pii_count": pii_count,
    }, weight=weight)


# ---- External-recipient check (email / share-link) ------------------

_INTERNAL_DOMAINS = {"bank.in", "bank.example", "corp.bank.in"}


def external_recipient_check(recipients: list[str] | None,
                              attachment_summary: str | None = None) -> ToolResult:
    if not recipients:
        return ToolResult(name="external_recipient", data={"verdict": "no_recipients"}, weight="low")
    external = []
    for r in recipients:
        if "@" not in r:
            continue
        domain = r.split("@", 1)[1].lower()
        if not any(domain == d or domain.endswith("." + d) for d in _INTERNAL_DOMAINS):
            external.append(r)
    if not external:
        return ToolResult(name="external_recipient", data={
            "internal_only": True, "external_count": 0,
        }, weight="low")
    has_attachment = bool(attachment_summary)
    if len(external) >= 10 and has_attachment:
        weight = "high"
    elif has_attachment:
        weight = "medium"
    else:
        weight = "low"
    return ToolResult(name="external_recipient", data={
        "external_recipients": external,
        "external_count": len(external),
        "has_attachment": has_attachment,
        "attachment_summary": attachment_summary,
    }, weight=weight)


# ---- HR-risk signal check (insider-threat enrichment) ---------------

# Mock per-user HR risk flags. Production: bidirectional integration
# with Workday / SAP SuccessFactors / in-house HR. Strict access
# controls — auth specialist + DLP are the only consumers.
_HR_RISK_FLAGS: dict[str, dict] = {
    "u_42891": {},
    "u_77104": {},
    "u_admin_99": {},
    "u_resigning_alice": {
        "resignation_submitted": True,
        "resignation_date": "2026-04-25",
        "last_day": "2026-05-09",
        "reason": "voluntary",
    },
    "u_pip_bob": {
        "performance_review_failed": True,
        "pip_started": "2026-03-15",
    },
}


def hr_risk_signal_check(user_id: str | None) -> ToolResult:
    if not user_id:
        return ToolResult(name="hr_risk", data={"verdict": "no_user"}, weight="low")
    flags = _HR_RISK_FLAGS.get(user_id) or {}
    if not flags:
        return ToolResult(name="hr_risk", data={
            "user_id": user_id, "has_hr_risk": False,
        }, weight="low")
    weight = "high" if (flags.get("resignation_submitted") or flags.get("performance_review_failed")) else "medium"
    return ToolResult(name="hr_risk", data={
        "user_id": user_id, "has_hr_risk": True, "flags": flags,
    }, weight=weight)


# ---- Egress-volume anomaly check (S3 / Blob / GCS GetObject) --------

# Per-principal baseline egress in MB / hour. Production: compute
# rolling p99 on the audit-log-derived series.
_EGRESS_BASELINE_MB_PER_HOUR = {
    "u_42891":          50.0,
    "u_77104":          120.0,
    "u_admin_99":       500.0,    # admins legitimately move more
    "u_resigning_alice": 80.0,
    "u_pip_bob":        70.0,
}


def egress_volume_anomaly_check(user_id: str | None,
                                observed_mb_last_hour: float | None) -> ToolResult:
    if not user_id or observed_mb_last_hour is None:
        return ToolResult(name="egress_volume", data={"verdict": "insufficient_data"}, weight="low")
    baseline = _EGRESS_BASELINE_MB_PER_HOUR.get(user_id, 100.0)
    ratio = observed_mb_last_hour / baseline if baseline > 0 else 0.0
    if ratio >= 10.0:
        weight = "high"
    elif ratio >= 3.0:
        weight = "medium"
    else:
        weight = "low"
    return ToolResult(name="egress_volume", data={
        "user_id": user_id,
        "observed_mb_last_hour": observed_mb_last_hour,
        "baseline_mb_per_hour_p99": baseline,
        "ratio_over_baseline": round(ratio, 2),
        "is_egress_anomaly": ratio >= 3.0,
    }, weight=weight)


def run_all_tools(alert: dict) -> list[ToolResult]:
    return [
        bulk_read_check(
            alert.get("table"),
            alert.get("rows_returned"),
            alert.get("queries_per_session"),
        ),
        sensitive_data_pattern_check(
            alert.get("payload") or alert.get("query") or alert.get("attachment_text"),
            context=alert.get("source", "data"),
        ),
        external_recipient_check(
            alert.get("recipients"),
            alert.get("attachment_summary"),
        ),
        hr_risk_signal_check(alert.get("user_id") or alert.get("principal_id")),
        egress_volume_anomaly_check(
            alert.get("user_id") or alert.get("principal_id"),
            alert.get("observed_mb_last_hour"),
        ),
    ]
