"""Tools for the Email / Phishing specialist."""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class ToolResult:
    name: str
    data: dict
    weight: str


# ---- Header authentication (SPF / DKIM / DMARC) --------------------

def header_auth_check(headers: dict | None) -> ToolResult:
    if not headers:
        return ToolResult(name="header_auth", data={"verdict": "no_headers"}, weight="low")
    spf = (headers.get("spf") or headers.get("Received-SPF") or "").lower()
    dkim = (headers.get("dkim") or headers.get("DKIM-Signature") or "").lower()
    dmarc = (headers.get("dmarc") or headers.get("Authentication-Results") or "").lower()

    spf_fail = "fail" in spf or "softfail" in spf
    dkim_fail = "fail" in dkim or (dkim == "")
    dmarc_fail = "fail" in dmarc or "dmarc=fail" in dmarc
    fails = sum([spf_fail, dkim_fail, dmarc_fail])
    if fails >= 2:
        weight = "high"
    elif fails == 1:
        weight = "medium"
    else:
        weight = "low"
    return ToolResult(name="header_auth", data={
        "spf_fail": spf_fail, "dkim_fail": dkim_fail, "dmarc_fail": dmarc_fail,
        "fail_count": fails,
    }, weight=weight)


# ---- Display-name spoof check --------------------------------------

# Internal display names that attackers commonly impersonate.
_PROTECTED_DISPLAY_NAMES = {
    "ceo", "cfo", "head of operations", "chief risk officer",
    "rbi", "reserve bank of india", "treasury",
    "compliance", "internal audit", "head of it",
}


def display_name_spoof_check(from_display: str | None,
                             from_address: str | None) -> ToolResult:
    if not from_display or not from_address:
        return ToolResult(name="display_spoof", data={"verdict": "no_data"}, weight="low")
    display_lower = from_display.lower().strip()
    address_domain = from_address.split("@", 1)[-1].lower() if "@" in from_address else ""
    is_internal_domain = address_domain.endswith("bank.in") or address_domain.endswith("bank.example")
    impersonates_protected = any(
        name in display_lower for name in _PROTECTED_DISPLAY_NAMES
    )
    spoof = impersonates_protected and not is_internal_domain
    return ToolResult(name="display_spoof", data={
        "display": from_display, "address": from_address,
        "domain": address_domain, "internal_domain": is_internal_domain,
        "impersonates_protected_role": impersonates_protected,
        "is_spoof": spoof,
    }, weight="high" if spoof else "low")


# ---- Lookalike domain check ----------------------------------------

# Tier-1 brands an attacker commonly typo-squats against.
_PROTECTED_DOMAINS = {
    "rbi.org.in", "bank.in", "sbi.co.in", "icici.com", "hdfc.com",
    "irctc.co.in", "incometaxindiaefiling.gov.in",
}

_HOMOGLYPH_PAIRS = [("0", "o"), ("1", "l"), ("rn", "m"), ("vv", "w"), ("cl", "d")]


def _is_lookalike(domain: str, target: str) -> bool:
    """Cheap lookalike: edit-distance 1, or homoglyph swap."""
    if domain == target:
        return False
    # Homoglyph swap
    for a, b in _HOMOGLYPH_PAIRS:
        if domain.replace(a, b) == target or domain.replace(b, a) == target:
            return True
    # Edit-distance 1 (single char insert / delete / substitute)
    if abs(len(domain) - len(target)) > 1:
        return False
    diffs = 0
    if len(domain) == len(target):
        for c1, c2 in zip(domain, target):
            if c1 != c2:
                diffs += 1
                if diffs > 1:
                    return False
        return diffs == 1
    longer, shorter = (domain, target) if len(domain) > len(target) else (target, domain)
    i = j = 0
    edits = 0
    while i < len(longer) and j < len(shorter):
        if longer[i] != shorter[j]:
            edits += 1
            if edits > 1:
                return False
            i += 1
        else:
            i += 1
            j += 1
    return True


def lookalike_domain_check(from_address: str | None,
                           urls_in_body: list[str] | None) -> ToolResult:
    if not from_address and not urls_in_body:
        return ToolResult(name="lookalike_domain", data={"verdict": "no_data"}, weight="low")
    domains_to_check: list[str] = []
    if from_address and "@" in from_address:
        domains_to_check.append(from_address.split("@", 1)[1].lower())
    for u in (urls_in_body or []):
        m = re.search(r"https?://([^/]+)", u)
        if m:
            domains_to_check.append(m.group(1).lower())
    matches: list[dict] = []
    for d in domains_to_check:
        for target in _PROTECTED_DOMAINS:
            if _is_lookalike(d, target):
                matches.append({"observed": d, "lookalike_of": target})
    weight = "high" if matches else "low"
    return ToolResult(name="lookalike_domain", data={
        "checked_domains": domains_to_check,
        "matches": matches,
    }, weight=weight)


# ---- Attachment risk check -----------------------------------------

_DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".vbs", ".js", ".wsf",
    ".jar", ".lnk", ".iso", ".img", ".chm", ".hta",
}
_OFFICE_MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm"}


def attachment_risk_check(attachments: list[dict] | None) -> ToolResult:
    if not attachments:
        return ToolResult(name="attachment_risk", data={"count": 0}, weight="low")
    dangerous = []
    macro = []
    archive = []
    for a in attachments:
        name = (a.get("filename") or a.get("name") or "").lower()
        for ext in _DANGEROUS_EXTENSIONS:
            if name.endswith(ext):
                dangerous.append(name)
                break
        for ext in _OFFICE_MACRO_EXTENSIONS:
            if name.endswith(ext):
                macro.append(name)
                break
        if name.endswith((".zip", ".rar", ".7z")):
            archive.append(name)
    if dangerous:
        weight = "high"
    elif macro:
        weight = "high"   # Office macros are the standard malware vector
    elif archive:
        weight = "medium"
    else:
        weight = "low"
    return ToolResult(name="attachment_risk", data={
        "dangerous": dangerous, "macro": macro, "archive": archive,
        "count": len(attachments),
    }, weight=weight)


# ---- Body pattern check (urgency + RBI-context bait) ---------------

_URGENCY_PHRASES = [
    "verify within 24 hours", "your account will be suspended",
    "click immediately", "wire transfer urgent", "kyc expires",
    "rbi mandate", "rbi notice", "kyc update required",
    "tax refund pending", "income tax department", "freeze account",
]
_CRED_BAITS = [
    "click here to login", "verify your password",
    "confirm your otp", "share your aadhaar",
    "enter pin to continue",
]


def body_pattern_check(subject: str | None, body: str | None) -> ToolResult:
    if not subject and not body:
        return ToolResult(name="body_pattern", data={"verdict": "no_data"}, weight="low")
    text = ((subject or "") + " " + (body or "")).lower()
    urgency_hits = [p for p in _URGENCY_PHRASES if p in text]
    cred_hits = [p for p in _CRED_BAITS if p in text]
    if cred_hits and urgency_hits:
        weight = "high"
    elif cred_hits or len(urgency_hits) >= 2:
        weight = "medium"
    elif urgency_hits:
        weight = "low"
    else:
        weight = "low"
    return ToolResult(name="body_pattern", data={
        "urgency_phrases": urgency_hits,
        "credential_bait_phrases": cred_hits,
        "phish_lexical_score": len(urgency_hits) + 2 * len(cred_hits),
    }, weight=weight)


# ---- Reply-chain anomaly (sender's send-volume baseline) -----------

_INTERNAL_SENDER_BASELINE = {
    "alice@bank.in":  {"max_external_per_hour": 10},
    "bob@bank.in":    {"max_external_per_hour": 5},
}


def reply_chain_anomaly_check(internal_sender: str | None,
                              external_send_count_last_hour: int | None) -> ToolResult:
    if not internal_sender or external_send_count_last_hour is None:
        return ToolResult(name="reply_chain", data={"verdict": "no_data"}, weight="low")
    baseline = _INTERNAL_SENDER_BASELINE.get(internal_sender, {"max_external_per_hour": 20})
    threshold = baseline["max_external_per_hour"]
    ratio = external_send_count_last_hour / threshold if threshold > 0 else 0.0
    if ratio >= 5.0:
        weight = "high"
    elif ratio >= 2.0:
        weight = "medium"
    else:
        weight = "low"
    return ToolResult(name="reply_chain", data={
        "sender": internal_sender,
        "external_send_count_last_hour": external_send_count_last_hour,
        "p99_baseline_per_hour": threshold,
        "ratio_over_baseline": round(ratio, 2),
        "is_blast_pattern": ratio >= 2.0,
    }, weight=weight)


def run_all_tools(alert: dict) -> list[ToolResult]:
    return [
        header_auth_check(alert.get("headers")),
        display_name_spoof_check(alert.get("from_display"), alert.get("from_address")),
        lookalike_domain_check(alert.get("from_address"), alert.get("urls_in_body")),
        attachment_risk_check(alert.get("attachments")),
        body_pattern_check(alert.get("subject"), alert.get("body")),
        reply_chain_anomaly_check(
            alert.get("internal_sender"),
            alert.get("external_send_count_last_hour"),
        ),
    ]
