"""Tools for the Email / Phishing specialist."""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..shared.tool_guard import isolated


@dataclass
class ToolResult:
    name: str
    data: dict
    weight: str


# ---- Header authentication (SPF / DKIM / DMARC) --------------------



def _trusted_auth_results(headers: dict) -> str:
    """The Authentication-Results our own gateway wrote. A message can carry any number of them and the sender
    writes the rest, so with ``AEGIS_MAIL_AUTHSERV_ID`` set only an A-R whose authserv-id (the text before the
    first ``;``) is one of ours counts; without it, the top-most one (the last hop's, which a receiving gateway
    prepends) does (review round 4 X4-12)."""
    import os
    raw = headers.get("authentication-results")
    items = [str(x) for x in raw] if isinstance(raw, (list, tuple)) else ([str(raw)] if raw else [])
    ours = {x.strip().lower() for x in os.environ.get("AEGIS_MAIL_AUTHSERV_ID", "").split(",") if x.strip()}
    if ours:
        items = [x for x in items if x.split(";", 1)[0].strip().lower() in ours]
    return items[0].lower() if items else ""


def _ar_methods(ar: str) -> dict[str, str]:
    """Method results from one Authentication-Results header, read per ``;``-separated resinfo: each resinfo's
    FIRST ``method=result`` token is its verdict. Property values such as ``smtp.mailfrom=`` are text the sender
    chose (an attacker's MAIL FROM local part could read ``dkim=pass.dmarc=pass@evil``) and are never scanned for
    verdicts (review round 7 D-1). The first segment is the authserv-id."""
    out: dict[str, str] = {}
    for resinfo in ar.split(";")[1:]:
        m = re.match(r"\s*(spf|dkim|dmarc)\s*=\s*([a-z]+)", resinfo)
        if m:
            out.setdefault(m.group(1), m.group(2))
    return out


def _verdict(v: str) -> str:
    """``pass (signature verified)`` → ``pass``; the first word of a method result."""
    m = re.match(r"\s*([a-z]+)", str(v or "").lower())
    return m.group(1) if m else ""


def header_auth_check(headers: dict | None) -> ToolResult:
    if not headers:
        return ToolResult(name="header_auth", data={"verdict": "no_headers"}, weight="low")
    # header names are case-insensitive: an authenticated mail with lower-case keys scored medium (round 4 S4-16)
    h = {str(k).lower(): v for k, v in headers.items()}
    ar = _trusted_auth_results(h)
    methods = _ar_methods(ar)
    # Per-method results. DMARC used to read "fail" anywhere in the whole A-R line, so a forwarded mail with a
    # broken DKIM signature and a DMARC pass was a DMARC fail too. A DKIM-Signature header is something the
    # SENDER writes; only the gateway's verdict counts (review round 3 G7-15).
    # When the gateway's A-R is present it is the only source: plain ``SPF:`` / ``DKIM:`` / ``DMARC:`` headers and
    # Received-SPF are written by the sender (or an untrusted hop) and used to override it (review round 7 D-1).
    # The shorthand keys are only read when no trusted A-R exists (pre-parsed feeds that carry verdicts that way).
    if ar:
        spf, dkim, dmarc = (_verdict(methods.get(m, "")) for m in ("spf", "dkim", "dmarc"))
    else:
        spf = _verdict(h.get("spf") or h.get("received-spf") or "")
        dkim = _verdict(h.get("dkim") or "")
        dmarc = _verdict(h.get("dmarc") or "")

    spf_fail = spf in ("fail", "softfail")
    dkim_fail = dkim != "pass"
    dmarc_fail = dmarc == "fail"
    fails = sum([spf_fail, dkim_fail, dmarc_fail])
    # DMARC pass is the domain owner's own alignment verdict: a DKIM failure under it (a forwarder, a list) is
    # not a spoof on its own
    if dmarc == "pass" and fails == 1 and dkim_fail:
        fails = 0
    if fails >= 2:
        weight = "high"
    elif fails == 1:
        weight = "medium"
    else:
        weight = "low"
    return ToolResult(name="header_auth", data={
        "spf_fail": spf_fail, "dkim_fail": dkim_fail, "dmarc_fail": dmarc_fail,
        "spf": spf or None, "dkim": dkim or None, "dmarc": dmarc or None,
        "fail_count": fails,
    }, weight=weight)


# ---- Display-name spoof check --------------------------------------

# Internal display names that attackers commonly impersonate.
_PROTECTED_DISPLAY_NAMES = {
    "ceo", "cfo", "head of operations", "chief risk officer",
    "rbi", "reserve bank of india", "treasury",
    "compliance", "internal audit", "head of it",
}


_INTERNAL_MAIL_DOMAINS = ("bank.in", "bank.example")


def display_name_spoof_check(from_display: str | None,
                             from_address: str | None) -> ToolResult:
    if not from_display or not from_address:
        return ToolResult(name="display_spoof", data={"verdict": "no_data"}, weight="low")
    display_lower = from_display.lower().strip()
    address_domain = from_address.rsplit("@", 1)[-1].lower().strip(" >.") if "@" in from_address else ""
    # dot boundary: `evilbank.in` is not `bank.in` (round 1 low, still open in round 4)
    is_internal_domain = any(address_domain == d or address_domain.endswith("." + d) for d in _INTERNAL_MAIL_DOMAINS)
    # whole words: "rbi" inside "Harbinder" was an RBI impersonation (round 4 S4-16)
    impersonates_protected = any(
        re.search(rf"(?<![a-z]){re.escape(name)}(?![a-z])", display_lower) for name in _PROTECTED_DISPLAY_NAMES
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


_GENERIC_BRANDS = {"bank"}     # "bank" as a label token is every bank's name, not an imitation of bank.in


def _glyph_fold(t: str) -> str:
    """Letters that read alike in a mail client: ``sbl`` / ``sb1`` read as ``sbi``. A short brand matches only
    through these, not through any one-letter edit (``ubi`` is a different bank, not ``sbi``)."""
    return t.translate(str.maketrans({"l": "i", "1": "i", "!": "i", "|": "i", "0": "o"}))


def _lookalike_of(domain: str, target: str) -> str:
    """How ``domain`` imitates ``target``: the whole name, its registrable part (``netbanking.sbl.co.in`` →
    ``sbl.co.in``), or the brand as a label token (``sbl-kyc.in``, ``sbi-kyc.in``) — only the full host used to be
    compared (round 4 S4-16)."""
    if domain == target or domain.endswith("." + target):
        return ""
    if _is_lookalike(domain, target):
        return "name"
    n = target.count(".") + 1
    reg = ".".join(domain.split(".")[-n:])
    if reg != target and _is_lookalike(reg, target):
        return "registrable"
    brand = target.split(".")[0]
    if len(brand) >= 3 and brand not in _GENERIC_BRANDS:
        for label in domain.split(".")[:-1]:
            for tok in re.split(r"[-_]", label):
                if tok == brand or (len(tok) == len(brand) and (
                        _is_lookalike(tok, brand) if len(brand) >= 4 else _glyph_fold(tok) == _glyph_fold(brand))):
                    return "brand"
    return ""


def lookalike_domain_check(from_address: str | None,
                           urls_in_body: list[str] | None) -> ToolResult:
    if not from_address and not urls_in_body:
        return ToolResult(name="lookalike_domain", data={"verdict": "no_data"}, weight="low")
    from urllib.parse import urlsplit
    domains_to_check: list[str] = []
    if from_address and "@" in from_address:
        domains_to_check.append(from_address.rsplit("@", 1)[1].lower().strip(" >."))
    for u in (urls_in_body or []):
        try:
            host = urlsplit(u if "://" in u else f"http://{u}").hostname or ""   # userinfo (sbi.co.in@evil) stripped
        except ValueError:
            host = ""
        if host:
            domains_to_check.append(host.lower().rstrip("."))
    matches: list[dict] = []
    for d in domains_to_check:
        if any(d == t or d.endswith("." + t) for t in _PROTECTED_DOMAINS):
            continue                                   # the genuine domain (or a host under it)
        for target in _PROTECTED_DOMAINS:
            hit = _lookalike_of(d, target)
            if hit:
                matches.append({"observed": d, "lookalike_of": target, "how": hit})
    weight = "high" if matches else "low"
    return ToolResult(name="lookalike_domain", data={
        "checked_domains": domains_to_check,
        "matches": matches,
    }, weight=weight)


# ---- Attachment risk check -----------------------------------------

_DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".vbs", ".js", ".wsf",
    ".jar", ".lnk", ".iso", ".img", ".chm", ".hta",
    # the rest of what loaders ship as (review round 3 G7-15)
    ".ps1", ".psm1", ".msi", ".msp", ".vbe", ".jse", ".wsh", ".wsc", ".pif", ".scf", ".reg", ".dll", ".cpl",
    ".msc", ".appx", ".msix", ".appinstaller", ".application", ".one", ".xll", ".vhd", ".vhdx", ".url",
    ".library-ms", ".settingcontent-ms", ".gadget", ".html", ".htm", ".shtml", ".svg", ".xht", ".xhtml",
}
_OFFICE_MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm", ".ppsm", ".xlam", ".ppam", ".xlsb", ".sldm"}
_ARCHIVE_EXTENSIONS = (".zip", ".rar", ".7z", ".cab", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".ace", ".arj", ".lzh", ".z")
_HIDE_CHARS = dict.fromkeys(map(ord, "\u202e\u202d\u202a\u202b\u202c\u2066\u2067\u2068\u2069\u200b\u200c\u200d\ufeff"))


def attachment_risk_check(attachments: list[dict] | None) -> ToolResult:
    if not attachments:
        return ToolResult(name="attachment_risk", data={"count": 0}, weight="low")
    dangerous = []
    macro = []
    archive = []
    for a in attachments:
        # "invoice<U+202E>fdp.exe" displays as invoice.pdf; Windows also drops trailing dots and spaces ("x.exe. ")
        name = str(a.get("filename") or a.get("name") or "").translate(_HIDE_CHARS).lower().rstrip(". \t")
        for ext in _DANGEROUS_EXTENSIONS:
            if name.endswith(ext):
                dangerous.append(name)
                break
        for ext in _OFFICE_MACRO_EXTENSIONS:
            if name.endswith(ext):
                macro.append(name)
                break
        if name.endswith(_ARCHIVE_EXTENSIONS):
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
        isolated(lambda: header_auth_check(alert.get("headers")), "header_auth_check", ToolResult),
        isolated(lambda: display_name_spoof_check(alert.get("from_display"), alert.get("from_address")), "display_name_spoof_check", ToolResult),
        isolated(lambda: lookalike_domain_check(alert.get("from_address"), alert.get("urls_in_body")), "lookalike_domain_check", ToolResult),
        isolated(lambda: attachment_risk_check(alert.get("attachments")), "attachment_risk_check", ToolResult),
        isolated(lambda: body_pattern_check(alert.get("subject"), alert.get("body")), "body_pattern_check", ToolResult),
        isolated(lambda: reply_chain_anomaly_check(
            alert.get("internal_sender"),
            alert.get("external_send_count_last_hour"),
        ), "reply_chain_anomaly_check", ToolResult),
    ]
