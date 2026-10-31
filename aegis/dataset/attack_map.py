"""Heuristic MITRE ATT&CK / ATLAS technique tags for a (alert, chain) pair.

Fine-tuning data is better with a technique label next to the verdict: the
model learns *what kind* of attack it is looking at, and analysts can
filter the dataset by technique. The map below is deliberately small and
transparent — each rule names the evidence it keys on, and every tag carries
that ``basis`` so a reviewer can see why. It is a heuristic
(``mitre_source = "heuristic_map/v1"``), not ground truth; 3.3 may replace
it with model-produced tags once a human-reviewed set exists.

Technique ids and names are from MITRE ATT&CK (Enterprise / Mobile) and
MITRE ATLAS; descriptions here are our own one-liners.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable

MITRE_SOURCE = "heuristic_map/v1"

TECHNIQUES: dict[str, dict[str, str]] = {
    "T1190": {"name": "Exploit Public-Facing Application", "framework": "ATT&CK",
              "about": "Injection or exploit primitives in a request to an internet-facing app (SQLi, XSS, RCE, path traversal)."},
    "T1059.001": {"name": "Command and Scripting Interpreter: PowerShell", "framework": "ATT&CK",
                  "about": "PowerShell used for execution, typically encoded (-enc) or download-cradle command lines."},
    "T1204.002": {"name": "User Execution: Malicious File", "framework": "ATT&CK",
                  "about": "An Office document or other file opened by a user spawns an interpreter or a child process."},
    "T1003.001": {"name": "OS Credential Dumping: LSASS Memory", "framework": "ATT&CK",
                  "about": "Reading lsass memory (procdump, comsvcs MiniDump, mimikatz) to harvest credentials."},
    "T1078": {"name": "Valid Accounts", "framework": "ATT&CK",
              "about": "A legitimate credential used from an impossible location, unknown device or outside its baseline."},
    "T1110": {"name": "Brute Force", "framework": "ATT&CK",
              "about": "Password guessing, spraying or credential stuffing against a sign-in endpoint."},
    "T1621": {"name": "Multi-Factor Authentication Request Generation", "framework": "ATT&CK",
              "about": "MFA push fatigue — repeated prompts until the user approves one."},
    "T1451": {"name": "SIM Card Swap", "framework": "ATT&CK-Mobile",
              "about": "The victim's number is moved to an attacker SIM to receive OTPs."},
    "T1557": {"name": "Adversary-in-the-Middle", "framework": "ATT&CK",
              "about": "Traffic intercepted or hooked (SSL-pinning bypass, instrumentation, rogue access point)."},
    "T1562.008": {"name": "Impair Defenses: Disable or Modify Cloud Logs", "framework": "ATT&CK",
                  "about": "Cloud audit logging stopped or trails deleted before the next move."},
    "T1562.007": {"name": "Impair Defenses: Disable or Modify Cloud Firewall", "framework": "ATT&CK",
                  "about": "A firewall / security group opened wide (any-any allow) or disabled."},
    "T1098": {"name": "Account Manipulation", "framework": "ATT&CK",
              "about": "Privileges, policies or keys added to an account outside a change ticket."},
    "T1136": {"name": "Create Account", "framework": "ATT&CK",
              "about": "A new user or service principal created for persistence."},
    "T1530": {"name": "Data from Cloud Storage", "framework": "ATT&CK",
              "about": "Bulk reads of cloud-hosted data stores."},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "framework": "ATT&CK",
              "about": "Large outbound volumes over a protocol or channel the data owner does not use."},
    "T1567": {"name": "Exfiltration Over Web Service", "framework": "ATT&CK",
              "about": "Data pushed to an external web service or personal cloud account."},
    "T1566.001": {"name": "Phishing: Spearphishing Attachment", "framework": "ATT&CK",
                  "about": "A targeted mail with a malicious attachment, usually with failing SPF/DKIM/DMARC."},
    "T1566.002": {"name": "Phishing: Spearphishing Link", "framework": "ATT&CK",
                  "about": "A targeted mail whose link leads to a credential-harvesting page."},
    "T1656": {"name": "Impersonation", "framework": "ATT&CK",
              "about": "The sender pretends to be an executive or a trusted partner to move money or data."},
    "T1657": {"name": "Financial Theft", "framework": "ATT&CK",
              "about": "Fraudulent transfers, mule-account funnelling or payment tampering."},
    "T1046": {"name": "Network Service Discovery", "framework": "ATT&CK",
              "about": "Port or service scanning inside the network."},
    "T1119": {"name": "Automated Collection", "framework": "ATT&CK",
              "about": "Scripted scraping or bulk reads far above a client's baseline volume."},
    "T1595": {"name": "Active Scanning", "framework": "ATT&CK",
              "about": "External probing of the perimeter for versions, paths and weaknesses."},
    "T1021": {"name": "Remote Services", "framework": "ATT&CK",
              "about": "Lateral movement over RDP / SMB / SSH / WinRM with valid credentials."},
    "AML.T0051": {"name": "LLM Prompt Injection", "framework": "ATLAS",
                  "about": "Text crafted to override the instructions of an AI system that reads it."},
    "T1195.002": {"name": "Supply Chain Compromise: Compromise Software Supply Chain", "framework": "ATT&CK",
                  "about": "A dependency, package, container image or vendor update altered before it reaches the bank (typosquat, hijacked maintainer, tampered artifact, malicious post-install)."},
    "T1195.001": {"name": "Supply Chain Compromise: Compromise Software Dependencies and Development Tools", "framework": "ATT&CK",
                  "about": "Build tooling or CI/CD pipeline tampered so every artifact it produces is compromised."},
    "AML.T0010": {"name": "ML Supply Chain Compromise", "framework": "ATLAS",
                  "about": "Poisoned or backdoored model weights, datasets or ML libraries pulled from a registry into an AI system."},
    "T1203": {"name": "Exploitation for Client Execution", "framework": "ATT&CK",
              "about": "A known vulnerability (CVE) in deployed software exploited to run code; actively-exploited (KEV) CVEs affecting a deployed component."},
}

_RuleFn = Callable[[dict, dict, str], bool]


def _text(alert: dict, chain: dict) -> str:
    try:
        return json.dumps({"a": alert, "e": chain.get("evidence"), "r": chain.get("reasoning")},
                          default=str).lower()
    except Exception:  # noqa: BLE001
        return ""


def _sources(chain: dict) -> set[str]:
    return {str(e.get("source", "")).lower() for e in chain.get("evidence", []) or []}


def _has(pattern: str) -> _RuleFn:
    rx = re.compile(pattern)
    return lambda alert, chain, text: bool(rx.search(text))


def _specialist(name: str) -> _RuleFn:
    return lambda alert, chain, text: (
        str(chain.get("investigated_by", "")).lower() == name
        or name in {str(s).lower() for s in chain.get("specialist_invocations", []) or []}
    )


def _all(*fns: _RuleFn) -> _RuleFn:
    return lambda a, c, t: all(f(a, c, t) for f in fns)


def _any(*fns: _RuleFn) -> _RuleFn:
    return lambda a, c, t: any(f(a, c, t) for f in fns)


# (technique id, basis label, predicate) — order matters only for readability.
RULES: list[tuple[str, str, _RuleFn]] = [
    ("AML.T0051", "injection_detected / injection phrasing",
     _any(lambda a, c, t: bool((c.get("metadata") or {}).get("injection_detected")),
          _has(r"ignore (all )?(previous|prior) instructions|you are now|system prompt|disregard (the )?(above|previous)"))),
    ("T1190", "perimeter exploit primitives / API authorisation abuse",
     _any(_has(r"\"sqli\": \[\"|\"xss\": \[\"|\"rce\": \[\"|\"traversal\": \[\"|union select|' or 1=1|<script|\.\./\.\./|/etc/passwd|xp_cmdshell|waitfor delay|\bbola\b|\bidor\b|object.level authori|schema drift"),
          lambda a, c, t: bool(_sources(c) & {"payload_decode", "decode_payload", "sqli", "xss", "rce", "exploit_primitives"}))),
    ("T1595", "scanner / enumeration signals",
     _has(r"nikto|sqlmap|nmap|masscan|\"scan_burst\"|directory enumeration|path enumeration|/\.git/|/\.env")),
    ("T1078", "impossible travel / unknown device / baseline deviation on a valid account",
     _any(lambda a, c, t: bool(_sources(c) & {"impossible_travel", "device_fingerprint", "privileged_baseline", "behavioral_baseline"}),
          _has(r"impossible_travel=true|\"impossible\": true|device_known=false"))),
    ("T1110", "credential stuffing / spray / brute force",
     _has(r"credential[ _]stuffing|password[ _]spray|brute[ _]force|failed_logins\": ?\d{2,}|login_failures\": ?\d{2,}")),
    ("T1621", "MFA fatigue",
     _has(r"mfa_fatigue|mfa_push_count\": ?\d|mfa_failures\": ?(?:[4-9]|\d{2,})|push fatigue")),
    ("T1451", "SIM swap",
     _has(r"sim[ _-]?swap|imsi_changed|mno_signals")),
    ("T1557", "instrumentation / pinning bypass / rogue AP",
     _has(r"frida_detected\": true|ssl_pinning_failed\": true|is_jailbroken\": true|is_rooted\": true|rogue[ _]ap|evil twin|deauth")),
    ("T1059.001", "PowerShell execution",
     _has(r"powershell(\.exe)?[^\"]*(-enc|-e |-encodedcommand|downloadstring|iex|invoke-expression|-nop|bypass)")),
    ("T1204.002", "Office parent spawning an interpreter",
     _has(r"\"parent_process\": \"(winword|excel|powerpnt|outlook|acrord32|wscript)\.exe\"")),
    ("T1003.001", "LSASS dump",
     _has(r"lsass|minidump|procdump|sekurlsa|mimikatz")),
    ("T1021", "lateral movement over remote services",
     _has(r"psexec|wmic .*process call create|winrm|\"dst_port\": (3389|445|5985|5986)\b.*(lateral|cross-zone|cross_zone)|lateral movement")),
    ("T1562.008", "cloud logging disabled",
     _has(r"stoplogging|deletetrail|updatetrail|disable.*(audit|logging)|putbucketlogging|diagnostic settings.*delete")),
    ("T1562.007", "flat-permit firewall / security-group change",
     _has(r"any.?any|\"source\": \"any\".*\"destination\": \"any\"|authorizesecuritygroupingress.*0\.0\.0\.0/0|add-rule.*allow|security_rule.*delete")),
    ("T1098", "unticketed privileged account/policy change",
     _any(_has(r"attachuserpolicy|putuserpolicy|attachrolepolicy|createaccesskey|roleassignments/write|addmemberto|updateloginprofile|high_impact_action\": true"),
          _all(_specialist("auth"), _has(r"change_ticket_id\": null")))),
    ("T1136", "account creation",
     _has(r"createuser|createloginprofile|new-mailbox|useradd|\"eventname\": \"createserviceprincipal")),
    ("T1530", "bulk read of a data store",
     _any(_has(r"rows_returned\": ?\d{4,}|queries_per_session\": ?\d{2,}|getobject.*bucket|listobjects|download.*bucket"),
          _all(_specialist("dlp"), _has(r"\"table\": ")))),
    ("T1048", "large outbound transfer",
     _has(r"observed_mb_last_hour\": ?\d{3,}|bytes_out\": ?\d{9,}|egress_mb\": ?\d{3,}|dns tunnel|icmp tunnel")),
    ("T1567", "upload to an external web service",
     _has(r"upload.*(dropbox|wetransfer|mega\.nz|drive\.google|personal)|pastebin|transfer\.sh|anonfiles")),
    ("T1566.001", "spearphishing attachment",
     _any(_has(r"\.docm|\.xlsm|\.iso\"|\.lnk\"|\.hta\"|macro"), _all(_specialist("email"), _has(r"\"attachment")))),
    ("T1566.002", "spearphishing link",
     _all(_specialist("email"), _has(r"credential|login bait|phish(ing)? link|\"urls\": \["))),
    ("T1656", "executive / partner impersonation",
     _has(r"cfo office|ceo office|display name mismatch|lookalike|impersonat")),
    ("T1657", "fraudulent financial movement",
     _any(_specialist("transaction"), _has(r"mule|beneficiary added|wire transfer|rtgs|neft|imps|upi"))),
    ("T1119", "automated scraping / bulk collection",
     _has(r"scrap|x baseline volume|bulk (read|download|export)|automated collection|rows_returned\": ?\d{4,}")),
    ("T1046", "internal service discovery",
     _has(r"port scan|portscan|\"scan_burst\"|service discovery|smb enumeration")),
    ("T1195.002", "tampered dependency / package / artifact",
     _has(r"typosquat|hash_mismatch|hash mismatch|unexpected_postinstall|post-install|unsigned_artifact|new_maintainer|maintainer takeover|dependency confusion|sbom_match\": ?false|provenance_verified\": ?false|supply.chain")),
    ("T1195.001", "compromised build / CI pipeline",
     _has(r"ci_runner|build pipeline|pipeline_tampered|ci token|runner compromise|build_tampered")),
    ("AML.T0010", "poisoned model / dataset / ML library",
     _has(r"hf-model|model_registry|model weights|pickle loader|poisoned (model|dataset)|safetensors_mismatch|ml.supply")),
    ("T1203", "actively exploited CVE on a deployed component",
     _has(r"cve_known_exploited\": ?true|known.exploited|\"kev\": ?true|exploit_maturity\": ?\"(weaponized|in_the_wild)")),
]


def techniques_for(alert: dict | None, chain: dict | None) -> list[dict[str, str]]:
    """Return ``[{"id", "name", "framework", "basis"}]`` for a scrubbed (alert, chain) pair."""
    alert = alert or {}
    chain = chain or {}
    text = _text(alert, chain)
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for tid, basis, fn in RULES:
        try:
            hit = fn(alert, chain, text)
        except Exception:  # noqa: BLE001 — a heuristic must never break an export
            hit = False
        if hit and tid not in seen:
            seen.add(tid)
            meta = TECHNIQUES[tid]
            out.append({"id": tid, "name": meta["name"], "framework": meta["framework"], "basis": basis})
    return out


def catalogue() -> list[dict[str, str]]:
    """The technique list as text records (for the attack-profile corpus)."""
    return [{"id": tid, **meta} for tid, meta in TECHNIQUES.items()]
