"""Native alert envelopes for the products in the CISO assessment stack.

A Sigma rule or a Mordor scenario gives us the *event*; a real SOC never sees the bare event —
it sees a CrowdStrike detection, a Sentinel incident, a Zscaler web-log line, an Imperva WAF
event. These builders wrap an event in each product's real field vocabulary so the triage
model trains on what the connectors (``aegis/ingest``) will actually hand it.

Severity on every envelope is drawn from an *overlapping* per-verdict distribution (same rule
as the synthetic generator) so the product severity field is realistic but never a label.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

Family = str   # "edr" | "siem" | "proxy" | "waf"

EDR_PRODUCTS = ("crowdstrike", "sophos", "defender")
_SEV_MIX = {"benign": (0.45, 0.40, 0.15), "suspicious": (0.15, 0.50, 0.35), "malicious": (0.05, 0.35, 0.60)}

_DEPTS = ("Retail Banking", "Treasury", "Cards", "Corporate IT", "Wealth", "Operations", "Risk", "Lending")
_HOSTS = ("LT", "WS", "SRV", "VDI", "JMP")
_OS = ("Windows 11 Enterprise 23H2", "Windows 10 Enterprise 22H2", "Windows Server 2022", "Ubuntu 22.04", "macOS 14.5")


def _sev(r: random.Random, verdict: str, low: str, med: str, high: str) -> str:
    return r.choices((low, med, high), weights=_SEV_MIX[verdict])[0]


def _ts(r: random.Random) -> str:
    return (datetime(2026, 9, 1, tzinfo=UTC) + timedelta(minutes=r.randint(0, 70000))).isoformat()


def _host(r):  return f"{r.choice(_HOSTS)}-{r.randint(1000, 9999)}"
def _user(r):  return f"u_{r.randint(10000, 99999)}"
def _ip_int(r): return f"10.{r.randint(20, 60)}.{r.randint(1, 254)}.{r.randint(1, 254)}"
def _ip_ext(r): return r.choice(("203.0.113.", "198.51.100.", "192.0.2.")) + str(r.randint(1, 254))


def family_for_logsource(product: str | None, cat: str | None) -> Family:
    cat = (cat or "").lower(); product = (product or "").lower()
    if cat in ("proxy", "dns", "firewall") and product in ("", "zeek", "zscaler", "squid"):
        return "proxy"
    if cat in ("webserver",) or product in ("apache", "nginx", "iis"):
        return "waf"
    if product in ("windows", "linux", "macos") and cat not in ("security", "system", "application", "windefend",
                                                                 "codeintegrity-operational", "taskscheduler",
                                                                 "powershell-classic", "msexchange-management",
                                                                 "firewall-as", "bits-client", "sysmon_status",
                                                                 "ntlm", "dns-server", "printservice-operational",
                                                                 "wmi", "auditd", "sshd", "sudo", "cron", "syslog",
                                                                 "vsftpd", "guacamole", "clamav", "auth"):
        return "edr"
    return "siem"


# --------------------------------------------------------------------------- EDR family

def crowdstrike(r, verdict, event, *, tactic, technique_id, technique_name, title) -> dict:
    return {
        "source": "CrowdStrike Falcon", "event_type": "DetectionSummaryEvent", "detect_id": f"ldt:{r.getrandbits(48):x}",
        "timestamp": _ts(r),
        "device": {"hostname": _host(r), "platform_name": r.choice(("Windows", "Linux", "Mac")), "os_version": r.choice(_OS),
                   "machine_domain": "corp.bank.in", "local_ip": _ip_int(r), "ou": r.choice(_DEPTS)},
        "max_severity_displayname": _sev(r, verdict, "Low", "Medium", "High"),
        "behaviors": [{
            "tactic": tactic, "technique": technique_name, "technique_id": technique_id, "scenario": title,
            "user_name": _user(r), "filename": event.get("Image", event.get("process", "")).split("\\")[-1].split("/")[-1],
            "cmdline": event.get("CommandLine", event.get("cmdline", "")),
            "parent_details": {"parent_cmdline": event.get("ParentCommandLine", event.get("ParentImage", ""))},
            "ioc_type": r.choice(("hash_sha256", "domain", "process", "")), "pattern_disposition": r.choice(("detection", "prevention")),
        }],
        "event_detail": event,
    }


def sophos(r, verdict, event, *, tactic, technique_id, technique_name, title) -> dict:
    return {
        "source": "Sophos Central", "type": r.choice(("Event::Endpoint::Threat::Detected", "Event::Endpoint::Threat::CleanedUp",
                                                      "Event::Endpoint::ExploitMitigation")),
        "created_at": _ts(r), "customer_id": "c-bank-in", "endpoint_type": r.choice(("computer", "server")),
        "endpoint_id": f"ep-{r.getrandbits(32):08x}", "location": _host(r), "user_id": _user(r),
        "group": r.choice(_DEPTS), "severity": _sev(r, verdict, "low", "medium", "high"),
        "name": title, "threat": f"{tactic}/{technique_id}",
        "core_remedy_items": {"totalItems": r.randint(0, 3), "items": []},
        "data": {"process": event.get("Image", event.get("process", "")), "cmdline": event.get("CommandLine", event.get("cmdline", "")),
                 "parent": event.get("ParentImage", ""), "event": event},
    }


def defender(r, verdict, event, *, tactic, technique_id, technique_name, title) -> dict:
    return {
        "source": "Microsoft Defender for Endpoint", "AlertId": f"da{r.getrandbits(40):x}", "Timestamp": _ts(r),
        "Title": title, "Category": tactic, "Severity": _sev(r, verdict, "Informational", "Medium", "High"),
        "DetectionSource": r.choice(("EDR", "Antivirus", "CustomDetection", "SmartScreen")),
        "DeviceName": f"{_host(r).lower()}.corp.bank.in", "AccountName": _user(r), "Department": r.choice(_DEPTS),
        "FileName": event.get("Image", event.get("process", "")).split("\\")[-1].split("/")[-1],
        "ProcessCommandLine": event.get("CommandLine", event.get("cmdline", "")),
        "InitiatingProcessFileName": event.get("ParentImage", "").split("\\")[-1],
        "AttackTechniques": [f"{technique_name} ({technique_id})"] if technique_id else [],
        "Evidence": event,
    }


# --------------------------------------------------------------------------- SIEM

_PRODUCT_NAMES = {
    "azure": "Azure Active Directory", "m365": "Microsoft 365 Defender", "okta": "Okta", "aws": "Amazon Web Services",
    "gcp": "Google Cloud Platform", "github": "GitHub", "bitbucket": "Bitbucket", "kubernetes": "Kubernetes",
    "cisco": "Cisco", "windows": "Windows Security Events", "linux": "Syslog", "macos": "Syslog",
    "opencanary": "OpenCanary", "rpc_firewall": "RPC Firewall", "zeek": "Zeek", "fortios": "Fortinet",
    "paloalto": "Palo Alto Networks", "juniper": "Juniper", "huawei": "Huawei",
}


def sentinel(r, verdict, event, *, product, service, tactic, technique_id, title, rule_name) -> dict:
    ents = []
    for k in ("User", "TargetUserName", "SubjectUserName", "userIdentity", "user", "actor", "principalId", "AccountName"):
        if k in event:
            ents.append({"Type": "account", "Name": str(event[k])[:64]}); break
    for k in ("Computer", "ComputerName", "host", "hostname", "DeviceName"):
        if k in event:
            ents.append({"Type": "host", "HostName": str(event[k])[:64]}); break
    for k in ("sourceIPAddress", "src_ip", "SourceIp", "IpAddress", "ipaddress", "c-ip", "clientip"):
        if k in event:
            ents.append({"Type": "ip", "Address": str(event[k])}); break
    return {
        "source": "Microsoft Sentinel", "IncidentNumber": r.randint(10000, 99999), "TimeGenerated": _ts(r),
        "Title": title, "AnalyticsRuleName": rule_name, "Severity": _sev(r, verdict, "Low", "Medium", "High"),
        "Status": "New", "ProviderName": "ASI Scheduled Alerts",
        "ProductName": _PRODUCT_NAMES.get((product or "").lower(), (product or "Custom").title()),
        "Tactics": [tactic] if tactic else [], "Techniques": [technique_id] if technique_id else [],
        "Entities": ents, "Workspace": "law-bank-soc-prod",
        "ExtendedProperties": {"log_source": f"{product}/{service}", "event": event},
    }


# --------------------------------------------------------------------------- proxy / WAF

_URLCATS = ("Business and Economy", "Finance", "Web Mail", "File Sharing", "Newly Registered Domains", "Malicious Content",
            "Internet Services", "Anonymizer", "Social Networking", "Professional Services")


def zscaler(r, verdict, event, *, title) -> dict:
    url = event.get("c-uri", event.get("url", event.get("cs-uri", event.get("query", "/"))))
    return {
        "source": "Zscaler ZIA", "datetime": _ts(r), "action": r.choice(("Blocked", "Allowed", "Cautioned")),
        "reason": title, "url": url if "://" in str(url) else f"https://{event.get('c-uri-host', event.get('dst_host', 'host.example'))}{url}",
        "urlcategory": r.choice(_URLCATS), "urlsupercategory": "General Browsing",
        "appname": r.choice(("General Browsing", "OneDrive", "Dropbox", "Unknown", "WhatsApp Web")),
        "user": f"{_user(r)}@bank.in", "department": r.choice(_DEPTS), "location": r.choice(("Mumbai HQ", "Noida DC", "Road Warrior")),
        "clientIP": _ip_int(r), "serverIP": _ip_ext(r), "requestmethod": event.get("cs-method", event.get("method", "GET")),
        "useragent": event.get("c-useragent", event.get("User-Agent", "Mozilla/5.0 (Windows NT 10.0) Chrome/130")),
        "threatname": event.get("threatname", "None"), "threatcategory": event.get("threatcategory", "None"),
        "riskscore": r.randint(0, 100), "bytes_out": r.randint(200, 900000), "bytes_in": r.randint(200, 2000000),
        "dlpdictionaries": event.get("dlpdictionaries", "None"), "raw": event,
    }


def imperva(r, verdict, event, *, title, attack_type) -> dict:
    return {
        "source": "Imperva Cloud WAF", "start": _ts(r), "site": r.choice(("netbanking.bank.in", "api.bank.in", "cards.bank.in")),
        "client_ip": _ip_ext(r), "country": r.choice(("IN", "SG", "US", "DE", "NL", "RU", "BR")),
        "url": event.get("c-uri", event.get("cs-uri-query", "/")), "method": event.get("cs-method", "GET"),
        "user_agent": event.get("c-useragent", "Mozilla/5.0"), "action": r.choice(("REQ_BLOCKED_SECURITY", "REQ_CHALLENGE", "REQ_PASSED")),
        "attack_type": attack_type, "rule": title, "severity": _sev(r, verdict, "Low", "Medium", "High"),
        "requests_per_min": r.randint(2, 900), "bot_classification": r.choice(("Unclassified", "Known Bad Bot", "Human", "Headless browser")),
        "http_status": r.choice((200, 403, 404, 500)), "raw": event,
    }


def f5_asm(r, verdict, event, *, title, attack_type) -> dict:
    return {
        "source": "F5 ASM", "date_time": _ts(r), "policy_name": r.choice(("pol_netbanking", "pol_api_gateway", "pol_cards")),
        "ip_client": _ip_ext(r), "geo_location": r.choice(("IN", "SG", "US", "CN", "NL")),
        "uri": event.get("c-uri", event.get("cs-uri-query", "/")), "method": event.get("cs-method", "GET"),
        "request_status": r.choice(("blocked", "alerted", "passed")), "attack_type": attack_type,
        "sig_names": [title], "violations": r.sample(("Attack signature detected", "Illegal meta character in value",
                                                    "Illegal parameter", "HTTP protocol compliance failed",
                                                    "Illegal method", "Bot client detected"), r.randint(1, 3)),
        "severity": _sev(r, verdict, "Informational", "Warning", "Critical"), "violation_rating": r.randint(1, 5),
        "x_forwarded_for_header_value": _ip_ext(r), "raw": event,
    }


# --------------------------------------------------------------------------- SOAR envelope

def xsoar(r, inner: dict, *, title) -> dict:
    """Wrap any product alert in the Cortex XSOAR incident shape (20 % of rows in practice)."""
    return {
        "source": "Cortex XSOAR", "incident_id": str(r.randint(100000, 999999)), "name": title,
        "type": r.choice(("Malware", "Phishing", "Access", "Cloud Alert", "WAF Alert", "Generic")),
        "severity": r.randint(0, 4), "status": "Pending", "owner": "", "playbook": "AEGIS-Triage-FirstPass",
        "occurred": _ts(r), "source_brand": inner.get("source"), "rawJSON": inner,
    }
