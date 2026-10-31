"""Tools available to the Perimeter specialist agent.

Walking-skeleton implementations are mocks with deterministic data.
Production swaps each one for a real backend (IP rep service, SIEM
historical query, etc.) keeping the same signature.
"""
from __future__ import annotations

import base64
import ipaddress
import os
import re
import urllib.parse
from dataclasses import dataclass
from typing import Optional


@dataclass
class ToolResult:
    name: str
    data: dict
    weight: str  # "low" | "medium" | "high"


# ---- Tool: decode an obfuscated payload --------------------------------

_SQLI_PRIMITIVES = (
    "union select", "' or 1=1", "' or '1'='1", " or 1=1", " or '1'='1",
    "/*!50000", "sleep(", "benchmark(", "load_file(", "@@version",
    "information_schema", " or true--", "'--", "\";--",
)
_XSS_PRIMITIVES = ("<script", "javascript:", "onerror=", "onload=", "<svg")
_RCE_PRIMITIVES = ("$(", "`whoami`", "; cat ", "&& cat ", "|nc ", "wget ", "curl ", "; id;",
                   "<?php", "$_get[", "$_post[", "system($", "eval(",
                   "shell_exec(", "passthru(")
_TRAVERSAL_PRIMITIVES = ("..%2f", "../", "..%5c", "..\\", "/etc/passwd", "boot.ini")
# XML external entity: the payload itself carries the structural tell (DOCTYPE/ENTITY/SYSTEM),
# so it is a clean addition to the layered payload scan below.
_XXE_PRIMITIVES = ("<!doctype", "<!entity", "<!element", 'system "file:', "system 'file:",
                   'system "http', "system 'http", "php://filter", "convert.base64-encode",
                   "file:///", "expect://", "xinclude", "<!entity %")


def decode_payload(raw: str) -> ToolResult:
    """Decode URL-encoding and base64, then scan for known exploit primitives.

    Layers tested:
      1. raw input
      2. URL-decoded
      3. base64-decoded substrings
      4. SQL-comment-stripped variant of (1) and (2) — catches /**/ evasion
      5. whitespace-collapsed variant — catches `' OR  1 = 1` and similar
    """
    layers = [raw]
    try:
        decoded_url = urllib.parse.unquote_plus(raw)
        if decoded_url != raw:
            layers.append(decoded_url)
    except Exception:  # noqa: BLE001, S110 — decode probing: failure is the common case, not an error
        pass
    # Try base64 on substrings that look like base64
    for token in re.findall(r"[A-Za-z0-9+/=]{16,}", raw):
        try:
            decoded_b64 = base64.b64decode(token, validate=True).decode("utf-8", errors="ignore")
            if decoded_b64 and decoded_b64 != token:
                layers.append(decoded_b64)
        except Exception:  # noqa: BLE001, S112 — not base64; try the next token
            continue
    # Comment-stripping evasion (UNI/**/ON SELECT -> UNION SELECT)
    extra_layers = []
    for layer in list(layers):
        no_comments = re.sub(r"/\*.*?\*/", "", layer, flags=re.DOTALL)
        if no_comments != layer:
            extra_layers.append(no_comments)
        # Whitespace-collapsing evasion (' OR  1 = 1 -> ' OR 1=1)
        collapsed = re.sub(r"\s*=\s*", "=", re.sub(r"\s+", " ", layer))
        if collapsed != layer:
            extra_layers.append(collapsed)
    layers.extend(extra_layers)

    flat = " ".join(layers).lower()
    primitives_found = {
        "sqli": [p for p in _SQLI_PRIMITIVES if p in flat],
        "xss": [p for p in _XSS_PRIMITIVES if p in flat],
        "rce": [p for p in _RCE_PRIMITIVES if p in flat],
        "traversal": [p for p in _TRAVERSAL_PRIMITIVES if p in flat],
        "xxe": [p for p in _XXE_PRIMITIVES if p in flat],
    }
    total = sum(len(v) for v in primitives_found.values())
    weight = "high" if total >= 2 else "medium" if total == 1 else "low"
    return ToolResult(
        name="decode_payload",
        data={"layers": layers, "primitives": primitives_found, "primitive_count": total},
        weight=weight,
    )


# ---- Tool: IP reputation aggregator ------------------------------------

# Stand-in dataset. Production: query AbuseIPDB / GreyNoise / internal feed.
_KNOWN_BAD = {
    "185.220.101.45": {"abuse_score": 96, "categories": ["scanner", "bruteforce"], "tor_exit": True},
    "45.155.205.233": {"abuse_score": 88, "categories": ["sqli_attempts"], "tor_exit": False},
    "203.0.113.66":   {"abuse_score": 78, "categories": ["credential_stuffing"], "tor_exit": False},
}
_KNOWN_GOOD = {"10.20.30.40", "192.168.1.5", "172.16.0.10"}


def ip_reputation(ip: str) -> ToolResult:
    if ip in _KNOWN_BAD:
        rep = _KNOWN_BAD[ip]
        return ToolResult(
            name="ip_reputation",
            data={"ip": ip, "verdict": "known_malicious", **rep},
            weight="high",
        )
    if ip in _KNOWN_GOOD:
        return ToolResult(
            name="ip_reputation",
            data={"ip": ip, "verdict": "internal_known_good", "abuse_score": 0},
            weight="low",
        )
    return ToolResult(
        name="ip_reputation",
        data={"ip": ip, "verdict": "unknown", "abuse_score": None},
        weight="low",
    )


# ---- Tool: similar past requests --------------------------------------

# Stand-in: a tiny in-memory corpus of "labeled" past requests.
_PAST_INCIDENTS = [
    {"id": "INC-2026-0411", "snippet": "UNION SELECT 1,2,version()", "label": "malicious",
     "summary": "Confirmed SQLi exfil attempt; IP blocked, no impact."},
    {"id": "INC-2026-0388", "snippet": "<script>fetch('//evil", "label": "malicious",
     "summary": "Stored XSS in support form; remediated, customer notified."},
    {"id": "INC-2026-0299", "snippet": "scanner User-Agent nikto", "label": "benign",
     "summary": "Authorized internal pentest run; whitelisted for window."},
]


def similar_past_requests(snippet: str) -> ToolResult:
    s = snippet.lower()
    hits = [inc for inc in _PAST_INCIDENTS if inc["snippet"].lower()[:12] in s or s[:20] in inc["snippet"].lower()]
    if hits:
        labels = {h["label"] for h in hits}
        weight = "high" if "malicious" in labels and "benign" not in labels else "medium"
        return ToolResult(
            name="similar_past_requests",
            data={"hits": hits, "n": len(hits)},
            weight=weight,
        )
    return ToolResult(name="similar_past_requests", data={"hits": [], "n": 0}, weight="low")


# ---- Tool: user behavior baseline -------------------------------------

# Stand-in: hand-built baselines per user_id.
_USER_BASELINES = {
    "u_42891": {"typical_geos": ["IN-MH", "IN-KA"], "typical_endpoints": ["/api/account", "/api/balance"],
                "typical_hours_utc": [3, 4, 5, 12, 13], "session_count_24h": 8},
    "u_77104": {"typical_geos": ["US-CA"], "typical_endpoints": ["/api/transfer", "/api/account"],
                "typical_hours_utc": [16, 17, 18, 19], "session_count_24h": 4},
}


def user_baseline(user_id: Optional[str]) -> ToolResult:
    if not user_id or user_id not in _USER_BASELINES:
        return ToolResult(name="user_baseline", data={"user_id": user_id, "baseline": None}, weight="low")
    return ToolResult(
        name="user_baseline",
        data={"user_id": user_id, "baseline": _USER_BASELINES[user_id]},
        weight="medium",
    )


# ---- Tool: SSRF target check (resolved-destination aware) --------------

_METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal", "metadata.goog",
                   "100.100.100.200", "fd00:ec2::254"}
_INTERNAL_NAMES = {"meta", "metadata", "metadata-server", "localhost", "internal"}
_SSRF_SCHEMES = ("file://", "gopher://", "dict://", "ldap://", "ftp://")


def _host_is_internal(host: str) -> tuple[bool, str]:
    """Classify a URL host as an SSRF target by what it *resolves to*, not a literal match."""
    h = (host or "").strip().strip("[]").lower()
    if not h:
        return False, ""
    if h in _METADATA_HOSTS or h in _INTERNAL_NAMES:
        return True, "cloud-metadata / internal service name"
    if h.endswith((".internal", ".local", ".svc", ".cluster.local")):
        return True, "internal DNS suffix"
    try:
        ip = ipaddress.ip_address(h)
        if ip.is_loopback:
            return True, "loopback address"
        if ip.is_link_local:
            return True, "link-local address"
        if ip.is_private or ip.is_reserved or ip.is_unspecified:
            return True, "private/reserved address"
    except ValueError:
        pass  # not an IP literal; a bare hostname with a dot is treated as external
    return False, ""


def ssrf_probe(raw: str) -> ToolResult:
    """Flag URL-valued input aimed at an internal / metadata / link-local destination.

    Resolved-destination aware: matches RFC1918, loopback, link-local and metadata IPs,
    internal DNS suffixes, and bare service names (``meta:8000``) — not a hand-written
    blocklist of three literals (the exact gap that lets ``fetch.php`` reach ``meta:8000``).
    """
    layers = [raw]
    try:
        u = urllib.parse.unquote_plus(raw)
        if u != raw:
            layers.append(u)
    except Exception:  # noqa: BLE001, S110 — decode probing; failure is common, not an error
        pass
    text = " ".join(layers)
    low = text.lower()
    hits: list[dict] = []
    seen: set[str] = set()
    # URLs with an explicit scheme
    for m in re.findall(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s\"'&<>]+", text):
        try:
            host = urllib.parse.urlsplit(m).hostname or ""
        except Exception:  # noqa: BLE001, S112 — malformed URL; skip it
            continue
        internal, why = _host_is_internal(host)
        if internal and host.lower() not in seen:
            seen.add(host.lower())
            hits.append({"url": m[:200], "host": host, "reason": why})
    # scheme-less service refs like meta:8000 — only when the host is known-internal
    for name, port in re.findall(r"\b([a-z0-9][a-z0-9.\-]{1,62}):(\d{2,5})\b", low):
        internal, why = _host_is_internal(name)
        if internal and name not in seen:
            seen.add(name)
            hits.append({"url": f"{name}:{port}", "host": name, "reason": why})
    schemes = [s for s in _SSRF_SCHEMES if s in low]
    weight = "high" if hits else ("medium" if schemes else "low")
    return ToolResult(name="ssrf_probe",
                      data={"targets": hits, "n": len(hits), "dangerous_schemes": schemes},
                      weight=weight)


# ---- Tool: CORS reflection (response-side) -----------------------------

def cors_reflection(alert: dict) -> ToolResult:
    """Detect an Access-Control-Allow-Origin that reflects an arbitrary Origin (or is ``*``)
    alongside Allow-Credentials: true — a credential-theft CORS misconfig (api/session.php)."""
    rh = alert.get("response_headers")
    rh = {str(k).lower(): str(v) for k, v in rh.items()} if isinstance(rh, dict) else {}
    acao = rh.get("access-control-allow-origin", "").strip()
    acac = rh.get("access-control-allow-credentials", "").strip().lower() == "true"
    req_headers = alert.get("request_headers") if isinstance(alert.get("request_headers"), dict) else {}
    origin = (alert.get("origin")
              or req_headers.get("Origin") or req_headers.get("origin") or "").strip()
    if not acao:
        return ToolResult(name="cors_reflection", data={"applicable": False}, weight="low")
    reflected = bool(origin) and acao == origin
    if (reflected or acao == "*") and acac:
        return ToolResult(name="cors_reflection",
                          data={"acao": acao, "allow_credentials": True, "origin": origin,
                                "reason": "reflects arbitrary Origin with credentials" if reflected
                                          else "wildcard origin with credentials"},
                          weight="high")
    if reflected or acao == "*":
        return ToolResult(name="cors_reflection",
                          data={"acao": acao, "allow_credentials": False, "origin": origin,
                                "reason": "permissive CORS (no credentials)"},
                          weight="medium")
    return ToolResult(name="cors_reflection", data={"acao": acao, "applicable": True}, weight="low")


# ---- Tool: mass assignment (request params vs rendered form) -----------

_SENSITIVE_PARAMS = {"role", "is_admin", "admin", "is_staff", "credit_score", "kyc_status",
                     "balance", "verified", "is_verified", "permissions", "scope", "status",
                     "account_type", "overdraft", "approved", "uid", "user_id"}


def mass_assignment(alert: dict, raw_payload: str = "") -> ToolResult:
    """Posted parameters beyond the form's rendered fields — privilege escalation by
    writing columns the UI never exposes (profile.php POST: credit_score, kyc_status)."""
    params = alert.get("body_params")
    if not isinstance(params, dict):
        try:
            params = {k: (v[0] if isinstance(v, list) else v)
                      for k, v in urllib.parse.parse_qs(raw_payload, keep_blank_values=True).items()}
        except Exception:  # noqa: BLE001, S110 — not a form body; nothing to parse
            params = {}
    posted = {str(k).lower() for k in params}
    form_fields = alert.get("form_fields")
    if isinstance(form_fields, (list, tuple, set)) and form_fields:
        allowed = {str(f).lower() for f in form_fields}
        extra = sorted(posted - allowed)
        sensitive = sorted(p for p in extra if p in _SENSITIVE_PARAMS)
        if sensitive:
            return ToolResult(name="mass_assignment",
                              data={"extra_params": extra, "sensitive": sensitive,
                                    "form_fields": sorted(allowed)}, weight="high")
        if extra:
            return ToolResult(name="mass_assignment",
                              data={"extra_params": extra, "form_fields": sorted(allowed)},
                              weight="medium")
        return ToolResult(name="mass_assignment", data={"extra_params": []}, weight="low")
    # no schema in telemetry → fall back to a sensitive-param denylist
    sensitive_posted = sorted(posted & _SENSITIVE_PARAMS)
    if sensitive_posted:
        return ToolResult(name="mass_assignment",
                          data={"sensitive_params_posted": sensitive_posted, "schema_known": False},
                          weight="medium")
    return ToolResult(name="mass_assignment", data={"applicable": bool(posted)}, weight="low")


# ---- Tool: host-header anomaly -----------------------------------------

def host_header_anomaly(alert: dict) -> ToolResult:
    """Host-header injection / routing abuse: CRLF or multiple hosts in the Host value, or a
    Host outside the configured allowlist (AEGIS_EXPECTED_HOSTS)."""
    req_headers = alert.get("request_headers") if isinstance(alert.get("request_headers"), dict) else {}
    host = str(alert.get("host") or req_headers.get("Host") or req_headers.get("host") or "").strip()
    if not host:
        return ToolResult(name="host_header_anomaly", data={"applicable": False}, weight="low")
    reasons = []
    if "\n" in host or "\r" in host:
        reasons.append("crlf in host header")
    if "," in host or len(host.split()) > 1:
        reasons.append("multiple hosts")
    if "@" in host or "/" in host:
        reasons.append("embedded userinfo/path")
    if reasons:
        return ToolResult(name="host_header_anomaly",
                          data={"host": host[:200], "reasons": reasons}, weight="high")
    expected = [h.strip().lower() for h in os.environ.get("AEGIS_EXPECTED_HOSTS", "").split(",") if h.strip()]
    hostname = host.split(":")[0].lower()
    if expected and hostname not in expected:
        return ToolResult(name="host_header_anomaly",
                          data={"host": host[:200], "reason": "host not in AEGIS_EXPECTED_HOSTS",
                                "expected": expected}, weight="medium")
    return ToolResult(name="host_header_anomaly", data={"host": host[:200]}, weight="low")


# ---- Helpers -----------------------------------------------------------

def run_all_tools(raw_payload: str, source_ip: str, user_id: Optional[str],
                  alert: Optional[dict] = None) -> list[ToolResult]:
    alert = alert or {}
    return [
        decode_payload(raw_payload),
        ip_reputation(source_ip),
        similar_past_requests(raw_payload),
        user_baseline(user_id),
        ssrf_probe(raw_payload),
        cors_reflection(alert),
        mass_assignment(alert, raw_payload),
        host_header_anomaly(alert),
    ]
