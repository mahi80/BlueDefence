"""Tools available to the Perimeter specialist agent.

Walking-skeleton implementations are mocks with deterministic data.
Production swaps each one for a real backend (IP rep service, SIEM
historical query, etc.) keeping the same signature.
"""
from __future__ import annotations

import base64
import collections
import html
import ipaddress
import os
import re
import threading
import time
import unicodedata
import urllib.parse
from dataclasses import dataclass

from ..shared.bounded import BoundedDict
from ..shared.tool_guard import isolated

_URL_RX = re.compile(r"[a-zA-Z0-9+.\-]{1,64}://[^\s\"'&<>]+")
_SCHEME_LEAD = re.compile(r"^[^a-zA-Z]+")


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
    # boolean-blind (AND true/false probes), ORDER BY / LIKE / nested sub-select, paren-close
    # breaks, and #/-- comment terminators — the signatureless SQLi variants the UNION-only set
    # slipped past in the 2026-10-27 purple-team run. decode_payload's whitespace-collapse layer
    # also makes these catch the newline-evaded body form (SQLI_BODY_NEWLINE).
    "' and 1=1", "' and 1=2", " and 1=1", " and 1=2", "' and '1'='1", "' and 'x'='x",
    "order by ", "' like '", " like '%", "(select ", "=(select ",
    "') or ", "') and ", ") or 1=1", "'#", '"#', "')#", "')-- ",
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


_UNION_RX = re.compile(r"union(?:\s|/\*\*/|\+)+(?:all|distinct)(?:\s|/\*\*/|\+)+select")
# `union(select(…))`, `union%0aselect`, `union/*x*/select` — any non-word run between the two keywords
_UNION_ANY_RX = re.compile(r"\bunion\W{0,40}?select\b")
# MySQL `#…\n` / `-- …\n` line comments used as whitespace (`UNION#x\nSELECT`)
_LINE_COMMENT_RX = re.compile(r"(?:#|--)[^\r\n]{0,200}[\r\n]")
# base64 tokens: no `=` inside (so `q=<b64>` is not one token), up to two pad characters, URL-safe alphabet too
_B64_RX = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_MAX_COMMENTS = 512
_JSON_ESC_RX = re.compile(r"\\(u[0-9a-fA-F]{4}|[nrt\"/\\])")
_JSON_ESC = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "/": "/", "\\": "\\"}


def _json_unescape(m: re.Match) -> str:
    g = m.group(1)
    return chr(int(g[1:], 16)) if g[0] == "u" else _JSON_ESC[g]


def _strip_comments(text: str) -> str:
    """Remove ``/* … */`` comments in one linear pass (``str.find`` for each ``*/``). The bounded regex still
    rescanned 4,000 characters from every unclosed ``/*`` — 12 s on a 32 KB ``/*a/*a…`` body (round 4 S4-9)."""
    out: list[str] = []
    i, n = 0, 0
    while True:
        j = text.find("/*", i)
        if j < 0 or n >= _MAX_COMMENTS:
            out.append(text[i:])
            break
        k = text.find("*/", j + 2)
        if k < 0:
            out.append(text[i:])                       # unclosed: nothing after it can close either
            break
        out.append(text[i:j])
        i, n = k + 2, n + 1
    return "".join(out)


def _b64_layers(texts: list[str]) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for text in texts:
        for token in _B64_RX.findall(text)[:200]:
            body = token.rstrip("=")
            if body in seen:
                continue
            seen.add(body)
            padded = body + "=" * (-len(body) % 4)
            for dec in (base64.b64decode, base64.urlsafe_b64decode):
                try:
                    out = dec(padded.replace("-", "+").replace("_", "/") if dec is base64.b64decode else padded)
                except Exception:  # noqa: BLE001, S112 — not base64; try the next form
                    continue
                txt = out.decode("utf-8", errors="ignore")
                # mostly printable: a random id that happens to decode is noise, not a layer
                if txt and txt != token and sum(c.isprintable() or c in "\r\n\t" for c in txt) >= 0.9 * len(txt):
                    found.append(txt)
                break
    return found


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
        # double (and triple) encoding: %2527 → %27 → '  (only one round was decoded; review round 3 G7-10)
        cur = raw
        for _ in range(3):
            nxt = urllib.parse.unquote_plus(cur)
            if nxt == cur:
                break
            layers.append(nxt)
            cur = nxt
    except Exception:  # noqa: BLE001, S110 — decode probing: failure is the common case, not an error
        pass
    # JSON string escapes (`\\n`, `\\uff07`): a JSON body serialised with ensure_ascii hid newline and full-width
    # evasions from the layers below (round 4 S4-11)
    if "\\" in raw:
        unesc = _JSON_ESC_RX.sub(_json_unescape, raw)
        if unesc != raw:
            layers.append(unesc)
    # HTML entities (&#39; &lt;script) and full-width / compatibility forms (＇ＯＲ　１＝１) fold to ASCII
    for layer in list(layers):
        for alt in (html.unescape(layer), unicodedata.normalize("NFKC", layer)):
            if alt != layer and alt not in layers:
                layers.append(alt)
    # base64 on substrings that look like base64, in the raw and URL-decoded layers: `q=<b64>` used to be one
    # token (the class included `=`), and %3D padding or missing padding failed validation (round 4 S4-4)
    layers.extend(_b64_layers(list(layers)))
    # Comment-stripping evasion (UNI/**/ON SELECT -> UNION SELECT), MySQL line comments, whitespace collapsing
    extra_layers = []
    for layer in layers:
        no_comments = _strip_comments(layer)
        if no_comments != layer:
            extra_layers.append(no_comments)
        no_line = _LINE_COMMENT_RX.sub(" ", no_comments)
        if no_line != no_comments:
            extra_layers.append(no_line)
        # Whitespace-collapsing evasion (' OR  1 = 1 -> ' OR 1=1)
        collapsed = re.sub(r"\s*=\s*", "=", re.sub(r"\s+", " ", no_line))
        if collapsed != layer:
            extra_layers.append(collapsed)
    layers.extend(extra_layers)

    flat = " ".join(layers).lower()
    flat = _UNION_RX.sub("union select", flat)        # UNION ALL / DISTINCT SELECT is UNION SELECT
    flat = _UNION_ANY_RX.sub("union select", flat)    # union(select(…)) — round 4 S4-11
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


def _canon_ip(v: object) -> str:
    """One spelling per address: ``::ffff:185.220.101.45`` is the seed bad IP ``185.220.101.45`` (round 7 D-11)."""
    import ipaddress
    t = str(v or "").strip().strip("[]")
    try:
        a = ipaddress.ip_address(t.split("%", 1)[0])
    except ValueError:
        return t
    if a.version == 6 and a.ipv4_mapped is not None:
        a = a.ipv4_mapped
    return str(a)


def _min_abuse_score() -> int:
    import os
    try:
        return max(0, min(100, int(os.environ.get("AEGIS_TI_MIN_ABUSE_SCORE", "50"))))
    except ValueError:
        return 50


def ip_reputation(ip: str) -> ToolResult:
    ip = _canon_ip(ip)
    if ip in _KNOWN_BAD:
        rep = _KNOWN_BAD[ip]
        # a feed entry is only "known malicious" above the confidence floor: a 0.02-confidence listing (a benign
        # scanner a feed half-heartedly lists) used to score high like a confirmed C2 (round 7 D-11)
        try:
            score = int(rep.get("abuse_score") or 0)
        except (TypeError, ValueError):
            score = 0
        floor = _min_abuse_score()
        if score >= floor:
            verdict, weight = "known_malicious", "high"
        elif score >= floor // 2:
            verdict, weight = "listed_low_confidence", "medium"
        else:
            verdict, weight = "listed_low_confidence", "low"
        return ToolResult(
            name="ip_reputation",
            data={"ip": ip, **rep, "verdict": verdict},
            weight=weight,
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


def user_baseline(user_id: str | None) -> ToolResult:
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


def _inet_aton(h: str) -> ipaddress.IPv4Address | None:
    """IPv4 the way a resolver / curl reads it: ``2852039166``, ``0xa9fea9fe``, ``127.1``, ``0177.0.0.1`` are all
    addresses (code review 2026-11-03 W12 — the literal check scored every one of them as an external host)."""
    parts = h.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    nums = []
    for p in parts:
        try:
            if p.startswith(("0x", "0X")):
                nums.append(int(p[2:] or "0", 16))
            elif len(p) > 1 and p.startswith("0"):
                nums.append(int(p, 8))
            else:
                nums.append(int(p, 10))
        except ValueError:
            return None
    *head, last = nums
    if any(n > 255 for n in head) or last >= 256 ** (4 - len(head)) or any(n < 0 for n in nums):
        return None
    v = 0
    for n in head:
        v = v * 256 + n
    v = v * 256 ** (4 - len(head)) + last
    return ipaddress.IPv4Address(v)


def _host_is_internal(host: str) -> tuple[bool, str]:
    """Classify a URL host as an SSRF target by what it *resolves to*, not a literal match."""
    h = (host or "").strip().strip("[]").lower().rstrip(".")
    if not h:
        return False, ""
    if h in _METADATA_HOSTS or h in _INTERNAL_NAMES:
        return True, "cloud-metadata / internal service name"
    if h.endswith((".internal", ".local", ".svc", ".cluster.local")):
        return True, "internal DNS suffix"
    try:
        from ..shared.netguard import unwrap
        try:
            ip = ipaddress.ip_address(h)
        except ValueError:
            ip = _inet_aton(h)
            if ip is None:
                raise
        ip = unwrap(ip)                                                # ::ffff:a.b.c.d, NAT64, 6to4
        if str(ip) in _METADATA_HOSTS:
            return True, "cloud-metadata address"
        if ip.is_loopback:
            return True, "loopback address"
        if ip.is_link_local:
            return True, "link-local address"
        if ip.is_private or ip.is_reserved or ip.is_unspecified:
            return True, "private/reserved address"
    except ValueError:
        pass  # not an IP literal
    # Wildcard-DNS services resolve a name to the address written inside it (``169.254.169.254.nip.io``,
    # ``10-0-0-5.sslip.io``) or always to loopback (``localtest.me``): "a dotted name is external" let both reach
    # the metadata service (round 7 D-9).
    if h == "localhost" or h.endswith(".localhost"):
        return True, "loopback name"
    for suf in _LOOPBACK_WILDCARD_DNS:
        if h == suf or h.endswith("." + suf):
            return True, f"wildcard DNS ({suf}) always resolves to loopback"
    for suf in _EMBEDDED_IP_DNS:
        if h.endswith("." + suf):
            prefix = h[: -len(suf) - 1]
            m = _EMBEDDED_QUAD.search(prefix)
            cand = m.group(1).replace("-", ".") if m else ""
            if not cand:
                hx = re.search(r"(?:^|[.-])([0-9a-f]{8})$", prefix)
                cand = str(ipaddress.ip_address(int(hx.group(1), 16))) if hx else ""
            if cand:
                inner, why = _host_is_internal(cand)
                if inner:
                    return True, f"wildcard DNS ({suf}) to {cand}: {why}"
    return False, ""


_LOOPBACK_WILDCARD_DNS = ("localtest.me", "lvh.me", "vcap.me", "lacolhost.com", "localho.st")
_EMBEDDED_IP_DNS = ("nip.io", "sslip.io", "xip.io", "traefik.me")
_EMBEDDED_QUAD = re.compile(r"(?:^|[.-])((?:\d{1,3}[.-]){3}\d{1,3})$")


def ssrf_probe(raw: str) -> ToolResult:
    """Flag URL-valued input aimed at an internal / metadata / link-local destination.

    Matches RFC1918, loopback, link-local and metadata IPs (in any form a resolver accepts),
    internal DNS suffixes, bare service names (``meta:8000``), and the wildcard-DNS services
    that resolve to an address written in the name (``169.254.169.254.nip.io``) or always to
    loopback (``localtest.me``). It does not resolve DNS: any other public-looking name is
    treated as external, so a domain the attacker controls that points at an internal address
    (DNS rebinding) is not caught here — that needs the egress proxy's resolved-IP check.
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
    # URLs with an explicit scheme. The scheme part is bounded: an unbounded `[a-z][a-z0-9+.-]*://` retries
    # from every letter of a long run and was quadratic (a 300 KB payload stalled triage for minutes — code
    # review 2026-11-03 T4). The bound keeps it linear; leading non-letters are trimmed after the match, so
    # `1http://…` and a 100-letter prefix before `http://` are still caught.
    for m in _URL_RX.findall(text):
        m = _SCHEME_LEAD.sub("", m)
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
        # `10:30`, `16:00`, an ISO timestamp's `T10:30` are times, not host:port: a bare 1–3 digit "host" read
        # through inet_aton as 0.0.0.10 made every UPI / NEFT body an SSRF probe (round 4 S4-3). Only a dotless
        # name of fewer than four digits is skipped: requiring a letter or a full dotted quad also dropped the
        # short and decimal forms a resolver accepts — `127.1:6379`, `2130706433:80`, `0177.1:8080`, `10.1:9200`
        # (review round 5 Y5-11).
        if not any(c.isalpha() for c in name):
            # a numeric "host": only a port without a leading zero, and only an address a resolver would reach
            # (not 0.0.0.0/8, where `1500:30`, `2026:11`, `25000:00` land) — amounts, years and clock times stay clean
            if (name.isdigit() and len(name) < 4) or port.startswith("0"):
                continue
            a = _inet_aton(name)
            if a is None or a in ipaddress.ip_network("0.0.0.0/8"):
                continue
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
        except Exception:  # noqa: BLE001 — not a form body; nothing to parse
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


# ---- Tool: header / cookie injection -----------------------------------

#: headers an app commonly trusts, logs or reflects unsanitized — a payload here reaches the
#: backend without ever touching the query string the simpler scanners watch.
_INJECTABLE_HEADERS = ("x-forwarded-for", "x-forwarded-host", "x-real-ip", "true-client-ip",
                       "referer", "referrer", "forwarded", "x-original-url", "x-rewrite-url",
                       "x-api-version", "x-request-id", "cookie", "user-agent")
_CRLF_MARKERS = ("\r", "\n", "%0d", "%0a", "\\r", "\\n")


def header_injection(alert: dict) -> ToolResult:
    """Injection carried in request headers (incl. Cookie): CRLF / response-splitting in any
    header value, or SQLi / XSS / traversal / RCE primitives in a header the app tends to trust
    (XFF, Referer, Cookie, …). Covers the header- and cookie-borne classes the query-only scan
    misses — e.g. SQLi read from a session cookie the app concatenates into a lookup."""
    req = dict(alert.get("request_headers")) if isinstance(alert.get("request_headers"), dict) else {}
    if alert.get("user_agent") and not any(str(k).lower() == "user-agent" for k in req):
        req["User-Agent"] = alert["user_agent"]          # the UA is a header too; it was never scanned (G7-10)
    if not req:
        return ToolResult(name="header_injection", data={"applicable": False}, weight="low")
    hits: list[dict] = []
    cookie_injection = False
    for name, value in req.items():
        lname = str(name).lower()
        val = str(value)
        if any(m in val for m in _CRLF_MARKERS) or any(m in val.lower() for m in ("%0d", "%0a")):   # %0D%0A too
            hits.append({"header": lname, "kind": "crlf"})
        if lname in _INJECTABLE_HEADERS:
            low = urllib.parse.unquote_plus(val).lower()
            prim = ([p for p in _SQLI_PRIMITIVES if p in low]
                    + [p for p in _XSS_PRIMITIVES if p in low]
                    + [p for p in _TRAVERSAL_PRIMITIVES if p in low]
                    + [p for p in _RCE_PRIMITIVES if p in low])
            if prim:
                hits.append({"header": lname, "kind": "payload", "primitives": prim[:5]})
                if lname == "cookie":
                    cookie_injection = True
    if not hits:
        return ToolResult(name="header_injection", data={"headers_checked": len(req)}, weight="low")
    weight = "high" if (cookie_injection or any(h["kind"] == "crlf" for h in hits) or len(hits) >= 2) else "medium"
    return ToolResult(name="header_injection",
                      data={"hits": hits, "cookie_injection": cookie_injection}, weight=weight)


# ---- Tool: automated-scanner signature ---------------------------------

#: known offensive tools and bare HTTP libraries used as a sole UA. The high set are scanners
#: with no benign use against a bank; the rest are tells, not proof.
_SCANNER_UAS_HIGH = ("sqlmap", "nikto", "nuclei", "acunetix", "nessus", "wpscan", "arachni",
                     "metasploit", "havij")
_SCANNER_UAS_MED = ("nmap", "masscan", "dirbuster", "gobuster", "feroxbuster", "ffuf", "zgrab",
                    "httpx", "python-requests", "go-http-client", "libwww-perl", "curl/", "wget/")


def scanner_signature(alert: dict) -> ToolResult:
    """Automated-tool tells: an empty / missing User-Agent (EMPTY_UA), or a known scanner /
    bare-HTTP-library UA. A tell, not a verdict — it raises suspicion, the brain decides."""
    req = alert.get("request_headers") if isinstance(alert.get("request_headers"), dict) else {}
    ua = str(alert.get("user_agent") or req.get("User-Agent") or req.get("user-agent") or "").strip()
    if not ua:
        return ToolResult(name="scanner_signature",
                          data={"user_agent": "", "reason": "empty/missing user-agent"}, weight="medium")
    low = ua.lower()
    for sig in _SCANNER_UAS_HIGH:
        if sig in low:
            return ToolResult(name="scanner_signature",
                              data={"user_agent": ua[:200], "scanner": sig}, weight="high")
    for sig in _SCANNER_UAS_MED:
        if sig in low:
            return ToolResult(name="scanner_signature",
                              data={"user_agent": ua[:200], "tool": sig}, weight="medium")
    return ToolResult(name="scanner_signature", data={"user_agent": ua[:120]}, weight="low")


# ---- Tool: reconnaissance sweep (per-source, stateful) -----------------

_RECON_WINDOW_SEC = int(os.environ.get("AEGIS_RECON_WINDOW_SEC", "60"))
_RECON_PATHS_HIGH = int(os.environ.get("AEGIS_RECON_PATHS_HIGH", "20"))
_RECON_PATHS_MED = int(os.environ.get("AEGIS_RECON_PATHS_MED", "10"))
_RECON_MAX_IPS = int(os.environ.get("AEGIS_RECON_MAX_IPS", "20000"))
_recon_lock = threading.Lock()
# least-recently-written source evicted past the cap: O(1) per call (the old cleanup scanned the whole map
# under the global lock on every call once it passed the cap)
_recon_seen: dict[str, collections.deque] = BoundedDict(_RECON_MAX_IPS)


def recon_sweep(source_ip: str, alert: dict, *, now: float | None = None) -> ToolResult:
    """Directory / endpoint sweep: one source touching many distinct paths in a short window —
    the shape of a scanner enumerating the app (RECON_SWEEP). Stateful per source IP, in a
    sliding window; thresholds via AEGIS_RECON_PATHS_HIGH / _MED / _WINDOW_SEC."""
    ip = str(source_ip or "").strip()
    if not ip:
        return ToolResult(name="recon_sweep", data={"applicable": False}, weight="low")
    url = str(alert.get("url") or "")
    path = urllib.parse.urlsplit(url).path or url
    ts = now if now is not None else time.time()
    cutoff = ts - _RECON_WINDOW_SEC
    with _recon_lock:
        dq = _recon_seen.get(ip)
        if dq is None:
            dq = _recon_seen[ip] = collections.deque(maxlen=1024)
        else:
            _recon_seen.move_to_end(ip)
        dq.append((ts, path))
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        n = len({p for _t, p in dq})
    if n >= _RECON_PATHS_HIGH:
        return ToolResult(name="recon_sweep",
                          data={"distinct_paths": n, "window_sec": _RECON_WINDOW_SEC}, weight="high")
    if n >= _RECON_PATHS_MED:
        return ToolResult(name="recon_sweep",
                          data={"distinct_paths": n, "window_sec": _RECON_WINDOW_SEC}, weight="medium")
    return ToolResult(name="recon_sweep", data={"distinct_paths": n}, weight="low")


# ---- Tool: object-id enumeration (IDOR probing, per-actor) -------------

#: parameter names that typically carry a direct object reference. Walking many distinct values
#: of one of these on a single endpoint is the shape of IDOR exploitation / enumeration.
_ID_PARAMS = {"id", "user_id", "userid", "uid", "account", "account_id", "accountid", "acct",
              "customer_id", "customerid", "cust_id", "order_id", "orderid", "invoice_id",
              "doc_id", "file_id", "record_id", "txn_id", "transaction_id", "ref", "pid",
              "object_id", "obj_id", "profile_id", "msg_id", "message_id", "card_id", "stmt_id"}
_IDENUM_WINDOW_SEC = int(os.environ.get("AEGIS_IDENUM_WINDOW_SEC", "120"))
_IDENUM_HIGH = int(os.environ.get("AEGIS_IDENUM_HIGH", "15"))
_IDENUM_MED = int(os.environ.get("AEGIS_IDENUM_MED", "6"))
_idenum_lock = threading.Lock()
_idenum_seen: dict[tuple, collections.deque] = BoundedDict(_RECON_MAX_IPS)


def _id_params_from(alert: dict, raw_payload: str) -> list[tuple[str, str]]:
    pairs: list = []
    q = urllib.parse.urlsplit(str(alert.get("url") or "")).query
    if q:
        pairs += urllib.parse.parse_qsl(q, keep_blank_values=False)
    bp = alert.get("body_params")
    if isinstance(bp, dict):
        pairs += [(k, v) for k, v in bp.items()]
    if not pairs and raw_payload:
        try:
            pairs += urllib.parse.parse_qsl(raw_payload, keep_blank_values=False)
        except Exception:  # noqa: BLE001, S110 — not form-encoded; nothing to enumerate
            pass
    return [(str(k).lower(), str(v).strip()) for k, v in pairs
            if str(k).lower() in _ID_PARAMS and str(v).strip()]


def id_enumeration(source_ip: str, alert: dict, raw_payload: str = "", *,
                   now: float | None = None) -> ToolResult:
    """Object-id enumeration / IDOR probing: one actor requesting many DISTINCT values of an
    object-id parameter on one endpoint in a window — walking ``/account?id=1,2,3…``. Keyed by
    the shim-supplied ``principal`` when present (so authenticated sessions are told apart even
    behind one IP / a loopback lab), else the source IP. Stateful, windowed, thread-safe."""
    actor = str(alert.get("principal") or source_ip or "").strip()
    ids = _id_params_from(alert, raw_payload)
    if not actor or not ids:
        return ToolResult(name="id_enumeration", data={"applicable": False}, weight="low")
    path = urllib.parse.urlsplit(str(alert.get("url") or "")).path or "/"
    ts = now if now is not None else time.time()
    cutoff = ts - _IDENUM_WINDOW_SEC
    best, best_param = 0, ""
    with _idenum_lock:
        for key, value in ids:
            k = (actor, path, key)
            dq = _idenum_seen.get(k)
            if dq is None:
                dq = _idenum_seen[k] = collections.deque(maxlen=1024)
            else:
                _idenum_seen.move_to_end(k)
            dq.append((ts, value))
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            n = len({v for _t, v in dq})
            if n > best:
                best, best_param = n, key
    data = {"actor": actor[:40], "path": path, "param": best_param,
            "distinct_ids": best, "window_sec": _IDENUM_WINDOW_SEC}
    if best >= _IDENUM_HIGH:
        return ToolResult(name="id_enumeration", data=data, weight="high")
    if best >= _IDENUM_MED:
        return ToolResult(name="id_enumeration", data=data, weight="medium")
    return ToolResult(name="id_enumeration", data=data, weight="low")


# ---- Tool: secret-file request signature (credential-disclosure attempt) ----

#: Paths with no benign reason to be fetched from a bank's web tier — a dev-left secret, a VCS
#: directory, a framework config, a key or a backup. A request for one is a credential-disclosure
#: attempt (the CVE_DOTENV_DISCLOSURE / CVE_LARAVEL_LOG_DISCLOSURE / edge-/export/-alias classes);
#: whether it SUCCEEDED is decided by the response (see secret_exfil_probe). Matched case-insensitively
#: against the decoded URL path, so ``/..%2f.env`` and ``/public/../.env`` both land here.
_SECRET_PATH_SIGNS = (
    ".env", ".env.local", ".env.prod", ".env.production", ".env.dev", ".env.bak",
    ".git/config", ".git/head", ".gitconfig", ".svn/", ".hg/",
    "wp-config.php", "config.php", "configuration.php", "settings.py", "local_settings.py",
    "application.properties", "application.yml", "appsettings.json", "web.config",
    "/storage/logs/", "laravel.log", "debug.log",
    "id_rsa", ".pem", ".ppk", ".p12", ".pfx", ".keystore", ".jks",
    ".aws/credentials", "/.aws/", ".npmrc", ".dockercfg", ".docker/config.json",
    ".kube/config", ".htpasswd", ".netrc", ".pgpass", "secrets.yml", "secrets.yaml", "credentials.json",
)
#: an /export/ or /backup/ directory is a leak only when what is fetched from it is a dump or an archive —
#: "/statements/export/pdf" is a customer downloading a statement (review round 3 G7-10)
_DUMP_DIRS = ("/export/", "/backup/", "/backups/")
_DUMP_EXT = (".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".sql", ".bak", ".dump", ".db", ".sqlite", ".bkp", ".mdb")
#: Backup / editor-swap suffixes that turn an otherwise-servable file into a source/secret leak
#: (``index.php.bak``, ``config.php~``, ``database.sql``, ``.env.swp``).
_SECRET_SUFFIXES = (".bak", ".old", ".save", ".orig", ".swp", ".swo", ".tmp", "~",
                    ".sql", ".sql.gz", ".dump", ".tar.gz", ".tgz", ".zip.old")
#: Served-content tells: a 200 with one of these content types on a secret path means the file came
#: back, not a redirect to /login. Octet-stream / plain text on a config path is the disclosure.
_DISCLOSURE_CONTENT_TYPES = ("application/octet-stream", "text/plain", "application/x-yaml",
                             "text/x-php", "application/json")


#: a customer's own export (a zipped statement, a passbook download) is not a dump (round 4 S4-16)
_CUSTOMER_EXPORT_HINTS = ("statement", "passbook", "/me/", "/my/", "/self/", "invoice", "receipt", "/customer/")


def _sign_in(sign: str, path: str) -> bool:
    """``.env`` family on a path-segment boundary: ``/.env``, ``/.env.local``, ``/.env~`` — not ``/.envelope/``
    or ``/api/.environment`` (round 4 S4-16)."""
    if not sign.startswith(".env"):
        return sign in path
    for seg in path.split("/"):
        if seg == sign or (seg.startswith(sign) and seg[len(sign):len(sign) + 1] in (".", "~", "_", "-")):
            return True
    return False


def _decoded_path(alert: dict) -> str:
    raw = str(alert.get("url") or alert.get("uri") or alert.get("path") or "")
    path = urllib.parse.urlsplit(raw).path or raw
    # double-decode so %2e%2e%2f and %2f obfuscation of the same target collapse to one string
    for _ in range(2):
        dec = urllib.parse.unquote(path)
        if dec == path:
            break
        path = dec
    return path.lower()


def _status_of(alert: dict) -> int | None:
    for k in ("status", "status_code", "response_code", "responseCode"):
        v = alert.get(k)
        if v is None:
            continue
        try:
            return int(v)
        except (TypeError, ValueError):
            continue
    return None


def secret_file_probe(alert: dict) -> ToolResult:
    """Credential-disclosure attempt: a request for a path that only exists to leak a secret — a
    dev-left ``.env``, a ``.git`` dir, a framework config, a private key, or a source/DB backup. These
    are the classes a scanning agent uses to harvest the ``id``/``password`` an app was shipped with.
    The signature is the attempt; the response decides success — a 200 that actually served the file
    (``_status``/content-type tell) is HIGH, a blocked/absent one (401/403/404) stays MEDIUM so a
    refused probe is noted without crying breach."""
    path = _decoded_path(alert)
    if not path:
        return ToolResult(name="secret_file_probe", data={"applicable": False}, weight="low")
    hit = next((s for s in _SECRET_PATH_SIGNS if _sign_in(s, path)), "")
    if not hit and any(d in path for d in _DUMP_DIRS) and path.endswith(_DUMP_EXT) \
            and not any(h in path for h in _CUSTOMER_EXPORT_HINTS):
        hit = next(d for d in _DUMP_DIRS if d in path)
    if not hit:
        hit = next((f"*{suf}" for suf in _SECRET_SUFFIXES if path.endswith(suf)), "")
    if not hit:
        return ToolResult(name="secret_file_probe", data={"path": path[:120]}, weight="low")
    status = _status_of(alert)
    rh = alert.get("response_headers") if isinstance(alert.get("response_headers"), dict) else {}
    ctype = str(rh.get("content-type") or rh.get("Content-Type") or "").split(";")[0].strip().lower()
    served = (status == 200) and (not ctype or any(ctype == c for c in _DISCLOSURE_CONTENT_TYPES)
                                  or ctype.startswith("text/"))
    data = {"path": path[:120], "signature": hit, "status": status, "content_type": ctype or None,
            "served": served}
    if status is None:
        # we saw the attempt but not the outcome — a real secret-file request is still high-signal
        return ToolResult(name="secret_file_probe", data=data, weight="high")
    if served:
        data["disclosure"] = True
        return ToolResult(name="secret_file_probe", data=data, weight="high")
    if status in (401, 403, 404, 400):
        data["blocked"] = True
        return ToolResult(name="secret_file_probe", data=data, weight="medium")
    return ToolResult(name="secret_file_probe", data=data, weight="high")


# ---- Tool: secret exfiltration in the response body --------------------

#: What a leaked secret looks like in a response body, independent of the path that served it — so a
#: novel disclosure vector (LFI, a misrouted download, an error page dumping config) is caught by the
#: SHAPE of what left the building, not by a path list. This is the response-side half of the claim
#: "even if the agent reads the file, the credentials don't leave": the brain can refuse on this.
_SECRET_BODY_PATTERNS = (
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws_secret", re.compile(r"aws_secret_access_key\s*[=:]", re.IGNORECASE)),
    ("gcp_sa_key", re.compile(r'"type"\s*:\s*"service_account"')),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}")),
    ("github_pat", re.compile(r"\bghp_[0-9A-Za-z]{30,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("bearer_token", re.compile(r"authorization\s*:\s*bearer\s+[0-9A-Za-z._\-]{16,}", re.IGNORECASE)),
    ("db_dsn", re.compile(r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s:@/]+@", re.IGNORECASE)),
    ("env_secret_assign", re.compile(
        r"(?im)^\s*(?:DB_PASSWORD|DB_USERNAME|DATABASE_URL|APP_KEY|SECRET_KEY|JWT_SECRET|"
        r"API_KEY|API_SECRET|PRIVATE_KEY|ENCRYPTION_KEY|STRIPE_SECRET|TWILIO_AUTH_TOKEN)\s*=\s*\S+")),
)


def _response_body_of(alert: dict) -> str:
    for k in ("response_body", "resp_body", "body_response", "response_text"):
        v = alert.get(k)
        if isinstance(v, str) and v:
            return v
    resp = alert.get("response")
    if isinstance(resp, dict):
        b = resp.get("body")
        if isinstance(b, str):
            return b
    return ""


def secret_exfil_probe(alert: dict) -> ToolResult:
    """Secret leaving in the RESPONSE: scan the body (when the sensor forwards it — the shim and the
    api-gateway path do) for the shape of a credential — a private key, an AWS/Slack/GitHub key, a
    DSN with an inline password, or ``DB_PASSWORD=``-style env assignments. Path-independent, so it
    catches disclosure vectors no path signature lists. HIGH on any match: a bank's web response has
    no benign reason to carry a private key or a database password."""
    body = _response_body_of(alert)
    if not body:
        return ToolResult(name="secret_exfil_probe", data={"applicable": False}, weight="low")
    sample = body[:200_000]  # cap the scan; a leak shows in the first page
    found = [name for name, rx in _SECRET_BODY_PATTERNS if rx.search(sample)]
    if not found:
        return ToolResult(name="secret_exfil_probe", data={"scanned_bytes": len(sample)}, weight="low")
    status = _status_of(alert)
    return ToolResult(name="secret_exfil_probe",
                      data={"secret_kinds": found[:8], "count": len(found), "status": status,
                            "bytes": len(body)}, weight="high")


# ---- Helpers -----------------------------------------------------------

def run_all_tools(raw_payload: str, source_ip: str, user_id: str | None,
                  alert: dict | None = None) -> list[ToolResult]:
    alert = alert or {}
    return [
        isolated(lambda: decode_payload(raw_payload), "decode_payload", ToolResult),
        isolated(lambda: ip_reputation(source_ip), "ip_reputation", ToolResult),
        isolated(lambda: similar_past_requests(raw_payload), "similar_past_requests", ToolResult),
        isolated(lambda: user_baseline(user_id), "user_baseline", ToolResult),
        isolated(lambda: ssrf_probe(raw_payload), "ssrf_probe", ToolResult),
        isolated(lambda: cors_reflection(alert), "cors_reflection", ToolResult),
        isolated(lambda: mass_assignment(alert, raw_payload), "mass_assignment", ToolResult),
        isolated(lambda: host_header_anomaly(alert), "host_header_anomaly", ToolResult),
        isolated(lambda: header_injection(alert), "header_injection", ToolResult),
        isolated(lambda: scanner_signature(alert), "scanner_signature", ToolResult),
        isolated(lambda: recon_sweep(source_ip, alert), "recon_sweep", ToolResult),
        isolated(lambda: id_enumeration(source_ip, alert, raw_payload), "id_enumeration", ToolResult),
        isolated(lambda: secret_file_probe(alert), "secret_file_probe", ToolResult),
        isolated(lambda: secret_exfil_probe(alert), "secret_exfil_probe", ToolResult),
    ]
