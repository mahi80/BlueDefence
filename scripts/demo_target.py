#!/usr/bin/env python3
"""Ledger Demo Bank — a BENIGN target for the AEGIS live demo.

This is the thing the "attack" hits during a near-real demo on a laptop. It is
deliberately *not* vulnerable:

  * SQL goes through parameterized queries, so an injection string in a param is
    stored/compared as data and can never alter the ledger.
  * File uploads are refused outright — nothing is ever written to disk, no
    interpreter is ever invoked, there is no web shell.
  * There is no eval, no shell-out, no templating of user input.

In front of the benign app sits a small signature WAF/IDS. It *inspects* every
request, FLAGS attack-shaped traffic (SQLi, path traversal / LFI, web-shell
upload attempts, command-injection, scanner user-agents, auth bursts, anomalous
TLS client fingerprints), answers it 403, and records it as a security event.
Detection + logging only — the payload is never executed. Each finding is also
emitted as an AEGIS-shaped alert and, with ``--aegis-url``, POSTed to a running
AEGIS ingest endpoint so the real SOC pipeline triages it live.

Pair it with ``scripts/demo_attack_traffic.py`` (the safe attack-shaped traffic
generator) and point a console at AEGIS to tell the whole story:

    attack-shaped traffic  ->  this target flags + 403s  ->  AEGIS detects,
    maps blast radius, proposes containment, a human approves  ->  contained.

stdlib only — no third-party deps, no outbound network except the optional
best-effort alert POST, so it won't fail in front of a prospect.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import pathlib
import re
import secrets
import sqlite3
import subprocess
import hmac
import ssl
import threading
import urllib.error
import urllib.request
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

# --------------------------------------------------------------------------- #
# Signature WAF / IDS  —  detection only, nothing is ever executed
# --------------------------------------------------------------------------- #

CRITICAL, HIGH, MEDIUM = "critical", "high", "medium"


@dataclass(frozen=True)
class Rule:
    name: str
    severity: str
    pattern: re.Pattern[str]
    where: str  # "qs" | "body" | "path" | "ua" | "any"
    detail: str


# Known-bad TLS client fingerprints (JA3). In a real deployment a TLS-inspecting
# proxy / NDR box computes these; here the generator presents one via a header so
# the demo can show a "malware TLS client posing as a browser" signal end-to-end.
BAD_JA3 = {
    "e7d705a3286e19ea42f587b344ee6865": "known-bad: commodity Go TLS client (malware C2 class)",
    "a0e9f5d64349fb13191bc781f81f42e1": "known-bad: automated scanner TLS stack",
}

# Scanner / offensive-tooling user-agents we never expect from a real customer.
SCANNER_UA = re.compile(
    r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|hydra|"
    r"nuclei|acunetix|havij|zgrab|curl/|python-requests|go-http-client)",
    re.I,
)

# Signatures are intentionally simple and well-known; they describe what to
# *catch*, not how to attack. This is the same class of rule a WAF ships with.
RULES: list[Rule] = [
    Rule("SQLI", CRITICAL,
         re.compile(r"(\bunion\b.{0,40}\bselect\b|\bor\b\s+1\s*=\s*1|';--|\bsleep\s*\(|\bwaitfor\s+delay\b|information_schema)", re.I),
         "qs", "SQL-injection signature in a request parameter"),
    Rule("PATH_TRAVERSAL", HIGH,
         re.compile(r"(\.\./|\.\.\\|/etc/passwd|/proc/self/|c:\\windows\\|%2e%2e%2f)", re.I),
         "any", "Path-traversal / local-file-inclusion signature"),
    Rule("CMD_INJECTION", CRITICAL,
         re.compile(r"(;\s*(cat|id|whoami|uname|nc|bash|sh)\b|\|\s*(cat|id|whoami|nc)\b|\$\(.*\)|`.*`|&&\s*curl\b)", re.I),
         "any", "OS-command-injection signature"),
    Rule("WEBSHELL_UPLOAD", CRITICAL,
         re.compile(r"(filename\s*=\s*\"?[^\"]*\.(php[0-9]?|phtml|jsp|jspx|asp|aspx|cfm|sh)\b|<\?php|<%\s*eval|system\s*\(\s*\$_)", re.I),
         "body", "Web-shell upload attempt (server-executable file / shell marker)"),
    Rule("XSS", MEDIUM,
         re.compile(r"(<script\b|onerror\s*=|javascript:|<img\b[^>]*onerror)", re.I),
         "any", "Cross-site-scripting signature"),
    Rule("SSRF_METADATA", HIGH,
         re.compile(r"(169\.254\.169\.254|metadata\.google\.internal|/latest/meta-data/)", re.I),
         "any", "SSRF toward a cloud metadata endpoint"),
    Rule("PROMPT_INJECTION", HIGH,
         re.compile(r"(ignore\s+(your|all|the|previous)\s+(rules|instructions)|disregard\s+(the\s+)?(above|previous)|approve\s+this\s+(transfer|request|payment)|you\s+are\s+now\s+)", re.I),
         "any", "LLM prompt-injection marker embedded in request content"),
]

_AUTH_PATHS = {"/login", "/api/login", "/api/auth"}


@dataclass
class Finding:
    rule: str
    severity: str
    detail: str
    signature: str  # short, redacted sample of what matched

    def as_dict(self) -> dict[str, str]:
        return {"rule": self.rule, "severity": self.severity, "detail": self.detail, "signature": self.signature}


def _redact(sample: str, limit: int = 80) -> str:
    """Keep a short, single-line sample of the matched token for the SOC feed."""
    s = " ".join(sample.split())
    return s[:limit] + ("…" if len(s) > limit else "")


@dataclass
class ClientState:
    """Per-source-IP state for stateful rules (auth bursts)."""
    auth_hits: deque = field(default_factory=lambda: deque(maxlen=50))


def inspect(
    method: str,
    path: str,
    query: str,
    headers: dict[str, str],
    body: str,
    *,
    state: ClientState | None = None,
    now: _dt.datetime | None = None,
) -> list[Finding]:
    """Return findings for a request. Pure inspection — no side effects on the app.

    ``headers`` keys are expected lower-cased. ``state`` enables the stateful
    auth-burst rule; omit it for a pure, order-independent signature check.
    """
    findings: list[Finding] = []
    ua = headers.get("user-agent", "")
    haystacks = {"qs": query or "", "body": body or "", "path": path or "", "ua": ua}
    haystacks["any"] = "\n".join((haystacks["qs"], haystacks["body"], haystacks["path"]))

    for rule in RULES:
        hay = haystacks.get(rule.where, "")
        m = rule.pattern.search(hay)
        if m:
            findings.append(Finding(rule.name, rule.severity, rule.detail, _redact(m.group(0))))

    if ua and SCANNER_UA.search(ua):
        findings.append(Finding("SCANNER_UA", HIGH, "Offensive-tooling / scanner user-agent", _redact(ua)))

    ja3 = headers.get("x-demo-ja3", "")
    if ja3 in BAD_JA3:
        findings.append(Finding("BAD_TLS_CLIENT", HIGH, BAD_JA3[ja3], _redact(ja3)))

    # Stateful: more than 5 auth attempts inside 10 s from one source.
    if state is not None and path in _AUTH_PATHS and method == "POST":
        ts = (now or _dt.datetime.now(_dt.timezone.utc)).timestamp()
        state.auth_hits.append(ts)
        recent = [t for t in state.auth_hits if ts - t <= 10.0]
        if len(recent) > 5:
            findings.append(Finding("AUTH_BURST", HIGH,
                                    f"Credential-stuffing burst: {len(recent)} logins in 10s", f"{len(recent)} attempts"))

    return findings


# When several rules fire on one request, show the most *specific* attack as the
# headline — a content attack beats a login burst beats a bad TLS client beats a
# scanner user-agent, so the generic agent-UA signal never masks the real action.
_PRIORITY = {"SQLI": 9, "CMD_INJECTION": 9, "WEBSHELL_UPLOAD": 9, "PROMPT_INJECTION": 8,
             "SSRF_METADATA": 7, "PATH_TRAVERSAL": 7, "XSS": 6, "AUTH_BURST": 5,
             "BAD_TLS_CLIENT": 3, "SCANNER_UA": 1}


def to_alert(findings: list[Finding], *, src_ip: str, method: str, url: str, ua: str,
             asset: str = "web-edge-01", now: _dt.datetime | None = None) -> dict[str, Any]:
    """Shape a request's findings into one AEGIS-ingestable alert.

    This is the push contract the target speaks; a running aegis.service with an
    HTTP ingest receiver triages it exactly like a real WAF feed.
    """
    sev_rank = {CRITICAL: 3, HIGH: 2, MEDIUM: 1}
    worst = max(findings, key=lambda f: (sev_rank.get(f.severity, 0), _PRIORITY.get(f.rule, 4)))
    score = {CRITICAL: 0.97, HIGH: 0.85, MEDIUM: 0.6}.get(worst.severity, 0.5)
    ts = (now or _dt.datetime.now(_dt.timezone.utc)).isoformat()
    return {
        "id": f"waf-{uuid.uuid4().hex[:10]}",
        "source": "waf",
        "ts": ts,
        "severity": worst.severity,
        "category": "web_attack",
        "rule": worst.rule,
        "rules": [f.rule for f in findings],
        "src_ip": src_ip,
        "method": method,
        "url": url,
        "user_agent": ua,
        "asset": asset,
        "action": "blocked",
        "anomaly_score": score,
        "detail": worst.detail,
        "signatures": [f.as_dict() for f in findings],
        "vendor": "ledger-demo-waf",
    }


# --------------------------------------------------------------------------- #
# Benign ledger (parameterized — injection in a param cannot alter it)
# --------------------------------------------------------------------------- #

# Synthetic customer accounts — a fictional, offline bank. Every row is invented:
# ``*.demo`` email domains, 555 phone numbers, made-up names and addresses, seed
# balances. No real person, account, or payment card is represented. "money,
# address, etc." lives here so the SOC demo can show behavioural detection over
# realistic-shaped records without any real customer data anywhere.
_COLS = ("id", "name", "email", "phone", "address", "city", "country",
         "balance", "currency", "kyc_status", "opened_at")

_SEED: list[dict[str, Any]] = [
    {"id": "AC-1001", "name": "Operating Account — Demo Bank", "email": "ops@ledger.demo",
     "phone": "+1-202-555-0101", "address": "1 Market Plaza, Suite 300", "city": "San Francisco",
     "country": "US", "balance": 4820145.55, "currency": "USD", "kyc_status": "verified", "opened_at": "2019-03-14"},
    {"id": "AC-1002", "name": "Payroll Clearing", "email": "payroll@ledger.demo",
     "phone": "+1-202-555-0102", "address": "1 Market Plaza, Suite 310", "city": "San Francisco",
     "country": "US", "balance": 1290000.00, "currency": "USD", "kyc_status": "verified", "opened_at": "2019-03-14"},
    {"id": "AC-1003", "name": "Treasury Reserve", "email": "treasury@ledger.demo",
     "phone": "+1-202-555-0103", "address": "1 Market Plaza, Suite 900", "city": "San Francisco",
     "country": "US", "balance": 18750000.00, "currency": "USD", "kyc_status": "verified", "opened_at": "2019-03-14"},
    {"id": "AC-2007", "name": "Merchant Settlement", "email": "settlement@ledger.demo",
     "phone": "+1-202-555-0207", "address": "412 Commerce Way", "city": "Denver",
     "country": "US", "balance": 642310.12, "currency": "USD", "kyc_status": "verified", "opened_at": "2020-11-05"},
    {"id": "AC-4242", "name": "Demo Customer — J. Rivera", "email": "j.rivera@mail.demo",
     "phone": "+1-202-555-0142", "address": "88 Alder Street", "city": "Austin",
     "country": "US", "balance": 15230.40, "currency": "USD", "kyc_status": "verified", "opened_at": "2022-07-02"},
    {"id": "AC-5100", "name": "Demo Customer — A. Khan", "email": "a.khan@mail.demo",
     "phone": "+1-202-555-0151", "address": "20 Birch Lane", "city": "Columbus",
     "country": "US", "balance": 48210.09, "currency": "USD", "kyc_status": "verified", "opened_at": "2021-05-19"},
    {"id": "AC-5101", "name": "Demo Customer — M. Okafor", "email": "m.okafor@mail.demo",
     "phone": "+1-202-555-0152", "address": "7 Cedar Court", "city": "Newark",
     "country": "US", "balance": 9875.00, "currency": "USD", "kyc_status": "pending", "opened_at": "2023-01-28"},
    {"id": "AC-5102", "name": "Demo Customer — L. Santos", "email": "l.santos@mail.demo",
     "phone": "+1-202-555-0153", "address": "305 Spruce Ave", "city": "Miami",
     "country": "US", "balance": 132540.77, "currency": "USD", "kyc_status": "verified", "opened_at": "2020-08-11"},
    {"id": "AC-5103", "name": "Demo Customer — K. Müller", "email": "k.mueller@mail.demo",
     "phone": "+49-30-5550-0154", "address": "Beispielstraße 5", "city": "Berlin",
     "country": "DE", "balance": 76110.25, "currency": "EUR", "kyc_status": "verified", "opened_at": "2021-09-30"},
    {"id": "AC-5104", "name": "Demo Customer — S. Nair", "email": "s.nair@mail.demo",
     "phone": "+91-11-5550-0155", "address": "14 Example Marg", "city": "New Delhi",
     "country": "IN", "balance": 254300.00, "currency": "INR", "kyc_status": "verified", "opened_at": "2022-02-17"},
    {"id": "AC-5105", "name": "Demo Customer — T. Yamamoto", "email": "t.yamamoto@mail.demo",
     "phone": "+81-3-5550-0156", "address": "2-1 Sample Chome", "city": "Tokyo",
     "country": "JP", "balance": 51290.40, "currency": "JPY", "kyc_status": "verified", "opened_at": "2023-06-04"},
    {"id": "AC-5106", "name": "Demo Customer — P. Dubois", "email": "p.dubois@mail.demo",
     "phone": "+33-1-5550-0157", "address": "9 Rue Exemple", "city": "Lyon",
     "country": "FR", "balance": 18740.60, "currency": "EUR", "kyc_status": "pending", "opened_at": "2023-10-22"},
]


def _coerce(v: Any) -> Any:
    """Make a DB value JSON-serializable: Decimal → float, date/datetime → ISO string."""
    import decimal  # noqa: PLC0415 — only to recognise psycopg2's NUMERIC return type
    if isinstance(v, decimal.Decimal):
        return float(v)
    if isinstance(v, (_dt.date, _dt.datetime)):
        return v.isoformat()
    return v


class Ledger:
    """A benign customer ledger backed by an in-memory SQLite DB.

    Every query is parameterized, so a request like ``?id=' OR '1'='1`` is bound
    as a literal string and matches nothing — the demo shows the WAF catching the
    attempt while the data layer is simply not exploitable. All rows are synthetic.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._db = sqlite3.connect(":memory:", check_same_thread=False)
        cols = ", ".join(f"{c} TEXT PRIMARY KEY" if c == "id" else c for c in _COLS)
        self._db.execute(f"CREATE TABLE accounts ({cols})")
        self._db.executemany(
            f"INSERT INTO accounts ({', '.join(_COLS)}) VALUES ({', '.join('?' * len(_COLS))})",
            [tuple(s[c] for c in _COLS) for s in _SEED])
        self._db.commit()

    def all_accounts(self) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._db.execute(f"SELECT {', '.join(_COLS)} FROM accounts ORDER BY id")
            return [{c: _coerce(v) for c, v in zip(_COLS, r)} for r in cur.fetchall()]

    def lookup(self, acct: str) -> dict[str, Any] | None:
        with self._lock:
            cur = self._db.execute(f"SELECT {', '.join(_COLS)} FROM accounts WHERE id = ?", (acct,))
            r = cur.fetchone()
            return {c: _coerce(v) for c, v in zip(_COLS, r)} if r else None


class PgLedger:
    """The same benign ledger backed by Docker Postgres (``--pg-dsn``).

    psycopg2 is imported lazily so the demo keeps its stdlib-only default. The table
    is created if missing and seeded idempotently (``ON CONFLICT DO NOTHING``); every
    query is parameterized (``%s``), so injection in ``id`` is bound as data and
    matches nothing. Synthetic rows only — the Postgres instance holds no real data.
    """

    def __init__(self, dsn: str) -> None:
        import psycopg2  # noqa: PLC0415 — optional dep, only when a DSN is configured
        self._lock = threading.Lock()
        self._conn = psycopg2.connect(dsn)
        self._conn.autocommit = True
        with self._conn.cursor() as cur:
            cur.execute(
                "CREATE TABLE IF NOT EXISTS demo_accounts ("
                "id TEXT PRIMARY KEY, name TEXT, email TEXT, phone TEXT, address TEXT, city TEXT, "
                "country TEXT, balance NUMERIC(18,2), currency TEXT, kyc_status TEXT, opened_at DATE)")
            cur.executemany(
                f"INSERT INTO demo_accounts ({', '.join(_COLS)}) "
                f"VALUES ({', '.join(['%s'] * len(_COLS))}) ON CONFLICT (id) DO NOTHING",
                [tuple(s[c] for c in _COLS) for s in _SEED])

    def all_accounts(self) -> list[dict[str, Any]]:
        with self._lock, self._conn.cursor() as cur:
            cur.execute(f"SELECT {', '.join(_COLS)} FROM demo_accounts ORDER BY id")
            return [{c: _coerce(v) for c, v in zip(_COLS, r)} for r in cur.fetchall()]

    def lookup(self, acct: str) -> dict[str, Any] | None:
        with self._lock, self._conn.cursor() as cur:
            cur.execute(f"SELECT {', '.join(_COLS)} FROM demo_accounts WHERE id = %s", (acct,))
            r = cur.fetchone()
            return {c: _coerce(v) for c, v in zip(_COLS, r)} if r else None


def build_ledger(pg_dsn: str | None):
    """Postgres when a DSN is set (Docker PG holds the synthetic customer data), else in-memory SQLite."""
    return PgLedger(pg_dsn) if pg_dsn else Ledger()


# --------------------------------------------------------------------------- #
# HTTP handler  +  a simple demo session login
# --------------------------------------------------------------------------- #

# Demo credentials — intentionally trivial; this is a fictional offline bank.
DEMO_USERNAME = "admin"
DEMO_PASSWORD = "123"

# Even a demo shouldn't keep plaintext passwords or compare with ``==``: store a salted PBKDF2
# hash and verify in constant time. (Fictional offline bank; the salt is not a secret.)
_PW_SALT = b"ledger-demo-bank/v1"


def _hash_pw(pw: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), _PW_SALT, 120_000)


# Principals with a role and an account scope. Least privilege: only admin sees the whole ledger;
# a teller is scoped to its own account. ``scope=None`` means every account (admin). This is the
# authorization layer the WAF/SOC cannot substitute for.
_PRINCIPALS: dict[str, dict[str, Any]] = {
    "admin":  {"pw": _hash_pw("123"), "role": "admin",  "scope": None},
    "teller": {"pw": _hash_pw("123"), "role": "teller", "scope": {"AC-4242"}},
}


def _verify_login(user: str, pwd: str) -> bool:
    """Constant-time credential check against the stored PBKDF2 hash."""
    rec = _PRINCIPALS.get(user)
    return bool(rec) and hmac.compare_digest(rec["pw"], _hash_pw(pwd))
_TRANSFER_LIMIT = 50_000.0   # a non-admin transfer above this needs step-up (denied in the demo)

# App surface whose traffic is forwarded to the SOC. Authz routes emit their own (allowed/denied)
# event with the principal + operation; the rest get a generic allowed event for signature inspection.
# Plumbing endpoints (/soc, /api/security/events, /healthz, /logout) are excluded so the monitor's
# own polling doesn't flood the stream.
_AUTHZ_ROUTES = {"/api/accounts", "/api/account", "/api/transfer"}
_MONITORED = {"/", "/dashboard", "/login", "/transfers", "/api/upload", "/upload"} | _AUTHZ_ROUTES


class DemoState:
    def __init__(self, aegis_url: str | None, asset: str, aegis_token: str | None = None,
                 pg_dsn: str | None = None, secure_cookies: bool = False) -> None:
        self.ledger = build_ledger(pg_dsn)          # Postgres when a DSN is set, else in-memory SQLite
        self.pg_dsn = pg_dsn
        self.secure_cookies = secure_cookies        # True under TLS → the session cookie gets ``Secure``
        self.aegis_url = aegis_url
        self.aegis_token = aegis_token
        self.asset = asset
        self.events: deque = deque(maxlen=200)      # recent security events (for /soc)
        self.clients: dict[str, ClientState] = defaultdict(ClientState)
        self.totals = defaultdict(int)              # rule -> count
        self.sessions: dict[str, str] = {}          # token -> principal name
        self.blocked_ips: set[str] = set()          # SOC-contained sources — their requests get 403ed
        self.revoked_sids: set[str] = set()         # sessions the SOC revoked (for reporting)
        self._lock = threading.Lock()

    # -- SOC enforcement (real containment, not shadow) ------------------- #
    def block_ip(self, ip: str) -> None:
        if ip:
            with self._lock:
                self.blocked_ips.add(ip)

    def is_blocked(self, ip: str | None) -> bool:
        if not ip:
            return False
        with self._lock:
            return ip in self.blocked_ips

    def revoke_sid(self, sid: str | None) -> bool:
        if not sid:
            return False
        with self._lock:
            existed = self.sessions.pop(sid, None) is not None
            self.revoked_sids.add(sid)
        return existed

    def revoke_principal(self, principal: str) -> int:
        """Drop every live session for a principal (e.g. revoke the attacker's logins)."""
        with self._lock:
            sids = [s for s, p in self.sessions.items() if p == principal]
            for s in sids:
                self.sessions.pop(s, None)
                self.revoked_sids.add(s)
        return len(sids)

    def enforcement_snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {"blocked_ips": sorted(self.blocked_ips), "revoked_sessions": len(self.revoked_sids)}

    def record(self, alert: dict[str, Any]) -> None:
        with self._lock:
            self.events.appendleft(alert)
            for r in alert.get("rules", []):
                self.totals[r] += 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {"events": list(self.events), "totals": dict(self.totals),
                    "blocked": len(self.events), "signatures_matched": sum(self.totals.values())}

    # -- sessions -------------------------------------------------------- #
    def new_session(self, principal: str) -> str:
        token = secrets.token_hex(16)
        with self._lock:
            self.sessions[token] = principal
        return token

    def session_cookie(self, token: str) -> str:
        """HttpOnly + SameSite=Lax always; ``Secure`` added under TLS so the cookie never rides plain HTTP."""
        secure = "; Secure" if self.secure_cookies else ""
        return f"sid={token}; HttpOnly; Path=/; SameSite=Lax{secure}"

    def valid_session(self, sid: str | None) -> bool:
        if not sid:
            return False
        with self._lock:
            return sid in self.sessions

    def principal_of(self, sid: str | None) -> str | None:
        if not sid:
            return None
        with self._lock:
            return self.sessions.get(sid)

    def drop_session(self, sid: str | None) -> None:
        if not sid:
            return
        with self._lock:
            self.sessions.pop(sid, None)


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%H:%M:%S")


def _esc(s: Any) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))


class Handler(BaseHTTPRequestHandler):
    server_version = "LedgerDemoBank/1.0"
    state: DemoState  # set on the server instance

    # -- plumbing ---------------------------------------------------------- #
    def log_message(self, *_a: Any) -> None:  # keep the console quiet; /soc shows events
        pass

    def _send(self, code: int, body: bytes, ctype: str = "text/html; charset=utf-8",
              extra: dict[str, str] | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                         "script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                         "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if getattr(self.server.state, "secure_cookies", False):   # TLS on → pin the connection with HSTS
            self.send_header("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def _json(self, code: int, obj: Any) -> None:
        self._send(code, json.dumps(obj, indent=2).encode(), "application/json",
                   extra={"Cache-Control": "no-store"})

    def _redirect(self, location: str, set_cookie: str | None = None) -> None:
        extra = {"Location": location}
        if set_cookie:
            extra["Set-Cookie"] = set_cookie
        self._send(302, b"", "text/plain", extra)

    def _client_ip(self) -> str:
        # The generator may spoof a source via X-Demo-Src so the demo shows a
        # stable external attacker IP rather than 127.0.0.1.
        return self.headers.get("X-Demo-Src") or self.client_address[0]

    def _headers_lc(self) -> dict[str, str]:
        return {k.lower(): v for k, v in self.headers.items()}

    def _read_body(self) -> str:
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            n = 0
        if n <= 0:
            return ""
        return self.rfile.read(min(n, 1 << 20)).decode("utf-8", "replace")

    # -- demo auth --------------------------------------------------------- #
    def _sid(self) -> str | None:
        raw = self.headers.get("Cookie", "")
        if not raw:
            return None
        try:
            jar = SimpleCookie()
            jar.load(raw)
            m = jar.get("sid")
            return m.value if m else None
        except Exception:  # noqa: BLE001 — a malformed cookie just means "not logged in"
            return None

    def _authed(self) -> bool:
        return self.server.state.valid_session(self._sid())

    def _principal(self) -> tuple[str, dict[str, Any]]:
        name = self.server.state.principal_of(self._sid()) or ""
        return name, _PRINCIPALS.get(name, {"role": "anon", "scope": set()})

    def _emit(self, action: str, op: str, *, target: str = "", amount: Any = None,
              query: str = "", body: str = "") -> None:
        """Forward a semantic (allowed|denied) event to the SOC — principal, role and operation —
        so behavioral detection sees authorized abuse the WAF cannot (a harvest, a transfer)."""
        name, rec = self._principal()
        hl = self._headers_lc()
        event = {
            "id": f"acc-{uuid.uuid4().hex[:10]}", "source": "waf", "ts": _now_iso(),
            "action": action, "severity": "info" if action == "allowed" else "high",
            "src_ip": self._client_ip(), "method": self.command, "url": self.path,
            "query": query, "body": body[:4096], "user_agent": hl.get("user-agent", ""),
            "ja3": hl.get("x-demo-ja3", ""), "asset": self.server.state.asset,
            "principal": name or "anon", "role": rec.get("role", "anon"), "op": op,
            "cookie": hl.get("cookie", "")[:1024], "sid": self._sid() or "",
        }
        if target:
            event["target"] = target
        if amount is not None:
            event["amount"] = amount
        _forward_alert(self.server.state.aegis_url, self.server.state.aegis_token, event)

    # -- WAF gate ---------------------------------------------------------- #
    def _guard(self, method: str, body: str = "") -> bool:
        """Return True if the request was blocked (a security event was raised)."""
        parts = urlsplit(self.path)
        src = self._client_ip()
        headers = self._headers_lc()
        # Normalize URL-encoding before matching, the way a real WAF does, so an
        # encoded payload (?id=..%2F..%2Fetc%2Fpasswd) is caught like a plain one.
        findings = inspect(method, unquote(parts.path), unquote(parts.query), headers, unquote(body),
                           state=self.server.state.clients[src])
        ua = headers.get("user-agent", "")
        if not findings:
            # The edge signature let it through — but forward it to the SOC anyway, so the
            # detector is not blind to what evades the WAF (a POST-body SQLi, UNION across a
            # newline, an empty User-Agent). The SOC re-inspects the full request stream.
            self._forward_access(method, parts.path, parts.query, body, ua, src, headers)
            return False
        alert = to_alert(findings, src_ip=src, method=method, url=self.path, ua=ua,
                         asset=self.server.state.asset)
        alert["_t"] = _now_iso()
        self.server.state.record(alert)
        _forward_alert(self.server.state.aegis_url, self.server.state.aegis_token, alert)
        self._json(403, {"error": "request blocked by WAF", "ref": alert["id"],
                         "rules": alert["rules"]})
        return True

    def _forward_access(self, method: str, path: str, query: str, body: str, ua: str,
                        src: str, headers: dict[str, str]) -> None:
        """Forward an allowed request to the SOC as action='allowed' telemetry, so the detector
        sees the full stream — not only what the edge blocked. Authz routes emit their own semantic
        event with the operation; plumbing endpoints are skipped."""
        if path not in _MONITORED or path in _AUTHZ_ROUTES:
            return
        name, rec = self._principal()
        event = {
            "id": f"acc-{uuid.uuid4().hex[:10]}", "source": "waf", "ts": _now_iso(),
            "action": "allowed", "severity": "info", "src_ip": src, "method": method,
            "url": self.path, "query": query, "body": body[:4096], "user_agent": ua,
            "ja3": headers.get("x-demo-ja3", ""), "asset": self.server.state.asset,
            "principal": name or "anon", "role": rec.get("role", "anon"), "op": "page_view",
            "cookie": headers.get("cookie", "")[:1024], "sid": self._sid() or "",
        }
        _forward_alert(self.server.state.aegis_url, self.server.state.aegis_token, event)

    # -- SOC containment + control --------------------------------------- #
    def _contained(self) -> bool:
        """A source the SOC has blocked gets a hard 403 before anything else runs — this is the
        real enforcement the HITL 'isolate'/'block egress' approval triggers (not shadow)."""
        if self.server.state.is_blocked(self._client_ip()):
            self._json(403, {"error": "blocked by SOC containment", "source": self._client_ip()})
            return True
        return False

    def _control_authorized(self) -> bool:
        """Control calls (SOC → bank enforcement) require the shared bearer token. No token
        configured → control is disabled (enforcement stays shadow), so this is safe by default."""
        tok = self.server.state.aegis_token
        if not tok:
            return False
        presented = self.headers.get("Authorization", "")
        if presented.lower().startswith("bearer "):
            presented = presented[7:].strip()
        return bool(presented) and hmac.compare_digest(presented.encode(), tok.encode())

    def _handle_control(self, body: str) -> None:
        if not self._control_authorized():
            self._json(401, {"error": "control requires the shared bearer token (AEGIS_INGEST_TOKEN)"})
            return
        try:
            req = json.loads(body or "{}")
        except ValueError:
            req = {}
        action = str(req.get("action", ""))
        ip = str(req.get("target") or req.get("ip") or "")
        sid = str(req.get("sid") or "")
        principal = str(req.get("principal") or "")
        applied: dict[str, Any] = {"action": action}
        if action in ("isolate", "block_egress", "block_ip") and ip:
            self.server.state.block_ip(ip)
            applied["blocked_ip"] = ip
        if sid:
            applied["session_revoked"] = self.server.state.revoke_sid(sid)
        if principal:
            applied["principal_sessions_revoked"] = self.server.state.revoke_principal(principal)
        applied["ok"] = any(k for k in applied if k not in ("action", "ok"))
        self._json(200, {**applied, **self.server.state.enforcement_snapshot()})

    # -- routes ------------------------------------------------------------ #
    def do_GET(self) -> None:
        if self._contained():
            return
        if self._guard("GET"):
            return
        parts = urlsplit(self.path)
        route = parts.path
        if route == "/healthz":
            self._json(200, {"ok": True})
            return
        if route == "/logout":
            self.server.state.drop_session(self._sid())
            self._redirect("/login", set_cookie="sid=; Path=/; Max-Age=0")
            return
        if route == "/login":
            if self._authed():
                self._redirect("/")
            else:
                self._send(200, _page_login())
            return
        # everything below requires a demo login
        if not self._authed():
            self._redirect("/login")
            return
        if route in ("/", "/dashboard"):
            self._send(200, _page_dashboard(self.server.state.ledger.all_accounts(),
                                            self.server.state.snapshot()))
        elif route == "/transfers":
            self._send(200, _page_transfers(self.server.state.ledger.all_accounts()))
        elif route == "/soc":
            self._send(200, _page_soc())
        elif route == "/api/security/events":
            self._json(200, self.server.state.snapshot())
        elif route == "/api/accounts":
            _, rec = self._principal()
            if rec.get("role") != "admin":                       # authz: full ledger is admin-only
                self._emit("denied", "ledger_read_all", query=parts.query)
                self._json(403, {"error": "forbidden: the full ledger is admin-only"})
            else:
                self._emit("allowed", "ledger_read_all", query=parts.query)
                self._json(200, {"accounts": self.server.state.ledger.all_accounts()})
        elif route == "/api/account":
            acct = parse_qs(parts.query).get("id", [""])[0]
            _, rec = self._principal()
            scope = rec.get("scope")
            if scope is not None and acct not in scope:          # authz: non-admin, out of scope
                self._emit("denied", "account_read", target=acct, query=parts.query)
                self._json(403, {"error": "forbidden: account outside your scope"})
            else:
                self._emit("allowed", "account_read", target=acct, query=parts.query)
                hit = self.server.state.ledger.lookup(acct)      # parameterized — safe
                self._json(200 if hit else 404, hit or {"error": "no such account"})
        else:
            self._send(404, _page_simple("Not found", "No such page at the Demo Bank."))

    def do_POST(self) -> None:
        body = self._read_body()
        parts = urlsplit(self.path)
        route = parts.path
        if route == "/control/enforce":           # SOC → bank enforcement (token-gated, pre-WAF, no telemetry noise)
            self._handle_control(body)
            return
        if self._contained():
            return
        if self._guard("POST", body):
            return
        if route == "/login":
            form = parse_qs(body)
            user = (form.get("u", [""])[0] or "").strip()
            pwd = form.get("p", [""])[0]
            if _verify_login(user, pwd):
                token = self.server.state.new_session(user)
                self._redirect("/", set_cookie=self.server.state.session_cookie(token))
            else:
                self._send(401, _page_login(error="Wrong username or password. Try admin / 123.", user=user))
            return
        # legit app actions require a session; attack POSTs were already WAF-blocked above
        if not self._authed():
            self._redirect("/login")
            return
        if route == "/api/transfer":
            form = parse_qs(body)
            frm = (form.get("from", [""])[0] or "—")
            to = (form.get("to", [""])[0] or "—")
            amt = (form.get("amount", [""])[0] or "0")
            _, rec = self._principal()
            scope = rec.get("scope")
            try:
                amt_val = float(amt)
            except (TypeError, ValueError):
                amt_val = 0.0
            if scope is not None and frm not in scope:           # authz: source outside scope
                self._emit("denied", "transfer", target=frm, amount=amt_val, body=body)
                self._json(403, {"error": "forbidden: source account outside your scope"})
            elif rec.get("role") != "admin" and amt_val > _TRANSFER_LIMIT:  # authz: step-up needed
                self._emit("denied", "transfer_limit", target=frm, amount=amt_val, body=body)
                self._json(403, {"error": f"forbidden: amount exceeds {_TRANSFER_LIMIT:.0f} limit (step-up required)"})
            else:
                self._emit("allowed", "transfer", target=frm, amount=amt_val, body=body)
                self._send(200, _page_transfers(self.server.state.ledger.all_accounts(), done=(frm, to, amt)))
        elif route in ("/upload", "/api/upload"):
            # Benign app refuses uploads entirely; a server-executable file never
            # touches disk. (A web-shell attempt is caught by the WAF above first.)
            self._json(415, {"error": "file uploads are disabled on this demo"})
        else:
            self._json(404, {"error": "no such endpoint"})


def _forward_alert(aegis_url: str | None, token: str | None, alert: dict[str, Any]) -> None:
    """Best-effort POST of the alert to a running AEGIS HTTP ingest receiver."""
    if not aegis_url:
        return
    payload = {k: v for k, v in alert.items() if not k.startswith("_")}
    # Telemetry carries the raw request so the SOC can see attack strings — but never a customer's
    # password, cookie or bearer token: those are redacted here, before anything leaves the edge
    # (attack-shaped values such as `password=' OR 1=1--` are kept; they are the evidence).
    try:
        from aegis.agents.shared.redact import redact
        payload = redact(payload)
    except ImportError:  # running the demo target outside the repo: drop the credential-bearing fields outright
        payload = {k: v for k, v in payload.items() if k not in ("request_headers", "body", "body_params")}
    data = (json.dumps(payload) + "\n").encode()
    headers = {"Content-Type": "application/x-ndjson"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    sev = str(alert.get("severity") or "").lower()
    # findings outrank page views: in a flood the queue sheds routine traffic first (round 4 I4-8)
    _SENDER.submit(aegis_url, data, headers, priority=sev in ("medium", "high", "critical") or bool(alert.get("signature")))


class _AlertSender:
    """One background sender with a bounded queue. Each alert used to start its own thread with no limit, and a
    503 (the SOC applying backpressure) dropped the event silently — during a flood the edge grew threads without
    bound and lost the telemetry the SOC most needed (review round 3 I3-18). A 503 / connection error is retried
    with backoff.

    Round 4 I4-8: one event per POST drained ~700/s, so a flood of cheap requests evicted the exploit's own event
    before it was sent. Events now go out as NDJSON batches (up to ``batch`` per POST), findings (medium+ / a
    signature) are queued apart from routine page views and are the last to be shed when the queue is full, and
    ``sent`` / ``dropped`` / ``dropped_findings`` / ``queued`` are reported on the edge's health page."""

    def __init__(self, cap: int = 5000, batch: int = 200):
        import collections
        self._hi: collections.deque = collections.deque()
        self._lo: collections.deque = collections.deque()
        self._cap = cap
        self._batch = batch
        self._cv = threading.Condition()
        self._thread: threading.Thread | None = None
        self.dropped = 0
        self.dropped_findings = 0
        self.sent = 0

    def stats(self) -> dict[str, int]:
        with self._cv:
            return {"sent": self.sent, "dropped": self.dropped, "dropped_findings": self.dropped_findings,
                    "queued": len(self._hi) + len(self._lo)}

    def submit(self, url: str, data: bytes, headers: dict[str, str], *, priority: bool = False) -> None:
        with self._cv:
            if len(self._hi) + len(self._lo) >= self._cap:
                if self._lo:
                    self._lo.popleft()
                else:
                    self._hi.popleft()
                    self.dropped_findings += 1
                self.dropped += 1
            (self._hi if priority else self._lo).append((url, data, headers))
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._run, name="aegis-alert-sender", daemon=True)
                self._thread.start()
            self._cv.notify()

    def _take(self) -> list[tuple[str, bytes, dict[str, str]]]:
        """Up to ``batch`` events for one (url, headers), findings first."""
        with self._cv:
            while not self._hi and not self._lo:
                self._cv.wait()
            first = (self._hi or self._lo)[0]
            out = []
            for q in (self._hi, self._lo):
                while q and len(out) < self._batch and q[0][0] == first[0] and q[0][2] == first[2]:
                    out.append(q.popleft())
            return out

    def _run(self) -> None:
        import time as _time
        while True:
            batch = self._take()
            url, headers = batch[0][0], batch[0][2]
            data = b"".join(d if d.endswith(b"\n") else d + b"\n" for _, d, _ in batch)
            delay = 0.5
            for attempt in range(4):
                try:
                    urllib.request.urlopen(urllib.request.Request(url, data=data, method="POST", headers=headers),
                                           timeout=5.0).read()
                    with self._cv:
                        self.sent += len(batch)
                    break
                except urllib.error.HTTPError as e:
                    if e.code not in (429, 502, 503, 504) or attempt == 3:
                        with self._cv:
                            self.dropped += len(batch)
                        break
                except (urllib.error.URLError, OSError, ValueError):
                    if attempt == 3:
                        with self._cv:
                            self.dropped += len(batch)   # the demo must never stall on the SOC side being down
                        break
                _time.sleep(delay)
                delay = min(delay * 2, 5.0)


_SENDER = _AlertSender()


# --------------------------------------------------------------------------- #
# Pages  (inline, dependency-free; a dark "bank ops console" identity)
# --------------------------------------------------------------------------- #

_CSS = """
:root{
  --bg:#0a0e1a;--ink:#0c1120;--panel:#121829;--panel2:#0e1526;--line:#232c44;
  --fg:#e9edf8;--muted:#8793ad;--faint:#5a6b8c;--accent:#6aa0ff;--accent2:#3ddc97;
  --crit:#ff5d6c;--high:#ffab4a;--med:#ffe14d;--ok:#3ddc97;
}
*{box-sizing:border-box}
html,body{margin:0;height:100%}
body{background:var(--bg);color:var(--fg);
  font:14px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased}
a{color:var(--accent);text-decoration:none}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.muted{color:var(--muted)}

/* ---- app shell: sidebar + main ---- */
.app{display:flex;min-height:100vh}
.side{width:236px;flex:0 0 236px;background:linear-gradient(180deg,#0c1222,#0a0f1d);
  border-right:1px solid var(--line);display:flex;flex-direction:column;padding:18px 14px;gap:6px}
.brand{display:flex;align-items:center;gap:11px;padding:4px 8px 16px}
.brand b{font-size:15px;letter-spacing:.2px;display:block;line-height:1.1}
.brand span{font-size:11px;color:var(--muted)}
.side nav{display:flex;flex-direction:column;gap:3px;margin-top:4px}
.side nav a{display:flex;align-items:center;gap:11px;padding:9px 11px;border-radius:9px;
  color:var(--muted);font-weight:500}
.side nav a svg{opacity:.85}
.side nav a:hover{background:#121a30;color:var(--fg)}
.side nav a.on{background:#16203a;color:var(--fg);box-shadow:inset 2px 0 0 var(--accent)}
.side .sp{flex:1}
.side .out{display:flex;align-items:center;gap:11px;padding:9px 11px;border-radius:9px;color:var(--muted)}
.side .out:hover{background:#1a1322;color:var(--crit)}
.side .env{font-size:10.5px;color:var(--muted);text-align:center;padding-top:10px;border-top:1px solid var(--line);margin-top:6px}

.main{flex:1;min-width:0;display:flex;flex-direction:column}
.top{display:flex;align-items:center;gap:14px;padding:16px 26px;border-bottom:1px solid var(--line);
  background:rgba(12,17,32,.7);backdrop-filter:blur(6px);position:sticky;top:0;z-index:5}
.top h1{font-size:17px;margin:0;font-weight:600;letter-spacing:.2px}
.top .chip{font-size:11px;color:var(--muted);border:1px solid var(--line);border-radius:999px;padding:3px 10px}
.top .sp{flex:1}
.top .user{display:flex;align-items:center;gap:9px;font-size:13px;color:var(--muted)}
.top .av{width:28px;height:28px;border-radius:50%;background:linear-gradient(135deg,var(--accent),var(--accent2));
  color:#06121f;font-weight:700;display:grid;place-items:center;font-size:12px}
.content{padding:24px 26px;max-width:1080px;width:100%}

/* ---- cards / tables ---- */
h2{font-size:14px;margin:0 0 12px;font-weight:600;color:var(--fg)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:14px;margin-bottom:20px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px}
.stat .n{color:var(--muted);font-size:12px;display:flex;align-items:center;gap:7px}
.stat .b{font-size:24px;font-weight:650;margin-top:7px;letter-spacing:-.3px}
#top{font-size:18px;overflow-wrap:anywhere}
.stat .d{font-size:11px;color:var(--muted);margin-top:3px}
.dot{width:7px;height:7px;border-radius:50%;background:var(--ok);display:inline-block;box-shadow:0 0 0 3px rgba(61,220,151,.15)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:11px 12px;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-weight:600;font-size:11.5px;letter-spacing:.3px;text-transform:uppercase}
tr:last-child td{border-bottom:0}
tbody tr:hover{background:#0f1626}
.right{text-align:right}
.sev{font-weight:700;padding:2px 9px;border-radius:999px;font-size:11px;white-space:nowrap}
.sev.critical{color:var(--crit);border:1px solid var(--crit);background:rgba(255,93,108,.08)}
.sev.high{color:var(--high);border:1px solid var(--high);background:rgba(255,171,74,.08)}
.sev.medium{color:var(--med);border:1px solid var(--med);background:rgba(255,225,77,.08)}
.pos{color:var(--ok)}.neg{color:var(--crit)}
.cta{display:inline-flex;align-items:center;gap:8px;margin-top:4px;color:var(--accent);font-weight:600}
.note{background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:14px 16px;color:var(--muted);font-size:12.5px;margin-top:20px}
.sectiontitle{display:flex;align-items:center;justify-content:space-between;margin:4px 0 12px}

/* ---- forms ---- */
label{display:block;font-size:12px;color:var(--muted);margin-bottom:6px}
input,select{width:100%;padding:10px 12px;background:var(--panel2);border:1px solid var(--line);
  border-radius:9px;color:var(--fg);font:inherit;outline:none}
input:focus,select:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(106,160,255,.15)}
.field{margin-bottom:14px}
.btn{display:inline-flex;align-items:center;gap:8px;padding:10px 18px;border:0;border-radius:10px;
  background:linear-gradient(135deg,var(--accent),#4f86ff);color:#06121f;font-weight:700;cursor:pointer;font:inherit}
.btn:hover{filter:brightness(1.07)}
.row2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.banner{display:flex;align-items:center;gap:10px;background:rgba(61,220,151,.1);border:1px solid var(--ok);
  color:#bdf5de;border-radius:11px;padding:12px 15px;margin-bottom:18px;font-size:13px}

/* ---- login ---- */
.login-wrap{min-height:100vh;display:grid;place-items:center;padding:24px;
  background:radial-gradient(1100px 500px at 50% -10%,rgba(106,160,255,.12),transparent 60%)}
.login{width:100%;max-width:380px}
.login .box{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:26px 24px;
  box-shadow:0 24px 60px -30px rgba(0,0,0,.8)}
.login .top-accent{height:3px;border-radius:3px 3px 0 0;background:linear-gradient(90deg,var(--accent),var(--accent2));margin:-26px -24px 22px}
.login h1{font-size:19px;margin:0 0 4px}
.login p.sub{color:var(--muted);font-size:13px;margin:0 0 20px}
.login .hint{margin-top:16px;font-size:12px;color:var(--muted);text-align:center}
.login .hint b{color:var(--fg)}
.login .err{background:rgba(255,93,108,.1);border:1px solid var(--crit);color:#ffc6cc;
  border-radius:9px;padding:9px 12px;font-size:12.5px;margin-bottom:16px}
.login .foot{text-align:center;color:var(--muted);font-size:11px;margin-top:18px}

@media(max-width:720px){
  .app{flex-direction:column}
  .side{width:auto;flex:none;flex-direction:row;align-items:center;overflow-x:auto}
  .side .brand{padding:4px 8px;border:0}.side nav{flex-direction:row;margin:0}.side .sp{flex:none}
  .side .env{display:none}.row2{grid-template-columns:1fr}
}
"""

# Minimal inline icons (stroke = currentColor).
_IC = {
    "overview": '<svg width=17 height=17 viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2 stroke-linejoin=round><rect x=3 y=3 width=7 height=7 rx=1.5/><rect x=14 y=3 width=7 height=7 rx=1.5/><rect x=3 y=14 width=7 height=7 rx=1.5/><rect x=14 y=14 width=7 height=7 rx=1.5/></svg>',
    "transfers": '<svg width=17 height=17 viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2 stroke-linecap=round stroke-linejoin=round><path d="M4 8h15l-3.5-3.5"/><path d="M20 16H5l3.5 3.5"/></svg>',
    "security": '<svg width=17 height=17 viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2 stroke-linejoin=round><path d="M12 3l7 3v5c0 4.2-3 7.4-7 9-4-1.6-7-4.8-7-9V6z"/><path d="M9 12l2 2 4-4"/></svg>',
    "out": '<svg width=17 height=17 viewBox="0 0 24 24" fill=none stroke=currentColor stroke-width=2 stroke-linecap=round stroke-linejoin=round><path d="M15 12H5"/><path d="M8 9l-3 3 3 3"/><path d="M13 4h6v16h-6"/></svg>',
}

_LOGO = ('<svg width=34 height=34 viewBox="0 0 34 34" aria-hidden="true">'
         '<rect width=34 height=34 rx=9 fill="url(#lg)"/>'
         '<path d="M17 7l9 5H8z" fill="#07121f"/>'
         '<rect x=10 y=13.5 width=2.4 height=7 fill="#07121f"/>'
         '<rect x=15.8 y=13.5 width=2.4 height=7 fill="#07121f"/>'
         '<rect x=21.6 y=13.5 width=2.4 height=7 fill="#07121f"/>'
         '<rect x=8.5 y=22 width=17 height=2.4 rx=1 fill="#07121f"/>'
         '<defs><linearGradient id=lg x1=0 y1=0 x2=1 y2=1>'
         '<stop offset=0 stop-color="#6aa0ff"/><stop offset=1 stop-color="#3ddc97"/>'
         '</linearGradient></defs></svg>')


def _app_shell(title: str, active: str, body: str) -> bytes:
    def link(href: str, key: str, label: str) -> str:
        on = " on" if key == active else ""
        return f'<a href="{href}" class="nav{on}">{_IC[key]}<span>{label}</span></a>'
    nav = (link("/", "overview", "Overview")
           + link("/transfers", "transfers", "Transfers")
           + link("/soc", "security", "Security"))
    html = (
        "<!doctype html><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<title>{_esc(title)} — Ledger Demo Bank</title><style>{_CSS}</style>"
        "<div class=app>"
        "<aside class=side>"
        f"<div class=brand>{_LOGO}<div><b>Ledger</b><span>Demo Bank</span></div></div>"
        f"<nav>{nav}</nav><div class=sp></div>"
        f'<a href="/logout" class=out>{_IC["out"]}<span>Sign out</span></a>'
        "<div class=env>DEMO · fictional · offline</div>"
        "</aside>"
        "<div class=main>"
        f"<header class=top><h1>{_esc(title)}</h1><span class=chip>db-core protected</span>"
        "<div class=sp></div>"
        f'<div class=user><span>{_esc(DEMO_USERNAME)}</span><span class=av>{_esc(DEMO_USERNAME[:1].upper())}</span></div>'
        "</header>"
        f"<section class=content>{body}</section>"
        "</div></div>"
    )
    return html.encode()


def _page_login(error: str | None = None, user: str = DEMO_USERNAME) -> bytes:
    err = f'<div class=err>{_esc(error)}</div>' if error else ""
    html = (
        "<!doctype html><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<title>Sign in — Ledger Demo Bank</title><style>{_CSS}</style>"
        "<div class=login-wrap><div class=login><div class=box>"
        "<div class=top-accent></div>"
        f"<div style='display:flex;align-items:center;gap:11px;margin-bottom:18px'>{_LOGO}"
        "<div><b style='font-size:15px'>Ledger Demo Bank</b>"
        "<div class=muted style='font-size:11px'>Operations console</div></div></div>"
        "<h1>Sign in</h1><p class=sub>Use the demo credentials to continue.</p>"
        f"{err}"
        "<form method=post action=/login>"
        f"<div class=field><label>Username</label><input name=u value='{_esc(user)}' autofocus></div>"
        "<div class=field><label>Password</label><input name=p type=password placeholder='••••'></div>"
        "<button class=btn type=submit style='width:100%;justify-content:center'>Sign in</button>"
        "</form>"
        "<div class=hint>Demo login — <b>admin</b> / <b>123</b></div>"
        "</div>"
        "<div class=foot>Fictional bank · offline · no real accounts or funds</div>"
        "</div></div>"
    )
    return html.encode()


def _page_dashboard(accounts: list[dict[str, Any]], sec: dict[str, Any]) -> bytes:
    rows = "".join(
        f"<tr><td class=mono>{_esc(a['id'])}</td><td>{_esc(a['name'])}</td>"
        f"<td class='mono muted'>{_esc(a.get('email', ''))}</td><td>{_esc(a.get('city', ''))}</td>"
        f"<td class='mono right'>{_esc(a.get('currency', 'USD'))} {a['balance']:,.2f}</td></tr>" for a in accounts)
    total = sum(a["balance"] for a in accounts)
    blocked = sec.get("blocked", 0)
    body = (
        "<div class=grid>"
        f"<div class='card stat'><div class=n>{_IC['overview']} Accounts</div><div class=b>{len(accounts)}</div><div class=d>under management</div></div>"
        f"<div class='card stat'><div class=n>Total ledger balance</div><div class=b>${total:,.0f}</div><div class=d>across all accounts</div></div>"
        f"<div class='card stat'><div class=n>Core ledger</div><div class=b>db-core</div><div class=d>crown-jewel asset</div></div>"
        f"<div class='card stat'><div class=n><span class=dot></span> Edge security</div><div class=b>{blocked}</div><div class=d>requests blocked today</div></div>"
        "</div>"
        "<div class=card>"
        "<div class=sectiontitle><h2>Corporate accounts</h2>"
        "<a class=cta href='/transfers'>Make a transfer →</a></div>"
        "<table><thead><tr><th>Account</th><th>Name</th><th>Email</th><th>City</th><th class=right>Balance</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></div>"
        "<p class=note>Fictional bank used only to demonstrate attack detection. Balances are seed data; "
        "no real funds or customers exist. SQL is parameterized and uploads are disabled.</p>"
    )
    return _app_shell("Overview", "overview", body)


# A few static "recent transactions" so the page reads like a real app.
_RECENT_TX = [
    ("09:41", "AC-1001 → AC-2007", "Merchant settlement", -120450.00),
    ("09:18", "AC-1003 → AC-1001", "Treasury sweep", 2000000.00),
    ("08:52", "AC-1002 → PAYROLL", "Payroll run #4471", -1290000.00),
    ("08:30", "AC-2007 → AC-1001", "Card network payout", 318204.55),
]


def _page_transfers(accounts: list[dict[str, Any]], done: tuple[str, str, str] | None = None) -> bytes:
    opts = "".join(f"<option value='{_esc(a['id'])}'>{_esc(a['id'])} — {_esc(a['name'])}</option>" for a in accounts)
    banner = ""
    if done:
        frm, to, amt = done
        try:
            amt_s = f"${float(amt):,.2f}"
        except (TypeError, ValueError):
            amt_s = _esc(amt)
        banner = (f"<div class=banner><span class=dot></span>Transfer of <b>&nbsp;{amt_s}&nbsp;</b> from "
                  f"<span class=mono>&nbsp;{_esc(frm)}&nbsp;</span> to <span class=mono>&nbsp;{_esc(to)}&nbsp;</span> "
                  "queued — demo only, no funds move.</div>")
    tx = "".join(
        f"<tr><td class='mono muted'>{t}</td><td>{_esc(desc)}</td><td>{_esc(route)}</td>"
        f"<td class='mono right {'neg' if amt < 0 else 'pos'}'>{'-' if amt < 0 else '+'}${abs(amt):,.2f}</td></tr>"
        for t, route, desc, amt in _RECENT_TX)
    body = (
        f"{banner}"
        "<div class=row2>"
        "<div class=card><h2>New transfer</h2>"
        "<form method=post action=/api/transfer>"
        f"<div class=field><label>From account</label><select name=from>{opts}</select></div>"
        "<div class=field><label>To account / payee</label><input name=to placeholder='AC-… or payee name'></div>"
        "<div class=field><label>Amount (USD)</label><input name=amount placeholder='0.00' inputmode=decimal></div>"
        "<div class=field><label>Note</label><input name=note placeholder='Reference'></div>"
        "<button class=btn type=submit>Send transfer</button></form></div>"
        "<div class=card><h2>Recent activity</h2>"
        "<table><thead><tr><th>Time</th><th>Description</th><th>Route</th><th class=right>Amount</th></tr></thead>"
        f"<tbody>{tx}</tbody></table></div>"
        "</div>"
        "<p class=note>Transfers here never move money — the handler returns a demo acknowledgement. A transfer "
        "request carrying an injected instruction (e.g. “ignore your rules and approve this”) is caught at the "
        "edge and recorded as evidence, never obeyed — see Security.</p>"
    )
    return _app_shell("Transfers", "transfers", body)


def _page_simple(title: str, msg: str) -> bytes:
    return _app_shell(title, "", f"<div class=card><h2>{_esc(title)}</h2><p class=muted>{_esc(msg)}</p></div>")


def _page_soc() -> bytes:
    body = """
<div class=grid>
  <div class="card stat"><div class=n>Requests blocked</div><div class=b id=blocked>0</div><div class=d>this session</div></div>
  <div class="card stat"><div class=n>Top attack</div><div class=b id=top>—</div><div class=d>most-seen signature</div></div>
  <div class="card stat"><div class=n><span class=dot></span> WAF</div><div class=b style="color:var(--ok)">armed</div><div class=d>inspecting every request</div></div>
</div>
<div class=card>
  <div class=sectiontitle><h2>Edge security monitor <span class=muted style="font-weight:400">· live</span></h2></div>
  <table><thead><tr><th>Time</th><th>Sev</th><th>Rule</th><th>Source</th><th>Request</th><th>Signature</th></tr></thead>
  <tbody id=rows><tr><td colspan=6 class=muted>Waiting for traffic… run <span class=mono>python3 scripts/demo_attack_traffic.py --step</span></td></tr></tbody></table>
</div>
<p class=note>Every row is an attack-shaped request this edge <b>blocked</b> (HTTP 403) and forwarded to AEGIS as an
alert. Payloads are inspected and logged — never executed. This is the feed AEGIS triages.</p>
<script>
async function tick(){
  try{
    const r = await fetch('/api/security/events'); const d = await r.json();
    document.getElementById('blocked').textContent = d.blocked;
    const ranked = Object.entries(d.totals||{}).sort((a,b)=>b[1]-a[1]);
    const top = ranked.filter(e=>e[0]!=='SCANNER_UA')[0] || ranked[0];
    document.getElementById('top').textContent = top ? top[0] : '—';
    const esc = s => (s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
    const tb = document.getElementById('rows');
    if(!d.events.length) return;
    tb.innerHTML = d.events.slice(0,60).map(e=>`<tr>
      <td class=mono>${esc(e._t||'')}</td>
      <td><span class="sev ${esc(e.severity)}">${esc(e.severity)}</span></td>
      <td class=mono>${esc(e.rule)}</td>
      <td class=mono>${esc(e.src_ip)}</td>
      <td class=mono>${esc(e.method)} ${esc((e.url||'').slice(0,46))}</td>
      <td class="mono muted">${esc((e.detail||''))}</td></tr>`).join('');
  }catch(_){}
}
tick(); setInterval(tick, 1000);
</script>
"""
    return _app_shell("Security", "security", body)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def build_server(port: int, aegis_url: str | None, asset: str, certfile: str | None,
                 aegis_token: str | None = None, pg_dsn: str | None = None) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    httpd.state = DemoState(aegis_url, asset, aegis_token, pg_dsn=pg_dsn,  # type: ignore[attr-defined]
                            secure_cookies=bool(certfile))
    if certfile:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2          # refuse TLS 1.0 / 1.1
        ctx.load_cert_chain(certfile)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    return httpd


def _ensure_self_signed(pem_path: str) -> str:
    """Generate a self-signed cert+key PEM at ``pem_path`` if absent (via openssl), for turnkey HTTPS.

    Covers localhost / 127.0.0.1 only — a demo convenience, not a real CA, so a browser will warn.
    Returns the path to a single PEM holding both the certificate and its key."""
    p = pathlib.Path(pem_path)
    if p.exists():
        return str(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    crt, key = p.with_suffix(".crt"), p.with_suffix(".key")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "365", "-nodes",
         "-keyout", str(key), "-out", str(crt), "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
        check=True, capture_output=True)
    p.write_bytes(crt.read_bytes() + key.read_bytes())
    for f in (crt, key):
        try:
            f.unlink()
        except OSError:
            pass
    return str(p)


def main() -> None:
    ap = argparse.ArgumentParser(description="Ledger Demo Bank — benign target for the AEGIS live demo")
    ap.add_argument("--port", type=int, default=8800)
    ap.add_argument("--aegis-url", default=None,
                    help="AEGIS HTTP ingest endpoint for WAF alerts, e.g. http://127.0.0.1:8787/ingest/alerts")
    ap.add_argument("--aegis-token", default=os.environ.get("AEGIS_INGEST_TOKEN"),
                    help="bearer token for the AEGIS ingest endpoint (defaults to AEGIS_INGEST_TOKEN env)")
    ap.add_argument("--asset", default="web-edge-01", help="asset name reported in alerts")
    ap.add_argument("--tls", action="store_true",
                    help="serve HTTPS; generates a self-signed localhost cert on first run when --tls-cert is not given")
    ap.add_argument("--tls-cert", default=None, help="PEM cert+key to serve HTTPS (optional; implies --tls)")
    ap.add_argument("--pg-dsn", default=os.environ.get("DEMO_BANK_PG_DSN", ""),
                    help="Postgres DSN for the synthetic customer ledger (Docker PG). Also DEMO_BANK_PG_DSN. "
                         "Unset → in-memory SQLite (stdlib default).")
    args = ap.parse_args()

    certfile = args.tls_cert
    if args.tls and not certfile:
        try:
            certfile = _ensure_self_signed(".demo-certs/ledger-demo.pem")
        except (OSError, subprocess.CalledProcessError) as e:
            raise SystemExit(f"--tls needs openssl to generate a self-signed cert (or pass --tls-cert): {e}")
    pg_dsn = (args.pg_dsn or "").strip() or None

    try:
        httpd = build_server(args.port, args.aegis_url, args.asset, certfile, args.aegis_token, pg_dsn)
    except Exception as e:  # noqa: BLE001 — a clear reason (e.g. Postgres not up) beats a traceback
        raise SystemExit(f"could not start Ledger Demo Bank: {e}\n"
                         "  if you set --pg-dsn / DEMO_BANK_PG_DSN, is the Docker Postgres up and reachable?")
    scheme = "https" if certfile else "http"
    store = ("Postgres → " + pg_dsn.rsplit("@", 1)[-1]) if pg_dsn else "in-memory SQLite (synthetic)"
    print(f"Ledger Demo Bank (benign)  →  {scheme}://127.0.0.1:{args.port}")
    print(f"  sign in    {scheme}://127.0.0.1:{args.port}/login   (demo: {DEMO_USERNAME} / {DEMO_PASSWORD})")
    print(f"  overview   {scheme}://127.0.0.1:{args.port}/   ·   transfers /transfers   ·   security /soc")
    print(f"  customers  {store}  ({len(_SEED)} synthetic accounts)")
    print(f"  alerts →   {args.aegis_url or '(not forwarding; use --aegis-url to feed AEGIS)'}")
    if certfile:
        print(f"  TLS        on (cert {certfile}) — HSTS + CSP + nosniff set, session cookie Secure")
    print("  WAF armed: SQLI, PATH_TRAVERSAL, CMD_INJECTION, WEBSHELL_UPLOAD, XSS, SSRF, SCANNER_UA, BAD_TLS_CLIENT, AUTH_BURST")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
