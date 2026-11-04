"""Tools for the API Abuse specialist."""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..shared.tool_guard import isolated


@dataclass
class ToolResult:
    name: str
    data: dict
    weight: str


# ---- BOLA / IDOR pattern check ----------------------------------------

def bola_pattern_check(principal_id: str | None, accessed_object_owner: str | None,
                       endpoint: str | None, http_method: str | None) -> ToolResult:
    """Compares the authenticated principal against the object's owner.

    Production: pulls owner from the data model's authorization layer
    (Spring Security ACL, Casbin, custom). Walking-skeleton: caller
    provides accessed_object_owner if known.
    """
    if not principal_id or not accessed_object_owner:
        return ToolResult(name="bola_pattern", data={
            "principal": principal_id, "owner": accessed_object_owner,
            "verdict": "insufficient_data",
        }, weight="low")

    is_self_access = principal_id == accessed_object_owner
    # Match the URL path style: /api/users/{id}/something
    is_id_in_path = bool(re.search(r"/(users?|accounts?|customers?)/[\w\-]+", endpoint or ""))
    is_modifying = http_method in ("POST", "PUT", "PATCH", "DELETE")

    if not is_self_access and is_id_in_path:
        weight = "high" if is_modifying else "medium"
        return ToolResult(name="bola_pattern", data={
            "principal": principal_id, "owner": accessed_object_owner,
            "endpoint": endpoint, "method": http_method,
            "is_self_access": False, "is_modifying": is_modifying,
            "is_bola_pattern": True,
        }, weight=weight)
    return ToolResult(name="bola_pattern", data={
        "is_self_access": is_self_access, "is_bola_pattern": False,
    }, weight="low")


# ---- Schema drift -----------------------------------------------------

# Mock schema registry. Production: pulled from OpenAPI / GraphQL
# introspection / schema registry (Confluent Schema Registry).
_KNOWN_SCHEMAS = {
    "/api/transfer": {
        "required": {"from_account", "to_account", "amount"},
        "allowed":  {"from_account", "to_account", "amount", "currency", "memo", "idempotency_key"},
    },
    "/api/profile": {
        "required": {"user_id"},
        "allowed":  {"user_id"},
    },
    "/api/login": {
        "required": {"username", "password"},
        "allowed":  {"username", "password", "mfa_token", "device_id"},
    },
}


def schema_drift_check(endpoint: str | None, params: dict | None) -> ToolResult:
    if not endpoint or endpoint not in _KNOWN_SCHEMAS:
        return ToolResult(name="schema_drift", data={
            "endpoint": endpoint, "tracked": False,
        }, weight="low")
    schema = _KNOWN_SCHEMAS[endpoint]
    seen = set((params or {}).keys())
    missing = schema["required"] - seen
    extra = seen - schema["allowed"]
    weight = "high" if extra else "medium" if missing else "low"
    return ToolResult(name="schema_drift", data={
        "endpoint": endpoint, "tracked": True,
        "missing_required": sorted(missing),
        "extra_unexpected": sorted(extra),
        "drift": bool(missing or extra),
    }, weight=weight)


# ---- Volumetric anomaly ----------------------------------------------

# Mock per-endpoint volume baselines (calls per minute, p99).
_VOLUMETRIC_BASELINES = {
    "/api/login":       {"p99_per_min": 30,  "kind": "auth"},
    "/api/transfer":    {"p99_per_min": 5,   "kind": "txn"},
    "/api/profile":     {"p99_per_min": 60,  "kind": "read"},
    "/api/statements":  {"p99_per_min": 20,  "kind": "read"},
}


def volumetric_anomaly_check(endpoint: str | None,
                             observed_per_min: float | None) -> ToolResult:
    if not endpoint or observed_per_min is None or endpoint not in _VOLUMETRIC_BASELINES:
        return ToolResult(name="volumetric", data={
            "endpoint": endpoint, "observed": observed_per_min,
            "verdict": "insufficient_data",
        }, weight="low")
    baseline = _VOLUMETRIC_BASELINES[endpoint]["p99_per_min"]
    ratio = observed_per_min / baseline if baseline > 0 else 0.0
    # >5x p99 = scraping / brute-force / DoS
    if ratio >= 5.0:
        weight = "high"
    elif ratio >= 2.0:
        weight = "medium"
    else:
        weight = "low"
    return ToolResult(name="volumetric", data={
        "endpoint": endpoint, "observed_per_min": observed_per_min,
        "p99_baseline": baseline, "ratio": round(ratio, 2),
        "anomaly": ratio >= 2.0,
    }, weight=weight)


# ---- Auth boundary check (privilege levels) -------------------------

# Mock role -> allowed-endpoint map. Production: pulled from IAM/RBAC.
_ROLE_PERMISSIONS = {
    "retail_customer": {"/api/balance", "/api/transfer", "/api/profile",
                        "/api/statements", "/api/login"},
    "wealth_advisor":  {"/api/portfolio", "/api/orders", "/api/clients",
                        "/api/profile", "/api/login"},
    "admin":           {"/api/admin/*", "/api/audit/*"},
}


def auth_boundary_check(role: str | None, endpoint: str | None) -> ToolResult:
    if not role or not endpoint:
        return ToolResult(name="auth_boundary", data={
            "role": role, "endpoint": endpoint, "verdict": "insufficient_data",
        }, weight="low")
    allowed = _ROLE_PERMISSIONS.get(role, set())
    # Wildcard match (e.g. /api/admin/* covers /api/admin/users)
    in_allowed = endpoint in allowed
    if not in_allowed:
        for entry in allowed:
            if entry.endswith("/*") and endpoint.startswith(entry[:-2]):
                in_allowed = True
                break
    return ToolResult(name="auth_boundary", data={
        "role": role, "endpoint": endpoint, "allowed": in_allowed,
        "violation": not in_allowed,
    }, weight="high" if not in_allowed else "low")


# ---- DB-direct query check ------------------------------------------

# Database queries that bypass the API layer (DBA tooling, ad-hoc
# psql / mysql / SSMS connections to prod). Different signal class
# from API abuse — these are AUTHENTICATED via DB creds, not the
# application's auth layer.

_MAX_QUERY_SCAN = 16_384            # per statement, after comments are stripped and whitespace collapsed
_MAX_QUERY_INPUT = 1 << 18          # the whole logged text that is tokenised (linear)
_MAX_STATEMENTS = 4096

_RISKY_QUERY_PATTERNS = [
    re.compile(r"\bselect\s+\*\s+from\s+(?:customers?|customer_kyc|loan_applications)\b", re.I),
    re.compile(r"\binto\s+outfile\b", re.I),
    re.compile(r"\bdumpfile\b", re.I),
    # postgres COPY … TO (query or table form, psql \copy too), judged per statement: one anchor, no nested
    # quantifier (round 7 D-8 ReDoS; round 8 D8-9 wide select lists and `COPY customer_kyc TO`)
    re.compile(r"^\\?copy\b.*\bto\b", re.IGNORECASE | re.DOTALL),
    re.compile(r"\bbcp\b", re.I),                          # MSSQL bulk copy
    re.compile(r"\bdrop\s+table\b", re.I),
    re.compile(r"\btruncate\s+table\b", re.I),
    re.compile(r"\bgrant\s+all\s+privileges\b", re.I),
]


_SQL_TOK = re.compile(r"""'[^']*(?:''[^']*)*'?|"[^"]*(?:""[^"]*)*"?|`[^`]*`?"""     # quoted: kept verbatim
                      r"|(?P<c>/\*.*?(?:\*/|\Z)|--[^\n]*)"                         # comment
                      r"|(?P<s>;)"                                               # statement break
                      r"|[^'\"`/;-]+|[/-]", re.DOTALL)


def _sql_statements(query: str) -> list[str]:
    """A logged SQL text → its statements, split on ``;`` outside quotes and whitespace collapsed, each bounded on
    its own. Every statement is returned twice: with comments (``/* */``, ``--``) removed — a 16 KB comment or a
    run of ``SELECT 1;`` can no longer push the real statement past the scan bound — and as written, since
    dialects disagree on what a comment is (MySQL's ``1--1`` is arithmetic). Linear in the (capped) input;
    identical statements collapse (round 8 D8-9)."""
    q = str(query)[:_MAX_QUERY_INPUT]
    out: list[str] = []
    seen: set[str] = set()
    cur: list[str] = []
    raw: list[str] = []

    def flush() -> None:
        for buf in (cur, raw):
            st = " ".join("".join(buf).split())[:_MAX_QUERY_SCAN]
            buf.clear()
            if st and st not in seen and len(out) < _MAX_STATEMENTS:
                seen.add(st)
                out.append(st)
    for m in _SQL_TOK.finditer(q):
        if m.group("s"):
            flush()
        elif m.group("c") is not None:
            cur.append(" ")
            raw.append(m.group(0))
        else:
            cur.append(m.group(0))
            raw.append(m.group(0))
    flush()
    return out


def _is_app_host(ip: str | None) -> bool:
    import ipaddress
    import os
    try:
        addr = ipaddress.ip_address(str(ip or "").strip())
    except ValueError:
        return False
    for tok in os.environ.get("AEGIS_DB_APP_HOSTS", "").replace(";", ",").split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            if addr in ipaddress.ip_network(tok, strict=False):
                return True
        except ValueError:
            continue
    return False


def db_direct_query_check(client_app: str | None,
                          query: str | None,
                          rows_returned: int | None,
                          source_ip: str | None) -> ToolResult:
    """Detects ad-hoc DB queries from non-application clients (psql,
    mysql CLI, DBeaver, SSMS, pgAdmin) — DBAs/data-scientists going
    direct without the application's audit + authorization layer.
    """
    if not query:
        return ToolResult(name="db_direct_query", data={"verdict": "no_query"}, weight="low")
    # `application_name` is whatever the CLIENT sends: `psql "application_name=app:ledger"` claimed to be the
    # application and got the milder weight (review round 3 G7-13). A claimed app name counts only from an
    # address listed as an application host (AEGIS_DB_APP_HOSTS: IPs / CIDRs).
    claims_app = bool(client_app and client_app.startswith(("app:", "service:")))
    is_app_client = claims_app and _is_app_host(source_ip)
    is_dba_client = bool(client_app and any(
        c in (client_app or "").lower()
        for c in ("psql", "mysql cli", "dbeaver", "ssms", "pgadmin", "mongo shell")
    ))
    # a logged statement is attacker-sized: each statement (comments stripped) is bounded on its own, not the
    # head of the whole text (round 7 D-8, round 8 D8-9)
    stmts = _sql_statements(str(query))
    risky_pattern_hits = [str(rx.pattern) for rx in _RISKY_QUERY_PATTERNS if any(rx.search(st) for st in stmts)]
    bulk = bool(rows_returned and rows_returned >= 5000)
    if is_dba_client and (risky_pattern_hits or bulk):
        weight = "high"
    elif risky_pattern_hits:
        weight = "high" if not is_app_client else "medium"
    elif is_dba_client and bulk:
        weight = "medium"
    elif is_dba_client:
        weight = "low"
    else:
        weight = "low"
    return ToolResult(name="db_direct_query", data={
        "client_app": client_app,
        "is_app_client": is_app_client,
        "app_name_unverified": claims_app and not is_app_client,
        "is_dba_client": is_dba_client,
        "risky_patterns": risky_pattern_hits,
        "rows_returned": rows_returned,
        "bulk": bulk,
        "source_ip": source_ip,
    }, weight=weight)


def run_all_tools(alert: dict) -> list[ToolResult]:
    return [
        isolated(lambda: bola_pattern_check(
            alert.get("principal_id"),
            alert.get("accessed_object_owner"),
            alert.get("endpoint"),
            alert.get("http_method"),
        ), "bola_pattern_check", ToolResult),
        isolated(lambda: schema_drift_check(alert.get("endpoint"), alert.get("params")), "schema_drift_check", ToolResult),
        isolated(lambda: volumetric_anomaly_check(alert.get("endpoint"), alert.get("observed_per_min")), "volumetric_anomaly_check", ToolResult),
        isolated(lambda: auth_boundary_check(alert.get("role"), alert.get("endpoint")), "auth_boundary_check", ToolResult),
        isolated(lambda: db_direct_query_check(
            alert.get("client_app"),
            alert.get("query"),
            alert.get("rows_returned"),
            alert.get("source_ip"),
        ), "db_direct_query_check", ToolResult),
    ]
