"""Client-exposure scan (roadmap 2.8c): find what an attacker's AI agent would harvest, first.

An agent fingerprints the stack in its first requests and then collects what that stack leaks.
This scan runs the same checklist over the bank's **own** repos and build outputs — per stack —
and hands findings to the patch agent exactly like the dependency / supply-chain findings.
Framework specificity lives here, not in the triage LLM (decision 2026-10-22).

Input is a ``scope`` dict describing a deployable (static facts a CI job can collect; no network):

    {"stack": "react|nextjs|angular|vue|nuxt|django|laravel|symfony|php|mobile|graphql",
     "build_files": ["main.3f2.js", "main.3f2.js.map", ...],          # names in the prod artefact
     "bundle_text": "...",                                            # concatenated prod JS (optional)
     "env_in_bundle": ["REACT_APP_API_KEY", ...],                     # vars found in the bundle
     "routes": ["/admin/", "/api/schema/", ...],                      # routes reachable unauthenticated
     "settings": {"DEBUG": true, "APP_DEBUG": "true", ...},           # framework settings as deployed
     "graphql": {"introspection": true, "depth_limit": null},
     "mobile": {"cert_pinning": false, "keys_in_app": ["..."]},
     "security_headers": {"content-security-policy": "...", "strict-transport-security": "..."},
     "sri_on_scripts": false}

Every check is a (stack applicability, predicate, finding) triple; the remediation text is what
a developer does, the technique is what the attacker would have done with it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

from .tools import Finding, _enrich_with_score

_KEY_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),                                  # AWS access key id shape
    re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"),
    re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}"),   # JWT-shaped literal
    re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
)
_PUBLIC_ENV_PREFIX = ("REACT_APP_", "NEXT_PUBLIC_", "VUE_APP_", "NUXT_PUBLIC_", "VITE_", "NG_APP_", "EXPO_PUBLIC_")
_SECRET_HINT = ("KEY", "SECRET", "TOKEN", "PASSWORD", "PRIVATE", "SIGNING", "DSN")

DEBUG_ROUTES = {
    "django":  ("/__debug__/", "/api/schema/", "/api/?format=api", "/static/debug_toolbar/", "/admin/"),
    "laravel": ("/telescope", "/_ignition/health-check", "/storage/logs/", "/vendor/", "/.env"),
    "symfony": ("/_profiler/", "/_wdt/", "/app_dev.php", "/config/", "/.env"),
    "php":     ("/phpinfo.php", "/.env", "/.git/config", "/backup.zip", "/admin.php"),
    "nextjs":  ("/api/__health", "/.env.local", "/_next/data/"),
    "react":   ("/asset-manifest.json", "/.env"),
    "angular": ("/assets/environment.prod.json", "/swagger-ui/", "/ngsw.json"),
    "vue":     ("/.env", "/api/docs", "/__vite_ping"),
    "nuxt":    ("/__nuxt_error", "/.env", "/api/_content"),
    "mobile":  ("/api/v1/internal/", "/api/v2/beta/", "/api/config/keys", "/api/v1/debug/env"),
    "graphql": ("/graphiql", "/playground"),
}
SPA = ("react", "nextjs", "angular", "vue", "nuxt", "graphql")
SERVER = ("django", "laravel", "symfony", "php", "nextjs", "nuxt")


@dataclass
class Check:
    id: str
    stacks: tuple[str, ...] | None          # None = every stack
    severity: str
    category: str
    technique: str
    predicate: Callable[[dict], str | None]  # returns evidence text when it fires
    remediation: str


def _has_file(scope: dict, suffix: str) -> str | None:
    hits = [f for f in scope.get("build_files", []) if f.endswith(suffix)]
    return f"{len(hits)} file(s): {', '.join(hits[:3])}" if hits else None


def _secrets_in_bundle(scope: dict) -> str | None:
    text = scope.get("bundle_text", "") or ""
    hits = [p.pattern[:30] for p in _KEY_PATTERNS if p.search(text)]
    env = [v for v in scope.get("env_in_bundle", []) if v.startswith(_PUBLIC_ENV_PREFIX) and any(h in v.upper() for h in _SECRET_HINT)]
    if not hits and not env:
        return None
    return "secret-shaped literals in the prod bundle: " + ", ".join(hits[:3] + env[:5])


def _debug_routes(scope: dict) -> str | None:
    stack = scope.get("stack", "")
    routes = set(scope.get("routes", []))
    hits = [r for r in DEBUG_ROUTES.get(stack, ()) if any(x.startswith(r) or x == r for x in routes)]
    return f"debug / profiler / env routes reachable unauthenticated: {', '.join(hits)}" if hits else None


def _truthy(v: Any) -> bool:
    return v is True or str(v).strip().lower() in ("1", "true", "yes", "on")


def _setting(scope: dict, *names: str) -> str | None:
    st = scope.get("settings", {}) or {}
    on = [n for n in names if _truthy(st.get(n))]
    return f"{', '.join(on)} enabled in the deployed settings" if on else None


CHECKS: list[Check] = [
    Check("CX-001", SPA, "high", "misconfig", "T1592.002", lambda s: _has_file(s, ".map"),
          "Strip source maps from the production artefact (or serve them only to an authenticated error-tracking host)."),
    Check("CX-002", None, "critical", "misconfig", "T1552.001", _secrets_in_bundle,
          "Remove secrets from the client bundle; public env prefixes (REACT_APP_/NEXT_PUBLIC_/VUE_APP_/VITE_) are shipped to every browser — move the call behind a backend route and rotate the exposed key."),
    Check("CX-003", None, "high", "misconfig", "T1592.002", _debug_routes,
          "Disable the debug / profiler route in production or restrict it to the admin network; add it to the WAF deny list."),
    Check("CX-004", ("django",), "critical", "misconfig", "T1592.002", lambda s: _setting(s, "DEBUG"),
          "Set DEBUG = False in production; tracebacks expose settings, paths and query fragments."),
    Check("CX-005", ("laravel", "symfony", "php"), "critical", "misconfig", "T1592.002", lambda s: _setting(s, "APP_DEBUG", "APP_ENV_DEBUG", "display_errors"),
          "Set APP_DEBUG=false / display_errors=Off; Ignition and the Symfony profiler expose env and routes."),
    Check("CX-006", ("django",), "high", "misconfig", "T1595.002",
          lambda s: "DRF browsable API / schema endpoint open" if any(r in set(s.get("routes", [])) for r in ("/api/?format=api", "/api/schema/")) else None,
          "Disable the browsable renderer and schema endpoints in production or require authentication for them."),
    Check("CX-007", ("graphql", "react", "nextjs", "vue", "nuxt", "angular"), "high", "misconfig", "T1595.002",
          lambda s: "GraphQL introspection enabled in production" if _truthy((s.get("graphql") or {}).get("introspection")) else None,
          "Disable introspection in production; add query depth / complexity limits and persisted queries."),
    Check("CX-008", ("graphql",), "medium", "misconfig", "T1499",
          lambda s: "no GraphQL depth / complexity limit" if s.get("graphql") and not (s["graphql"].get("depth_limit") or s["graphql"].get("complexity_limit")) else None,
          "Set a query depth limit (≤ 10) and a complexity budget per request."),
    Check("CX-009", ("mobile",), "high", "misconfig", "T1557",
          lambda s: "certificate pinning inactive" if s.get("mobile") and not _truthy(s["mobile"].get("cert_pinning")) else None,
          "Enable certificate pinning for the banking API hosts; without it an interception proxy reads every call."),
    Check("CX-010", ("mobile",), "critical", "misconfig", "T1552.001",
          lambda s: f"{len(s['mobile']['keys_in_app'])} key(s) embedded in the app" if (s.get("mobile") or {}).get("keys_in_app") else None,
          "Move embedded API keys behind an authenticated backend; anything in the app binary is decompiled within minutes."),
    Check("CX-011", None, "medium", "misconfig", "T1059.007",
          lambda s: "no Content-Security-Policy header" if not (s.get("security_headers") or {}).get("content-security-policy") else None,
          "Add a CSP with report-to so skimmer / inline-script injections are both blocked and reported to Sentinel."),
    Check("CX-012", SPA, "medium", "misconfig", "T1059.007",
          lambda s: "scripts loaded without Subresource Integrity" if s.get("sri_on_scripts") is False else None,
          "Add integrity= hashes to every third-party script tag; a modified script then fails to load and reports."),
    Check("CX-013", None, "high", "misconfig", "T1190",
          lambda s: f"admin route reachable from the internet: {', '.join(r for r in s.get('routes', []) if r.startswith(('/admin', '/wp-admin', '/manage')))}"
          if any(r.startswith(("/admin", "/wp-admin", "/manage")) for r in s.get("routes", [])) and not _truthy(s.get("admin_ip_restricted")) else None,
          "Restrict the admin route to the corporate / bastion range at the WAF or ingress."),
    Check("CX-014", None, "medium", "misconfig", "T1592.002",
          lambda s: "server banner / X-Powered-By exposes the stack" if _truthy(s.get("stack_banner_exposed")) else None,
          "Remove X-Powered-By / Server version headers; the fingerprint is the agent's first step."),
]


def client_exposure_scan(scope: dict) -> list[Finding]:
    """Run every applicable check; findings are scored like the other scanners' output."""
    stack = str(scope.get("stack", "")).lower()
    out: list[Finding] = []
    for c in CHECKS:
        if c.stacks is not None and stack not in c.stacks:
            continue
        try:
            ev = c.predicate(scope)
        except Exception:  # noqa: BLE001 — a malformed scope field must not abort the scan
            ev = None
        if not ev:
            continue
        f = Finding(
            id=f"{c.id}:{stack or 'any'}", severity=c.severity, confidence=0.9, category=c.category,
            affected_component=f"{scope.get('name', 'deployable')} ({stack or 'unknown stack'})",
            evidence=f"[{c.technique}] {ev}", recommended_remediation=c.remediation,
            cvss_estimate={"critical": 9.1, "high": 7.5, "medium": 5.3, "low": 3.1}.get(c.severity),
            # no CVE → no EPSS; use an exposure likelihood instead (off-the-shelf agents harvest these
            # on first contact, so the "probability of exploitation" is a property of the exposure)
            epss={"critical": 0.9, "high": 0.7, "medium": 0.45, "low": 0.2}.get(c.severity),
            poc_available=True,
        )
        _enrich_with_score(f)
        f.severity = c.severity                       # severity is policy (checklist), not score-derived
        out.append(f)
    return out


# --------------------------------------------------------------------------- 2.8d: stack canaries

CANARY_PACK = {
    # what to plant per stack: agents fetch everything; a touch is a confirmed signal (honeytoken monitor)
    "react":   [("url", "/static/js/vendor.a1b2.js.map", "decoy source map"), ("api_key", "REACT_APP_INTERNAL_KEY=rk_live_DECOY_7f3a9c", "decoy bundle key"),
                ("url", "/api/v1/admin/export", "decoy admin export route")],
    "nextjs":  [("url", "/_next/static/chunks/pages/_app-DECOY.js.map", "decoy source map"), ("url", "/api/internal/__debug", "decoy debug route"),
                ("api_key", "NEXT_PUBLIC_INTERNAL_TOKEN=npt_DECOY_4c1d", "decoy bundle token")],
    "angular": [("url", "/assets/environment.staging.json", "decoy environment file"), ("url", "/swagger-ui/index.html", "decoy swagger"),
                ("api_key", "NG_APP_SIGNING_KEY=ngk_DECOY_91e2", "decoy bundle key")],
    "vue":     [("url", "/assets/index-DECOY.js.map", "decoy source map"), ("url", "/api/docs/internal", "decoy docs route"),
                ("api_key", "VUE_APP_ADMIN_TOKEN=vat_DECOY_55aa", "decoy bundle token")],
    "nuxt":    [("url", "/_nuxt/entry-DECOY.js.map", "decoy source map"), ("url", "/api/_content/admin", "decoy content route")],
    "django":  [("url", "/admin-old/", "decoy legacy admin"), ("url", "/api/v1/schema-internal/", "decoy schema"), ("db_name", "customers_kyc_archive", "decoy DB name in settings")],
    "laravel": [("url", "/telescope-old", "decoy telescope"), ("url", "/storage/logs/laravel-2024.log", "decoy log path"), ("credential", "laravel_deploy_svc", "decoy service account")],
    "symfony": [("url", "/_profiler-dev/", "decoy profiler"), ("url", "/app_dev_old.php", "decoy front controller")],
    "php":     [("url", "/phpinfo-old.php", "decoy phpinfo"), ("url", "/backup-2024.zip", "decoy backup"), ("url", "/.git-old/config", "decoy git config")],
    "mobile":  [("url", "/api/v1/internal/config", "decoy internal config"), ("api_key", "MOBILE_LEGACY_KEY=mlk_DECOY_c0de", "decoy app key")],
    "graphql": [("url", "/graphql-internal", "decoy internal endpoint"), ("url", "/playground-old", "decoy playground")],
}


def canaries_for(stack: str):
    """Honeytokens to plant for a stack — feed them to ``HoneytokenMonitor(registry=...)``."""
    from ..deception.honeytoken_monitor import Honeytoken
    out = []
    for i, (kind, value, desc) in enumerate(CANARY_PACK.get(stack.lower(), [])):
        out.append(Honeytoken(f"cx_{stack.lower()}_{i:02d}", kind, value, f"{desc} ({stack}); no human or service references it — a touch is confirmed"))
    return out


__all__ = ["CANARY_PACK", "CHECKS", "DEBUG_ROUTES", "canaries_for", "client_exposure_scan"]
