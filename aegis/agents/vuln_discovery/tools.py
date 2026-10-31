"""Tools for the Vulnerability Discovery agent.

Read-only scans on dependency manifests, config files, and code paths.
Walking-skeleton implementations use mock data; production swaps:
  - dependency_scan -> Snyk / Trivy / OSV
  - config_scan -> Checkov / kube-bench / internal policy engine
  - code_scan -> Semgrep / CodeQL
  - supply_chain_anomaly -> npm/PyPI advisory feed + dependency drift

Risk scoring uses a weighted formula combining four signals — CVSS
alone is well-known to be a poor prioritization metric (a CVSS-9 with
near-zero exploit-prediction is often less urgent than a CVSS-7 that's
listed in CISA KEV with a public PoC). Weights and combination logic
are inspired by industry practice (FIRST EPSS + CISA KEV are the
primary signals SOCs already use to triage):

    risk = 0.35 * EPSS  +  0.30 * KEV  +  0.20 * (CVSS / 10)  +  0.15 * PoC
    boost x1.4 (capped at 1.0) when EPSS > 0.5 AND (KEV OR PoC)

Severity buckets are derived from the score, not from CVSS alone, so
findings that are technically severe but have no real exploitation
signal don't drown the queue.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class Finding:
    id: str
    severity: str  # critical | high | medium | low | info
    confidence: float
    category: str  # dependency_cve | misconfig | logic_flaw | supply_chain
    affected_component: str
    evidence: str
    recommended_remediation: str
    cvss_estimate: float | None = None
    # Threat-intel signals — None means "no data", treated as 0 in scoring.
    epss: float | None = None        # 0-1 exploit-prediction (FIRST.org)
    kev: bool = False                # CISA Known Exploited Vulnerabilities catalog
    poc_available: bool = False      # public exploit / PoC seen in the wild
    risk_score: float | None = None  # weighted prioritization, 0-1


# ---- Risk scoring -----------------------------------------------------

def compute_risk_score(
    *,
    cvss: float | None,
    epss: float | None,
    kev: bool,
    poc_available: bool,
) -> float:
    """Weighted prioritization score. Inputs treated as 0 when None."""
    cvss_n = (cvss or 0.0) / 10.0
    epss_v = epss or 0.0
    kev_v = 1.0 if kev else 0.0
    poc_v = 1.0 if poc_available else 0.0
    score = 0.35 * epss_v + 0.30 * kev_v + 0.20 * cvss_n + 0.15 * poc_v
    if epss_v > 0.5 and (kev or poc_available):
        score = min(1.0, score * 1.4)
    return round(score, 3)


def severity_from_score(score: float) -> str:
    if score >= 0.85:
        return "critical"
    if score >= 0.65:
        return "high"
    if score >= 0.40:
        return "medium"
    if score >= 0.15:
        return "low"
    return "info"


def _enrich_with_score(f: Finding) -> Finding:
    """Mutate a Finding to set risk_score + recompute severity from score."""
    f.risk_score = compute_risk_score(
        cvss=f.cvss_estimate, epss=f.epss, kev=f.kev, poc_available=f.poc_available,
    )
    f.severity = severity_from_score(f.risk_score)
    return f


# ---- Tool: dependency CVE scan ----------------------------------------

# Stand-in DB. Production: OSV.dev API or internal mirror.
# EPSS data: FIRST.org's daily feed (CC BY 4.0). KEV: CISA's daily JSON.
# These mock entries reflect approximate real values for the listed CVEs.
_KNOWN_CVE_DB = {
    "litellm": {
        "1.82.7": {
            "cve": "PYSEC-2026-LITELLM-IS",
            "cvss": 9.8,
            "summary": "Malicious package version (TeamPCP infostealer).",
            "epss": 0.97, "kev": True, "poc_available": True,
        },
        "1.82.8": {
            "cve": "PYSEC-2026-LITELLM-IS",
            "cvss": 9.8,
            "summary": "Malicious package version (TeamPCP infostealer).",
            "epss": 0.97, "kev": True, "poc_available": True,
        },
    },
    "log4j-core": {
        "2.14.1": {
            "cve": "CVE-2021-44228",
            "cvss": 10.0,
            "summary": "Log4Shell RCE.",
            "epss": 0.97, "kev": True, "poc_available": True,
        },
    },
    "openssl": {
        "1.1.1k": {
            # Lower-priority example: CVSS 7.5 looks scary, but EPSS is
            # ~0.05 and it's not in KEV. Risk score is much lower.
            "cve": "CVE-2022-0778",
            "cvss": 7.5,
            "summary": "Infinite loop in BN_mod_sqrt.",
            "epss": 0.05, "kev": False, "poc_available": True,
        },
    },
    "django": {
        "3.2.10": {
            # Mid-range: CVSS 7.5, EPSS modest, KEV-listed -> bumps up
            "cve": "CVE-2022-22818",
            "cvss": 7.5,
            "summary": "Possible XSS via {% debug %} template tag.",
            "epss": 0.10, "kev": True, "poc_available": True,
        },
    },
}


def dependency_scan(manifest: dict, intel: Any = None) -> list[Finding]:
    """Static table first (deterministic, offline); when a ``cve_feeds.CveIntel`` consumer is given,
    every package is also matched against live NVD CPE ranges with real CVSS / KEV / EPSS."""
    findings: list[Finding] = []
    seen: set[str] = set()
    for package, version in (manifest or {}).items():
        if intel is not None and hasattr(intel, "affected"):
            try:
                live = intel.affected(package, str(version))
            except Exception:  # noqa: BLE001 — a bad cache never breaks the scan
                live = []
            for rec in live[:5]:
                seen.add(rec.cve_id)
                kev = getattr(rec, "kev", None)
                f = Finding(
                    id=f"VULN-{rec.cve_id}-{package}", severity="info", confidence=0.9, category="dependency_cve",
                    affected_component=f"{package}=={version}",
                    evidence=(f"{rec.cve_id} (NVD, CVSS {rec.cvss if rec.cvss is not None else '?'}" + (f", KEV since {kev.date_added}, due {kev.due_date}" if kev else "")
                              + (", ransomware campaign use" if kev and kev.ransomware else "") + f"): {rec.description[:200]}"),
                    recommended_remediation=(kev.action if kev and kev.action else f"Upgrade {package} past the affected range; rebuild and redeploy"),
                    cvss_estimate=rec.cvss, epss=rec.epss, kev=bool(kev), poc_available=bool(kev),
                )
                findings.append(_enrich_with_score(f))
        cves = _KNOWN_CVE_DB.get(package, {})
        if version in cves and cves[version]["cve"] not in seen:
            cve = cves[version]
            f = Finding(
                id=f"VULN-{cve['cve']}-{package}",
                severity="info",  # placeholder — overwritten by _enrich_with_score
                confidence=0.95,
                category="dependency_cve",
                affected_component=f"{package}=={version}",
                evidence=cve["summary"],
                recommended_remediation=(
                    f"Pin {package} to a non-vulnerable version; rebuild and redeploy"
                ),
                cvss_estimate=cve.get("cvss"),
                epss=cve.get("epss"),
                kev=bool(cve.get("kev", False)),
                poc_available=bool(cve.get("poc_available", False)),
            )
            findings.append(_enrich_with_score(f))
    return findings


# ---- Tool: config scan -----------------------------------------------

def config_scan(config: dict) -> list[Finding]:
    findings: list[Finding] = []
    if config.get("debug_endpoint_exposed"):
        findings.append(_enrich_with_score(Finding(
            id="VULN-CFG-DEBUG-001",
            severity="info",
            confidence=0.9,
            category="misconfig",
            affected_component=config.get("service", "unknown"),
            evidence="Debug endpoint reachable from non-internal network",
            recommended_remediation="Restrict debug endpoint to localhost or remove",
            cvss_estimate=7.5,
            poc_available=True,
        )))
    if (config.get("tls_min_version") or "").lower() in ("tls1.0", "tls1.1"):
        findings.append(_enrich_with_score(Finding(
            id="VULN-CFG-TLS-001",
            severity="info",
            confidence=0.95,
            category="misconfig",
            affected_component=config.get("service", "unknown"),
            evidence=f"TLS minimum version is {config.get('tls_min_version')}",
            recommended_remediation="Set tls_min_version to TLS 1.2 or 1.3",
            cvss_estimate=5.3,
            poc_available=True,
        )))
    perms = config.get("iam_role_permissions", [])
    if "*:*" in perms or "AdministratorAccess" in perms:
        findings.append(_enrich_with_score(Finding(
            id="VULN-CFG-IAM-001",
            severity="info",
            confidence=0.92,
            category="misconfig",
            affected_component=config.get("iam_role_name", "unknown"),
            evidence="IAM role grants wildcard or AdministratorAccess",
            recommended_remediation="Replace wildcard with least-privilege scoped policy",
            cvss_estimate=8.0,
            poc_available=True,
        )))
    return findings


# ---- Tool: code scan (logic-flaw heuristics) -------------------------

def code_scan(code_paths: list[dict]) -> list[Finding]:
    """Each entry: {'path': str, 'snippet': str, 'context': dict}"""
    findings: list[Finding] = []
    for entry in code_paths or []:
        snippet = entry.get("snippet", "").lower()
        path = entry.get("path", "?")
        # BOLA/IDOR: route uses :id without authorization check
        if "user_id" in snippet and "request" in snippet and "is_admin" not in snippet and "owner" not in snippet:
            findings.append(_enrich_with_score(Finding(
                id=f"VULN-CODE-BOLA-{abs(hash(path)) % 10000}",
                severity="info",
                confidence=0.6,
                category="logic_flaw",
                affected_component=path,
                evidence="Route appears to read user_id from request without ownership check",
                recommended_remediation="Add explicit 'request.user == record.owner' enforcement",
                cvss_estimate=7.0,
                poc_available=True,  # BOLA is trivially exploitable when present
            )))
        # Hardcoded secret
        if any(token in snippet for token in ("password = \"", "api_key = \"", "secret = \"", "token = \"")):
            findings.append(_enrich_with_score(Finding(
                id=f"VULN-CODE-SECRET-{abs(hash(path)) % 10000}",
                severity="info",
                confidence=0.85,
                category="misconfig",
                affected_component=path,
                evidence="Hardcoded credential pattern in source",
                recommended_remediation="Move secret to Vault / HSM; rotate the leaked value",
                cvss_estimate=8.5,
                poc_available=True,
            )))
    return findings


# ---- Tool: supply chain anomaly --------------------------------------

def supply_chain_anomaly(events: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for ev in events or []:
        if ev.get("publish_age_seconds", 1e9) < 600 and ev.get("major_version_bump"):
            findings.append(_enrich_with_score(Finding(
                id=f"VULN-SC-{ev.get('package', 'unknown')}",
                severity="info",
                confidence=0.7,
                category="supply_chain",
                affected_component=ev.get("package", "unknown"),
                evidence=(
                    f"Major version bump published {ev.get('publish_age_seconds')}s ago "
                    f"(LiteLLM-style window - withhold rollout pending review)"
                ),
                recommended_remediation=(
                    "Block in internal mirror until approved; verify maintainer + signature"
                ),
                cvss_estimate=8.0,
                # Supply chain incidents have very high EPSS by nature once the
                # malicious package goes live — the exploit IS the install.
                epss=0.85,
                poc_available=True,
            )))
    return findings


# ---- CI/CD pipeline drift -------------------------------------------

# Suspicious patterns in CI/CD config diffs and runner inventory.
# Source: GitHub Actions workflows, Jenkinsfile, GitLab CI, Argo
# Workflows manifests + the runner registration log.
_CI_RISKY_PATTERNS = [
    re.compile(r"curl\s+[^|]*\|\s*(?:bash|sh)", re.I),    # pipe-to-shell
    re.compile(r"\b(?:wget|curl)\s+[^\s]*\.(?:sh|py|bin)\b", re.I),
    re.compile(r"echo\s+[^|]*\|\s*base64\s+-d\s*\|\s*sh", re.I),
    re.compile(r"\bpip\s+install\s+--index-url\s+https?://", re.I),  # alt index
    re.compile(r"\bnpm\s+install\s+--registry\s+https?://", re.I),
    re.compile(r"AWS_SECRET_ACCESS_KEY\s*[:=]\s*['\"]?[A-Z0-9/+=]{20,}", re.I),
    re.compile(r"to:\s*['\"]?(?:0xattacker|attacker@|paste(?:bin)?\.com)", re.I),
]


def cicd_drift_check(workflows: list[dict] | None,
                     runner_inventory: list[dict] | None) -> list[Finding]:
    """Reasons about CI/CD pipeline drift:
      - workflow steps that pipe untrusted content to shell
      - alternative package-registry URLs (typosquat / mirror swap)
      - unauthorized runners registered to the org
      - long-running self-hosted runners with stale OS

    Production seam: GitHub Audit Log + Actions API for workflow
    file diffs; org-runner-registration events; runner OS-version
    inventory from a sweep.
    """
    findings: list[Finding] = []

    for wf in (workflows or []):
        path = wf.get("path", "<unknown>")
        content = wf.get("content", "")
        diff_added = wf.get("diff_added_lines", []) or []
        scan_text = content + "\n" + "\n".join(diff_added)
        risky_hits = [rx.pattern for rx in _CI_RISKY_PATTERNS if rx.search(scan_text)]
        if risky_hits:
            findings.append(_enrich_with_score(Finding(
                id=f"VULN-CICD-{wf.get('id', path)}",
                severity="info",
                confidence=0.85,
                category="cicd_drift",
                affected_component=path,
                evidence=(
                    f"CI/CD workflow {path} contains risky patterns: "
                    f"{', '.join(risky_hits[:3])}"
                ),
                recommended_remediation=(
                    "Revert change; require two-person review on pipeline diffs; "
                    "lock pipeline file via CODEOWNERS + branch protection"
                ),
                cvss_estimate=7.5,
                epss=0.6,
                poc_available=False,
            )))

    for runner in (runner_inventory or []):
        if runner.get("self_hosted") and not runner.get("authorized", True):
            findings.append(_enrich_with_score(Finding(
                id=f"VULN-CICD-RUNNER-{runner.get('id','unknown')}",
                severity="info",
                confidence=0.9,
                category="cicd_drift",
                affected_component=runner.get("name", "unknown"),
                evidence=(
                    f"Unauthorized self-hosted runner registered "
                    f"(id={runner.get('id')}, registered_by={runner.get('registered_by')})"
                ),
                recommended_remediation=(
                    "De-register runner; rotate any tokens it had access to; "
                    "audit recent jobs that ran on it for command tampering"
                ),
                cvss_estimate=8.5,
                epss=0.7,
                poc_available=False,
            )))
        if runner.get("self_hosted") and runner.get("os_age_days", 0) > 365:
            findings.append(_enrich_with_score(Finding(
                id=f"VULN-CICD-RUNNER-STALE-{runner.get('id','unknown')}",
                severity="info",
                confidence=0.7,
                category="cicd_drift",
                affected_component=runner.get("name", "unknown"),
                evidence=(
                    f"Self-hosted runner OS age {runner.get('os_age_days')}d; "
                    "above 1y threshold for prod-touching runners"
                ),
                recommended_remediation="Replace with fresh image; set max-age policy",
                cvss_estimate=5.0,
                epss=0.3,
                poc_available=False,
            )))

    return findings
