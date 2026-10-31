"""Tenable.io / Tenable.sc / Tenable CSPM REST client.

Tenable is the dominant VAPT + cloud-misconfig scanner in Indian bank
environments — every CV in the bank-security candidate pool lists it
(see CV_ABHISHEK_SINHA which prompted this module). The threat_intel
agent treats Tenable findings as another IOC source: each finding
becomes a CVE-class IOC (when CVE-backed) or a bespoke
configuration-finding IOC (CSPM rule violations).

API contract (Tenable.io v3):
  GET /vulns/export
    headers: X-ApiKeys: accessKey=...; secretKey=...
    Response: streaming JSONL of vuln records.
  GET /findings (Tenable CSPM):
    headers: X-ApiKeys: accessKey=...; secretKey=...
    Response: { findings: [...] }

Each Tenable finding has: severity ('critical'|'high'|'medium'|'low'),
plugin_id, cve[] (when applicable), description, asset_uuid,
first_found, last_found, state ('OPEN'|'REOPENED'|'FIXED').

Walking-skeleton: pulls a single page of findings, converts to AEGIS
IOC objects (kind=cve when there's a CVE, otherwise kind=config). The
IOC then flows through the existing distribution into vuln_discovery's
prioritization pipeline. Production extends with paging, severity
threshold filters, asset-tag-aware filtering.
"""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Iterable, Optional

from .store import IOC


_log = logging.getLogger("aegis.tenable")


_SEVERITY_TO_CONFIDENCE = {
    "critical": 0.99,
    "high":     0.92,
    "medium":   0.75,
    "low":      0.55,
    "info":     0.30,
}


@dataclass
class TenableConfig:
    base_url: str
    access_key: str
    secret_key: str
    verify_tls: bool = True
    timeout_s: float = 30.0
    page_size: int = 1000

    @classmethod
    def from_env(cls) -> Optional["TenableConfig"]:
        url = os.environ.get("TENABLE_URL", "https://cloud.tenable.com")
        access = os.environ.get("TENABLE_ACCESS_KEY")
        secret = os.environ.get("TENABLE_SECRET_KEY")
        if not (access and secret):
            return None
        return cls(
            base_url=url,
            access_key=access,
            secret_key=secret,
            verify_tls=os.environ.get("TENABLE_VERIFY_TLS", "true").lower() != "false",
        )


class TenableClient:
    """Thin REST client for Tenable.io / .sc / CSPM.

    No external dependency on `pytenable` — we go through urllib so the
    supply-chain surface stays small (per the project plan).
    """

    name = "tenable"

    def __init__(self, config: TenableConfig):
        self._cfg = config

    def _auth_header(self) -> str:
        return f"accessKey={self._cfg.access_key}; secretKey={self._cfg.secret_key}"

    def fetch_findings(
        self,
        *,
        severity_threshold: str = "medium",
        state_filter: tuple[str, ...] = ("OPEN", "REOPENED"),
        max_pages: int = 1,
    ) -> Iterable[IOC]:
        """Pull vulnerability findings; yield as AEGIS IOCs.

        - severity_threshold: skip below this severity rank.
        - state_filter: only OPEN/REOPENED by default — FIXED entries
          are noise for live IOC distribution.
        - max_pages: paging cap.
        """
        rank = ["info", "low", "medium", "high", "critical"]
        threshold_idx = rank.index(severity_threshold) if severity_threshold in rank else 2

        url = self._cfg.base_url.rstrip("/") + "/findings"
        for page in range(1, max_pages + 1):
            req = urllib.request.Request(
                f"{url}?page={page}&size={self._cfg.page_size}",
                headers={
                    "X-ApiKeys": self._auth_header(),
                    "Accept": "application/json",
                    "User-Agent": "aegis-tenable-client/1",
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=self._cfg.timeout_s) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
            except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
                _log.warning("Tenable fetch_findings failed (page %d): %s", page, exc)
                return

            findings = payload.get("findings") or []
            if not findings:
                return
            now = time.time()
            for f in findings:
                sev = (f.get("severity") or "low").lower()
                if rank.index(sev) < threshold_idx if sev in rank else True:
                    continue
                state = (f.get("state") or "OPEN").upper()
                if state not in state_filter:
                    continue
                cves = f.get("cve") or []
                conf = _SEVERITY_TO_CONFIDENCE.get(sev, 0.5)
                tags = ("tenable", f"severity={sev}", f"plugin={f.get('plugin_id','?')}",
                        f"asset={f.get('asset_uuid','?')}")
                if cves:
                    for cve in cves:
                        yield IOC(
                            kind="cve", value=cve, confidence=conf,
                            source=f"tenable:{f.get('plugin_id','?')}",
                            first_seen=float(f.get("first_found", now)),
                            last_seen=now,
                            tags=tags,
                        )
                else:
                    # Config / CSPM finding without CVE — emit as config IOC
                    yield IOC(
                        kind="config",
                        value=f"tenable:{f.get('plugin_id', 'unknown')}",
                        confidence=conf,
                        source="tenable.cspm",
                        first_seen=float(f.get("first_found", now)),
                        last_seen=now,
                        tags=tags + (f.get("rule_id", "config-finding"),),
                    )
            if len(findings) < self._cfg.page_size:
                return  # last page


# ---- Mock for offline / CI demo ------------------------------------

class MockTenableClient:
    """Returns canned Tenable-shaped findings so the threat_intel
    pipeline is testable without a real Tenable instance.

    Mix of CVE-backed VAPT findings (Tenable.sc / Nessus shape) and
    CSPM config-rule findings (Tenable CSPM shape).
    """

    name = "tenable_mock"

    def fetch_findings(self, *, severity_threshold: str = "medium",
                       state_filter: tuple[str, ...] = ("OPEN", "REOPENED"),
                       max_pages: int = 1) -> Iterable[IOC]:
        now = time.time()
        canned: list[IOC] = [
            # Tenable.sc / Nessus VAPT — CVE-backed
            IOC(kind="cve", value="CVE-2024-3094", confidence=0.99,
                source="tenable:185501",
                first_seen=now, last_seen=now,
                tags=("tenable", "severity=critical", "plugin=185501",
                      "asset=ws-fin-0421", "openssh-backdoor")),
            IOC(kind="cve", value="CVE-2026-99999", confidence=0.92,
                source="tenable:191234",
                first_seen=now, last_seen=now,
                tags=("tenable", "severity=high", "plugin=191234",
                      "asset=core-api-prod-1")),
            # Tenable CSPM — AWS misconfigs
            IOC(kind="config", value="tenable:CSPM-AWS-S3-001", confidence=0.92,
                source="tenable.cspm",
                first_seen=now, last_seen=now,
                tags=("tenable", "severity=high", "plugin=CSPM-AWS-S3-001",
                      "asset=s3-bucket-customer-statements", "public-bucket-policy")),
            IOC(kind="config", value="tenable:CSPM-AWS-IAM-014", confidence=0.92,
                source="tenable.cspm",
                first_seen=now, last_seen=now,
                tags=("tenable", "severity=high", "plugin=CSPM-AWS-IAM-014",
                      "asset=iam-role-core-api-role", "wildcard-iam-policy")),
            # Tenable CSPM — Azure misconfigs
            IOC(kind="config", value="tenable:CSPM-AZ-NSG-007", confidence=0.92,
                source="tenable.cspm",
                first_seen=now, last_seen=now,
                tags=("tenable", "severity=high", "plugin=CSPM-AZ-NSG-007",
                      "asset=nsg-prod-web", "rdp-open-internet")),
        ]
        return canned


def get_client() -> "TenableClient | MockTenableClient":
    cfg = TenableConfig.from_env()
    if cfg is None:
        return MockTenableClient()
    return TenableClient(cfg)
