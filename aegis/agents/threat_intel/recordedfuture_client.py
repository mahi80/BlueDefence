"""Recorded Future client.

Recorded Future is one of the dominant commercial threat-intel
platforms used by banks. AEGIS' threat_intel agent treats it as
another feed source (alongside MISP / FS-ISAC / CISA KEV / Splunk ES).

API contract (Recorded Future v2):
  GET /v2/{entity}/risklist
    headers: X-RFToken: <api_token>
  Response: NDJSON, one risk-list entry per line

Each entry has: Name (the IOC value), Risk (numeric 0-99 score),
RiskString, EvidenceDetails. AEGIS maps Risk >= 65 to confidence
0.85+, keeping below-65 entries informational only.

Production hardening:
- Pin RF API version explicitly (header X-RF-Version)
- Use the bank's RF subscription tier (different lists, e.g. ip,
  domain, hash, vulnerability)
- Cache and dedupe — the lists are large
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


_log = logging.getLogger("aegis.recorded_future")


_ENTITY_TO_KIND: dict[str, str] = {
    "ip":        "ip",
    "domain":    "domain",
    "url":       "url",
    "hash":      "hash_sha256",   # RF returns whichever hash is the canonical one
    "vulnerability": "cve",
}


@dataclass
class RecordedFutureConfig:
    base_url: str
    api_token: str
    timeout_s: float = 30.0
    risk_threshold: int = 65   # 0-99 scale; 65+ = "potentially malicious"

    @classmethod
    def from_env(cls) -> Optional["RecordedFutureConfig"]:
        url = os.environ.get("RF_BASE_URL", "https://api.recordedfuture.com/v2")
        token = os.environ.get("RF_API_TOKEN")
        if not token:
            return None
        return cls(base_url=url, api_token=token)


class RecordedFutureClient:
    """Thin REST client for Recorded Future risklist endpoints."""

    name = "recorded_future"

    def __init__(self, config: RecordedFutureConfig):
        self._cfg = config

    def fetch_risklist(self, entity_type: str = "ip") -> Iterable[IOC]:
        """Stream the configured risklist for an entity type.

        entity_type ∈ {"ip", "domain", "url", "hash", "vulnerability"}.
        Yields IOC objects. Skips entries below the configured risk
        threshold so the local store doesn't bloat with informational
        noise.
        """
        if entity_type not in _ENTITY_TO_KIND:
            raise ValueError(f"unknown RF entity_type: {entity_type!r}")
        kind = _ENTITY_TO_KIND[entity_type]
        url = self._cfg.base_url.rstrip("/") + f"/{entity_type}/risklist"
        req = urllib.request.Request(
            url,
            headers={
                "X-RFToken": self._cfg.api_token,
                "Accept": "application/json",
                "User-Agent": "aegis-rf-client/1",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self._cfg.timeout_s) as resp:
                body = resp.read().decode("utf-8")
        except (urllib.error.URLError, urllib.error.HTTPError) as exc:
            _log.warning("Recorded Future fetch failed for %s: %s", entity_type, exc)
            return

        now = time.time()
        # RF returns NDJSON; one line per record. Some endpoints return
        # a single JSON array — handle both.
        if body.lstrip().startswith("["):
            try:
                records = json.loads(body)
            except json.JSONDecodeError:
                records = []
        else:
            records = []
            for line in body.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        for r in records:
            try:
                value = r.get("Name") or r.get("entity") or ""
                risk = int(r.get("Risk", 0))
            except (ValueError, TypeError):
                continue
            if not value or risk < self._cfg.risk_threshold:
                continue
            risk_string = r.get("RiskString", "")
            tags: list[str] = []
            for ev in (r.get("EvidenceDetails") or []):
                rule = ev.get("Rule") if isinstance(ev, dict) else None
                if rule:
                    tags.append(f"rf:rule={rule}")
            if risk_string:
                tags.append(f"rf:string={risk_string}")
            # Map RF Risk (0-99) to confidence (0-1) with a floor of
            # 0.5 even at threshold so the perimeter agent's hot-path
            # IOC matcher takes notice.
            confidence = max(0.5, min(0.99, risk / 100.0))
            yield IOC(
                kind=kind,
                value=value,
                confidence=confidence,
                source=f"recorded_future:{entity_type}",
                first_seen=now,
                last_seen=now,
                tags=tuple(tags) if tags else (),
            )


# ---- Mock for offline / CI demo ------------------------------------

class MockRecordedFutureClient:
    """Returns canned RF-shaped data so the threat_intel pipeline is
    testable without an RF subscription.
    """

    name = "recorded_future_mock"

    def fetch_risklist(self, entity_type: str = "ip") -> Iterable[IOC]:
        if entity_type not in _ENTITY_TO_KIND:
            return []
        kind = _ENTITY_TO_KIND[entity_type]
        now = time.time()
        canned: list[IOC] = []
        if entity_type == "ip":
            canned = [
                IOC(kind=kind, value="192.0.2.55", confidence=0.92,
                    source="recorded_future:ip", first_seen=now, last_seen=now,
                    tags=("rf:rule=Recent C2 Communication",)),
                IOC(kind=kind, value="192.0.2.66", confidence=0.78,
                    source="recorded_future:ip", first_seen=now, last_seen=now,
                    tags=("rf:rule=Historical Phishing Host",)),
            ]
        elif entity_type == "domain":
            canned = [
                IOC(kind=kind, value="rf-c2.example.test", confidence=0.91,
                    source="recorded_future:domain", first_seen=now, last_seen=now,
                    tags=("rf:rule=Recently Registered C2 Domain",)),
            ]
        elif entity_type == "vulnerability":
            canned = [
                IOC(kind=kind, value="CVE-2026-50001", confidence=0.95,
                    source="recorded_future:vulnerability", first_seen=now, last_seen=now,
                    tags=("rf:rule=Actively Exploited",)),
            ]
        return canned


def get_client() -> "RecordedFutureClient | MockRecordedFutureClient":
    cfg = RecordedFutureConfig.from_env()
    if cfg is None:
        return MockRecordedFutureClient()
    return RecordedFutureClient(cfg)
