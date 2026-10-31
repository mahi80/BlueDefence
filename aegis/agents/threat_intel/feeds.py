"""Feed pullers: STIX/TAXII, abuse.ch, FS-ISAC peer exchange.

Production replaces these with real-feed clients. For the walking
skeleton we ship:

  - A mock seed (curated tiny IOC list) so the demo runs offline.
  - A real STIX 2.1 puller via plain urllib (no taxii2-client dep)
    that handles the bundle / indicator pattern shape.
  - CISA KEV + NVD 2.0 + EPSS through the cached consumer in cve_feeds.py
    (KEV entries become CVE-class IOCs; NVD records feed vuln_discovery).

All pullers return Iterable[IOC] so the IOCStore.add_many() pipeline is
uniform regardless of source.
"""
from __future__ import annotations

import json
import logging
import re
import time
import urllib.error
import urllib.request
from typing import Iterable, Optional

from .store import IOC


_log = logging.getLogger("aegis.threat_intel.feeds")


# ---- Mock seed (offline demo) ----------------------------------------

_MOCK_SEED: list[IOC] = [
    IOC(kind="ip",     value="198.51.100.99", confidence=0.92, source="mock_feed",
        tags=("scanner", "credential_stuffing"), last_seen=time.time()),
    IOC(kind="ip",     value="203.0.113.150", confidence=0.95, source="mock_feed",
        tags=("c2",), last_seen=time.time()),
    IOC(kind="domain", value="malware.example.test", confidence=0.96, source="mock_feed",
        tags=("phishing",), last_seen=time.time()),
    IOC(kind="hash_md5", value="9f8d24c1aa1f0bc4e0ddcc0bb8b56f00", confidence=0.97,
        source="mock_feed", tags=("infostealer", "TeamPCP-shape"), last_seen=time.time()),
    IOC(kind="cve", value="CVE-2026-99999", confidence=0.85, source="mock_feed",
        tags=("known-exploited", "rce"), last_seen=time.time()),
]


def pull_mock_seed() -> Iterable[IOC]:
    """Return curated test IOCs. For the demo / CI."""
    return list(_MOCK_SEED)


# ---- STIX 2.1 puller -------------------------------------------------

# Pattern shape: STIX indicators carry a `pattern` field like
#   "[ipv4-addr:value = '1.2.3.4']"
# We extract the value with a small regex; this is a subset of STIX
# pattern parsing (real implementations use the stix2 library, but
# adding it for one subset is more supply-chain risk than it's worth).
_STIX_VALUE_RX = re.compile(r"\[(?P<type>[\w-]+):value\s*=\s*'(?P<value>[^']+)'")


def parse_stix_bundle(payload: dict) -> list[IOC]:
    """Convert a STIX 2.1 bundle dict into IOCs. Skips non-indicator objects."""
    iocs: list[IOC] = []
    now = time.time()
    for obj in payload.get("objects", []):
        if obj.get("type") != "indicator":
            continue
        m = _STIX_VALUE_RX.search(obj.get("pattern", ""))
        if not m:
            continue
        kind_map = {
            "ipv4-addr": "ip", "ipv6-addr": "ip",
            "domain-name": "domain", "url": "url",
            "file": "hash_sha256", "email-addr": "email",
        }
        kind = kind_map.get(m.group("type"))
        if not kind:
            continue
        labels = tuple(obj.get("labels", ()))
        confidence = float(obj.get("confidence", 80)) / 100.0
        iocs.append(IOC(
            kind=kind, value=m.group("value"),
            confidence=confidence, source=obj.get("created_by_ref", "stix_feed"),
            tags=labels, last_seen=now,
        ))
    return iocs


def pull_stix_feed(url: str, *, timeout_s: float = 30.0) -> list[IOC]:
    """Fetch a STIX 2.1 bundle from `url` and parse to IOCs.

    Real TAXII 2.1 endpoints require auth + collection paging; this
    minimal puller handles the common case where the feed is a static
    JSON bundle (the FS-ISAC + many ISAC feeds publish this way).
    """
    try:
        with urllib.request.urlopen(url, timeout=timeout_s) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
        _log.warning("STIX pull failed for %s: %s", url, exc)
        return []
    return parse_stix_bundle(body)


# ---- MISP bridge ---------------------------------------------------

def pull_misp(*, types: Optional[list[str]] = None,
              to_ids_only: bool = True,
              since: Optional[str] = None,
              max_pages: int = 1) -> list[IOC]:
    """Pull from MISP via misp_client.get_client() (real if MISP_URL +
    MISP_API_KEY env set, mock otherwise). Same Iterable[IOC] flow.
    """
    from .misp_client import get_client as _misp_client
    client = _misp_client()
    return list(client.fetch_attributes(
        types=types, to_ids_only=to_ids_only,
        since=since, max_pages=max_pages,
    ))


# ---- Recorded Future bridge ----------------------------------------

def pull_recorded_future(*, entity_types: Optional[list[str]] = None) -> list[IOC]:
    """Pull risklists from Recorded Future via recordedfuture_client.
    Returns combined IOC list across the requested entity types.
    Defaults to ('ip', 'domain', 'vulnerability'); production typically
    pulls all five (ip, domain, url, hash, vulnerability).
    """
    from .recordedfuture_client import get_client as _rf_client
    client = _rf_client()
    types = entity_types or ["ip", "domain", "vulnerability"]
    out: list[IOC] = []
    for t in types:
        out.extend(client.fetch_risklist(entity_type=t))
    return out


# ---- Tenable bridge -------------------------------------------------

def pull_tenable(*, severity_threshold: str = "medium",
                 state_filter: tuple[str, ...] = ("OPEN", "REOPENED"),
                 max_pages: int = 1) -> list[IOC]:
    """Pull from Tenable.io / .sc / CSPM via tenable_client.get_client()
    (real if TENABLE_ACCESS_KEY + TENABLE_SECRET_KEY env set, mock
    otherwise). Findings flow through the same Iterable[IOC] pipeline,
    so vuln_discovery sees Tenable VAPT + CSPM alongside CISA KEV /
    EPSS / MISP / Recorded Future without special-casing.
    """
    from .tenable_client import get_client as _tenable_client
    client = _tenable_client()
    return list(client.fetch_findings(
        severity_threshold=severity_threshold,
        state_filter=state_filter,
        max_pages=max_pages,
    ))


# ---- CISA KEV bridge -------------------------------------------------

def pull_cisa_kev(intel: "Optional[object]" = None) -> list[IOC]:
    """Pull the CISA KEV catalog and emit CVE-class IOCs with rich tags (vendor/product/due
    date/ransomware/CVSS band) through the cached ``cve_feeds.CveIntel`` consumer. Pass an
    existing consumer to share its cache; otherwise one is created from the environment."""
    from .cve_feeds import CveIntel
    ti = intel if isinstance(intel, CveIntel) else CveIntel()
    ti.refresh_kev()
    return ti.iocs()


def pull_nvd(intel: "Optional[object]" = None, *, days: int = 7) -> dict:
    """Incremental NVD 2.0 pull (+ EPSS for the KEV set). NVD records are CVE knowledge, not
    IOCs — they live in the consumer and feed vuln_discovery; returns the refresh counts."""
    from .cve_feeds import CveIntel
    ti = intel if isinstance(intel, CveIntel) else CveIntel()
    return {"nvd_updated": ti.refresh_nvd(days=days), "epss_added": ti.refresh_epss(), "last_error": ti.last_error}
