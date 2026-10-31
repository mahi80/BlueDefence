"""Live threat-intel fetchers — FIRST.org EPSS + CISA KEV catalog.

Used by aegis/scripts/refresh_threat_intel.py to refresh the local CVE
DB embedded in tools.py. NOT called from the scan hot path — keeping
the scan offline-deterministic. The scan reads from the static DB; this
module is what populates that DB on a scheduled refresh.

Both feeds are free and public:
  - EPSS:  https://api.first.org/data/v1/epss?cve=CVE-XXXX-NNNN
           (CC BY 4.0; daily-updated probabilities)
  - KEV:   https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
           (public domain; daily-updated catalog)

urllib only — no extra deps, consistent with the supply-chain hardening
principle in the project plan.
"""
from __future__ import annotations

import json
import logging
import urllib.request
from typing import Optional


_log = logging.getLogger("aegis.threat_intel")

EPSS_API = "https://api.first.org/data/v1/epss"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_epss(cve_id: str, *, timeout_s: float = 10.0) -> Optional[float]:
    """Return EPSS probability [0,1] for a CVE id, or None if unknown."""
    url = f"{EPSS_API}?cve={cve_id}"
    try:
        with urllib.request.urlopen(url, timeout=timeout_s) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        _log.warning("EPSS fetch failed for %s: %s", cve_id, exc)
        return None
    data = payload.get("data") or []
    if not data:
        return None
    try:
        return float(data[0].get("epss", 0.0))
    except (TypeError, ValueError):
        return None


def fetch_kev_catalog(*, timeout_s: float = 30.0) -> set[str]:
    """Return the set of CVE ids in the CISA KEV catalog. Empty on error."""
    try:
        with urllib.request.urlopen(KEV_FEED, timeout=timeout_s) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        _log.warning("KEV fetch failed: %s", exc)
        return set()
    return {entry["cveID"] for entry in payload.get("vulnerabilities", []) if "cveID" in entry}


def is_kev(cve_id: str, kev_set: set[str]) -> bool:
    """Membership check — separate so callers fetch the catalog once and reuse."""
    return cve_id in kev_set
