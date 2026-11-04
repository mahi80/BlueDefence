"""MISP REST API consumer.

MISP (Malware Information Sharing Platform) is the most-deployed
open-source threat-intel platform; FS-ISAC, CERT-In, and many
peer-bank exchanges publish MISP feeds. AEGIS' threat_intel agent
treats MISP as one feed source among several (alongside CISA KEV,
FIRST.org EPSS, and STIX bundles).

API contract (MISP 2.4.x):
  POST /attributes/restSearch
    headers: Authorization: <api_key>
              Accept: application/json
    body: { returnFormat: "json", limit, page, type[], to_ids, ... }
  Response: { response: { Attribute: [...] } }

Each Attribute has: type (ip-src|ip-dst|domain|md5|sha256|url|email-src|...),
value, comment, timestamp, to_ids (whether suitable for IDS), tags[],
event_id, distribution.

Walking-skeleton: pulls a single page of attributes, converts to AEGIS
IOC objects. Production extends with paging, event-level tag filters
(MISP "warning-list" exclusion), and the full MISP galaxy taxonomy.
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


_log = logging.getLogger("aegis.misp")


# Map MISP attribute types to AEGIS IOC kinds.
_TYPE_MAP: dict[str, str] = {
    "ip-src":     "ip",
    "ip-dst":     "ip",
    "domain":     "domain",
    "hostname":   "domain",
    "url":        "url",
    "md5":        "hash_md5",
    "sha1":       "hash_sha1",     # was coalesced into hash_sha256 and then rejected for being 40 hex (round 7 D-12)
    "sha256":     "hash_sha256",
    "email-src":  "email",
    "email-dst":  "email",
}


@dataclass
class MISPConfig:
    base_url: str
    api_key: str
    verify_tls: bool = True
    timeout_s: float = 30.0
    page_size: int = 1000

    @classmethod
    def from_env(cls) -> Optional["MISPConfig"]:
        url = os.environ.get("MISP_URL")
        api_key = os.environ.get("MISP_API_KEY")
        if not (url and api_key):
            return None
        return cls(
            base_url=url,
            api_key=api_key,
            verify_tls=os.environ.get("MISP_VERIFY_TLS", "true").lower() != "false",
        )


class MISPClient:
    """Thin REST client for MISP attributes endpoint."""

    name = "misp"

    def __init__(self, config: MISPConfig):
        self._cfg = config

    def fetch_attributes(
        self,
        *,
        types: Optional[list[str]] = None,
        to_ids_only: bool = True,
        since: Optional[str] = None,    # e.g., "7d", "24h"
        max_pages: int = 1,
    ) -> Iterable[IOC]:
        """Pull attributes matching filters; yield as AEGIS IOC objects.

        - types: restrict to specific MISP attribute types. Default = all
          mapped types.
        - to_ids_only: skip attributes flagged as informational (to_ids
          = False); production-default since informational entries
          aren't meant for blocking.
        - since: time window (e.g., "7d") — limits backfill volume.
        - max_pages: paging cap.
        """
        url = self._cfg.base_url.rstrip("/") + "/attributes/restSearch"
        types = types or list(_TYPE_MAP.keys())

        for page in range(1, max_pages + 1):
            body = {
                "returnFormat": "json",
                "limit": self._cfg.page_size,
                "page": page,
                "type": types,
                "to_ids": 1 if to_ids_only else 0,
                # MISP warninglists (top sites, CDNs, cloud ranges, public resolvers): an event that lists
                # sharepoint.com or a CDN must not turn the whole provider "known bad" (round 7 D-5)
                "enforceWarninglist": True,
            }
            if since:
                body["last"] = since

            req = urllib.request.Request(
                url,
                data=json.dumps(body).encode("utf-8"),
                method="POST",
                headers={
                    "Authorization": self._cfg.api_key,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": "aegis-misp-client/1",
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=self._cfg.timeout_s) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
            except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
                _log.warning("MISP fetch_attributes failed (page %d): %s", page, exc)
                return

            attrs = (payload.get("response") or {}).get("Attribute") or []
            if not attrs:
                return
            now = time.time()
            for a in attrs:
                kind = _TYPE_MAP.get(a.get("type", ""))
                value = a.get("value", "")
                if not (kind and value):
                    continue
                tags = []
                for tag in (a.get("Tag") or []):
                    name = tag.get("name") if isinstance(tag, dict) else str(tag)
                    if name:
                        tags.append(name)
                yield IOC(
                    kind=kind,
                    value=value,
                    confidence=0.85,    # MISP doesn't carry per-attribute confidence
                    source=f"misp:event:{a.get('event_id', '?')}",
                    first_seen=float(a.get("timestamp", now)),
                    last_seen=now,
                    tags=tuple(tags),
                )
            if len(attrs) < self._cfg.page_size:
                return  # last page


# ---- Mock for offline / CI demo ------------------------------------

class MockMISPClient:
    """Returns a small canned set of MISP-shaped attributes so the
    threat_intel pipeline is testable without a real MISP install.
    """

    name = "misp_mock"

    def fetch_attributes(self, *, types=None, to_ids_only=True,
                         since=None, max_pages=1) -> Iterable[IOC]:
        now = time.time()
        canned: list[IOC] = [
            IOC(kind="ip",       value="198.51.100.42", confidence=0.85,
                source="misp:event:1001", first_seen=now, last_seen=now,
                tags=("misp:type=botnet", "tlp:amber")),
            IOC(kind="domain",   value="threat-intel.example.test", confidence=0.85,
                source="misp:event:1002", first_seen=now, last_seen=now,
                tags=("misp:malware-family=trickbot", "tlp:amber")),
            IOC(kind="hash_md5", value="a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3", confidence=0.85,
                source="misp:event:1003", first_seen=now, last_seen=now,
                tags=("misp:malware-family=ryuk",)),
        ]
        return canned


def get_client() -> "MISPClient | MockMISPClient":
    cfg = MISPConfig.from_env()
    if cfg is None:
        return MockMISPClient()
    return MISPClient(cfg)
