"""Multi-region IOC sync.

Single-process IOC stores don't help an Indian bank running in Mumbai
+ Bengaluru DCs. Each region needs its own ThreatIntelAgent instance
to keep the perimeter/edr matchers fresh on its local cluster, but
the IOC stores must converge — when a Mumbai-detected IOC enters the
store, Bengaluru should have it within seconds.

This module ships:

  - export_for_peer():   produces a self-describing JSON bundle suitable
                         for transport between regions (same envelope
                         as STIX 2.1 + a few AEGIS-specific fields)
  - import_from_peer():  ingests a peer's bundle, deduplicates by
                         (kind, value), keeps the higher-confidence
                         entry on conflict, extends last_seen
  - SyncSession:         pull + push helper that talks HTTP to a peer
                         endpoint (mock + production-shape)

Walking-skeleton transport: in-process function calls + a tiny mock
HTTP server using stdlib http.server (same pattern as
infra/mock_splunk_server.py).

Production: replace the HTTP transport with mTLS over the bank's
internal mesh. Add Lamport-clock-style logical timestamps if you need
strict ordering. Use Kafka MirrorMaker if you want push-based
replication instead of pull.
"""
from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict
from typing import Optional

from .store import IOC, IOCStore


_log = logging.getLogger("aegis.threat_intel.sync")


# ---- Wire format ----------------------------------------------------

def export_for_peer(store: IOCStore, *, source_region: str = "ap-south-1") -> dict:
    """Export the store as a peer-syncable bundle.

    Includes a `source_region` tag so the receiver can attribute IOCs
    back to the originating region (useful for debugging which region
    detected what first).
    """
    iocs = store.all_active()
    return {
        "format": "aegis-ioc-sync/1",
        "source_region": source_region,
        "exported_at": time.time(),
        "count": len(iocs),
        "iocs": [asdict(ioc) for ioc in iocs],
    }


def import_from_peer(store: IOCStore, bundle: dict, *,
                     trust_factor: float = 0.95) -> dict:
    """Ingest a peer's bundle into the local store.

    `trust_factor` slightly discounts the peer's confidence — the local
    store keeps the higher value on conflict, but a peer's "0.92"
    becomes "0.92 * 0.95 = 0.874" before merge to favor locally-
    sourced IOCs in close-call decisions. Set to 1.0 to disable.
    """
    fmt = bundle.get("format")
    if fmt not in ("aegis-ioc-sync/1", "aegis-ioc-sync/2"):
        raise ValueError(f"unknown bundle format: {fmt!r}")
    iocs_data = bundle.get("iocs", [])
    incoming: list[IOC] = []
    for d in iocs_data:
        try:
            incoming.append(IOC(
                kind=d["kind"],
                value=d["value"],
                confidence=float(d.get("confidence", 0.7)) * trust_factor,
                source=f"peer:{bundle.get('source_region', 'unknown')}:{d.get('source', 'unknown')}",
                first_seen=float(d.get("first_seen", 0.0)),
                last_seen=float(d.get("last_seen", time.time())),
                tags=tuple(d.get("tags") or ()),
                ttl_seconds=int(d.get("ttl_seconds", 86400 * 14)),
            ))
        except (KeyError, ValueError, TypeError) as exc:
            _log.warning("skipping bad peer entry: %s", exc)
            continue

    before_total = store.stats().total
    n_added = store.add_many(incoming)
    after_total = store.stats().total
    return {
        "received": len(incoming),
        "merged": n_added,
        "store_before": before_total,
        "store_after": after_total,
        "new_iocs": after_total - before_total,
    }


# ---- HTTP transport (mock peer server) -----------------------------

import http.server


class _SyncHandler(http.server.BaseHTTPRequestHandler):
    server_version = "AEGISSync/1"

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        _log.debug("%s - %s", self.address_string(), format % args)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/sync/export":
            store: IOCStore = self.server.store  # type: ignore[attr-defined]
            region: str = self.server.region     # type: ignore[attr-defined]
            bundle = export_for_peer(store, source_region=region)
            data = json.dumps(bundle).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path == "/sync/health":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok\n")
            return
        self.send_response(404)
        self.end_headers()


class _Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, store: IOCStore, region: str):
        super().__init__(addr, _SyncHandler)
        self.store = store
        self.region = region


class PeerEndpoint:
    """Stand-in production-shape peer endpoint server. In real
    deployment, this is replaced by an authenticated mTLS HTTP service
    inside the bank's internal mesh (Istio / Linkerd).
    """

    def __init__(self, store: IOCStore, region: str = "ap-south-1",
                 host: str = "127.0.0.1", port: int = 0):
        self._server = _Server((host, port), store, region)
        self._thread: Optional[threading.Thread] = None
        self.host = host
        self.port = self._server.server_address[1]
        self.region = region

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="AEGISSyncPeer", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def pull_from_peer(local_store: IOCStore, peer_url: str, *,
                   timeout_s: float = 30.0,
                   trust_factor: float = 0.95) -> dict:
    """HTTP GET the peer's /sync/export and merge into local store."""
    url = peer_url.rstrip("/") + "/sync/export"
    try:
        with urllib.request.urlopen(url, timeout=timeout_s) as resp:
            bundle = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
        _log.warning("peer pull failed (%s): %s", url, exc)
        return {"error": str(exc), "merged": 0}
    return import_from_peer(local_store, bundle, trust_factor=trust_factor)
