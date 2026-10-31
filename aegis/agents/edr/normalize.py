"""Normalizer / event-shipper: raw Sysmon + osquery rows -> edr alert dicts.

The edr scorers in :mod:`aegis.agents.edr.tools` consume a flat ``alert`` dict.
This module maps the two collectors shipped under ``edr/collectors/``
(``sysmon-aegis.xml`` and ``aegis-host.pack.json``) onto that shape, and
aggregates egress connects so ``beacon_periodicity`` can score a (host, dest)
time series.

All inputs are host telemetry — untrusted. The edr agent already wraps the
assembled alert with the injection-defense layer before it reaches the LLM;
this module only reshapes fields, it never executes anything from them.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Iterable, Optional


# --------------------------------------------------------------------- helpers
def _basename(p: Optional[str]) -> str:
    return (p or "").replace("\\", "/").rsplit("/", 1)[-1]


def _int(v) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _float(v) -> Optional[float]:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _reg_leaf(target_object: str) -> str:
    return (target_object or "").replace("/", "\\").rsplit("\\", 1)[-1]


def ssh_fingerprint(key_line: Optional[str]) -> Optional[str]:
    """Stable fingerprint for an authorized_keys line. Stand-in: SHA-256 of the
    key material. Production would decode the base64 blob and hash that (the
    canonical ``SHA256:`` fingerprint); a stable hash is enough for baseline diff."""
    if not key_line:
        return None
    parts = key_line.split()
    blob = parts[1] if len(parts) >= 2 else key_line
    return "SHA256:" + hashlib.sha256(blob.encode()).hexdigest()[:43]


# ------------------------------------------------------------------- sysmon map
def from_sysmon(evt: dict) -> dict:
    """Map one parsed Sysmon event to a partial alert.

    ``evt`` = ``{"event_id": int, "host": str, **EventData}`` where EventData keys
    are the native Sysmon field names (Image, ParentImage, CommandLine, ...).
    A NetworkConnect carries a single ``egress_ts``; run it through
    :class:`BeaconAggregator` to build ``egress_connect_times``.
    """
    eid = _int(evt.get("event_id"))
    base = {"source": "sysmon", "host": evt.get("host") or evt.get("Computer"),
            "host_class": evt.get("host_class")}
    if eid == 1:  # ProcessCreate
        return {**base,
                "parent_process": _basename(evt.get("ParentImage")),
                "child_process": _basename(evt.get("Image")),
                "cmdline": evt.get("CommandLine", "")}
    if eid == 3:  # NetworkConnect
        return {**base,
                "dest_ip": evt.get("DestinationIp"),
                "dst_port": _int(evt.get("DestinationPort")),
                "egress_ts": _float(evt.get("ts") or evt.get("UtcTimeEpoch"))}
    if eid == 22:  # DnsQuery
        q = evt.get("QueryName", "")
        return {**base, "dns_queries": [q], "dest_domain": q}
    if eid == 11:  # FileCreate
        return {**base, "file_path": evt.get("TargetFilename")}
    if eid in (12, 13):  # RegistryEvent -> autostart/persistence
        return {**base, "autostart_entries": [{
            "name": _reg_leaf(evt.get("TargetObject", "")),
            "path": evt.get("Details") or evt.get("TargetObject"),
            "source": "registry"}]}
    return base


# ------------------------------------------------------------------ osquery map
_PERSIST_QUERIES = {
    "persistence_launchd", "persistence_startup_items", "persistence_services_win",
    "persistence_scheduled_tasks_win", "persistence_systemd", "persistence_crontab",
}


def from_osquery(query: str, row: dict) -> dict:
    """Map one osquery result row (from a named pack query) to a partial alert."""
    base = {"source": f"osquery:{query}", "host": row.get("_host") or row.get("hostIdentifier"),
            "host_class": row.get("host_class")}
    if query in _PERSIST_QUERIES:
        name = row.get("name") or row.get("id") or row.get("label") or row.get("command")
        path = (row.get("path") or row.get("program") or row.get("fragment_path")
                or row.get("action") or row.get("command"))
        return {**base, "autostart_entries": [{"name": name, "path": path, "source": query}]}
    if query == "persistence_authorized_keys":
        return {**base, "ssh_key_fingerprint": ssh_fingerprint(row.get("key")),
                "ssh_key_uid": row.get("uid")}
    if query == "exec_lolbin_events":
        return {**base, "parent_process": _basename(row.get("parent")),
                "child_process": _basename(row.get("path")), "cmdline": row.get("cmdline", "")}
    if query == "net_egress_events":
        return {**base, "dest_ip": row.get("remote_address"),
                "dst_port": _int(row.get("remote_port")), "egress_ts": _float(row.get("time"))}
    if query == "webshell_webroot_scripts":
        return {**base, "file_path": row.get("path"), "file_hash_current": row.get("sha256")}
    if query == "macos_tcc_grants":
        return {**base, "tcc_service": row.get("service"), "tcc_client": row.get("client"),
                "tcc_allowed": _int(row.get("allowed"))}
    if query == "net_etc_hosts":
        return {**base, "file_path": "/etc/hosts"}
    if query == "net_dns_resolvers":
        return {**base, "file_path": "/etc/resolv.conf"}
    return base


# --------------------------------------------------------------- beacon window
class BeaconAggregator:
    """Accumulates egress connect timestamps per (host, dest) within a window so
    ``beacon_periodicity`` sees a series instead of a single connect."""

    def __init__(self, window_s: float = 3600.0):
        self.window_s = window_s
        self._log: dict[tuple, list[float]] = defaultdict(list)

    def add(self, host: Optional[str], dest: Optional[str], ts: Optional[float]) -> list[float]:
        if dest is None or ts is None:
            return []
        key = (host, dest)
        series = [t for t in self._log[key] if ts - t <= self.window_s]
        series.append(ts)
        self._log[key] = series
        return series

    def enrich(self, alert: dict) -> dict:
        """If the alert is an egress connect, fold it into the window and attach
        ``egress_connect_times`` for the scorer."""
        if alert.get("dest_ip") and alert.get("egress_ts") is not None:
            series = self.add(alert.get("host"), alert["dest_ip"], alert["egress_ts"])
            alert["egress_connect_times"] = series
        return alert
