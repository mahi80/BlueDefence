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
import json
import os
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
                "egress_ts": _float(evt.get("ts") or evt.get("UtcTimeEpoch")) or _utc(evt.get("UtcTime"))}
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
        # osquery's `parent` is a PID; the name, when the pack joins it in, is parent_name / parent_path
        # (the PID was taken for a process name; review round 3 S3-25)
        parent = row.get("parent_name") or row.get("parent_path") or ""
        return {**base, "parent_process": _basename(parent), "parent_pid": row.get("parent"),
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

    def __init__(self, window_s: float = 3600.0, *, max_pairs: int = 50_000, max_points: int = 1_000):
        self.window_s = window_s
        # bounded: (host, dest) pairs and points per pair — it grew without limit (review round 3 S3-25)
        from ..shared.bounded import BoundedDict
        self._log: BoundedDict = BoundedDict(max_pairs)
        self.max_points = max_points

    def add(self, host: Optional[str], dest: Optional[str], ts: Optional[float]) -> list[float]:
        if dest is None or ts is None:
            return []
        key = (host, dest)
        series = [t for t in self._log.get(key, []) if ts - t <= self.window_s]
        series.append(ts)
        self._log[key] = series[-self.max_points:]
        return self._log[key]

    def enrich(self, alert: dict) -> dict:
        """If the alert is an egress connect, fold it into the window and attach
        ``egress_connect_times`` for the scorer."""
        if alert.get("dest_ip") and alert.get("egress_ts") is not None:
            series = self.add(alert.get("host"), alert["dest_ip"], alert["egress_ts"])
            alert["egress_connect_times"] = series
        return alert


_AGG: BeaconAggregator | None = None


def _utc(v: object) -> float | None:
    """Sysmon's ``UtcTime`` ("2026-11-03 10:30:00.123") as epoch seconds — real EID 3 events carry no ``ts``,
    so the beacon series was never built from stock Sysmon (round 4 S4-8)."""
    if not isinstance(v, str) or not v.strip():
        return None
    from datetime import UTC, datetime
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(v.strip(), fmt).replace(tzinfo=UTC).timestamp()
        except ValueError:
            continue
    return None


def to_alert(raw: dict) -> dict | None:
    """One collector record — a Sysmon event (``EventID`` / ``event_id``) or an osquery result log line (``name`` +
    ``columns``) — as an EDR alert with an id, or None for a shape this module does not know. This is what wires the
    normaliser into ingest: it existed but nothing called it (review round 3 S3-25). Egress connects are folded
    into a bounded per-(host, dest) series for the beacon scorer."""
    global _AGG
    if not isinstance(raw, dict):
        return None
    if "EventID" in raw or "event_id" in raw:
        evt = {**(raw.get("EventData") if isinstance(raw.get("EventData"), dict) else {}), **raw}
        evt.setdefault("event_id", evt.get("EventID"))
        alert = from_sysmon(evt)
    elif isinstance(raw.get("columns"), dict) and raw.get("name"):
        query = str(raw["name"])
        for known in ("exec_lolbin_events", "net_egress_events", "persistence_authorized_keys", "webshell_webroot_scripts",
                      *_PERSIST_QUERIES):
            if query.endswith(known):
                query = known
                break
        row = {**raw["columns"], "_host": raw.get("hostIdentifier")}
        alert = from_osquery(query, row)
        alert["timestamp"] = raw.get("unixTime") or raw.get("calendarTime")
    else:
        return None
    if alert.get("dest_ip") is not None:
        if _AGG is None:
            _AGG = BeaconAggregator()
        _AGG.enrich(alert)
    if len(alert) <= 3:                       # only source/host/host_class: nothing a scorer can use
        return None
    # Pre-filter: every Sysmon / osquery row used to become an LLM investigation (a notepad launch, one DNS
    # query), and storm mode then deferred real alerts behind them. Only a row a scorer finds something in is an
    # alert; the rest has been folded into the beacon window above and is done (round 4 S4-8).
    # AEGIS_EDR_PREFILTER=0 sends every row to the specialist (a pilot that wants to see what the scorers miss).
    from .tools import run_all_tools
    try:
        quiet = all(getattr(r, "weight", "low") == "low" for r in run_all_tools(alert))
    except Exception:  # noqa: BLE001 — a scorer that cannot run must not drop the row: let the specialist see it
        quiet = False
    if quiet and os.environ.get("AEGIS_EDR_PREFILTER", "1").strip().lower() not in ("0", "off", "false", "no"):
        return None
    # the whole canonical event is hashed: cutting the repr at 4000 chars left the host and time out of the id once a
    # command line was long (an encoded stager), so a second host's compromise deduped away (round 7 G-4)
    try:
        canon = json.dumps(raw, sort_keys=True, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        canon = repr(sorted(raw.items(), key=lambda kv: str(kv[0])))
    digest = hashlib.sha256(canon.encode("utf-8", "surrogatepass")).hexdigest()[:16]
    return {"id": f"edr-{digest}", "alert_type": "host_endpoint", **alert}
