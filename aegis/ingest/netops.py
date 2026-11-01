"""Network-operations ingest — device syslog, SNMP traps, flow records, streaming telemetry, configs, topology.

What a bank's network already emits, normalised to one event shape for the network-assurance
detector (``aegis.agents.netops.assurance``):

    syslog      Cisco IOS / IOS-XE / NX-OS system messages, raw (``<189>...%LINK-3-UPDOWN: ...``) or
                JSON-wrapped by a relay (Logstash / Fluent Bit / Telegraf / rsyslog ``{"host","message"}``)
    trap        SNMP traps as JSON from snmptrapd / Telegraf (``linkDown``, ``linkUp``, ``coldStart``,
                ``bgpBackwardTransition``, ``authenticationFailure``, Cisco ``cefcFRURemoved`` …)
    flow        NetFlow v9 / IPFIX / sFlow summaries as JSON (nfdump / pmacct / Telegraf netflow)
    telemetry   model-driven streaming telemetry (gNMI / MDT) interface counters as JSON
    config      a configuration snapshot or change record (RANCID / Oxidized / NSO / a ``show run`` hash)
    topology    LLDP / CDP neighbour rows (``show lldp neighbors detail`` exported as JSON)

One normalised event::

    {"kind": syslog|trap|flow|telemetry|config|topology, "ts": float, "device": str, "iface": str|None,
     "mnemonic": str|None,        # FACILITY-SEV-MNEMONIC, e.g. LINK-3-UPDOWN, BGP-5-ADJCHANGE
     "severity": int|None,        # syslog severity 0..7 (Cisco's middle field)
     "state": up|down|None, "peer": str|None, "msg": str, ...kind-specific fields}

Everything here is pure parsing: nothing is judged. The detector keeps the state (topology, link
history, counters, golden configs) and decides what is a fault, what is a symptom of another fault,
and what is drift. ``NetopsConsumer`` mirrors ``NdrConsumer``: normalise → detector → only its
alerts reach the orchestrator.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

from .base import CONSUMED, AlertCheckpoint, BaseConsumer

# <PRI>SEQ: *Oct 29 20:05:01.123 UTC: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/24, changed state to down
_CISCO_RX = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?\s*"
    r"(?:(?P<seq>\d+):\s*)?"
    r"(?:(?P<host>[A-Za-z][A-Za-z0-9_.-]*):?\s+)??"
    r"(?:\*?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+(?:\d{4}\s+)?\d{2}:\d{2}:\d{2}(?:\.\d+)?)(?:\s+[A-Z]{2,5})?:?\s+)?"
    r"%(?P<facility>[A-Z0-9_]+)-(?:(?P<sub>[A-Z0-9_]+)-)?(?P<sev>[0-7])-(?P<mnemonic>[A-Z0-9_]+):\s*(?P<msg>.*)$"
)
_NXOS_RX = re.compile(   # 2026 Oct 29 20:05:01 UTC: %ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/49 is down (Link failure)
    r"^(?:<(?P<pri>\d{1,3})>)?\s*(?:(?P<host>[A-Za-z][A-Za-z0-9_.-]*):?\s+)?"
    r"(?:(?P<ts>\d{4}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})(?:\s+[A-Z]{2,5})?:?\s+)?"
    r"(?:%(?P<vdc>[A-Z0-9_-]+)\s+)?%(?P<facility>[A-Z0-9_]+)-(?P<sev>[0-7])-(?P<mnemonic>[A-Z0-9_]+):\s*(?P<msg>.*)$"
)
_IFACE_RX = re.compile(
    r"\b(?:Interface\s+|on\s+interface\s+|port\s+)?((?:(?:Ten|Forty|Hundred|TwentyFive)?Gigabit)?Ethernet\d+(?:/\d+){0,3}(?:\.\d+)?"
    r"|(?:Gi|Te|Fo|Hu|Twe|Eth|Et|Fa|Po|Port-channel|Vlan|Tunnel|Loopback|Serial|Bundle-Ether)\d+(?:/\d+){0,3}(?:\.\d+)?)",
    re.I)
_STATE_RX = re.compile(r"changed state to (up|down)|is (up|down)\b|state to (Up|Down)\b|(?:Up|Down)\s*$", re.I)
_PEER_RX = re.compile(r"(?:neighbor|neighbour|Nbr|peer)\s+(\d{1,3}(?:\.\d{1,3}){3}|[A-Fa-f0-9:]{3,}|[A-Za-z0-9_.-]+)", re.I)
_BGP_DOWN_RX = re.compile(r"\bDown\b", re.I)

_MONTHS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}


def _parse_cisco_ts(raw: str | None, year_hint: int | None = None) -> float | None:
    if not raw:
        return None
    parts = raw.replace(",", " ").split()
    try:
        if parts[0].isdigit() and len(parts[0]) == 4:            # NX-OS: 2026 Oct 29 20:05:01
            year, mon, day, hms = int(parts[0]), _MONTHS[parts[1]], int(parts[2]), parts[3]
        elif len(parts) >= 4 and parts[2].isdigit() and len(parts[2]) == 4:   # IOS with year: Oct 29 2026 20:05:01
            mon, day, year, hms = _MONTHS[parts[0]], int(parts[1]), int(parts[2]), parts[3]
        else:                                                     # IOS: Oct 29 20:05:01.123
            mon, day, hms = _MONTHS[parts[0]], int(parts[1]), parts[2]
            year = year_hint or datetime.now(timezone.utc).year
        hh, mm, ss = hms.split(":")
        sec = float(ss)
        return datetime(year, mon, day, int(hh), int(mm), int(sec), int(round((sec % 1) * 1e6)), tzinfo=timezone.utc).timestamp()
    except (KeyError, ValueError, IndexError):
        return None


def _scale_epoch(f: float) -> float | None:
    """Seconds, whatever unit the exporter used (gNMI/MDT send ns, Kafka ms, some tools µs); non-finite → None."""
    if f != f or f in (float("inf"), float("-inf")):
        return None
    while f > 1e11:                                              # ms → s, µs → s, ns → s
        f /= 1000.0
    return f if f >= 0 else None


def _ts_any(v: Any) -> float | None:
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return _scale_epoch(float(v))
    s = str(v).strip()
    if not s:
        return None
    try:
        return _scale_epoch(float(s))
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return _parse_cisco_ts(s)


def _g(rec: dict, *keys: str, default: Any = None) -> Any:
    for k in keys:
        if k in rec and rec[k] not in (None, ""):
            return rec[k]
        # one level of nesting: {"tags": {...}, "fields": {...}} (Telegraf), {"host": {"name": ..}} (ECS)
        for sub in ("tags", "fields", "host", "observer", "network", "interface", "event"):
            v = rec.get(sub)
            if isinstance(v, dict) and k in v and v[k] not in (None, ""):
                return v[k]
    return default


#: Cisco short → long interface prefixes, longest short form first so ``Twe`` wins over ``Te``
_IFACE_LONG = (
    ("TwentyFiveGigE", "twentyfivegige"), ("TwentyFiveGigE", "twe"), ("HundredGigE", "hundredgige"), ("HundredGigE", "hu"),
    ("FortyGigabitEthernet", "fortygigabitethernet"), ("FortyGigabitEthernet", "fo"),
    ("TenGigabitEthernet", "tengigabitethernet"), ("TenGigabitEthernet", "te"),
    ("GigabitEthernet", "gigabitethernet"), ("GigabitEthernet", "gi"), ("FastEthernet", "fastethernet"), ("FastEthernet", "fa"),
    ("Ethernet", "ethernet"), ("Ethernet", "eth"), ("Ethernet", "et"), ("Port-channel", "port-channel"), ("Port-channel", "po"),
    ("Bundle-Ether", "bundle-ether"), ("Bundle-Ether", "be"), ("Loopback", "loopback"), ("Loopback", "lo"),
    ("Vlan", "vlan"), ("Vlan", "vl"), ("Tunnel", "tunnel"), ("Tunnel", "tu"), ("Serial", "serial"), ("Serial", "se"),
)
_IFACE_SPLIT_RX = re.compile(r"^([A-Za-z-]+)\s*(\d[\d/.]*)$")


def canon_iface(name: str | None) -> str | None:
    """``Gi1/0/49`` and ``GigabitEthernet1/0/49`` are the same port: LLDP, syslog, SNMP and telemetry each
    spell it their own way, and topology-aware correlation only works if they all land on one name."""
    if not name:
        return None
    m = _IFACE_SPLIT_RX.match(str(name).strip())
    if not m:
        return str(name).strip()
    prefix, num = m.group(1).lower(), m.group(2)
    for long, short in _IFACE_LONG:
        if prefix == short:
            return f"{long}{num}"
    return f"{m.group(1)}{num}"


def _iface(text: str | None) -> str | None:
    if not text:
        return None
    m = _IFACE_RX.search(text)
    return canon_iface(m.group(1)) if m else None


def _device_from(rec: dict, fallback: str | None = None) -> str:
    return str(_g(rec, "device", "hostname", "host", "name", "sysName", "agent_host", "source", default=fallback or "unknown")).strip()


# ------------------------------------------------------------------ syslog --

# RFC 3164 relay header: <189>Oct 29 20:05:01 SW1 123: *Oct 29 …: %LINK… (host may be a name or an IP)
_RFC3164_RX = re.compile(r"^(?:<(?P<pri>\d{1,3})>)?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>[A-Za-z0-9][A-Za-z0-9_.:-]*)\s+(?P<rest>.*%.*)$")
# RFC 5424: <189>1 2026-10-29T20:05:01Z SW1 - - - %LINK…
_RFC5424_RX = re.compile(r"^(?:<(?P<pri>\d{1,3})>)?1\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+\S+\s+\S+\s+\S+\s+(?:\[[^\]]*\]\s*|-\s+)?(?P<rest>.*%.*)$")


def _strip_relay_header(s: str) -> tuple[str, str | None, float | None]:
    """rsyslog / syslog-ng forward the device line wrapped in their own header; peel it off and keep its host."""
    m = _RFC5424_RX.match(s)
    if m:
        host = m.group("host") if m.group("host") != "-" else None
        return "<%s>%s" % (m.group("pri") or "189", m.group("rest")), host, _ts_any(m.group("ts"))
    m = _RFC3164_RX.match(s)
    if m and "%" in m.group("rest") and not m.group("host").isupper() or (m and "%" in m.group("rest") and ":" not in m.group("host")):
        rest = m.group("rest")
        if not rest.startswith("<"):
            rest = "<%s>%s" % (m.group("pri") or "189", rest)
        return rest, m.group("host"), None
    return s, None, None


def parse_syslog_line(line: str, *, device: str | None = None, ts: float | None = None) -> dict | None:
    """A Cisco IOS / IOS-XE / NX-OS system message → event, or ``None`` if it is not one. Relay headers
    (RFC 3164 / 5424 from rsyslog, syslog-ng, Kiwi) are stripped and their hostname used when the device
    line itself has none."""
    s = line.strip()
    if "%" not in s:
        return None
    s, relay_host, relay_ts = _strip_relay_header(s)
    m = _CISCO_RX.match(s) or _NXOS_RX.match(s)
    if not m:
        return None
    d = m.groupdict()
    msg = d["msg"].strip()
    facility, mnemonic, sev = d["facility"], d["mnemonic"], int(d["sev"])
    sub = d.get("sub")
    full = f"{facility}-{sub + '-' if sub else ''}{sev}-{mnemonic}"
    state = None
    sm = _STATE_RX.search(msg)
    if sm:
        state = next((g for g in sm.groups() if g), sm.group(0)).strip().lower()
        state = "up" if state.startswith("up") else "down" if state.startswith("down") else None
    peer = None
    pm = _PEER_RX.search(msg)
    if pm:
        peer = pm.group(1)
    if facility == "BGP" and mnemonic == "ADJCHANGE":
        state = "down" if _BGP_DOWN_RX.search(msg) else "up"
    if facility == "OSPF" and mnemonic == "ADJCHG":
        state = "down" if re.search(r"to DOWN|from FULL to\b", msg) else ("up" if "to FULL" in msg else state)
    if facility in ("ETHPORT", "LINK", "LINEPROTO") and state is None:
        state = "down" if "DOWN" in mnemonic or "down" in msg.lower() else "up" if "UP" in mnemonic or " up" in msg.lower() else None
    return {
        "kind": "syslog", "ts": ts or _parse_cisco_ts(d.get("ts")) or relay_ts or None,
        "device": device or d.get("host") or relay_host or "unknown",
        "iface": _iface(msg), "facility": facility, "mnemonic": full, "mnemonic_short": mnemonic,
        "severity": sev, "state": state, "peer": peer, "msg": msg[:400],
    }


# ------------------------------------------------------------------- traps --

_TRAP_MAP = {
    "linkdown": ("LINK-3-UPDOWN", "down"), "linkup": ("LINK-3-UPDOWN", "up"),
    "coldstart": ("SYS-5-RESTART", None), "warmstart": ("SYS-5-RESTART", None),
    "authenticationfailure": ("SNMP-3-AUTHFAIL", None),
    "bgpbackwardtransition": ("BGP-5-ADJCHANGE", "down"), "bgpestablished": ("BGP-5-ADJCHANGE", "up"),
    "ospfnbrstatechange": ("OSPF-5-ADJCHG", None),
    "cefcfruremoved": ("PLATFORM-2-FRU_REMOVED", None), "cefcfruinserted": ("PLATFORM-5-FRU_INSERTED", None),
    "ciscoenvmontemperaturenotification": ("ENVM-2-TEMP", None), "ciscoenvmonfannotification": ("ENVM-2-FAN", None),
    "entsensorthresholdnotification": ("PLATFORM-2-SENSOR", None),
}


def _trap(rec: dict) -> dict | None:
    name = _g(rec, "trap", "trapName", "name", "oid_name", "snmpTrapOID", "notification")
    if not name:
        return None
    key = str(name).split("::")[-1].split(".")[0].strip().lower()
    mnemonic, state = _TRAP_MAP.get(key, (f"SNMP-4-{key.upper()[:24]}", None))
    vb = rec.get("varbinds") if isinstance(rec.get("varbinds"), dict) else rec.get("fields") if isinstance(rec.get("fields"), dict) else {}
    iface = _g(rec, "ifDescr", "ifName", "interface", "iface") or (vb or {}).get("ifDescr") or (vb or {}).get("ifName")
    if state is None and key == "ospfnbrstatechange":
        st = str((vb or {}).get("ospfNbrState") or _g(rec, "ospfNbrState", default="")).lower()
        state = "up" if st in ("full", "8") else "down" if st in ("down", "1", "init", "2") else None
    return {"kind": "trap", "ts": _ts_any(_g(rec, "ts", "timestamp", "time", "@timestamp")),
            "device": _device_from(rec), "iface": _iface(str(iface)) if iface else None,
            "facility": mnemonic.split("-")[0], "mnemonic": mnemonic, "mnemonic_short": mnemonic.split("-")[-1],
            "severity": int(mnemonic.split("-")[1]) if mnemonic.split("-")[1].isdigit() else 5,
            "state": state, "peer": _g(rec, "peer", "bgpPeerRemoteAddr", "ospfNbrIpAddr") or (vb or {}).get("bgpPeerRemoteAddr"),
            "msg": f"SNMP trap {name}" + (f" {iface}" if iface else "")}


# ------------------------------------------------------------------- flows --

def _flow(rec: dict) -> dict | None:
    src = _g(rec, "src_ip", "srcaddr", "sourceIPv4Address", "ipv4_src_addr", "sa", "src")
    dst = _g(rec, "dst_ip", "dstaddr", "destinationIPv4Address", "ipv4_dst_addr", "da", "dst")
    if not (src and dst):
        return None
    b = _g(rec, "bytes", "in_bytes", "octetDeltaCount", "ibyt", "octets", default=0)
    p = _g(rec, "packets", "in_pkts", "packetDeltaCount", "ipkt", default=0)
    return {"kind": "flow", "ts": _ts_any(_g(rec, "ts", "timestamp", "flowStartSysUpTime", "first", "@timestamp")),
            "device": _device_from(rec, _g(rec, "exporter", "agent", "exporterIPv4Address")),
            "iface": _g(rec, "iface", "input_snmp", "ingressInterface", "in_if", "ifName"),
            "src": str(src), "dst": str(dst), "dport": int(_g(rec, "dst_port", "dstport", "destinationTransportPort", "dp", default=0) or 0),
            "proto": str(_g(rec, "proto", "protocol", "protocolIdentifier", default="")),
            "bytes": int(float(b or 0)), "packets": int(float(p or 0)),
            "duration_s": float(_g(rec, "duration", "duration_s", "td", default=0) or 0),
            "mnemonic": None, "severity": None, "state": None, "peer": None, "msg": "flow"}


# --------------------------------------------------------------- telemetry --

_COUNTER_KEYS = {
    "in_errors": ("in_errors", "in-errors", "ifInErrors", "input_errors", "rx_errors"),
    "out_errors": ("out_errors", "out-errors", "ifOutErrors", "output_errors", "tx_errors"),
    "crc": ("crc", "in_crc_errors", "in-crc-errors", "crc_errors", "input_crc"),
    "in_discards": ("in_discards", "in-discards", "ifInDiscards", "input_discards"),
    "out_discards": ("out_discards", "out-discards", "ifOutDiscards", "output_discards", "output_drops"),
    "in_octets": ("in_octets", "in-octets", "ifHCInOctets", "ifInOctets", "rx_bytes"),
    "out_octets": ("out_octets", "out-octets", "ifHCOutOctets", "ifOutOctets", "tx_bytes"),
    "speed_bps": ("speed", "speed_bps", "ifHighSpeed", "port-speed", "bandwidth"),
    "util_pct": ("util_pct", "utilization", "in_util_pct", "output_utilization", "utilisation"),
    "oper_status": ("oper_status", "oper-status", "ifOperStatus", "admin_status", "link_state"),
}


def _telemetry(rec: dict) -> dict | None:
    iface = _g(rec, "iface", "interface", "ifName", "name", "ifDescr")
    if not iface:
        return None
    counters: dict[str, float] = {}
    for key, names in _COUNTER_KEYS.items():
        v = _g(rec, *names)
        if v is None:
            continue
        if key == "oper_status":
            s = str(v).lower()
            counters[key] = 1.0 if s in ("up", "1", "true") else 0.0 if s in ("down", "2", "false", "lower-layer-down") else -1.0
            continue
        try:
            counters[key] = float(v)
        except (TypeError, ValueError):
            continue
    if not counters:
        return None
    speed = counters.get("speed_bps")
    if speed is not None and speed < 1e6:                        # ifHighSpeed is in Mbit/s
        counters["speed_bps"] = speed * 1e6
    return {"kind": "telemetry", "ts": _ts_any(_g(rec, "ts", "timestamp", "time", "@timestamp")),
            "device": _device_from(rec), "iface": _iface(str(iface)) or str(iface), "counters": counters,
            "mnemonic": None, "severity": None, "peer": None, "msg": "telemetry",
            "state": "up" if counters.get("oper_status") == 1.0 else "down" if counters.get("oper_status") == 0.0 else None}


# ------------------------------------------------------------------ config --

def _config(rec: dict) -> dict | None:
    text = _g(rec, "config", "running_config", "config_text", "diff")
    chash = _g(rec, "config_hash", "hash", "sha256")
    if text is None and chash is None and str(_g(rec, "kind", "type", "event", default="")).lower() not in ("config", "config_change", "configchange"):
        return None
    if text is not None and chash is None:
        chash = hashlib.sha256(str(text).encode("utf-8", "replace")).hexdigest()
    return {"kind": "config", "ts": _ts_any(_g(rec, "ts", "timestamp", "time", "@timestamp", "changed_at")),
            "device": _device_from(rec), "iface": None, "config_hash": str(chash) if chash else None,
            "config_text": str(text)[:20000] if text is not None else None,
            "user": _g(rec, "user", "username", "changed_by", "actor"),
            "change_ticket": _g(rec, "change_ticket", "ticket", "change_id", "cr"),
            "source_ip": _g(rec, "source_ip", "from", "client_ip"),
            "mnemonic": "SYS-5-CONFIG_I", "severity": 5, "state": None, "peer": None,
            "msg": f"configuration {'changed' if text is not None or _g(rec, 'event') else 'snapshot'}"}


# ---------------------------------------------------------------- topology --

def _topology(rec: dict) -> dict | None:
    local = _g(rec, "local_device", "device", "hostname", "local")
    local_if = _g(rec, "local_iface", "local_interface", "local_port", "port")
    nbr = _g(rec, "neighbor", "neighbour", "remote_device", "remote", "neighbor_device", "sysname")
    nbr_if = _g(rec, "neighbor_iface", "remote_iface", "remote_interface", "port_id", "remote_port")
    if not (local and nbr and (local_if or nbr_if)):
        return None
    return {"kind": "topology", "ts": _ts_any(_g(rec, "ts", "timestamp", "@timestamp")),
            "device": str(local), "iface": _iface(str(local_if)) or (str(local_if) if local_if else None),
            "neighbor": str(nbr), "neighbor_iface": _iface(str(nbr_if)) or (str(nbr_if) if nbr_if else None),
            "role": _g(rec, "role", "device_role", "tier"), "neighbor_role": _g(rec, "neighbor_role", "remote_role"),
            "site": _g(rec, "site", "location"), "users": _g(rec, "users", "endpoints", "hosts"),
            "mnemonic": None, "severity": None, "state": None, "peer": str(nbr), "msg": "lldp/cdp neighbour"}


# ---------------------------------------------------------------- dispatch --

def normalize(record: Any) -> dict | None:
    """Any network-ops record (raw syslog line or one JSON object) → one event, or ``None``."""
    if isinstance(record, str):
        return parse_syslog_line(record)
    if not isinstance(record, dict):
        return None
    kind = str(_g(record, "kind", "type", "record_type", default="")).lower()
    if kind == "topology" or ("neighbor" in record or "neighbour" in record or "local_iface" in record):
        ev = _topology(record)
        if ev:
            return ev
    msg = _g(record, "message", "msg", "raw", "syslog", "log")
    if isinstance(msg, str) and "%" in msg:
        ev = parse_syslog_line(msg, device=_g(record, "device", "hostname", "host", "sysName"),
                               ts=_ts_any(_g(record, "ts", "timestamp", "@timestamp", "time")))
        if ev:
            return ev
    if kind == "trap" or any(k in record for k in ("trap", "trapName", "snmpTrapOID", "varbinds")):
        ev = _trap(record)
        if ev:
            return ev
    if kind in ("config", "config_change") or any(k in record for k in ("running_config", "config_hash", "config_text")):
        ev = _config(record)
        if ev:
            return ev
    if kind in ("flow", "netflow", "ipfix", "sflow") or any(k in record for k in ("srcaddr", "sourceIPv4Address", "ipv4_src_addr", "src_ip")):
        ev = _flow(record)
        if ev:
            return ev
    ev = _telemetry(record)
    if ev:
        return ev
    return None


class NetopsConsumer(BaseConsumer):
    """Normalise → network-assurance detector → only its alerts are yielded (deduped like any source)."""

    name = "netops"

    def __init__(self, *, detector: Any = None, checkpoint: AlertCheckpoint | None = None):
        super().__init__(checkpoint)
        self.detector = detector or shared_detector()
        self.events = 0

    def fetch(self, *, lines: Iterable[str] | None = None, path: str | Path | None = None) -> Iterator[Any]:
        sources: list[Iterable[str]] = []
        if lines is not None:
            sources.append(lines)
        elif path is not None:
            for one in [x.strip() for x in str(path).split(",") if x.strip()]:
                p = Path(one)
                sources.append((gzip.open if p.suffix == ".gz" else open)(p, "rt", encoding="utf-8", errors="replace"))
        else:
            raise ValueError("NetopsConsumer.fetch needs lines= or path=")
        for src in sources:
            for ln in src:
                ln = ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                if ln[0] in "{[":
                    try:
                        obj = json.loads(ln)
                    except json.JSONDecodeError:
                        self.skipped_invalid += 1
                        continue
                    recs = obj if isinstance(obj, list) else obj.get("records") if isinstance(obj, dict) and isinstance(obj.get("records"), list) else [obj]
                    yield from recs
                else:
                    yield ln                                     # a raw syslog line

    def normalize(self, record: Any) -> Any:
        ev = normalize(record)
        if ev is None:
            return CONSUMED
        self.events += 1
        return self.detector.observe(ev) or CONSUMED


_shared: Any = None


def _state_path() -> Optional[Path]:
    """Where the detector checkpoints (AEGIS_NETOPS_STATE; default next to the audit log; empty string disables)."""
    raw = os.environ.get("AEGIS_NETOPS_STATE")
    if raw is not None:
        return Path(raw) if raw.strip() else None
    audit = os.environ.get("AEGIS_AUDIT_PATH", "").strip()
    return Path(audit).parent / "netops-state.json" if audit else None


def shared_detector() -> Any:
    """One detector per process: pushed and file-read records share topology, link history and counters.
    On first use it restores the previous process's checkpoint, so a restart mid-outage keeps the open
    incident (no re-alert storm) and the learned topology."""
    global _shared
    if _shared is None:
        from ..agents.netops.assurance import NetworkAssurance
        _shared = NetworkAssurance.from_env()
        sp = _state_path()
        if sp is not None and sp.exists():
            n = _shared.restore_from(sp)
            logger.info("[netops] restored detector state from %s (%d open incident(s))", sp, n)
    return _shared


_last_checkpoint = 0.0


def checkpoint_shared_detector(every_s: float = 5.0, *, force: bool = False) -> bool:
    """Called from the service loop: write the checkpoint at most every ``every_s`` seconds. Never raises."""
    global _last_checkpoint
    sp = _state_path()
    if _shared is None or sp is None:
        return False
    now = time.time()
    if not force and now - _last_checkpoint < every_s:
        return False
    try:
        _shared.checkpoint(sp)
        _last_checkpoint = now
        return True
    except OSError as e:
        logger.warning("[netops] checkpoint to %s failed: %s", sp, e)
        return False


def reset_shared_detector() -> None:
    global _shared
    _shared = None


__all__ = ["NetopsConsumer", "canon_iface", "normalize", "parse_syslog_line", "shared_detector", "reset_shared_detector"]
