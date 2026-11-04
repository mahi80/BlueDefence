"""Executable Sigma over OCSF (integration plan #7): SigmaHQ rules as a first-pass detector on normalised events.

The community's detection rules — 3,000+ in SigmaHQ, plus whatever the bank's own SOC writes — run directly on every
OCSF event AEGIS ingests (``/ingest/ocsf``, Kafka ``ocsf`` topics, OCSF connectors). A hit does not decide anything
by itself: it is attached to the alert (``sigma``: rule id, title, level, ATT&CK techniques), raises the alert's
severity to the rule's level, and the swarm and Agent Q investigate it like any other signal.

What is supported (the large majority of SigmaHQ rules):

* detection maps, lists of maps, keyword lists, ``null`` values;
* modifiers ``contains``, ``startswith``, ``endswith``, ``all``, ``re``, ``cidr``, ``exists``, ``windash``,
  ``lt`` / ``lte`` / ``gt`` / ``gte``; ``*`` / ``?`` wildcards; case-insensitive string matching;
* conditions with ``and`` / ``or`` / ``not``, parentheses, ``1 of x*``, ``all of x*``, ``1 of them``, ``all of them``.

Not supported — the rule is skipped and counted, never half-evaluated: aggregations (``| count() …``), ``near``,
``base64`` / ``base64offset`` / ``utf16*`` / ``wide`` / ``fieldref`` / ``expand`` modifiers, Sigma correlation rules.

The logsource decides which OCSF classes a rule sees (``process_creation`` → Process Activity 1007, ``proxy`` /
``webserver`` → HTTP Activity 4002 …), and Sigma field names map onto OCSF attributes (``CommandLine`` →
``process.cmd_line``, ``ParentImage`` → ``process.parent_process.file.path`` …). A field with no mapping is looked up
in the event's ``unmapped`` object, then at the top level, by its Sigma name. A field the event does not carry
never matches (Sigma semantics). Field values are capped at 8 KB before matching; rules come from the bank's own
checkout (``AEGIS_SIGMA_RULES``), so their regular expressions are trusted the way its SIEM trusts them.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import logging
import os
import re
import threading
import unicodedata
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus

logger = logging.getLogger("aegis.detect.sigma")

MAX_VALUE = 32768                   # Windows command lines reach 32 K; matching is linear, so the cap can be generous
_LEVELS = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

#: logsource (category / service / product) → OCSF class_uids a rule applies to
_CATEGORY_CLASSES: dict[str, tuple[int, ...]] = {
    "process_creation": (1007,), "process_access": (1007,), "process_termination": (1007,), "image_load": (1007,),
    "create_remote_thread": (1007,), "driver_load": (1007,),
    "file_event": (1001,), "file_change": (1001,), "file_delete": (1001,), "file_rename": (1001,), "file_access": (1001,),
    "registry_event": (201001, 201002), "registry_set": (201001, 201002), "registry_add": (201001, 201002),
    "registry_delete": (201001, 201002),
    "network_connection": (4001,), "firewall": (4001,), "dns_query": (4003,), "dns": (4003,),
    "proxy": (4002,), "webserver": (4002,), "application": (4002, 6003),
    "ps_script": (1009,), "ps_module": (1009,), "ps_classic_start": (1009, 1008), "ps_classic_provider_start": (1009, 1008),
    "pipe_created": (1008,), "wmi_event": (1008,), "create_stream_hash": (1001,), "raw_access_thread": (1001,),
    "antivirus": (2004,), "sysmon_status": (1008,), "sysmon_error": (1008,),
}
_SERVICE_CLASSES: dict[str, tuple[int, ...]] = {
    "cloudtrail": (6003,), "azureactivity": (6003,), "activitylogs": (6003,), "gcp.audit": (6003,), "okta": (3002, 3001, 6003),
    "signinlogs": (3002,), "auditlogs": (3001, 6003), "security": (3002, 3001, 1007), "sysmon": (1007, 1001, 4001, 4003),
    "dns": (4003,), "zeek": (4001, 4002, 4003), "smb_files": (4006,), "ssh": (3002,), "sshd": (3002,), "auth": (3002,),
    "auditd": (1007, 1001, 1008), "syslog": (1008,), "http": (4002,), "dce_rpc": (4001,), "kerberos": (3002,),
    "audit": (6003,), "aaa": (3002, 6003), "event": (4001, 1008), "windefend": (2004, 1008),
    "powershell": (1009, 1008), "powershell-classic": (1009, 1008),
}
#: categories whose OCSF class carries an activity_id that tells them apart (Process Activity: 1 Launch, 2 Terminate,
#: 3 Open, 4 Inject; File System Activity: 1 Create, 2 Read, 3 Update, 4 Delete, 5 Rename). An event without an
#: activity_id is not gated.
_CATEGORY_ACTIVITIES: dict[str, tuple[int, ...]] = {
    "process_creation": (1,), "process_termination": (2,), "process_access": (3,), "create_remote_thread": (4,),
    "file_event": (1, 3), "file_access": (2,), "file_delete": (4,), "file_rename": (5,),
}
#: products whose every other service is an event log (Windows channels, a Linux host's journal)
_PRODUCT_DEFAULT: dict[str, tuple[int, ...]] = {"windows": (1008,), "linux": (1007, 1008), "macos": (1007, 1008)}

#: Sigma field → OCSF attribute paths, first that exists wins
FIELD_MAP: dict[str, tuple[str, ...]] = {
    "image": ("process.file.path", "process.name"),
    "commandline": ("process.cmd_line",),
    "currentdirectory": ("process.file.parent_folder",),
    "originalfilename": ("process.file.original_name", "process.file.name"),
    "product": ("process.file.product.name",),
    "company": ("process.file.company_name",),
    "description": ("process.file.desc",),
    "parentimage": ("process.parent_process.file.path", "process.parent_process.name"),
    "parentcommandline": ("process.parent_process.cmd_line",),
    "user": ("actor.user.name", "user.name", "process.user.name"),
    "integritylevel": ("process.integrity",),
    "processid": ("process.pid",),
    "parentprocessid": ("process.parent_process.pid",),
    "hashes": ("process.file.hashes",),
    "targetfilename": ("file.path",),
    "sourceip": ("src_endpoint.ip",),
    "sourceport": ("src_endpoint.port",),
    "sourcehostname": ("src_endpoint.hostname",),
    "destinationip": ("dst_endpoint.ip",),
    "destinationport": ("dst_endpoint.port",),
    "destinationhostname": ("dst_endpoint.hostname", "dst_endpoint.domain"),
    "queryname": ("query.hostname",),
    "querytype": ("query.type",),
    "computer": ("device.hostname",),
    "computername": ("device.hostname",),
    "eventid": ("metadata.event_code", "unmapped.EventID"),
    "targetusername": ("user.name",),
    "subjectusername": ("actor.user.name",),
    "ipaddress": ("src_endpoint.ip",),
    "logontype": ("logon_type_id", "unmapped.LogonType"),
    "targetobject": ("reg_key.path", "reg_value.path"),
    "details": ("reg_value.data",),
    "c-uri": ("http_request.url.url_string", "http_request.url.path"),
    "cs-uri": ("http_request.url.url_string", "http_request.url.path"),
    "cs-uri-stem": ("http_request.url.path",),
    "cs-uri-query": ("http_request.url.query_string",),
    "c-uri-query": ("http_request.url.query_string",),
    "c-uri-extension": ("http_request.url.path",),
    "cs-method": ("http_request.http_method",),
    "cs-user-agent": ("http_request.user_agent",),
    "c-useragent": ("http_request.user_agent",),
    "cs-host": ("http_request.url.hostname",),
    "cs-referrer": ("http_request.referrer",),
    "sc-status": ("http_response.code",),
    "c-ip": ("src_endpoint.ip",),
    "r-dns": ("dst_endpoint.hostname", "http_request.url.hostname"),
    "eventname": ("api.operation",),
    "eventsource": ("api.service.name",),
    "useridentity.type": ("actor.user.type",),
    "useridentity.arn": ("actor.user.uid",),
    "sourceipaddress": ("src_endpoint.ip",),
    "awsregion": ("cloud.region",),
    "errorcode": ("api.response.error",),
    "operationname": ("api.operation",),
    "resultdescription": ("status_detail",),
    "eventtype": ("activity_name",),
    "displaymessage": ("message",),
    # PowerShell script blocks / module logging (OCSF Script Activity)
    "scriptblocktext": ("script.script_content", "unmapped.ScriptBlockText"),
    "path": ("script.file.path", "file.path", "unmapped.Path"),
    "payload": ("unmapped.Payload", "script.script_content"),
    "contextinfo": ("unmapped.ContextInfo",),
    "hostapplication": ("process.cmd_line", "unmapped.HostApplication"),
    # Windows event-log channels (OCSF Event Log Activity) and AV detections
    "provider_name": ("metadata.log_provider", "unmapped.Provider_Name"),
    "channel": ("metadata.log_name", "unmapped.Channel"),
    "servicename": ("unmapped.ServiceName", "service.name"),
    "imagepath": ("unmapped.ImagePath", "process.file.path"),
    "pipename": ("unmapped.PipeName", "file.name"),
    "signature": ("malware.name", "finding_info.title", "unmapped.Signature"),
    "filename": ("file.path", "unmapped.Filename"),
    # Linux auditd
    "exe": ("process.file.path", "unmapped.exe"),
    "comm": ("process.name", "unmapped.comm"),
    "a0": ("unmapped.a0",), "a1": ("unmapped.a1",), "a2": ("unmapped.a2",), "a3": ("unmapped.a3",),
    "key": ("unmapped.key",),
    # Kubernetes / Bitbucket / GitHub audit
    "verb": ("api.operation", "unmapped.verb"),
    "objectref.resource": ("resources.type", "unmapped.objectRef.resource"),
    "audittype.action": ("api.operation",),
}
FIELD_MAP = {k.lower(): v for k, v in FIELD_MAP.items()}          # lookups lowercase the Sigma field name
#: in every OCSF class except Process Activity the process that did it is the actor (actor.process); Process
#: Activity describes the process itself in `process`
_ACTOR_FIELDS: dict[str, tuple[str, ...]] = {
    "image": ("actor.process.file.path", "process.file.path", "actor.process.name", "process.name"),
    "parentimage": ("actor.process.parent_process.file.path", "process.parent_process.file.path",
                    "actor.process.parent_process.name"),
    "commandline": ("actor.process.cmd_line", "process.cmd_line"),
    "parentcommandline": ("actor.process.parent_process.cmd_line", "process.parent_process.cmd_line"),
    "processid": ("actor.process.pid", "process.pid"),
    "originalfilename": ("actor.process.file.original_name", "process.file.original_name", "actor.process.file.name"),
    "user": ("actor.user.name", "actor.process.user.name", "user.name", "process.user.name"),
    "hashes": ("actor.process.file.hashes", "process.file.hashes"),
}

_UNSUPPORTED_MODS = ("base64", "base64offset", "utf16", "utf16le", "utf16be", "wide", "fieldref", "expand")
#: modifiers this engine implements; anything else (a time modifier, a typo) makes the rule Unsupported rather
#: than being silently ignored
_KNOWN_MODS = frozenset({"contains", "startswith", "endswith", "all", "re", "i", "m", "s", "cidr", "exists", "windash",
                         "lt", "lte", "gt", "gte", "cased"})


class Unsupported(ValueError):
    pass


# ------------------------------------------------------------------------------------------------ matching --

def _glob_pieces(value: str) -> list[list[str | None]]:
    """A Sigma value → literal pieces split on unescaped ``*``; ``None`` inside a piece is a ``?`` (any one char).
    ``\\*``, ``\\?`` and ``\\\\`` are literal; any other backslash is itself (a Windows path)."""
    pieces: list[list[str | None]] = [[]]
    i = 0
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            pieces[-1].append(value[i + 1])
            i += 2
            continue
        if c == "*":
            pieces.append([])
        else:
            pieces[-1].append(None if c == "?" else c)
        i += 1
    return pieces


class _Glob:
    """A Sigma wildcard value matched without regex backtracking: anchored first / last pieces, the middle ones
    found left to right (leftmost is always safe for ``*``-only globs). Linear in the text for ``?``-free pieces;
    O(text × piece) with ``?`` — never exponential, never polynomial blow-up from attacker-written input."""

    __slots__ = ("cased", "fast", "first", "last", "mids", "shape", "star")

    def __init__(self, value: str, *, contains: bool = False, start: bool = False, end: bool = False,
                 cased: bool = False):
        pieces = _glob_pieces(value)
        if contains or end:
            pieces = [[], *pieces]
        if contains or start:
            pieces = [*pieces, []]
        self.cased = cased
        norm = [self._norm(p) for p in pieces]
        self.star = len(norm) > 1
        self.first, self.last = norm[0], norm[-1]
        self.mids = norm[1:-1] if self.star else []
        self.fast = self._specialise()

    def _specialise(self) -> Callable[[str], bool] | None:
        """The common ``?``-free shapes on native str methods (most SigmaHQ values)."""
        parts = [self.first, *self.mids, self.last]
        if any(None in p for p in parts):
            return None
        first, last = "".join(self.first), "".join(self.last)              # type: ignore[arg-type]
        mids = ["".join(m) for m in self.mids]                               # type: ignore[arg-type]
        self.shape: tuple[str, str] | None = None
        if not self.star:
            self.shape = ("eq", first)
            return first.__eq__
        if not mids:
            if not first and not last:
                return lambda t: True
            if not first:
                self.shape = ("end", last)
                return lambda t, s=last: t.endswith(s)
            if not last:
                self.shape = ("start", first)
                return lambda t, s=first: t.startswith(s)
        if not first and not last and len(mids) == 1:
            self.shape = ("in", mids[0])
            return lambda t, s=mids[0]: s in t
        return None

    def _norm(self, piece: list[str | None]) -> tuple[str | None, ...]:
        return tuple(c if c is None or self.cased else c.lower() for c in piece)

    @staticmethod
    def _at(text: str, i: int, piece: tuple[str | None, ...]) -> bool:
        if i < 0 or i + len(piece) > len(text):
            return False
        return all(p is None or text[i + k] == p for k, p in enumerate(piece))

    @staticmethod
    def _find(text: str, piece: tuple[str | None, ...], lo: int, hi: int) -> int:
        n = len(piece)
        if None not in piece:
            return text.find("".join(piece), lo, hi)                      # type: ignore[arg-type]
        for i in range(lo, hi - n + 1):
            if _Glob._at(text, i, piece):
                return i
        return -1

    def __call__(self, x: Any) -> bool:
        text = x if isinstance(x, str) else str(x)
        if not self.cased:
            text = _lower(text)
        if self.fast is not None:
            return self.fast(text)
        if not self.star:
            return len(text) == len(self.first) and self._at(text, 0, self.first)
        lo, hi = len(self.first), len(text) - len(self.last)
        if hi < lo or not self._at(text, 0, self.first) or not self._at(text, hi, self.last):
            return False
        for piece in self.mids:
            j = self._find(text, piece, lo, hi)
            if j < 0:
                return False
            lo = j + len(piece)
        return True


def _lower(text: str) -> str:
    """``text.lower()``, computed once per string per event while SigmaEngine.match runs."""
    cache = getattr(_LOCAL, "lowers", None)
    if cache is None:
        return text.lower()
    low = cache.get(text)
    if low is None:
        low = cache[text] = text.lower()
    return low


#: dash-like characters at a flag position (start, or after whitespace / quote, before a word char)
_WINDASH_RX = re.compile(r"(?:(?<=^)|(?<=[\s\"']))[-/\u2013\u2014\u2015](?=\w)")


def _windash(text: str) -> str:
    return _WINDASH_RX.sub("-", text)


def _ip(x: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """An event address as written by any sensor → one canonical address: whitespace and ``[…]`` stripped, an
    IPv6 zone id dropped, an IPv4-mapped IPv6 address (``::ffff:a.b.c.d`` / ``::FFFF:A9FE:A9FE``) unwrapped."""
    s = str(x).strip()[:64]
    if s.startswith("[") and "]" in s:
        s = s[1:s.index("]")]
    s = s.split("%", 1)[0].strip()
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _num(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


@dataclass
class _Field:
    name: str
    mods: tuple[str, ...]
    tests: list[Callable[[Any], bool]]
    need_all: bool
    null: bool = False                  # null alone, or as one alternative in a list: missing / empty matches
    exists: bool | None = None


def _value_test(v: Any, mods: tuple[str, ...]) -> list[Callable[[Any], bool]]:
    if "re" in mods:
        flags = re.IGNORECASE if "i" in mods else 0
        rx = re.compile(str(v), flags | (re.MULTILINE if "m" in mods else 0) | (re.DOTALL if "s" in mods else 0))
        # a rule author's own regex (trusted like the bank's SIEM trusts it); input bounded by MAX_VALUE
        return [lambda x, rx=rx: rx.search(str(x)[:MAX_VALUE]) is not None]
    if "cidr" in mods:
        net = ipaddress.ip_network(str(v).strip(), strict=False)

        def in_net(x: Any, net=net) -> bool:
            ip = _ip(x)
            return ip is not None and ip.version == net.version and ip in net
        return [in_net]
    for op in ("lt", "lte", "gt", "gte"):
        if op in mods:
            ref = _num(v)
            if ref is None:
                raise Unsupported(f"non-numeric {op} value {v!r}")
            cmp = {"lt": float.__lt__, "lte": float.__le__, "gt": float.__gt__, "gte": float.__ge__}[op]
            return [lambda x, ref=ref, cmp=cmp: (n := _num(x)) is not None and cmp(n, ref)]
    string_mods = {"contains", "startswith", "endswith", "windash", "cased"} & set(mods)
    if isinstance(v, bool):
        return [lambda x, v=v: str(x).lower() == str(v).lower()]
    if isinstance(v, (int, float)) and not string_mods:
        return [lambda x, v=v: _num(x) == float(v) or str(x) == str(v)]
    s = str(v)                                   # an int under a string modifier (`Port|startswith: 44`) is a string
    cased, windash = "cased" in mods, "windash" in mods
    if windash:
        s = _windash(s)
    g = _Glob(s, contains="contains" in mods, start="startswith" in mods, end="endswith" in mods, cased=cased)
    if windash:
        return [lambda x, g=g: g(_windash(str(x)))]
    return [g]


def _compile_field(key: str, value: Any) -> _Field:
    name, *mods = key.split("|")
    mods_t = tuple(m.lower() for m in mods)
    bad = [m for m in mods_t if m in _UNSUPPORTED_MODS or m.startswith("base64") or m not in _KNOWN_MODS]
    if bad:
        raise Unsupported(f"modifier {bad[0]}")
    if "exists" in mods_t:
        return _Field(name, mods_t, [], False, exists=bool(value))
    vals = value if isinstance(value, list) else [value]
    tests: list[Callable[[Any], bool]] = []
    for v in vals:
        if v is None:
            continue
        tests += _value_test(v, mods_t)
    if "all" not in mods_t:
        tests = _merge(tests)
    return _Field(name, mods_t, tests, "all" in mods_t, null=None in vals)


def _merge(tests: list[Callable[[Any], bool]]) -> list[Callable[[Any], bool]]:
    """Any-of: fold the plain (``?``-free, same-case) values of one field into one native check per shape —
    ``endswith(tuple)``, ``startswith(tuple)``, set membership, one ``in`` loop — instead of one call per value."""
    groups: dict[tuple[str, bool], list[str]] = {}
    rest: list[Callable[[Any], bool]] = []
    for t in tests:
        shape = getattr(t, "shape", None)
        if isinstance(t, _Glob) and shape is not None:
            groups.setdefault((shape[0], t.cased), []).append(shape[1])
        else:
            rest.append(t)
    out: list[Callable[[Any], bool]] = []
    for (kind, cased), vals in groups.items():
        low = (lambda x: x if isinstance(x, str) else str(x)) if cased else (lambda x: _lower(x if isinstance(x, str) else str(x)))
        if kind == "end":
            out.append(lambda x, v=tuple(vals), low=low: low(x).endswith(v))
        elif kind == "start":
            out.append(lambda x, v=tuple(vals), low=low: low(x).startswith(v))
        elif kind == "eq":
            out.append(lambda x, v=frozenset(vals), low=low: low(x) in v)
        else:
            out.append(lambda x, v=tuple(vals), low=low: any(s in low(x) for s in v))
    return out + rest


def _walk(obj: Any, parts: list[str]) -> list[Any]:
    if not parts:
        return obj if isinstance(obj, list) else [obj]
    out: list[Any] = []
    if isinstance(obj, list):
        for it in obj[:200]:
            out += _walk(it, parts)
        return out
    if isinstance(obj, dict):
        nxt = obj.get(parts[0])
        if nxt is None:
            nxt = _lowered(obj).get(parts[0].lower())
        if nxt is not None:
            return _walk(nxt, parts[1:])
    return out


_LOCAL = threading.local()            # per-event lookup cache while SigmaEngine.match runs


def _lowered(obj: dict) -> dict:
    """A dict with lower-cased keys, built once per dict per event while SigmaEngine.match runs (a wide event must
    not be re-copied for every Sigma field that misses on it)."""
    cache = getattr(_LOCAL, "lowdicts", None)
    if cache is not None:
        hit = cache.get(id(obj))
        if hit is not None and hit[0] is obj:
            return hit[1]
    low = {}
    for k, v in obj.items():
        low.setdefault(str(k).lower(), v)
    if cache is not None:
        cache[id(obj)] = (obj, low)
    return low


def field_values(ev: dict, sigma_field: str) -> list[Any]:
    cache = getattr(_LOCAL, "cache", None)
    if cache is not None and cache[0] is ev:
        hit = cache[1].get(sigma_field)
        if hit is None:
            hit = cache[1][sigma_field] = _field_values(ev, sigma_field)
        return hit
    return _field_values(ev, sigma_field)


def _paths(ev: dict, field_lower: str) -> tuple[str, ...]:
    if field_lower in _ACTOR_FIELDS and ev.get("class_uid") not in (1007, "1007"):
        return _ACTOR_FIELDS[field_lower]
    return FIELD_MAP.get(field_lower, ())


_HASH_NAMES = {1: "MD5", 2: "SHA1", 3: "SHA256", 4: "SHA512", 5: "CTPH", 6: "TLSH", 7: "QUICKXORHASH"}


def _sysmon_hashes(hashes: Any) -> str:
    """OCSF ``hashes`` objects → the Sysmon ``Hashes`` string rules match (``SHA256=…,IMPHASH=…``)."""
    parts = []
    for h in hashes if isinstance(hashes, list) else []:
        if not isinstance(h, dict) or not h.get("value"):
            continue
        alg = str(h.get("algorithm") or _HASH_NAMES.get(h.get("algorithm_id"), "")).upper().replace("-", "")
        if alg:
            parts.append(f"{alg}={h['value']}")
    return ",".join(parts)


def _present(vals: list[Any]) -> list[Any]:
    return [v for v in vals if v is not None]


#: Sigma web fields whose values are matched both as received and URL-decoded + NFKC-folded: a probe written
#: ``id=1%27%20or%201%3D1`` or with fullwidth letters is the same probe
_URL_FIELDS = frozenset({"cs-uri-query", "c-uri-query", "cs-uri", "c-uri", "cs-uri-stem", "c-uri-stem"})
_URL_DECODE_ROUNDS = 3
_SQL_COMMENT_RX = re.compile(r"/\*.{0,256}?\*/", re.DOTALL)


def _url_norm(v: Any) -> str:
    """URL-decode (``+`` is a space; at most a few rounds, so double encoding is seen), NFKC-fold, and turn inline
    SQL comments into a space. Bounded by MAX_VALUE."""
    s = str(v)[:MAX_VALUE]
    for _ in range(_URL_DECODE_ROUNDS):
        d = unquote_plus(s)
        if d == s:
            break
        s = d
    s = unicodedata.normalize("NFKC", s)[:MAX_VALUE]
    return _SQL_COMMENT_RX.sub(" ", s)


def _field_values(ev: dict, sigma_field: str) -> list[Any]:
    """Values of a Sigma field in an OCSF event: [] when the field is absent; "" when it is present but empty."""
    vals = _field_values_raw(ev, sigma_field)
    if vals and sigma_field.lower() in _URL_FIELDS:
        extra = [n for v in vals if isinstance(v, str) and (n := _url_norm(v)) != v]
        return vals + extra if extra else vals
    return vals


def _field_values_raw(ev: dict, sigma_field: str) -> list[Any]:
    low = sigma_field.lower()
    if low == "c-uri-extension":
        out = []
        for path in _present(_walk(ev, ["http_request", "url", "path"]) or _walk(ev, ["http_request", "url", "url_string"])):
            last = str(path).split("?", 1)[0].split("#", 1)[0].rstrip("/").rsplit("/", 1)[-1]
            out.append(last.rsplit(".", 1)[1] if "." in last else "")
        if out:
            return out
    for p in _paths(ev, low):
        vals = _present(_walk(ev, p.split(".")))
        if vals:
            if low == "hashes" and any(isinstance(v, dict) for v in vals):
                return [_sysmon_hashes(vals)]
            return vals
    for root in ("unmapped", None):
        base = ev.get(root) if root else ev
        if isinstance(base, dict):
            vals = _present(_walk(base, sigma_field.split(".")))
            if vals:
                return vals
    return []


#: total characters of one event that keyword rules search (every value is still capped at MAX_VALUE): a padded
#: event costs at most this much per keyword, not 2,000 × 32 K
KEYWORD_BUDGET = 1 << 20


def _str_values(obj: Any, out: list[str], depth: int = 0, budget: list[int] | None = None) -> None:
    if budget is None:
        budget = [KEYWORD_BUDGET]
    if depth > 8 or len(out) > 2000 or budget[0] <= 0:
        return
    if isinstance(obj, dict):
        for v in obj.values():
            _str_values(v, out, depth + 1, budget)
    elif isinstance(obj, list):
        for v in obj[:500]:
            _str_values(v, out, depth + 1, budget)
    elif isinstance(obj, (str, int, float)) and not isinstance(obj, bool):
        s = str(obj)[:min(MAX_VALUE, budget[0])]
        budget[0] -= len(s)
        out.append(s)


def _field_match(f: _Field, ev: dict) -> bool:
    vals = field_values(ev, f.name)
    if f.exists is not None:
        return bool(vals) == f.exists
    if f.null and (not vals or all(v == "" for v in vals)):
        return True                     # null: absent or empty (alone, or as one alternative of a list)
    if not vals or not f.tests:
        return False
    if any(isinstance(v, str) and len(v) > MAX_VALUE for v in vals):
        vals = [v[:MAX_VALUE] if isinstance(v, str) else v for v in vals]
    if f.need_all:
        return all(any(t(v) for v in vals) for t in f.tests)
    return any(t(v) for t in f.tests for v in vals)


def _haystack(ev: dict) -> list[str]:
    """Every string value of the event (bounded), collected once per event however many keyword rules run."""
    cache = getattr(_LOCAL, "hay", None)
    if cache is not None and cache[0] is ev:
        return cache[1]
    strs: list[str] = []
    _str_values(ev, strs)
    if getattr(_LOCAL, "cache", None) is not None:
        _LOCAL.hay = (ev, strs)
    return strs


def _keywords(words: list[Any], *, need_all: bool = False) -> Callable[[dict], bool]:
    globs = [_Glob(str(w), contains=True) for w in words]

    def keywords(ev: dict) -> bool:
        strs = _haystack(ev)
        found = (any(g(x) for x in strs) for g in globs)
        return all(found) if need_all else any(found)
    return keywords


def _compile_item(item: Any) -> Callable[[dict], bool]:
    """One named detection block → predicate."""
    if isinstance(item, dict):
        preds: list[Callable[[dict], bool]] = []
        fields = []
        for k, v in item.items():
            name, *mods = str(k).split("|")
            if name == "":                  # `'|all': [...]` — keywords, every one of which must appear
                preds.append(_keywords(v if isinstance(v, list) else [v], need_all="all" in [m.lower() for m in mods]))
            else:
                fields.append(_compile_field(k, v))
        return lambda ev, fields=fields, preds=preds: (all(_field_match(f, ev) for f in fields)
                                                       and all(p(ev) for p in preds))
    if isinstance(item, list):
        if all(isinstance(x, dict) for x in item):
            preds = [_compile_item(x) for x in item]
            return lambda ev, preds=preds: any(p(ev) for p in preds)
        return _keywords(item)
    if isinstance(item, str):
        return _compile_item([item])
    raise Unsupported(f"detection block of type {type(item).__name__}")


# ----------------------------------------------------------------------------------------------- condition --

#: a condition nested deeper than this (parentheses / ``not``), or longer than _MAX_TOKENS tokens, is skipped as
#: Unsupported — SigmaHQ conditions are a handful of levels deep; a 1,000-deep one is a broken or hostile file
_MAX_DEPTH = 32
_MAX_TOKENS = 512


def _all_of(preds: list[Callable[[dict], bool]]) -> Callable[[dict], bool]:
    if len(preds) == 1:
        return preds[0]
    return lambda ev, preds=tuple(preds): all(p(ev) for p in preds)


def _any_of(preds: list[Callable[[dict], bool]]) -> Callable[[dict], bool]:
    if len(preds) == 1:
        return preds[0]
    return lambda ev, preds=tuple(preds): any(p(ev) for p in preds)


_TOK = re.compile(r"\s*(\(|\)|\b(?:1|any|all)\s+of\s+[\w*]+|\band\b|\bor\b|\bnot\b|[\w*.-]+)", re.IGNORECASE)


def _compile_condition(cond: str, blocks: dict[str, Callable[[dict], bool]]) -> Callable[[dict], bool]:
    if "|" in cond or re.search(r"\bnear\b", cond, re.IGNORECASE):
        raise Unsupported("aggregation / near condition")
    toks: list[str] = []
    pos = 0
    depth = 0
    while pos < len(cond.strip()):
        m = _TOK.match(cond, pos)
        if not m:
            raise Unsupported(f"condition {cond[:80]!r}")
        tok = m.group(1)
        depth += tok == "("
        if depth > _MAX_DEPTH or len(toks) >= _MAX_TOKENS:
            raise Unsupported("condition too deep / too long")
        depth -= tok == ")"
        toks.append(tok)
        pos = m.end()
        if not cond[pos:].strip():
            break
    i = 0

    def peek() -> str:
        return toks[i].lower() if i < len(toks) else ""

    def take() -> str:
        nonlocal i
        if i >= len(toks):
            raise Unsupported(f"condition ends early: {cond!r}")
        i += 1
        return toks[i - 1]

    def group(pattern: str) -> list[Callable[[dict], bool]]:
        names = list(blocks) if pattern.lower() == "them" else [n for n in blocks if fnmatch.fnmatchcase(n, pattern)]
        if not names:
            raise Unsupported(f"no detection block matches {pattern!r}")
        return [blocks[n] for n in names]

    def atom(level: int) -> Callable[[dict], bool]:
        if level > _MAX_DEPTH:
            raise Unsupported("condition too deep / too long")
        t = take()
        lo = t.lower()
        if lo == "(":
            e = expr(level + 1)
            if take() != ")":
                raise Unsupported("unbalanced parentheses")
            return e
        if lo == "not":
            inner = atom(level + 1)
            return lambda ev: not inner(ev)
        m = re.fullmatch(r"(1|any|all)\s+of\s+([\w*]+)", t, re.IGNORECASE)
        if m:
            preds = group(m.group(2))
            if m.group(1).lower() == "all":
                return _all_of(preds)
            return _any_of(preds)
        if t not in blocks:
            raise Unsupported(f"unknown detection block {t[:80]!r}")
        return blocks[t]

    def conj(level: int) -> Callable[[dict], bool]:
        terms = [atom(level)]               # flat, not a left-deep lambda chain: `a and b and …` cannot overflow
        while peek() == "and":
            take()
            terms.append(atom(level))
        return _all_of(terms)

    def expr(level: int) -> Callable[[dict], bool]:
        terms = [conj(level)]
        while peek() == "or":
            take()
            terms.append(conj(level))
        return _any_of(terms)

    fn = expr(0)
    if i != len(toks):
        raise Unsupported(f"trailing tokens in condition {cond!r}")
    return fn


# ----------------------------------------------------------------------------------------------- rules --

@dataclass
class CompiledRule:
    id: str
    title: str
    level: str
    tags: list[str]
    classes: tuple[int, ...] | None          # None = any class (a keyword rule with a broad logsource)
    match: Callable[[dict], bool]
    path: str = ""
    activities: tuple[int, ...] | None = None   # OCSF activity_ids this rule applies to (None = any)

    @property
    def techniques(self) -> list[str]:
        return sorted({t.split(".", 1)[1].upper() for t in self.tags if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t.lower())})

    def hit(self) -> dict:
        return {"id": self.id, "title": self.title, "level": self.level, "techniques": self.techniques}


def _classes(logsource: dict) -> tuple[int, ...] | None:
    cat = str(logsource.get("category") or "").lower()
    svc = str(logsource.get("service") or "").lower()
    prod = str(logsource.get("product") or "").lower()
    if cat in _CATEGORY_CLASSES:
        return _CATEGORY_CLASSES[cat]
    if svc in _SERVICE_CLASSES:
        return _SERVICE_CLASSES[svc]
    if prod in ("aws", "azure", "gcp", "m365", "okta", "github", "bitbucket", "kubernetes") and not cat:
        return (6003, 3002, 3001)
    if prod in _PRODUCT_DEFAULT and not cat:
        return _PRODUCT_DEFAULT[prod]
    raise Unsupported(f"logsource {cat or '-'} / {svc or '-'} / {prod or '-'} has no OCSF class mapping")


class Malformed(Unsupported):
    """A rule whose YAML does not have Sigma's shape (logsource not a mapping, tags not a list, a non-string block
    name, a condition that is not a string)."""


def compile_rule(doc: dict, path: str = "") -> CompiledRule:
    if not isinstance(doc, dict):
        raise Malformed("malformed rule: not a mapping")
    det = doc.get("detection")
    if not isinstance(det, dict) or "condition" not in det:
        raise Unsupported("no detection / condition")
    if doc.get("correlation"):
        raise Unsupported("correlation rule")
    logsource = doc.get("logsource")
    if logsource is None:
        logsource = {}
    if not isinstance(logsource, dict):
        raise Malformed("malformed rule: logsource is not a mapping")
    tags = doc.get("tags")
    if tags is None:
        tags = []
    if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
        raise Malformed("malformed rule: tags is not a list of strings")
    if not all(isinstance(k, str) for k in det):
        raise Malformed("malformed rule: detection block name is not a string")
    cond = det["condition"]
    if isinstance(cond, list):
        if len(cond) != 1:
            raise Unsupported("multiple conditions")
        cond = cond[0]
    if not isinstance(cond, str):
        raise Malformed("malformed rule: condition is not a string")
    blocks = {k: _compile_item(v) for k, v in det.items() if k not in ("condition", "timeframe")}
    match = _compile_condition(cond, blocks)
    return CompiledRule(id=str(doc.get("id") or path), title=str(doc.get("title") or path),
                        level=str(doc.get("level") or "medium").lower(), tags=list(tags),
                        classes=_classes(logsource), match=match, path=path,
                        activities=_CATEGORY_ACTIVITIES.get(str(logsource.get("category") or "").lower()))


@dataclass
class SigmaEngine:
    rules: list[CompiledRule] = field(default_factory=list)
    skipped: dict[str, int] = field(default_factory=dict)        # reason → count
    _by_class: dict[int, list[CompiledRule]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.reindex()

    def reindex(self) -> None:
        self._by_class = {}
        for r in self.rules:
            for c in r.classes or ():
                self._by_class.setdefault(c, []).append(r)

    @classmethod
    def from_dir(cls, root: str | Path, *, min_level: str = "low") -> SigmaEngine:
        import yaml
        root = Path(root)
        base = root / "rules" if (root / "rules").is_dir() else root
        eng = cls()
        floor = _LEVELS.get(min_level, 1)
        for p in sorted(base.rglob("*.yml")):
            try:
                docs = [d for d in yaml.safe_load_all(p.read_text(encoding="utf-8")) if isinstance(d, dict)]
            except Exception:  # noqa: BLE001 — one malformed community file is skipped, not fatal
                eng.skipped["unreadable"] = eng.skipped.get("unreadable", 0) + 1
                continue
            for d in docs:
                rel = str(p.relative_to(root))
                try:
                    if d.get("status") in ("deprecated", "unsupported"):
                        eng.skipped["deprecated"] = eng.skipped.get("deprecated", 0) + 1
                        continue
                    if _LEVELS.get(str(d.get("level") or "medium").lower(), 2) < floor:
                        eng.skipped["below level"] = eng.skipped.get("below level", 0) + 1
                        continue
                    eng.rules.append(compile_rule(d, rel))
                except Malformed as e:
                    eng.skipped["malformed"] = eng.skipped.get("malformed", 0) + 1
                    logger.warning("[sigma] skipped %s: %s", rel, e)
                except (Unsupported, re.error, ValueError) as e:
                    reason = str(e).split(" ", 1)[0] if isinstance(e, Unsupported) else "bad regex/value"
                    reason = {"modifier": "unsupported modifier", "aggregation": "aggregation / near",
                              "logsource": "logsource not mapped", "condition": "bad condition"}.get(reason, reason)
                    eng.skipped[reason] = eng.skipped.get(reason, 0) + 1
                except Exception as e:  # noqa: BLE001 — one broken rule is skipped (once, at load), never fatal
                    eng.skipped["malformed"] = eng.skipped.get("malformed", 0) + 1
                    logger.warning("[sigma] skipped %s: %s: %s", rel, type(e).__name__, str(e)[:200])
        eng.reindex()
        return eng

    def match(self, ev: dict) -> list[CompiledRule]:
        try:
            cls = int(ev.get("class_uid"))
        except (TypeError, ValueError):
            return []
        out = []
        try:
            act: int | None = int(ev.get("activity_id"))
        except (TypeError, ValueError):
            act = None                     # no activity_id: rules are not gated on it
        _LOCAL.cache = (ev, {})            # each field is looked up once per event, not once per rule
        _LOCAL.lowers = {}                 # and each value lowercased once
        _LOCAL.lowdicts = {}               # each dict key-lowercased once
        _LOCAL.hay = None                  # and the keyword haystack collected once
        try:
            for r in self._by_class.get(cls, ()):
                if act is not None and r.activities is not None and act not in r.activities:
                    continue
                try:
                    if r.match(ev):
                        out.append(r)
                except Exception as e:  # noqa: BLE001 — one rule's bad regex never stops the others
                    logger.debug("[sigma] rule %s failed on an event: %s", r.id, e)
        finally:
            _LOCAL.cache = None
            _LOCAL.lowers = None
            _LOCAL.lowdicts = None
            _LOCAL.hay = None
        return out


_ENGINE: SigmaEngine | None = None
_ENGINE_LOCK = threading.Lock()
_ENGINE_KEY: tuple = ("", "")
_WARNED: set[str] = set()


def _dir_mtime(root: str) -> float | None:
    """mtime of the rules directory (and of its ``rules/`` sub-directory): a rule added or removed there reloads
    the engine; otherwise the loaded (or failed) result is reused for every event."""
    out = None
    for d in (Path(root), Path(root) / "rules"):
        try:
            m = d.stat().st_mtime
        except OSError:
            continue
        out = m if out is None else max(out, m)
    return out


def engine_from_env() -> SigmaEngine | None:
    """``AEGIS_SIGMA_RULES`` (a SigmaHQ checkout or a rules directory; unset = off), ``AEGIS_SIGMA_MIN_LEVEL``
    (``low``). Loaded once per (path, level, directory mtime) — including a load that failed — so the per-event path
    is one ``stat`` and takes no lock."""
    global _ENGINE, _ENGINE_KEY
    root = os.environ.get("AEGIS_SIGMA_RULES", "").strip()
    if not root:
        return None
    key = (root, os.environ.get("AEGIS_SIGMA_MIN_LEVEL", "low").strip().lower() or "low", _dir_mtime(root))
    eng, cur = _ENGINE, _ENGINE_KEY
    if eng is not None and cur == key:
        return eng
    with _ENGINE_LOCK:
        if _ENGINE is None or _ENGINE_KEY != key:
            if not Path(root).is_dir() and root not in _WARNED:
                _WARNED.add(root)
                logger.error("[sigma] AEGIS_SIGMA_RULES=%s is not a directory — no Sigma rule will run", root)
            try:
                eng = SigmaEngine.from_dir(root, min_level=key[1])
            except Exception as e:  # noqa: BLE001 — a failed load is cached too: never re-walk the tree per event
                logger.error("[sigma] loading %s failed (%s: %s) — no Sigma rule will run until it changes",
                             root, type(e).__name__, str(e)[:200])
                eng = SigmaEngine(skipped={"load failed": 1})
            logger.info("[sigma] %d rule(s) loaded from %s; skipped %s", len(eng.rules), root,
                        ", ".join(f"{k}: {v}" for k, v in sorted(eng.skipped.items())) or "none")
            _ENGINE, _ENGINE_KEY = eng, key
        return _ENGINE


_SEV = ["low", "low", "medium", "high", "critical"]
_SCORE = {"low": 0.3, "medium": 0.6, "high": 0.8, "critical": 0.95}


def enrich(alert: dict, ev: dict, engine: SigmaEngine | None = None) -> dict:
    """Attach Sigma hits to an alert built from ``ev``; raise its severity to the highest hit's level."""
    eng = engine if engine is not None else engine_from_env()
    if eng is None:
        return alert
    hits = eng.match(ev)
    if not hits:
        return alert
    alert["sigma"] = [h.hit() for h in hits[:20]]
    top = max(_LEVELS.get(h.level, 2) for h in hits)
    sev = _SEV[top]
    if _LEVELS.get(str(alert.get("severity") or "low"), 1) < top:
        alert["severity"] = sev
        alert["anomaly_score"] = max(float(alert.get("anomaly_score") or 0), _SCORE[sev])
    techs = sorted({t for h in hits for t in h.techniques} | set(alert.get("techniques") or []))
    if techs:
        alert["techniques"] = techs
    return alert


def _events(paths: Iterable[str]) -> Iterable[dict]:
    for p in paths:
        for line in Path(p).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            yield from (obj if isinstance(obj, list) else [obj])


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="python -m aegis.detect.sigma",
                                 description="Load Sigma rules and run them over OCSF events (NDJSON).")
    ap.add_argument("--rules", required=True, help="SigmaHQ checkout or rules directory")
    ap.add_argument("--min-level", default="low")
    ap.add_argument("events", nargs="*", help="OCSF NDJSON files")
    a = ap.parse_args(argv)
    eng = SigmaEngine.from_dir(a.rules, min_level=a.min_level)
    print(json.dumps({"loaded": len(eng.rules), "skipped": eng.skipped,
                      "by_class": {str(k): len(v) for k, v in sorted(eng._by_class.items())}}, indent=1))
    n = hit = 0
    for ev in _events(a.events):
        n += 1
        rules = eng.match(ev)
        if rules:
            hit += 1
            print(json.dumps({"event": (ev.get("metadata") or {}).get("uid") or n, "hits": [r.hit() for r in rules]}))
    if a.events:
        print(json.dumps({"events": n, "with_hits": hit}))
    return 0


__all__ = ["FIELD_MAP", "CompiledRule", "SigmaEngine", "Unsupported", "compile_rule", "engine_from_env", "enrich",
           "field_values", "main"]
