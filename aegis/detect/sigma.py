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
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("aegis.detect.sigma")

MAX_VALUE = 8192
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
    "auditType.action": ("api.operation",),
}

_UNSUPPORTED_MODS = ("base64", "base64offset", "utf16", "utf16le", "utf16be", "wide", "fieldref", "expand")


class Unsupported(ValueError):
    pass


# ------------------------------------------------------------------------------------------------ matching --

def _glob_rx(value: str, *, contains: bool = False, start: bool = False, end: bool = False) -> re.Pattern:
    out, i = [], 0
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
        i += 1
    body = "".join(out)
    if contains or end:
        body = ".*" + body
    if contains or start:
        body = body + ".*"
    return re.compile(f"(?s){body}\\Z", re.IGNORECASE)


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
    null: bool = False
    exists: bool | None = None


def _value_test(v: Any, mods: tuple[str, ...]) -> list[Callable[[Any], bool]]:
    if "re" in mods:
        flags = re.IGNORECASE if "i" in mods else 0
        rx = re.compile(str(v), flags | (re.MULTILINE if "m" in mods else 0) | (re.DOTALL if "s" in mods else 0))
        return [lambda x, rx=rx: rx.search(str(x)) is not None]
    if "cidr" in mods:
        net = ipaddress.ip_network(str(v), strict=False)

        def in_net(x: Any, net=net) -> bool:
            try:
                return ipaddress.ip_address(str(x)) in net
            except ValueError:
                return False
        return [in_net]
    for op in ("lt", "lte", "gt", "gte"):
        if op in mods:
            ref = _num(v)
            if ref is None:
                raise Unsupported(f"non-numeric {op} value {v!r}")
            cmp = {"lt": float.__lt__, "lte": float.__le__, "gt": float.__gt__, "gte": float.__ge__}[op]
            return [lambda x, ref=ref, cmp=cmp: (n := _num(x)) is not None and cmp(n, ref)]
    if isinstance(v, bool):
        return [lambda x, v=v: str(x).lower() == str(v).lower()]
    if isinstance(v, (int, float)):
        return [lambda x, v=v: _num(x) == float(v) or str(x) == str(v)]
    s = str(v)
    variants = [s]
    if "windash" in mods:
        variants = list({s, s.replace("-", "/"), s.replace("/", "-"), s.replace("-", "–")})
    contains, start, end = "contains" in mods, "startswith" in mods, "endswith" in mods
    rxs = [_glob_rx(x, contains=contains, start=start, end=end) for x in variants]
    return [lambda x, rxs=rxs: any(r.match(str(x)) for r in rxs)]


def _compile_field(key: str, value: Any) -> _Field:
    name, *mods = key.split("|")
    mods_t = tuple(m.lower() for m in mods)
    bad = [m for m in mods_t if m in _UNSUPPORTED_MODS or m.startswith("base64")]
    if bad:
        raise Unsupported(f"modifier {bad[0]}")
    if "exists" in mods_t:
        return _Field(name, mods_t, [], False, exists=bool(value))
    vals = value if isinstance(value, list) else [value]
    if vals == [None]:
        return _Field(name, mods_t, [], False, null=True)
    tests: list[Callable[[Any], bool]] = []
    for v in vals:
        if v is None:
            continue
        tests += _value_test(v, mods_t)
    return _Field(name, mods_t, tests, "all" in mods_t)


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
            low = {str(k).lower(): v for k, v in obj.items()}
            nxt = low.get(parts[0].lower())
        if nxt is not None:
            return _walk(nxt, parts[1:])
    return out


def field_values(ev: dict, sigma_field: str) -> list[Any]:
    paths = FIELD_MAP.get(sigma_field.lower(), ())
    for p in paths:
        vals = [v for v in _walk(ev, p.split(".")) if v is not None and v != ""]
        if vals:
            return vals
    for root in ("unmapped", None):
        base = ev.get(root) if root else ev
        if isinstance(base, dict):
            vals = [v for v in _walk(base, sigma_field.split(".")) if v is not None and v != ""]
            if vals:
                return vals
    return []


def _str_values(obj: Any, out: list[str], depth: int = 0) -> None:
    if depth > 6 or len(out) > 400:
        return
    if isinstance(obj, dict):
        for v in obj.values():
            _str_values(v, out, depth + 1)
    elif isinstance(obj, list):
        for v in obj[:100]:
            _str_values(v, out, depth + 1)
    elif isinstance(obj, (str, int, float)) and not isinstance(obj, bool):
        out.append(str(obj)[:MAX_VALUE])


def _field_match(f: _Field, ev: dict) -> bool:
    vals = field_values(ev, f.name)
    if f.exists is not None:
        return bool(vals) == f.exists
    if f.null:
        return not vals
    if not vals:
        return False
    vals = [str(v)[:MAX_VALUE] if isinstance(v, str) else v for v in vals]
    if f.need_all:
        return all(any(t(v) for v in vals) for t in f.tests)
    return any(t(v) for t in f.tests for v in vals)


def _compile_item(item: Any) -> Callable[[dict], bool]:
    """One named detection block → predicate."""
    if isinstance(item, dict):
        fields = [_compile_field(k, v) for k, v in item.items()]
        return lambda ev, fields=fields: all(_field_match(f, ev) for f in fields)
    if isinstance(item, list):
        if all(isinstance(x, dict) for x in item):
            preds = [_compile_item(x) for x in item]
            return lambda ev, preds=preds: any(p(ev) for p in preds)
        rxs = [_glob_rx(str(x), contains=True) for x in item]

        def keywords(ev: dict, rxs=rxs) -> bool:
            strs: list[str] = []
            _str_values(ev, strs)
            return any(r.match(s) for r in rxs for s in strs)
        return keywords
    if isinstance(item, str):
        return _compile_item([item])
    raise Unsupported(f"detection block of type {type(item).__name__}")


# ----------------------------------------------------------------------------------------------- condition --

def _and(a: Callable[[dict], bool], b: Callable[[dict], bool]) -> Callable[[dict], bool]:
    return lambda ev: a(ev) and b(ev)


def _or(a: Callable[[dict], bool], b: Callable[[dict], bool]) -> Callable[[dict], bool]:
    return lambda ev: a(ev) or b(ev)


_TOK = re.compile(r"\s*(\(|\)|\b(?:1|any|all)\s+of\s+[\w*]+|\band\b|\bor\b|\bnot\b|[\w*.-]+)", re.IGNORECASE)


def _compile_condition(cond: str, blocks: dict[str, Callable[[dict], bool]]) -> Callable[[dict], bool]:
    if "|" in cond or re.search(r"\bnear\b", cond, re.IGNORECASE):
        raise Unsupported("aggregation / near condition")
    toks: list[str] = []
    pos = 0
    while pos < len(cond.strip()):
        m = _TOK.match(cond, pos)
        if not m:
            raise Unsupported(f"condition {cond!r}")
        toks.append(m.group(1))
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

    def atom() -> Callable[[dict], bool]:
        t = take()
        lo = t.lower()
        if lo == "(":
            e = expr()
            if take() != ")":
                raise Unsupported("unbalanced parentheses")
            return e
        if lo == "not":
            inner = atom()
            return lambda ev: not inner(ev)
        m = re.fullmatch(r"(1|any|all)\s+of\s+([\w*]+)", t, re.IGNORECASE)
        if m:
            preds = group(m.group(2))
            if m.group(1).lower() == "all":
                return lambda ev: all(p(ev) for p in preds)
            return lambda ev: any(p(ev) for p in preds)
        if t not in blocks:
            raise Unsupported(f"unknown detection block {t!r}")
        return blocks[t]

    def conj() -> Callable[[dict], bool]:
        left = atom()
        while peek() == "and":
            take()
            right = atom()
            left = _and(left, right)
        return left

    def expr() -> Callable[[dict], bool]:
        left = conj()
        while peek() == "or":
            take()
            right = conj()
            left = _or(left, right)
        return left

    fn = expr()
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


def compile_rule(doc: dict, path: str = "") -> CompiledRule:
    det = doc.get("detection")
    if not isinstance(det, dict) or "condition" not in det:
        raise Unsupported("no detection / condition")
    if doc.get("correlation"):
        raise Unsupported("correlation rule")
    cond = det["condition"]
    if isinstance(cond, list):
        if len(cond) != 1:
            raise Unsupported("multiple conditions")
        cond = cond[0]
    blocks = {k: _compile_item(v) for k, v in det.items() if k not in ("condition", "timeframe")}
    match = _compile_condition(str(cond), blocks)
    return CompiledRule(id=str(doc.get("id") or path), title=str(doc.get("title") or path),
                        level=str(doc.get("level") or "medium").lower(), tags=[str(t) for t in doc.get("tags") or []],
                        classes=_classes(doc.get("logsource") or {}), match=match, path=path)


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
                if d.get("status") in ("deprecated", "unsupported"):
                    eng.skipped["deprecated"] = eng.skipped.get("deprecated", 0) + 1
                    continue
                if _LEVELS.get(str(d.get("level") or "medium").lower(), 2) < floor:
                    eng.skipped["below level"] = eng.skipped.get("below level", 0) + 1
                    continue
                try:
                    eng.rules.append(compile_rule(d, str(p.relative_to(root))))
                except (Unsupported, re.error, ValueError) as e:
                    reason = str(e).split(" ", 1)[0] if isinstance(e, Unsupported) else "bad regex/value"
                    reason = {"modifier": "unsupported modifier", "aggregation": "aggregation / near",
                              "logsource": "logsource not mapped"}.get(reason, reason)
                    eng.skipped[reason] = eng.skipped.get(reason, 0) + 1
        eng.reindex()
        return eng

    def match(self, ev: dict) -> list[CompiledRule]:
        try:
            cls = int(ev.get("class_uid"))
        except (TypeError, ValueError):
            return []
        out = []
        for r in self._by_class.get(cls, ()):
            try:
                if r.match(ev):
                    out.append(r)
            except Exception as e:  # noqa: BLE001 — one rule's bad regex never stops the others
                logger.debug("[sigma] rule %s failed on an event: %s", r.id, e)
        return out


_ENGINE: SigmaEngine | None = None
_ENGINE_LOCK = threading.Lock()
_ENGINE_FROM = ""


def engine_from_env() -> SigmaEngine | None:
    """``AEGIS_SIGMA_RULES`` (a SigmaHQ checkout or a rules directory; unset = off), ``AEGIS_SIGMA_MIN_LEVEL``
    (``low``). Loaded once per process."""
    global _ENGINE, _ENGINE_FROM
    root = os.environ.get("AEGIS_SIGMA_RULES", "").strip()
    if not root:
        return None
    with _ENGINE_LOCK:
        if _ENGINE is None or _ENGINE_FROM != root:
            eng = SigmaEngine.from_dir(root, min_level=os.environ.get("AEGIS_SIGMA_MIN_LEVEL", "low").strip().lower())
            logger.info("[sigma] %d rule(s) loaded from %s; skipped %s", len(eng.rules), root,
                        ", ".join(f"{k}: {v}" for k, v in sorted(eng.skipped.items())) or "none")
            _ENGINE, _ENGINE_FROM = eng, root
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
