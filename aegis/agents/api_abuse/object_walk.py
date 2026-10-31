"""Object-walk detector — BOLA / IDOR across many requests, from API-gateway logs.

A single request to ``/accounts/1002`` proves nothing. A principal touching twenty account ids
it does not own in two minutes is how bank data actually leaks, and no WAF signature sees it:
every request is well-formed and most return 200. This detector keeps a bounded, per-principal
window of gateway events (cheap, in memory) and emits **one AEGIS alert** only when the pattern
crosses a threshold — gateway logs are every API call, so raw events never reach the LLM.

Per principal (the token's subject; ``anon:<ip>|<ua>`` when unauthenticated) and endpoint
template (``/api/v1/accounts/{id}``) inside ``AEGIS_BOLA_WINDOW_S`` (300 s):

    confirmed    ≥ ``AEGIS_BOLA_CROSS_MIN`` (2) objects owned by someone else answered 2xx —
                 data left the bank                                                → critical
    attempted    ≥ ``AEGIS_BOLA_ATTEMPT_MIN`` (5) foreign objects requested, authz refused
                 (403/404) — the API held, the intent did not                      → high
    behavioural  ≥ ``AEGIS_BOLA_DISTINCT_MIN`` (10) distinct objects not known to be the
                 principal's own, plus sequential ids, a not-found ratio ≥ 0.3 or machine
                 cadence — no ownership data needed, so only ever *suspicious*      → medium

Ownership comes from ``ownership.py`` (bank-supplied); without it only *behavioural* fires.
An object the principal owns never counts; exempt principals (staff tools, service accounts)
are skipped. Re-emission is throttled per (principal, template) to once a minute unless the
level rises or the walk shows up from a new client IP (the walker rotated). Alerts carry counts and **masked** object ids (last four characters), never the
victims' owner identifiers.
"""

from __future__ import annotations

import hashlib
import os
import re
import statistics
import threading
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import parse_qsl, urlsplit

from .ownership import NoOwnership, OwnershipSource, exempt_principals, is_exempt

LEVELS = ("behavioural", "attempted", "confirmed")
_SEVERITY = {"confirmed": "critical", "attempted": "high", "behavioural": "medium"}
_NUM = re.compile(r"^\d{3,}$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$")
_TOKENISH = re.compile(r"^(?=(?:.*\d){2})[A-Za-z0-9_-]{6,64}$")   # ≥ 2 digits: "oauth2" is a word, "ACC000123" an id
_VERSION = re.compile(r"^v\d+(\.\d+)?$", re.I)
_SELF = {"me", "self", "current", "mine"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


def _is_id(seg: str) -> bool:
    if not seg or seg.lower() in _SELF or _VERSION.match(seg):
        return False
    return bool(_NUM.match(seg) or _UUID.match(seg) or _TOKENISH.match(seg))


def objects_in(path: str) -> tuple[str, list[tuple[str, str]]]:
    """``/api/v1/customers/770001/accounts/1002?statementId=9001`` →
    (``/api/v1/customers/{id}/accounts/{id}``, [("statement","9001"), ("customer","770001"), ("account","1002")]).
    The last entry is the primary object (deepest in the path)."""
    parts = urlsplit(str(path or ""))
    segs = [s for s in parts.path.split("/")]
    out: list[tuple[str, str]] = []
    tmpl: list[str] = []
    for i, seg in enumerate(segs):
        if _is_id(seg):
            prev = next((segs[j] for j in range(i - 1, -1, -1) if segs[j] and not _is_id(segs[j]) and not _VERSION.match(segs[j])), "object")
            out.append((_singular(prev), seg))
            tmpl.append("{id}")
        else:
            tmpl.append(seg)
    query: list[tuple[str, str]] = []
    for k, v in parse_qsl(parts.query, keep_blank_values=False):
        kl = k.lower()
        if (kl == "id" or kl.endswith("id") or kl.endswith("_id")) and _is_id(v):
            query.append((_singular(re.sub(r"_?id$", "", kl, flags=re.I) or "object"), v))
    # the deepest *path* object is the primary one (last in the list); query-string ids come first
    return "/".join(tmpl) or "/", query + out


def _singular(t: str) -> str:
    t = t.lower()
    return t[:-1] if t.endswith("s") and len(t) > 3 else t


def mask(object_id: str) -> str:
    s = str(object_id)
    return ("•" * 4 + s[-4:]) if len(s) > 4 else "•" * len(s)


@dataclass
class _Ev:
    ts: float
    template: str
    objects: tuple[tuple[str, str], ...]
    status: int
    ip: str
    owned: Optional[bool]              # True: all objects are the principal's · False: at least one foreign · None: unknown
    foreign: tuple[tuple[str, str], ...]


@dataclass
class _Principal:
    events: deque = field(default_factory=deque)
    emitted: dict[str, tuple[float, str, int]] = field(default_factory=dict)    # template → (ts, level, seq)
    emitted_ips: dict[str, set] = field(default_factory=dict)                     # template → client IPs already reported


class ObjectWalkDetector:
    def __init__(self, ownership: Optional[OwnershipSource] = None, *, window_s: Optional[int] = None,
                 cross_min: Optional[int] = None, attempt_min: Optional[int] = None, distinct_min: Optional[int] = None,
                 reemit_s: int = 60, max_principals: int = 100_000, max_events: int = 2_000,
                 exempt: Optional[list[str]] = None):
        self.ownership = ownership or NoOwnership()
        self.window_s = window_s if window_s is not None else _env_int("AEGIS_BOLA_WINDOW_S", 300)
        self.cross_min = cross_min if cross_min is not None else _env_int("AEGIS_BOLA_CROSS_MIN", 2)
        self.attempt_min = attempt_min if attempt_min is not None else _env_int("AEGIS_BOLA_ATTEMPT_MIN", 5)
        self.distinct_min = distinct_min if distinct_min is not None else _env_int("AEGIS_BOLA_DISTINCT_MIN", 10)
        self.reemit_s = reemit_s
        self.max_principals, self.max_events = max_principals, max_events
        self.exempt = exempt if exempt is not None else exempt_principals()
        self._p: "OrderedDict[str, _Principal]" = OrderedDict()
        self._lock = threading.Lock()
        self.seen = self.emitted = self.exempted = 0

    # ------------------------------------------------------------------ api --
    def observe(self, ev: dict) -> Optional[dict]:
        """Feed one normalised gateway event (``apigw.normalize`` shape); returns an alert or ``None``."""
        self.seen += 1
        principal = str(ev.get("principal") or "")
        if principal and is_exempt(principal, self.exempt):
            self.exempted += 1
            return None
        key = principal or f"anon:{ev.get('client_ip', '')}|{ev.get('user_agent', '')}"
        template, objs = objects_in(ev.get("path") or "")
        if not objs:
            return None
        ts = float(ev.get("ts") or 0.0)
        owned, foreign = self._ownership(principal, objs)
        e = _Ev(ts=ts, template=template, objects=tuple(objs), status=int(ev.get("status") or 0),
                ip=str(ev.get("client_ip") or ""), owned=owned, foreign=tuple(foreign))
        with self._lock:
            st = self._p.get(key)
            if st is None:
                st = self._p[key] = _Principal()
                while len(self._p) > self.max_principals:
                    self._p.popitem(last=False)
            else:
                self._p.move_to_end(key)
            st.events.append(e)
            while st.events and (ts - st.events[0].ts > self.window_s or len(st.events) > self.max_events):
                st.events.popleft()
            same = [x for x in st.events if x.template == template]
            level, stats = self._judge(same)
            if level is None:
                return None
            last = st.emitted.get(template)
            rank = LEVELS.index(level)
            ips = set(stats["client_ips"])
            new_ip = bool(ips - st.emitted_ips.get(template, set()))
            # re-emit on a higher level, a new client IP in the walk (the walker rotated — that IP must be
            # contained too), or once a minute while it continues
            if last and ts - last[0] < self.reemit_s and LEVELS.index(last[1]) >= rank and not new_ip:
                return None
            seq = (last[2] + 1) if last else 1
            st.emitted[template] = (ts, level, seq)
            st.emitted_ips[template] = ips
        self.emitted += 1
        return self._alert(ev, principal, key, template, level, stats, seq, same)

    # ------------------------------------------------------------- internals --
    def _ownership(self, principal: str, objs: list[tuple[str, str]]) -> tuple[Optional[bool], list[tuple[str, str]]]:
        if not principal:
            return None, []
        foreign: list[tuple[str, str]] = []
        known = 0
        for t, oid in objs:
            owners = self.ownership.owners_of(t, oid)
            if owners is None:
                continue
            known += 1
            if principal not in owners:
                foreign.append((t, oid))
        if foreign:
            return False, foreign
        return (True if known == len(objs) else None), []

    def _judge(self, evs: list[_Ev]) -> tuple[Optional[str], dict]:
        distinct = {e.objects[-1] for e in evs}
        foreign_ok = {o for e in evs if e.owned is False and 200 <= e.status < 300 for o in e.foreign}
        foreign_any = {o for e in evs if e.owned is False for o in e.foreign}
        own = {e.objects[-1] for e in evs if e.owned is True}
        not_own = distinct - own
        nf = sum(1 for e in evs if e.status in (403, 404))
        gaps = [b.ts - a.ts for a, b in zip(evs, evs[1:]) if b.ts >= a.ts]
        med = statistics.median(gaps) if gaps else None
        nums = sorted(int(o[1]) for o in not_own if o[1].isdigit())
        diffs = [b - a for a, b in zip(nums, nums[1:])]
        sequential = len(nums) >= 4 and sum(1 for d in diffs if 0 < d <= 3) >= 0.6 * len(diffs)
        stats = {"requests": len(evs), "distinct_objects": len(distinct), "own_objects": len(own),
                 "cross_owner_success": len(foreign_ok), "cross_owner_attempts": len(foreign_any),
                 "not_found_or_forbidden": nf, "not_found_ratio": round(nf / len(evs), 2) if evs else 0.0,
                 "sequential_ids": sequential, "median_gap_s": round(med, 2) if med is not None else None,
                 "client_ips": sorted({e.ip for e in evs if e.ip})[:16]}
        if len(foreign_ok) >= self.cross_min:
            return "confirmed", stats
        if len(foreign_any) >= self.attempt_min:
            return "attempted", stats
        machine = med is not None and med <= 2.0
        if len(not_own) >= self.distinct_min and (sequential or stats["not_found_ratio"] >= 0.3 or machine):
            return "behavioural", stats
        return None, stats

    def _alert(self, ev: dict, principal: str, key: str, template: str, level: str, stats: dict, seq: int,
               evs: list[_Ev]) -> dict:
        first = evs[0].ts if evs else float(ev.get("ts") or 0.0)
        digest = hashlib.sha256(f"{key}|{template}|{int(first)}".encode()).hexdigest()[:12]
        obj_type = evs[-1].objects[-1][0] if evs else "object"
        exposed = sorted({o[1] for e in evs if e.owned is False and 200 <= e.status < 300 for o in e.foreign})
        sample = [mask(o) for o in (exposed or sorted({e.objects[-1][1] for e in evs}))[:8]]
        ts_iso = datetime.fromtimestamp(float(ev.get("ts") or 0.0), timezone.utc).isoformat()
        walk = {"level": level, "object_type": obj_type, "template": template, "window_s": self.window_s,
                "ownership_source": getattr(self.ownership, "name", "?"), "sample_objects_masked": sample, **stats}
        verb = {"confirmed": f"read {stats['cross_owner_success']} {obj_type}(s) owned by other customers",
                "attempted": f"requested {stats['cross_owner_attempts']} {obj_type}(s) owned by other customers (refused)",
                "behavioural": f"walked {stats['distinct_objects']} distinct {obj_type} ids"}[level]
        alert: dict[str, Any] = {
            "id": f"APIGW-OW-{digest}-{seq}", "source": ev.get("gateway") or "API gateway", "alert_type": "object_walk",
            "severity": _SEVERITY[level], "anomaly_score": {"critical": 0.95, "high": 0.85, "medium": 0.6}[_SEVERITY[level]],
            "principal_id": principal or None, "user_id": principal or "anonymous",
            "source_ip": ev.get("client_ip") or "", "user_agent": ev.get("user_agent") or "", "http_method": ev.get("method") or "GET",
            "url": template, "timestamp": ts_iso, "object_walk": walk,
            "payload": f"{ev.get('method') or 'GET'} {template} ×{stats['requests']} ({stats['distinct_objects']} objects)",
            "note": f"{principal or key} {verb} via {template} in {self.window_s}s ({ev.get('gateway') or 'API gateway'})",
        }
        for k in ("ja4", "ja3", "request_id"):
            if ev.get(k):
                alert[k] = ev[k]
        return {k: v for k, v in alert.items() if v is not None}


__all__ = ["ObjectWalkDetector", "objects_in", "mask", "LEVELS"]
