"""Campaign context (roadmap 2.8b): the last N minutes of the same source, folded into the alert.

An AI-agent attack is twenty alerts in fifteen minutes; the triage model sees one. The
``EventStore`` keeps a bounded ring of recent alerts per key (source IP, session, user) and
``campaign_summary`` folds them into the **campaign-summary shape the model is trained on**
(``importers/agentic.py``): ``recon`` / ``enumeration`` / ``automation`` / ``waf`` / ``access`` /
``timeline`` sections with raw counts, never a verdict. The orchestrator attaches it as
``alert["campaign_context"]`` *before* triage when the window has ≥ ``min_events`` prior
events, so specialists and the fine-tuned first-pass read the chain, not the single event.

Everything here is derived from fields the alerts already carry; nothing is fetched. It is
cheap enough for the hot path (in-memory, O(window)).
"""

from __future__ import annotations

import contextvars

import logging
import os
import re
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC as _UTC
from datetime import datetime
from typing import Any

from ...shared.bounded import BoundedDict
from ...shared.fingerprint import client_fingerprint
from ...shared.tls_client import TlsEstate, spoofed_browser
from .walk import SEED_KEYS

#: a stop (block / challenge) followed within this many seconds by another attempt from the same
#: client counts as "adapted after block" — humans pause; agents retry immediately
ADAPT_WINDOW_S = 120
_EMPTY_VALUES = frozenset({"", "-", "?", "none", "null", "unknown", "anonymous", "n/a"})
#: vendor actions that mean "let through untouched" — only those events teach the TLS model
_ALLOW_ACTIONS = frozenset({"allow", "allowed", "pass", "skip", "none", "noaction"})

_MAX_TEXT = 2048          # per-event text kept for campaign matching (a payload can be megabytes)

_RECON_HINTS = (".map", "/.env", "swagger", "openapi", "graphql", "__schema", "/admin", "phpinfo", "/.git", "telescope",
                "_profiler", "/api/schema", "debug", "actuator", "asset-manifest")


def _keys(alert: dict) -> list[str]:
    out = []
    for typ, keys in SEED_KEYS.items():
        if typ not in ("ip", "session", "account"):
            continue
        for k in keys:
            v = alert.get(k)
            # placeholder values ("anonymous", "-") would lump every unauthenticated event
            # on the internet into one fake campaign
            if isinstance(v, (str, int)) and str(v).strip().lower() not in _EMPTY_VALUES:
                out.append(f"{typ}:{v}")
    fp = client_fingerprint(alert)
    if fp is not None:
        out.append(f"fp:{fp.key}")
    return out


def _ip(alert: dict) -> str:
    for k in SEED_KEYS["ip"]:
        v = alert.get(k)
        if isinstance(v, str) and v:
            return v
    return ""


def _ts(alert: dict, now: float) -> float:
    for k in ("ts", "timestamp", "observed_at", "TimeGenerated", "Timestamp", "created_at"):
        v = alert.get(k)
        if isinstance(v, str):
            try:
                return datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
            except ValueError:
                pass
    return now


def _text(alert: dict) -> str:
    parts = []
    for k in ("url", "payload", "uri", "path", "endpoint", "c-uri", "request", "message"):
        v = alert.get(k)
        if isinstance(v, str):
            parts.append(v.lower())
    return " ".join(parts)


@dataclass
class _Event:
    ts: float
    alert_id: str
    source: str
    endpoint: str
    method: str
    text: str
    waf_sig: str
    blocked: bool | None
    status: int | None
    owner_mismatch: bool
    ua: str
    referer: bool | None
    ip: str = ""
    fp: str = ""


@dataclass
class EventStore:
    """Bounded per-key ring buffers of recent events, plus what the estate's benign traffic
    says about each TLS fingerprint (``tls``, outlives the window — see ``shared/tls_client.py``)."""
    window_min: int = 30
    max_per_key: int = 500
    # distinct keys (source IPs, sessions, users, fingerprints) kept: least-recently-seen evicted first, so a
    # botnet of a million IPs cannot grow this without limit (50k distinct IPs used to retain ~160 MB forever)
    max_keys: int = field(default_factory=lambda: int(os.environ.get("AEGIS_CAMPAIGN_MAX_KEYS", "50000")))
    tls: TlsEstate = field(default_factory=TlsEstate.from_env)
    _rings: BoundedDict = field(default=None)  # type: ignore[assignment]
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        if self._rings is None:
            self._rings = BoundedDict(self.max_keys)

    def add(self, alert: dict, now: float | None = None) -> list[str]:
        now = now or time.time()
        ev = _Event(
            ts=_ts(alert, now), alert_id=str(alert.get("id", "")), source=str(alert.get("source", "")),
            endpoint=str(alert.get("url") or alert.get("endpoint") or alert.get("uri") or alert.get("api") or "")[:120],
            method=str(alert.get("http_method") or alert.get("method") or alert.get("cs-method") or ""),
            text=_text(alert)[:_MAX_TEXT], waf_sig=str(alert.get("waf_rule") or alert.get("attack_type") or alert.get("rule") or ""),
            blocked=alert.get("blocked") if isinstance(alert.get("blocked"), bool) else None,
            status=alert.get("http_status") if isinstance(alert.get("http_status"), int) else alert.get("response_status") if isinstance(alert.get("response_status"), int) else None,
            owner_mismatch=bool(alert.get("accessed_object_owner") and alert.get("principal_id") and alert["accessed_object_owner"] != alert["principal_id"]),
            ua=str(alert.get("user_agent") or (alert.get("device_fingerprint") or {}).get("ua") if isinstance(alert.get("device_fingerprint"), dict) else alert.get("user_agent") or ""),
            referer=alert.get("referer_present") if isinstance(alert.get("referer_present"), bool) else None,
            ip=_ip(alert), fp=(lambda f: f.key if f else "")(client_fingerprint(alert)),
        )
        keys = _keys(alert)
        with self._lock:
            for k in keys:
                ring = self._rings.setdefault(k, deque(maxlen=self.max_per_key))
                self._rings.move_to_end(k)          # most recently seen keys are the last evicted
                ring.append(ev)
        fp = client_fingerprint(alert)
        if fp is not None and fp.kind == "ja4":
            # only requests the edge let through untouched teach the model what customers present
            benign = ev.blocked is False and str(alert.get("action") or "allow").strip().lower() in _ALLOW_ACTIONS
            try:
                self.tls.observe(fp.value, ev.ua, ev.ip, benign=benign, now=ev.ts)
            except Exception as e:  # noqa: BLE001 — learning is a bonus, never a blocker
                logging.getLogger("aegis.campaign").debug("[campaign] TLS learning skipped: %s", str(e)[:120])
        return keys

    def recent(self, key: str, before_ts: float, window_min: int | None = None) -> list[_Event]:
        w = (window_min or self.window_min) * 60
        with self._lock:
            ring = self._rings.get(key, ())
            return [e for e in ring if before_ts - w <= e.ts <= before_ts]


def campaign_summary(alert: dict, store: EventStore, *, min_events: int = 3, window_min: int | None = None,
                     now: float | None = None) -> dict | None:
    """Fold prior events for the alert's keys into the campaign-summary shape, or ``None`` when
    there is not enough history to say anything."""
    now = now or time.time()
    t = _ts(alert, now)
    seen: dict[str, _Event] = {}
    by_key: dict[str, int] = {}
    for k in _keys(alert):
        evs = [e for e in store.recent(k, t, window_min) if e.alert_id != str(alert.get("id", ""))]
        by_key[k] = len(evs)
        for e in evs:
            seen[e.alert_id or f"{e.ts}:{e.endpoint}"] = e
    events = sorted(seen.values(), key=lambda e: e.ts)
    if len(events) < min_events:
        return None
    w = window_min or store.window_min
    endpoints = {e.endpoint for e in events if e.endpoint}
    recon_hits = [e.endpoint for e in events if any(h in (e.text + " " + e.endpoint.lower()) for h in _RECON_HINTS)]
    sigs = {e.waf_sig for e in events if e.waf_sig and e.waf_sig.lower() not in ("none", "")}
    blocked = sum(1 for e in events if e.blocked is True)
    passed_sensitive = any(e.blocked is False and e.status == 200 and any(s in e.endpoint for s in ("/transfer", "/account", "/card", "/kyc", "/login"))
                           for e in events)
    cross = sum(1 for e in events if e.owner_mismatch)
    writes = sum(1 for e in events if e.owner_mismatch and e.method in ("PUT", "POST", "DELETE", "PATCH"))
    gaps = [b.ts - a.ts for a, b in zip(events, events[1:]) if b.ts >= a.ts]
    sd = 0.0
    if len(gaps) >= 2:
        m = sum(gaps) / len(gaps); sd = (sum((g - m) ** 2 for g in gaps) / len(gaps)) ** 0.5
    uas = {e.ua for e in events if e.ua}
    no_ref = [e for e in events if e.referer is False]
    first = events[0].ts
    summary: dict[str, Any] = {
        "alert_type": "campaign_summary", "window_minutes": w, "events_in_window": len(events),
        "keys": by_key, "sources": sorted({e.source for e in events if e.source}),
        "enumeration": {"distinct_endpoints": len(endpoints), "requests": len(events),
                        "no_referer_ratio": round(len(no_ref) / len(events), 2) if any(e.referer is not None for e in events) else None,
                        "sequential_id_pattern": _sequential(endpoints)},
        "recon": {"artefact_probes": sorted(set(recon_hits))[:6], "probe_count": len(recon_hits)},
        "waf": {"blocked": blocked, "distinct_signatures": len(sigs), "attack_classes": sorted(sigs)[:6],
                "passed_on_sensitive_endpoint_200": passed_sensitive},
        "access": {"cross_owner_reads": max(0, cross - writes), "cross_owner_writes": writes},
        "automation": {"inter_request_stddev_ms": int(sd * 1000), "distinct_user_agents": len(uas),
                       "requests_per_min": round(len(events) / max(1.0, (t - first) / 60), 1)},
        "timeline": {"first_event_at": datetime.fromtimestamp(first, _UTC).isoformat(),
                     "this_event_at": datetime.fromtimestamp(t, _UTC).isoformat(),
                     "span_minutes": round((t - first) / 60, 1)},
    }
    fp = client_fingerprint(alert)
    current = _Event(ts=t, alert_id=str(alert.get("id", "")), source="", endpoint=str(alert.get("url") or ""),
                     method=str(alert.get("http_method") or alert.get("method") or "").upper(), text=_text(alert), waf_sig=str(alert.get("attack_type") or ""),
                     blocked=alert.get("blocked") if isinstance(alert.get("blocked"), bool) else None,
                     status=None, owner_mismatch=False, ua=str(alert.get("user_agent") or ""), referer=None,
                     ip=_ip(alert), fp=fp.key if fp else "")
    known: set[str] = set()
    if fp is not None and fp.kind == "ja4":
        try:
            known = store.tls.benign_ips(fp.value)
        except Exception:  # noqa: BLE001
            known = set()
    summary["identity"] = _identity(events + [current], fp, known_benign_ips=known)
    summary["adaptation"] = _adaptation(events + [current])
    # a consistent browser user agent is a population, not a client: every customer on the same
    # browser build shares fingerprint + user agent, so a login burst is counted per IP + UA then
    population = current.ua.startswith("Mozilla/") and spoofed_browser(alert) is None
    summary["auth_burst"] = _auth_burst(events + [current], current, browser_population=population)
    if recon_hits and (sigs or cross or passed_sensitive):
        first_recon = min(e.ts for e in events if e.endpoint in recon_hits)
        first_attack = min((e.ts for e in events if (e.waf_sig and e.waf_sig.lower() != "none") or e.owner_mismatch), default=None)
        if first_attack is not None and first_attack >= first_recon:
            summary["timeline"]["recon_to_exploit_minutes"] = round((first_attack - first_recon) / 60, 1)
    return summary


def _attack_shaped(e: _Event) -> bool:
    """Stopped by the WAF, or flagged with an attack signature when the log does not say."""
    return e.blocked is True or (e.blocked is None and bool(e.waf_sig) and e.waf_sig.lower() != "none")


def _identity(events: list[_Event], fp, *, known_benign_ips: set[str] | None = None) -> dict:
    """Who the client is across the IPs it used: fingerprint, IP rotation, UA rotation — and how
    many *benign* clients share the fingerprint (a TLS fingerprint is shared by every user of the
    same browser build; one seen on customer traffic must never be enforced). ``known_benign_ips``
    is the estate's long memory of the fingerprint (``store.tls``): a partner whose job runs
    hourly is outside a 30-minute window but must still never be challenged."""
    same = [e for e in events if fp is not None and e.fp == fp.key]
    hostile = [e for e in (same or events) if _attack_shaped(e)]
    ips = {e.ip for e in hostile if e.ip}
    uas = {e.ua for e in hostile if e.ua}
    out: dict[str, Any] = {"distinct_source_ips": len(ips), "distinct_user_agents": len(uas)}
    if fp is not None:
        benign_ips = {e.ip for e in same if e.ip and e.blocked is False} - ips
        # the exact client (fingerprint *and* user agent): what a composite enforcement target hits
        client_ips = {e.ip for e in same if e.ip and e.blocked is False and e.ua == fp.user_agent} - ips
        out.update({"fingerprint": fp.key, "fingerprint_strength": fp.strength,
                    "events_with_fingerprint": len(same), "benign_ips_sharing_fingerprint": len(benign_ips),
                    "benign_ips_sharing_client": len(client_ips),
                    "known_benign_ips_for_fingerprint": len(set(known_benign_ips or ()) - ips)})
    return out


def _adaptation(events: list[_Event]) -> dict:
    """Did the client come straight back after being stopped — from a new IP, with a new payload?

    For every stopped event, the attempts that follow within ``ADAPT_WINDOW_S`` count as retries;
    a retry from a different IP is a rotation, one with a different payload / signature / endpoint
    is a mutation. Median seconds-to-retry separates an agent (seconds) from a human (minutes)."""
    # only attack-shaped requests count: a customer's page view that happens to share a
    # fingerprint (or a NAT IP) with a blocked client is not that client "coming back"
    current = events[-1] if events else None
    evs = sorted((e for e in events if _attack_shaped(e)), key=lambda e: e.ts)
    stops = [e for e in evs if e.blocked is True]
    retries: list[float] = []
    rot = mut = 0
    current_is_retry = False
    retry_ips: list[str] = []
    for e in evs:
        # a retry is the *same client coming back for the same thing*: within the window after a
        # stop, on the same endpoint template (object ids normalised) — or from the stopped IP
        # itself. Another client's unrelated false positive on a different endpoint is not one.
        prior = [b for b in stops if b.ts <= e.ts and b is not e and e.ts - b.ts <= ADAPT_WINDOW_S
                 and (_path_key(e.endpoint) == _path_key(b.endpoint) or (e.ip and e.ip == b.ip))]
        if not prior:
            continue
        # the stop this retry answers: the latest on the same endpoint template (same IP first,
        # then same user agent), else the latest from the same IP
        same_path = [x for x in prior if _path_key(x.endpoint) == _path_key(e.endpoint)]
        b = (next((x for x in reversed(same_path) if x.ip and x.ip == e.ip), None)
             or next((x for x in reversed(same_path) if x.ua and x.ua == e.ua), None)
             or (same_path[-1] if same_path else prior[-1]))
        retries.append(e.ts - b.ts)
        if e.ip and b.ip and e.ip != b.ip:
            rot += 1
        if (e.text, e.waf_sig, e.endpoint) != (b.text, b.waf_sig, b.endpoint):
            mut += 1
        for ip in (b.ip, e.ip):                      # both ends of the retry belong to the client
            if ip and ip not in retry_ips:
                retry_ips.append(ip)
        if e is current:
            current_is_retry = True
    retries.sort()
    # ``current_is_retry``: the request being judged is itself an attack-shaped retry after a stop.
    # Without it a customer's page view sharing a fingerprint (or a NAT) with the attacker would
    # inherit the group's verdict — found by the purple-team benchmark (browser-driven agent).
    # ``retry_ips``: every IP the client retried from — the pool it will rotate back to.
    return {"stops": len(stops), "retries_after_stop": len(retries), "ip_rotations_after_stop": rot,
            "mutations_after_stop": mut, "current_is_retry": current_is_retry, "retry_ips": retry_ips[:32],
            "median_seconds_to_retry": round(retries[len(retries) // 2], 1) if retries else None}


AUTH_BURST_WINDOW_S = 60
_AUTH_PATH = re.compile(r"/(log-?in|sign-?in|log-?on|auth(enticate)?|oauth2?/token|token|otp|mfa|2fa|verify-?otp|"
                        r"password|passwd|reset-?password|forgot-?password)(/|$)", re.I)
_WRITE = {"POST", "PUT", "PATCH"}


def is_auth_write(method: str, endpoint: str) -> bool:
    """An auth-form submission: POST / PUT / PATCH to a login, token, OTP or password endpoint."""
    return str(method or "").upper() in _WRITE and bool(_AUTH_PATH.search(str(endpoint or "").split("?", 1)[0]))


def _auth_burst(events: list[_Event], current: _Event, *, browser_population: bool = False) -> dict:
    """Credential stuffing / OTP brute force: one client submitting an auth form at machine rate.

    "One client" is strict on purpose — same TLS fingerprint *and* user agent, or same IP *and*
    user agent — so the customers behind a branch NAT (one IP, many browsers) never add up.
    When the user agent is a real browser's (``browser_population``), fingerprint + user agent
    is every customer on that browser build, so the client is IP + user agent instead.
    Only writes (POST / PUT / PATCH) to auth endpoints count; loading the login page does not."""
    by_fp = bool(current.fp) and not browser_population

    def same_client(e: _Event) -> bool:
        if by_fp and e.fp:
            return e.fp == current.fp and e.ua == current.ua
        return bool(current.ip) and e.ip == current.ip and e.ua == current.ua

    out: dict[str, Any] = {"current_is_auth_write": is_auth_write(current.method, current.endpoint), "attempts": 0,
                           "window_s": AUTH_BURST_WINDOW_S, "client": "fingerprint+ua" if by_fp else "ip+ua"}
    if not out["current_is_auth_write"]:
        return out
    hits = [e for e in events if current.ts - AUTH_BURST_WINDOW_S <= e.ts <= current.ts
            and is_auth_write(e.method, e.endpoint) and same_client(e)]
    gaps = sorted(b.ts - a.ts for a, b in zip(sorted(hits, key=lambda e: e.ts), sorted(hits, key=lambda e: e.ts)[1:]))
    out.update({"attempts": len(hits), "distinct_ips": len({e.ip for e in hits if e.ip}),
                "median_gap_s": round(gaps[len(gaps) // 2], 1) if gaps else None,
                "endpoints": sorted({_path_key(e.endpoint) for e in hits})[:4]})
    return out


_NUMERIC_SEG = re.compile(r"^\d+$")
_ID_SEG = re.compile(r"^[0-9a-fA-F-]{16,}$")


def _path_key(endpoint: str) -> str:
    """Endpoint template: no query string, numeric / id-shaped segments normalised."""
    path = str(endpoint).split("?", 1)[0]
    parts = [("{n}" if _NUMERIC_SEG.match(p) else "{id}" if _ID_SEG.match(p) else p) for p in path.split("/")]
    return "/".join(parts)


def _sequential(endpoints: set[str]) -> bool:
    import re
    nums = sorted(int(m.group(1)) for e in endpoints for m in [re.search(r"(?:id=|/)(\d{2,})(?:\b|/|$)", e)] if m)
    if len(nums) < 4:
        return False
    diffs = [b - a for a, b in zip(nums, nums[1:])]
    return sum(1 for d in diffs if 0 < d <= 3) >= len(diffs) * 0.6


# Low-and-slow: one client mutating payloads against a single endpoint over a long span,
# deliberately paced below the retry-after-stop cadence so ``_adaptation`` never counts an attempt
# as a retry and ``_auth_burst`` never sees a burst. Found by *accumulation* instead of cadence —
# a long-window count of attack-shaped WAF stops per source IP, grouped by endpoint template.
LOWSLOW_WINDOW_MIN = int(os.environ.get("AEGIS_LOWSLOW_WINDOW_MIN", "360"))     # 6 h of long memory
_LOWSLOW_REPORT_MIN = 2                      # attach the signal once a template has this many stops
_SENSITIVE_HINTS = ("/transfer", "/account", "/card", "/kyc", "/login", "/statement",
                    "/payment", "/download", "/export", "/beneficiary", "/fund")


def _low_and_slow_signal(alert: dict, store: EventStore, now: float | None = None) -> dict | None:
    """One client grinding a single endpoint, slow enough to stay under burst / retry detection.

    Keyed on the **source IP** (benign clients have their own IPs, so a shared TLS fingerprint or a
    branch NAT never aggregates here); only attack-shaped WAF stops count, and our own enforcement
    records are excluded. Events are grouped by endpoint template over ``LOWSLOW_WINDOW_MIN`` and the
    worst template is reported: its stop count, distinct payloads (the query string carries the
    mutation), median gap and span. Returns ``None`` unless the request being judged is itself an
    attack-shaped stop and some template has reached ``_LOWSLOW_REPORT_MIN`` — the *fire* thresholds
    live in ``orchestrator/low_and_slow.py`` so this stays a measurement, not a verdict."""
    now = now or time.time()
    t = _ts(alert, now)
    ip = _ip(alert)
    if not ip:
        return None
    blocked = alert.get("blocked")
    sig = str(alert.get("attack_type") or alert.get("waf_rule") or alert.get("rule") or alert.get("signature") or "")
    current_is_attack_stop = blocked is True or (blocked is None and bool(sig) and sig.lower() != "none")
    if not current_is_attack_stop:
        return None
    seen: dict[str, _Event] = {}
    for k in _keys(alert):
        for e in store.recent(k, t, window_min=LOWSLOW_WINDOW_MIN):
            seen[e.alert_id or f"{e.ts}:{e.endpoint}"] = e
    evs = [e for e in seen.values() if e.ip == ip and _attack_shaped(e) and "aegis" not in (e.waf_sig or "").lower()]
    if len(evs) < _LOWSLOW_REPORT_MIN:
        return None
    groups: dict[str, list[_Event]] = {}
    for e in evs:
        groups.setdefault(_path_key(e.endpoint), []).append(e)
    best_key, best = max(groups.items(), key=lambda kv: (len(kv[1]), len({x.endpoint for x in kv[1]})))
    if len(best) < _LOWSLOW_REPORT_MIN:
        return None
    stops = sorted(best, key=lambda e: e.ts)
    gaps = sorted(b.ts - a.ts for a, b in zip(stops, stops[1:]) if b.ts >= a.ts)
    median_gap = gaps[len(gaps) // 2] if gaps else None
    sensitive_templates = {k for k in groups if any(h in k.lower() for h in _SENSITIVE_HINTS)}
    return {
        "current_is_attack_stop": True,
        "window_min": LOWSLOW_WINDOW_MIN,
        "endpoint": best_key,
        "stops_on_endpoint": len(stops),
        "distinct_payloads": len({e.endpoint for e in stops}),
        "sensitive": bool(any(h in best_key.lower() for h in _SENSITIVE_HINTS)),
        "median_gap_s": round(median_gap, 1) if median_gap is not None else None,
        "span_minutes": round((stops[-1].ts - stops[0].ts) / 60, 1),
        "distinct_sensitive_endpoints": len(sensitive_templates),
        "client_ip": ip,
    }


def attach_campaign_context(alert: dict, store: EventStore, **kw) -> dict:
    """Judge the client's TLS handshake against the browser it claims (``tls_client``, before the
    request teaches the model anything), record the alert, then return a copy carrying
    ``campaign_context`` when history warrants it. The original dict is never mutated (it is what
    gets audited as received)."""
    # these keys are AEGIS's own findings about the alert; a copy already on the incoming alert was written by
    # whoever sent it — a forged `campaign_context.adaptation.retry_ips` used to become an unattended block on
    # the IPs the sender chose (review round 3 G1-9)
    if any(k in alert for k in _DERIVED_KEYS):
        alert = {k: v for k, v in alert.items() if k not in _DERIVED_KEYS}
    fp = client_fingerprint(alert)
    if fp is not None and fp.kind == "ja4":
        try:
            check = store.tls.assess(fp.value, fp.user_agent)
        except Exception:  # noqa: BLE001 — a bonus, never a blocker
            check = None
        if check is not None:
            alert = {**alert, "tls_client": check.to_dict()}
    store.add(alert)
    summary = campaign_summary(alert, store, **kw)
    low_slow = _low_and_slow_signal(alert, store, now=kw.get("now"))
    if summary is None and low_slow is None:
        return alert
    # low-and-slow is found by accumulation, not a 30-minute burst, so it can fire before the normal
    # summary has enough events: attach a minimal context carrying just the signal in that case.
    if summary is None:
        summary = {"alert_type": "campaign_summary", "events_in_window": 0, "window_minutes": store.window_min}
    if low_slow is not None:
        summary = {**summary, "low_and_slow": low_slow}
    return {**alert, "campaign_context": summary}


_DERIVED_KEYS = ("campaign_context", "tls_client", "low_and_slow", "deferred_at", "deferred_by", "audit_deferred")

# Keys only AEGIS writes about an alert, which the orchestrator's fast paths act on with no model in the loop.
ORCH_DERIVED_KEYS = ("campaign_context", "tls_client", "low_and_slow")

# The alert object whose derived keys were just attached here, in this thread/context. The orchestrator trusts derived
# keys only on that exact object; anywhere else (aegis/main.py, tenant / async callers, future entry points) they were
# written by the sender and are stripped (review round 4 O4-11).
TRUSTED_CONTEXT: contextvars.ContextVar[object | None] = contextvars.ContextVar("aegis_trusted_context", default=None)


__all__ = ["EventStore", "attach_campaign_context", "campaign_summary", "is_auth_write"]
