"""API-gateway consumer — every API call in, only object-walk alerts out.

Gateway logs carry what WAF logs do not: the **authenticated principal** (token subject /
consumer) next to the object id in the path. That is what BOLA detection needs. They also
carry *every* request, so this consumer never forwards raw events: each record is normalised
and fed to ``agents/api_abuse/object_walk.ObjectWalkDetector``, and only the alerts it emits
reach the orchestrator.

Record shapes understood (one JSON object per line; ``{"records": [...]}`` and ``.gz`` too):

    Azure API Management   ``GatewayLogs`` diagnostics (nested ``properties``) and the Log
                           Analytics ``ApiManagementGatewayLogs`` columns. APIM does not log JWT
                           claims by default — add the subject with a ``log-to-eventhub`` policy
                           or a ``x-user-id`` trace (``AEGIS_APIGW_PRINCIPAL_FIELD``); otherwise
                           ``userId`` / ``apimSubscriptionId`` is used.
    AWS API Gateway        JSON access logs (``$context.*``): ``requestId``, ``ip``, ``httpMethod``,
                           ``path`` / ``resourcePath``, ``status``, principal from
                           ``principalId`` / ``authorizer.claims.sub`` / ``sub`` / ``user``.
    Kong                   ``http-log`` plugin: ``request``, ``response``, ``client_ip``,
                           ``consumer`` / ``authenticated_entity``, ``started_at``.
    generic                any JSON with path/url, method, status, client ip and a principal
                           under a common name (sub, principal, user_id, consumer, subject) —
                           Apigee message logging, custom forwarders.

``AEGIS_APIGW_PRINCIPAL_FIELD`` names an extra (dotted) field to read the principal from.
"""

from __future__ import annotations

import gzip
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

from ..agents.api_abuse.object_walk import ObjectWalkDetector
from ..agents.api_abuse.ownership import ownership_from_env
from .base import AlertCheckpoint, BaseConsumer

logger = logging.getLogger("aegis.ingest.apigw")

_PRINCIPAL_KEYS = ("sub", "principal", "principalId", "principal_id", "user_id", "userId", "subject", "customer_id",
                   "cif", "consumer_id", "authenticated_user")


def _dig(obj: Any, dotted: str) -> Any:
    cur = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _ts(v: Any) -> Optional[float]:
    if isinstance(v, (int, float)):
        return float(v) / (1000.0 if v > 1e11 else 1.0)
    if isinstance(v, str) and v:
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
        except ValueError:
            pass
        for fmt in ("%d/%b/%Y:%H:%M:%S %z",):      # AWS $context.requestTime
            try:
                return datetime.strptime(v, fmt).timestamp()
            except ValueError:
                pass
    return None


def _first(obj: dict, *keys: str) -> Any:
    for k in keys:
        v = _dig(obj, k) if "." in k else obj.get(k)
        if v not in (None, "", "-"):
            return v
    return None


def normalize(record: dict, *, principal_field: str = "") -> Optional[dict]:
    """Vendor record → ``{gateway, ts, principal, client_ip, user_agent, method, path, status, request_id, ja4}``."""
    if not isinstance(record, dict):
        return None
    extra = principal_field or os.environ.get("AEGIS_APIGW_PRINCIPAL_FIELD", "").strip()
    props = record.get("properties") if isinstance(record.get("properties"), dict) else {}
    cat = str(record.get("category") or record.get("Category") or "")
    out: dict[str, Any]
    if cat == "GatewayLogs" or "ApimSubscriptionId" in record or ("apimSubscriptionId" in props):
        src = {**record, **props}
        out = {"gateway": "Azure APIM",
               "ts": _ts(_first(src, "time", "TimeGenerated")),
               "client_ip": _first(src, "callerIpAddress", "CallerIpAddress"),
               "method": _first(src, "method", "Method"),
               "path": _first(src, "url", "Url"),
               "status": _first(src, "responseCode", "ResponseCode"),
               "request_id": _first(src, "correlationId", "CorrelationId", "requestId"),
               "user_agent": _first(src, "userAgent", "UserAgent", "requestHeaders.User-Agent"),
               # the subscription key belongs to an APP: every customer of that app shares it. As the principal it
               # merged them into one "attacker" walking everyone's accounts, and the alert landed on whichever IP
               # came last (review round 3 G7-1). It is context, not identity: without a user the call is keyed
               # by its client address, like any unauthenticated call.
               "principal": _first(src, *(([extra] if extra else []) + ["userId", "UserId"])),
               "subscription": _first(src, "apimSubscriptionId", "ApimSubscriptionId")}
    elif isinstance(record.get("request"), dict) and isinstance(record.get("response"), dict):
        req, resp = record["request"], record["response"]
        headers = req.get("headers") if isinstance(req.get("headers"), dict) else {}
        out = {"gateway": "Kong",
               "ts": _ts(record.get("started_at")),
               "client_ip": record.get("client_ip"),
               "method": req.get("method"),
               "path": req.get("uri") or req.get("url"),
               "status": resp.get("status"),
               "request_id": headers.get("x-request-id") or headers.get("kong-request-id"),
               "user_agent": headers.get("user-agent"),
               "principal": _first(record, *(([extra] if extra else []) + ["consumer.custom_id", "consumer.username",
                                                                           "consumer.id", "authenticated_entity.id"]))}
    elif "httpMethod" in record and ("requestId" in record or "resourcePath" in record):
        out = {"gateway": "AWS API Gateway",
               "ts": _ts(_first(record, "requestTimeEpoch", "requestTime")),
               "client_ip": _first(record, "ip", "sourceIp"),
               "method": record.get("httpMethod"),
               "path": _first(record, "path", "resourcePath"),
               "status": record.get("status"),
               "request_id": record.get("requestId"),
               "user_agent": _first(record, "userAgent", "user_agent"),
               "principal": _first(record, *(([extra] if extra else []) + ["principalId", "authorizer.principalId",
                                                                           "authorizer.claims.sub", "claims.sub", "sub", "user", "caller"]))}
    else:
        path = _first(record, "path", "url", "uri", "request_uri", "requestUrl")
        method = _first(record, "method", "http_method", "httpMethod", "verb")
        if not path or not method:
            return None
        out = {"gateway": str(record.get("gateway") or record.get("source") or "API gateway"),
               "ts": _ts(_first(record, "timestamp", "time", "@timestamp", "ts")),
               "client_ip": _first(record, "client_ip", "clientIp", "ip", "source_ip", "remote_addr"),
               "method": method, "path": path,
               "status": _first(record, "status", "status_code", "response_code", "responseCode"),
               "request_id": _first(record, "request_id", "requestId", "id"),
               "user_agent": _first(record, "user_agent", "userAgent"),
               "principal": _first(record, *(([extra] if extra else []) + list(_PRINCIPAL_KEYS)))}
    if out.get("ts") is None:
        import time as _time
        out["ts"] = _time.time()                   # no vendor timestamp: order by arrival
    try:
        out["status"] = int(out.get("status") or 0)
    except (TypeError, ValueError):
        out["status"] = 0
    if not out.get("path") or not out.get("method"):
        return None
    out["method"] = str(out["method"]).upper()
    if out.get("principal") is not None:
        out["principal"] = str(out["principal"])
    for k in ("ja4", "JA4", "ja3"):
        if record.get(k):
            out["ja4" if k.lower() == "ja4" else "ja3"] = record[k]
    return out


class ApiGatewayConsumer(BaseConsumer):
    """Normalise → object-walk detector → only its alerts are yielded (deduped like any source)."""

    name = "apigw"

    def __init__(self, *, detector: Optional[ObjectWalkDetector] = None, checkpoint: Optional[AlertCheckpoint] = None):
        super().__init__(checkpoint)
        self.detector = detector or ObjectWalkDetector(ownership_from_env())
        self.events = 0

    def fetch(self, *, lines: Optional[Iterable[str]] = None, path: Optional[str | Path] = None) -> Iterator[dict]:
        src: Iterable[str]
        if lines is not None:
            src = lines
        elif path is not None:
            p = Path(path)
            src = (gzip.open if p.suffix == ".gz" else open)(p, "rt", encoding="utf-8", errors="replace")
        else:
            raise ValueError("ApiGatewayConsumer.fetch needs lines= or path=")
        for ln in src:
            ln = ln.strip()
            if not ln:
                continue
            try:
                obj = json.loads(ln)
            except json.JSONDecodeError:
                self.skipped_invalid += 1
                continue
            recs = obj.get("records") if isinstance(obj, dict) and isinstance(obj.get("records"), list) else [obj]
            for r in recs:
                yield r

    def normalize(self, record: dict) -> Optional[dict]:
        ev = normalize(record)
        if ev is None:
            return None
        self.events += 1
        return self.detector.observe(ev)

    def iter_alerts(self, **kwargs) -> Iterator[dict]:
        # an event that does not cross a threshold is the normal case, not an invalid record
        for record in self.fetch(**kwargs):
            try:
                alert = self.normalize(record)
            except Exception as e:  # noqa: BLE001 — one bad record must not stop the stream
                self.skipped_invalid += 1
                logger.warning("[ingest:apigw] record dropped: %s", str(e)[:160])
                continue
            if not alert:
                continue
            if not self.checkpoint.mark(f"{self.name}:{alert['id']}"):
                self.skipped_duplicates += 1
                continue
            self.yielded += 1
            yield alert


_shared: Optional[ObjectWalkDetector] = None


def shared_detector() -> ObjectWalkDetector:
    """One detector per process, so pushed and file-read gateway events share their windows."""
    global _shared
    if _shared is None:
        _shared = ObjectWalkDetector(ownership_from_env())
    return _shared


def reset_shared_detector() -> None:
    global _shared
    _shared = None


__all__ = ["ApiGatewayConsumer", "normalize", "shared_detector", "reset_shared_detector"]
