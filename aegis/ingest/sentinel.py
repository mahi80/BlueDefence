"""Microsoft Sentinel consumer — Log Analytics query API (KQL).

Pulls ``SecurityAlert`` rows (or any KQL you give it) from the Sentinel
workspace and yields AEGIS alerts. Uses the same plumbing choices as the
Splunk consumer: stdlib ``urllib`` (no new dependency), client-credential
OAuth with token caching, retry with backoff on 429/5xx, a wall-clock
timeout per request, injectable transport for tests.

API
    token  POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
           scope https://api.loganalytics.io/.default   (client credentials)
    query  POST https://api.loganalytics.io/v1/workspaces/{workspace}/query
           {"query": <KQL>, "timespan": "PT1H"} → {"tables":[{"name","columns","rows"}]}

Env
    SENTINEL_WORKSPACE_ID, SENTINEL_TENANT_ID, SENTINEL_CLIENT_ID,
    SENTINEL_CLIENT_SECRET   (app registration with Log Analytics Reader)
    SENTINEL_TIMESPAN        default PT1H
    SENTINEL_KQL             default: open SecurityAlert rows, newest first

Normalisation: a Sentinel alert's ``Entities`` JSON (Account / Host / Ip /
Url / Process ...) is folded into the flat keys the specialists read
(``user_id``, ``host``, ``source_ip``, ``url``, ``parent_process`` ...);
``Tactics`` / ``AlertName`` / ``Description`` are kept for triage; the raw
row stays under ``raw`` (minus nothing — Sentinel rows carry no secrets).
"""

from __future__ import annotations

import json
import logging
import os
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator, Optional

from .base import AlertCheckpoint, BaseConsumer, normalize_severity, severity_to_score

_log = logging.getLogger("aegis.ingest.sentinel")

DEFAULT_KQL = (
    "SecurityAlert"
    " | where Status != 'Resolved'"
    " | project TimeGenerated, SystemAlertId, AlertName, AlertSeverity, Description,"
    " ProductName, ProviderName, Tactics, Techniques, Entities, ExtendedProperties,"
    " CompromisedEntity, Status, AlertType"
    " | order by TimeGenerated desc"
)

#: transport(method, url, body_bytes|None, headers, timeout) -> (status, body_text)
Transport = Callable[[str, str, Optional[bytes], dict, float], tuple[int, str]]


def _urllib_transport(method: str, url: str, body: Optional[bytes], headers: dict, timeout: float) -> tuple[int, str]:
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — https to Microsoft endpoints
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


@dataclass
class SentinelConfig:
    workspace_id: str
    tenant_id: str
    client_id: str
    client_secret: str = field(repr=False, default="")
    timespan: str = "PT1H"
    kql: str = DEFAULT_KQL
    login_base: str = "https://login.microsoftonline.com"
    api_base: str = "https://api.loganalytics.io/v1"
    timeout_sec: float = 30.0
    max_retries: int = 4

    @classmethod
    def from_env(cls) -> "SentinelConfig":
        return cls(
            workspace_id=os.environ.get("SENTINEL_WORKSPACE_ID", ""),
            tenant_id=os.environ.get("SENTINEL_TENANT_ID", ""),
            client_id=os.environ.get("SENTINEL_CLIENT_ID", ""),
            client_secret=os.environ.get("SENTINEL_CLIENT_SECRET", ""),
            timespan=os.environ.get("SENTINEL_TIMESPAN", "PT1H"),
            kql=os.environ.get("SENTINEL_KQL", DEFAULT_KQL),
            login_base=os.environ.get("SENTINEL_LOGIN_BASE", "https://login.microsoftonline.com"),
            api_base=os.environ.get("SENTINEL_API_BASE", "https://api.loganalytics.io/v1"),
        )

    @property
    def configured(self) -> bool:
        return all((self.workspace_id, self.tenant_id, self.client_id, self.client_secret))


class SentinelAuthError(RuntimeError):
    pass


class SentinelConsumer(BaseConsumer):
    name = "sentinel"

    def __init__(self, config: Optional[SentinelConfig] = None, *,
                 checkpoint: Optional[AlertCheckpoint] = None,
                 transport: Optional[Transport] = None):
        super().__init__(checkpoint)
        self.cfg = config or SentinelConfig.from_env()
        self._transport: Transport = transport or _urllib_transport
        self._token: Optional[str] = None
        self._token_expiry = 0.0

    # ------------------------------------------------------------- fetch --

    def fetch(self, *, kql: Optional[str] = None, timespan: Optional[str] = None) -> Iterator[dict]:
        """Run the KQL and yield one dict per row (column name → value)."""
        query = kql or self.cfg.kql
        if kql is None and self.cfg.kql == DEFAULT_KQL:
            query = self._since_watermark()
        payload = json.dumps({"query": query, "timespan": timespan or self.cfg.timespan}).encode()
        url = f"{self.cfg.api_base}/workspaces/{self.cfg.workspace_id}/query"
        status, body = self._request_with_retry("POST", url, payload)
        if status != 200:
            raise RuntimeError(f"Sentinel query failed: HTTP {status}: {body[:200]}")
        data = json.loads(body or "{}")
        for table in data.get("tables", []):
            cols = [c.get("name") for c in table.get("columns", [])]
            for row in table.get("rows", []):
                yield dict(zip(cols, row))

    def _since_watermark(self) -> str:
        """The default query from the last alert handled (5 min overlap), oldest first. It re-read the whole
        1-hour window every poll, newest first: with more than the 5,000-id dedupe window of unresolved alerts,
        each poll evicted what it had just marked and re-triaged every alert on every poll (round 4 I4-3)."""
        from .base import _when
        wm = self.checkpoint.watermark(self.name) if self.checkpoint is not None else None
        t = _when(wm) if wm else None
        if t is None:
            return DEFAULT_KQL.replace("order by TimeGenerated desc", "order by TimeGenerated asc")
        since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(max(0.0, t - 300)))
        return (DEFAULT_KQL.replace("SecurityAlert", f"SecurityAlert | where TimeGenerated > datetime({since})", 1)
                .replace("order by TimeGenerated desc", "order by TimeGenerated asc"))

    def _request_with_retry(self, method: str, url: str, body: Optional[bytes]) -> tuple[int, str]:
        delay = 1.0
        last: tuple[int, str] = (0, "")
        for attempt in range(self.cfg.max_retries + 1):
            headers = {"Content-Type": "application/json", "Authorization": f"Bearer {self._bearer()}"}
            status, text = self._transport(method, url, body, headers, self.cfg.timeout_sec)
            last = (status, text)
            if status == 401 and attempt == 0:
                self._token = None  # rotated / expired token: re-auth once
                continue
            if status in (429, 500, 502, 503, 504) and attempt < self.cfg.max_retries:
                sleep = min(delay, 30.0) + random.uniform(0, 0.3)  # noqa: S311 — jitter, not crypto
                _log.warning("[sentinel] HTTP %s; retry %d/%d in %.1fs", status, attempt + 1, self.cfg.max_retries, sleep)
                time.sleep(sleep)
                delay *= 2
                continue
            return status, text
        return last

    def _bearer(self) -> str:
        if self._token and time.time() < self._token_expiry - 60:
            return self._token
        form = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": self.cfg.client_id,
            "client_secret": self.cfg.client_secret,
            "scope": "https://api.loganalytics.io/.default",
        }).encode()
        url = f"{self.cfg.login_base}/{self.cfg.tenant_id}/oauth2/v2.0/token"
        status, text = self._transport("POST", url, form,
                                       {"Content-Type": "application/x-www-form-urlencoded"},
                                       self.cfg.timeout_sec)
        if status != 200:
            raise SentinelAuthError(f"token request failed: HTTP {status}: {text[:160]}")
        data = json.loads(text)
        self._token = str(data["access_token"])
        self._token_expiry = time.time() + float(data.get("expires_in", 3600))
        return self._token

    # --------------------------------------------------------- normalize --

    def normalize(self, row: dict) -> Optional[dict]:
        alert_id = str(row.get("SystemAlertId") or row.get("AlertId") or "").strip()
        if not alert_id:
            return None
        severity = normalize_severity(row.get("AlertSeverity") or row.get("Severity"))
        entities = _parse_json(row.get("Entities"), default=[])
        ext = _parse_json(row.get("ExtendedProperties"), default={})
        product = str(row.get("ProductName") or row.get("ProviderName") or "Sentinel")
        alert: dict[str, Any] = {
            "id": f"SENTINEL-{alert_id}",
            "source": f"Sentinel/{product}",
            "severity": severity,
            "anomaly_score": severity_to_score(severity),
            "timestamp": str(row.get("TimeGenerated") or ""),
            "title": str(row.get("AlertName") or "")[:256],
            "description": str(row.get("Description") or "")[:2000],
            "tactics": _split_list(row.get("Tactics")),
            "techniques": _split_list(row.get("Techniques")),
            "alert_type": str(row.get("AlertType") or "")[:128],
            "status": str(row.get("Status") or ""),
            "compromised_entity": str(row.get("CompromisedEntity") or "")[:256],
        }
        _fold_entities(alert, entities if isinstance(entities, list) else [])
        if isinstance(ext, dict):
            # Identity Protection travel alerts carry the two locations here;
            # the Auth specialist reads them as prev_geo / curr_geo.
            for k, tgt in (("Previous Location", "prev_geo"), ("Current Location", "curr_geo"),
                           ("PreviousLocation", "prev_geo"), ("CurrentLocation", "curr_geo")):
                if ext.get(k) and tgt not in alert:
                    alert[tgt] = str(ext[k])[:64]
            for k in ("ProcessCommandLine", "Command Line", "CommandLine"):
                if ext.get(k) and "cmdline" not in alert:
                    alert["cmdline"] = str(ext[k])[:2000]
            for k in ("Request", "RequestUri", "Url"):
                if ext.get(k) and "url" not in alert:
                    alert["url"] = str(ext[k])[:2000]
        alert["payload"] = alert.get("payload") or _payload_from(alert)
        alert["note"] = f"{alert['title']} ({product})"
        alert["raw"] = {k: v for k, v in row.items() if k not in ("Entities", "ExtendedProperties")}
        return alert


def _parse_json(raw: Any, default: Any) -> Any:
    if raw is None or raw == "":
        return default
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except Exception:  # noqa: BLE001
        return default


def _split_list(raw: Any) -> list[str]:
    if not raw:
        return []
    if isinstance(raw, list):
        return [str(x) for x in raw]
    return [x.strip() for x in str(raw).split(",") if x.strip()]


def _fold_entities(alert: dict, entities: list) -> None:
    """Sentinel entity graph → the flat keys the specialists read."""
    for ent in entities:
        if not isinstance(ent, dict):
            continue
        t = str(ent.get("Type") or ent.get("type") or "").lower()
        if t == "account":
            name = ent.get("Name") or ent.get("name") or ent.get("AadUserId") or ent.get("Sid")
            if name and "user_id" not in alert:
                alert["user_id"] = str(name)[:256]
            upn = ent.get("UPNSuffix")
            if upn and name:
                alert["user_upn"] = f"{name}@{upn}"[:256]
        elif t == "host":
            name = ent.get("HostName") or ent.get("hostname") or ent.get("NetBiosName")
            if name and "host" not in alert:
                alert["host"] = str(name)[:256]
        elif t == "ip":
            addr = ent.get("Address") or ent.get("address")
            if addr:
                alert.setdefault("source_ip", str(addr)[:64])
                alert.setdefault("ips", []).append(str(addr)[:64])
        elif t == "url":
            u = ent.get("Url") or ent.get("url")
            if u and "url" not in alert:
                alert["url"] = str(u)[:2000]
        elif t == "process":
            cmd = ent.get("CommandLine") or ent.get("commandline")
            img = ent.get("ImageFile") or {}
            img_name = img.get("Name") if isinstance(img, dict) else None
            if cmd and "cmdline" not in alert:
                alert["cmdline"] = str(cmd)[:2000]
            parent = ent.get("ParentProcess") or {}
            pimg = parent.get("ImageFile") if isinstance(parent, dict) else None
            pname = pimg.get("Name") if isinstance(pimg, dict) else None
            if pname and "parent_process" not in alert:
                alert["parent_process"] = str(pname)[:256]
            if img_name and "child_process" not in alert:
                alert["child_process"] = str(img_name)[:256]
        elif t == "file":
            h = ent.get("FileHashes") or ent.get("Hashes")
            if isinstance(h, list) and h and "file_hash" not in alert:
                first = h[0]
                alert["file_hash"] = str(first.get("Value") if isinstance(first, dict) else first)[:128]
            name = ent.get("Name")
            if name and "file_path" not in alert:
                d = ent.get("Directory") or ""
                alert["file_path"] = f"{d}\\{name}"[:512] if d else str(name)[:512]
        elif t == "mailbox":
            mb = ent.get("MailboxPrimaryAddress")
            if mb and "user_id" not in alert:
                alert["user_id"] = str(mb)[:256]
        elif t == "dns":
            dom = ent.get("DomainName")
            if dom:
                alert.setdefault("dns_queries", []).append(str(dom)[:256])


def _payload_from(alert: dict) -> str:
    parts = [alert.get("title", "")]
    for k in ("url", "cmdline", "description"):
        if alert.get(k):
            parts.append(str(alert[k]))
    return " | ".join(p for p in parts if p)[:4000]
