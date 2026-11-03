"""WAF consumer — Imperva, F5 ASM, Cloudflare, AWS WAF, Azure WAF (Front Door / App Gateway).

Reads exported attack events from a file (plain or ``.gz``), a socket-fed
spool, or any iterable and yields AEGIS perimeter alerts. Wire formats:

    CEF          "CEF:0|Vendor|Product|Version|SignatureId|Name|Severity|k=v k=v ..."
                 Imperva Cloud WAF ("Incapsula|SIEMintegration"), Imperva
                 SecureSphere, F5 ASM in CEF mode.
    F5 ASM kv    F5's default remote-logging profile: 'attack_type="...",
                 ip_client="1.2.3.4",request="GET /x HTTP/1.1",uri="/x",...'
    JSON lines   one event object per line (Imperva API exports, F5 JSON
                 logging profile), plus the cloud WAFs' native log records:
                   Cloudflare  Logpush ``firewall_events`` (``ClientIP``, ``RayID``, ``Source`` …)
                               and GraphQL ``firewallEventsAdaptive`` (``clientIP``, ``rayName`` …)
                   AWS WAF     WAFv2 logs from S3 / Firehose / CloudWatch (``httpRequest``,
                               ``terminatingRuleId``, ``terminatingRuleMatchDetails``, ``labels``)
                   Azure WAF   diagnostic records — ``FrontDoorWebApplicationFirewallLog`` and
                               ``ApplicationGatewayFirewallLog`` — nested (``properties``) or the
                               flattened Log Analytics ``AzureDiagnostics`` columns (``clientIP_s`` …);
                               an Event Hub / storage blob ``{"records": [...]}`` line is expanded.

Field mapping is table-driven per vendor so new keys are one line each;
the untouched event is kept under ``raw`` for the specialist's evidence.
No network code here on purpose — the WAF *enforcement* connector (roadmap
Phase 1) is where the vendor APIs live; ingestion stays a passive reader.
"""

from __future__ import annotations

import gzip
import json
import logging
import re
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

from .base import AlertCheckpoint, BaseConsumer, normalize_severity, severity_to_score

_log = logging.getLogger("aegis.ingest.waf")

_CEF_PREFIX = re.compile(r"^.*?CEF:(\d+)\|")  # tolerate any syslog prefix, incl. "ASM:CEF:0|"
_CEF_KEY_AT = re.compile(r"(?:^|\s)(\w+)=")  # a key starts a token only after whitespace
_F5_KV = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')

_F5_MAP = {
    "ip_client": "source_ip", "uri": "url", "request": "payload", "attack_type": "attack_type",
    "sig_names": "signature", "sig_ids": "signature_ids", "violations": "violations",
    "severity": "severity", "method": "http_method", "geo_location": "geo", "username": "user_id",
    "policy_name": "policy", "response_code": "response_code", "ip_client_port": "src_port",
    "dest_ip": "dest_ip", "web_application_name": "app", "support_id": "support_id",
    "request_status": "action", "date_time": "timestamp", "violation_rating": "violation_rating",
    "unit_hostname": "waf_host", "management_ip_address": "waf_mgmt_ip",
}
_IMPERVA_MAP = {
    "src": "source_ip", "request": "url", "requestMethod": "http_method", "act": "action",
    "cs1": "signature", "cs3": "rule_id", "cs4": "visitor_id", "cs5": "threat_type",
    "cs6": "client_app", "cs8": "attack_id", "cs9": "site", "suid": "user_id",
    "deviceExternalId": "event_id", "sourceServiceName": "site", "siteid": "site_id",
    "ccode": "geo", "xff": "x_forwarded_for", "start": "timestamp", "ref": "referrer",
    "requestClientApplication": "user_agent", "postbody": "post_body", "qstr": "query_string",
    "filePermission": "signature_file", "cn1": "response_code", "sPort": "src_port",
    "dproc": "dest_port", "fileid": "file_id",
}
_JSON_MAP = {
    "client_ip": "source_ip", "src_ip": "source_ip", "ip": "source_ip", "srcIp": "source_ip",
    "request_uri": "url", "uri": "url", "path": "url", "requestUrl": "url",
    "attack_type": "attack_type", "attackType": "attack_type", "signature": "signature",
    "sig_names": "signature", "ruleName": "signature", "severity": "severity", "method": "http_method",
    "http_method": "http_method", "user": "user_id", "username": "user_id", "geo": "geo",
    "country": "geo", "timestamp": "timestamp", "time": "timestamp", "@timestamp": "timestamp",
    "request": "payload", "raw_request": "payload", "action": "action", "host": "host",
}

_ATTACK_SEVERITY_HINT = {
    "sql injection": "high", "sqli": "high", "command execution": "critical", "remote code execution": "critical",
    "path traversal": "high", "xss": "medium", "cross site scripting": "medium",
    "illegal resource access": "medium", "bot": "medium", "ddos": "high", "credential stuffing": "high",
    "brute force": "high", "information leakage": "low", "scanner": "medium",
}


def parse_cef(line: str) -> Optional[dict]:
    """CEF line → {'vendor','product','version','signature_id','name','severity','ext':{...}}."""
    m = _CEF_PREFIX.match(line)
    if not m:
        return None
    body = line[m.end():]
    # header is 6 more pipe-separated fields; '\|' inside a field is an escaped pipe
    parts: list[str] = []
    cur = []
    i = 0
    while i < len(body) and len(parts) < 6:
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            cur.append(body[i + 1]); i += 2; continue
        if ch == "|":
            parts.append("".join(cur)); cur = []; i += 1; continue
        cur.append(ch); i += 1
    if len(parts) < 6:
        return None
    ext_raw = body[i:]
    ext: dict[str, str] = {}
    # Values may contain spaces and (in sloppy exports) unescaped '='; a new
    # key only begins after whitespace, so slice between key positions.
    keys = list(_CEF_KEY_AT.finditer(ext_raw))
    for n, m in enumerate(keys):
        start = m.end()
        end = keys[n + 1].start() if n + 1 < len(keys) else len(ext_raw)
        ext[m.group(1)] = ext_raw[start:end].replace("\\=", "=").replace("\\\\", "\\").strip()
    # CEF 'csNLabel=Name' pairs: expose 'Name' → value too
    for k, v in list(ext.items()):
        if k.endswith("Label") and k[:-5] in ext:
            ext[v.strip()] = ext[k[:-5]]
    return {
        "vendor": parts[0], "product": parts[1], "version": parts[2],
        "signature_id": parts[3], "name": parts[4], "severity": parts[5], "ext": ext,
    }


def parse_f5_kv(line: str) -> Optional[dict]:
    """F5 ASM 'key="value",key="value"' remote-logging line → dict (or None)."""
    pairs = _F5_KV.findall(line)
    if len(pairs) < 3:
        return None
    return {k: v.replace('\\"', '"') for k, v in pairs}


def _expand(line: str) -> Iterator[str]:
    """Azure Event Hub / storage-blob lines wrap many records: ``{"records": [...]}``."""
    if line.lstrip().startswith('{"records"'):
        try:
            recs = json.loads(line).get("records")
        except (ValueError, AttributeError):
            recs = None
        if isinstance(recs, list):
            for r in recs:
                if isinstance(r, dict):
                    yield json.dumps(r)
            return
    yield line


def _severity_hint(alert: dict) -> str:
    text = f"{alert.get('attack_type', '')} {alert.get('signature', '')}".lower()
    for key, sev in _ATTACK_SEVERITY_HINT.items():
        if key in text:
            return sev
    return "medium"


# ------------------------------------------------------------ cloud WAFs --

_CF_SOURCE_ATTACK = {
    "waf": "managed WAF rule", "firewallmanaged": "managed WAF rule", "firewallcustom": "custom firewall rule",
    "firewallrules": "custom firewall rule", "ratelimit": "rate limit", "bic": "browser integrity check",
    "securitylevel": "IP reputation", "uablock": "user-agent block", "ip": "IP access rule",
    "iprange": "IP access rule", "asn": "ASN access rule", "country": "country access rule",
    "botfight": "bot", "botmanagement": "bot", "dlp": "data loss prevention", "l7ddos": "ddos",
    "apishield": "API schema violation", "hot": "hotlink protection", "validation": "invalid request",
}
_AWS_CONDITION = {"SQL_INJECTION": "sql injection", "XSS": "xss", "REGEX": "regex match",
                  "SIZE_CONSTRAINT": "oversized request", "GEO_MATCH": "geo block", "IP_MATCH": "IP set match",
                  "RATE_BASED": "rate limit", "LABEL_MATCH": "label match"}


def _cf_attack(source: str, description: str, scores: dict) -> str:
    if description:
        return description
    worst = min(((v, k) for k, v in scores.items() if isinstance(v, (int, float)) and v > 0), default=None)
    if worst and worst[0] <= 20:
        return {"sqli": "sql injection", "xss": "xss", "rce": "remote code execution"}.get(worst[1], "WAF attack score")
    return _CF_SOURCE_ATTACK.get(source.lower(), source or "Cloudflare security event")


def _cloudflare(obj: dict) -> Optional[tuple[dict, Any]]:
    # Logpush firewall_events / http_requests (PascalCase) or GraphQL firewallEventsAdaptive (camelCase)
    if not (("RayID" in obj or "rayName" in obj or "OriginatorRayID" in obj)
            and ("ClientIP" in obj or "clientIP" in obj)):
        return None
    g = lambda *ks: next((obj[k] for k in ks if obj.get(k) not in (None, "")), "")  # noqa: E731
    source = str(g("Source", "source"))
    scores = {"sqli": obj.get("WAFSQLiAttackScore"), "xss": obj.get("WAFXSSAttackScore"),
              "rce": obj.get("WAFRCEAttackScore")}
    path, query = str(g("ClientRequestPath", "clientRequestPath", "ClientRequestURI")), str(g("ClientRequestQuery", "clientRequestQuery"))
    alert = {
        "source": "Cloudflare WAF", "source_ip": g("ClientIP", "clientIP"),
        "url": path + (query if query.startswith("?") or not query else "?" + query),
        "host": g("ClientRequestHost", "clientRequestHTTPHost"),
        "http_method": g("ClientRequestMethod", "clientRequestHTTPMethodName") or "GET",
        "user_agent": g("ClientRequestUserAgent", "userAgent"),
        "geo": g("ClientCountry", "clientCountryName", "clientCountry"),
        "action": g("Action", "action", "SecurityAction"),
        "signature": g("RuleID", "ruleId", "SecurityRuleID"),
        "rule_source": source,
        "attack_type": _cf_attack(source, str(g("Description", "description", "SecurityRuleDescription")), scores),
        "timestamp": g("Datetime", "datetime", "EdgeStartTimestamp"),
        "asn": g("ClientASN", "clientAsn"),
        "ja4": g("JA4", "ja4"), "ja3": g("JA3Hash", "ja3Hash"),
        "bot_score": obj.get("BotScore") if isinstance(obj.get("BotScore"), int) else None,
        "http_status": obj.get("EdgeResponseStatus") if isinstance(obj.get("EdgeResponseStatus"), int) else None,
    }
    if isinstance(obj.get("WAFAttackScore"), (int, float)):
        alert["waf_attack_score"] = obj["WAFAttackScore"]
        if 0 < obj["WAFAttackScore"] <= 20:
            alert["severity"] = "high"
    return {k: v for k, v in alert.items() if v not in (None, "")}, g("RayID", "rayName")


def _aws(obj: dict) -> Optional[tuple[dict, Any]]:
    req = obj.get("httpRequest")
    if not (isinstance(req, dict) and "clientIp" in req and ("webaclId" in obj or "terminatingRuleId" in obj)):
        return None
    headers = {str(h.get("name", "")).lower(): h.get("value") for h in req.get("headers") or [] if isinstance(h, dict)}
    details = obj.get("terminatingRuleMatchDetails") or []
    cond = next((d.get("conditionType") for d in details if isinstance(d, dict) and d.get("conditionType")), "")
    labels = [str(lb.get("name", "")) for lb in obj.get("labels") or [] if isinstance(lb, dict)]
    rule = str(obj.get("terminatingRuleId") or "")
    if cond:
        attack = _AWS_CONDITION.get(cond, cond.lower())
    elif any("sqli" in lb.lower() for lb in labels):
        attack = "sql injection"
    elif any("xss" in lb.lower() or "crosssitescripting" in lb.lower() for lb in labels):
        attack = "xss"
    elif obj.get("terminatingRuleType") == "RATE_BASED":
        attack = "rate limit"
    else:
        attack = rule or "AWS WAF rule"
    args = str(req.get("args") or "")
    alert = {
        "source": "AWS WAF", "source_ip": req.get("clientIp"), "geo": req.get("country"),
        "url": str(req.get("uri") or "") + (f"?{args}" if args else ""), "http_method": req.get("httpMethod") or "GET",
        "host": headers.get("host"), "user_agent": headers.get("user-agent"),
        "action": obj.get("action"), "signature": rule, "attack_type": attack,
        "matched_data": ",".join(str(x) for d in details if isinstance(d, dict) for x in (d.get("matchedData") or []))[:500],
        "labels": labels[:20] or None, "web_acl": str(obj.get("webaclId") or "").rsplit("/", 2)[-2:][0] or None,
        "timestamp": obj.get("timestamp"),
        "ja4": obj.get("ja4Fingerprint") or req.get("ja4Fingerprint"),
        "ja3": obj.get("ja3Fingerprint") or req.get("ja3Fingerprint"),
        "header_order": [str(h.get("name", "")) for h in req.get("headers") or [] if isinstance(h, dict)] or None,
    }
    # no requestId: no vendor id at all. The millisecond timestamp it fell back to is shared by every request in
    # that millisecond, and the content hash below tells them apart (review round 3 G4-4)
    return {k: v for k, v in alert.items() if v not in (None, "")}, req.get("requestId")


def _azure(obj: dict) -> Optional[tuple[dict, Any]]:
    cat = str(obj.get("category") or obj.get("Category") or "")
    flat = "clientIP_s" in obj or "clientIp_s" in obj
    if not (cat in ("FrontDoorWebApplicationFirewallLog", "ApplicationGatewayFirewallLog") or flat):
        return None
    props = obj.get("properties") if isinstance(obj.get("properties"), dict) else {}
    g = lambda *ks: next((src[k] for src in (props, obj) for k in ks if src.get(k) not in (None, "")), "")  # noqa: E731
    details = props.get("details") if isinstance(props.get("details"), dict) else {}
    appgw = cat == "ApplicationGatewayFirewallLog" or "ruleSetType" in props or "ruleSetType_s" in obj
    msg = str(details.get("msg") or details.get("message") or g("message", "Message", "details_msg_s", "details_message_s"))
    rule = str(g("ruleName", "ruleId", "ruleName_s", "ruleId_s"))
    attack = msg or rule or "Azure WAF rule"
    if "sqli" in rule.lower() or "sql" in msg.lower():
        attack = msg or "sql injection"
    alert = {
        "source": "Azure App Gateway WAF" if appgw else "Azure Front Door WAF",
        "source_ip": g("clientIP", "clientIp", "clientIP_s", "clientIp_s"),
        "url": g("requestUri", "requestUri_s"), "host": g("host", "hostname", "host_s", "hostname_s"),
        "action": g("action", "action_s"), "signature": rule, "attack_type": attack,
        "policy": g("policy", "policyId", "policy_s", "policyId_s"),
        "matched_data": str(details.get("data") or g("details_data_s"))[:500],
        "timestamp": g("time", "TimeGenerated"),
    }
    vendor_id = g("trackingReference", "transactionId", "trackingReference_s", "transactionId_g")
    return {k: v for k, v in alert.items() if v not in (None, "")}, vendor_id


def _cloud_normalize(obj: dict) -> Optional[tuple[dict, Any]]:
    for fn in (_cloudflare, _aws, _azure):
        out = fn(obj)
        if out is not None:
            return out
    return None


class WafConsumer(BaseConsumer):
    name = "waf"

    def __init__(self, *, vendor: str = "auto", checkpoint: Optional[AlertCheckpoint] = None):
        super().__init__(checkpoint)
        self.vendor = vendor

    # ------------------------------------------------------------- fetch --

    def fetch(self, *, lines: Optional[Iterable[str]] = None, path: Optional[str | Path] = None) -> Iterator[str]:
        if lines is not None:
            for ln in lines:
                if ln and ln.strip():
                    yield from _expand(ln.rstrip("\n"))
            return
        if path is None:
            raise ValueError("WafConsumer.fetch needs lines= or path=")
        p = Path(path)
        opener = gzip.open if p.suffix == ".gz" else open
        with opener(p, "rt", encoding="utf-8", errors="replace") as fh:
            for ln in fh:
                if ln.strip():
                    yield from _expand(ln.rstrip("\n"))

    # --------------------------------------------------------- normalize --

    def normalize(self, line: str) -> Optional[dict]:
        line = line.strip()
        if line.startswith("{"):
            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, RecursionError):
                return None                      # counted as invalid by the caller; not worth a log line per record
            return self._from_json(obj)
        cef = parse_cef(line)
        if cef is not None:
            return self._from_cef(cef)
        kv = parse_f5_kv(line)
        if kv is not None:
            return self._from_f5(kv)
        return None

    def _from_cef(self, cef: dict) -> dict:
        vendor = cef["vendor"].lower()
        ext = cef["ext"]
        if "f5" in vendor:
            alert = self._map(ext, _F5_MAP, source="F5 ASM")
        elif "imperva" in vendor or "incapsula" in vendor:
            alert = self._map(ext, _IMPERVA_MAP, source="Imperva WAF")
        else:
            alert = self._map(ext, {**_IMPERVA_MAP, **_F5_MAP}, source=f"{cef['vendor']} {cef['product']}".strip())
        alert.setdefault("attack_type", cef["name"])
        alert["signature_id"] = cef.get("signature_id", "")
        alert["severity"] = normalize_severity(alert.get("severity") or cef.get("severity"))
        if "id" not in alert:
            alert["id"] = self._make_id(alert, ext.get("deviceExternalId") or ext.get("support_id")
                                        or ext.get("fileid") or ext.get("rt") or ext.get("start"))
        alert["raw"] = {"cef": {k: v for k, v in cef.items() if k != "ext"}, **ext}
        return self._finish(alert)

    def _from_f5(self, kv: dict) -> dict:
        alert = self._map(kv, _F5_MAP, source="F5 ASM")
        alert["severity"] = normalize_severity(kv.get("severity") or _ATTACK_SEVERITY_HINT.get(
            str(alert.get("attack_type", "")).lower(), "medium"))
        if "id" not in alert:
            alert["id"] = self._make_id(alert, kv.get("support_id"))
        alert["raw"] = dict(kv)
        return self._finish(alert)

    def _from_json(self, obj: dict) -> Optional[dict]:
        if not isinstance(obj, dict):
            return None
        cloud = _cloud_normalize(obj)
        if cloud is not None:
            alert, vendor_id = cloud
            alert["severity"] = normalize_severity(alert.get("severity") or _severity_hint(alert))
            alert["id"] = self._make_id(alert, vendor_id)
            alert["raw"] = obj
            return self._finish(alert)
        src = str(obj.get("vendor") or obj.get("product") or obj.get("source") or "").lower()
        source = "F5 ASM" if "f5" in src else "Imperva WAF" if ("imperva" in src or "incapsula" in src) else (obj.get("source") or "WAF")
        alert = self._map(obj, _JSON_MAP, source=str(source))
        alert["severity"] = normalize_severity(obj.get("severity") or _ATTACK_SEVERITY_HINT.get(
            str(alert.get("attack_type", "")).lower(), "medium"))
        if "id" not in alert:
            alert["id"] = self._make_id(alert, obj.get("id") or obj.get("event_id") or obj.get("support_id"))
        alert["raw"] = obj
        return self._finish(alert)

    @staticmethod
    def _map(src: dict, mapping: dict, *, source: str) -> dict:
        alert: dict[str, Any] = {"source": source}
        for k, v in src.items():
            tgt = mapping.get(k)
            if tgt and v not in (None, ""):
                alert.setdefault(tgt, v)
        return alert

    @staticmethod
    def _make_id(alert: dict, vendor_id: Any) -> str:
        if vendor_id:
            vid = str(vendor_id)
            if len(vid) <= 48:
                return f"WAF-{vid}"
            # cutting at 48 merged two ids that share a long prefix (round 3 G4-4); keep a prefix and a hash of all
            import hashlib
            return f"WAF-{vid[:40]}-{hashlib.sha256(vid.encode()).hexdigest()[:12]}"
        import hashlib
        seed = "|".join(str(alert.get(k, "")) for k in ("source", "source_ip", "url", "timestamp", "signature", "payload",
                                                       "http_method", "user_agent", "matched_data", "action"))
        return "WAF-" + hashlib.sha256(seed.encode()).hexdigest()[:16]

    @staticmethod
    def _finish(alert: dict) -> dict:
        alert["anomaly_score"] = severity_to_score(alert.get("severity"))
        if "blocked" not in alert and alert.get("action"):
            # the WAF stopped this request (block / challenge / deny) — campaign context
            # uses it to see an attacker retrying after being stopped
            act = str(alert["action"]).lower()
            alert["blocked"] = any(w in act for w in ("block", "challenge", "captcha", "deny", "drop", "reject"))
        if "payload" not in alert:
            method = alert.get("http_method", "GET")
            url = alert.get("url", "")
            qs = alert.get("query_string")
            alert["payload"] = f"{method} {url}{('?' + qs) if qs and '?' not in str(url) else ''} HTTP/1.1".strip()
        for k in ("payload", "url"):
            if k in alert:
                # padding the request past 4,000 characters pushed the attack out of what the specialists saw
                # (review round 3 G7-10): keep 32 KB, and when cutting keep the head AND the tail
                v = str(alert[k])
                if len(v) > 32_000:
                    alert[k] = _cut_keeping_attack(v)
                    alert[f"{k}_truncated_from"] = len(v)       # over-length is itself a signal
        if "user_id" not in alert:
            alert["user_id"] = "anonymous"
        atk = alert.get("attack_type") or alert.get("signature") or "WAF event"
        alert["note"] = f"{atk} from {alert.get('source_ip', '?')} on {alert.get('url', '?')} ({alert['source']})"
        return alert


def _cut_keeping_attack(v: str) -> str:
    """Head and tail of an over-long payload, plus the window around the first exploit primitive wherever it
    sits: keeping only the first and last 16 KB let a 20 KB pad on each side hide the SQL injection in the middle
    (review round 4 S4-10). The full value (up to 1 MB) is decoded once to find it."""
    import urllib.parse
    head, tail = v[:12_000], v[-12_000:]
    mid = ""
    try:
        from ..agents.perimeter.tools import decode_payload
        scan = v[:1_000_000]
        prims = [p for ps in decode_payload(scan).data.get("primitives", {}).values() for p in ps]
        if prims:
            for src in (scan, urllib.parse.unquote_plus(scan)):      # original text first: offsets line up
                low = src.lower()
                at = min((i for i in (low.find(p.strip() or p) for p in prims) if i >= 0), default=-1)
                if 12_000 <= at < len(src) - 12_000:
                    lo = max(12_000, at - 4_000)
                    mid = src[lo:lo + 8_000]
                    break
    except Exception:  # noqa: BLE001 — the cut must happen even if the scan cannot
        mid = ""
    cut = len(v) - len(head) - len(tail) - len(mid)
    return f"{head} …[{cut} chars cut]… {mid}{' …… ' if mid else ''}{tail}"

