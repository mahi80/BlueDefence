"""OCSF (Open Cybersecurity Schema Framework) in and out.

OCSF is the common event schema AWS Security Lake, CrowdStrike, Splunk, Microsoft Sentinel, Okta, Cribl and a
growing list of vendors already emit. One mapping here means any OCSF producer feeds AEGIS with no connector of its
own — ``POST /ingest/ocsf`` (push), a declarative connector whose spec says ``format: ocsf`` (pull), or the Kafka /
Vector / Fluent Bit paths — and AEGIS verdicts go back out as OCSF Detection Findings (``to_detection_finding``).

Inbound: one OCSF event (any class) → one AEGIS alert in the shape the specialists already read (``source_ip``,
``user_id``, ``host``, ``url``, ``cmdline``, ``parent_process`` …). Only fields OCSF defines are read; the event is
kept (bounded) under ``ocsf`` for the specialists and the audit trail. An event that names no class or carries no
time is refused (None) rather than guessed at.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

#: class_uid → (AEGIS alert_type, short name). Unknown classes still map (alert_type "ocsf_<uid>").
CLASSES: dict[int, tuple[str, str]] = {
    1001: ("file_activity", "File System Activity"),
    1006: ("scheduled_job", "Scheduled Job Activity"),
    1007: ("process_activity", "Process Activity"),
    1008: ("event_log_activity", "Event Log Activity"),
    1009: ("script_activity", "Script Activity"),
    2001: ("security_finding", "Security Finding"),
    2002: ("vulnerability_finding", "Vulnerability Finding"),
    2003: ("compliance_finding", "Compliance Finding"),
    2004: ("detection_finding", "Detection Finding"),
    3001: ("account_change", "Account Change"),
    3002: ("authentication", "Authentication"),
    3003: ("authorize_session", "Authorize Session"),
    3005: ("user_access", "User Access Management"),
    4001: ("network_activity", "Network Activity"),
    4002: ("http_activity", "HTTP Activity"),
    4003: ("dns_activity", "DNS Activity"),
    4006: ("smb_activity", "SMB Activity"),
    4009: ("email_activity", "Email Activity"),
    6003: ("api_activity", "API Activity"),
}
_SEVERITY = {0: "low", 1: "low", 2: "low", 3: "medium", 4: "high", 5: "critical", 6: "critical", 99: "medium"}
_SEV_SCORE = {"low": 0.3, "medium": 0.6, "high": 0.8, "critical": 0.95}
_MAX_RAW = 16_000


def _g(obj: Any, *path: str) -> Any:
    for p in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(p)
    return obj


def _first(*vals: Any) -> Any:
    for v in vals:
        if v not in (None, "", [], {}):
            return v
    return None


def _iso(t: Any) -> str | None:
    if isinstance(t, bool):
        return None
    if isinstance(t, (int, float)):
        secs = t / 1000.0 if t > 1e11 else float(t)        # OCSF `time` is epoch milliseconds
        try:
            return datetime.fromtimestamp(secs, UTC).isoformat()
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(t, str) and t.strip():
        return t.strip()
    return None


def _int(v: Any) -> int | None:
    """An OCSF enum id (``severity_id``, ``status_id``) that a producer may send as int, numeric string or junk."""
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, float) and v.is_integer():
        return int(v)
    if isinstance(v, str):
        t = v.strip()
        if 0 < len(t) <= 6 and t.isascii() and (t.isdigit() or (t[0] == "-" and t[1:].isdigit())):
            return int(t)
    return None


#: AEGIS's own verdicts (``to_detection_finding``) carry this marker; one fed back in is never a new alert
AEGIS_ORIGIN = "aegis_origin"
_OWN_PRODUCT = "bluedefence"


def is_own(ev: dict) -> bool:
    """An AEGIS verdict coming back (a SIEM / Security Lake that forwards ``/ingest/verdicts?format=ocsf`` to
    ``/ingest/ocsf``): re-ingesting it would loop — every finding a new alert, a new chain, a new finding."""
    un = ev.get("unmapped")
    if isinstance(un, dict) and un.get(AEGIS_ORIGIN):
        return True
    prod = _g(ev, "metadata", "product")
    if isinstance(prod, dict):
        for k in ("name", "vendor_name"):
            if str(prod.get(k) or "").strip().lower() == _OWN_PRODUCT:
                return True
    return False


def _base(p: Any) -> str:
    return str(p or "").replace("\\", "/").rsplit("/", 1)[-1]


def is_ocsf(ev: Any) -> bool:
    return (isinstance(ev, dict) and isinstance(ev.get("class_uid"), int) and not isinstance(ev.get("class_uid"), bool)
            and "time" in ev)


def to_alert(ev: dict, *, source_hint: str = "") -> dict | None:
    """One OCSF event → one AEGIS alert, or None when it is not OCSF (no ``class_uid`` / ``time``)."""
    if not is_ocsf(ev) or is_own(ev):
        return None
    cls = int(ev["class_uid"])
    alert_type, cls_name = CLASSES.get(cls, (f"ocsf_{cls}", str(ev.get("class_name") or f"class {cls}")))
    product = _first(_g(ev, "metadata", "product", "name"), _g(ev, "metadata", "product", "vendor_name"),
                     source_hint, "OCSF")
    vendor = _g(ev, "metadata", "product", "vendor_name")
    sid = _int(ev.get("severity_id"))
    sev = _SEVERITY.get(sid if sid is not None else 0, "medium")
    finding = ev.get("finding_info") if isinstance(ev.get("finding_info"), dict) else {}
    uid = _first(_g(ev, "metadata", "uid"), finding.get("uid"))
    if not uid:
        # the whole event: a prefix cut made two events that differ only after 8,000 characters one id (dedupe ate one)
        uid = hashlib.sha256(json.dumps(ev, sort_keys=True, default=str).encode()).hexdigest()[:32]
    alert: dict[str, Any] = {
        "id": f"ocsf:{str(uid)[:120]}",
        "source": f"{product}" + (f" ({vendor})" if vendor and vendor != product else ""),
        "alert_type": alert_type,
        "ocsf_class": cls_name,
        "severity": sev,
        "anomaly_score": _SEV_SCORE[sev],
        "timestamp": _iso(ev.get("time")),
    }
    title = _first(finding.get("title"), ev.get("message"), ev.get("activity_name"))
    if title:
        alert["title"] = str(title)[:256]
    desc = _first(finding.get("desc"), ev.get("status_detail"))
    if desc:
        alert["description"] = str(desc)[:2000]
    attacks = finding.get("attacks") or ev.get("attacks") or []
    if isinstance(attacks, list) and attacks:
        alert["tactics"] = sorted({str(_g(a, "tactic", "name")) for a in attacks if _g(a, "tactic", "name")})
        alert["techniques"] = sorted({str(_g(a, "technique", "uid")) for a in attacks if _g(a, "technique", "uid")})

    # who / where
    # never device.ip: that is the host that LOGGED the event (a domain controller for a 4625), not the source
    src_ip = _g(ev, "src_endpoint", "ip")
    if src_ip:
        alert["source_ip"] = str(src_ip)
    dst_ip = _g(ev, "dst_endpoint", "ip")
    if dst_ip:
        alert["dest_ip"] = str(dst_ip)
    dst_host = _first(_g(ev, "dst_endpoint", "hostname"), _g(ev, "dst_endpoint", "domain"))
    if dst_host:
        alert["dest_domain"] = str(dst_host)
    port = _g(ev, "dst_endpoint", "port")
    if isinstance(port, int):
        alert["dst_port"] = port
    if cls in (3001, 3002, 3003, 3005):
        # IAM classes: `user` is the account being authenticated / changed; `actor` is who (or which host) acted
        user = _first(_g(ev, "user", "name"), _g(ev, "user", "email_addr"), _g(ev, "user", "uid"),
                      _g(ev, "actor", "user", "name"), _g(ev, "actor", "user", "email_addr"), _g(ev, "actor", "user", "uid"))
    else:
        user = _first(_g(ev, "actor", "user", "name"), _g(ev, "actor", "user", "email_addr"), _g(ev, "user", "name"),
                      _g(ev, "user", "email_addr"), _g(ev, "actor", "user", "uid"), _g(ev, "user", "uid"))
    if user:
        alert["user_id"] = str(user)
    host = _first(_g(ev, "device", "hostname"), _g(ev, "device", "name"))
    if host:
        alert["host"] = str(host)
    cloud = _g(ev, "cloud", "provider")
    if cloud:
        alert["cloud_provider"] = str(cloud)

    # what
    url = _first(_g(ev, "http_request", "url", "url_string"), _g(ev, "http_request", "url", "path"))
    if url:
        alert["url"] = str(url)[:2000]
    ua = _g(ev, "http_request", "user_agent")
    if ua:
        alert["user_agent"] = str(ua)[:512]
    method = _g(ev, "http_request", "http_method")
    if method:
        alert["http_method"] = str(method)
    status = _first(_g(ev, "http_response", "code"), ev.get("status_code"))
    if status is not None:
        alert["status_code"] = status
    if cls == 1007 or _g(ev, "process", "cmd_line"):
        cmd = _g(ev, "process", "cmd_line")
        if cmd:
            alert["cmdline"] = str(cmd)[:2000]
        child = _first(_g(ev, "process", "name"), _base(_g(ev, "process", "file", "path")))
        parent = _first(_g(ev, "process", "parent_process", "name"), _base(_g(ev, "process", "parent_process", "file", "path")),
                        _g(ev, "actor", "process", "name"))
        if child:
            alert["child_process"] = str(child)
        if parent:
            alert["parent_process"] = str(parent)
    fpath = _g(ev, "file", "path")
    if fpath:
        alert["file_path"] = str(fpath)
    hashes = _g(ev, "file", "hashes")
    if isinstance(hashes, list):
        sha = next((h.get("value") for h in hashes if isinstance(h, dict) and str(h.get("algorithm", "")).upper().startswith("SHA-256")), None)
        if sha:
            alert["file_hash"] = str(sha)
    q = _g(ev, "query", "hostname")
    if q:
        alert["dns_queries"] = [str(q)]
        alert.setdefault("dest_domain", str(q))
    op = _g(ev, "api", "operation")
    if op:
        alert["operationName"] = str(op)
        svc = _g(ev, "api", "service", "name")
        if svc:
            alert["eventSource"] = str(svc)
    if cls == 3002:
        st = _int(ev.get("status_id"))
        alert["auth_result"] = "failure" if st == 2 else (
            "success" if st == 1 else str(ev.get("status") or "unknown").lower()[:32])
        mfa = ev.get("is_mfa")
        if isinstance(mfa, bool):
            alert["mfa"] = mfa
    vulns = ev.get("vulnerabilities")
    if isinstance(vulns, list) and vulns:
        cves = [str(_g(v, "cve", "uid")) for v in vulns if _g(v, "cve", "uid")]
        if cves:
            alert["cve"] = {"cve_ref": cves[0], "all": cves[:20]}
    disp = ev.get("disposition")
    if disp:
        alert["vendor_disposition"] = str(disp)
        alert["blocked"] = str(disp).lower() in ("blocked", "denied", "dropped", "quarantined")
    if ev.get("action") and "blocked" not in alert:
        alert["blocked"] = str(ev.get("action")).lower() in ("denied", "blocked")
    raw = json.dumps(ev, default=str, sort_keys=True)
    alert["ocsf"] = ev if len(raw) <= _MAX_RAW else {"class_uid": cls, "truncated": True, "head": raw[:_MAX_RAW]}
    return alert


# ---------------------------------------------------------------------------------------------------- outbound --

_VERDICT_SEVERITY = {"malicious": 4, "suspicious": 3, "uncertain": 2, "benign": 1}


def to_detection_finding(chain: dict, *, product_version: str = "") -> dict:
    """An AEGIS evidence chain (as stored in the audit log) → OCSF Detection Finding (class 2004), so a SIEM /
    Security Lake / data lake reads AEGIS verdicts like any other finding."""
    c = chain.get("chain", chain) if isinstance(chain, dict) else {}
    verdict = str(c.get("verdict") or "uncertain")
    # an EvidenceChain carries started_at / completed_at; the finding's time is when the verdict was reached (it used
    # to read created_at / timestamp, which a chain does not have, so every finding was stamped "now")
    ts = c.get("completed_at") or c.get("started_at") or c.get("created_at") or c.get("timestamp")
    t_ms = None
    if isinstance(ts, (int, float)) and not isinstance(ts, bool):
        t_ms = int(ts * 1000 if ts < 1e11 else ts)
    elif ts:
        try:
            d = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            t_ms = int((d if d.tzinfo else d.replace(tzinfo=UTC)).timestamp() * 1000)
        except ValueError:
            t_ms = None
    actions = c.get("recommended_actions") or []
    return {
        "class_uid": 2004, "class_name": "Detection Finding", "category_uid": 2, "category_name": "Findings",
        "activity_id": 1, "activity_name": "Create", "type_uid": 200401,
        "time": t_ms if t_ms is not None else int(datetime.now(UTC).timestamp() * 1000),
        "severity_id": _VERDICT_SEVERITY.get(verdict, 2), "status_id": 1,
        "confidence_score": int(round(float(c.get("confidence") or 0) * 100)),
        "metadata": {"version": "1.3.0", "uid": str(c.get("integrity_hash") or c.get("alert_id") or ""),
                     "product": {"name": "BlueDefence", "vendor_name": "BlueDefence", "version": product_version}},
        "finding_info": {"uid": str(c.get("alert_id") or ""), "title": f"AEGIS verdict: {verdict}",
                         "desc": "; ".join(str(r.get("conclusion") or "") for r in (c.get("reasoning") or [])[:3])[:2000],
                         "analytic": {"name": str(c.get("investigated_by") or "aegis"), "type_id": 1}},
        "evidences": [{"data": {"source": e.get("source"), "weight": e.get("weight"), "signal": str(e.get("signal") or "")[:500]}}
                      for e in (c.get("evidence") or [])[:20] if isinstance(e, dict)],
        "remediation": {"desc": "; ".join(f"{a.get('action_type')} -> {a.get('target')}" for a in actions[:10] if isinstance(a, dict))},
        "unmapped": {"verdict": verdict, "integrity_hash": c.get("integrity_hash"), AEGIS_ORIGIN: True},
    }


__all__ = ["AEGIS_ORIGIN", "CLASSES", "is_ocsf", "is_own", "to_alert", "to_detection_finding"]
