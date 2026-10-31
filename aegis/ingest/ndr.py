"""Network sensor (NDR) consumer — Zeek and Suricata TLS metadata in, egress findings out.

The sensor sees every connection, so this consumer never forwards raw events. Each record is
normalised and fed to ``agents/ndr/egress.EgressDetector``, and only its findings reach the
orchestrator: beacons, exfiltration, known-bad TLS and shadow AI.

Record shapes understood (one JSON object per line; ``{"records": [...]}`` and ``.gz`` too):

    Zeek       JSON logs (``LogAscii::use_json=T``; flat ``id.orig_h`` keys or a nested ``id``;
               epoch or ISO ``ts``). ``ssl.log`` → handshake: ``server_name``, ``version``,
               ``ja3`` / ``ja3s`` (ja3 package), ``ja4`` (FoxIO package), ``cert_chain_fps``,
               ``subject`` / ``issuer`` / ``validation_status`` when logged.
               ``conn.log`` → bytes: ``orig_bytes`` / ``resp_bytes``, ``duration``, ``service``.
               ``x509.log`` → certificate: ``fingerprint``, ``certificate.subject`` /
               ``.issuer`` / ``.not_valid_before`` / ``.not_valid_after``, ``san.dns``.
               ``_path`` tells them apart when present; otherwise the fields do.
    Suricata   EVE JSON: ``event_type`` ``tls`` (``tls.sni``, ``tls.ja3.hash``, ``tls.ja3s.hash``,
               ``tls.ja4``, ``tls.fingerprint`` (SHA1), ``tls.subject`` / ``issuerdn`` /
               ``notbefore`` / ``notafter``) and ``flow`` (``bytes_toserver`` / ``_toclient``,
               ``app_proto`` tls), joined by ``flow_id``.
    generic    any JSON with a client and server address plus a server name and / or byte
               counts: a forward proxy (``host`` / ``hostname``), firewall or Zscaler NSS feed
               shaped to ``src_ip``, ``dst_ip``, ``sni``, ``bytes_out``, ``bytes_in``, ``ts``.

Order matters only for joins: certificates (x509) before handshakes, and handshakes before
the connections they belong to. That is how Zeek and Suricata write them.
"""

from __future__ import annotations

import gzip
import json
import logging
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from ..agents.ndr.egress import EgressDetector
from .base import CONSUMED, AlertCheckpoint, BaseConsumer

logger = logging.getLogger("aegis.ingest.ndr")


_TS_MIN, _TS_MAX = 946_684_800.0, 4_102_444_800.0        # 2000-01-01 … 2100-01-01


def _ts(v: Any) -> float | None:
    """Epoch (s or ms) or ISO text → epoch seconds; ``None`` when absent, unreadable or absurd."""
    t = _ts_raw(v)
    return t if t is not None and _TS_MIN <= t <= _TS_MAX else None


def _ts_raw(v: Any) -> float | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v) / (1000.0 if v > 1e11 else 1.0)
    if isinstance(v, str) and v:
        s = v.strip().replace("Z", "+00:00")
        if len(s) >= 5 and s[-5] in "+-" and s[-3] != ":":             # Suricata +0000 → +00:00
            s = s[:-2] + ":" + s[-2:]
        try:
            return datetime.fromisoformat(s).timestamp()
        except ValueError:
            try:
                return float(s)
            except ValueError:
                return None
    return None


def _g(rec: dict, *keys: str) -> Any:
    """First present value among flat dotted keys (Zeek JSON) or nested paths."""
    for k in keys:
        if k in rec and rec[k] not in (None, "", "-", "(empty)"):
            return rec[k]
        cur: Any = rec
        for part in k.split("."):
            cur = cur.get(part) if isinstance(cur, dict) else None
            if cur is None:
                break
        if cur not in (None, "", "-", "(empty)"):
            return cur
    return None


def _int(v: Any) -> int:
    try:
        return max(0, min(int(float(v)), 10**13))          # bytes / ports: never negative, never absurd
    except (TypeError, ValueError, OverflowError):
        return 0


def _list(v: Any) -> list[str]:
    if isinstance(v, list):
        return [str(x) for x in v if x not in (None, "", "-")]
    if isinstance(v, str) and v not in ("", "-", "(empty)"):
        return [x for x in v.split(",") if x]
    return []


def _zeek(rec: dict) -> dict | None:
    path = str(rec.get("_path") or rec.get("_log") or "").lower()
    base = {"sensor": "zeek", "ts": _ts(rec.get("ts")), "uid": str(rec.get("uid") or ""),
            "src": _g(rec, "id.orig_h"), "sport": _int(_g(rec, "id.orig_p")),
            "dst": _g(rec, "id.resp_h"), "dport": _int(_g(rec, "id.resp_p"))}
    if path == "x509" or "certificate.subject" in rec or isinstance(rec.get("certificate"), dict):
        fp = rec.get("fingerprint") or rec.get("id")
        sha = str(rec.get("fingerprint") or "")
        return {"kind": "x509", "sensor": "zeek", "ts": base["ts"], "fingerprint": str(fp or ""), "fuid": str(rec.get("id") or ""),
                "sha256": sha if len(sha.replace(":", "")) == 64 else "",
                "sha1": str(rec.get("sha1") or rec.get("certificate.sha1") or (sha if len(sha.replace(":", "")) == 40 else "")),
                "subject": _g(rec, "certificate.subject"), "issuer": _g(rec, "certificate.issuer"),
                "not_before": _ts(_g(rec, "certificate.not_valid_before")), "not_after": _ts(_g(rec, "certificate.not_valid_after")),
                "san": _list(_g(rec, "san.dns"))}
    if not base["src"] or not base["dst"]:
        return None
    if path == "ssl" or any(k in rec for k in ("server_name", "ssl_history", "cipher", "cert_chain_fps", "ja3", "ja4")):
        return {**base, "kind": "tls", "sni": str(rec.get("server_name") or ""), "version": str(rec.get("version") or ""),
                "ja3": str(rec.get("ja3") or ""), "ja3s": str(rec.get("ja3s") or ""), "ja4": str(rec.get("ja4") or ""),
                "established": bool(rec.get("established", True)), "resumed": bool(rec.get("resumed", False)),
                "cert_fps": _list(rec.get("cert_chain_fps") or rec.get("cert_chain_fuids")),
                "subject": rec.get("subject"), "issuer": rec.get("issuer"),
                "validation": str(rec.get("validation_status") or "")}
    if path == "conn" or "conn_state" in rec or "orig_bytes" in rec:
        service = str(rec.get("service") or "").lower()
        return {**base, "kind": "conn", "bytes_out": _int(rec.get("orig_bytes")), "bytes_in": _int(rec.get("resp_bytes")),
                "duration": float(rec.get("duration") or 0.0), "service": service,
                "tls": "ssl" in service or "tls" in service}
    return None


def _suricata(rec: dict) -> dict | None:
    et = str(rec.get("event_type") or "")
    base = {"sensor": "suricata", "uid": str(rec.get("flow_id") or ""), "src": rec.get("src_ip"), "sport": _int(rec.get("src_port")),
            "dst": rec.get("dest_ip"), "dport": _int(rec.get("dest_port"))}
    if not base["src"] or not base["dst"]:
        return None
    if et == "tls":
        t = rec.get("tls") if isinstance(rec.get("tls"), dict) else {}
        ja3 = t.get("ja3") if isinstance(t.get("ja3"), dict) else {}
        ja3s = t.get("ja3s") if isinstance(t.get("ja3s"), dict) else {}
        ja4 = t.get("ja4")
        return {**base, "kind": "tls", "ts": _ts(rec.get("timestamp")), "sni": str(t.get("sni") or ""),
                "version": str(t.get("version") or ""), "ja3": str(ja3.get("hash") or ""), "ja3s": str(ja3s.get("hash") or ""),
                "ja4": str(ja4.get("hash") if isinstance(ja4, dict) else ja4 or ""),
                "cert_sha1": str(t.get("fingerprint") or ""), "subject": t.get("subject"), "issuer": t.get("issuerdn"),
                "not_before": _ts(t.get("notbefore")), "not_after": _ts(t.get("notafter"))}
    if et == "flow":
        f = rec.get("flow") if isinstance(rec.get("flow"), dict) else {}
        app = str(rec.get("app_proto") or "").lower()
        return {**base, "kind": "conn", "ts": _ts(f.get("start")) or _ts(rec.get("timestamp")),
                "bytes_out": _int(f.get("bytes_toserver")), "bytes_in": _int(f.get("bytes_toclient")),
                "duration": max(0.0, (_ts(f.get("end")) or 0.0) - (_ts(f.get("start")) or 0.0)), "service": app,
                "tls": app in ("tls", "ssl")}
    return None


def _generic(rec: dict) -> dict | None:
    src = _g(rec, "src_ip", "source_ip", "client_ip", "src", "clientip", "cip")
    dst = _g(rec, "dst_ip", "dest_ip", "server_ip", "dst", "serverip", "sip")
    sni = _g(rec, "sni", "server_name", "host", "hostname", "domain")
    out_b, in_b = _g(rec, "bytes_out", "sent_bytes", "bytes_sent", "reqsize", "client_bytes"), _g(rec, "bytes_in", "received_bytes", "bytes_received", "respsize", "server_bytes")
    if not src or not dst or (sni is None and out_b is None and in_b is None):
        return None
    return {"kind": "flow" if sni else "conn", "sensor": str(rec.get("sensor") or rec.get("source") or "generic")[:24],
            "ts": _ts(_g(rec, "ts", "timestamp", "time", "datetime", "@timestamp")), "uid": str(_g(rec, "uid", "id", "session_id") or ""),
            "src": str(src), "dst": str(dst), "dport": _int(_g(rec, "dst_port", "dest_port", "dport", "server_port") or 443),
            "sni": str(sni or ""), "ja4": str(rec.get("ja4") or ""), "ja3": str(rec.get("ja3") or ""),
            "cert_sha1": str(rec.get("cert_sha1") or ""), "bytes_out": _int(out_b), "bytes_in": _int(in_b), "tls": True}


_CAPS = {"sni": 255, "subject": 512, "issuer": 512, "validation": 128, "version": 32, "service": 32, "sensor": 24}


def _bound(ev: dict) -> dict | None:
    """Every string a record can put into detector state is capped; addresses must be strings."""
    for k in ("src", "dst"):
        if k in ev and not isinstance(ev[k], str):
            return None
    for k, v in list(ev.items()):
        if isinstance(v, str):
            ev[k] = v[:_CAPS.get(k, 128)]
        elif isinstance(v, list):
            ev[k] = [str(x)[:255] for x in v[:16]]
        elif k in ("subject", "issuer") and v is not None:
            ev[k] = str(v)[:512]
    return ev


def normalize(record: dict) -> dict | None:
    """Vendor record → one NDR event (``kind`` tls | conn | x509 | flow), or ``None``."""
    if not isinstance(record, dict):
        return None
    if "event_type" in record and ("src_ip" in record or "dest_ip" in record):
        ev = _suricata(record)
    elif "id.orig_h" in record or isinstance(record.get("id"), dict) or "_path" in record or "certificate.subject" in record \
            or isinstance(record.get("certificate"), dict):
        ev = _zeek(record)
    else:
        ev = _generic(record)
    if ev is None or _bound(ev) is None:
        return None
    if ev.get("ts") is None:
        import time as _time
        ev["ts"] = _time.time()                     # no sensor timestamp: order by arrival
    return ev


class NdrConsumer(BaseConsumer):
    """Normalise → egress detector → only its findings are yielded (deduped like any source)."""

    name = "ndr"

    def __init__(self, *, detector: EgressDetector | None = None, checkpoint: AlertCheckpoint | None = None):
        super().__init__(checkpoint)
        self.detector = detector or EgressDetector.from_env()
        self.events = 0

    def fetch(self, *, lines: Iterable[str] | None = None, path: str | Path | None = None) -> Iterator[dict]:
        sources: list[Iterable[str]] = []
        if lines is not None:
            sources.append(lines)
        elif path is not None:
            for one in [x.strip() for x in str(path).split(",") if x.strip()]:
                p = Path(one)
                sources.append((gzip.open if p.suffix == ".gz" else open)(p, "rt", encoding="utf-8", errors="replace"))
        else:
            raise ValueError("NdrConsumer.fetch needs lines= or path=")
        for src in sources:
            for ln in src:
                ln = ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                try:
                    obj = json.loads(ln)
                except json.JSONDecodeError:
                    self.skipped_invalid += 1
                    continue
                recs = obj.get("records") if isinstance(obj, dict) and isinstance(obj.get("records"), list) else [obj]
                yield from recs

    def normalize(self, record: dict) -> Any:
        ev = normalize(record)
        if ev is None:
            return CONSUMED
        self.events += 1
        return self.detector.observe(ev) or CONSUMED


_shared: EgressDetector | None = None
_ioc_store: Any = None
_sink: Any = None


def set_ioc_store(store: Any) -> None:
    """The service's threat-intel IOC store: SNI / server IP checked against feed domains and IPs."""
    global _ioc_store
    _ioc_store = store
    if _shared is not None:
        _shared.ioc_store = store


def set_sink(sink: Any) -> None:
    """The dashboard sink: discovered AI usage is mirrored to ``/api/soc/ai-usage`` (``/ai-registry``)."""
    global _sink
    _sink = sink
    if _shared is not None:
        _shared.usage.sink = sink


def shared_detector() -> EgressDetector:
    """One detector per process, so pushed and file-read sensor events share their state."""
    global _shared
    if _shared is None:
        _shared = EgressDetector.from_env(ioc_store=_ioc_store)
        if _sink is not None:
            _shared.usage.sink = _sink
    return _shared


def flush() -> None:
    """Write the discovered-AI-usage register now (service shutdown)."""
    if _shared is not None:
        _shared.usage.write()


def reset_shared_detector() -> None:
    global _shared
    _shared = None


__all__ = ["NdrConsumer", "flush", "normalize", "reset_shared_detector", "set_ioc_store", "set_sink", "shared_detector"]
