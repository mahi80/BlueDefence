"""Outbound TLS from inside the bank: beacons, exfiltration, known-bad servers, shadow AI.

The WAF sees attackers coming in. A network sensor (Zeek, Suricata) sees what leaves: an
implant calling home, a slow drip of data to a host nobody else uses, a desktop pasting into
a public chatbot. The payloads are encrypted, so everything here is metadata: when, how often,
how much, to whom, with which certificate and from which client TLS stack.

The events come from ``ingest/ndr.py``:
- ``tls``: a handshake (SNI, client JA4 / JA3, server JA3S, the certificate when visible);
- ``conn``: a finished connection (bytes each way, duration);
- ``x509``: a certificate, joined to handshakes by fingerprint;
- ``flow``: a record that carries both handshake and bytes (generic exports).

Findings are kept per (internal host, destination). The destination is the SNI, or the
server IP when there is none.

    beacon     ≥ ``AEGIS_NDR_BEACON_MIN_CONN`` (8) handshakes over ≥ 10 min, median interval
               5 s – 6 h, jitter (MAD / median) ≤ ``AEGIS_NDR_BEACON_MAX_JITTER`` (0.2), RITA-style;
               the jitter bar is stricter on few intervals (× √(intervals / 24), up to 1),
               because the test runs on every new connection and a small sample can look regular by luck
    exfil      ≥ ``AEGIS_NDR_EXFIL_MIN_MB`` (50) MB sent within ``AEGIS_NDR_EXFIL_WINDOW_S`` (6 h)
               and ≥ 5 × what came back
    intel      the certificate, name, server or client fingerprint is on the TLS IOC list
               (``tls_intel.py``), or the name / IP is a known-bad domain / IP in the IOC store
    shadow AI  an AI service the host is not registered for (``ai_usage.py``); a second
               finding when it uploads ≥ ``AEGIS_NDR_AI_UPLOAD_MB`` (10) MB within an hour

Beacons and exfiltration count only towards **rare** destinations, where at most
``AEGIS_NDR_RARE_MAX_SRCS`` (3) internal hosts talk to the destination. Windows Update, Teams
and the EDR's own telemetry beacon too, from every host, and prevalence is what keeps them
quiet. ``AEGIS_NDR_ALLOW_DOMAINS`` names destinations that are never judged (suffix match);
``AEGIS_NDR_ALLOW_HOSTS`` names internal hosts that are never judged (proxies, scanners).
Certificate oddities never alert on their own; they corroborate:
- strong: a tool's default subject;
- medium: a self-signed certificate;
- weak: days old, a name mismatch, an untrusted chain, or no SNI.

Each finding is raised once per (host, destination), and raised again only when it gets
worse. All state is bounded LRU: pairs, prevalence, uid → destination, and certificates.

Known gaps: TLS 1.3 hides the server certificate from passive sensors, and ECH hides the SNI
(the destination becomes the IP). An implant that holds one connection open and talks inside
it makes no new handshakes. C2 behind a popular CDN name is suppressed by prevalence, and
exfiltration to a sanctioned SaaS that many hosts use is a DLP / CASB question, not this one.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import statistics
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from itertools import pairwise
from typing import Any

from ..shared.tls_client import parse_ja4
from .ai_usage import AiRegister, AiUsageRegister, ai_service
from .tls_intel import TlsIntel

logger = logging.getLogger("aegis.ndr.egress")

DEFAULT_INTERNAL = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7", "fe80::/10")
TLS_PORTS = frozenset({443, 8443, 4443, 9443, 993, 995, 465, 636, 853, 5061, 10443})
#: subjects that tools write when nobody fills in a certificate request (OpenSSL, Go's example)
DEFAULT_SUBJECT_MARKERS = ("internet widgits pty ltd", "default company ltd", "default city", "some-state",
                           "acme co", "cn=localhost")
FINDINGS = ("tls_known_bad", "tls_beacon", "tls_exfil", "shadow_ai")


def _env_f(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "") or default)
    except ValueError:
        return default


def internal_networks() -> list[Any]:
    raw = os.environ.get("AEGIS_INTERNAL_NETS", "").strip()
    nets = [n.strip() for n in raw.split(",") if n.strip()] if raw else list(DEFAULT_INTERNAL)
    out = []
    for n in nets:
        try:
            out.append(ipaddress.ip_network(n, strict=False))
        except ValueError:
            logger.warning("[ndr] AEGIS_INTERNAL_NETS entry %r is not a network; ignored", n)
    return out


def _suffix_list(name: str) -> tuple[str, ...]:
    return tuple(s.strip().lower().strip(".") for s in os.environ.get(name, "").split(",") if s.strip())


def _name_matches(name: str, pattern: str) -> bool:
    name, pattern = name.lower().strip("."), pattern.lower().strip(".")
    if pattern.startswith("*."):
        base = pattern[2:]
        return name.endswith("." + base) and name.count(".") == base.count(".") + 1
    return name == pattern


def _dn(x: str) -> str:
    return ",".join(sorted(p.strip().lower() for p in str(x).split(",") if p.strip()))


def client_shape(ja4: str) -> str:
    """``browser`` / ``library`` / ``unknown`` from the JA4 a-section alone."""
    j = parse_ja4(ja4)
    if j is None:
        return "unknown"
    if j.alpn in ("00", "h1") or j.extensions < 10:
        return "library"
    if j.alpn in ("h2", "h3") and j.extensions >= 13:
        return "browser"
    return "unknown"


def cert_flags(cert: dict, *, ts: float, sni: str) -> list[tuple[str, str, str]]:
    """(name, weight, detail) for each oddity in a server certificate — corroboration only."""
    subj, iss = str(cert.get("subject") or ""), str(cert.get("issuer") or "")
    validation = str(cert.get("validation") or "").lower()
    low = f"{subj} | {iss}".lower()
    out: list[tuple[str, str, str]] = []
    if any(m in low for m in DEFAULT_SUBJECT_MARKERS):
        out.append(("default_subject", "strong", f"certificate carries a tool's default subject ({subj[:80] or iss[:80]})"))
    self_signed = bool(subj and iss and _dn(subj) == _dn(iss)) or "self signed" in validation or "self-signed" in validation
    if self_signed:
        out.append(("self_signed", "medium", "self-signed certificate"))
    nb, na = cert.get("not_before"), cert.get("not_after")
    if isinstance(nb, (int, float)) and 0 <= ts - nb < 7 * 86400:
        out.append(("fresh_cert", "weak", f"certificate issued {(ts - nb) / 86400:.1f} days before the connection"))
    if isinstance(nb, (int, float)) and isinstance(na, (int, float)) and na - nb > 825 * 86400 and not self_signed:
        out.append(("long_validity", "weak", f"certificate valid {(na - nb) / 86400:.0f} days (public CAs issue ≤ 398)"))
    names = [n for n in (cert.get("san") or []) if n]
    cn = next((p.split("=", 1)[1].strip() for p in subj.split(",") if p.strip().lower().startswith("cn=")), "")
    if cn:
        names.append(cn)
    if sni and names and not any(_name_matches(sni, n) for n in names):
        out.append(("name_mismatch", "weak", f"certificate names {', '.join(names[:3])}, not {sni}"))
    if validation and validation not in ("ok", "valid") and not self_signed:
        out.append(("untrusted_chain", "weak", f"certificate validation: {validation[:60]}"))
    return out


def beacon_stats(starts: list[float]) -> dict | None:
    """Interval regularity of connection starts (seconds): median, MAD / median, Bowley skew."""
    ts = sorted(starts)
    iv = [b - a for a, b in pairwise(ts) if b - a >= 1.0]          # parallel connections are one beat
    if len(iv) < 2:
        return None
    med = statistics.median(iv)
    if med <= 0:
        return None
    mad = statistics.median(abs(x - med) for x in iv)
    if len(iv) >= 4:
        q1, _, q3 = statistics.quantiles(iv, n=4)
    else:
        q1, q3 = min(iv), max(iv)
    skew = (q3 + q1 - 2 * med) / (q3 - q1) if q3 > q1 else 0.0
    return {"connections": len(ts), "span_s": round(ts[-1] - ts[0], 1), "median_interval_s": round(med, 1),
            "jitter": round(mad / med, 3), "skew": round(skew, 3)}


@dataclass
class _Pair:
    src: str
    key: str
    first: float
    last: float
    sni: str = ""
    starts: deque = field(default_factory=lambda: deque(maxlen=256))
    sizes: deque = field(default_factory=lambda: deque(maxlen=256))
    volume: deque = field(default_factory=deque)          # (ts, out, in) inside the exfil window
    out_sum: int = 0
    in_sum: int = 0
    dsts: list = field(default_factory=list)              # server IPs, most recent last (≤ 8)
    ja4: list = field(default_factory=list)                # client fingerprints (≤ 4)
    dport: int = 0
    cert: dict = field(default_factory=dict)              # latest certificate identifiers
    cert_flags: list = field(default_factory=list)
    no_sni: bool = False
    intel: dict | None = None
    beacon: dict | None = None
    exfil: dict | None = None
    sensor: str = ""
    emitted: dict = field(default_factory=dict)           # (finding, indicator) → level raised


def _keep(lst: list, v: Any, cap: int) -> None:
    if not v:
        return
    if v in lst:
        lst.remove(v)
    lst.append(v)
    del lst[:-cap]


class EgressDetector:
    def __init__(self, *, intel: TlsIntel | None = None, ai: AiRegister | None = None,
                 usage: AiUsageRegister | None = None, ioc_store: Any = None, internal: list | None = None,
                 max_pairs: int = 100_000, max_keys: int = 100_000):
        self.intel = intel if intel is not None else TlsIntel()
        self.ai = ai if ai is not None else AiRegister()
        self.usage = usage if usage is not None else AiUsageRegister()
        self.ioc_store = ioc_store
        self.internal = internal if internal is not None else internal_networks()
        self.max_pairs, self.max_keys = max_pairs, max_keys
        self.min_conn = int(_env_f("AEGIS_NDR_BEACON_MIN_CONN", 8))
        self.min_span = _env_f("AEGIS_NDR_BEACON_MIN_SPAN_S", 600)
        self.max_jitter = _env_f("AEGIS_NDR_BEACON_MAX_JITTER", 0.2)
        self.min_interval, self.max_interval = 5.0, 6 * 3600.0
        self.rare_max = int(_env_f("AEGIS_NDR_RARE_MAX_SRCS", 3))
        self.exfil_bytes = int(_env_f("AEGIS_NDR_EXFIL_MIN_MB", 50) * 1_000_000)
        self.exfil_window = _env_f("AEGIS_NDR_EXFIL_WINDOW_S", 6 * 3600)
        self.exfil_ratio = _env_f("AEGIS_NDR_EXFIL_RATIO", 5)
        self.ai_upload = int(_env_f("AEGIS_NDR_AI_UPLOAD_MB", 10) * 1_000_000)
        self.allow_domains = _suffix_list("AEGIS_NDR_ALLOW_DOMAINS")
        self.allow_hosts = set(_suffix_list("AEGIS_NDR_ALLOW_HOSTS"))
        self._pairs: OrderedDict[tuple[str, str], _Pair] = OrderedDict()
        self._prev: OrderedDict[str, set] = OrderedDict()
        self._uid: OrderedDict[str, str] = OrderedDict()
        self._certs: OrderedDict[str, dict] = OrderedDict()
        self._hosts: OrderedDict[str, None] = OrderedDict()
        self._lock = threading.Lock()
        self.stats = {"tls": 0, "conn": 0, "x509": 0, "skipped": 0, "alerts": 0}

    @classmethod
    def from_env(cls, *, ioc_store: Any = None) -> EgressDetector:
        return cls(intel=TlsIntel.from_env(), ai=AiRegister.from_env(), usage=AiUsageRegister.from_env(), ioc_store=ioc_store)

    # ----------------------------------------------------------- plumbing --
    def _is_internal(self, ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a.version == n.version and a in n for n in self.internal)

    def _allowed_domain(self, name: str) -> bool:
        return bool(name) and any(name == d or name.endswith("." + d) for d in self.allow_domains)

    def _lru_get(self, od: OrderedDict, key: Any, make: Any, cap: int) -> Any:
        v = od.get(key)
        if v is None:
            v = od[key] = make()
            while len(od) > cap:
                od.popitem(last=False)
        else:
            od.move_to_end(key)
        return v

    def prevalence(self, key: str) -> int:
        with self._lock:
            return len(self._prev.get(key, ()))

    def _rare(self, key: str) -> bool:
        return len(self._prev.get(key, ())) <= self.rare_max

    # ------------------------------------------------------------- events --
    def observe(self, ev: dict) -> list[dict]:
        """One normalised NDR event in, zero or more alerts out."""
        kind = ev.get("kind")
        if kind == "x509":
            self.stats["x509"] += 1
            self._remember_cert(ev)
            return []
        src, dst = str(ev.get("src") or ""), str(ev.get("dst") or "")
        if not src or not dst or not self._is_internal(src) or self._is_internal(dst) or src in self.allow_hosts:
            self.stats["skipped"] += 1                     # egress only: internal → external
            return []
        try:
            ts = float(ev.get("ts") or 0.0)
        except (TypeError, ValueError):
            ts = 0.0
        if not 946_684_800.0 <= ts <= 4_102_444_800.0:       # absent / absurd → arrival time
            ts = time.time()
        out: list[dict] = []
        with self._lock:
            if kind in ("tls", "flow"):
                self.stats["tls"] += 1
                out += self._handshake(ev, src, dst, ts)
            if kind in ("conn", "flow"):
                self.stats["conn"] += 1
                out += self._bytes(ev, src, dst, ts, handshake_seen=kind == "flow")
        out = [a for a in out if a]
        self.stats["alerts"] += len(out)
        return out

    def _remember_cert(self, ev: dict) -> None:
        cert = {k: ev.get(k) for k in ("subject", "issuer", "not_before", "not_after", "san", "sha1", "sha256")}
        with self._lock:
            for fp in (ev.get("fingerprint"), ev.get("sha256"), ev.get("sha1"), ev.get("fuid")):
                if fp:
                    self._lru_get(self._certs, str(fp).lower().replace(":", ""), dict, 50_000).update(cert)

    def _cert_for(self, ev: dict) -> dict:
        cert = {k: ev.get(k) for k in ("subject", "issuer", "not_before", "not_after", "san", "validation") if ev.get(k)}
        for fp in list(ev.get("cert_fps") or [])[:1] + [ev.get("cert_sha256"), ev.get("cert_sha1")]:
            known = self._certs.get(str(fp or "").lower().replace(":", "")) if fp else None
            if known:
                cert = {**{k: v for k, v in known.items() if v}, **cert}
                break
        sha1 = ev.get("cert_sha1") or cert.get("sha1") or ""
        sha256 = ev.get("cert_sha256") or cert.get("sha256") or (list(ev.get("cert_fps") or []) or [""])[0]
        cert["sha1"], cert["sha256"] = str(sha1).lower().replace(":", ""), str(sha256).lower().replace(":", "")
        return cert

    def _pair(self, src: str, key: str, ts: float) -> _Pair:
        p = self._lru_get(self._pairs, (src, key), lambda: _Pair(src=src, key=key, first=ts, last=ts), self.max_pairs)
        p.last = max(p.last, ts)
        return p

    def _handshake(self, ev: dict, src: str, dst: str, ts: float) -> list[dict | None]:
        sni = str(ev.get("sni") or "").strip().lower().strip(".")
        key = sni or dst
        if ev.get("uid"):
            self._lru_get(self._uid, f"{ev.get('sensor')}:{ev['uid']}", lambda: key, 200_000)
        self._lru_get(self._hosts, src, lambda: None, 100_000)
        srcs = self._lru_get(self._prev, key, set, self.max_keys)
        if len(srcs) < 64:
            srcs.add(src)
        # The SNI is chosen by the client, so the allow-list only quiets the *heuristics* (beacon, shadow-AI)
        # for a domain the bank trusts. A threat-intel hit on the destination IP, JA3S or certificate is still
        # reported: "SNI c2.windowsupdate.com" on a known-bad IP used to return before the intel match.
        allowed = self._allowed_domain(sni)
        p = self._pair(src, key, ts)
        p.sni, p.sensor = sni, str(ev.get("sensor") or "")
        p.dport = int(ev.get("dport") or 0)
        _keep(p.dsts, dst, 8)
        _keep(p.ja4, str(ev.get("ja4") or ""), 4)
        p.starts.append(ts)
        cert = self._cert_for(ev)
        if any(cert.get(k) for k in ("subject", "issuer", "sha1", "sha256")):
            p.cert = {k: cert.get(k) for k in ("subject", "issuer", "sha1", "sha256") if cert.get(k)}
            p.cert_flags = cert_flags(cert, ts=ts, sni=sni)
        p.no_sni = not sni and p.dport in TLS_PORTS
        out: list[dict | None] = []
        hit = self.intel.match(cert_sha1=cert.get("sha1", ""), cert_sha256=cert.get("sha256", ""), sni=sni, ip=dst,
                               ja3s=str(ev.get("ja3s") or ""), ja4=str(ev.get("ja4") or ""), ja3=str(ev.get("ja3") or ""))
        if hit is None:
            hit = self._store_hit(sni, dst)
        if hit is not None and not (allowed and hit.kind == "domain"):
            p.intel = hit.to_dict()
            out.append(self._emit("tls_known_bad", p, ts, 1, indicator=f"{hit.kind}:{hit.value}"))
        if allowed:
            return out
        svc = ai_service(sni)
        if svc is not None:
            status, system = self.ai.status(src, svc.endpoint)
            u, _ = self.usage.touch(src, svc, status, system, ts)
            if status in ("unregistered", "unapproved"):
                out.append(self._emit("shadow_ai", p, ts, 1, indicator=svc.endpoint,
                                      shadow_ai={**u.to_dict(), "level": "use"}))
            return out                       # an AI service is judged as AI usage, not as a beacon
        out.append(self._check_beacon(p, ts))
        return out

    def _store_hit(self, sni: str, dst: str) -> Any:
        if self.ioc_store is None:
            return None
        from .tls_intel import TlsIndicator
        try:
            labels = sni.split(".") if sni else []
            for i in range(max(0, len(labels) - 1)):
                ioc = self.ioc_store.lookup(".".join(labels[i:]), "domain")
                if ioc is not None:
                    return TlsIndicator("domain", ioc.value, ",".join(ioc.tags) or "threat-intel feed", ioc.confidence, ioc.source)
            ioc = self.ioc_store.lookup(dst, "ip")
            if ioc is not None:
                return TlsIndicator("ip", ioc.value, ",".join(ioc.tags) or "threat-intel feed", ioc.confidence, ioc.source)
        except Exception as e:  # noqa: BLE001 — a broken store must not stop the sensor feed
            logger.debug("[ndr] IOC store lookup failed: %s", str(e)[:120])
        return None

    def _bytes(self, ev: dict, src: str, dst: str, ts: float, *, handshake_seen: bool) -> list[dict | None]:
        if not (handshake_seen or ev.get("tls") or int(ev.get("dport") or 0) in TLS_PORTS):
            return []
        uid_key = f"{ev.get('sensor')}:{ev.get('uid')}" if ev.get("uid") else ""
        key = self._uid.get(uid_key) if uid_key else None
        known = handshake_seen or key is not None          # this connection's handshake was already counted
        sni = str(ev.get("sni") or "").strip().lower().strip(".")
        key = key or sni or dst
        # Known limit: the SNI is client-chosen, so a forged allow-listed SNI on a clean IP also skips the
        # volume (exfil) heuristic here. Closing it needs certificate-to-SNI verification; intel hits on the
        # IP / JA3S / certificate are still caught at the handshake.
        if self._allowed_domain(sni) or self._allowed_domain(key):
            return []
        p = self._pair(src, key, ts)
        _keep(p.dsts, dst, 8)
        p.dport = p.dport or int(ev.get("dport") or 0)
        p.sensor = p.sensor or str(ev.get("sensor") or "")
        if not known:
            # no handshake logged for it (ECH, a sensor that missed it): its start is still a beat
            srcs = self._lru_get(self._prev, key, set, self.max_keys)
            if len(srcs) < 64:
                srcs.add(src)
            p.starts.append(ts)
        out_b, in_b = max(0, int(ev.get("bytes_out") or 0)), max(0, int(ev.get("bytes_in") or 0))
        p.sizes.append(out_b)
        p.volume.append((ts, out_b, in_b))
        p.out_sum += out_b
        p.in_sum += in_b
        while p.volume and ts - p.volume[0][0] > self.exfil_window:
            _, o, i = p.volume.popleft()
            p.out_sum -= o
            p.in_sum -= i
        out: list[dict | None] = []
        svc = ai_service(p.sni or sni)
        if svc is not None:
            status, _ = self.ai.status(src, svc.endpoint)
            sent = self.usage.add_bytes(src, svc.endpoint, ts, out_b, 3600.0)
            if status in ("unregistered", "unapproved") and sent >= self.ai_upload:
                rows = [r for r in self.usage.rows() if r["host"] == src and r["endpoint"] == svc.endpoint]
                out.append(self._emit("shadow_ai", p, ts, 2, indicator=svc.endpoint,
                                      shadow_ai={**(rows[0] if rows else {}), "level": "upload", "uploaded_last_hour": sent}))
            return out
        if not known:
            out.append(self._check_beacon(p, ts))
        out.append(self._check_exfil(p, ts))
        return out

    # ---------------------------------------------------------- findings --
    def _check_beacon(self, p: _Pair, ts: float) -> dict | None:
        if len(p.starts) < self.min_conn or not self._rare(p.key):
            return None
        b = beacon_stats(list(p.starts))
        if b is None or b["span_s"] < self.min_span or not (self.min_interval <= b["median_interval_s"] <= self.max_interval):
            return None
        # the jitter estimate is noisy on a handful of intervals and this runs on every new one, so
        # the bar starts stricter and relaxes to AEGIS_NDR_BEACON_MAX_JITTER by 24 intervals
        bar = self.max_jitter * min(1.0, ((b["connections"] - 1) / 24) ** 0.5)
        if b["jitter"] > bar:
            return None
        b["jitter_bar"] = round(bar, 3)
        sizes = [s for s in p.sizes if s]
        if len(sizes) >= 4:
            med = statistics.median(sizes)
            b["median_bytes_out"] = int(med)
            b["size_dispersion"] = round(statistics.median(abs(s - med) for s in sizes) / med, 3) if med else None
        p.beacon = b
        return self._emit("tls_beacon", p, ts, 1)

    def _check_exfil(self, p: _Pair, ts: float) -> dict | None:
        if p.out_sum < self.exfil_bytes or p.out_sum < self.exfil_ratio * max(1, p.in_sum) or not self._rare(p.key):
            return None
        level = 2 if p.out_sum >= 10 * self.exfil_bytes else 1
        span = ts - p.volume[0][0] if p.volume else 0.0
        p.exfil = {"bytes_out": p.out_sum, "bytes_in": p.in_sum, "window_s": self.exfil_window, "span_s": round(span, 1),
                   "connections": len(p.volume), "ratio": round(p.out_sum / max(1, p.in_sum), 1)}
        return self._emit("tls_exfil", p, ts, level)

    def _signals(self, p: _Pair) -> list[dict]:
        sig: list[dict] = []
        if p.intel:
            sig.append({"name": "intel", "weight": "confirmed" if p.intel.get("confirming") else "strong",
                        "detail": f"{p.intel['kind']} on the TLS IOC list: {p.intel.get('name') or p.intel.get('source')}"})
        if p.beacon:
            b = p.beacon
            sig.append({"name": "beacon", "weight": "strong",
                        "detail": (f"every {b['median_interval_s']:.0f} s ±{b['jitter'] * 100:.0f}% over "
                                   f"{b['span_s'] / 60:.0f} min ({b['connections']} connections)")})
        if p.exfil:
            e = p.exfil
            sig.append({"name": "exfil", "weight": "strong",
                        "detail": f"{e['bytes_out'] / 1e6:.0f} MB out vs {e['bytes_in'] / 1e6:.1f} MB in over {e['span_s'] / 60:.0f} min"})
        for name, weight, detail in p.cert_flags:
            sig.append({"name": name, "weight": weight, "detail": detail})
        if p.no_sni:
            sig.append({"name": "no_sni", "weight": "weak", "detail": "client named no server (SNI): connecting by IP"})
        return sig

    def _emit(self, finding: str, p: _Pair, ts: float, level: int, *, indicator: str = "", **extra: Any) -> dict | None:
        k = (finding, indicator)
        if p.emitted.get(k, 0) >= level:
            return None
        p.emitted[k] = level
        n_srcs = len(self._prev.get(p.key, ()))
        shapes = {client_shape(j) for j in p.ja4} - {"unknown"}
        shape = "library" if "library" in shapes else ("browser" if shapes else "unknown")
        egress = {"finding": finding, "level": level, "destination": p.key, "sni": p.sni, "dst_ips": list(p.dsts),
                  "dest_port": p.dport, "prevalence": n_srcs, "rare": n_srcs <= self.rare_max,
                  "client_ja4": list(p.ja4), "client_shape": shape, "first_seen": p.first, "cert": dict(p.cert),
                  "beacon": p.beacon, "exfil": p.exfil, "intel": p.intel, "signals": self._signals(p), **extra}
        digest = hashlib.sha1(f"{finding}|{p.src}|{p.key}|{level}|{indicator}".encode()).hexdigest()[:16]
        when = datetime.fromtimestamp(ts, UTC).isoformat().replace("+00:00", "Z")
        note = {
            "tls_known_bad": lambda: f"{p.src} → {p.key}: {(p.intel or {}).get('kind')} on the TLS IOC list ({(p.intel or {}).get('name') or 'intel'})",
            "tls_beacon": lambda: (f"{p.src} calls {p.key} every {p.beacon['median_interval_s']:.0f} s (±{p.beacon['jitter'] * 100:.0f}%), "
                                   f"{p.beacon['connections']} connections; {n_srcs} internal host(s) talk to it"),
            "tls_exfil": lambda: (f"{p.src} sent {p.exfil['bytes_out'] / 1e6:.0f} MB to {p.key} "
                                  f"({p.exfil['ratio']:.0f}× what came back); {n_srcs} internal host(s) talk to it"),
            "shadow_ai": lambda: (f"{p.src} uses {extra.get('shadow_ai', {}).get('service', 'an AI service')} ({p.key}) — "
                                  f"{extra.get('shadow_ai', {}).get('status', 'unregistered')}"
                                  + (f", {extra['shadow_ai'].get('uploaded_last_hour', 0) / 1e6:.0f} MB uploaded in the last hour"
                                     if extra.get("shadow_ai", {}).get("level") == "upload" else "")),
        }[finding]()
        sev = {"tls_known_bad": "high", "tls_exfil": "high" if level > 1 else "medium", "tls_beacon": "medium",
               "shadow_ai": "medium" if level > 1 else "low"}[finding]
        return {"id": f"ndr-{finding}-{digest}", "source": f"NDR ({p.sensor or 'sensor'})", "alert_type": finding,
                "severity": sev, "timestamp": when, "source_ip": p.src, "dest_ip": p.dsts[-1] if p.dsts else "",
                "sni": p.sni, "dest_port": p.dport, "user_id": "anonymous", "egress": egress, "note": note}

    def snapshot(self) -> dict:
        with self._lock:
            return {**self.stats, "pairs": len(self._pairs), "destinations": len(self._prev), "hosts": len(self._hosts),
                    "certificates": len(self._certs), "intel": len(self.intel), "ai_registrations": len(self.ai.rows)}


__all__ = [
    "DEFAULT_SUBJECT_MARKERS",
    "FINDINGS",
    "TLS_PORTS",
    "EgressDetector",
    "beacon_stats",
    "cert_flags",
    "client_shape",
    "internal_networks",
]
