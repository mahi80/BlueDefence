"""TLS client consistency — does the TLS handshake match the browser the user agent claims?

The client chooses its user agent string, but the TLS ClientHello comes from its real network
stack. An AI agent built on python-httpx, aiohttp, Go or Node that sets a Chrome user agent
to blend in still shakes hands like a scripting library. JA4 (FoxIO, BSD-3-Clause) summarises
the ClientHello in a form that survives Chrome's extension-order randomisation::

    t13d1516h2_8daaf6152771_02713d6af862
    │ │ │ │ │ │  └ sorted cipher-suite hash  └ sorted extension + signature-algorithm hash
    │ │ │ │ │ └ ALPN, first + last character of the first value: h2 · h1 (http/1.1) · 00 (none)
    │ │ │ │ └ extension count (GREASE excluded)
    │ │ │ └ cipher-suite count (GREASE excluded)
    │ │ └ d = SNI names a domain · i = no SNI
    │ └ highest TLS version offered: 13, 12, …
    └ t = TLS over TCP · q = QUIC · d = DTLS

The evidence, strongest first:

    reference   ``AEGIS_JA4_DB`` — the operator's JSONL (``ja4``, ``label`` browser | library |
                middlebox, ``family``, ``name``), e.g. an export of their own traffic or a licensed
                database. None is bundled; ``ingest/fixtures/ja4_reference.sample.jsonl`` shows
                the shape with made-up values.
    learned     the estate's own traffic, *benign events only*. If honest automation
                (``python-httpx/…``, ``partner-sync/…``) introduces itself with this JA4 from two or
                more IPs, the JA4 is a library. If the JA4 carries three or more *different*
                browser user agents, it is shared by real people: a browser population, or a
                TLS-inspecting middlebox that re-originates every employee's handshake. A shared
                JA4 is never a mismatch.
    structural  what no mainstream browser's own handshake does: no ALPN, http/1.1 offered
                before h2, no TLS 1.3 from a version that has it, a handful of extensions. Thirty
                or more cipher suites, or no SNI, count for half.

The result for each request is a ``TlsCheck``:
- ``consistent``: True or False.
- ``strength``: ``strong`` when no browser produces this handshake (acted on), or ``weak``
  when it is odd (evidence only).
- ``observed``: browser, library, middlebox or unknown.
- the reasons, in plain words.

No check is made when the user agent claims no browser, or when there is no JA4.

**What it buys.** An agent that lies about being Chrome can be *challenged* on the exact pair,
its TLS fingerprint plus that user agent, wherever it rotates. Real Chrome users present a
different JA4 and never match. Anyone behind an unlearned middlebox who did match passes a
managed challenge. The check is never a block on its own.

**Limits.**
- A client that drives a real browser (Playwright, browser-use) is consistent by
  construction, as is one that imitates a browser's ClientHello (curl-impersonate, curl_cffi,
  uTLS).
- An HTTP/2-capable library (httpx[http2], Go, curl) has a browser-shaped structure. It is
  caught only by the reference file, or once the estate learns its honest user agent.
- Quiet requests can teach the learned model that a lie is normal. That only returns AEGIS to
  IP-level actions; it never causes collateral.
- Only the JA4 TLS *client* fingerprint (BSD-3-Clause) is used. JA4S, JA4H and JA4X are under
  the FoxIO licence, and this module does not use them.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("aegis.tls_client")

_JA4 = re.compile(r"^([tqd])([0-9a-z]{2})([di])(\d{2})(\d{2})([0-9a-z]{2})_([0-9a-f]{12})_([0-9a-f]{12})$", re.IGNORECASE)
_TRANSPORT = {"t": "tcp", "q": "quic", "d": "dtls"}

#: distinct browser user agents on one JA4 (benign) that make it "shared by real people"
SHARED_UAS = int(os.environ.get("AEGIS_TLS_SHARED_UAS", "3"))
#: distinct IPs whose honest automation user agent teaches "this JA4 is a library"
LIBRARY_IPS = int(os.environ.get("AEGIS_TLS_LIBRARY_IPS", "2"))
#: reference labels
LABELS = ("browser", "library", "middlebox")


# ------------------------------------------------------------------ parsing --

@dataclass(frozen=True)
class Ja4:
    raw: str
    transport: str        # tcp | quic | dtls
    version: str          # "13", "12", …
    sni: bool
    ciphers: int
    extensions: int
    alpn: str             # "h2", "h1", "h3", "00", …


def parse_ja4(value: Any) -> Ja4 | None:
    """The ``a`` section of a JA4 TLS client fingerprint, or ``None`` when ``value`` is not one."""
    if not isinstance(value, str):
        return None
    m = _JA4.match(value.strip())
    if not m:
        return None
    t, ver, sni, c, e, alpn = (g.lower() for g in m.group(1, 2, 3, 4, 5, 6))
    return Ja4(raw=value.strip().lower(), transport=_TRANSPORT[t], version=ver, sni=sni == "d",
               ciphers=int(c), extensions=int(e), alpn=alpn)


@dataclass(frozen=True)
class Claim:
    family: str           # chromium | firefox | webkit — the TLS stack the claimed browser uses
    product: str          # chrome | edge | opera | samsung | firefox | safari | chrome-ios | …
    major: int | None  # the engine's major version where the user agent says it

    @property
    def label(self) -> str:
        return f"{self.product.replace('-', ' ').title()}" + (f" {self.major}" if self.major else "")


def _ver(ua: str, token: str) -> int | None:
    m = re.search(re.escape(token) + r"(\d+)", ua)
    return int(m.group(1)) if m else None


def claimed_browser(user_agent: Any) -> Claim | None:
    """The mainstream browser a user agent claims to be, or ``None`` (automation, crawler, legacy).

    iOS browsers (Chrome / Firefox / Edge on iOS) run on WebKit's network stack, so they claim
    the ``webkit`` family; Edge, Opera and Samsung Internet are Chromium."""
    ua = str(user_agent or "")
    if not ua.startswith("Mozilla/5.0"):
        return None
    low = ua.lower()
    if "compatible;" in low and any(b in low for b in ("bot", "crawler", "spider", "slurp")):
        return None                    # a crawler that says so: verified separately (reverse DNS)
    if "trident/" in low or "msie " in low:
        return None                    # legacy Internet Explorer: TLS 1.2-era stacks, not judged
    ios = _ver(ua, " OS ")
    for tok, product in (("CriOS/", "chrome-ios"), ("FxiOS/", "firefox-ios"), ("EdgiOS/", "edge-ios"), ("OPT/", "opera-ios")):
        if tok in ua:
            return Claim("webkit", product, ios)
    for tok, product in (("Edg/", "edge"), ("EdgA/", "edge"), ("OPR/", "opera"), ("SamsungBrowser/", "samsung"),
                         ("YaBrowser/", "yandex"), ("Chrome/", "chrome"), ("Chromium/", "chromium")):
        if tok in ua:
            return Claim("chromium", product, _ver(ua, "Chrome/") or _ver(ua, "Chromium/"))
    if "Firefox/" in ua:
        return Claim("firefox", "firefox", _ver(ua, "Firefox/"))
    if "AppleWebKit/" in ua and "Safari/" in ua:
        return Claim("webkit", "safari", _ver(ua, "Version/") or ios)
    return None


def automation_product(user_agent: Any) -> str:
    """The product token of an honest non-browser user agent (``partner-sync`` for
    ``partner-sync/3.2 (python-httpx/0.27)``), or ``""`` for a browser claim / empty / opaque."""
    ua = str(user_agent or "").strip()
    if not ua or ua.startswith("Mozilla/"):
        return ""
    m = re.match(r"([A-Za-z][\w.\-]{1,40})/[\w.\-]+", ua)
    return m.group(1).lower() if m else ""


#: engine versions that offer TLS 1.3 by default (offering only 1.2 means it is not that browser)
_TLS13_SINCE = {"chromium": 70, "firefox": 63, "webkit": 13}


def _structure(j: Ja4, claim: Claim) -> list[tuple[int, str]]:
    """(weight, reason) for each thing the claimed browser's own handshake would not do."""
    out: list[tuple[int, str]] = []
    if j.transport == "tcp":
        if j.alpn == "00":
            out.append((2, "no ALPN offered (every mainstream browser offers h2)"))
        elif j.alpn == "h1":
            out.append((2, "http/1.1 offered before h2 (browsers offer h2 first)"))
        elif j.alpn != "h2":
            out.append((2, f"first ALPN value '{j.alpn}' (browsers offer h2 first)"))
    elif j.transport == "quic" and not j.alpn.startswith("h3"):
        out.append((1, f"QUIC with first ALPN value '{j.alpn}' (browsers offer h3)"))
    since = _TLS13_SINCE.get(claim.family)
    if j.version != "13" and since and claim.major and claim.major >= since:
        out.append((2, f"TLS 1.3 not offered ({claim.label} offers it)"))
    if j.extensions < 6:
        out.append((2, f"{j.extensions} TLS extensions (browsers send 13 or more)"))
    elif j.extensions < 10:
        out.append((1, f"{j.extensions} TLS extensions (browsers send 13 or more)"))
    if j.ciphers > 30:
        out.append((1, f"{j.ciphers} cipher suites (browsers offer 15-25; OpenSSL-default stacks offer 30+)"))
    if not j.sni and j.transport != "dtls":
        out.append((1, "no SNI (a browser names the site it connects to)"))
    return out


# ------------------------------------------------------------------ result --

@dataclass(frozen=True)
class TlsCheck:
    ja4: str
    claimed: str                 # e.g. "Chrome 130"
    family: str                  # chromium | firefox | webkit
    observed: str                # browser | library | middlebox | unknown
    consistent: bool
    strength: str                # "strong" (acted on) | "weak" (evidence only) | "" when consistent
    reasons: tuple[str, ...] = ()

    @property
    def mismatch(self) -> bool:
        return not self.consistent and self.strength == "strong"

    def to_dict(self) -> dict:
        return {"ja4": self.ja4, "claimed": self.claimed, "family": self.family, "observed": self.observed,
                "consistent": self.consistent, "strength": self.strength, "reasons": list(self.reasons)}


def spoofed_browser(alert: Any) -> dict | None:
    """The attached ``tls_client`` check when it is a strong mismatch (the user agent claims a
    browser the TLS stack cannot be), else ``None``. Attached by campaign context."""
    t = alert.get("tls_client") if isinstance(alert, dict) else None
    if isinstance(t, dict) and t.get("consistent") is False and t.get("strength") == "strong":
        return t
    return None


# ----------------------------------------------------------------- estate --

def _add(s: set, v: str, cap: int) -> None:
    if v and (v in s or len(s) < cap):
        s.add(v)


@dataclass
class _Seen:
    first: float
    last: float
    benign_events: int = 0
    browser_uas: set = field(default_factory=set)       # distinct browser-claim user agents
    browser_ips: set = field(default_factory=set)
    families: dict = field(default_factory=dict)        # family → benign events
    auto_ips: set = field(default_factory=set)          # IPs with an honest automation user agent
    auto_products: dict = field(default_factory=dict)   # product → benign events


def load_reference(path: str | Path) -> dict[str, dict]:
    """``AEGIS_JA4_DB``: one JSON object per line — ``ja4``, ``label`` (browser | library |
    middlebox), optional ``family`` and ``name``. Bad lines are skipped with a warning."""
    out: dict[str, dict] = {}
    p = Path(path)
    try:
        lines = p.read_text(encoding="utf-8").splitlines()
    except OSError as e:
        logger.warning("[tls] reference %s unreadable (%s); using none", p, e)
        return out
    for n, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            row = json.loads(line)
        except ValueError:
            logger.warning("[tls] %s:%d not JSON; skipped", p, n)
            continue
        j = parse_ja4(row.get("ja4")) if isinstance(row, dict) else None
        label = str(row.get("label", "")).lower() if isinstance(row, dict) else ""
        if j is None or label not in LABELS:
            logger.warning("[tls] %s:%d needs a JA4 and a label in %s; skipped", p, n, LABELS)
            continue
        out[j.raw] = {"label": label, "family": str(row.get("family") or "").lower(),
                      "name": str(row.get("name") or label)[:80]}
    logger.info("[tls] %d reference JA4 entries from %s", len(out), p)
    return out


class TlsEstate:
    """What this estate's own traffic says about each JA4 (bounded LRU), plus the reference file."""

    def __init__(self, *, reference: dict[str, dict] | None = None, max_ja4: int = 4096,
                 shared_uas: int = SHARED_UAS, library_ips: int = LIBRARY_IPS):
        self.reference = dict(reference or {})
        self.max_ja4 = max_ja4
        self.shared_uas = shared_uas
        self.library_ips = library_ips
        self._seen: OrderedDict[str, _Seen] = OrderedDict()
        self._lock = threading.Lock()
        self.observed = 0
        self.checks = 0
        self.mismatches = 0

    @classmethod
    def from_env(cls) -> TlsEstate:
        path = os.environ.get("AEGIS_JA4_DB", "").strip()
        return cls(reference=load_reference(path) if path else None)

    # -- learning (benign events only: hostile traffic never teaches the model)
    def observe(self, ja4: str, user_agent: str, ip: str, *, benign: bool, now: float | None = None) -> None:
        if not benign:
            return
        j = parse_ja4(ja4)
        if j is None:
            return
        claim = claimed_browser(user_agent)
        product = automation_product(user_agent) if claim is None else ""
        if claim is None and not product:
            return
        now = time.time() if now is None else now
        with self._lock:
            s = self._seen.get(j.raw)
            if s is None:
                s = self._seen[j.raw] = _Seen(first=now, last=now)
                while len(self._seen) > self.max_ja4:
                    self._seen.popitem(last=False)
            else:
                self._seen.move_to_end(j.raw)
            s.last = max(s.last, now)
            s.benign_events += 1
            if claim is not None:
                _add(s.browser_uas, str(user_agent)[:256], 64)
                _add(s.browser_ips, ip, 256)
                s.families[claim.family] = s.families.get(claim.family, 0) + 1
            else:
                _add(s.auto_ips, ip, 256)
                if product in s.auto_products or len(s.auto_products) < 8:
                    s.auto_products[product] = s.auto_products.get(product, 0) + 1
            self.observed += 1

    def benign_ips(self, ja4: str) -> set[str]:
        """Every IP that presented this JA4 on a request the edge let through (browser claims and
        honest automation alike) — the estate's long memory, not the campaign window."""
        j = parse_ja4(ja4)
        with self._lock:
            s = self._seen.get(j.raw) if j else None
            return set(s.browser_ips) | set(s.auto_ips) if s is not None else set()

    def learned(self, ja4: str) -> dict:
        j = parse_ja4(ja4)
        with self._lock:
            s = self._seen.get(j.raw) if j else None
            if s is None:
                return {}
            return {"benign_events": s.benign_events, "browser_user_agents": len(s.browser_uas),
                    "browser_ips": len(s.browser_ips), "families": dict(s.families),
                    "automation_ips": len(s.auto_ips), "automation_products": dict(s.auto_products),
                    "first_seen": s.first, "last_seen": s.last}

    # -- judging
    def assess(self, ja4: Any, user_agent: Any) -> TlsCheck | None:
        """Judge one request's JA4 against the browser its user agent claims (before the
        request itself is learned). ``None`` when it claims no browser or carries no JA4."""
        j = parse_ja4(ja4)
        claim = claimed_browser(user_agent)
        if j is None or claim is None:
            return None
        ref = self.reference.get(j.raw)
        seen = self.learned(j.raw)
        shared = int(seen.get("browser_user_agents") or 0) >= self.shared_uas
        library = (not shared) and int(seen.get("automation_ips") or 0) >= self.library_ips
        structure = _structure(j, claim)
        score = 0
        reasons: list[str] = []
        observed = "unknown"

        def consistent(obs: str, why: str) -> TlsCheck:
            return TlsCheck(ja4=j.raw, claimed=claim.label, family=claim.family, observed=obs, consistent=True,
                            strength="", reasons=(why,) if why else ())

        if ref is not None:
            name = ref["name"]
            if ref["label"] == "middlebox":
                return self._count(consistent("middlebox", f"reference: {name} (TLS-inspecting middlebox)"))
            if ref["label"] == "browser":
                if not ref["family"] or ref["family"] == claim.family:
                    return self._count(consistent("browser", f"reference: {name}"))
                score, observed = 2, "browser"
                reasons.append(f"reference: a {ref['family']} TLS stack ({name}), not {claim.family}")
            else:
                score, observed = 2, "library"
                reasons.append(f"reference: {name}")
        elif shared:
            n = seen["browser_user_agents"]
            obs = "middlebox" if sum(w for w, _ in structure) >= 2 else "browser"
            return self._count(consistent(obs, f"shared by {n} different browser user agents in this estate"
                                                + (" (a TLS-inspecting middlebox)" if obs == "middlebox" else "")))
        elif library:
            prods = seen.get("automation_products") or {}
            top = max(prods, key=prods.get) if prods else "automation"
            score, observed = 2, "library"
            reasons.append(f"this TLS stack introduces itself as {top}/… on {seen['automation_ips']} other clients")
        struct_score = sum(w for w, _ in structure)
        score += struct_score
        reasons.extend(r for _, r in structure)
        if observed == "unknown":
            observed = "library" if struct_score >= 2 else "browser" if not structure else "unknown"
        if score <= 0:
            return self._count(consistent("browser", ""))
        return self._count(TlsCheck(ja4=j.raw, claimed=claim.label, family=claim.family, observed=observed,
                                    consistent=False, strength="strong" if score >= 2 else "weak",
                                    reasons=tuple(reasons)))

    def _count(self, check: TlsCheck) -> TlsCheck:
        self.checks += 1
        if check.mismatch:
            self.mismatches += 1
        return check

    def stats(self) -> dict:
        with self._lock:
            return {"ja4_known": len(self._seen), "reference_entries": len(self.reference), "observed": self.observed,
                    "checks": self.checks, "mismatches": self.mismatches}


__all__ = [
    "LIBRARY_IPS",
    "SHARED_UAS",
    "Claim",
    "Ja4",
    "TlsCheck",
    "TlsEstate",
    "automation_product",
    "claimed_browser",
    "load_reference",
    "parse_ja4",
    "spoofed_browser",
]
