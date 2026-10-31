"""Known-bad TLS indicators: server certificates, client / server fingerprints, names.

A C2 server's certificate is far more specific than any client fingerprint. One SHA1 identifies
one certificate, while a JA3 or JA4 is shared by every program built on the same TLS library,
malware and legitimate software alike. Matches are therefore ranked:

    cert_sha1 / cert_sha256   the server's certificate        → "confirmed" (the list's confidence)
    sni / domain              the name the client asked for    → "confirmed" (parent domains match too)
    ip                        the server address               → strong
    ja3s                      the server's handshake reply     → strong
    ja4 / ja3                 the client's TLS stack           → strong, never confirmed on its own

Files (``AEGIS_TLS_IOC_FILE``, a comma list) in either shape:

    JSONL     {"kind": "cert_sha1", "value": "…", "name": "…", "confidence": 0.95, "source": "…"}
    CSV       abuse.ch SSLBL exports, recognised by their header comment:
              ``# Listingdate,SHA1,Listingreason`` (certificates) or
              ``# ja3_md5,Firstseen,Lastseen,Listingreason`` (JA3 fingerprints)

Nothing is fetched or bundled. ``ingest/fixtures/ndr/tls_ioc.sample.jsonl`` and
``sslbl.sample.csv`` show both shapes with invented values.
"""

from __future__ import annotations

import csv
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("aegis.ndr.intel")

KINDS = ("cert_sha1", "cert_sha256", "sni", "domain", "ip", "ja3s", "ja4", "ja3")
#: a match on one of these identifies the server or its name: proof, not a hint
CONFIRMING = frozenset({"cert_sha1", "cert_sha256", "sni", "domain"})


@dataclass(frozen=True)
class TlsIndicator:
    kind: str
    value: str
    name: str = ""
    confidence: float = 0.9
    source: str = "local"

    @property
    def confirming(self) -> bool:
        return self.kind in CONFIRMING

    def to_dict(self) -> dict:
        return {"kind": self.kind, "value": self.value, "name": self.name, "confidence": self.confidence,
                "source": self.source, "confirming": self.confirming}


def _norm(kind: str, value: str) -> str:
    v = str(value or "").strip().lower()
    if kind in ("cert_sha1", "cert_sha256"):
        v = v.replace(":", "")
    if kind in ("sni", "domain"):
        v = v.strip(".")
    return v


class TlsIntel:
    def __init__(self, indicators: tuple[TlsIndicator, ...] | list[TlsIndicator] = ()):
        self._by: dict[tuple[str, str], TlsIndicator] = {}
        for ind in indicators:
            self.add(ind)

    def __len__(self) -> int:
        return len(self._by)

    def add(self, ind: TlsIndicator) -> None:
        kind = "domain" if ind.kind == "sni" else ind.kind
        if kind not in KINDS:
            return
        self._by[(kind, _norm(kind, ind.value))] = TlsIndicator(kind, _norm(kind, ind.value), ind.name, ind.confidence, ind.source)

    @classmethod
    def from_env(cls) -> TlsIntel:
        intel = cls()
        for path in [p.strip() for p in os.environ.get("AEGIS_TLS_IOC_FILE", "").split(",") if p.strip()]:
            intel.load(path)
        return intel

    def load(self, path: str | Path) -> int:
        p = Path(path)
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.warning("[ndr:intel] %s unreadable (%s); skipped", p, e)
            return 0
        before = len(self._by)
        head = "\n".join(ln for ln in text.splitlines()[:12] if ln.startswith("#")).lower()
        if "sha1" in head and "listingreason" in head:
            self._load_sslbl(text, "cert_sha1", 1, src=p.name)
        elif "ja3_md5" in head:
            self._load_sslbl(text, "ja3", 0, src=p.name)
        else:
            for n, line in enumerate(text.splitlines(), 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    row = json.loads(line)
                    kind = str(row.get("kind") or row.get("type") or "").lower()
                    value = str(row.get("value") or "")
                    if kind not in KINDS or not value:
                        raise ValueError(f"kind must be one of {KINDS} with a value")
                    self.add(TlsIndicator(kind, value, str(row.get("name") or "")[:120],
                                          float(row.get("confidence", 0.9)), str(row.get("source") or p.name)[:60]))
                except (ValueError, TypeError, AttributeError) as e:
                    logger.warning("[ndr:intel] %s:%d skipped (%s)", p, n, str(e)[:80])
        added = len(self._by) - before
        logger.info("[ndr:intel] %d TLS indicators from %s", added, p)
        return added

    def _load_sslbl(self, text: str, kind: str, col: int, *, src: str) -> None:
        rows = csv.reader(ln for ln in text.splitlines() if ln.strip() and not ln.startswith("#"))
        for row in rows:
            if len(row) <= col or not row[col].strip():
                continue
            reason = row[-1].strip() if len(row) > col + 1 else ""
            self.add(TlsIndicator(kind, row[col], reason[:120], 0.9, f"abuse.ch SSLBL ({src})"))

    def match(self, *, cert_sha1: str = "", cert_sha256: str = "", sni: str = "", ip: str = "", ja3s: str = "",
              ja4: str = "", ja3: str = "") -> TlsIndicator | None:
        """The strongest indicator this connection matches, or ``None``."""
        if not self._by:
            return None
        for kind, value in (("cert_sha1", cert_sha1), ("cert_sha256", cert_sha256)):
            hit = self._by.get((kind, _norm(kind, value))) if value else None
            if hit:
                return hit
        if sni:
            labels = _norm("domain", sni).split(".")
            for i in range(len(labels) - 1):               # the name and each parent domain
                hit = self._by.get(("domain", ".".join(labels[i:])))
                if hit:
                    return hit
        for kind, value in (("ip", ip), ("ja3s", ja3s), ("ja4", ja4), ("ja3", ja3)):
            hit = self._by.get((kind, _norm(kind, value))) if value else None
            if hit:
                return hit
        return None


__all__ = ["CONFIRMING", "KINDS", "TlsIndicator", "TlsIntel"]
