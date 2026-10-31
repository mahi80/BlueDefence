"""Client fingerprints — follow an attacking agent across the IPs it rotates through.

An AI agent behind a residential-proxy pool changes IP every few requests; its TLS
stack and HTTP client usually do not. So AEGIS keys campaigns and enforcement on the
client fingerprint as well as the IP:

    ja4 / ja3   TLS ClientHello fingerprints, from Cloudflare (``JA4``, ``JA3Hash``),
                AWS WAF (``ja4Fingerprint``, ``ja3Fingerprint``) or any log that carries them.
                ``strength = "tls"`` — enforceable on Cloudflare and AWS WAF.
    headers     hash of the request's header *names in order* + user agent, when the log has
                the header list (AWS WAF does). ``strength = "headers"`` — correlation only,
                never enforced (no WAF matches header order).

Collateral is the risk: a bare JA4 is shared by every user of the same browser build.
So an enforcement *target* is a composite —

    fp:ja4:<value>                      challenge only (browsers pass a managed challenge)
    fp:ja4:<value>;ua:<percent-encoded>  block — same TLS stack *and* the exact user agent

— and ``AEGIS_FP_ALLOW`` lists fingerprints that are never acted on (the bank's own
monitoring, partners' integrations).
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import quote, unquote

FP_PREFIX = "fp:"
_JA4_KEYS = ("ja4", "JA4", "ja4_fingerprint", "ja4Fingerprint", "tls_ja4")
_JA3_KEYS = ("ja3", "JA3Hash", "ja3_hash", "ja3Fingerprint", "ja3_fingerprint", "tls_ja3")
_EMPTY = frozenset({"", "-", "none", "null", "unknown", "0"})


@dataclass(frozen=True)
class Fingerprint:
    kind: str           # "ja4" | "ja3" | "headers"
    value: str
    user_agent: str = ""

    @property
    def strength(self) -> str:
        return "headers" if self.kind == "headers" else "tls"

    @property
    def key(self) -> str:
        """Correlation key (campaign context): TLS / header fingerprint alone."""
        return f"{self.kind}:{self.value}"

    def target(self, *, with_user_agent: bool) -> str:
        """Enforcement target string (see module doc)."""
        t = f"{FP_PREFIX}{self.kind}:{self.value}"
        if with_user_agent and self.user_agent:
            t += f";ua:{quote(self.user_agent, safe='')}"
        return t


def _first(obj: dict, keys: tuple[str, ...]) -> str:
    for k in keys:
        v = obj.get(k)
        if isinstance(v, str) and v.strip().lower() not in _EMPTY:
            return v.strip()
    return ""


def client_fingerprint(alert: dict) -> Optional[Fingerprint]:
    """The strongest fingerprint the alert (or its raw vendor record) carries, or ``None``."""
    if not isinstance(alert, dict):
        return None
    raw = alert.get("raw") if isinstance(alert.get("raw"), dict) else {}
    req = raw.get("httpRequest") if isinstance(raw.get("httpRequest"), dict) else {}
    ua = str(alert.get("user_agent") or "")[:512]
    for kind, keys in (("ja4", _JA4_KEYS), ("ja3", _JA3_KEYS)):
        for src in (alert, raw, req):
            v = _first(src, keys)
            if v:
                return Fingerprint(kind, v[:128], ua)
    names = alert.get("header_order")
    if not names and isinstance(req.get("headers"), list):
        names = [str(h.get("name", "")) for h in req["headers"] if isinstance(h, dict)]
    if isinstance(names, list) and len(names) >= 3:
        basis = ",".join(n.lower() for n in names) + "|" + ua
        return Fingerprint("headers", hashlib.sha256(basis.encode()).hexdigest()[:24], ua)
    return None


def is_fingerprint_target(target: Any) -> bool:
    return isinstance(target, str) and target.startswith(FP_PREFIX)


def parse_target(target: str) -> tuple[str, str, str]:
    """``fp:ja4:<v>[;ua:<enc>]`` → (kind, value, user_agent)."""
    if not is_fingerprint_target(target):
        raise ValueError(f"not a fingerprint target: {target!r}")
    body, _, ua = target[len(FP_PREFIX):].partition(";ua:")
    kind, _, value = body.partition(":")
    if kind not in ("ja4", "ja3", "headers") or not value:
        raise ValueError(f"bad fingerprint target: {target!r}")
    return kind, value, unquote(ua)


def allowed_fingerprints() -> set[str]:
    """``AEGIS_FP_ALLOW`` — comma list of fingerprint values never acted on."""
    return {v.strip() for v in os.environ.get("AEGIS_FP_ALLOW", "").split(",") if v.strip()}


__all__ = ["Fingerprint", "client_fingerprint", "is_fingerprint_target", "parse_target", "allowed_fingerprints", "FP_PREFIX"]
