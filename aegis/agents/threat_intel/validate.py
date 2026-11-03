"""Gate for every indicator entering the IOC store: feeds, peer sync and LLM-extracted advisory indicators.

An IOC store feeds blocklists and "known bad" matchers, so a poisoned entry turns detection against the bank
itself. Rejected: unknown kinds, malformed values, non-finite or out-of-range confidence, and any IP / domain
that is the bank's own (private and carrier-grade NAT ranges, loopback / reserved space, the operator's
``AEGIS_INTERNAL_NETS`` / ``AEGIS_NEVER_BLOCK`` / ``AEGIS_NEVER_BLOCK_HOSTS`` and ``AEGIS_INTERNAL_DOMAINS``).
Accepted values are normalised (lower-case domains and hashes, canonical IPs) so the matchers compare like
with like.
"""

from __future__ import annotations

import ipaddress
import math
import os
import re

from ..shared.netguard import never_block_target

KINDS = frozenset({"ip", "domain", "url", "hash_md5", "hash_sha256", "email", "asn", "cve", "config"})

_OWN_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8",
    "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4", "fc00::/7", "fe80::/10", "::1/128", "::/128", "ff00::/8")]
_HEX = {"hash_md5": 32, "hash_sha256": 64}
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_EMAIL = re.compile(r"^[^@\s]{1,64}@([^@\s]{1,253})$")


def _env_list(name: str) -> list[str]:
    return [t.strip().lower() for t in os.environ.get(name, "").replace(";", ",").split(",") if t.strip()]


def _internal_nets() -> list:
    out = []
    for tok in _env_list("AEGIS_INTERNAL_NETS"):
        try:
            out.append(ipaddress.ip_network(tok, strict=False))
        except ValueError:
            continue
    return out


def _own_domain(d: str) -> bool:
    return any(d == o or d.endswith("." + o) for o in _env_list("AEGIS_INTERNAL_DOMAINS") + _env_list("AEGIS_NEVER_BLOCK_HOSTS"))


def _ip(value: str) -> tuple[str | None, str]:
    try:
        ip = ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return None, "not an IP address"
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    for n in _OWN_NETS + _internal_nets():
        if ip.version == n.version and ip in n:
            return None, f"{ip} is private / reserved / internal space"
    refuse, why = never_block_target(str(ip))
    if refuse:
        return None, why
    return str(ip), ""


def _domain(value: str) -> tuple[str | None, str]:
    d = value.strip().lower().rstrip(".")
    d = d.removeprefix("*.")
    if not _DOMAIN.match(d):
        return None, "not a domain name"
    if _own_domain(d):
        return None, f"{d} is the bank's own domain"
    return d, ""


def normalise(kind: str, value: str) -> tuple[str | None, str]:
    """``(normalised value, "")`` or ``(None, reason)``."""
    v = str(value or "").strip()
    if kind not in KINDS:
        return None, f"unknown kind {kind!r}"
    if not v or len(v) > 2048:
        return None, "empty or oversized value"
    if kind == "ip":
        return _ip(v)
    if kind == "domain":
        return _domain(v)
    if kind in _HEX:
        h = v.lower()
        if len(h) != _HEX[kind] or any(c not in "0123456789abcdef" for c in h):
            return None, f"not a {kind}"
        return h, ""
    if kind == "cve":
        c = v.upper()
        return (c, "") if _CVE.match(c) else (None, "not a CVE id")
    if kind == "email":
        m = _EMAIL.match(v.lower())
        if not m:
            return None, "not an email address"
        dom, why = _domain(m.group(1))
        return (v.lower(), "") if dom else (None, why)
    if kind == "url":
        from urllib.parse import urlsplit
        try:
            host = (urlsplit(v if "://" in v else "http://" + v).hostname or "").lower()
        except ValueError:
            return None, "not a URL"
        if not host:
            return None, "URL has no host"
        try:
            ipaddress.ip_address(host)
            ok, why = _ip(host)
        except ValueError:
            ok, why = _domain(host)
        return (v, "") if ok else (None, why)
    return v, ""


def clamp_confidence(c) -> float | None:
    try:
        f = float(c)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(f):
        return None
    return min(1.0, max(0.0, f))


__all__ = ["KINDS", "clamp_confidence", "normalise"]
