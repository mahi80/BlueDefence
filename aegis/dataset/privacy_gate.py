"""The last check before a dataset bundle leaves a bank — and the first check when it arrives.

Stdlib only, on purpose: this same file is vendored into the licence service (private repo ``mahi80/Blueteamlicence``),
so the sender and the receiver refuse exactly the same things. The ``Scrubber`` has already
pseudonymised identities; this gate looks for what must never appear in derived telemetry at all,
whatever the scrubber did: raw public IPs (v4 and v6), MAC addresses, e-mail addresses, credentials
in URLs, Indian PAN / Aadhaar shapes, payment card numbers (Luhn), IBAN-like strings, phone numbers,
long bare account-number-like digit runs, bearer/API-key shapes and private-key blocks. Anything
found is a reason the record is NOT sent, with the field path reported so the operator can fix the
capture.

Numbers are checked too (``{"to_acct": 50100234567890}`` is as much a leak as the string), and so
are dict keys (``{"rajesh.verma@bank.in": …}``). Only values that are unmistakably scrubber output
(``email-3f9a…``, ``ip-…``, ``host-…``, ``id_…``) or chain hashes are exempt.
"""

from __future__ import annotations

import re
from typing import Any, Iterator

_RX = {
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "secret": re.compile(r"(?:\bAKIA[0-9A-Z]{16}\b|\bsk-[A-Za-z0-9_-]{20,}|\bghp_[A-Za-z0-9]{30,}|\bxox[baprs]-[A-Za-z0-9-]{10,}"
                         r"|\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
                         r"|(?i:(?:aws_secret_access_key|client_secret|api[_-]?key|password|passwd|secret_key)\s*[=:]\s*[\"']?[A-Za-z0-9+/=_\-]{12,}))"),
    "url_userinfo": re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/@:]+(?::[^\s/@]*)?@[^\s/]+"),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "mac": re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
    "ipv6": re.compile(r"(?<![:\w.])[0-9A-Fa-f:]{7,39}(?![:\w])"),          # candidates; validated with ipaddress below
    "pan": re.compile(r"\b(?:[A-Z]{5}\d{4}[A-Z]|[a-z]{5}\d{4}[a-z])\b"),
    "aadhaar": re.compile(r"(?<![-\w.])[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?![-\w.])"),
    "card": re.compile(r"(?<![-\w.])(?:\d[ -]?){13,19}(?![-\w.])"),
    "iban": re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}[ ]?[A-Z0-9]{1,4}\b"),
    "phone_in": re.compile(r"(?<![\w.-])(?:\+91[ -]?|0)?[6-9]\d{9}(?![\w.-])"),
    "account_number": re.compile(r"(?<![\w.-])\d{11,16}(?![\w.-])"),
}
# values that are unmistakably scrubber output or chain hashes: a known prefix + hex, or long hex with a letter in it
_TOKEN_RX = re.compile(r"^(?:(?:bd|email|ip|host|usr|user|id|card|pan|aadhaar|phone|acct|dev|iface|url|path|name)[-_])(?=[0-9a-f]*[a-f])[0-9a-f]{6,}$|^(?=[0-9a-f]*[a-f])[0-9a-f]{16,}$")
# a chain's own hash fields are hex and never PII ("id" is NOT here: alert ids are often account numbers)
_SKIP_KEYS = {"integrity_hash", "prev_hash", "fingerprint", "record_id", "token_sha256", "digest", "sha256", "manifest_token"}
# shapes that look like Aadhaar / card / account digits but are telemetry identifiers
_SID_RX = re.compile(r"\bS-1-5-\d+(?:-\d+)+\b")
_UUID_RX = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_EPOCH_PREFIXES = ("16", "17", "18", "19", "20")


def _private_ip(ip: str) -> bool:
    a, b, *_ = (int(x) for x in ip.split("."))
    return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or a == 127 or (a == 169 and b == 254) or a == 0


def _is_ip6(v: str) -> bool:
    import ipaddress
    try:
        return isinstance(ipaddress.ip_address(v), ipaddress.IPv6Address)
    except ValueError:
        return False


def _private_ip6(ip: str) -> bool:
    low = ip.lower()
    return low in ("::1", "::") or low.startswith(("fe80:", "fc", "fd", "::ffff:"))


def _luhn(digits: str) -> bool:
    total, alt = 0, False
    for d in reversed(digits):
        n = int(d)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


def _mask(s: str, spans: list[tuple[int, int]]) -> str:
    """Blank out spans (SIDs, UUIDs) so the digit-run rules do not see them."""
    if not spans:
        return s
    out = list(s)
    for a, b in spans:
        for i in range(a, b):
            out[i] = "x"
    return "".join(out)


def _walk(obj: Any, path: str) -> Iterator[tuple[str, str]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            ks = str(k)
            if ks in _SKIP_KEYS:
                continue
            if len(ks) >= 6:
                yield f"{path}.<key>" if path else "<key>", ks
            yield from _walk(v, f"{path}.{ks}" if path else ks)
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{path}[{i}]")
    elif isinstance(obj, bool):
        return
    elif isinstance(obj, (int, float)):
        if isinstance(obj, float) and (obj != obj or obj in (float("inf"), float("-inf"))):
            return
        yield path, str(int(obj)) if float(obj).is_integer() else repr(obj)
    elif isinstance(obj, str):
        yield path, obj


def _check(s: str, *, allow_private_ips: bool) -> dict | None:
    if _TOKEN_RX.match(s):
        return None
    spans = [m.span() for m in _SID_RX.finditer(s)] + [m.span() for m in _UUID_RX.finditer(s)]
    masked = _mask(s, spans)
    for kind, rx in _RX.items():
        hay = masked if kind in ("aadhaar", "card", "account_number", "phone_in", "ipv6", "mac") else s
        for m in rx.finditer(hay):
            v = m.group(0)
            if kind == "ipv4" and allow_private_ips and _private_ip(v):
                continue
            if kind == "ipv6":
                if v.count(":") < 2 or not _is_ip6(v) or (allow_private_ips and _private_ip6(v)):
                    continue           # 12:30:45-style times, port lists and MACs are not addresses
            if kind == "card":
                digits = re.sub(r"\D", "", v)
                sep = len(digits) != len(v)
                if not (13 <= len(digits) <= 19 and _luhn(digits) and (sep or len(digits) >= 16)):
                    continue
            if kind == "aadhaar":
                digits = re.sub(r"\D", "", v)
                if len(digits) != 12 or digits.startswith(_EPOCH_PREFIXES):
                    continue
            if kind == "account_number" and v.startswith(_EPOCH_PREFIXES) and len(v) in (13, 16, 19):
                continue           # epoch ms / µs / ns
            return {"kind": kind, "sample": v[:3] + "…" + v[-2:]}
    return None


def findings(obj: Any, *, allow_private_ips: bool = True) -> list[dict]:
    """Every PII-shaped value in ``obj``: ``[{"kind", "path", "sample"}]`` (sample is masked)."""
    out: list[dict] = []
    for path, s in _walk(obj, ""):
        if len(s) > 20000:
            s = s[:20000]
        f = _check(s, allow_private_ips=allow_private_ips)
        if f:
            out.append({"kind": f["kind"], "path": path, "sample": f["sample"]})
    return out


def gate(obj: Any, *, allow_private_ips: bool = True) -> tuple[bool, list[dict]]:
    """``(ok, findings)``. ``ok`` is False if anything PII-shaped is present."""
    f = findings(obj, allow_private_ips=allow_private_ips)
    return (not f), f


def gate_records(records: list[Any], *, allow_private_ips: bool = True) -> tuple[list[int], dict[int, list[dict]]]:
    """Per-record gating: ``(clean_indexes, {bad_index: findings})`` — one leaky record does not block the rest."""
    clean: list[int] = []
    bad: dict[int, list[dict]] = {}
    for i, r in enumerate(records):
        f = findings(r, allow_private_ips=allow_private_ips)
        if f:
            bad[i] = f
        else:
            clean.append(i)
    return clean, bad


__all__ = ["findings", "gate", "gate_records"]
