"""The last check before a dataset bundle leaves a bank — and the first check when it arrives.

Stdlib only, on purpose: this same file is copied into the licence service (``license-server/``),
so the sender and the receiver refuse exactly the same things. The ``Scrubber`` has already
pseudonymised identities; this gate looks for what must never appear in derived telemetry at all,
whatever the scrubber did: raw public IPs, e-mail addresses, Indian PAN / Aadhaar shapes, payment
card numbers (Luhn), IBAN-like strings, phone numbers, bearer/API-key shapes. Anything found is a
reason the bundle is NOT sent, with the field path reported so the operator can fix the capture.
"""

from __future__ import annotations

import re
from typing import Any, Iterator

_RX = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "pan": re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"),
    "aadhaar": re.compile(r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b"),
    "card": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    "iban": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
    "phone_in": re.compile(r"(?<!\d)(?:\+91[ -]?)?[6-9]\d{9}(?!\d)"),
    "secret": re.compile(r"\b(?:AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"),
}
# keys whose values are expected to look like identifiers the scrubber already tokenised (bd-… / usr-… / host-…)
_TOKEN_RX = re.compile(r"^(?:[a-z]{2,6}-)?[0-9a-f]{8,}$")
# a chain's own hash fields are hex and never PII
_SKIP_KEYS = {"integrity_hash", "prev_hash", "fingerprint", "record_id", "token_sha256", "digest", "sha256", "id"}


def _private_ip(ip: str) -> bool:
    a, b, *_ = (int(x) for x in ip.split("."))
    return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or a == 127 or (a == 169 and b == 254) or a == 0


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


def _walk(obj: Any, path: str) -> Iterator[tuple[str, str]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k) in _SKIP_KEYS:
                continue
            yield from _walk(v, f"{path}.{k}" if path else str(k))
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{path}[{i}]")
    elif isinstance(obj, str):
        yield path, obj


def findings(obj: Any, *, allow_private_ips: bool = True) -> list[dict]:
    """Every PII-shaped value in ``obj``: ``[{"kind", "path", "sample"}]`` (sample is masked)."""
    out: list[dict] = []
    for path, s in _walk(obj, ""):
        if len(s) > 20000:
            s = s[:20000]
        if _TOKEN_RX.match(s):
            continue
        for kind, rx in _RX.items():
            for m in rx.finditer(s):
                v = m.group(0)
                if kind == "ipv4" and allow_private_ips and _private_ip(v):
                    continue
                if kind == "card":
                    digits = re.sub(r"\D", "", v)
                    if not (13 <= len(digits) <= 19 and _luhn(digits)):
                        continue
                if kind == "aadhaar" and not _luhn_aadhaar_plausible(v):
                    continue
                out.append({"kind": kind, "path": path, "sample": v[:3] + "…" + v[-2:]})
                break               # one finding per value is enough to refuse it
    return out


def _luhn_aadhaar_plausible(v: str) -> bool:
    # Aadhaar uses the Verhoeff checksum; a cheap plausibility filter keeps timestamps/counters out
    digits = re.sub(r"\D", "", v)
    return len(digits) == 12 and not digits.startswith(("17", "18", "19", "20"))   # epoch-second/ms shapes


def gate(obj: Any, *, allow_private_ips: bool = True) -> tuple[bool, list[dict]]:
    """``(ok, findings)``. ``ok`` is False if anything PII-shaped is present."""
    f = findings(obj, allow_private_ips=allow_private_ips)
    return (not f), f


__all__ = ["findings", "gate"]
