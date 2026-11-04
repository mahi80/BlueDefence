"""Credential redaction for anything that is stored or shipped: alert snapshots, audit rows, the dashboard,
training exports and the edge shim's telemetry.

The SOC has to see attack strings, so it cannot simply drop request bodies. It must never keep a
customer's password, session cookie, bearer token or cloud key. Two rules, applied everywhere:

1. **Credential-bearing fields** — keys such as ``password``, ``authorization``, ``cookie``,
   ``api_key``, ``aws_secret_access_key`` — have their value replaced with ``[REDACTED:<kind>]``.
2. **Credentials inside free text** — ``password=…`` / ``"token": "…"`` pairs in query strings,
   form bodies and JSON text, ``Bearer``/``Basic`` credentials, JWTs, AWS access-key ids, PEM private
   keys and ``Cookie:`` header lines — are replaced the same way.

**Exception: attack-shaped values are kept.** ``password=' OR 1=1--`` is the SQL injection the
perimeter specialist and the training set need, not a credential worth protecting. A value is kept
only when it matches a strong attack pattern (SQL keywords with a quote or comment, ``<script``,
``${jndi:``, path traversal, shell chaining); ordinary passwords — even with a quote or a semicolon in
them — are redacted. The redaction marker carries the value's length so "a 12-character password was
submitted" survives as a signal.
"""

from __future__ import annotations

import re
from typing import Any

#: field names whose whole value is a credential (compared lower-case, ``-`` and ``_`` equivalent)
SECRET_KEYS: frozenset[str] = frozenset({
    "password", "passwd", "pwd", "pass", "passcode", "passphrase", "new_password", "old_password",
    "current_password", "confirm_password", "user_password", "login_password",
    "secret", "client_secret", "app_secret", "shared_secret", "secret_key", "private_key",
    "api_key", "apikey", "x_api_key", "api_token", "access_token", "refresh_token", "id_token",
    "auth_token", "bearer_token", "token", "session_token", "csrf_token", "xsrf_token",
    "authorization", "proxy_authorization", "cookie", "set_cookie", "x_auth_token", "x_amz_security_token",
    "aws_secret_access_key", "aws_session_token", "secretaccesskey", "sessiontoken",
    "otp", "mpin", "pin", "cvv", "cvv2", "cvc", "tpin", "upi_pin",
    "connection_string", "connectionstring", "sas_token", "sig",
})

# A credential-field value is kept only when it is an injection that needs to break out of its field: a quote
# or comment before SQL, a script/handler, JNDI, traversal or shell chaining. A bare "select … from" or a
# back-ticked word is a plausible passphrase, so it no longer counts (it kept such passwords in clear).
_ATTACK_RX = re.compile(
    r"(?:'|\"|%27|%22|\)|--|#|/\*)\s*(?:or|and|union|select|insert|update|delete|drop|sleep|benchmark|waitfor)\b"
    r"|\bunion\b[\s/*]+(?:all\s+)?select\b|;\s*(?:drop|shutdown|exec)\b"
    r"|<\s*script|<\s*img[^>]*\bon\w+\s*=|javascript:|\bon(?:error|load|focus|mouseover)\s*="
    r"|\$\{\s*jndi:|\$\{[^}]*\$\{|(?:\.\./|\.\.\\|%2e%2e%2f){2,}|/etc/passwd|\bwin\.ini\b"
    r"|(?:;|\|\||&&|\|)\s*(?:cat|curl|wget|bash|sh|nc|id|whoami|powershell|cmd)\b|\$\([^)]+\)",
    re.IGNORECASE)

#: any key ending in one of these is a credential too (db_password, githubToken, stripeSecretKey, …)
SECRET_SUFFIXES: tuple[str, ...] = ("password", "passwd", "passphrase", "secret", "secret_key", "token",
                                    "api_key", "apikey", "private_key", "access_key", "pwd", "_pin", "mpin", "tpin",
                                    "_otp")
_PAIR_KEYS = "|".join(sorted((re.escape(k).replace("_", "[_-]?") for k in SECRET_KEYS), key=len, reverse=True))
_PAIR_KEYS = rf"(?:[A-Za-z0-9]*[_-]?)?(?:password|passwd|passphrase|secret(?:[_-]?key)?|token|api[_-]?key|access[_-]?key|private[_-]?key|pwd|[Pp]wd|mpin|MPin|[mt][Pp]in)|{_PAIR_KEYS}"
# key=value in query strings / form bodies / log lines. The value runs to the next "&" or end of line: a
# password may contain spaces, quotes or ";" — over-redacting the rest of a log line is the safe direction,
# and an attack-shaped value (the whole of it) is kept by redact_value.
# The value stops at the next " key=" on the same log line, so one credential followed by an attack string
# (kept whole) is not stored in clear with it.
# The terminator is bounded ([ \t]{1,64}, key ≤ 64 chars): an unbounded \s+ re-scanned the whole whitespace run at
# every position of the lazy value — 40 KB of spaces after "password=" took 15 s per call (review round 7 O-1).
_KV_RX = re.compile(rf"(?i)(?<![A-Za-z0-9_-])((?:{_PAIR_KEYS})[ \t]{{0,64}}=[ \t]{{0,64}})([^&\r\n]+?)"
                    rf"(?=[ \t]{{1,64}}[A-Za-z_][\w.-]{{0,64}}=|&|\r|\n|$)")
# "key": "value" inside JSON text, and 'key': 'value' in a Python repr of a dict
_JSON_RX = re.compile(rf"(?i)(([\"'])(?:{_PAIR_KEYS})\2\s*:\s*([\"']))((?:(?!\3)[^\\]|\\.)*)(\3)")
# header lines: "X-Api-Key: …", "Authorization: ApiKey …", "X-Auth-Token: …"
_HEADER_RX = re.compile(rf"(?im)^((?:proxy-)?authorization|x[-_]api[-_]key|api[-_]key|x[-_]auth[-_]token|(?:{_PAIR_KEYS}))(\s*:\s*)(.+)$")
_BEARER_RX = re.compile(r"(?i)\b(bearer|basic|digest|negotiate|token)\s+([A-Za-z0-9._~+/=-]{8,})")
_JWT_RX = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{0,}")
_AWS_KEY_RX = re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b")
_PEM_RX = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.DOTALL)
_COOKIE_LINE_RX = re.compile(r"(?im)^((?:set-)?cookie\s*:\s*)(.+)$")


def _norm(key: Any) -> str:
    k = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(key).strip())      # userPassword -> user_Password
    return k.lower().replace("-", "_").replace(" ", "_")


def is_secret_key(key: Any) -> bool:
    k = _norm(key)
    return k in SECRET_KEYS or k.endswith(SECRET_SUFFIXES)


def looks_like_attack(value: str) -> bool:
    return bool(_ATTACK_RX.search(value or ""))


def _mark(kind: str, value: str) -> str:
    return f"[REDACTED:{kind} len={len(value)}]"


def redact_value(key: Any, value: str) -> str:
    """The stored form of ``value`` under credential field ``key``: kept only when attack-shaped."""
    if not value or looks_like_attack(value):
        return value
    k = _norm(key)
    if k in ("authorization", "proxy_authorization"):
        scheme, _, rest = value.partition(" ")
        return f"{scheme} {_mark('credential', rest)}" if rest else _mark("credential", value)
    if k in ("cookie", "set_cookie"):
        # keep cookie NAMES (a missing session cookie is a signal), drop every value
        names = [c.split("=", 1)[0].strip() for c in value.split(";") if "=" in c]
        return "; ".join(f"{n}=[REDACTED]" for n in names) if names else _mark("cookie", value)
    return _mark(k, value)


_JSON_MAX = 4 * 1024 * 1024


def _as_json(text: str) -> Any:
    """The parsed value when ``text`` is a JSON object / array, else ``None``."""
    t = text.strip()
    if len(t) < 2 or len(t) > _JSON_MAX or t[0] not in "{[" or t[-1] not in "}]":
        return None
    try:
        import json
        v = json.loads(t)
    except ValueError:
        return None
    return v if isinstance(v, (dict, list)) else None


def redact_text(text: str, _depth: int = 0) -> str:
    """Credentials inside free text (query strings, form bodies, JSON text, header dumps, logs).

    JSON text is redacted field by field: run over ``json.dumps(alert)`` as one string, a ``token=`` value ran
    to the end of the whole alert and blanked every later field (the model saw no source IP, no URI), while a
    password inside a JSON-escaped nested body or a ``\\r\\n``-escaped header dump was not matched at all
    (review round 4 O4-3 / O4-5)."""
    if not text or not isinstance(text, str):
        return text
    if _depth < 4:
        parsed = _as_json(text)
        if parsed is not None:
            import json
            return json.dumps(_redact(parsed, _depth + 1))
    out = _PEM_RX.sub("[REDACTED:private_key]", text)
    out = _COOKIE_LINE_RX.sub(lambda m: m.group(1) + redact_value("cookie", m.group(2)), out)
    out = _JSON_RX.sub(lambda m: m.group(1) + redact_value(m.group(1).strip("\"' :"), m.group(4)) + m.group(5), out)
    out = _HEADER_RX.sub(lambda m: m.group(1) + m.group(2) + redact_value(m.group(1), m.group(3)), out)
    out = _KV_RX.sub(lambda m: m.group(1) + redact_value(m.group(1).split("=")[0], m.group(2)), out)
    out = _BEARER_RX.sub(lambda m: m.group(0) if looks_like_attack(m.group(2)) else f"{m.group(1)} {_mark('credential', m.group(2))}", out)
    out = _JWT_RX.sub(lambda m: _mark("jwt", m.group(0)), out)
    return _AWS_KEY_RX.sub(lambda m: _mark("aws_access_key_id", m.group(0)), out)


def redact(obj: Any) -> Any:
    """Deep copy of a JSON-like object with every credential redacted (input never mutated)."""
    return _redact(obj, 0)


def _redact(obj: Any, depth: int) -> Any:
    def redact(v: Any) -> Any:                 # recursion at the same JSON-string depth
        return _redact(v, depth)

    if isinstance(obj, dict):
        out: dict = {}
        for k, v in obj.items():
            if is_secret_key(k) and isinstance(v, str):
                out[k] = redact_value(k, v)
            elif is_secret_key(k) and isinstance(v, (int, float)) and not isinstance(v, bool):
                out[k] = _mark(_norm(k), str(v))            # a numeric PIN / OTP is still a credential
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(redact(v) for v in obj)
    if isinstance(obj, str):
        return redact_text(obj, depth)        # a JSON body kept as a string is redacted field by field too
    return obj


def redact_chain(chain: Any) -> int:
    """Redact credentials in an EvidenceChain **in place**, before it is hashed and written. Returns the
    number of fields changed. Evidence signals and raw data, reasoning text, action reasoning and
    metadata are covered; action *targets* are not touched (a ``rotate_credential`` on an access-key id
    must still name the key)."""
    changed = 0

    def swap(obj: Any, attr: str, fn) -> None:
        nonlocal changed
        old = getattr(obj, attr, None)
        if old is None:
            return
        new = fn(old)
        if new != old:
            setattr(obj, attr, new)
            changed += 1

    for ev in getattr(chain, "evidence", None) or []:
        swap(ev, "signal", redact_text)
        swap(ev, "raw_data", redact)
    for st in getattr(chain, "reasoning", None) or []:
        swap(st, "observation", redact_text)
        swap(st, "conclusion", redact_text)
    for a in getattr(chain, "recommended_actions", None) or []:
        swap(a, "reasoning", redact_text)
    md = getattr(chain, "metadata", None)
    if isinstance(md, dict):
        new_md = redact(md)
        if new_md != md:
            md.clear()
            md.update(new_md)
            changed += 1
    return changed


__all__ = ["SECRET_KEYS", "is_secret_key", "looks_like_attack", "redact", "redact_chain", "redact_text", "redact_value"]
