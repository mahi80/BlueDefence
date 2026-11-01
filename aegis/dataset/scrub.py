"""Pseudonymise identities in alerts and chains before they become training data.

The SOC agent runs inside the bank; the dataset leaves it (a fine-tune job,
a vendor GPU, a shared bucket). The scrubber runs **at capture time on the
agent host** (``capture.py``) and again at export, so no raw identity ever
reaches the dashboard's ``soc_evidence_chains`` rows or a dataset file.

What is replaced
- values under identity keys (``user_id``, ``email``, ``account_number`` …)
  → a keyed pseudonym that is **consistent** for the same value, so
  "same user across three alerts" survives as a signal
- e-mail addresses anywhere in text → local part replaced, **domain kept**
  (a lookalike domain + SPF fail is the phishing signal)
- card numbers (Luhn-valid 13–19 digits), Aadhaar-shaped 12-digit numbers,
  Indian PAN codes, Indian mobile numbers
- literal occurrences of any pseudonymised structured value in free text
  (``"user u_42891 impossible travel"`` → the same pseudonym as the field)
- optionally public IPv4 addresses (``scrub_ips=True``). Off by default:
  IOC matching on known-bad IPs is a detection *feature*, and RFC 1918
  ranges carry the "internal vs. external" signal.

What is kept
- URLs, HTTP payloads, process trees, hostnames, severities, scores — the
  telemetry the model has to learn from. Payload text still passes the
  regexes above.

The pseudonym is ``HMAC-SHA256(salt, kind|value)[:10]``; the salt
(``AEGIS_DATASET_SALT``) is the only way back to an identity and stays in
the bank. With no salt set the map is deterministic (dev / CI) — set one
in production.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
from typing import Any, Iterable

IDENTITY_KEYS: frozenset[str] = frozenset({
    "user_id", "userid", "user", "username", "user_name", "userprincipalname", "upn",
    "employee_id", "employee", "staff_id",
    "customer_id", "customer", "cif", "cif_id",
    "account", "account_id", "account_no", "account_number", "acct", "beneficiary_account",
    "email", "mail", "from_address", "to_address", "reply_to", "sender", "recipient", "recipients",
    "from_display", "display_name", "full_name", "first_name", "last_name", "owner_name",
    "phone", "mobile", "msisdn", "phone_number", "mobile_number",
    "pan", "pan_number", "aadhaar", "aadhaar_number", "card", "card_number", "card_no",
    "principal", "principal_id", "actor", "actor_id", "mailbox", "subject_user", "target_user",
    "target_user_id", "accountid", "caller_id", "device_owner", "owner", "object_owner", "resource_owner",
    "victim", "victim_id", "initiator", "requester", "approver",
    # Windows / Sentinel / Splunk / CrowdStrike identity fields
    "targetusername", "subjectusername", "accountname", "samaccountname", "src_user", "dest_user", "src_user_name",
    "dest_user_name", "user_sid", "targetsid", "subjectusersid", "logonaccount", "userprincipal", "callerid",
    "workstationname", "src_host_name", "logon_user", "initiatedby", "targetresources", "identity", "identityname",
    "mailboxowner", "onbehalfof", "senderfromaddress", "recipientemailaddress", "p1sender", "p2sender",
})

# Alert keys that change on every event and must not take part in a fingerprint.
VOLATILE_KEYS: frozenset[str] = frozenset({
    "id", "alert_id", "event_id", "uuid", "guid", "timestamp", "time", "@timestamp", "event_time",
    "received_at", "observed_at", "ingested_at", "created_at", "detected_at", "_checkpoint",
    "_ingest", "ingest", "ttl", "sequence", "seq",
})

_EMAIL_RX = re.compile(r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]{1,64})@([A-Za-z0-9.-]+\.[A-Za-z]{2,24})\b")
_CARD_RX = re.compile(r"(?<![\w-])(?:\d[ -]?){12,18}\d(?![\w-])")
_AADHAAR_RX = re.compile(r"(?<![\w-])[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?![\w-])")
_PAN_RX = re.compile(r"(?<![A-Za-z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Za-z0-9])")
_IN_MOBILE_RX = re.compile(r"(?<![\w+])(?:\+91[ -]?|0)?[6-9]\d{4}[ -]?\d{5}(?!\w)")
_IPV4_RX = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
# arn:aws:iam::123456789012:user/x — the 12-digit account id names the bank's cloud tenant; tokenised, the rest kept
_ARN_ACCOUNT_RX = re.compile(r"(arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:)(\d{12})(?=:|$)")
# keep a short prefix only when the rest is a number / hex id (u_42891, emp-00123); "rverma_admin" is a handle, tokenised whole
_PREFIXED_ID_RX = re.compile(r"^([A-Za-z]{1,4}[_\-])(\d{2,}|[0-9a-f]{6,})$")

_MIN_LITERAL_LEN = 3


def _luhn_ok(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        d = ord(ch) - 48
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _is_public_ipv4(text: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(text)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
                or ip.is_reserved or ip.is_unspecified)


class Scrubber:
    """Consistent, keyed pseudonymisation of a JSON-like object (dicts / lists / scalars)."""

    def __init__(self, salt: str | None = None, *, scrub_ips: bool = False,
                 identity_keys: Iterable[str] = IDENTITY_KEYS):
        self._salt = (salt if salt is not None else "").encode("utf-8")
        self.scrub_ips = scrub_ips
        self._identity_keys = frozenset(k.lower() for k in identity_keys)
        self._map: dict[tuple[str, str], str] = {}
        self._known: set[str] = set()            # identity values seen so far (any call)
        self._known_sorted: tuple[str, ...] = ()
        self.replacements = 0

    # ----------------------------------------------------------------- api --

    def scrub(self, obj: Any) -> Any:
        """Return a scrubbed deep copy. The input is never mutated.

        Identity values found under identity keys are remembered for the
        lifetime of the scrubber, so a user id first seen in an alert is also
        replaced where a later chain's evidence mentions it under some other key.
        """
        self._remember(self._collect_identity_values(obj))
        return self._walk(obj, self._known_sorted, under_identity_key=False)

    def scrub_text(self, text: str) -> str:
        return self._scrub_string(text, self._known_sorted)

    def _remember(self, values: Iterable[str]) -> None:
        new = set(values) - self._known
        if new:
            self._known |= new
            self._known_sorted = tuple(sorted(self._known, key=len, reverse=True))

    def token(self, kind: str, value: str) -> str:
        key = (kind, value.strip().lower())
        tok = self._map.get(key)
        if tok is None:
            msg = f"{kind}|{key[1]}".encode("utf-8")
            if self._salt:
                tok = hmac.new(self._salt, msg, hashlib.sha256).hexdigest()[:10]
            else:
                tok = hashlib.sha256(b"aegis-dataset|" + msg).hexdigest()[:10]
            self._map[key] = tok
        return tok

    @property
    def distinct_identities(self) -> int:
        return len(self._map)

    @property
    def salted(self) -> bool:
        return bool(self._salt)

    # ------------------------------------------------------------ internals --

    def _collect_identity_values(self, obj: Any) -> tuple[str, ...]:
        found: set[str] = set()

        def walk(o: Any, key: str | None):
            if isinstance(o, dict):
                for k, v in o.items():
                    walk(v, str(k))
            elif isinstance(o, (list, tuple)):
                for v in o:
                    walk(v, key)
            elif isinstance(o, str) and key is not None and key.lower() in self._identity_keys:
                if len(o.strip()) >= _MIN_LITERAL_LEN:
                    found.add(o.strip())
        walk(obj, None)
        return tuple(found)

    def _walk(self, obj: Any, literals: tuple[str, ...], *, under_identity_key: bool) -> Any:
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                ident = str(k).lower() in self._identity_keys
                out[k] = self._walk(v, literals, under_identity_key=ident)
            return out
        if isinstance(obj, list):
            return [self._walk(v, literals, under_identity_key=under_identity_key) for v in obj]
        if isinstance(obj, tuple):
            return tuple(self._walk(v, literals, under_identity_key=under_identity_key) for v in obj)
        if isinstance(obj, str):
            if under_identity_key:
                return self._pseudonym_for_field(obj)
            return self._scrub_string(obj, literals)
        if isinstance(obj, (int, float)) and not isinstance(obj, bool) and under_identity_key:
            # numeric account / customer ids
            self.replacements += 1
            return f"id_{self.token('id', str(obj))}"
        return obj

    def _pseudonym_for_field(self, value: str) -> str:
        """Shape-aware pseudonym: the same value found in free text gets the same token."""
        v = value.strip()
        if not v:
            return value
        self.replacements += 1
        m = _EMAIL_RX.fullmatch(v)
        if m:
            return f"{self.token('email', m.group(1))}@{m.group(2).lower()}"
        if "@" in v:
            local, _, domain = v.partition("@")
            return f"{self.token('email', local)}@{domain.lower()}"
        digits = re.sub(r"[ +-]", "", v)
        if _CARD_RX.fullmatch(v) and 13 <= len(digits) <= 19 and _luhn_ok(digits):
            return f"card_{self.token('card', digits)}"
        if _AADHAAR_RX.fullmatch(v):
            return f"aadhaar_{self.token('aadhaar', digits)}"
        if _PAN_RX.fullmatch(v):
            return f"pan_{self.token('pan', v)}"
        if _IN_MOBILE_RX.fullmatch(v):
            return f"phone_{self.token('phone', digits[-10:])}"
        pm = _PREFIXED_ID_RX.match(v)
        if pm and len(pm.group(2)) >= 2:
            return f"{pm.group(1)}{self.token('id', pm.group(2))}"
        return f"id_{self.token('id', v)}"

    def _scrub_string(self, text: str, literals: tuple[str, ...]) -> str:
        if not text:
            return text
        # shape regexes first (they produce the same tokens the fields got),
        # then literal identity values that have no recognisable shape
        out = _EMAIL_RX.sub(self._sub_email, text)
        out = _CARD_RX.sub(self._sub_card, out)
        out = _AADHAAR_RX.sub(self._sub_aadhaar, out)
        out = _PAN_RX.sub(self._sub_pan, out)
        out = _IN_MOBILE_RX.sub(self._sub_mobile, out)
        out = _ARN_ACCOUNT_RX.sub(self._sub_arn, out)
        if self.scrub_ips:
            out = _IPV4_RX.sub(self._sub_ip, out)
        for lit in literals:
            if lit in out:
                out = out.replace(lit, self._pseudonym_for_literal(lit))
        return out

    def _pseudonym_for_literal(self, lit: str) -> str:
        # same pseudonym the structured field got (replacements counted there)
        saved = self.replacements
        p = self._pseudonym_for_field(lit)
        self.replacements = saved
        return p

    def _sub_arn(self, m: re.Match) -> str:
        self.replacements += 1
        return f"{m.group(1)}acct_{self.token('acct', m.group(2))}"

    def _sub_email(self, m: re.Match) -> str:
        self.replacements += 1
        return f"{self.token('email', m.group(1))}@{m.group(2).lower()}"

    def _sub_card(self, m: re.Match) -> str:
        digits = re.sub(r"[ -]", "", m.group(0))
        if not (13 <= len(digits) <= 19 and _luhn_ok(digits)):
            return m.group(0)
        self.replacements += 1
        return f"card_{self.token('card', digits)}"

    def _sub_aadhaar(self, m: re.Match) -> str:
        digits = re.sub(r"[ -]", "", m.group(0))
        self.replacements += 1
        return f"aadhaar_{self.token('aadhaar', digits)}"

    def _sub_pan(self, m: re.Match) -> str:
        self.replacements += 1
        return f"pan_{self.token('pan', m.group(0))}"

    def _sub_mobile(self, m: re.Match) -> str:
        digits = re.sub(r"[ +-]", "", m.group(0))[-10:]
        self.replacements += 1
        return f"phone_{self.token('phone', digits)}"

    def _sub_ip(self, m: re.Match) -> str:
        ip = m.group(0)
        if not _is_public_ipv4(ip):
            return ip
        self.replacements += 1
        # keep it a syntactically valid *public-looking* address in the
        # benchmarking range (198.18.0.0/15) so parsers downstream still work
        tok = int(self.token("ip", ip), 16)
        return f"198.{18 + (tok >> 16) % 2}.{(tok >> 8) % 256}.{tok % 256}"


def scrubber_from_env(**overrides: Any) -> Scrubber:
    """``AEGIS_DATASET_SALT`` keys the pseudonyms; ``AEGIS_DATASET_SCRUB_IPS=1`` also pseudonymises public IPs."""
    salt = os.environ.get("AEGIS_DATASET_SALT", "")
    scrub_ips = os.environ.get("AEGIS_DATASET_SCRUB_IPS", "0").strip().lower() in {"1", "true", "yes", "on"}
    kw: dict[str, Any] = {"salt": salt, "scrub_ips": scrub_ips}
    kw.update(overrides)
    return Scrubber(**kw)
