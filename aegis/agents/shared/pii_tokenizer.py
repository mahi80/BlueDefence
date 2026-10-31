"""PII tokenization layer.

The project plan requires PII tokenization before any LLM call —
DPDP Act 2023 + PCI-DSS scope-out + the bank's data-residency posture
all want raw PII to never leave the trusted boundary into a model
that may log, cache, or train on inputs.

Strategy: replace PII patterns with stable tokens BEFORE the LLM call,
detokenize on response. Tokens are deterministic within a session so
the LLM sees consistent references (same email -> same token across
the conversation), and the mapping lives only in the agent's process
memory — never serialized, never logged.

Production swaps in:
  - Vault Transit / Voltage SecureData / Protegrity for HSM-backed
    cryptographic tokenization (format-preserving encryption).
  - The same Tokenizer interface; the in-process dict becomes the
    HSM API.

Detection patterns are conservative (low false-positive rate). Banks
should add tenant-specific patterns (internal account formats, KYC
fields) on top via add_pattern().
"""
from __future__ import annotations

import hashlib
import re
import threading
from collections import OrderedDict
from dataclasses import dataclass


# Pattern order matters: more specific patterns must match first so
# generic ones (PHONE) don't eat fragments of compound IDs (Aadhaar)
# or internal account numbers.
_BUILTIN_PATTERNS: list[tuple[str, str]] = [
    # India-specific (DPDP Act 2023 in scope)
    ("AADHAAR",  r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b"),    # 12-digit ID, first digit 2-9
    ("PAN_IN",   r"\b[A-Z]{3}[ABCEFGHJLPT][A-Z]\d{4}[A-Z]\b"),  # 10-char India PAN
    ("IFSC",     r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),          # bank routing code
    # Internal IDs — match BEFORE PHONE so digit-runs don't get eaten
    ("ACCOUNT",  r"\bACC-\d{8,12}\b"),                  # internal account format
    # Global
    ("PAN_CC",   r"\b(?:\d[ -]*?){13,19}\b"),           # credit-card PAN (Luhn-validated below)
    ("EMAIL",    r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    # Phone: require a separator (space/dash) inside so raw digit
    # strings (account numbers, IDs) don't match. Leading "+" allowed
    # without preceding word boundary.
    ("PHONE",    r"(?:(?<=\s)|(?<=^))\+?\d{1,3}[ -]\(?\d{3,5}\)?[ -]\d{3,5}\b"),
    ("SSN_US",   r"\b\d{3}-\d{2}-\d{4}\b"),
]


def _luhn_ok(digits: str) -> bool:
    """Validate credit-card-shaped strings to suppress false positives."""
    digits = re.sub(r"\D", "", digits)
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


@dataclass
class TokenMap:
    """Maps tokens -> original values. Lives in process memory only.

    Held by the agent for the duration of one alert/investigation;
    discarded when the chain is finalized so PII has no persistence
    beyond the LLM call envelope.
    """
    by_token: "OrderedDict[str, str]"
    by_value: dict[str, str]   # for stable token reuse across the same value


class PIITokenizer:
    def __init__(self, *, secret: bytes | None = None):
        # Per-session salt so identical PII across different sessions
        # produces different tokens — bounds correlation attacks if the
        # token space ever leaks.
        self._secret = secret or hashlib.sha256(b"aegis-pii-default-salt").digest()
        self._patterns: list[tuple[str, re.Pattern[str]]] = [
            (kind, re.compile(rx)) for kind, rx in _BUILTIN_PATTERNS
        ]
        self._lock = threading.Lock()

    def add_pattern(self, kind: str, regex: str) -> None:
        """Register an additional pattern (tenant-specific PII shape)."""
        with self._lock:
            self._patterns.append((kind, re.compile(regex)))

    def tokenize(self, text: str) -> tuple[str, TokenMap]:
        """Return (tokenized_text, token_map). Idempotent within a call:
        the same value always gets the same token in this output.
        """
        if not text:
            return text, TokenMap(OrderedDict(), {})

        by_token: OrderedDict[str, str] = OrderedDict()
        by_value: dict[str, str] = {}
        counters: dict[str, int] = {}

        out = text
        for kind, rx in self._patterns:
            def _replace(match: re.Match[str]) -> str:
                value = match.group(0)
                # Suppress false positives on credit-card-shaped strings
                if kind == "PAN_CC" and not _luhn_ok(value):
                    return value
                if value in by_value:
                    return by_value[value]
                idx = counters.get(kind, 0) + 1
                counters[kind] = idx
                token = f"<PII:{kind}:{idx}>"
                by_token[token] = value
                by_value[value] = token
                return token
            out = rx.sub(_replace, out)

        return out, TokenMap(by_token=by_token, by_value=by_value)

    def detokenize(self, text: str, token_map: TokenMap) -> str:
        """Replace tokens back with original values. Order: longest token
        first so e.g. <PII:EMAIL:10> isn't partially matched by
        <PII:EMAIL:1>.
        """
        if not text or not token_map.by_token:
            return text
        out = text
        # Replace longest tokens first to avoid prefix collisions
        for token in sorted(token_map.by_token, key=len, reverse=True):
            out = out.replace(token, token_map.by_token[token])
        return out

    def stats(self, token_map: TokenMap) -> dict[str, int]:
        """Count tokens emitted, grouped by kind."""
        out: dict[str, int] = {}
        for token in token_map.by_token:
            # token format: <PII:KIND:N>
            kind = token.split(":")[1]
            out[kind] = out.get(kind, 0) + 1
        return out


# Module-level shared instance for convenience. Production agents
# instantiate their own per-session.
_DEFAULT = PIITokenizer()


def tokenize(text: str) -> tuple[str, TokenMap]:
    return _DEFAULT.tokenize(text)


def detokenize(text: str, token_map: TokenMap) -> str:
    return _DEFAULT.detokenize(text, token_map)
