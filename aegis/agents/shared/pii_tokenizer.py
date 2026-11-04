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
import secrets
import threading
import unicodedata
from collections import OrderedDict
from dataclasses import dataclass


# Pattern order matters: more specific patterns must match first so
# generic ones (PHONE) don't eat fragments of compound IDs (Aadhaar)
# or internal account numbers.
#
# Card PANs and Aadhaar numbers are not regexes any more: they are found by `_scan_digit_ids` (run first), which
# reads every run of digits once and picks Luhn-valid card windows and Aadhaar windows on group boundaries
# (review round 8 O8-3 / O8-4 / O8-5). Every regex below is linear on adversarial input: each quantifier that can
# meet a long run of the same character is bounded or possessive (review round 8 O8-1 / O8-3).
_BUILTIN_PATTERNS: list[tuple[str, str]] = [
    # India-specific (DPDP Act 2023 in scope)
    # 10-char India PAN, any case; upper-case also when glued to a word ("PANABCPE1234F")
    ("PAN_IN",   r"(?i)\b[A-Z]{3}[ABCEFGHJLPT][A-Z]\d{4}[A-Z]\b"),
    ("PAN_IN",   r"(?<![A-Z0-9])(?:[A-Z]{0,8}?)(?P<v>[A-Z]{3}[ABCEFGHJLPT][A-Z]\d{4}[A-Z])(?![A-Za-z0-9])"),
    ("IFSC",     r"(?i)\b[A-Z]{4}0[A-Z0-9]{6}\b"),      # bank routing code, any case
    # Internal IDs — match BEFORE PHONE so digit-runs don't get eaten
    ("ACCOUNT",  r"\bACC-\d{8,12}\b"),                  # internal account format
    # Bank account numbers carry no shape of their own; take a 9–18 digit run only where a field or label
    # names it an account (review round 3 G2-4). Only the `v` group is replaced. Every gap is bounded: the old
    # `\s*[:=#]?\s*` re-scanned a whitespace run from every split point — "acct" + 20 KB of spaces took 110 s
    # (review round 8 O8-1). Labels: account / acct / acc / accNo / ac_no / A/c No. / bene / beneficiary.
    ("ACCOUNT",  (r"(?i)(?-i:(?<![a-z]))(?:acc(?:oun)?t?|a/c|ac(?=[_ .-]?no\b)|bene(?:ficiary)?)"
                 r"[A-Za-z_ ./-]{0,24}+[\"']?+[ \t]{0,8}+[:=#]?+[ \t]{0,8}+[\"']?+(?<!\d)(?P<v>\d{9,18})(?!\d)")),
    # a JSON / form field that only names the direction of a transfer ("to": "50100012345678")
    ("ACCOUNT",  r"(?i)(?<![\w-])[\"']?(?:to|from|payee|payer|creditor|debtor|sender|remitter|receiver)[\"']?[ \t]{0,4}[:=][ \t]{0,4}[\"']?(?P<v>\d{9,18})(?![\w.-])"),
    # Global
    # bounded parts: an unbounded `[\w.+-]+` re-scanned "a.a.a.…" (no "@") from every position (O8-3)
    ("EMAIL",    r"\b[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,8}\b"),
    # UPI VPA (name@okhdfcbank, 98xxxxxx@ybl): an e-mail-like handle with no dot in the provider; a full stop
    # after it ends a sentence, it is not a domain
    ("UPI_VPA",  r"\b[\w.-]{2,64}@[A-Za-z][A-Za-z0-9]{1,31}\b(?![@\w-]|\.[\w-])"),
    # Indian mobile: 10 digits starting 6–9, optional +91 / 0091 / 91 / 0 prefix, separators space / dash / dot;
    # glued to a word too ("mob9876543210", "user_9876543210") — never the middle of a longer digit run
    ("PHONE_IN", r"(?<![\d+.])(?:(?:\+|00)?91[ .-]?|0)?[6-9]\d{4}[ .-]?\d{5}(?!\d)"),
    # Phone: require a separator (space/dash) inside so raw digit
    # strings (account numbers, IDs) don't match. Leading "+" allowed
    # without preceding word boundary.
    # not only after whitespace: inside a JSON string the number follows a quote (review round 7 O-3)
    ("PHONE",    r"(?<![\w.+])\+?\d{1,3}[ -]\(?\d{3,5}\)?[ -]\d{3,5}\b"),
    ("SSN_US",   r"\b\d{3}-\d{2}-\d{4}\b"),
]

# --- card PAN / Aadhaar scanner --------------------------------------------------------------------------------
# A digit is an ASCII / Unicode digit (fullwidth, Devanagari, …) or its JSON escape (``２``) — the model reads
# json.dumps output, where non-ASCII digits arrive escaped. A separator is a space, dot, dash, NBSP or zero-width
# character (raw or escaped), at most three in a row.
_DIGIT = r"(?:\d|\\u(?:ff1[0-9]|096[6-9a-fA-F]|0be[6-9a-fA-F]|09e[6-9a-fA-F]))"
_SEP = r"(?:[ .\-\u00a0\u2007\u202f\u200b\u200c\u200d\u2060\ufeff]|\\u(?:00a0|2007|202f|200[bcd]|2060|feff))"
# possessive: a run that is not an ID is consumed once and never re-scanned from inside (O8-3: "1-.1-.1-." took 2.6 s)
_DIGIT_RUN_RX = re.compile(rf"(?<!\d){_DIGIT}(?:{_SEP}{{0,3}}+{_DIGIT})*+")
_ASCII_DIGITS_RX = re.compile(r"[0-9]+")
_PIECE_RX = re.compile(rf"(?P<d>{_DIGIT})|{_SEP}")
_ESCAPE_RX = re.compile(r"\\u([0-9a-fA-F]{4})")

# card group shapes (besides one unbroken 13–19 digit run): 4-4-4-4(-1..3), Amex 4-6-5, Diners 4-6-4
_CARD_SHAPES = {(4, 4, 4, 4), (4, 4, 4, 4, 1), (4, 4, 4, 4, 2), (4, 4, 4, 4, 3), (4, 6, 5), (4, 6, 4)}
_AADHAAR_SHAPES = {(12,), (4, 4, 4)}


def _digit_value(tok: str) -> str:
    if len(tok) == 1 and "0" <= tok <= "9":
        return tok
    m = _ESCAPE_RX.fullmatch(tok)
    ch = chr(int(m.group(1), 16)) if m else tok
    try:
        return str(unicodedata.digit(ch))
    except (TypeError, ValueError):
        return ch if ch.isdigit() else "0"


def _chunks(run: str, offset: int) -> list[tuple[int, int, str]]:
    """(start, end, ascii digits) of each separator-delimited group of a digit run."""
    if run.isascii() and "\\" not in run:                # the common case: ASCII digits and separators
        return [(offset + m.start(), offset + m.end(), m.group(0)) for m in _ASCII_DIGITS_RX.finditer(run)]
    out: list[tuple[int, int, str]] = []
    cur_start, cur_end, digits = -1, -1, []
    for m in _PIECE_RX.finditer(run):
        if m.group("d") is None:                   # a separator closes the current group
            if digits:
                out.append((offset + cur_start, offset + cur_end, "".join(digits)))
                digits = []
            continue
        if not digits:
            cur_start = m.start()
        digits.append(_digit_value(m.group(0)))
        cur_end = m.end()
    if digits:
        out.append((offset + cur_start, offset + cur_end, "".join(digits)))
    return out


_VERHOEFF_D = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
               [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
               [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
               [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_VERHOEFF_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
               [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
               [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]


def _verhoeff_ok(digits: str) -> bool:
    """Aadhaar's own check digit (UIDAI uses Verhoeff)."""
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def _id_windows(chunks: list[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
    """Card and Aadhaar windows over one digit run, as (first chunk, last chunk + 1, kind), non-overlapping.

    Every chunk-aligned window is a candidate, not only the one starting at the run's first digit: a Luhn-invalid
    prefix ("ref 99 4111…", a date, a time) used to swallow the span and leave the card in clear (O8-5). The cover
    that hides the most digits wins (a card ahead of two Aadhaars only when it hides more), check digits break ties.
    """
    n = len(chunks)
    alld = "".join(c[2] for c in chunks)
    off = [0]
    for c in chunks:
        off.append(off[-1] + len(c[2]))
    cands: list[list[tuple[int, str, int]]] = [[] for _ in range(n)]     # per start: (end, kind, score)
    for i in range(n):
        if len(chunks[i][2]) != 4 and len(chunks[i][2]) < 12:
            continue                           # every multi-group shape starts with a group of 4
        total = 0
        shape: list[int] = []
        for j in range(i, min(n, i + 6)):
            d = chunks[j][2]
            total += len(d)
            shape.append(len(d))
            if total > 19:
                break
            tup = tuple(shape)
            card = 13 <= total <= 19 and (len(tup) == 1 or tup in _CARD_SHAPES)
            aadhaar = tup in _AADHAAR_SHAPES
            if not (card or aadhaar):
                continue
            digits = alld[off[i]:off[j + 1]]
            if card and _luhn_digits(digits):
                cands[i].append((j + 1, "PAN_CC", total * 10 + 2))
            if aadhaar and digits[0] in "23456789":
                cands[i].append((j + 1, "AADHAAR", total * 10 + (1 if _verhoeff_ok(digits) else 0)))
    best = [0] * (n + 1)                       # best[i]: score of the best cover of chunks[i:]
    pick: list[tuple[int, str] | None] = [None] * (n + 1)
    for i in range(n - 1, -1, -1):
        best[i], pick[i] = best[i + 1], None
        for end, kind, score in cands[i]:
            if score + best[end] > best[i]:
                best[i], pick[i] = score + best[end], (end, kind)
    out: list[tuple[int, int, str]] = []
    i = 0
    while i < n:
        if pick[i] is None:
            i += 1
            continue
        end, kind = pick[i]
        out.append((i, end, kind))
        i = end
    return out


def _scan_digit_ids(text: str) -> list[tuple[int, int, str]]:
    """(start, end, kind) of every card PAN / Aadhaar in ``text``. Linear: one pass over each digit run."""
    spans: list[tuple[int, int, str]] = []
    for m in _DIGIT_RUN_RX.finditer(text):
        nxt = text[m.end():m.end() + 1]
        if nxt and (nxt.isalnum() and nxt.isascii()):      # glued on the right: a hash / token, not an ID
            continue
        if m.end() - m.start() < 12:
            continue
        chunks = _chunks(m.group(0), m.start())
        if sum(len(c[2]) for c in chunks) < 12 or max(len(c[2]) for c in chunks) < 4:
            continue
        for i, j, kind in _id_windows(chunks):
            spans.append((chunks[i][0], chunks[j - 1][1], kind))
    return spans


def _luhn_ok(digits: str) -> bool:
    """Validate credit-card-shaped strings to suppress false positives."""
    return _luhn_digits("".join(_digit_value(c) for c in digits if c.isdigit()))


def _luhn_digits(digits: str) -> bool:
    """Luhn over a string of ASCII digits only."""
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
    nonce: str = ""            # random per map: a token an attacker wrote into the input never matches


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

    def tokenize(self, text: str, *, into: TokenMap | None = None, nonce: str | None = None) -> tuple[str, TokenMap]:
        """Return (tokenized_text, token_map). The same value always gets the same token in this output.

        Tokens carry a per-map random nonce (``<PII:ACCOUNT:1:9f3a2c>``). They used to be ``<PII:ACCOUNT:1>``,
        which an attacker can write into an alert: the model echoes it and detokenization turns it into the
        victim's account number in the action target (review round 3 G2-5). A token without the nonce is
        never detokenized. Pass ``into`` to keep numbering in one map across several texts (system + user
        used to restart at 1 each, so the two maps collided).
        """
        tm = into if into is not None else TokenMap(OrderedDict(), {})
        if not getattr(tm, "nonce", ""):
            tm.nonce = nonce or secrets.token_hex(3)
        if not text:
            return text, tm
        counters: dict[str, int] = {}
        for tok in tm.by_token:
            k = tok.split(":")[1]
            counters[k] = counters.get(k, 0) + 1

        def _token(kind: str, value: str) -> str:
            if value in tm.by_value:
                return tm.by_value[value]
            idx = counters.get(kind, 0) + 1
            counters[kind] = idx
            token = f"<PII:{kind}:{idx}:{tm.nonce}>"
            tm.by_token[token] = value
            tm.by_value[value] = token
            return token

        # card PANs and Aadhaar numbers first (they used to be the first two patterns)
        parts: list[str] = []
        last = 0
        for s, e, kind in _scan_digit_ids(text):
            parts.append(text[last:s])
            parts.append(_token(kind, text[s:e]))
            last = e
        parts.append(text[last:])
        out = "".join(parts)
        for kind, rx in self._patterns:
            def _replace(match: re.Match[str], kind: str = kind, rx: re.Pattern[str] = rx) -> str:
                whole = match.group(0)
                grouped = "v" in rx.groupindex and match.group("v") is not None
                value = match.group("v") if grouped else whole
                # Suppress false positives on credit-card-shaped strings (a tenant pattern may still say PAN_CC)
                if kind == "PAN_CC" and not _luhn_ok(value):
                    return whole
                if "<PII:" in value:
                    return whole
                token = _token(kind, value)
                if grouped:
                    s, e = match.start("v") - match.start(0), match.end("v") - match.start(0)
                    return whole[:s] + token + whole[e:]
                return token
            out = rx.sub(_replace, out)

        # A value found once with its label ("sender_account": "5010…") is the same PII where it appears bare —
        # an action target, "from 5010… to …" in a signal (review round 8 O8-11). Every occurrence gets the token.
        recent = list(tm.by_value)[-2000:]                # a long-lived map (MCP gateway): its newest values
        found = [v for v in recent if len(v) >= 6 and "<PII:" not in v and v in out][:256]
        if found:
            alt = "|".join(re.escape(v) for v in sorted(found, key=len, reverse=True))
            out = re.sub(rf"(?<![0-9A-Za-z])(?:{alt})(?![0-9A-Za-z])", lambda m: tm.by_value[m.group(0)], out)
        return out, tm

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
