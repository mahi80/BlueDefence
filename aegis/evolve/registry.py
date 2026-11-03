"""The allowlist of symbols a rule may change, and how.

A rule from the feed is *data that mutates code paths*; the only thing
standing between a bad feed entry and the detection logic is this table.
A target not listed here is refused whatever the rule says. Each entry
says what kind of value is accepted, the caps, and any post-apply hook
(e.g. recompiling a regex union that was built at import time).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from importlib import import_module
from typing import Any, Callable, Optional

KIND_SUBSTRING_TUPLE = "substring_tuple"     # tuple[str] of lowercase substrings, matched with `in`
KIND_REGEX_STR_LIST = "regex_str_list"       # list[str] of regex sources (compiled elsewhere)
KIND_COMPILED_REGEX_LIST = "compiled_regex_list"  # list[re.Pattern]
KIND_NUMBER = "number"


@dataclass(frozen=True)
class PatchSpec:
    kind: str
    max_len: int = 200
    #: a primitive shorter than this matches almost every request (`"e"` turned every request into SQLi)
    min_len: int = 4
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    #: called after a successful mutation, e.g. to rebuild a derived compiled regex
    post_apply: Optional[Callable[[], None]] = field(default=None, compare=False)
    description: str = ""


def _recompile_edr_cmdline() -> None:
    mod = import_module("aegis.agents.edr.tools")
    mod._CMDLINE_RX = re.compile("|".join(mod._SUSPICIOUS_CMDLINE_PATTERNS), re.IGNORECASE)


PATCHABLE: dict[str, PatchSpec] = {
    "aegis.agents.perimeter.tools._SQLI_PRIMITIVES": PatchSpec(
        KIND_SUBSTRING_TUPLE, description="SQL-injection payload primitives"),
    "aegis.agents.perimeter.tools._XSS_PRIMITIVES": PatchSpec(
        KIND_SUBSTRING_TUPLE, description="XSS payload primitives"),
    "aegis.agents.perimeter.tools._RCE_PRIMITIVES": PatchSpec(
        KIND_SUBSTRING_TUPLE, description="command-execution payload primitives"),
    "aegis.agents.perimeter.tools._TRAVERSAL_PRIMITIVES": PatchSpec(
        KIND_SUBSTRING_TUPLE, description="path-traversal payload primitives"),
    "aegis.agents.edr.tools._SUSPICIOUS_CMDLINE_PATTERNS": PatchSpec(
        KIND_REGEX_STR_LIST, max_len=300, post_apply=_recompile_edr_cmdline,
        description="suspicious command-line regexes (union recompiled on change)"),
    "aegis.agents.api_abuse.tools._RISKY_QUERY_PATTERNS": PatchSpec(
        KIND_COMPILED_REGEX_LIST, max_len=300, description="risky SQL query regexes"),
}

#: text every detector sees on ordinary traffic; a feed primitive or regex that matches it would fire on everything
BENIGN_SAMPLES = (
    "", "e", "a", "1", " ", "GET / HTTP/1.1", "GET /index.html HTTP/1.1", "POST /api/v1/login HTTP/1.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "user=alice&page=2", "hello world",
    "/api/v1/accounts/1002/statements?month=2026-10", "C:\\Windows\\System32\\svchost.exe -k netsvcs",
    "the quick brown fox", "application/json",
)


def _redos_risk(source: str) -> str | None:
    """A quantified group whose body can itself repeat or branch — ``(a+)+``, ``(\\w+\\s?)*``, ``(a|aa)+``,
    ``((ab)*c)+``, ``(x{1,})*`` — or a backreference. The old check was a single regex that missed alternation,
    nested groups, ``?`` and ``{n,}`` (review round 3 G5-9)."""
    if re.search(r"\\[1-9]|\(\?P=", source):
        return "backreference refused (ReDoS guard)"
    stack: list[dict] = []
    i, n = 0, len(source)
    while i < n:
        c = source[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":                                   # skip a character class
            j = i + 1
            if j < n and source[j] == "^":
                j += 1
            if j < n and source[j] == "]":
                j += 1
            while j < n and source[j] != "]":
                j += 2 if source[j] == "\\" else 1
            i = j + 1
            continue
        if c == "(":
            if stack:
                stack[-1]["risky"] = True               # a nested group
            stack.append({"risky": False})
            i += 1
            continue
        if c == ")":
            g = stack.pop() if stack else {"risky": False}
            j = i + 1
            q = source[j:j + 1]
            repeated = q in ("+", "*") or (q == "{" and re.match(r"\{\d*,\d*\}|\{\d*[2-9]\d*\}|\{\d{2,}\}", source[j:]))
            if repeated and g["risky"]:
                return "nested quantifier or alternation inside a repeated group refused (ReDoS guard)"
            if stack and (repeated or g["risky"]):
                stack[-1]["risky"] = True
            i += 1
            continue
        if stack and (c in "+*?|" or (c == "{" and re.match(r"\{\d", source[i:]))):
            stack[-1]["risky"] = True
        i += 1
    return None


def validate_regex(source: str, max_len: int, min_len: int = 4) -> Optional[str]:
    """Return an error string, or None when the regex is acceptable."""
    if not isinstance(source, str) or not source.strip():
        return "regex must be a non-empty string"
    if len(source) > max_len:
        return f"regex longer than {max_len} chars"
    if len(source.strip()) < min_len:
        return f"regex shorter than {min_len} chars"
    why = _redos_risk(source)
    if why:
        return why
    try:
        rx = re.compile(source, re.IGNORECASE)
    except re.error as e:
        return f"regex does not compile: {e}"
    hit = next((b for b in BENIGN_SAMPLES if rx.search(b)), None)
    if hit is not None:
        return f"regex matches ordinary traffic ({hit!r})"
    return None


def validate_primitive(value: object, spec: PatchSpec) -> str | None:
    """A substring primitive: long enough to mean something, and absent from ordinary traffic."""
    if not isinstance(value, str) or not value.strip():
        return "heuristic_primitive needs change.add (non-empty string)"
    if len(value) > spec.max_len:
        return f"primitive longer than {spec.max_len} chars"
    if len(value.strip()) < spec.min_len:
        return f"primitive shorter than {spec.min_len} chars (it would match almost every request)"
    v = value.lower()
    hit = next((b for b in BENIGN_SAMPLES if b and v in b.lower()), None)
    if hit is not None:
        return f"primitive occurs in ordinary traffic ({hit!r})"
    return None


def resolve(target: str) -> tuple[Any, str]:
    mod_path, _, attr = target.rpartition(".")
    module = import_module(mod_path)
    if not hasattr(module, attr):
        raise AttributeError(f"{target} not found")
    return module, attr
