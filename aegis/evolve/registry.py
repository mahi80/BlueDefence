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

#: regex sources longer than this, or with nested quantifiers, are refused (ReDoS guard)
_NESTED_QUANTIFIER = re.compile(r"\([^)]*[+*][^)]*\)[+*{]")


def validate_regex(source: str, max_len: int) -> Optional[str]:
    """Return an error string, or None when the regex is acceptable."""
    if not isinstance(source, str) or not source.strip():
        return "regex must be a non-empty string"
    if len(source) > max_len:
        return f"regex longer than {max_len} chars"
    if _NESTED_QUANTIFIER.search(source):
        return "nested quantifier refused (ReDoS guard)"
    try:
        re.compile(source, re.IGNORECASE)
    except re.error as e:
        return f"regex does not compile: {e}"
    return None


def resolve(target: str) -> tuple[Any, str]:
    mod_path, _, attr = target.rpartition(".")
    module = import_module(mod_path)
    if not hasattr(module, attr):
        raise AttributeError(f"{target} not found")
    return module, attr
