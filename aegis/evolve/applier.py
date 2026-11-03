"""Apply accepted rules to the running specialists — safely, reversibly."""

from __future__ import annotations

import logging
import math
import re
import threading
from dataclasses import dataclass, field
from collections.abc import Callable
from typing import Any

from .registry import (
    KIND_COMPILED_REGEX_LIST, KIND_NUMBER, KIND_REGEX_STR_LIST, KIND_SUBSTRING_TUPLE,
    PATCHABLE, resolve, validate_primitive, validate_regex,
)

logger = logging.getLogger("aegis.evolve")

SUPPORTED_CHANGE_TYPES = ("heuristic_primitive", "threshold_adjustment")


@dataclass
class ApplyReport:
    version: str = ""
    applied: list[str] = field(default_factory=list)      # rule ids applied in this call
    already: list[str] = field(default_factory=list)      # rule ids applied earlier (no-op)
    rejected: list[tuple[str, str]] = field(default_factory=list)  # (rule id, reason)
    withdrawn: list[str] = field(default_factory=list)    # rule ids no longer in the feed: reverted

    @property
    def ok(self) -> bool:
        return not self.rejected


class RuleApplier:
    """Idempotent, allowlist-checked, revertible in-process rule application."""

    def __init__(self):
        self._lock = threading.Lock()
        self._originals: dict[str, Any] = {}       # target → value before the first rule touched it
        self._applied: dict[str, dict] = {}        # rule id → rule
        self.version: str = ""

    # ---------------------------------------------------------------- api --

    def apply(self, rules: list[dict], version: str = "", *, snapshot: bool = True) -> ApplyReport:
        """Apply ``rules``. With ``snapshot`` (the feed's full current rule set, the default) a rule applied earlier
        and no longer listed is WITHDRAWN: everything is reverted to the original values and the current set
        re-applied. A withdrawn rule used to stay in force until the process restarted (review round 3 G5-9)."""
        report = ApplyReport(version=version)
        with self._lock:
            ids = {str(r.get("id") or r.get("proposal_id") or "") for r in rules}
            gone = sorted(set(self._applied) - ids) if snapshot else []
            if gone:
                self._revert_locked()
                report.withdrawn = gone
                logger.warning("[evolve] %d rule(s) withdrawn from the feed and reverted: %s", len(gone), ", ".join(gone[:10]))
            for rule in rules:
                rid = str(rule.get("id") or rule.get("proposal_id") or "")
                if not rid:
                    report.rejected.append(("?", "rule without id"))
                    continue
                if rid in self._applied:
                    report.already.append(rid)
                    continue
                err = self._apply_one(rule)
                if err:
                    report.rejected.append((rid, err))
                    logger.warning("[evolve] rule %s rejected: %s", rid, err)
                else:
                    self._applied[rid] = rule
                    report.applied.append(rid)
                    logger.info("[evolve] rule %s applied: %s", rid, rule.get("title") or rule.get("target_module"))
            if version:
                self.version = version
        return report

    def revert_all(self) -> int:
        """Restore every patched symbol to its pre-feed value. Returns the count."""
        with self._lock:
            return self._revert_locked()

    def _revert_locked(self) -> int:
        n = 0
        for target, original in self._originals.items():
            try:
                module, attr = resolve(target)
                setattr(module, attr, original)
                spec = PATCHABLE.get(target)
                if spec and spec.post_apply:
                    spec.post_apply()
                n += 1
            except Exception as e:  # noqa: BLE001
                logger.error("[evolve] revert of %s failed: %s", target, e, exc_info=True)
        self._originals.clear()
        self._applied.clear()
        self.version = ""
        return n

    @property
    def applied_rules(self) -> list[dict]:
        return list(self._applied.values())

    # ---------------------------------------------------------- internals --

    def _apply_one(self, rule: dict) -> str | None:
        plan = plan_change(rule)
        if isinstance(plan, str):
            return plan
        target, spec, mutate = plan
        try:
            module, attr = resolve(target)
        except Exception as e:  # noqa: BLE001
            return f"cannot resolve {target}: {e}"
        current = getattr(module, attr)
        new_value = mutate(current)
        if isinstance(new_value, _Err):
            return str(new_value)
        self._originals.setdefault(target, current)
        setattr(module, attr, new_value)
        if spec.post_apply:
            try:
                spec.post_apply()
            except Exception as e:  # noqa: BLE001 — undo the mutation rather than leave a half-applied rule
                setattr(module, attr, current)
                return f"post-apply hook failed: {e}"
        return None


class _Err(str):
    """An error message returned by a mutate function instead of a new value."""


def plan_change(rule: dict) -> tuple[str, Any, Callable[[Any], Any]] | str:
    """Check a rule against the allowlist and return ``(target, spec, mutate)``, or an error string.

    The ONE place a rule's effect is defined: the applier runs ``mutate`` on the live symbol, and the meta-agent's
    validator replays the eval with the very same ``mutate``. They used to be two implementations (the validator
    did not lower-case primitives, compile regexes or check the allowlist), so a proposal was measured as one
    change and applied as another (review round 3 G5-9)."""
    change_type = str(rule.get("change_type", ""))
    if change_type not in SUPPORTED_CHANGE_TYPES:
        return f"unsupported change_type {change_type!r} (prompt_addendum needs a live-LLM measurement first)"
    target = str(rule.get("target_module", ""))
    spec = PATCHABLE.get(target)
    if spec is None:
        return f"target {target!r} is not in the patchable allowlist"
    change = rule.get("change") if isinstance(rule.get("change"), dict) else {}

    if change_type == "heuristic_primitive":
        addition = change.get("add")
        if spec.kind == KIND_SUBSTRING_TUPLE:
            err = validate_primitive(addition, spec)
            if err:
                return err
            addition = str(addition).lower()

            def mutate(current: Any) -> Any:
                if not isinstance(current, (tuple, list)):
                    return _Err(f"{target} is not a sequence")
                if addition in current:
                    return current
                return tuple(current) + (addition,) if isinstance(current, tuple) else list(current) + [addition]
            return target, spec, mutate
        if spec.kind in (KIND_REGEX_STR_LIST, KIND_COMPILED_REGEX_LIST):
            err = validate_regex(addition, spec.max_len, spec.min_len)
            if err:
                return err
            src = str(addition)

            def mutate(current: Any) -> Any:
                if spec.kind == KIND_REGEX_STR_LIST:
                    return current if src in current else list(current) + [src]
                if any(getattr(rx, "pattern", None) == src for rx in current):
                    return current
                return list(current) + [re.compile(src, re.IGNORECASE)]
            return target, spec, mutate
        return f"heuristic_primitive not valid for kind {spec.kind}"

    if spec.kind != KIND_NUMBER:
        return f"threshold_adjustment not valid for {target} ({spec.kind})"
    try:
        value = float(change.get("new_value"))
    except (TypeError, ValueError):
        return "threshold_adjustment needs numeric change.new_value"
    if not math.isfinite(value):
        return "threshold_adjustment needs a finite change.new_value"
    if spec.min_value is not None and value < spec.min_value:
        return f"new_value below minimum {spec.min_value}"
    if spec.max_value is not None and value > spec.max_value:
        return f"new_value above maximum {spec.max_value}"

    def mutate(current: Any) -> Any:
        return type(current)(value) if isinstance(current, (int, float)) and not isinstance(current, bool) else value
    return target, spec, mutate
