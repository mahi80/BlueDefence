"""Apply accepted rules to the running specialists — safely, reversibly."""

from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass, field
from typing import Any

from .registry import (
    KIND_COMPILED_REGEX_LIST, KIND_NUMBER, KIND_REGEX_STR_LIST, KIND_SUBSTRING_TUPLE,
    PATCHABLE, resolve, validate_regex,
)

logger = logging.getLogger("aegis.evolve")

SUPPORTED_CHANGE_TYPES = ("heuristic_primitive", "threshold_adjustment")


@dataclass
class ApplyReport:
    version: str = ""
    applied: list[str] = field(default_factory=list)      # rule ids applied in this call
    already: list[str] = field(default_factory=list)      # rule ids applied earlier (no-op)
    rejected: list[tuple[str, str]] = field(default_factory=list)  # (rule id, reason)

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

    def apply(self, rules: list[dict], version: str = "") -> ApplyReport:
        report = ApplyReport(version=version)
        with self._lock:
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
        change_type = str(rule.get("change_type", ""))
        if change_type not in SUPPORTED_CHANGE_TYPES:
            return f"unsupported change_type {change_type!r} (prompt_addendum needs a live-LLM measurement first)"
        target = str(rule.get("target_module", ""))
        spec = PATCHABLE.get(target)
        if spec is None:
            return f"target {target!r} is not in the patchable allowlist"
        change = rule.get("change") if isinstance(rule.get("change"), dict) else {}
        try:
            module, attr = resolve(target)
        except Exception as e:  # noqa: BLE001
            return f"cannot resolve {target}: {e}"
        current = getattr(module, attr)

        if change_type == "heuristic_primitive":
            addition = change.get("add")
            if spec.kind == KIND_SUBSTRING_TUPLE:
                if not isinstance(addition, str) or not addition.strip():
                    return "heuristic_primitive needs change.add (non-empty string)"
                if len(addition) > spec.max_len:
                    return f"primitive longer than {spec.max_len} chars"
                addition = addition.lower()
                if not isinstance(current, (tuple, list)):
                    return f"{target} is not a sequence"
                if addition in current:
                    new_value = current
                else:
                    new_value = tuple(current) + (addition,) if isinstance(current, tuple) else list(current) + [addition]
            elif spec.kind in (KIND_REGEX_STR_LIST, KIND_COMPILED_REGEX_LIST):
                err = validate_regex(addition, spec.max_len)
                if err:
                    return err
                if spec.kind == KIND_REGEX_STR_LIST:
                    new_value = list(current) if addition not in current else current
                    if addition not in current:
                        new_value.append(addition)
                else:
                    if any(getattr(rx, "pattern", None) == addition for rx in current):
                        new_value = current
                    else:
                        new_value = list(current) + [re.compile(addition, re.IGNORECASE)]
            else:
                return f"heuristic_primitive not valid for kind {spec.kind}"
        else:  # threshold_adjustment
            if spec.kind != KIND_NUMBER:
                return f"threshold_adjustment not valid for {target} ({spec.kind})"
            try:
                value = float(change.get("new_value"))
            except (TypeError, ValueError):
                return "threshold_adjustment needs numeric change.new_value"
            if spec.min_value is not None and value < spec.min_value:
                return f"new_value below minimum {spec.min_value}"
            if spec.max_value is not None and value > spec.max_value:
                return f"new_value above maximum {spec.max_value}"
            new_value = type(current)(value) if isinstance(current, (int, float)) else value

        self._originals.setdefault(target, current)
        setattr(module, attr, new_value)
        if spec.post_apply:
            try:
                spec.post_apply()
            except Exception as e:  # noqa: BLE001 — undo the mutation rather than leave a half-applied rule
                setattr(module, attr, current)
                return f"post-apply hook failed: {e}"
        return None
