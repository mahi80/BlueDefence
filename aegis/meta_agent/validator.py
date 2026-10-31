"""Validator — replays the eval with a Proposal applied as a monkey-patch
and measures the delta vs the baseline failure set.

Strict invariants:
  - Validation runs in simulation only. Never modifies repo files.
  - Proposal must reduce failures without introducing regressions to be
    `recommend_accept`-eligible.
  - Patch is applied in a context manager so state is cleanly restored
    after each validation, regardless of outcome.
"""
from __future__ import annotations

from dataclasses import dataclass

from .observer import FailurePattern, Patch, observe
from .proposer import Proposal


@dataclass
class ValidationResult:
    proposal_id: str
    failures_before: int
    failures_after: int
    regressions: int
    recommend_accept: bool
    notes: str = ""


def _proposal_to_patch(proposal: Proposal) -> Patch | None:
    if proposal.change_type == "heuristic_primitive":
        target = proposal.target_module
        addition = proposal.change.get("add")
        if not target or not addition:
            return None

        def mutate(current):
            if isinstance(current, tuple):
                if addition in current:
                    return current
                return current + (addition,)
            if isinstance(current, list):
                if addition in current:
                    return current
                return current + [addition]
            if isinstance(current, set):
                return current | {addition}
            return current  # unsupported container type — no-op patch

        return Patch(target=target, mutate=mutate,
                     description=f"add {addition!r} to {target}")

    if proposal.change_type == "threshold_adjustment":
        target = proposal.target_module
        new_value = proposal.change.get("new_value")
        if not target or new_value is None:
            return None

        def mutate(current):
            return type(current)(new_value) if current is not None else new_value

        return Patch(target=target, mutate=mutate,
                     description=f"set {target} = {new_value}")

    # prompt_addendum: production would re-read the prompt file with text appended;
    # for the walking skeleton we don't validate prompt-level changes (they require
    # an LLM call to measure impact, and the mock doesn't honor prompt addenda).
    return None


def validate(proposal: Proposal,
             baseline_failures: list[FailurePattern]) -> ValidationResult:
    if proposal.change_type == "no_change":
        return ValidationResult(
            proposal_id=proposal.id,
            failures_before=len(baseline_failures),
            failures_after=len(baseline_failures),
            regressions=0,
            recommend_accept=False,
            notes="proposer chose no_change",
        )

    patch = _proposal_to_patch(proposal)
    if patch is None:
        return ValidationResult(
            proposal_id=proposal.id,
            failures_before=len(baseline_failures),
            failures_after=len(baseline_failures),
            regressions=0,
            recommend_accept=False,
            notes=f"unsupported change_type or invalid change for {proposal.change_type}",
        )

    baseline_ids = {f.case_id for f in baseline_failures}
    after = observe(patches=[patch])
    after_ids = {f.case_id for f in after}
    regressions = sorted(after_ids - baseline_ids)

    accept = (
        len(after) < len(baseline_failures)
        and not regressions
    )

    notes = patch.description
    if regressions:
        notes += f" | regressions: {','.join(regressions)}"

    return ValidationResult(
        proposal_id=proposal.id,
        failures_before=len(baseline_failures),
        failures_after=len(after),
        regressions=len(regressions),
        recommend_accept=accept,
        notes=notes,
    )
