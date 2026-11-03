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
    """The proposal as the applier would apply it — same allowlist, same lower-casing, same compiled regex
    (``aegis.evolve.applier.plan_change``). A proposal the applier would refuse is not validated at all."""
    from aegis.evolve.applier import _Err, plan_change
    plan = plan_change({"change_type": proposal.change_type, "target_module": proposal.target_module,
                        "change": proposal.change})
    if isinstance(plan, str):
        return None
    target, _spec, mutate = plan

    def safe(current):
        out = mutate(current)
        return current if isinstance(out, _Err) else out

    verb = "add" if proposal.change_type == "heuristic_primitive" else "set"
    what = proposal.change.get("add") if verb == "add" else proposal.change.get("new_value")
    return Patch(target=target, mutate=safe, description=f"{verb} {what!r} {'to' if verb == 'add' else 'on'} {target}")


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
