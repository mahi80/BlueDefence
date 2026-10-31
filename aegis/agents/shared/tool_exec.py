"""Defensive execution layer for specialist agents.

The specialist agents call deterministic tools (`run_all_tools`) that assume
well-typed alert fields. Under a live LLM — especially adversarial red-team
alert generation — field types vary arbitrarily (int where a list is expected,
a dict where a string is expected), and a tool raises an uncaught exception
that kills the whole investigation and crashes the orchestrator.

`@defensive_investigate` wraps a specialist's `investigate(self, alert)` so any
exception is turned into a **safe, auditable** EvidenceChain instead of a crash:

  - verdict = "uncertain", a recommended action of "escalate" (route to a human),
  - a ReasoningStep recording the failure,
  - `metadata["tool_error"]` capturing the exception type + detail.

This fails safe (never silently drops to a passive verdict), keeps the failure
visible in the WORM audit log, and — crucially — is deterministic: it hardens
*every* specialist against *any* malformed input in one place, rather than
chasing per-tool type-guards that can't converge against non-deterministic
LLM-generated inputs.

Per-tool type-guards (e.g. in auth/tools.py) remain valuable: they let the
common malformed cases degrade *without* losing the other tools' signals. This
decorator is the catch-all net beneath them.
"""
from __future__ import annotations

import logging
import traceback
from functools import wraps
from typing import Callable

from aegis.agents.shared.evidence_chain import (
    EvidenceChain,
    ReasoningStep,
    RecommendedAction,
)

logger = logging.getLogger("aegis.agents.defensive")


def defensive_investigate(fn: Callable) -> Callable:
    """Wrap a specialist `investigate(self, alert)` so a tool crash becomes a
    safe 'escalate for review' EvidenceChain rather than an uncaught exception."""

    @wraps(fn)
    def wrapper(self, alert, *args, **kwargs):
        try:
            return fn(self, alert, *args, **kwargs)
        except Exception as e:  # noqa: BLE001 — deliberate catch-all safety net
            alert_id = alert.get("id", "unknown") if isinstance(alert, dict) else "unknown"
            investigated_by = getattr(self, "name", getattr(fn, "__qualname__", "specialist"))
            logger.warning(
                "[defensive] %s.investigate crashed on alert %s: %s: %s — escalating",
                investigated_by, alert_id, type(e).__name__, str(e)[:200],
            )
            chain = EvidenceChain(
                alert_id=alert_id,
                investigated_by=investigated_by,
                verdict="uncertain",
                confidence=0.5,
            )
            chain.reasoning.append(ReasoningStep(
                step=1,
                action="tool_execution",
                observation=f"{type(e).__name__}: {str(e)[:200]}",
                conclusion="Automated investigation could not complete on this input; escalating for human review.",
            ))
            chain.recommended_actions.append(RecommendedAction(
                action_type="escalate",
                target=alert_id,
                reasoning="A tool raised on a malformed/unexpected input shape; routing to a human rather than guessing.",
                requires_hitl=True,
                confidence=0.5,
            ))
            # Record the failing tool's location (last aegis frame, excluding this
            # wrapper) so the audit trail says *which* tool choked, not just that
            # one did — useful for both HITL triage and follow-up hardening.
            _frames = [
                ln.strip() for ln in traceback.format_exc().splitlines()
                if ln.strip().startswith("File") and "aegis" in ln and "tool_exec.py" not in ln
            ]
            chain.metadata["tool_error"] = {
                "type": type(e).__name__,
                "detail": str(e)[:300],
                "location": _frames[-1] if _frames else "?",
            }
            return chain.finalize()

    return wrapper
