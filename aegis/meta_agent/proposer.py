"""Proposer — turns FailurePatterns into structured Proposals via LLM.

Single-LLM proposer for the walking skeleton. Production extension
adds multi-agent voting (different model families) and only marks a
proposal `recommend_accept` when both concur.
"""
from __future__ import annotations

import logging
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from aegis.agents.shared.injection_defense import wrap_untrusted
from aegis.agents.shared.llm_client import LLMClient, parse_json

from .observer import FailurePattern

logger = logging.getLogger("aegis.meta_agent.proposer")


_SYSTEM_FILE = Path(__file__).parent / "prompts" / "proposer_system.md"


@dataclass
class Proposal:
    id: str
    target_module: str
    change_type: str   # "heuristic_primitive" | "threshold_adjustment" | "prompt_addendum" | "no_change"
    change: dict
    rationale: str
    evidence_case_ids: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


def _system_prompt() -> str:
    return _SYSTEM_FILE.read_text(encoding="utf-8")


def _build_user_prompt(failures: list[FailurePattern]) -> str:
    serialized = json.dumps([
        {
            "case_id": f.case_id,
            "suite": f.suite,
            "expected": f.expected,
            "got": f.got,
            "confidence": f.confidence,
            "alert": f.alert,
        }
        for f in failures
    ], indent=2)
    wrapped = wrap_untrusted("eval_failures", serialized)
    return (
        f"Failures observed in the eval run ({len(failures)} cases):\n\n"
        f"{wrapped.wrapped}\n\n"
        "Produce one or more JSON proposals per the schema. Only the JSON object."
    )


# ---- Heuristic fallback (used when MockClient or LLM unavailable) -----

_KNOWN_FIXES = {
    # Maps a (module, missing-substring) pair to a heuristic_primitive proposal.
    # Used as a deterministic fallback so the demo still produces useful output
    # without a live LLM. Real production runs always go through the LLM.
}


_SQLI_KEYWORDS_TO_RESTORE = (
    "@@version", "information_schema", "load_file(", "/*!50000",
    "union select", " or 1=1", "' or 1=1", " or true--",
)


def _fallback_proposals(failures: list[FailurePattern]) -> list[Proposal]:
    """Heuristic fallback: inspect failing cases' payloads and propose
    restoring whichever known SQLi keyword is present in the payload but
    apparently missing from the perimeter primitive list. Keeps the demo
    loop closeable when running offline with MockClient.
    """
    proposals: list[Proposal] = []
    miss_failures = [f for f in failures if f.expected != f.got]
    by_keyword: dict[str, list[FailurePattern]] = {}
    for f in miss_failures:
        payload = (f.alert.get("payload") or "").lower()
        for kw in _SQLI_KEYWORDS_TO_RESTORE:
            if kw in payload:
                by_keyword.setdefault(kw, []).append(f)
                break
    for kw, fs in by_keyword.items():
        suffix = "".join(c if c.isalnum() else "_" for c in kw).strip("_")[:24]
        proposals.append(Proposal(
            id=f"PROP-SQLI-PRIMITIVE-RESTORE-{suffix}",
            target_module="aegis.agents.perimeter.tools._SQLI_PRIMITIVES",
            change_type="heuristic_primitive",
            change={"add": kw},
            rationale=(
                f"Failure cases contain '{kw}' in payload; restoring this "
                "primitive to the perimeter list recovers detection."
            ),
            evidence_case_ids=[f.case_id for f in fs],
            metadata={"source": "fallback_heuristic"},
        ))
    return proposals


def _fallback_proposals_old_unused(failures: list[FailurePattern]) -> list[Proposal]:
    """Old single-keyword fallback. Kept for reference; not called."""
    proposals: list[Proposal] = []
    sqli_failures = [
        f for f in failures
        if f.suite == "historical"
        and ("union" in (f.alert.get("payload") or "").lower()
             or "or 1=1" in (f.alert.get("payload") or "").lower())
        and f.expected == "malicious"
        and f.got != "malicious"
    ]
    if sqli_failures:
        proposals.append(Proposal(
            id="PROP-SQLI-PRIMITIVE-RESTORE",
            target_module="aegis.agents.perimeter.tools._SQLI_PRIMITIVES",
            change_type="heuristic_primitive",
            change={"add": "union select"},
            rationale=(
                "Multiple SQLi-shaped historical cases now miss the perimeter heuristic. "
                "Restoring 'union select' to the primitive list restores detection. "
                "This is a known-good pattern; the proposal is conservative."
            ),
            evidence_case_ids=[f.case_id for f in sqli_failures],
            metadata={"source": "fallback_heuristic"},
        ))
    return proposals


def propose(failures: list[FailurePattern], *, llm: Optional[LLMClient] = None,
            max_proposals: int = 5) -> list[Proposal]:
    """Generate proposals from failure patterns. Falls back to heuristics
    if the LLM is unavailable or its output unparseable.
    """
    if not failures:
        return []

    if llm is None:
        return _fallback_proposals(failures)

    system = _system_prompt()
    user = _build_user_prompt(failures)
    try:
        resp = llm.complete(system, user, max_tokens=2048)
        obj = parse_json(resp.text)
    except Exception as exc:  # noqa: BLE001 — heuristic proposals keep the loop alive
        logger.warning("[meta_agent] LLM proposer failed (%s: %s); using heuristic fallback proposals", type(exc).__name__, str(exc)[:120])
        return _fallback_proposals(failures)

    raw_props = obj.get("proposals") or []
    proposals: list[Proposal] = []
    for raw in raw_props[:max_proposals]:
        try:
            proposals.append(Proposal(
                id=str(raw.get("id") or f"PROP-{len(proposals)+1:04d}"),
                target_module=str(raw.get("target_module", "")),
                change_type=str(raw.get("change_type", "no_change")),
                change=dict(raw.get("change") or {}),
                rationale=str(raw.get("rationale", "")),
                evidence_case_ids=list(raw.get("evidence_case_ids") or []),
                metadata={"source": "llm"},
            ))
        except Exception as exc:  # noqa: BLE001 — one malformed proposal is skipped
            logger.debug("[meta_agent] skipped malformed LLM proposal: %s", exc)
            continue
    if not proposals:
        return _fallback_proposals(failures)
    return proposals
