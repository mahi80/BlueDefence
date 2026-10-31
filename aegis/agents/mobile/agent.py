"""Mobile-app specialist."""
from __future__ import annotations

import logging
import json
from pathlib import Path

from ..shared.evidence_chain import (
    EvidenceChain,
    EvidenceItem,
    ReasoningStep,
    RecommendedAction,
)
from ..shared.injection_defense import SYSTEM_PROMPT_PREAMBLE, wrap_untrusted
from ..shared.llm_client import LLMClient, parse_json, complete_for_json
from . import tools
from ..shared.tool_exec import defensive_investigate

logger = logging.getLogger("aegis.mobile")


_SYSTEM_PROMPT_FILE = Path(__file__).parent / "system_prompt.md"


def _build_system_prompt() -> str:
    return SYSTEM_PROMPT_PREAMBLE + "\n\n" + _SYSTEM_PROMPT_FILE.read_text(encoding="utf-8")


def _summarize(r: tools.ToolResult) -> str:
    if r.name == "jailbreak_root":
        return f"tampered={r.data.get('tampered')}"
    if r.name == "sdk_integrity":
        return f"repackaged={r.data.get('repackaged')} pinning_failed={r.data.get('ssl_pinning_failed')}"
    if r.name == "sim_swap":
        return f"swap_24h={r.data.get('swap_within_24h')} porting={r.data.get('number_porting_in_progress')}"
    if r.name == "mobile_session":
        return (f"impossible_velocity={r.data.get('impossible_velocity')} "
                f"overlay={r.data.get('screen_overlay_detected')} "
                f"side_loaded={r.data.get('side_loaded')}")
    return "tool_result"


class MobileAgent:
    name = "mobile"

    def __init__(self, llm: LLMClient):
        self._llm = llm
        self._system = _build_system_prompt()

    @defensive_investigate
    def investigate(self, alert: dict) -> EvidenceChain:
        chain = EvidenceChain(
            alert_id=alert.get("id", "unknown"),
            investigated_by=self.name,
            verdict="uncertain",
            confidence=0.5,
        )
        results = tools.run_all_tools(alert)
        for r in results:
            chain.evidence.append(EvidenceItem(
                source=r.name, signal=_summarize(r), weight=r.weight, raw_data=r.data,
            ))
        chain.reasoning.append(ReasoningStep(
            step=1,
            action="Ran mobile-app toolkit (jailbreak_root, sdk_integrity, sim_swap, mobile_session)",
            observation=f"{len(results)} tool results",
        ))

        wrapped_alert = wrap_untrusted("mobile_event", json.dumps(alert))
        wrapped_tools = wrap_untrusted(
            "tool_output",
            "\n".join(f"[{r.name}] weight={r.weight} data={json.dumps(r.data)}" for r in results),
        )
        user_msg = (
            "Mobile-app agent investigation.\n\n"
            f"Event (untrusted):\n{wrapped_alert.wrapped}\n\n"
            f"Tool output (untrusted):\n{wrapped_tools.wrapped}\n\n"
            "Produce JSON verdict per the schema."
        )
        resp = complete_for_json(self._llm, self._system, user_msg)   # JSON-only, retry on truncation
        chain.metadata.update(
            llm_model=resp.model, llm_input_tokens=resp.input_tokens, llm_output_tokens=resp.output_tokens,
        )
        try:
            verdict = parse_json(resp.text)
        except Exception as exc:  # noqa: BLE001 — a bad LLM answer escalates, never crashes the SOC
            logger.warning("[%s] LLM verdict unparsable for alert %s (%s: %s); escalating", self.name, alert.get("id", "?"), type(exc).__name__, str(exc)[:120])
            chain.recommended_actions.append(RecommendedAction(
                action_type="escalate", target=alert.get("id", "unknown"),
                reasoning="Mobile agent failed to produce valid verdict",
                requires_hitl=True, confidence=0.0,
            ))
            return chain.finalize()

        chain.verdict = verdict.get("verdict", "uncertain")
        chain.confidence = float(verdict.get("confidence", 0.5))
        chain.reasoning.append(ReasoningStep(
            step=2,
            action="LLM produced mobile verdict",
            observation=verdict.get("summary", ""),
            conclusion=f"verdict={chain.verdict}, conf={chain.confidence}",
        ))
        for action in verdict.get("actions", []):
            chain.recommended_actions.append(RecommendedAction(
                action_type=action.get("type", "monitor"),
                target=str(action.get("target", alert.get("user_id") or alert.get("id", "unknown"))),
                reasoning=verdict.get("summary", ""),
                requires_hitl=bool(action.get("hitl", False)),
                confidence=float(action.get("confidence", chain.confidence)),
            ))
        return chain.finalize()
