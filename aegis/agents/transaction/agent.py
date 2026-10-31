"""Transaction/Fraud specialist."""
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

logger = logging.getLogger("aegis.transaction")


_SYSTEM_PROMPT_FILE = Path(__file__).parent / "system_prompt.md"


def _build_system_prompt() -> str:
    return SYSTEM_PROMPT_PREAMBLE + "\n\n" + _SYSTEM_PROMPT_FILE.read_text(encoding="utf-8")


def _summarize(r: tools.ToolResult) -> str:
    if r.name == "mule_pattern":
        return f"is_mule_shape={r.data.get('is_mule_shape')}"
    if r.name == "beneficiary_risk":
        return (
            f"high_risk_geo={r.data.get('is_high_risk_geo')} "
            f"new={r.data.get('is_new_beneficiary')} "
            f"sanctioned={r.data.get('sanctioned')}"
        )
    if r.name == "velocity":
        return f"count_p99x={r.data.get('count_ratio_p99')} amt_p99x={r.data.get('amount_ratio_p99')}"
    if r.name == "payment_rail":
        return f"novel={r.data.get('novel_rail')} high_value={r.data.get('high_value')}"
    if r.name == "aml_structuring":
        return f"structuring={r.data.get('structuring_pattern')}"
    return "tool_result"


class TransactionAgent:
    name = "transaction"

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
            action="Ran fraud toolkit (mule, beneficiary_risk, velocity, rail, aml_structuring)",
            observation=f"{len(results)} tool results",
        ))

        # Causal-inference layer: posterior over compromise / extraction
        from ..shared.causal import infer_fraud
        causal_obs: dict[str, str] = {}
        for r in results:
            if r.name == "mule_pattern" and "is_mule_shape" in r.data:
                causal_obs["mule_destination"] = "yes" if r.data["is_mule_shape"] else "no"
            elif r.name == "payment_rail" and "novel_rail" in r.data and "high_value" in r.data:
                causal_obs["novel_high_value_rail"] = (
                    "yes" if (r.data["novel_rail"] and r.data["high_value"]) else "no"
                )
            elif r.name == "aml_structuring" and "structuring_pattern" in r.data:
                causal_obs["structuring"] = "yes" if r.data["structuring_pattern"] else "no"
            elif r.name == "velocity" and "over_p99" in r.data:
                causal_obs["velocity_anomaly"] = "yes" if r.data["over_p99"] else "no"
        if causal_obs:
            causal = infer_fraud(causal_obs)
            chain.evidence.append(EvidenceItem(
                source="causal_inference",
                signal=(
                    f"P(compromise)={causal['p_compromise']:.2f}; "
                    f"most_likely_root_cause={causal['most_likely_root_cause'][0]} "
                    f"(P={causal['most_likely_root_cause'][1]:.2f})"
                ),
                weight=("high" if causal["p_compromise"] >= 0.6 else
                        "medium" if causal["p_compromise"] >= 0.3 else "low"),
                raw_data=causal,
            ))
            chain.reasoning.append(ReasoningStep(
                step=len(chain.reasoning) + 1,
                action="Causal-inference posterior over fraud root cause",
                observation=(
                    f"Bayesian inference on fraud causal network: "
                    f"P(compromise|observations)={causal['p_compromise']:.2f}, "
                    f"P(attacker_extracting)={causal['p_attacker_extracting']:.2f}"
                ),
                conclusion=(
                    "Causal signal supports compromise/extraction hypothesis"
                    if causal['p_compromise'] >= 0.6 else
                    "Causal signal weakly supports / refutes; review with caution"
                ),
            ))

        wrapped_alert = wrap_untrusted("txn_alert", json.dumps(alert))
        wrapped_tools = wrap_untrusted(
            "tool_output",
            "\n".join(f"[{r.name}] weight={r.weight} data={json.dumps(r.data)}" for r in results),
        )

        user_msg = (
            "Transaction/Fraud agent investigation.\n\n"
            f"Alert (untrusted):\n{wrapped_alert.wrapped}\n\n"
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
                reasoning="Transaction agent failed to produce valid verdict",
                requires_hitl=True, confidence=0.0,
            ))
            return chain.finalize()

        chain.verdict = verdict.get("verdict", "uncertain")
        chain.confidence = float(verdict.get("confidence", 0.5))
        chain.reasoning.append(ReasoningStep(
            step=2,
            action="LLM produced fraud verdict",
            observation=verdict.get("summary", ""),
            conclusion=f"verdict={chain.verdict}, conf={chain.confidence}",
        ))
        for action in verdict.get("actions", []):
            chain.recommended_actions.append(RecommendedAction(
                action_type=action.get("type", "monitor"),
                target=str(action.get("target", alert.get("user_id", "unknown"))),
                reasoning=verdict.get("summary", ""),
                requires_hitl=bool(action.get("hitl", False)),
                confidence=float(action.get("confidence", chain.confidence)),
            ))
        return chain.finalize()
