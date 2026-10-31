"""EDR/Host specialist — process / lateral-movement / IOC focus."""
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

logger = logging.getLogger("aegis.edr")


_SYSTEM_PROMPT_FILE = Path(__file__).parent / "system_prompt.md"


def _build_system_prompt() -> str:
    return SYSTEM_PROMPT_PREAMBLE + "\n\n" + _SYSTEM_PROMPT_FILE.read_text(encoding="utf-8")


def _summarize(r: tools.ToolResult) -> str:
    if r.name == "parent_process_tree":
        return (
            f"susp_pair={r.data.get('suspicious_pair')} "
            f"cmd_indicators={r.data.get('cmdline_indicators')}"
        )
    if r.name == "lateral_movement":
        return f"cross_zone_admin={r.data.get('cross_zone_admin')} flow_known={r.data.get('flow_known')}"
    if r.name == "ioc_match":
        return f"ioc_hits={r.data.get('n', 0)}"
    if r.name == "file_integrity":
        return f"drifted={r.data.get('drifted')} tracked={r.data.get('tracked')}"
    if r.name == "autostart_persistence":
        return f"new_autostart={r.data.get('n', 0)} hot_path={r.data.get('hot_path')}"
    if r.name == "webshell_drop":
        return f"in_webroot={r.data.get('in_webroot')} tokens={r.data.get('webshell_tokens')}"
    if r.name == "beacon_periodicity":
        return f"regular={r.data.get('regular')} interval={r.data.get('mean_interval_s')}s hits={r.data.get('hits')}"
    if r.name == "tcc_grant":
        return f"service={r.data.get('service')} trusted={r.data.get('trusted')}"
    if r.name == "ssh_key_added":
        return f"known={r.data.get('known')} uid={r.data.get('uid')}"
    return "tool_result"


class EDRAgent:
    name = "edr"

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
            chain.evidence.append(
                EvidenceItem(source=r.name, signal=_summarize(r), weight=r.weight, raw_data=r.data)
            )
        chain.reasoning.append(
            ReasoningStep(
                step=1,
                action="Ran EDR toolkit (process_tree, lateral_movement, ioc_match, file_integrity)",
                observation=f"{len(results)} tool results",
            )
        )

        # Causal-inference layer: posterior over initial-access + pivoting
        from ..shared.causal import infer_lateral_movement
        causal_obs: dict[str, str] = {}
        for r in results:
            if r.name == "parent_process_tree":
                susp = r.data.get("suspicious_pair") or r.data.get("cmdline_indicators")
                causal_obs["suspicious_process_tree"] = "yes" if susp else "no"
            elif r.name == "lateral_movement" and "cross_zone_admin" in r.data:
                causal_obs["cross_zone_admin"] = (
                    "yes" if r.data["cross_zone_admin"] else "no"
                )
            elif r.name == "ioc_match":
                causal_obs["ioc_match"] = "yes" if (r.data.get("n", 0) > 0) else "no"
            elif r.name == "file_integrity" and "drifted" in r.data:
                causal_obs["file_integrity_drift"] = (
                    "yes" if r.data["drifted"] else "no"
                )
        if causal_obs:
            causal = infer_lateral_movement(causal_obs)
            chain.evidence.append(EvidenceItem(
                source="causal_inference",
                signal=(
                    f"P(initial_access)={causal['p_initial_access']:.2f}; "
                    f"P(pivoting)={causal['p_pivoting']:.2f}"
                ),
                weight=("high" if causal["p_initial_access"] >= 0.6 else
                        "medium" if causal["p_initial_access"] >= 0.3 else "low"),
                raw_data=causal,
            ))
            chain.reasoning.append(
                ReasoningStep(
                    step=len(chain.reasoning) + 1,
                    action="Causal-inference posterior over lateral-movement root cause",
                    observation=(
                        f"Bayesian inference: P(initial_access|observations)="
                        f"{causal['p_initial_access']:.2f}, "
                        f"P(pivoting)={causal['p_pivoting']:.2f}"
                    ),
                    conclusion=(
                        "Causal signal supports initial-access + pivot hypothesis"
                        if causal['p_initial_access'] >= 0.6 else
                        "Causal signal weakly supports / refutes; review carefully"
                    ),
                )
            )

        wrapped_alert = wrap_untrusted("edr_alert", json.dumps(alert))
        wrapped_tools = wrap_untrusted(
            "tool_output",
            "\n".join(f"[{r.name}] weight={r.weight} data={json.dumps(r.data)}" for r in results),
        )

        user_msg = (
            "EDR agent investigation.\n\n"
            f"Alert (untrusted):\n{wrapped_alert.wrapped}\n\n"
            f"Tool output (untrusted):\n{wrapped_tools.wrapped}\n\n"
            "Produce JSON verdict per the schema."
        )
        resp = complete_for_json(self._llm, self._system, user_msg)   # JSON-only, retry on truncation
        chain.metadata.update(
            llm_model=resp.model, llm_input_tokens=resp.input_tokens, llm_output_tokens=resp.output_tokens
        )
        try:
            verdict = parse_json(resp.text)
        except Exception as exc:  # noqa: BLE001 — a bad LLM answer escalates, never crashes the SOC
            logger.warning("[%s] LLM verdict unparsable for alert %s (%s: %s); escalating", self.name, alert.get("id", "?"), type(exc).__name__, str(exc)[:120])
            chain.recommended_actions.append(
                RecommendedAction(
                    action_type="escalate",
                    target=alert.get("host", alert.get("id", "unknown")),
                    reasoning="EDR agent failed to produce valid verdict",
                    requires_hitl=True,
                    confidence=0.0,
                )
            )
            return chain.finalize()

        chain.verdict = verdict.get("verdict", "uncertain")
        chain.confidence = float(verdict.get("confidence", 0.5))
        chain.reasoning.append(
            ReasoningStep(
                step=2,
                action="LLM produced EDR verdict",
                observation=verdict.get("summary", ""),
                conclusion=f"verdict={chain.verdict}, conf={chain.confidence}",
            )
        )
        for action in verdict.get("actions", []):
            chain.recommended_actions.append(
                RecommendedAction(
                    action_type=action.get("type", "monitor"),
                    target=str(action.get("target", alert.get("host", "unknown"))),
                    reasoning=verdict.get("summary", ""),
                    requires_hitl=bool(action.get("hitl", False)),
                    confidence=float(action.get("confidence", chain.confidence)),
                )
            )
        return chain.finalize()
