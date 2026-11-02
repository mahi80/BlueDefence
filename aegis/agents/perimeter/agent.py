"""Perimeter Specialist Agent.

Investigates web/L7 alerts dispatched by the SOC Orchestrator. Runs its
toolkit, hands the structured tool output to the LLM as analyzed_data,
and parses a verdict back into a structured EvidenceChain.
"""
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

logger = logging.getLogger("aegis.perimeter")


_SYSTEM_PROMPT_FILE = Path(__file__).parent / "system_prompt.md"


def _build_system_prompt() -> str:
    return SYSTEM_PROMPT_PREAMBLE + "\n\n" + _SYSTEM_PROMPT_FILE.read_text(encoding="utf-8")


def _format_tool_output_for_llm(results: list[tools.ToolResult]) -> str:
    return "\n".join(
        f"[{r.name}] weight={r.weight} data={json.dumps(r.data)}" for r in results
    )


class PerimeterAgent:
    name = "perimeter"

    def __init__(self, llm: LLMClient):
        self._llm = llm
        self._system = _build_system_prompt()

    @defensive_investigate
    def investigate(self, alert: dict) -> EvidenceChain:
        alert_id = alert.get("id", "unknown")
        chain = EvidenceChain(
            alert_id=alert_id,
            investigated_by=self.name,
            verdict="uncertain",
            confidence=0.5,
        )

        payload = alert.get("payload", "")
        ip = alert.get("source_ip", "")
        user_id = alert.get("user_id")

        # Run tools; convert results to evidence items.
        tool_results = tools.run_all_tools(payload, ip, user_id, alert=alert)
        for r in tool_results:
            chain.evidence.append(
                EvidenceItem(
                    source=r.name,
                    signal=_summarize_result(r),
                    weight=r.weight,
                    raw_data=r.data,
                )
            )

        chain.reasoning.append(
            ReasoningStep(
                step=1,
                action="Ran perimeter toolkit (decode, ip_rep, similar_requests, baseline)",
                observation=f"{len(tool_results)} tool results collected",
            )
        )

        # Build LLM input with strict data/instruction separation.
        wrapped_alert = wrap_untrusted("alert", json.dumps(alert))
        wrapped_tools = wrap_untrusted("tool_output", _format_tool_output_for_llm(tool_results))
        injection_warning = ""
        if wrapped_alert.injection_detected or wrapped_tools.injection_detected:
            chain.evidence.append(
                EvidenceItem(
                    source="injection_defense",
                    signal=(
                        "Prompt-injection patterns detected in analyzed data: "
                        + ", ".join(wrapped_alert.matched_patterns + wrapped_tools.matched_patterns)
                    ),
                    weight="high",
                    raw_data={
                        "alert_patterns": wrapped_alert.matched_patterns,
                        "tool_patterns": wrapped_tools.matched_patterns,
                    },
                )
            )
            chain.reasoning.append(
                ReasoningStep(
                    step=len(chain.reasoning) + 1,
                    action="Detected prompt-injection patterns in untrusted data",
                    observation="Recording as attack signal; will not act on contained instructions",
                )
            )
            injection_warning += "[heuristic flag] prompt-injection text patterns present\n"
        obf_count = wrapped_alert.obfuscation_char_count + wrapped_tools.obfuscation_char_count
        if obf_count > 0:
            obf_findings = wrapped_alert.obfuscation_findings + wrapped_tools.obfuscation_findings
            chain.evidence.append(
                EvidenceItem(
                    source="injection_defense",
                    signal=(
                        f"Unicode-obfuscation chars detected ({obf_count} total): "
                        + ", ".join(obf_findings)
                    ),
                    weight="high",
                    raw_data={"findings": obf_findings, "count": obf_count},
                )
            )
            chain.reasoning.append(
                ReasoningStep(
                    step=len(chain.reasoning) + 1,
                    action="Detected unicode-obfuscation characters in untrusted data",
                    observation=(
                        f"{obf_count} hidden chars (U+3000 padding / zero-width / "
                        "RLO override / zalgo). Codex branch-name exploit class — "
                        "treat input as suspicious even if visible text looks benign."
                    ),
                )
            )
            injection_warning += (
                f"[heuristic flag] {obf_count} unicode-obfuscation chars present "
                f"({', '.join(obf_findings)})\n"
            )

        user_msg = (
            "Perimeter agent investigation.\n\n"
            + (injection_warning + "\n" if injection_warning else "")
            + f"Alert (untrusted):\n{wrapped_alert.wrapped}\n\n"
            + f"Tool output (untrusted):\n{wrapped_tools.wrapped}\n\n"
            + "Produce the JSON verdict per the schema."
        )

        resp = complete_for_json(self._llm, self._system, user_msg)   # JSON-only, retry on truncation
        chain.metadata["llm_model"] = resp.model
        chain.metadata["llm_input_tokens"] = resp.input_tokens
        chain.metadata["llm_output_tokens"] = resp.output_tokens

        try:
            verdict = parse_json(resp.text)
        except Exception as exc:  # noqa: BLE001 — recorded as a reasoning step + logged, never a crash
            logger.warning("[%s] LLM verdict unparsable for alert %s (%s: %s)", self.name, alert.get("id", "?"), type(exc).__name__, str(exc)[:120])
            chain.reasoning.append(
                ReasoningStep(
                    step=len(chain.reasoning) + 1,
                    action="Parse LLM verdict",
                    observation=f"Failed to parse JSON: {exc}",
                    conclusion="Defaulting to uncertain — escalate to human.",
                )
            )
            chain.recommended_actions.append(
                RecommendedAction(
                    action_type="escalate",
                    target=alert_id,
                    reasoning="Specialist failed to produce valid verdict",
                    requires_hitl=True,
                    confidence=0.0,
                )
            )
            return chain.finalize()

        chain.verdict = verdict.get("verdict", "uncertain")
        chain.confidence = float(verdict.get("confidence", 0.5))
        chain.reasoning.append(
            ReasoningStep(
                step=len(chain.reasoning) + 1,
                action="LLM produced structured verdict",
                observation=verdict.get("summary", ""),
                conclusion=f"verdict={chain.verdict}, confidence={chain.confidence}",
            )
        )
        for action in verdict.get("actions", []):
            chain.recommended_actions.append(
                RecommendedAction(
                    action_type=action.get("type", "monitor"),
                    target=str(action.get("target", "unknown")),
                    reasoning=verdict.get("summary", ""),
                    requires_hitl=bool(action.get("hitl", False)),
                    confidence=float(action.get("confidence", chain.confidence)),
                )
            )

        return chain.finalize()


def _summarize_result(r: tools.ToolResult) -> str:
    if r.name == "decode_payload":
        return f"primitives_found={r.data.get('primitive_count', 0)}"
    if r.name == "ip_reputation":
        return f"ip_verdict={r.data.get('verdict')}, abuse_score={r.data.get('abuse_score')}"
    if r.name == "similar_past_requests":
        return f"similar_past_n={r.data.get('n', 0)}"
    if r.name == "user_baseline":
        return f"baseline_known={r.data.get('baseline') is not None}"
    if r.name == "ssrf_probe":
        return f"ssrf_targets={r.data.get('n', 0)}, schemes={r.data.get('dangerous_schemes', [])}"
    if r.name == "cors_reflection":
        return f"cors={r.data.get('reason', 'ok')}, allow_credentials={r.data.get('allow_credentials', False)}"
    if r.name == "mass_assignment":
        return f"extra_params={r.data.get('extra_params', r.data.get('sensitive_params_posted', []))}"
    if r.name == "host_header_anomaly":
        return f"host_anomaly={r.data.get('reasons', r.data.get('reason', 'ok'))}"
    if r.name == "header_injection":
        return f"header_injection={[h.get('header') for h in r.data.get('hits', [])]}, cookie={r.data.get('cookie_injection', False)}"
    if r.name == "scanner_signature":
        return f"scanner={r.data.get('scanner') or r.data.get('tool') or r.data.get('reason', 'none')}"
    if r.name == "recon_sweep":
        return f"distinct_paths={r.data.get('distinct_paths', 0)} in {r.data.get('window_sec', 0)}s"
    if r.name == "id_enumeration":
        return f"distinct_ids={r.data.get('distinct_ids', 0)} on {r.data.get('param', '-')}@{r.data.get('path', '-')}"
    if r.name == "secret_file_probe":
        return f"secret_path={r.data.get('signature', 'none')}, served={r.data.get('served', False)}"
    if r.name == "secret_exfil_probe":
        return f"secret_exfil={r.data.get('secret_kinds', [])}"
    return "tool_result"
