"""Auth/IAM specialist — account takeover and identity-abuse focus."""
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

logger = logging.getLogger("aegis.auth")


_SYSTEM_PROMPT_FILE = Path(__file__).parent / "system_prompt.md"


def _build_system_prompt() -> str:
    return SYSTEM_PROMPT_PREAMBLE + "\n\n" + _SYSTEM_PROMPT_FILE.read_text(encoding="utf-8")


def _summarize(r: tools.ToolResult) -> str:
    if r.name == "impossible_travel":
        if r.data.get("impossible"):
            return f"impossible_travel=TRUE distance={r.data.get('distance_km')}km in {r.data.get('minutes_since')}min"
        return f"travel_plausible distance={r.data.get('distance_km', 'n/a')}"
    if r.name == "device_fingerprint":
        return f"device_known={r.data.get('known')}"
    if r.name == "peer_baseline":
        return f"deviations={r.data.get('deviations', [])}"
    if r.name == "mfa_failure_pattern":
        return f"failures={r.data.get('failures')} burst={r.data.get('burst_pattern')}"
    if r.name == "behavioral_biometrics":
        return f"drift_score={r.data.get('drift_score', 'n/a')} severe={r.data.get('drift_severe')}"
    if r.name == "privileged_baseline":
        if r.data.get("is_privileged"):
            return (f"role={r.data.get('role')} "
                    f"red_flags={r.data.get('red_flags', [])} "
                    f"expected_admin_signals={r.data.get('expected_admin_signals', [])}")
        return f"role={r.data.get('role')} privileged=False"
    return "tool_result"


class AuthAgent:
    name = "auth"

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
                EvidenceItem(
                    source=r.name,
                    signal=_summarize(r),
                    weight=r.weight,
                    raw_data=r.data,
                )
            )
        chain.reasoning.append(
            ReasoningStep(
                step=1,
                action="Ran auth toolkit (impossible_travel, fingerprint, peer_baseline, mfa_pattern)",
                observation=f"{len(results)} tool results",
            )
        )

        # Causal-inference layer: distinguish correlation from causation.
        # Build observation dict from the toolkit results in the format the
        # ATO causal network expects, then ask the network for the posterior
        # P(phished | observations). This is what separates "user travelled
        # + bought new phone" (low P) from "attacker has phished creds" (high P).
        from ..shared.causal import infer_ato
        causal_obs: dict[str, str] = {}
        for r in results:
            if r.name == "impossible_travel" and r.data.get("impossible") is not None:
                causal_obs["impossible_travel"] = "yes" if r.data["impossible"] else "no"
            elif r.name == "device_fingerprint" and "known" in r.data:
                causal_obs["new_device"] = "no" if r.data["known"] else "yes"
            elif r.name == "mfa_failure_pattern":
                causal_obs["mfa_burst"] = "yes" if r.data.get("burst_pattern") else "no"
        if causal_obs:
            causal = infer_ato(causal_obs)
            chain.evidence.append(EvidenceItem(
                source="causal_inference",
                signal=(
                    f"P(phished_credentials)={causal['p_phished']:.2f}; "
                    f"most_likely_root_cause={causal['most_likely_root_cause'][0]} "
                    f"(P={causal['most_likely_root_cause'][1]:.2f})"
                ),
                weight="high" if causal["p_phished"] >= 0.7 else "medium" if causal["p_phished"] >= 0.4 else "low",
                raw_data=causal,
            ))
            chain.reasoning.append(ReasoningStep(
                step=len(chain.reasoning) + 1,
                action="Causal-inference posterior over root cause",
                observation=(
                    f"Bayesian inference on ATO causal network: "
                    f"P(phished|observations)={causal['p_phished']:.2f}, "
                    f"P(attacker_active|observations)={causal['p_attacker_active']:.2f}"
                ),
                conclusion=(
                    "Causal signal supports ATO hypothesis"
                    if causal['p_phished'] >= 0.7 else
                    "Causal signal weakly supports / refutes ATO; review with caution"
                ),
            ))

        wrapped_alert = wrap_untrusted("auth_alert", json.dumps(alert))
        wrapped_tools = wrap_untrusted(
            "tool_output",
            "\n".join(f"[{r.name}] weight={r.weight} data={json.dumps(r.data)}" for r in results),
        )
        if wrapped_alert.injection_detected or wrapped_tools.injection_detected:
            chain.evidence.append(
                EvidenceItem(
                    source="injection_defense",
                    signal="Prompt-injection patterns in auth payload (e.g. crafted user-agent)",
                    weight="high",
                    raw_data={"patterns": wrapped_alert.matched_patterns + wrapped_tools.matched_patterns},
                )
            )

        user_msg = (
            "Auth/IAM agent investigation.\n\n"
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
                    target=alert.get("id", "unknown"),
                    reasoning="Auth agent failed to produce valid verdict",
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
                action="LLM produced auth verdict",
                observation=verdict.get("summary", ""),
                conclusion=f"verdict={chain.verdict}, conf={chain.confidence}",
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
