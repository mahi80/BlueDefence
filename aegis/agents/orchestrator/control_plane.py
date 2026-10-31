"""Control-plane facts as a deterministic fast path (the Q ↔ AEGIS bridge, SOC side).

An event from ``aegis.ingest.acp`` says what the ACP control plane *did*: Q37 blocked a call
the agent made to the metadata endpoint, the pause-gate stopped the agent, a rogue detector
fired at CRITICAL. Those are facts, not signals to weigh — like a honeytoken touch. So they
do not go to the LLM for a verdict; they get a chain built from the control evidence, and the
swarm / async tier then do what they do for any confirmed alert: enrich, walk the blast
radius, plan containment, put it on the HITL card. Lower-severity rogue events (budget
runaway, control spikes) still go through normal triage.
"""

from __future__ import annotations

from typing import Optional

from ..shared.evidence_chain import EvidenceChain, EvidenceItem, ReasoningStep, RecommendedAction

CONFIRMED_BLOCK_CODES = {"ACP-737"}                       # Q37 infrastructure guard: the agent tried to attack infrastructure
CONFIRMED_ISSUES = {"infra_attack", "audit_chain_break", "undeclared_subagent"}


def is_control_plane_fact(alert: dict) -> bool:
    if not alert.get("governed_agent"):
        return False
    kind = str(alert.get("alert_type") or "")
    if kind == "governance_block" or kind == "agent_paused":
        return True
    return kind == "rogue_alert" and (str(alert.get("severity", "")).lower() == "critical" or alert.get("issue_type") in CONFIRMED_ISSUES)


def control_plane_chain(alert: dict) -> EvidenceChain:
    kind = str(alert.get("alert_type") or "")
    agent = str(alert.get("agent_id") or "unknown-agent")
    code = str(alert.get("control_code") or "")
    issue = str(alert.get("issue_type") or "")
    confirmed = (kind == "governance_block" and code in CONFIRMED_BLOCK_CODES) or issue == "infra_attack" \
        or (kind == "agent_paused" and "infra" in str(alert.get("reason", "")).lower())
    verdict = "malicious" if confirmed else "suspicious"
    chain = EvidenceChain(alert_id=str(alert.get("id", "unknown")), investigated_by="control_plane", verdict=verdict,
                          confidence=0.97 if confirmed else 0.75)
    if kind == "governance_block":
        signal = f"ACP control {code or '?'} ({alert.get('control', 'governance')}) blocked {alert.get('tool_name', 'a tool call')} by governed agent {agent}: {str(alert.get('reason', ''))[:200]}"
    elif kind == "agent_paused":
        signal = f"Control plane paused governed agent {agent} ({alert.get('paused_by', '?')}): {str(alert.get('reason', ''))[:200]}"
    else:
        signal = f"Rogue detector '{issue}' at {str(alert.get('severity', '')).upper()} on governed agent {agent}: {str(alert.get('title', ''))[:160]}"
    chain.evidence.append(EvidenceItem(source="acp_control_plane", signal=signal, weight="high",
                                       raw_data={k: alert.get(k) for k in ("agent_id", "agent_framework", "bu", "control_code", "issue_type", "tool_name",
                                                                           "destination", "dest_ip", "url", "paused_by", "timestamp") if alert.get(k) is not None}))
    if alert.get("destination") or alert.get("dest_ip") or alert.get("url"):
        chain.evidence.append(EvidenceItem(source="acp_control_plane", weight="medium",
                                           signal=f"Target of the blocked / detected activity: {alert.get('destination') or alert.get('dest_ip') or alert.get('url')}"))
    if alert.get("agent_paused"):
        chain.evidence.append(EvidenceItem(source="acp_control_plane", weight="medium", signal=f"Agent {agent} is currently paused (heartbeat 423) — it cannot act further"))
    chain.reasoning.append(ReasoningStep(step=1, action="Control-plane fact (no LLM verdict)",
                                         observation=("Confirmed: the control plane enforced on an attack-shaped action" if confirmed
                                                      else "Governed-agent anomaly reported by the control plane; investigate before judging")))
    chain.reasoning.append(ReasoningStep(step=2, action="Hand to swarm + async tier",
                                         observation="Blast radius: what did the agent touch before it was stopped; campaign: external traffic from its host"))
    chain.recommended_actions.append(RecommendedAction(action_type="escalate", target=agent, requires_hitl=True, confidence=chain.confidence,
                                                       reasoning="Governed agent incident — a human decides whether to unpause, rotate its credentials, or roll back its last actions"))
    if confirmed and not alert.get("agent_paused"):
        chain.recommended_actions.append(RecommendedAction(action_type="isolate", target=agent, requires_hitl=True, confidence=chain.confidence,
                                                           reasoning="Agent attacked infrastructure and is not paused — pause it at the control plane"))
    if confirmed:
        chain.recommended_actions.append(RecommendedAction(action_type="rotate_credential", target=agent, requires_hitl=True, confidence=0.8,
                                                           reasoning="An agent that reached for cloud metadata may hold or have leaked credentials"))
    chain.metadata["control_plane"] = {"kind": kind, "control_code": code, "issue_type": issue, "confirmed": confirmed,
                                       "agent_framework": alert.get("agent_framework"), "bu": alert.get("bu")}
    return chain.finalize()


__all__ = ["control_plane_chain", "is_control_plane_fact"]
