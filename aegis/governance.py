"""ACP governance for the AEGIS SOC agents (Agent Q) — roadmap Phase 0.1.

Makes the SOC orchestrator, its specialists and the ResponseAgent a governed
ACP agent (default ``SOC-AGENTQ-01``, BU ``Security``): every investigation
and every response action passes ``ACPGuard.pre_tool_call`` /
``post_tool_call`` (loop guard, per-alert budget, autonomy tier, Q30 tool
allowlist, Q37 infrastructure guard, ...), the agent registers with the
dashboard, heartbeats, and honours the dashboard pause-gate — pausing
``SOC-AGENTQ-01`` in the dashboard stops the SOC brain within one heartbeat.

Scope — actions, not data
    The guard sees the agent's *actions* (which specialist runs on which
    alert id, which response action targets what). It does **not** see alert
    payloads: those are untrusted attacker-controlled content that AEGIS's
    own ``injection_defense`` wraps, and feeding them to Q29/Q37 would make
    ACP block the investigation of the very attacks the SOC exists to
    investigate.

Fail-safe, never fail-open
    * A control block (or the pause-gate) during an investigation returns
      an ``uncertain`` / ``escalate`` EvidenceChain carrying
      ``metadata["governance_block"]`` — the alert reaches a human, the
      block is in the ACP audit chain (allowed=False, sdk >= 0.8.1).
    * A blocked auto-safe response action is queued for HITL; a blocked
      approval is skipped. Nothing is silently executed or dropped.
    * SDK missing / govern() failing → ERROR log, orchestrator runs
      ungoverned (the dashboard shows the agent silent, which the rogue
      scanner flags).

Opt-in by environment (same contract as the loan app):

    ACP_GOVERN           "1" governs even without a dashboard (local/CI);
                         "0" never governs
    ACP_DASHBOARD_URL    setting it governs (unless ACP_GOVERN=0) and starts
                         the heartbeat reporter
    ACP_API_KEY          dashboard agent API key
    ACP_AGENT_CODE       default SOC-AGENTQ-01
    ACP_AGENT_NAME       default aegis-soc-orchestrator
    ACP_BU               default Security
    ACP_BUDGET           USD per alert, default 0.50
    ACP_TIER             default TIER_2
    ACP_RATE_LIMIT       governed calls per minute, default 3000 (Q33)

Requires acp-sdk >= 0.8.2 (``get_guard``, ``begin_task``).

Concurrency note: one guard per orchestrator; its per-task counters are
reset per alert by the ``handle`` wrapper, so run the governed orchestrator
synchronously (the eval harness) or one alert at a time. The async /
swarm path (roadmap Phase 2) gets one guard per worker through the SDK's
swarm API.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from functools import wraps
from typing import Any, Callable

from aegis.agents.shared.evidence_chain import (
    EvidenceChain,
    ReasoningStep,
    RecommendedAction,
)

logger = logging.getLogger("aegis.governance")

AGENT_CODE_DEFAULT = "SOC-AGENTQ-01"
AGENT_NAME_DEFAULT = "aegis-soc-orchestrator"
BU_DEFAULT = "Security"
PROCESS_NAME = "soc-triage"
PROCESS_TYPE = "internal"
BUDGET_DEFAULT = 0.50
RATE_LIMIT_DEFAULT = 3000   # governed calls per minute (ACP_RATE_LIMIT overrides)
TIER_DEFAULT = "TIER_2"

#: SOCOrchestrator attributes holding specialists (None when not registered).
SPECIALIST_ATTRS = (
    "_perimeter", "_auth", "_edr", "_api_abuse", "_transaction",
    "_cloud_controlplane", "_dlp", "_email", "_mobile", "_wireless",
)

TOOL_ORCHESTRATOR = "orchestrator.handle"
TOOL_DECEPTION = "deception.build_chain"
_WRAPPED_FLAG = "_acp_wrapped"


def governance_enabled() -> bool:
    flag = os.environ.get("ACP_GOVERN", "").strip().lower()
    if flag in {"0", "false", "no", "off"}:
        return False
    if flag in {"1", "true", "yes", "on"}:
        return True
    return bool(os.environ.get("ACP_DASHBOARD_URL", "").strip())


def governance_settings() -> dict[str, Any]:
    return {
        "name": os.environ.get("ACP_AGENT_NAME", AGENT_NAME_DEFAULT),
        "agent_code": os.environ.get("ACP_AGENT_CODE", AGENT_CODE_DEFAULT),
        "bu": os.environ.get("ACP_BU", BU_DEFAULT),
        "process_name": os.environ.get("ACP_PROCESS_NAME", PROCESS_NAME),
        "process_type": os.environ.get("ACP_PROCESS_TYPE", PROCESS_TYPE),
        "budget": float(os.environ.get("ACP_BUDGET", str(BUDGET_DEFAULT))),
        "tier": os.environ.get("ACP_TIER", TIER_DEFAULT),
        "framework": "generic",
    }


@dataclass
class GovernedSOC:
    """Handle returned by :func:`govern_soc`."""

    guard: Any
    agent_code: str
    tools: list[str] = field(default_factory=list)
    specialists: list[str] = field(default_factory=list)
    response_wrapped: bool = False

    @property
    def paused(self) -> bool:
        return bool(getattr(self.guard, "_paused", False))

    def begin_alert(self, alert_id: str | None = None) -> str:
        """Open a new ACP task — per-alert loop / budget counters."""
        return self.guard.begin_task(alert_id)


# ---------------------------------------------------------------- helpers --

def _alert_id(alert: Any) -> str:
    return str(alert.get("id", "unknown")) if isinstance(alert, dict) else "unknown"


def _alert_meta(alert: Any) -> dict[str, Any]:
    """What the guard may see about an alert: identifiers, never the payload."""
    if not isinstance(alert, dict):
        return {"alert_id": "unknown"}
    meta: dict[str, Any] = {"alert_id": _alert_id(alert)}
    for key in ("type", "source", "category", "severity", "tenant"):
        val = alert.get(key)
        if isinstance(val, (str, int, float)):
            meta[key] = str(val)[:64]
    return meta


def _violation_info(exc: Exception) -> dict[str, Any]:
    return {
        "control": getattr(exc, "control", type(exc).__name__),
        "code": getattr(exc, "code", ""),
        "severity": getattr(exc, "severity", ""),
        "message": str(exc)[:300],
    }


def blocked_chain(alert: Any, investigated_by: str, exc: Exception) -> EvidenceChain:
    """The EvidenceChain an ACP block turns into: escalate to a human."""
    info = _violation_info(exc)
    chain = EvidenceChain(
        alert_id=_alert_id(alert),
        investigated_by=investigated_by,
        verdict="uncertain",
        confidence=0.5,
    )
    chain.reasoning.append(ReasoningStep(
        step=1,
        action="acp_governance",
        observation=f"{info['control']} {info['code']}: {info['message']}",
        conclusion="ACP governance stopped the automated investigation; escalating for human review.",
    ))
    chain.recommended_actions.append(RecommendedAction(
        action_type="escalate",
        target=_alert_id(alert),
        reasoning=f"Blocked by ACP control {info['control']} ({info['code']}); a human must decide.",
        requires_hitl=True,
        confidence=0.5,
    ))
    chain.metadata["governance_block"] = info
    return chain.finalize()


def _violation_type():
    from acp import ACPViolation  # local import: the SDK is optional at import time
    return ACPViolation


def _guard_investigate(specialist: Any, guard: Any, tool: str) -> Callable:
    original = specialist.investigate
    acp_violation = _violation_type()

    @wraps(original)
    def investigate(alert, *args, **kwargs):
        try:
            guard.pre_tool_call(tool, _alert_meta(alert))
        except acp_violation as v:
            logger.warning("[acp] %s blocked on alert %s: %s", tool, _alert_id(alert), str(v)[:160])
            return blocked_chain(alert, f"acp:{tool}", v)
        try:
            chain = original(alert, *args, **kwargs)
        except Exception as e:  # noqa: BLE001 — record, then let the caller's safety net decide
            guard.post_tool_call(tool, success=False, error=str(e)[:200], exception=e)
            raise
        guard.post_tool_call(
            tool,
            result={"verdict": getattr(chain, "verdict", None),
                    "confidence": getattr(chain, "confidence", None)},
            success=True,
        )
        return chain

    investigate._acp_wrapped = True  # type: ignore[attr-defined]
    return investigate


def _guard_handle(orch: Any, governed: GovernedSOC) -> Callable:
    original = orch.handle
    guard = governed.guard
    acp_violation = _violation_type()

    @wraps(original)
    def handle(alert, *args, **kwargs):
        governed.begin_alert(_alert_id(alert))
        try:
            guard.pre_tool_call(TOOL_ORCHESTRATOR, _alert_meta(alert))
        except acp_violation as v:
            logger.warning("[acp] orchestrator blocked on alert %s: %s", _alert_id(alert), str(v)[:160])
            return blocked_chain(alert, "acp:orchestrator", v)
        try:
            chain = original(alert, *args, **kwargs)
        except Exception as e:  # noqa: BLE001
            guard.post_tool_call(TOOL_ORCHESTRATOR, success=False, error=str(e)[:200], exception=e)
            raise
        guard.post_tool_call(
            TOOL_ORCHESTRATOR,
            result={"verdict": getattr(chain, "verdict", None)},
            success=True,
        )
        return chain

    handle._acp_wrapped = True  # type: ignore[attr-defined]
    return handle


def _guard_response(response: Any, guard: Any) -> None:
    """Guard the two places a response action actually executes."""
    from aegis.agents.response.agent import ExecutedAction

    acp_violation = _violation_type()
    orig_auto = response._execute_auto
    orig_approve = response.approve

    def _args(action: Any) -> dict[str, Any]:
        return {"action_type": str(getattr(action, "action_type", "")),
                "target": str(getattr(action, "target", ""))[:256]}

    @wraps(orig_auto)
    def _execute_auto(action, *a, **kw):
        tool = f"response.{getattr(action, 'action_type', 'unknown')}"
        try:
            guard.pre_tool_call(tool, _args(action))
        except acp_violation as v:
            return ExecutedAction(action=action, status="queued_for_hitl",
                                  note=f"[ACP blocked] {str(v)[:200]}")
        try:
            executed = orig_auto(action, *a, **kw)
        except Exception as e:  # noqa: BLE001
            guard.post_tool_call(tool, success=False, error=str(e)[:200], exception=e)
            raise
        guard.post_tool_call(tool, result={"status": getattr(executed, "status", "")}, success=True)
        return executed

    @wraps(orig_approve)
    def approve(action, approver, *a, **kw):
        tool = f"response.{getattr(action, 'action_type', 'unknown')}"
        try:
            guard.pre_tool_call(tool, {**_args(action), "approver": str(approver)[:64]}, user_role="approver")
        except acp_violation as v:
            return ExecutedAction(action=action, status="skipped",
                                  note=f"[ACP blocked] approved action not executed: {str(v)[:200]}")
        try:
            executed = orig_approve(action, approver, *a, **kw)
        except Exception as e:  # noqa: BLE001
            guard.post_tool_call(tool, success=False, error=str(e)[:200], exception=e)
            raise
        guard.post_tool_call(tool, result={"status": getattr(executed, "status", "")}, success=True)
        return executed

    response._execute_auto = _execute_auto
    response.approve = approve
    response._acp_wrapped = True


def _response_tools() -> list[str]:
    from aegis.agents.response.agent import _ALWAYS_HITL_ACTIONS, _AUTO_SAFE_ACTIONS
    return sorted(f"response.{a}" for a in (_AUTO_SAFE_ACTIONS | _ALWAYS_HITL_ACTIONS | {"escalate"}))


def _swarm_tools() -> list[str]:
    try:
        from aegis.agents.orchestrator.swarm import DEFAULT_WORKERS
    except Exception as exc:  # noqa: BLE001
        logger.warning("[acp] swarm workers not importable (%s); they will be absent from the Q30 allowlist", exc)
        return []
    return [f"swarm.{name}" for name in DEFAULT_WORKERS]


def _walker_tools() -> list[str]:
    try:
        from aegis.agents.orchestrator.walkers.walk import DEFAULT_WALKERS
    except Exception as exc:  # noqa: BLE001
        logger.warning("[acp] walkers not importable (%s); they will be absent from the Q30 allowlist", exc)
        return []
    return [f"walker.{name}" for name in DEFAULT_WALKERS] + ["twin.simulate"]


def tool_allowlist(orch: Any, response: Any | None = None) -> list[str]:
    """Every governed call site, by name — Q30 closes the matrix to exactly these."""
    tools = [TOOL_ORCHESTRATOR, TOOL_DECEPTION] + _swarm_tools() + _walker_tools()
    for attr in SPECIALIST_ATTRS:
        spec = getattr(orch, attr, None)
        if spec is not None and hasattr(spec, "investigate"):
            tools.append(f"specialist.{getattr(spec, 'name', attr.lstrip('_'))}.investigate")
    if response is not None:
        tools.extend(_response_tools())
    return tools


# ---------------------------------------------------------------- entry --

def govern_soc(orch: Any, response: Any | None = None) -> GovernedSOC | None:
    """Govern a SOCOrchestrator (and optionally its ResponseAgent) with ACP.

    Returns the :class:`GovernedSOC` handle, or ``None`` when governance is
    disabled or unavailable — the objects are then left untouched.
    """
    if not governance_enabled():
        return None
    if getattr(orch, _WRAPPED_FLAG, False):
        logger.debug("[acp] orchestrator already governed")
        return getattr(orch, "_acp_governed", None)
    try:
        from acp import get_guard, govern
    except ImportError as e:
        logger.error("ACP governance requested but acp-sdk is not installed (%s); SOC runs UNGOVERNED", e)  # noqa: TRY400 — ImportError needs no traceback
        return None

    settings = governance_settings()
    allowlist = tool_allowlist(orch, response)
    # Q33: a SOC brain makes ~2 governed calls per alert, ~9 with the swarm;
    # the SDK default (100/min) would block it after a dozen alerts.
    rate_limit = int(os.environ.get("ACP_RATE_LIMIT", str(RATE_LIMIT_DEFAULT)))
    try:
        governed_obj = govern(
            orch,
            governance_config={
                "tool_permissions": {"allowlist": allowlist},
                "rate_limiter": {"global_limit": rate_limit, "window_seconds": 60},
            },
            **settings,
        )
        guard = get_guard(governed_obj)
    except Exception as e:  # noqa: BLE001 — never take the SOC down over governance wiring
        logger.error("acp.govern() failed for %s (%s); SOC runs UNGOVERNED", settings["agent_code"], e, exc_info=True)
        return None
    if guard is None or not hasattr(guard, "begin_task"):
        logger.error("acp-sdk >= 0.8.2 required (get_guard / begin_task missing); SOC runs UNGOVERNED")
        return None

    governed = GovernedSOC(guard=guard, agent_code=settings["agent_code"], tools=allowlist)

    for attr in SPECIALIST_ATTRS:
        spec = getattr(orch, attr, None)
        if spec is None or not hasattr(spec, "investigate"):
            continue
        if getattr(spec.investigate, _WRAPPED_FLAG, False):
            continue
        name = getattr(spec, "name", attr.lstrip("_"))
        spec.investigate = _guard_investigate(spec, guard, f"specialist.{name}.investigate")
        governed.specialists.append(name)

    honeytoken = getattr(orch, "_honeytoken", None)
    if honeytoken is not None and hasattr(honeytoken, "build_chain") \
            and not getattr(honeytoken.build_chain, _WRAPPED_FLAG, False):
        _orig_build = honeytoken.build_chain
        acp_violation = _violation_type()

        @wraps(_orig_build)
        def build_chain(alert, *a, **kw):
            try:
                guard.pre_tool_call(TOOL_DECEPTION, _alert_meta(alert))
            except acp_violation as v:
                return blocked_chain(alert, "acp:deception", v)
            chain = _orig_build(alert, *a, **kw)
            guard.post_tool_call(TOOL_DECEPTION, result={"verdict": getattr(chain, "verdict", None)}, success=True)
            return chain

        build_chain._acp_wrapped = True  # type: ignore[attr-defined]
        honeytoken.build_chain = build_chain

    orch.handle = _guard_handle(orch, governed)
    setattr(orch, _WRAPPED_FLAG, True)
    orch._acp_governed = governed

    if response is not None and not getattr(response, _WRAPPED_FLAG, False):
        _guard_response(response, guard)
        governed.response_wrapped = True

    logger.info(
        "ACP governance active: %s (%s, bu=%s, tier=%s, budget=$%.2f/alert) — %d specialists, response=%s -> %s",
        settings["agent_code"], settings["name"], settings["bu"], settings["tier"], settings["budget"],
        len(governed.specialists), governed.response_wrapped,
        os.environ.get("ACP_DASHBOARD_URL", "") or "no dashboard (local guard only)",
    )
    return governed
