"""Response Agent — the actuator + HITL gate.

Receives an EvidenceChain with recommended_actions and either:
  - executes auto-applicable actions through bounded action APIs, or
  - queues HITL-gated actions for human approval (printed in this
    walking skeleton; production: Slack/ServiceNow approval card).

High-impact actions (isolate host, lock executive account, trigger self-heal,
wide or internal blocks) ALWAYS require HITL even if confidence is high. The one
exception is tiered autonomy (``autonomy.py``): a short, self-expiring block on a
narrow external target with strong, undisputed evidence runs at machine speed.
A multi-agent vote (already done at orchestrator/specialist level) and
the HITL gate are independent layers.
"""
from __future__ import annotations

import sys
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

import ipaddress
import os

from ..shared.evidence_chain import EvidenceChain, RecommendedAction
from ..shared.netguard import enforcement_refused
from .autonomy import AutonomyPolicy
from .breaker import OutflowBreaker
from .hitl_timeout import HitlTimeoutPolicy
from .connectors import ConnectorRegistry, Receipt, STATUS_REFUSED, registry_from_env


_AUTO_SAFE_ACTIONS = {
    "allow", "monitor", "challenge", "throttle", "notify_user",
    "redact",                # DLP: deterministic redaction is safe
    "force_logout",          # Mobile: forcing re-auth is recoverable
    "quarantine_message",    # Email: standard ESG behavior, recoverable
}

# How long a human-approved action stays in force. The connector default (1 h) is for automated actions;
# a person who approved isolating a host or cutting a C2 did not approve it lapsing an hour later. Containment
# is permanent until a person releases it (at the vendor, which is where the release is audited); edge
# actions on IPs (block / throttle / challenge) get a day by default so WAF rule sets do not grow forever.
# The HITL-timeout path ("aegis:hitl-timeout") is not a person and keeps the connector default.
_EDGE_ACTIONS = {"block", "throttle", "challenge"}


def approved_ttl_sec(action_type: str, approver: str) -> int | None:
    """TTL for an approved action: None = the connector default, 0 = until a person releases it."""
    if not approver or approver.startswith("aegis:"):
        return None
    if action_type in _EDGE_ACTIONS:
        return int(os.environ.get("AEGIS_APPROVED_BLOCK_TTL_SEC", "86400"))
    return int(os.environ.get("AEGIS_APPROVED_TTL_SEC", "0"))


_ALWAYS_HITL_ACTIONS = {
    "block", "isolate", "lock_account", "revoke_sessions",
    "trigger_self_heal", "kill_process", "quarantine_file",
    "escalate_to_fraud_team", "hold",
    "block_export",          # DLP: irreversible-ish, queue for HITL
    "block_egress",          # NDR: an egress proxy / firewall change belongs to that team
    "recall_message",        # Email: visible to recipients, queue
    "rotate_credential",
    "escalate_to_hr",        # DLP/insider: HR + legal involvement
    "snapshot_forensic",     # Self-healing forensic snapshot — auditable
    "config_rollback",       # Network: a config push to a device — the network team approves, shadow first
    "interface_shutdown",    # Network: shutting a port takes users off the air; a human confirms
}


@dataclass
class ExecutedAction:
    action: RecommendedAction
    status: str   # "executed" | "queued_for_hitl" | "skipped"
    note: str = ""
    receipt: Optional[Receipt] = None   # Phase 1.1 — the connector's receipt when one was produced
    # why it did not run, for the HITL settle logic: never_block | rate_cap | needs_second_approver |
    # connector_failed | governance | "" (ran, or not classified)
    reason: str = ""


@dataclass
class ResponseSummary:
    alert_id: str
    executed: list[ExecutedAction] = field(default_factory=list)
    hitl_queue: list[ExecutedAction] = field(default_factory=list)

    @property
    def receipts(self) -> list[Receipt]:
        return [a.receipt for a in self.executed if a.receipt is not None]


# Phase 1.1 — actions that need a second human when they hit a protected target.
_TWO_PERSON_ACTIONS = {"block", "isolate", "kill_process", "rotate_credential"}


def _protected_targets_from_env() -> list[str]:
    raw = os.environ.get("AEGIS_PROTECTED_TARGETS", "")
    return [t.strip() for t in raw.split(",") if t.strip()]


def _target_matches(target: str, patterns: list[str]) -> bool:
    """CIDR match for IP targets, case-insensitive glob (``prod-*``) otherwise."""
    import fnmatch
    t = str(target).strip()
    ip = None
    try:
        ip = ipaddress.ip_address(t)
    except ValueError:
        pass
    for pat in patterns:
        if ip is not None and "/" in pat:
            try:
                if ip in ipaddress.ip_network(pat, strict=False):
                    return True
                continue
            except ValueError:
                pass
        if fnmatch.fnmatch(t.lower(), pat.lower()):
            return True
    return False


class ResponseAgent:
    name = "response"

    def __init__(self, *, mtd=None, self_healing=None, hitl_stream=sys.stdout, hitl=None,
                 connectors: Optional[ConnectorRegistry] = None,
                 protected_targets: Optional[list[str]] = None,
                 two_person_actions: Optional[set[str]] = None,
                 autonomy: Optional[AutonomyPolicy] = None,
                 hitl_timeout: Optional[HitlTimeoutPolicy] = None,
                 breaker: Optional[OutflowBreaker] = None):
        self._mtd = mtd
        self._self_healing = self_healing
        self._hitl_stream = hitl_stream
        # Phase 1.1 — enforcement goes through connectors (vendor APIs in
        # 1.2/1.3; today the logging fallback). Shadow mode is the default:
        # AEGIS_ENFORCEMENT_MODE=live flips vendor connectors to real calls.
        self._connectors = connectors if connectors is not None else registry_from_env()
        # Two-person rule: block/isolate/... on a protected target needs a
        # second approver. AEGIS_PROTECTED_TARGETS="10.0.0.0/8,prod-*".
        self._protected_targets = protected_targets if protected_targets is not None else _protected_targets_from_env()
        self._two_person_actions = two_person_actions if two_person_actions is not None else set(_TWO_PERSON_ACTIONS)
        # Phase 0.2 — optional HITL transport (aegis.hitl.DashboardHITL): the
        # card is filed as an ACP dashboard approval and the decision comes
        # back through sync_hitl(). None → the stdout card, as before.
        self._hitl = hitl
        # Tiered autonomy: short self-expiring blocks on narrow external targets run without
        # waiting for a human when the evidence is strong (autonomy.py). AEGIS_AUTO_BLOCK=0 → off.
        self._autonomy = autonomy if autonomy is not None else AutonomyPolicy.from_env()
        # Outflow circuit breaker: during a drain burst a hold on the sender's further payments runs
        # without waiting (breaker.py). Every other hold still waits. AEGIS_OUTFLOW_BREAKER, shadow by default.
        self._breaker = breaker if breaker is not None else OutflowBreaker.from_env()
        # Timeout fallback for pending HITL approvals (hitl_timeout.py). With few analysts,
        # a reversible action nobody has decided on auto-executes once past its wait window;
        # irreversible actions and split votes hold for a human. AEGIS_HITL_TIMEOUT=off → off.
        self._hitl_timeout = hitl_timeout if hitl_timeout is not None else HitlTimeoutPolicy.from_env()
        self._env_policies = (autonomy is None, breaker is None, hitl_timeout is None)
        # Rolling-window rate limit for high-impact actions; bounds blast radius if the agent is itself
        # compromised. It used to be a counter nothing ever reset — a lifetime cap of 10 approvals that
        # then silently skipped every later one. AEGIS_HIGH_IMPACT_MAX per AEGIS_HIGH_IMPACT_WINDOW_SEC.
        self._high_impact_max = int(os.environ.get("AEGIS_HIGH_IMPACT_MAX", "10"))
        self._high_impact_window = float(os.environ.get("AEGIS_HIGH_IMPACT_WINDOW_SEC", "60"))
        self._high_impact_times: deque[float] = deque()

    @property
    def _high_impact_counter(self) -> int:
        """High-impact actions executed inside the current window (old entries drop out)."""
        cutoff = time.monotonic() - self._high_impact_window
        while self._high_impact_times and self._high_impact_times[0] < cutoff:
            self._high_impact_times.popleft()
        return len(self._high_impact_times)

    def execute(self, chain: EvidenceChain) -> ResponseSummary:
        from ..shared import observability as obs

        with obs.span("aegis.response.execute",
                      alert_id=chain.alert_id,
                      actions_count=len(chain.recommended_actions)):
            summary = ResponseSummary(alert_id=chain.alert_id)
            for action in chain.recommended_actions:
                obs.record_action_proposed(action.action_type, action.requires_hitl)
                decision = self._dispatch(action, chain)
                if decision.status == "executed":
                    summary.executed.append(decision)
                    obs.record_action_executed()
                elif decision.status == "queued_for_hitl":
                    summary.hitl_queue.append(decision)
                    obs.record_action_hitl_queued()
                    self._file_hitl(action, chain, decision)
        return summary

    def _file_hitl(self, action: RecommendedAction, chain: EvidenceChain,
                   decision: ExecutedAction) -> None:
        """Dashboard approval when a transport is configured and reachable,
        else the stdout card. Never raises — HITL routing must not lose the
        decision record already in ``summary.hitl_queue``."""
        approval_id = None
        if self._hitl is not None:
            try:
                approval_id = self._hitl.request(action, chain)
            except Exception as e:  # noqa: BLE001
                approval_id = None
                print(f"[HITL] dashboard transport failed ({type(e).__name__}); using stdout card",
                      file=self._hitl_stream)
        if approval_id:
            decision.note = f"{decision.note} | dashboard approval {approval_id}"
            return
        self._print_hitl_card(action, chain)

    def refresh_policies(self) -> None:
        """Rebuild the env-derived autonomy / breaker / HITL-timeout policies after the environment changed
        (licence drop to over-limit or evaluation forces them to shadow). Explicitly injected policies are kept."""
        a, b, h = self._env_policies
        if a:
            self._autonomy = AutonomyPolicy.from_env()
        if b:
            self._breaker = OutflowBreaker.from_env()
        if h:
            self._hitl_timeout = HitlTimeoutPolicy.from_env()

    def sync_hitl(self, **kwargs) -> list:
        """Pull decisions from the dashboard: approved actions run through
        ``approve()``, rejections are recorded. Returns the decisions made."""
        if self._hitl is None:
            return []
        kwargs.setdefault("timeout_policy", self._hitl_timeout)
        return self._hitl.sync(self, **kwargs)

    # ---- decision logic ------------------------------------------------

    def _dispatch(self, action: RecommendedAction, chain: EvidenceChain) -> ExecutedAction:
        # Tiered autonomy first: a narrow, external, short-TTL block on strong evidence
        # does not wait for a human (everything else below is unchanged).
        if action.action_type == "block":
            ok, why = self._autonomy.check(action, chain, protected=self._is_protected)
            if ok and self._autonomy.mode == "shadow":
                # record what auto-block would have done; the block itself still goes to a human
                self._connectors.preview(action, alert_id=chain.alert_id, approver="aegis:auto-shadow",
                                         ttl_sec=self._autonomy.ttl_sec, note="auto-block shadow")
            elif ok:
                receipt = self._apply_unattended(action, alert_id=chain.alert_id, approver="aegis:auto",
                                                 ttl_sec=self._autonomy.ttl_sec)
                if receipt is None:
                    return ExecutedAction(action=action, status="queued_for_hitl",
                                          note="auto-block refused by governance; routed to a human")
                if receipt.active:
                    self._autonomy.take()
                done = self._from_receipt(action, receipt, prefix="auto-block")
                done.note = f"{done.note} ({why})"
                return done
        # Outflow circuit breaker: a drain in progress does not wait for an analyst to open a card.
        if action.action_type == "hold":
            ok, why = self._breaker.check(action, chain)
            if ok and self._breaker.mode == "shadow":
                self._connectors.preview(action, alert_id=chain.alert_id, approver="aegis:breaker-shadow",
                                         ttl_sec=self._breaker.ttl_sec, note="outflow breaker shadow")
            elif ok:
                receipt = self._apply_unattended(action, alert_id=chain.alert_id, approver="aegis:breaker",
                                                 ttl_sec=self._breaker.ttl_sec)
                if receipt is not None and receipt.active:
                    self._breaker.take()
                    done = self._from_receipt(action, receipt, prefix="outflow-breaker")
                    done.note = f"{done.note} ({why})"
                    return done
        # Always-HITL list takes precedence
        if action.action_type in _ALWAYS_HITL_ACTIONS:
            return ExecutedAction(action=action, status="queued_for_hitl",
                                  note=f"Action {action.action_type} requires HITL by policy")

        if action.requires_hitl:
            return ExecutedAction(action=action, status="queued_for_hitl",
                                  note="Action explicitly flagged HITL by upstream agent")

        if action.action_type in _AUTO_SAFE_ACTIONS:
            return self._execute_auto(action, alert_id=chain.alert_id)

        # Unknown action class → safe-by-default
        return ExecutedAction(action=action, status="queued_for_hitl",
                              note=f"Unknown action class {action.action_type}; routing to HITL")

    def _apply_unattended(self, action: RecommendedAction, *, alert_id: str, approver: str,
                          ttl_sec: int) -> Receipt | None:
        """The live auto-block / outflow-breaker apply — no human in the loop, so it is one of the
        places ACP governance guards (``governance._guard_response``). ``None`` = refused upstream."""
        return self._connectors.apply(action, alert_id=alert_id, approver=approver, ttl_sec=ttl_sec)

    def _execute_auto(self, action: RecommendedAction, *, alert_id: str = "") -> ExecutedAction:
        """Auto-safe actions run through the connector registry (Phase 1.1).
        A failed or unsupported receipt is parked for a human, never
        reported as done."""
        receipt = self._connectors.apply(action, alert_id=alert_id)
        return self._from_receipt(action, receipt, prefix="auto")

    @staticmethod
    def _from_receipt(action: RecommendedAction, receipt: Receipt, *, prefix: str) -> ExecutedAction:
        if receipt.status == STATUS_REFUSED:
            # never-block guard refused it — terminal, do not re-queue for a human
            return ExecutedAction(
                action=action, status="skipped", receipt=receipt, reason="never_block",
                note=f"[{prefix}:never-block] {receipt.error or 'refused: own/infra target'}",
            )
        if receipt.active:
            return ExecutedAction(
                action=action, status="executed", receipt=receipt,
                note=f"[{prefix}:{receipt.connector}:{receipt.status}] {receipt.detail or action.action_type}",
            )
        return ExecutedAction(
            action=action, status="queued_for_hitl", receipt=receipt, reason="connector_failed",
            note=f"[{prefix}:{receipt.connector}:{receipt.status}] {receipt.error or receipt.detail}; human needed",
        )

    def _is_protected(self, target: str) -> bool:
        return bool(self._protected_targets) and _target_matches(target, self._protected_targets)

    def two_person_required(self, action: RecommendedAction) -> bool:
        return (action.action_type in self._two_person_actions
                and bool(self._protected_targets)
                and _target_matches(action.target, self._protected_targets))

    def sweep_expired(self) -> list[Receipt]:
        """Roll back TTL-expired enforcement (call from the scheduler loop)."""
        return self._connectors.sweep_expired()

    @property
    def connectors(self) -> ConnectorRegistry:
        return self._connectors

    # ---- HITL card -----------------------------------------------------

    def _print_hitl_card(self, action: RecommendedAction, chain: EvidenceChain) -> None:
        print(
            f"\n[HITL APPROVAL REQUEST]  alert={chain.alert_id}\n"
            f"  Action:     {action.action_type} -> {action.target}\n"
            f"  Confidence: {action.confidence:.2f}  Verdict: {chain.verdict}  Conf: {chain.confidence:.2f}\n"
            f"  Reason:     {action.reasoning}\n"
            f"  Evidence:   {len(chain.evidence)} items, {len(chain.specialist_invocations)} specialists\n"
            f"  --> approve via: pomerium/servicenow/aegis-respond ({chain.alert_id})\n",
            file=self._hitl_stream,
        )

    # ---- approval path (when human approves through ticket) ----------

    def approve(self, action: RecommendedAction, approver: str,
                source_alert_id: Optional[str] = None,
                second_approver: Optional[str] = None) -> ExecutedAction:
        # Never-block guard, ahead of everything (incl. the self-heal/isolate branch that
        # bypasses the connector registry): a human approval can't block loopback/own infra.
        refuse, why = enforcement_refused(action.action_type, str(action.target))
        if refuse:
            return ExecutedAction(action=action, status="skipped", reason="never_block",
                                  note=f"never-block guard refused {action.action_type} on {action.target}: {why}")
        if self._high_impact_counter >= self._high_impact_max:
            return ExecutedAction(
                action=action, status="skipped", reason="rate_cap",
                note=f"Rate-limit reached ({self._high_impact_max} high-impact actions in window); "
                     "blast-radius cap activated",
            )
        # Phase 1.1 — two-person rule on protected targets
        if self.two_person_required(action):
            if not second_approver or second_approver == approver:
                return ExecutedAction(
                    action=action, status="queued_for_hitl", reason="needs_second_approver",
                    note=f"{action.action_type} on protected target {action.target} needs a second "
                         f"approver (first: {approver})",
                )
        self._high_impact_times.append(time.monotonic())
        # Route to the right back-end
        if action.action_type == "trigger_self_heal" and self._self_healing:
            self._self_healing.handle_compromise(action.target, source_alert=source_alert_id)
            return ExecutedAction(action=action, status="executed",
                                  note=f"Self-heal triggered (approved by {approver})")
        # isolate goes to the EDR when one is configured; the self-healing pipeline (workload snapshot +
        # sever) only takes it when no connector can. Before, an approved isolate always went to the
        # pipeline and was reported "Host isolated" while the EDR was never called.
        if action.action_type == "isolate" and self._self_healing and self._connectors.route_action(action) is self._connectors.fallback:
            # Treat isolate as a precursor to heal: snapshot+sever, hold respawn for human
            self._self_healing.snapshot_and_sever(action.target, source_alert=source_alert_id)
            return ExecutedAction(action=action, status="executed",
                                  note=f"Host isolated (approved by {approver})")
        # Everything else: the connector registry (vendor APIs in 1.2/1.3;
        # the logging fallback until then). The receipt carries the approver.
        approved_by = approver if not second_approver else f"{approver}+{second_approver}"
        receipt = self._connectors.apply(action, alert_id=source_alert_id or "", approver=approved_by,
                                         ttl_sec=approved_ttl_sec(action.action_type, approver))
        executed = self._from_receipt(action, receipt, prefix="approved")
        executed.note = f"{executed.note} approved by {approved_by}"
        return executed
