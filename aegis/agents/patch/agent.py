"""Patch Agent — finding → patch → staged deploy.

Pipeline (per the plan, target finding-to-prod ≤60min):
  1. Receive Finding from Vuln Discovery agent or external CVE feed.
  2. Generate a patch proposal (mock: lookup table; production: LLM
     synthesis with code-context + safety constraints).
  3. Run in dev environment (mock: simulated build + test).
  4. Stage to canary (mock: simulated traffic split + smoke test).
  5. Wait for HITL approval before prod.
  6. Roll to prod with ramped rollout.
  7. Watch for regression; auto-rollback on signal.

This walking-skeleton ships steps 1-2 + the gated workflow stub. Real
build/deploy integrations slot in at the marked seams.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Literal

from ..vuln_discovery.tools import Finding


PatchStage = Literal["proposed", "dev_built", "canary_deployed", "awaiting_hitl", "prod_deployed", "rolled_back"]


@dataclass
class PatchPlan:
    finding_id: str
    affected_component: str
    proposal: str
    estimated_risk: float  # 0-1; higher = more disruptive
    requires_hitl: bool = True
    stage: PatchStage = "proposed"
    started_at: float = 0.0
    history: list[tuple[float, PatchStage, str]] = None

    def __post_init__(self):
        if self.history is None:
            self.history = []
        if self.started_at == 0.0:
            self.started_at = time.time()


# Stand-in patch templates indexed by category. Production: LLM-generated
# diff with code-context + change-control approval.
_PATCH_TEMPLATES = {
    "dependency_cve": "Pin {component} to a non-vulnerable version; rebuild image; deploy via blue/green",
    "misconfig":      "Apply config diff: {component} per OPA policy; reload service",
    "logic_flaw":     "Apply code change to {component}: enforce ownership / authorization check",
    "supply_chain":   "Block {component} in internal mirror pending maintainer review; rebuild image",
}


class PatchAgent:
    name = "patch"

    def __init__(self):
        self._patches: dict[str, PatchPlan] = {}

    def propose(self, finding: Finding) -> PatchPlan:
        template = _PATCH_TEMPLATES.get(finding.category, "Manual remediation required for {component}")
        plan = PatchPlan(
            finding_id=finding.id,
            affected_component=finding.affected_component,
            proposal=template.format(component=finding.affected_component),
            estimated_risk=0.6 if finding.category in ("logic_flaw", "supply_chain") else 0.4,
        )
        plan.history.append((time.time(), "proposed", "Patch generated from template"))
        self._patches[finding.id] = plan
        return plan

    def build_in_dev(self, plan: PatchPlan) -> PatchPlan:
        # Mock: real impl runs build pipeline + unit tests in dev cluster
        plan.stage = "dev_built"
        plan.history.append((time.time(), "dev_built", "Dev build green; unit tests pass (mock)"))
        return plan

    def deploy_canary(self, plan: PatchPlan) -> PatchPlan:
        # Mock: real impl deploys to canary slice (1-5% traffic), watches metrics
        plan.stage = "canary_deployed"
        plan.history.append((time.time(), "canary_deployed", "Canary stable for window (mock)"))
        return plan

    def request_hitl(self, plan: PatchPlan) -> PatchPlan:
        plan.stage = "awaiting_hitl"
        plan.history.append((time.time(), "awaiting_hitl", "Pending human approval for prod rollout"))
        return plan

    def deploy_prod(self, plan: PatchPlan, approved_by: str) -> PatchPlan:
        plan.stage = "prod_deployed"
        plan.history.append((time.time(), "prod_deployed", f"Approved by {approved_by}; rolled to prod (mock)"))
        return plan

    def rollback(self, plan: PatchPlan, reason: str) -> PatchPlan:
        plan.stage = "rolled_back"
        plan.history.append((time.time(), "rolled_back", f"Auto-rollback: {reason}"))
        return plan

    def run_pipeline(self, finding: Finding, *, hitl_approver: str | None = None,
                     auto_approve: bool = False) -> PatchPlan:
        plan = self.propose(finding)
        plan = self.build_in_dev(plan)
        plan = self.deploy_canary(plan)
        plan = self.request_hitl(plan)
        if auto_approve:
            plan = self.deploy_prod(plan, approved_by=hitl_approver or "auto-approve-(test-mode)")
        return plan
