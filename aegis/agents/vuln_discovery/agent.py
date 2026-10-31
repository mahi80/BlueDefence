"""Vulnerability Discovery agent — Glasswing-style internal red team.

Runs continuous scans on dependency manifests, configs, code paths, and
supply-chain events. Produces VulnFinding objects to be picked up by the
Patch agent.

This walking-skeleton version is read-only / static analysis. Production
extension would add sandboxed fuzzing, dynamic probing, and integration
with smolagents CodeAgent for novel exploit synthesis (gated behind
additional approvals + heavy sandbox per the project plan).
"""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ..shared.evidence_chain import (
    EvidenceChain,
    EvidenceItem,
    ReasoningStep,
    RecommendedAction,
)
from ..shared.injection_defense import SYSTEM_PROMPT_PREAMBLE, wrap_untrusted
from ..shared.llm_client import LLMClient, parse_json
from . import tools


_SYSTEM_PROMPT_FILE = Path(__file__).parent / "system_prompt.md"


def _build_system_prompt() -> str:
    return SYSTEM_PROMPT_PREAMBLE + "\n\n" + _SYSTEM_PROMPT_FILE.read_text(encoding="utf-8")


class VulnDiscoveryAgent:
    name = "vuln_discovery"

    def __init__(self, llm: LLMClient, cve_intel: Any = None):
        self._llm = llm
        self._system = _build_system_prompt()
        self.cve_intel = cve_intel          # threat_intel.cve_feeds.CveIntel — live KEV/NVD/EPSS for dependency_scan

    def scan(self, scope: dict) -> tuple[EvidenceChain, list[tools.Finding]]:
        """scope = {
            'dependency_manifest': {pkg: ver, ...},
            'configs': [{...}, ...],
            'code_paths': [{path, snippet, context}, ...],
            'supply_chain_events': [{...}, ...],
            'deployables': [{stack, build_files, routes, settings, ...}, ...],   # see client_exposure.py
        }
        """
        findings: list[tools.Finding] = []
        findings.extend(tools.dependency_scan(scope.get("dependency_manifest", {}), intel=self.cve_intel))
        for cfg in scope.get("configs", []):
            findings.extend(tools.config_scan(cfg))
        findings.extend(tools.code_scan(scope.get("code_paths", [])))
        findings.extend(tools.supply_chain_anomaly(scope.get("supply_chain_events", [])))
        findings.extend(tools.cicd_drift_check(
            scope.get("cicd_workflows", []),
            scope.get("cicd_runners", []),
        ))
        # 2.8c: client-exposure checklist per deployable (what an attacker's agent harvests first)
        from .client_exposure import client_exposure_scan
        for dep in scope.get("deployables", []):
            findings.extend(client_exposure_scan(dep))
        # Sort by risk_score desc so top-priority findings lead the evidence chain
        findings.sort(key=lambda f: (f.risk_score or 0.0), reverse=True)

        chain = EvidenceChain(
            alert_id=scope.get("scan_id", "VULN-SCAN"),
            investigated_by=self.name,
            verdict="suspicious" if findings else "benign",
            confidence=max((f.confidence for f in findings), default=0.85),
        )
        for f in findings:
            signal_bits = [f"{f.severity} (risk={f.risk_score:.2f})" if f.risk_score is not None else f.severity]
            if f.kev:
                signal_bits.append("KEV-listed")
            if f.epss is not None:
                signal_bits.append(f"EPSS={f.epss:.2f}")
            if f.poc_available:
                signal_bits.append("PoC")
            signal = f"{' | '.join(signal_bits)}: {f.evidence}"
            chain.evidence.append(
                EvidenceItem(
                    source=f.category,
                    signal=signal,
                    weight="high" if f.severity in ("critical", "high") else "medium" if f.severity == "medium" else "low",
                    raw_data=asdict(f),
                )
            )
        chain.reasoning.append(
            ReasoningStep(
                step=1,
                action="Static scans (dependency / config / code / supply chain)",
                observation=f"{len(findings)} findings",
            )
        )

        # Optional LLM pass: prioritize and produce a human-readable summary.
        if findings:
            wrapped = wrap_untrusted(
                "scan_results",
                json.dumps([asdict(f) for f in findings]),
            )
            user_msg = (
                "Vulnerability discovery summary.\n\n"
                f"Findings (untrusted):\n{wrapped.wrapped}\n\n"
                "Produce a JSON summary with prioritized findings per the schema."
            )
            resp = self._llm.complete(self._system, user_msg, max_tokens=1024)
            try:
                summary_obj = parse_json(resp.text)
                chain.metadata["summary"] = summary_obj.get("summary", "")
            except Exception:  # noqa: BLE001
                chain.metadata["summary"] = "(LLM summary parse failed)"

        for f in findings:
            chain.recommended_actions.append(
                RecommendedAction(
                    action_type="escalate",
                    target=f.affected_component,
                    reasoning=f"{f.severity.upper()}: {f.recommended_remediation}",
                    requires_hitl=True,
                    confidence=f.confidence,
                )
            )
        return chain.finalize(), findings
