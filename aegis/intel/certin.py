"""CERT-In incident submission auto-drafter.

CERT-In's 6-hour reporting rule for cyber incidents (RBI-regulated
entities) is a hard regulatory deadline. This module produces a draft
submission from an EvidenceChain that a human can review and submit
within the window.

The exact CERT-In format is regulator-specific and changes; this
walking skeleton emits a structured JSON envelope that mirrors the
documented fields. Production swaps the dispatcher (._submit) for the
real CERT-In API or email-based submission per current procedure.
"""
from __future__ import annotations

import json
import sys
import time
from typing import Optional

from ..agents.shared.evidence_chain import EvidenceChain


_SEVERITY_BY_VERDICT = {
    "benign": "low",
    "uncertain": "medium",
    "suspicious": "medium",
    "malicious": "high",
}


def draft_submission(chain: EvidenceChain, *, organization: str = "ACME Bank",
                     contact_email: str = "soc@acmebank.example",
                     incident_category: Optional[str] = None) -> dict:
    """Build the CERT-In submission envelope.

    Note: real CERT-In submissions also require manual narrative,
    impact assessment, and customer-impact details. This is the
    machine-readable scaffold a human refines.
    """
    return {
        "format": "CERT-In incident report (auto-drafted, human review required)",
        "submitted_by": {
            "organization": organization,
            "contact_email": contact_email,
        },
        "incident": {
            "id": chain.alert_id,
            "detected_at_utc": chain.started_at.isoformat() if chain.started_at else None,
            "severity": _SEVERITY_BY_VERDICT.get(chain.verdict, "medium"),
            "category": incident_category or _infer_category(chain),
            "summary": _build_summary(chain),
            "affected_systems": _affected_targets(chain),
            "indicators_of_compromise": _iocs(chain),
            "mitigation_actions_taken": _mitigations(chain),
            "evidence_chain_integrity_hash": chain.integrity_hash,
        },
        "compliance_metadata": {
            "regulation": "CERT-In Directions, April 2022 (6-hour reporting)",
            "deadline_window_hours": 6,
        },
        "draft_generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def _infer_category(chain: EvidenceChain) -> str:
    sources = {e.source for e in chain.evidence}
    if "honeytoken_monitor" in sources:
        return "Unauthorized access (decoy interaction)"
    if any(s in sources for s in ("decode_payload", "ip_reputation", "similar_past_requests")):
        return "Web application attack (L7)"
    if any(s in sources for s in ("impossible_travel", "device_fingerprint", "mfa_failure_pattern")):
        return "Identity / account compromise"
    if any(s in sources for s in ("parent_process_tree", "lateral_movement", "ioc_match")):
        return "Endpoint / lateral movement"
    return "Other / multi-vector"


def _build_summary(chain: EvidenceChain) -> str:
    bits = [
        f"Verdict: {chain.verdict} (confidence {chain.confidence:.2f})",
        f"Investigated by: {chain.investigated_by}",
    ]
    if chain.specialist_invocations:
        bits.append("Specialists: " + ", ".join(chain.specialist_invocations))
    if chain.reasoning:
        bits.append("Reasoning chain (latest step): " + chain.reasoning[-1].action)
    return " | ".join(bits)


def _affected_targets(chain: EvidenceChain) -> list[str]:
    targets = []
    for action in chain.recommended_actions:
        if action.target and action.target not in targets:
            targets.append(action.target)
    return targets


def _iocs(chain: EvidenceChain) -> list[dict]:
    iocs: list[dict] = []
    for e in chain.evidence:
        rd = e.raw_data or {}
        if "ip" in rd and rd.get("verdict") == "known_malicious":
            iocs.append({"type": "ip", "value": rd["ip"], "context": "abuse_score=" + str(rd.get("abuse_score"))})
        if "matches" in rd:
            for m in rd.get("matches", []):
                iocs.append({"type": "raw", "value": m, "context": "edr ioc match"})
    return iocs


def _mitigations(chain: EvidenceChain) -> list[str]:
    return [
        f"{a.action_type} -> {a.target} (HITL={a.requires_hitl}, conf={a.confidence:.2f})"
        for a in chain.recommended_actions
    ]


def submit(chain: EvidenceChain, stream=sys.stdout, **kwargs) -> dict:
    """Stand-in for real CERT-In submission. Prints a draft + returns it.
    Production: replace with actual API or email dispatch + delivery
    confirmation.
    """
    draft = draft_submission(chain, **kwargs)
    print("\n[CERT-In submission draft]", file=stream)
    print(json.dumps(draft, indent=2, default=str), file=stream)
    return draft
