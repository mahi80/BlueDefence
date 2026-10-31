"""ServiceNow ticket writer.

Production: REST POST to ServiceNow Incident table with the evidence
chain attached as a structured field. Walking skeleton: pretty-prints
the ticket to stdout so the demo is self-contained.
"""
from __future__ import annotations

import json
import sys

from ..agents.shared.evidence_chain import EvidenceChain


_SEVERITY_BY_VERDICT = {
    "benign": "P5 (informational)",
    "uncertain": "P4 (review)",
    "suspicious": "P3 (investigate)",
    "malicious": "P1 (active threat)",
}


def write_ticket(chain: EvidenceChain, stream=sys.stdout) -> None:
    sev = _SEVERITY_BY_VERDICT.get(chain.verdict, "P4")
    actions_text = "\n".join(
        f"  - {a.action_type} -> {a.target} (HITL={a.requires_hitl}, conf={a.confidence:.2f}): {a.reasoning}"
        for a in chain.recommended_actions
    ) or "  (none)"
    reasoning_text = "\n".join(
        f"  {step.step}. {step.action} -> {step.observation}"
        + (f" -> {step.conclusion}" if step.conclusion else "")
        for step in chain.reasoning
    ) or "  (none)"
    evidence_text = "\n".join(
        f"  - [{e.source}] weight={e.weight}: {e.signal}"
        for e in chain.evidence
    ) or "  (none)"

    print(
        f"\n{'=' * 72}\n"
        f"SERVICENOW TICKET (mock)  [{sev}]\n"
        f"{'=' * 72}\n"
        f"Alert:        {chain.alert_id}\n"
        f"Investigated: {chain.investigated_by}\n"
        f"Verdict:      {chain.verdict}  (confidence={chain.confidence:.2f})\n"
        f"Specialists:  {', '.join(chain.specialist_invocations) or '(none)'}\n"
        f"Voter concur: {chain.metadata.get('vote_concur', '(n/a)')}"
        + (f"  reason={chain.metadata.get('vote_reason')}" if 'vote_reason' in chain.metadata else "")
        + f"\nIntegrity:    {chain.integrity_hash[:16] + '...' if chain.integrity_hash else '(unsigned)'}\n"
        f"\nEvidence:\n{evidence_text}\n"
        f"\nReasoning:\n{reasoning_text}\n"
        f"\nRecommended actions:\n{actions_text}\n"
        f"{'=' * 72}\n",
        file=stream,
    )


def write_ticket_json(chain: EvidenceChain, stream=sys.stdout) -> None:
    json.dump(chain.model_dump(mode="json"), stream, indent=2, default=str)
    stream.write("\n")
