"""Slack notifier (mock).

Production: posts to a SOC channel via incoming webhook. Walking
skeleton: prints a one-line summary suitable for demo/log scraping.
"""
from __future__ import annotations

import sys

from ..agents.shared.evidence_chain import EvidenceChain


_EMOJI = {
    "benign": "[ok]",
    "uncertain": "[?]",
    "suspicious": "[!]",
    "malicious": "[!!]",
}


def notify(chain: EvidenceChain, stream=sys.stdout) -> None:
    actions = ",".join(
        f"{a.action_type}{'(HITL)' if a.requires_hitl else ''}"
        for a in chain.recommended_actions
    ) or "none"
    print(
        f"#soc-aegis  {_EMOJI.get(chain.verdict, '[?]')}  "
        f"{chain.alert_id}  verdict={chain.verdict} conf={chain.confidence:.2f}  "
        f"by={chain.investigated_by}  actions=[{actions}]",
        file=stream,
    )
