"""Honeytoken / decoy monitor — separate fast path.

A reasoning attacker probes the environment. We plant fake artifacts
(API keys, admin URLs, decoy DB names, fake credentials) that no
legitimate user/process should ever touch. Any access = high-confidence
intrusion signal — bypasses orchestrator triage.

Production: tokens registered in Thinkst Canary or canarytokens.org;
they fire webhooks on touch. Walking skeleton: in-memory registry
matched against incoming alerts.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..shared.client_actions import client_actions
from ..shared.evidence_chain import (
    EvidenceChain,
    EvidenceItem,
    ReasoningStep,
    RecommendedAction,
)


@dataclass
class Honeytoken:
    id: str
    kind: str  # "url" | "api_key" | "credential" | "db_name" | ...
    value: str
    description: str


# Stand-in registry. Production planting is a separate provisioning step.
_DEFAULT_REGISTRY: list[Honeytoken] = [
    Honeytoken("ht_001", "url", "/admin-internal-debug",
               "Fake admin endpoint; no human or service should ever hit it."),
    Honeytoken("ht_002", "url", "/.git/config",
               "Decoy .git path; benign clients never request it."),
    Honeytoken("ht_003", "api_key", "AKIA_DECOY_8X4F7Q2N",
               "Fake AWS-shaped key seeded in honeydoc; use = compromise."),
    Honeytoken("ht_004", "credential", "svc_banking_legacy",
               "Decoy service account; any auth attempt = compromise signal."),
    Honeytoken("ht_005", "db_name", "old_payments_archive_2019",
               "Decoy DB name in connection-string config files."),
]


def registry_with_stacks(stacks: list[str] | None = None, base: list[Honeytoken] | None = None) -> list[Honeytoken]:
    """Default registry plus the 2.8d per-stack canaries (fake source map, decoy bundle key,
    dummy admin/export route, ...) for each framework the bank runs. ``stacks`` may also come
    from ``AEGIS_STACKS`` (comma-separated)."""
    import os
    from ..vuln_discovery.client_exposure import canaries_for
    out = list(base if base is not None else _DEFAULT_REGISTRY)
    stacks = stacks if stacks is not None else [s for s in os.environ.get("AEGIS_STACKS", "").split(",") if s.strip()]
    seen = {t.value for t in out}
    for s in stacks:
        for t in canaries_for(s.strip()):
            if t.value not in seen:
                seen.add(t.value); out.append(t)
    return out


class HoneytokenMonitor:
    name = "deception"

    def __init__(self, registry: list[Honeytoken] | None = None):
        self._registry = registry or registry_with_stacks()

    def alert_touches_decoy(self, alert: dict) -> bool:
        return self._match(alert) is not None

    def _match(self, alert: dict) -> Honeytoken | None:
        haystack = " ".join(
            str(alert.get(field, ""))
            for field in ("payload", "url", "username", "query", "raw")
        )
        for token in self._registry:
            if token.value in haystack:
                return token
        return None

    def build_chain(self, alert: dict) -> EvidenceChain:
        token = self._match(alert)
        chain = EvidenceChain(
            alert_id=alert.get("id", "unknown"),
            investigated_by=self.name,
            verdict="malicious",
            confidence=0.97,
        )
        chain.evidence.append(
            EvidenceItem(
                source="honeytoken_monitor",
                signal=f"Honeytoken {token.id} ({token.kind}) touched",
                weight="high",
                raw_data={
                    "token_id": token.id,
                    "kind": token.kind,
                    "description": token.description,
                },
            )
        )
        chain.reasoning.append(
            ReasoningStep(
                step=1,
                action="Match alert content against decoy registry",
                observation=f"Touched {token.id}: {token.description}",
                conclusion="Legitimate users never touch decoys; treat as confirmed intrusion.",
            )
        )
        # the client, not just its current IP: a rotating agent walks around a single IP block
        # (found by the purple-team benchmark); same safety rules as the adaptive fast path
        actions = client_actions(alert, confidence=0.97, why=f"Honeytoken {token.id} touched", evidence=chain.evidence)
        if not actions:
            actions = [RecommendedAction(action_type="block", target=str(alert.get("source_ip") or "unknown"),
                                         reasoning=f"Honeytoken touch is high-confidence intrusion signal ({token.id})",
                                         requires_hitl=True, confidence=0.97)]
        chain.recommended_actions.extend(actions)
        chain.recommended_actions.append(
            RecommendedAction(
                action_type="isolate",
                target=str(alert.get("user_id") or "unknown_principal"),
                reasoning="Suspend the principal that touched the decoy",
                requires_hitl=True,
                confidence=0.97,
            )
        )
        return chain.finalize()
