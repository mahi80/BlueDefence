"""Adaptive-attacker fast path: a client that comes straight back after being stopped.

Humans who hit a WAF block pause, read, try later. An AI agent retries within seconds,
from a new IP in its proxy pool, with a mutated payload — and keeps its TLS stack. When
campaign context (``walkers/campaign.py``) shows exactly that, the verdict does not need
an LLM: it is built here, deterministically, and the response targets the *client*, not
the one IP it happens to be on.

Fires when the request being judged is itself an attack-shaped retry after a stop and, inside
the campaign window:
    retries_after_stop ≥ MIN_RETRIES, median seconds to retry ≤ MAX_MEDIAN_RETRY_S,
    and the retries rotated IPs or mutated the request (≥ MIN_ROTATIONS_OR_MUTATIONS).

Actions (the ResponseAgent's autonomy policy decides which run without a human):
    block <current IP>                   — short TTL
    block fp:<tls>;ua:<exact UA>         — when the client kept one user agent
    challenge fp:<tls>                   — when it rotated user agents (a bare TLS fingerprint
                                           is shared by every user of that browser build, so it
                                           is challenged, never blocked)
    escalate                             — the campaign goes on an analyst's queue regardless
Fingerprints are never enforced when they are seen on benign traffic (≥ ``BENIGN_SHARE_LIMIT``
clients) or carry a mainstream browser user agent with a matching TLS handshake — an agent driving
a real browser looks like a customer, so it gets IP-level actions only. A browser user agent the
handshake contradicts (``shared/tls_client.py``) is challenged on that exact pair instead. Header-order fingerprints correlate but are never
enforced; ``AEGIS_FP_ALLOW`` is honoured. Only attack-shaped requests (stopped or flagged by the
WAF) count as retries, so customers behind a shared IP or fingerprint never make a campaign.
"""

from __future__ import annotations

import os

from ..shared.client_actions import BENIGN_SHARE_LIMIT, client_actions, looks_like_browser  # noqa: F401 — re-exported for callers
from ..shared.evidence_chain import EvidenceChain, EvidenceItem, ReasoningStep, RecommendedAction
from ..shared.fingerprint import client_fingerprint

MIN_RETRIES = int(os.environ.get("AEGIS_ADAPTIVE_MIN_RETRIES", "3"))
MAX_MEDIAN_RETRY_S = float(os.environ.get("AEGIS_ADAPTIVE_MAX_RETRY_S", "30"))
MIN_ROTATIONS_OR_MUTATIONS = 2
MAX_POOL_BLOCKS = 16                 # retry-chain IPs blocked alongside the current one


def _adaptation(alert: dict) -> dict:
    cc = alert.get("campaign_context")
    return (cc or {}).get("adaptation") or {} if isinstance(cc, dict) else {}


def is_adaptive_attacker(alert: dict) -> bool:
    a = _adaptation(alert)
    if not a:
        return False
    med = a.get("median_seconds_to_retry")
    return (bool(a.get("current_is_retry"))
            and a.get("retries_after_stop", 0) >= MIN_RETRIES
            and med is not None and med <= MAX_MEDIAN_RETRY_S
            and max(a.get("ip_rotations_after_stop", 0), a.get("mutations_after_stop", 0)) >= MIN_ROTATIONS_OR_MUTATIONS)


def adaptive_attacker_chain(alert: dict) -> EvidenceChain:
    a = _adaptation(alert)
    ident = (alert.get("campaign_context") or {}).get("identity") or {}
    fp = client_fingerprint(alert)
    rot, mut = a.get("ip_rotations_after_stop", 0), a.get("mutations_after_stop", 0)
    conf = 0.90 + (0.03 if rot >= 2 and mut >= 2 else 0.0) + (0.02 if fp is not None and fp.strength == "tls" else 0.0)
    chain = EvidenceChain(alert_id=str(alert.get("id", "unknown")), investigated_by="adaptive_attacker",
                          verdict="malicious", confidence=min(conf, 0.96))
    chain.evidence.append(EvidenceItem(
        source="campaign_context", weight="high",
        signal=(f"Stopped {a.get('stops', 0)}× and came back {a.get('retries_after_stop', 0)}× within "
                f"{a.get('median_seconds_to_retry')}s (median): {rot} retries from a new IP, {mut} with a changed request"),
        raw_data={"adaptation": a, "identity": ident}))
    if fp is not None:
        chain.evidence.append(EvidenceItem(
            source="campaign_context", weight="high" if fp.strength == "tls" else "medium",
            signal=(f"Same client fingerprint ({fp.kind}) across {ident.get('distinct_source_ips', '?')} IPs and "
                    f"{ident.get('distinct_user_agents', '?')} user agents")))
    chain.reasoning.append(ReasoningStep(step=1, action="Adaptive-attacker fast path (no LLM verdict)",
                                         observation="Retry-after-stop at machine cadence with rotation / mutation is the signature of an automated attacker",
                                         conclusion="malicious"))

    chain.recommended_actions.extend(client_actions(
        alert, confidence=chain.confidence, why="Retries after every stop", identity=ident, evidence=chain.evidence))
    # the rest of the pool it has already retried from — it will rotate back to them (found by the
    # purple-team benchmark: a browser-driven agent, un-fingerprintable, came back on an earlier IP)
    current_ip = str(alert.get("source_ip") or "")
    for ip in [x for x in a.get("retry_ips") or [] if x and x != current_ip][:MAX_POOL_BLOCKS]:
        chain.recommended_actions.append(RecommendedAction(
            action_type="block", target=ip, requires_hitl=False, confidence=chain.confidence,
            reasoning="Retries after every stop: another IP of the same client's retry chain"))
    chain.recommended_actions.append(RecommendedAction(
        action_type="escalate", target=str(alert.get("id", "unknown")), requires_hitl=True, confidence=chain.confidence,
        reasoning="Automated attack campaign in progress — analyst review of what it reached before it was stopped"))
    chain.metadata["adaptive_attacker"] = {"adaptation": a, "identity": ident,
                                           "fingerprint": fp.key if fp else None}
    return chain.finalize()


__all__ = ["is_adaptive_attacker", "adaptive_attacker_chain"]
