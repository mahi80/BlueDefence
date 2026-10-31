"""Low-and-slow fast path: one client mutating against a single endpoint, paced slow.

An attacker who keeps the cadence below the retry-after-stop window (``adaptive.py``) never
registers as a "retry" — each attempt lands minutes after the last, so ``_adaptation`` sees no
retries and ``_auth_burst`` sees no burst. ``walkers/campaign.py`` therefore also keeps a
long-window count of attack-shaped WAF stops per client (by **source IP**, so a shared TLS
fingerprint or a branch NAT never aggregates): when one endpoint template has collected several
blocked attempts with distinct payloads — the client mutating around the managed rule — that is an
attack whatever its speed.

The verdict is built here, deterministically, from ``campaign_context["low_and_slow"]``. It fires
when the request being judged is itself an attack-shaped stop and, inside the long window, its
endpoint has ≥ ``MIN_STOPS`` stops with ≥ ``MIN_PAYLOADS`` distinct payloads at a median gap
≥ ``MIN_GAP_S`` — slower than what ``adaptive`` fires on, so the two partition the speed axis and
``adaptive`` (dispatched first) keeps the fast case. The response targets the client through the
shared ``client_actions`` helper (collateral-safe fingerprint rules: the current IP always, the
TLS fingerprint only where that cannot be a customer), plus an ``escalate`` for a human.

Only single-source-IP low-and-slow is covered; an attacker that also rotates IPs slowly is a known
gap (the fingerprint action still follows it where that is safe). Benign false positives scatter
across endpoints and never reach ``MIN_STOPS`` mutations on one template, so a customer whose client
trips the WAF now and then is never caught here.
"""

from __future__ import annotations

import os

from ..shared.client_actions import client_actions
from ..shared.evidence_chain import EvidenceChain, EvidenceItem, ReasoningStep, RecommendedAction

MIN_STOPS = int(os.environ.get("AEGIS_LOWSLOW_MIN_STOPS", "3"))
MIN_PAYLOADS = int(os.environ.get("AEGIS_LOWSLOW_MIN_PAYLOADS", "2"))
MIN_GAP_S = float(os.environ.get("AEGIS_LOWSLOW_MIN_GAP_S", "30"))      # slower than adaptive's fire cadence


def _signal(alert: dict) -> dict:
    cc = alert.get("campaign_context")
    return (cc.get("low_and_slow") or {}) if isinstance(cc, dict) else {}


def is_low_and_slow(alert: dict) -> bool:
    s = _signal(alert)
    if not s or not s.get("current_is_attack_stop"):
        return False
    med = s.get("median_gap_s")
    return (int(s.get("stops_on_endpoint") or 0) >= MIN_STOPS
            and int(s.get("distinct_payloads") or 0) >= MIN_PAYLOADS
            and (med is None or float(med) >= MIN_GAP_S))


def low_and_slow_chain(alert: dict) -> EvidenceChain:
    s = _signal(alert)
    ident = (alert.get("campaign_context") or {}).get("identity") or None
    stops, payloads = int(s.get("stops_on_endpoint") or 0), int(s.get("distinct_payloads") or 0)
    conf = min(0.90 + 0.02 * (stops - MIN_STOPS) + (0.02 if s.get("sensitive") else 0.0), 0.95)
    chain = EvidenceChain(alert_id=str(alert.get("id", "unknown")), investigated_by="low_and_slow",
                          verdict="malicious", confidence=conf)
    chain.evidence.append(EvidenceItem(
        source="campaign_context", weight="high",
        signal=(f"{stops} WAF-blocked attempts with {payloads} distinct payloads against {s.get('endpoint')} "
                f"from one client over {s.get('span_minutes')} min (median gap {s.get('median_gap_s')}s) — "
                f"mutating around the rule below the retry-after-stop cadence"),
        raw_data={"low_and_slow": s}))
    conclusion = ("malicious — persistent WAF evasion on a sensitive endpoint" if s.get("sensitive")
                  else "malicious — persistent WAF evasion against one endpoint")
    chain.reasoning.append(ReasoningStep(
        step=1, action="Low-and-slow fast path (no LLM verdict)",
        observation="One client mutating payloads against a single endpoint, paced slow to stay under burst / retry detection",
        conclusion=conclusion))
    chain.recommended_actions.extend(client_actions(
        alert, confidence=conf, why="Mutating against one endpoint, low and slow", identity=ident, evidence=chain.evidence))
    chain.recommended_actions.append(RecommendedAction(
        action_type="escalate", target=str(alert.get("id", "unknown")), requires_hitl=True, confidence=conf,
        reasoning="Low-and-slow WAF evasion — review the endpoint it is grinding and whether any payload variant got through"))
    chain.metadata["low_and_slow"] = s
    return chain.finalize()


__all__ = ["is_low_and_slow", "low_and_slow_chain", "MIN_STOPS", "MIN_PAYLOADS", "MIN_GAP_S"]
