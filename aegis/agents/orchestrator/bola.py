"""BOLA fast path — an object-walk alert from the API-gateway detector, judged without the LLM.

The detector (``agents/api_abuse/object_walk.py``) already did the counting; its level is the
verdict:

    confirmed    malicious 0.95 — other customers' objects answered 2xx: data left the bank.
                 Contain the client (every IP of the walk + safe fingerprint action), **revoke the
                 principal's sessions** (human — a compromised customer is also a victim), escalate
                 as a possible personal-data breach (the regulator's reporting clock may be running).
                 The token is the real containment; IP blocks only buy time until it is revoked.
    attempted    malicious 0.90 — foreign objects requested, the API refused them. Same client
                 containment and session review; no exposure to report.
    behavioural  suspicious 0.70 — many distinct objects, no ownership data to confirm.
                 Recoverable friction only: throttle + challenge, escalate.
"""

from __future__ import annotations

from ..shared.client_actions import client_actions

MAX_WALK_IPS = 16
from ..shared.evidence_chain import EvidenceChain, EvidenceItem, ReasoningStep, RecommendedAction


def is_object_walk(alert: dict) -> bool:
    return alert.get("alert_type") == "object_walk" and isinstance(alert.get("object_walk"), dict)


def object_walk_chain(alert: dict) -> EvidenceChain:
    w = alert["object_walk"]
    level = str(w.get("level") or "behavioural")
    principal = str(alert.get("principal_id") or alert.get("user_id") or "")
    verdict, conf = {"confirmed": ("malicious", 0.95), "attempted": ("malicious", 0.90)}.get(level, ("suspicious", 0.70))
    chain = EvidenceChain(alert_id=str(alert.get("id", "unknown")), investigated_by="object_walk", verdict=verdict, confidence=conf)
    obj = w.get("object_type", "object")
    chain.evidence.append(EvidenceItem(
        source=str(alert.get("source") or "API gateway"), weight="high" if level != "behavioural" else "medium",
        signal=(f"{principal or 'unauthenticated client'} on {w.get('template')}: {w.get('distinct_objects')} distinct {obj} ids in "
                f"{w.get('window_s')} s — {w.get('cross_owner_success', 0)} owned by others answered 2xx, "
                f"{w.get('cross_owner_attempts', 0)} foreign requested, {w.get('own_objects', 0)} own; "
                f"not-found/forbidden ratio {w.get('not_found_ratio')}, sequential ids {w.get('sequential_ids')}, "
                f"median gap {w.get('median_gap_s')} s, ownership via {w.get('ownership_source')}"),
        raw_data={k: w.get(k) for k in ("level", "object_type", "template", "distinct_objects", "cross_owner_success",
                                        "cross_owner_attempts", "own_objects", "not_found_ratio", "sequential_ids",
                                        "median_gap_s", "client_ips", "sample_objects_masked", "window_s")}))
    chain.reasoning.append(ReasoningStep(
        step=1, action="Object-walk fast path (no LLM verdict)",
        observation={"confirmed": "Objects owned by other customers were returned to this principal",
                     "attempted": "This principal requested many objects it does not own; authorisation refused them",
                     "behavioural": "Enumeration-shaped access across many object ids; ownership unknown"}[level],
        conclusion=verdict))
    if level in ("confirmed", "attempted"):
        chain.recommended_actions.extend(client_actions(alert, confidence=conf, why="Broken object-level authorisation",
                                                        evidence=chain.evidence))
        # every IP this principal walked from — it will rotate back (the autonomy policy still refuses
        # internal, wide or protected targets, and the TTL lifts them)
        current = str(alert.get("source_ip") or "")
        for ip in [x for x in (w.get("client_ips") or []) if x and x != current][:MAX_WALK_IPS]:
            chain.recommended_actions.append(RecommendedAction(
                action_type="block", target=ip, requires_hitl=False, confidence=conf,
                reasoning="Broken object-level authorisation: another IP the same principal walked from"))
        if principal and not principal.startswith("anon:"):
            chain.recommended_actions.append(RecommendedAction(
                action_type="revoke_sessions", target=principal, requires_hitl=True, confidence=conf,
                reasoning="Revoke this principal's tokens: either a compromised customer account or a customer abusing the API"))
        exposure = (f"{w.get('cross_owner_success')} {obj}(s) of other customers were returned — treat as a possible "
                    "personal-data breach (regulatory reporting clock may apply)") if level == "confirmed" else \
                   "Refused cross-customer requests — review the authorisation layer and the principal"
        chain.recommended_actions.append(RecommendedAction(
            action_type="escalate", target=str(alert.get("id", "unknown")), requires_hitl=True, confidence=conf,
            reasoning=exposure))
    else:
        ip = str(alert.get("source_ip") or "")
        if ip:
            chain.recommended_actions.append(RecommendedAction(action_type="throttle", target=ip, requires_hitl=False, confidence=conf,
                                                               reasoning="Slow an enumeration-shaped walk until ownership is known"))
            chain.recommended_actions.append(RecommendedAction(action_type="challenge", target=ip, requires_hitl=False, confidence=conf,
                                                               reasoning="A human passes a challenge; a scripted walker does not"))
        chain.recommended_actions.append(RecommendedAction(
            action_type="escalate", target=str(alert.get("id", "unknown")), requires_hitl=True, confidence=conf,
            reasoning="Possible object walk without ownership data — connect AEGIS_OWNERSHIP_FILE / _URL to confirm or clear"))
    chain.metadata["object_walk"] = {k: w.get(k) for k in ("level", "template", "distinct_objects", "cross_owner_success",
                                                         "cross_owner_attempts", "ownership_source")}
    return chain.finalize()


__all__ = ["is_object_walk", "object_walk_chain"]
