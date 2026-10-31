"""Egress fast path: findings from the network sensor (``agents/ndr/egress.py``), judged without the LLM.

The detector already did the counting and lists the pair's signals with weights. The verdict
follows the corroboration rule the triage model is trained on:

    a confirming indicator (the server's certificate or name on the IOC list)  malicious ≥ 0.90
    two strong signals (beacon, exfiltration, client / server IOC, tool-default
    certificate subject)                                                        malicious 0.90
    one strong + two weaker (self-signed, days-old certificate, name mismatch,
    untrusted chain, no SNI)                                                    malicious 0.85
    one strong                                                                  suspicious 0.70
    (a beacon whose client presents a browser handshake: a polling tab)         suspicious 0.60

Actions are all human-approved except ``monitor``. An internal host is isolated, never
auto-blocked: the WAF connectors act on the internet edge, while egress control is the
proxy or firewall team's change, so ``block_egress`` waits for them.

Shadow AI is a governance finding, not an attack. Plain use is ``suspicious`` 0.55 with an
``escalate``: register the system in the AI inventory, or block the service at the proxy.
An upload of ≥ 10 MB in an hour is 0.70 and adds a ``block_egress`` proposal, since customer
data may be leaving through a public AI service.
"""

from __future__ import annotations

import math

from ..shared.evidence_chain import (
    EvidenceChain,
    EvidenceItem,
    ReasoningStep,
    RecommendedAction,
)

_FINDINGS = frozenset({"tls_known_bad", "tls_beacon", "tls_exfil", "shadow_ai"})


_WEIGHTS = frozenset({"confirmed", "strong", "medium", "weak"})


def is_egress_finding(alert: dict) -> bool:
    return alert.get("alert_type") in _FINDINGS and isinstance(alert.get("egress"), dict)


def _num(v: object, default: float) -> float:
    try:
        f = float(v)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError):
        return default
    return f if math.isfinite(f) else default


def _clean(alert: dict) -> dict:
    """The egress block with its shape enforced. Findings normally come from the detector, but an
    already-normalised alert can also arrive through ``/ingest/alerts``: a malformed one must
    still produce a chain, never crash the fast path."""
    e = alert.get("egress") if isinstance(alert.get("egress"), dict) else {}
    sig = []
    for s in e.get("signals") if isinstance(e.get("signals"), list) else []:
        if isinstance(s, dict):
            w = str(s.get("weight") or "weak")
            sig.append({"name": str(s.get("name") or "signal")[:64], "weight": w if w in _WEIGHTS else "weak",
                        "detail": str(s.get("detail") or "")[:300]})
    intel = e.get("intel") if isinstance(e.get("intel"), dict) else {}
    return {**{k: v for k, v in e.items() if isinstance(k, str)},
            "finding": str(alert.get("alert_type")), "level": max(1, int(_num(e.get("level"), 1))), "signals": sig[:32],
            "intel": {**intel, "confidence": min(0.98, max(0.0, _num(intel.get("confidence"), 0.9)))} if intel else {},
            "dst_ips": [str(x)[:64] for x in (e.get("dst_ips") if isinstance(e.get("dst_ips"), list) else [])][:8],
            "shadow_ai": e.get("shadow_ai") if isinstance(e.get("shadow_ai"), dict) else {},
            "destination": str(e.get("destination") or "")[:255], "client_shape": str(e.get("client_shape") or "")}


def egress_verdict(e: dict) -> tuple[str, float, str]:
    """(verdict, confidence, why) from the detector's weighted signals."""
    if e.get("finding") == "shadow_ai":
        return ("suspicious", 0.70, "AI service used by an unregistered host, with a bulk upload") if _num(e.get("level"), 1) > 1 \
            else ("suspicious", 0.55, "AI service used outside the AI inventory")
    sig = e.get("signals") or []
    confirmed = [s for s in sig if s.get("weight") == "confirmed"]
    strong = [s for s in sig if s.get("weight") == "strong"]
    weaker = [s for s in sig if s.get("weight") in ("medium", "weak")]
    if confirmed:
        conf = max(0.90, _num((e.get("intel") or {}).get("confidence"), 0.9))
        return "malicious", min(0.98, conf + (0.04 if strong else 0.0)), "the server's certificate or name is a known-bad indicator"
    if len(strong) >= 2:
        return "malicious", 0.90, "two independent strong signals: " + ", ".join(s["name"] for s in strong)
    if strong and len(weaker) >= 2:
        return "malicious", 0.85, f"{strong[0]['name']} corroborated by " + ", ".join(s["name"] for s in weaker)
    if strong:
        if strong[0]["name"] == "beacon" and e.get("client_shape") == "browser" and not weaker:
            return "suspicious", 0.60, "regular calls from a browser-shaped client: often a polling tab"
        return "suspicious", 0.70 + (0.05 if weaker else 0.0), f"one strong signal ({strong[0]['name']})"
    return "suspicious", 0.55, "weak signals only"


def egress_chain(alert: dict) -> EvidenceChain:
    e = _clean(alert)
    finding = e["finding"]
    host, dest = str(alert.get("source_ip") or ""), str(e.get("destination") or alert.get("sni") or alert.get("dest_ip") or "")
    verdict, conf, why = egress_verdict(e)
    chain = EvidenceChain(alert_id=str(alert.get("id", "unknown")), investigated_by="egress", verdict=verdict, confidence=conf)
    chain.evidence.append(EvidenceItem(
        source=str(alert.get("source") or "NDR"), weight="high" if verdict == "malicious" else "medium",
        signal=str(alert.get("note") or finding),
        raw_data={k: e.get(k) for k in ("finding", "level", "destination", "dst_ips", "dest_port", "prevalence", "rare",
                                        "client_ja4", "client_shape", "cert", "beacon", "exfil", "intel", "shadow_ai")}))
    for s in e.get("signals") or []:
        chain.evidence.append(EvidenceItem(source="ndr_signal", weight={"confirmed": "high", "strong": "high", "medium": "medium"}
                                           .get(str(s.get("weight")), "low"), signal=f"{s.get('name')}: {s.get('detail')}"))
    chain.evidence.append(EvidenceItem(source="ndr_prevalence", weight="low",
                                       signal=f"{e.get('prevalence')} internal host(s) talk to {dest}"
                                              + (" — rare" if e.get("rare") else "")))
    chain.reasoning.append(ReasoningStep(step=1, action="Egress fast path (no LLM verdict)", observation=why, conclusion=verdict))
    target = str(alert.get("id", "unknown"))
    if finding == "shadow_ai":
        sa = e.get("shadow_ai") or {}
        chain.recommended_actions.append(RecommendedAction(
            action_type="escalate", target=target, requires_hitl=True, confidence=conf,
            reasoning=(f"{host} uses {sa.get('service', 'an AI service')} ({dest}) — {sa.get('status', 'unregistered')}"
                       + (f" (registered system {sa['system']})" if sa.get("system") else "")
                       + ": register it in the AI inventory (RBI FREE-AI Rec 23) or block the service at the proxy")))
        if int(e.get("level") or 1) > 1:
            chain.recommended_actions.append(RecommendedAction(
                action_type="block_egress", target=dest, requires_hitl=True, confidence=conf,
                reasoning="Bulk upload to a public AI service from an unregistered host: customer data may be leaving — DLP review"))
        chain.metadata["shadow_ai"] = sa
    elif verdict == "malicious":
        chain.recommended_actions.append(RecommendedAction(
            action_type="isolate", target=host, requires_hitl=True, confidence=conf,
            reasoning=f"Isolate {host}: {why} on its outbound TLS to {dest}"))
        chain.recommended_actions.append(RecommendedAction(
            action_type="block_egress", target=dest, requires_hitl=True, confidence=conf,
            reasoning=f"Block {dest} at the egress proxy / firewall (and its IPs {', '.join((e.get('dst_ips') or [])[:3])})"))
        chain.recommended_actions.append(RecommendedAction(
            action_type="escalate", target=target, requires_hitl=True, confidence=conf,
            reasoning="Possible compromised host — hunt for the process making these connections and for other hosts calling the same place"))
    else:
        if host:
            chain.recommended_actions.append(RecommendedAction(
                action_type="monitor", target=host, requires_hitl=False, confidence=conf,
                reasoning=f"Watch {host}'s outbound TLS while an analyst looks"))
        chain.recommended_actions.append(RecommendedAction(
            action_type="escalate", target=target, requires_hitl=True, confidence=conf,
            reasoning=f"{why} towards {dest}: confirm the process and whether anyone else needs it"))
    chain.metadata["egress"] = {k: e.get(k) for k in ("finding", "level", "destination", "prevalence", "rare", "client_shape")}
    return chain.finalize()


__all__ = ["egress_chain", "egress_verdict", "is_egress_finding"]
