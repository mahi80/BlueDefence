"""PXE firmware fast path: an ICMP-during-boot finding from the NDR sensor
(``agents/ndr/pxe_boot.py``), judged without the LLM.

This is the on-wire detection and response side of CVE-2026-97631, a firmware-level
PXE boot flaw. AEGIS cannot patch firmware; what it can do is see the hostile boot-time
traffic and contain it — isolate the booting host, block the source on the boot segment,
and escalate to disable network boot and apply the vendor firmware update. Actions are
human-approved except ``monitor``.
"""
from __future__ import annotations

from ..shared.evidence_chain import (
    EvidenceChain,
    EvidenceItem,
    ReasoningStep,
    RecommendedAction,
)

_CVE = "CVE-2026-97631"


def is_pxe_firmware_finding(alert: dict) -> bool:
    return alert.get("alert_type") == "pxe_icmp_overflow" and isinstance(alert.get("pxe"), dict)


def _clean(alert: dict) -> dict:
    p = alert.get("pxe") if isinstance(alert.get("pxe"), dict) else {}
    sig = []
    for s in p.get("signals") if isinstance(p.get("signals"), list) else []:
        if isinstance(s, dict):
            w = str(s.get("weight") or "weak")
            sig.append({"name": str(s.get("name") or "signal")[:64],
                        "weight": w if w in ("strong", "medium", "weak") else "weak",
                        "detail": str(s.get("detail") or "")[:300]})
    return {
        "cve": str(p.get("cve") or _CVE),
        "host": str(p.get("host") or ""),
        "src": str(p.get("src") or alert.get("source_ip") or ""),
        "icmp_bytes": max(0, int(p.get("icmp_bytes") or 0)),
        "icmp_count": max(0, int(p.get("icmp_count") or 0)),
        "oversize": bool(p.get("oversize")),
        "signals": sig[:16],
    }


def pxe_firmware_verdict(p: dict) -> tuple[str, float, str]:
    """(verdict, confidence, why). Oversize payload into the boot buffer is a code-execution
    attempt (build-specific, so just under the certain-IOC bar); a burst alone is boot-time
    disruption or probing."""
    if p.get("oversize"):
        return ("malicious", 0.85,
                f"{p['icmp_bytes']} B of ICMP error payload reached the PXE boot stack — "
                f"pre-boot code-execution attempt ({p['cve']})")
    return ("suspicious", 0.65,
            f"{p['icmp_count']} ICMP errors to a booting host — boot-time disruption or probing ({p['cve']})")


def pxe_firmware_chain(alert: dict) -> EvidenceChain:
    p = _clean(alert)
    host, src = p["host"], p["src"]
    verdict, conf, why = pxe_firmware_verdict(p)
    chain = EvidenceChain(alert_id=str(alert.get("id", "unknown")), investigated_by="pxe_firmware",
                          verdict=verdict, confidence=conf)
    chain.evidence.append(EvidenceItem(
        source=str(alert.get("source") or "NDR"),
        weight="high" if verdict == "malicious" else "medium",
        signal=f"{p['cve']}: ICMP anomaly during PXE boot of {host or 'a host'}",
        raw_data={k: p.get(k) for k in ("cve", "host", "src", "icmp_bytes", "icmp_count", "oversize")}))
    for s in p["signals"]:
        chain.evidence.append(EvidenceItem(
            source="ndr_signal", weight={"strong": "high", "medium": "medium"}.get(s["weight"], "low"),
            signal=f"{s['name']}: {s['detail']}"))
    chain.reasoning.append(ReasoningStep(step=1, action="PXE firmware fast path (no LLM verdict)",
                                         observation=why, conclusion=verdict))
    target = str(alert.get("id", "unknown"))
    if verdict == "malicious":
        if host:
            chain.recommended_actions.append(RecommendedAction(
                action_type="isolate", target=host, requires_hitl=True, confidence=conf,
                reasoning=f"Isolate {host}: hostile ICMP into its PXE boot stack ({p['cve']}) — code may run before Secure Boot"))
        if src:
            chain.recommended_actions.append(RecommendedAction(
                action_type="block", target=src, requires_hitl=True, confidence=conf,
                reasoning=f"Block {src} on the provisioning/boot segment — it is the source of the boot-time ICMP"))
        chain.recommended_actions.append(RecommendedAction(
            action_type="escalate", target=target, requires_hitl=True, confidence=conf,
            reasoning=(f"{p['cve']}: disable PXE/network boot where not required, apply the vendor firmware update "
                       "when shipped, and preserve boot logs; firmware-patch governance owns the fleet follow-up")))
    else:
        if host:
            chain.recommended_actions.append(RecommendedAction(
                action_type="monitor", target=host, requires_hitl=False, confidence=conf,
                reasoning=f"Watch {host}'s boot-time network traffic while an analyst reviews"))
        chain.recommended_actions.append(RecommendedAction(
            action_type="escalate", target=target, requires_hitl=True, confidence=conf,
            reasoning=f"Repeated boot-time ICMP to {host or 'a host'} ({p['cve']}) — confirm the source and whether PXE is needed here"))
    chain.metadata["pxe_firmware"] = {k: p.get(k) for k in ("cve", "host", "src", "icmp_bytes", "icmp_count", "oversize")}
    return chain.finalize()


__all__ = ["is_pxe_firmware_finding", "pxe_firmware_chain", "pxe_firmware_verdict"]
