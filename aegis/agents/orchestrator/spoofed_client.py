"""Spoofed-browser fast path: a client whose user agent claims a browser its TLS stack cannot be.

Campaign context attaches ``tls_client`` to every request that carries a JA4 and claims a
browser (``shared/tls_client.py``). When that check is a *strong* mismatch (a scripting
library's handshake behind a copied Chrome user agent), the request was sent by automation
that is pretending to be a customer. The fast path fires when that lie comes with intent:

    stopped by the bank's own WAF   an attack the WAF caught (not AEGIS's enforcement showing up
                                    in the WAF log) — suspicious 0.80, plus an escalate card
    an auth-form submission         credential stuffing / account-takeover bots spoof browsers to
                                    get past naive bot rules — suspicious 0.75, no card (a slow
                                    stuffing run would file one per attempt)

The response is one auto-safe action: ``challenge`` the exact pair (TLS fingerprint and that
user agent). The pair follows the client across its proxy pool. A script cannot pass the
challenge, a real browser never presents the pair, and a customer behind an unlearned
TLS-inspecting middlebox who did match it passes the challenge. There is no block and no
``malicious`` verdict here. If the client keeps coming back after being challenged, the
adaptive path (retry after stop) makes that call.
"""

from __future__ import annotations

from ..shared.evidence_chain import (
    EvidenceChain,
    EvidenceItem,
    ReasoningStep,
    RecommendedAction,
)
from ..shared.fingerprint import allowed_fingerprints, client_fingerprint
from ..shared.tls_client import spoofed_browser
from .walkers.campaign import is_auth_write

_RULE_FIELDS = ("signature", "attack_type", "rule", "waf_rule", "rule_name", "description")


def aegis_enforcement(alert: dict) -> bool:
    """The WAF log line is AEGIS's own rule firing (its rules are named ``aegis …``), not a new attack."""
    return any(str(alert.get(k) or "").strip().lower().startswith("aegis") for k in _RULE_FIELDS)


def stopped_by_bank_waf(alert: dict) -> bool:
    return alert.get("blocked") is True and not aegis_enforcement(alert)


def _auth_write(alert: dict) -> bool:
    return is_auth_write(str(alert.get("http_method") or alert.get("method") or ""),
                         str(alert.get("url") or alert.get("endpoint") or alert.get("uri") or ""))


def is_spoofed_client(alert: dict) -> bool:
    if spoofed_browser(alert) is None:
        return False
    fp = client_fingerprint(alert)
    if fp is None or fp.strength != "tls":
        return False
    return stopped_by_bank_waf(alert) or _auth_write(alert)


def spoofed_client_chain(alert: dict) -> EvidenceChain:
    t = spoofed_browser(alert) or {}
    stopped = stopped_by_bank_waf(alert)
    conf = 0.80 if stopped else 0.75
    chain = EvidenceChain(alert_id=str(alert.get("id", "unknown")), investigated_by="spoofed_client",
                          verdict="suspicious", confidence=conf)
    chain.evidence.append(EvidenceItem(
        source="tls_client", weight="high",
        signal=(f"User agent claims {t.get('claimed')} but the TLS handshake is not a browser's: "
                f"{'; '.join(t.get('reasons') or [])} (JA4 {t.get('ja4')}, seen as {t.get('observed')})"),
        raw_data={"tls_client": t}))
    method = str(alert.get("http_method") or alert.get("method") or "")
    url = str(alert.get("url") or "")
    if stopped:
        chain.evidence.append(EvidenceItem(source=str(alert.get("source") or "WAF"), weight="medium",
                                           signal=f"The bank's WAF stopped this request: {alert.get('attack_type') or alert.get('signature') or 'rule match'} on {url}"))
    else:
        chain.evidence.append(EvidenceItem(source=str(alert.get("source") or "WAF"), weight="medium",
                                           signal=f"Auth-form submission: {method} {url.split('?', 1)[0]}"))
    chain.reasoning.append(ReasoningStep(
        step=1, action="TLS / user-agent consistency fast path (no LLM verdict)",
        observation=("Automation presenting itself as a browser, " +
                     ("sending traffic the WAF blocks" if stopped else "submitting an auth form")),
        conclusion="suspicious — challenge the exact client; the adaptive path decides malicious if it keeps coming back"))
    fp = client_fingerprint(alert)
    ip = str(alert.get("source_ip") or "")
    if fp is not None and fp.value not in allowed_fingerprints():
        chain.recommended_actions.append(RecommendedAction(
            action_type="challenge", target=fp.target(with_user_agent=True), requires_hitl=False, confidence=conf,
            reasoning=(f"Challenge this exact TLS stack + user agent wherever it rotates: it claims {t.get('claimed')}, "
                       "a real browser never presents the pair and would pass; a script cannot")))
    elif ip:
        chain.evidence.append(EvidenceItem(source="client_fingerprint", weight="low",
                                           signal="Fingerprint on AEGIS_FP_ALLOW — challenging the IP only"))
        chain.recommended_actions.append(RecommendedAction(
            action_type="challenge", target=ip, requires_hitl=False, confidence=conf,
            reasoning="Challenge the IP — a human passes a managed challenge, a script does not"))
    if stopped:
        chain.recommended_actions.append(RecommendedAction(
            action_type="escalate", target=str(alert.get("id", "unknown")), requires_hitl=True, confidence=conf,
            reasoning="Automation spoofing a browser is attacking — review; AEGIS is challenging it meanwhile"))
    chain.metadata["tls_client"] = t
    return chain.finalize()


__all__ = ["aegis_enforcement", "is_spoofed_client", "spoofed_client_chain", "stopped_by_bank_waf"]
