"""Credential-stuffing fast path: one client submitting an auth form at machine rate.

No WAF signature fires on credential stuffing: every request is a well-formed login POST.
What gives it away is the rate from one client. Campaign context (``walkers/campaign.py::
_auth_burst``) counts auth-endpoint writes per client — same TLS fingerprint *and* user agent,
or same IP *and* user agent, so customers behind one branch NAT never add up — inside a
60-second window. A real browser's user agent with a matching TLS handshake is every customer
on that browser build, so it is counted per IP + user agent; a browser user agent the handshake
contradicts (``shared/tls_client.py``) is a script and is counted, and challenged, by fingerprint. When the request being judged is itself one of them and the count reaches
``AEGIS_AUTH_BURST_MIN`` (8), the chain is built here without the LLM.

The response is deliberately soft and recoverable: ``challenge`` the client (a human passes a
managed challenge; a stuffing bot does not) and ``throttle`` its IP, both auto-safe, plus an
``escalate`` so an analyst looks at which accounts were tried. No block: the same burst from a
customer retyping a password on a slow link must cost them a challenge, not access.
"""

from __future__ import annotations

import os

from ..shared.client_actions import looks_like_browser
from ..shared.evidence_chain import EvidenceChain, EvidenceItem, ReasoningStep, RecommendedAction
from ..shared.fingerprint import allowed_fingerprints, client_fingerprint
from ..shared.tls_client import spoofed_browser

MIN_ATTEMPTS = int(os.environ.get("AEGIS_AUTH_BURST_MIN", "8"))


def _burst(alert: dict) -> dict:
    cc = alert.get("campaign_context")
    return (cc.get("auth_burst") or {}) if isinstance(cc, dict) else {}


def is_auth_burst(alert: dict) -> bool:
    b = _burst(alert)
    return bool(b.get("current_is_auth_write")) and int(b.get("attempts") or 0) >= MIN_ATTEMPTS


def auth_burst_chain(alert: dict) -> EvidenceChain:
    b = _burst(alert)
    n = int(b.get("attempts") or 0)
    conf = min(0.80 + 0.01 * (n - MIN_ATTEMPTS), 0.90)
    chain = EvidenceChain(alert_id=str(alert.get("id", "unknown")), investigated_by="auth_burst",
                          verdict="malicious", confidence=conf)
    chain.evidence.append(EvidenceItem(
        source="campaign_context", weight="high",
        signal=(f"{n} auth submissions in {b.get('window_s')} s from one client ({b.get('client')}), median gap "
                f"{b.get('median_gap_s')} s, {b.get('distinct_ips', 1)} IP(s), endpoints {', '.join(b.get('endpoints') or [])}"),
        raw_data={"auth_burst": b}))
    chain.reasoning.append(ReasoningStep(step=1, action="Credential-stuffing fast path (no LLM verdict)",
                                         observation="Auth-form submissions at machine rate from one client; no WAF signature applies",
                                         conclusion="malicious — respond with recoverable friction, not a block"))
    ip = str(alert.get("source_ip") or "")
    if ip:
        chain.recommended_actions.append(RecommendedAction(
            action_type="throttle", target=ip, requires_hitl=False, confidence=conf,
            reasoning="Rate-limit the IP submitting the auth form at machine rate"))
    fp = client_fingerprint(alert)
    # a browser user agent is followed by fingerprint only when the TLS handshake contradicts it
    # (then the pair is a script's, not every customer on that browser build)
    spoof = spoofed_browser(alert)
    if (fp is not None and fp.strength == "tls" and fp.value not in allowed_fingerprints()
            and (spoof is not None or not looks_like_browser(fp.user_agent))):
        chain.recommended_actions.append(RecommendedAction(
            action_type="challenge", target=fp.target(with_user_agent=True), requires_hitl=False, confidence=conf,
            reasoning="Challenge the client wherever it rotates to: same TLS fingerprint and exact user agent"
                      + (f" (it claims {spoof.get('claimed')}; its TLS stack is not a browser's)" if spoof else "")))
    elif ip:
        chain.recommended_actions.append(RecommendedAction(
            action_type="challenge", target=ip, requires_hitl=False, confidence=conf,
            reasoning="Challenge the IP — a human passes a managed challenge, a stuffing bot does not"))
    chain.recommended_actions.append(RecommendedAction(
        action_type="escalate", target=str(alert.get("id", "unknown")), requires_hitl=True, confidence=conf,
        reasoning="Credential stuffing in progress — review which accounts were tried and force resets where a login succeeded"))
    chain.metadata["auth_burst"] = b
    return chain.finalize()


__all__ = ["is_auth_burst", "auth_burst_chain", "MIN_ATTEMPTS"]
