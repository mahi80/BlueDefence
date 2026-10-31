"""Actions on the *client* behind a confirmed-hostile request — shared by every fast path.

A confirmed attacker (decoy touch, retry-after-stop, control-plane fact) is a client, not an
IP: it will rotate IPs the moment one is blocked. So besides ``block <current IP>`` the chain
carries, when it is safe, an action on the client's TLS fingerprint:

    block     fp:<kind>:<value>;ua:<exact UA>   one non-browser user agent → the whole proxy pool
    challenge fp:<kind>:<value>                 rotating user agents → bare fingerprint, which real
                                                browsers pass and bots fail
    challenge fp:<kind>:<value>;ua:<exact UA>   a *browser* user agent the TLS handshake contradicts
                                                (``shared/tls_client.py``): only clients telling the
                                                same lie match, and a real browser would pass

and never when the fingerprint could be customers or trusted automation:
- the exact client (fingerprint + user agent) is seen on ≥ ``BENIGN_SHARE_LIMIT`` benign clients
  in the campaign window — for a composite target;
- the bare fingerprint is, in the window or in the estate's longer memory of benign traffic
  (``shared/tls_client.py``) — for a bare-fingerprint challenge;
- the user agent is a ``Mozilla/`` one that the TLS handshake does *not* contradict (an agent
  driving a real browser looks exactly like a customer);
- a header-order fingerprint (correlation only), or one in ``AEGIS_FP_ALLOW``.
A spoofed browser user agent is not held back by benign sharing: the "benign" requests carrying
that exact lie are the agent's own quiet ones (a partner integration that spoofs a browser goes
on ``AEGIS_FP_ALLOW``). ``requires_hitl`` is left False: whether a block runs without a human is
the response agent's autonomy policy, which is stricter than any single chain.
"""

from __future__ import annotations

from typing import Optional

from .evidence_chain import EvidenceItem, RecommendedAction
from .fingerprint import allowed_fingerprints, client_fingerprint
from .tls_client import spoofed_browser

BENIGN_SHARE_LIMIT = 2


def looks_like_browser(user_agent: str) -> bool:
    return str(user_agent or "").startswith("Mozilla/")


def campaign_identity(alert: dict) -> dict:
    cc = alert.get("campaign_context")
    return (cc.get("identity") or {}) if isinstance(cc, dict) else {}


def client_actions(alert: dict, *, confidence: float, why: str, identity: Optional[dict] = None,
                   evidence: Optional[list[EvidenceItem]] = None) -> list[RecommendedAction]:
    """``block <ip>`` plus the fingerprint action that is safe for this client, or an evidence
    line (appended to ``evidence`` when given) saying why the fingerprint is left alone."""
    ident = identity if identity is not None else campaign_identity(alert)
    fp = client_fingerprint(alert)
    out: list[RecommendedAction] = []
    ip = str(alert.get("source_ip") or "")
    if ip:
        out.append(RecommendedAction(action_type="block", target=ip, requires_hitl=False, confidence=confidence,
                                     reasoning=f"{why}: current IP of the client"))
    if fp is None or fp.strength != "tls":
        return out

    def hold(why_not: str) -> list[RecommendedAction]:
        if evidence is not None:
            evidence.append(EvidenceItem(source="client_fingerprint", weight="low",
                                         signal=f"Fingerprint not enforced: {why_not} — acting on the IP only"))
        return out

    if fp.value in allowed_fingerprints():
        return hold("on AEGIS_FP_ALLOW")
    # the bare fingerprint: the campaign window, and the estate's long memory of who presents it
    shared_fp = max(int(ident.get("benign_ips_sharing_fingerprint") or 0),
                    int(ident.get("known_benign_ips_for_fingerprint") or 0))
    shared_client = int(ident.get("benign_ips_sharing_client", shared_fp) or 0)
    spoof = spoofed_browser(alert)
    if spoof is not None:
        if evidence is not None:
            evidence.append(EvidenceItem(source="tls_client", weight="high",
                                         signal=(f"User agent claims {spoof.get('claimed')} but the TLS handshake is not a "
                                                 f"browser's: {'; '.join(spoof.get('reasons') or [])}"),
                                         raw_data={"tls_client": spoof}))
        out.append(RecommendedAction(action_type="challenge", target=fp.target(with_user_agent=True), requires_hitl=False,
                                     confidence=confidence,
                                     reasoning=(f"{why}: the user agent claims {spoof.get('claimed')} but the TLS stack is not "
                                                "a browser's — challenge that exact pair wherever it rotates; a real browser "
                                                "never presents it and would pass")))
        return out
    if looks_like_browser(fp.user_agent):
        return hold("mainstream browser user agent and a matching TLS handshake — a fingerprint action could hit customers")
    single_ua = bool(fp.user_agent) and int(ident.get("distinct_user_agents") or 1) <= 1
    if single_ua:
        if shared_client >= BENIGN_SHARE_LIMIT:
            return hold(f"this TLS fingerprint with this exact user agent is seen on {shared_client} benign clients")
        out.append(RecommendedAction(action_type="block", target=fp.target(with_user_agent=True), requires_hitl=False,
                                     confidence=confidence,
                                     reasoning=f"{why}: follows the client across its proxy pool — same TLS fingerprint and exact user agent"))
    elif shared_fp >= BENIGN_SHARE_LIMIT:
        return hold(f"the client rotates user agents and its TLS fingerprint is seen on {shared_fp} benign clients "
                    "(this window or earlier) — a bare-fingerprint challenge would hit them")
    else:
        out.append(RecommendedAction(action_type="challenge", target=fp.target(with_user_agent=False), requires_hitl=False,
                                     confidence=confidence,
                                     reasoning=f"{why}: client rotates user agents; a bare TLS fingerprint is shared by real browsers, so challenge (browsers pass) rather than block"))
    return out


__all__ = ["client_actions", "campaign_identity", "looks_like_browser", "BENIGN_SHARE_LIMIT"]
