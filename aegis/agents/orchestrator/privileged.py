"""Privileged-identity guard: engineers with production reach, and the crown jewels they can touch.

Attackers aim at DevOps, SRE, DevSecOps and platform engineers because their laptops carry the keys
to production — deploy credentials, kube tokens, cloud keys, access to the payment signer. The Oct
2026 Binance drain began on a DevOps engineer's laptop. A generic triage treats those events like
any other host or web alert; this path treats them as crown-jewel incidents, without the LLM:

  1. endpoint compromise on a privileged host or identity (EDR: credential-store read, tamper,
     sensor stopped, token theft)  ->  malicious; isolate the host, revoke the engineer's sessions,
     rotate their production credentials — assume what the laptop could reach is in other hands
  2. interactive access to a crown jewel (exec / ssh / console into a payment, signer, HSM, SWIFT,
     treasury, vault or KMS system) scored on: outside the change window, no change ticket, a
     source never used before, an actor who is not a known engineer  ->  malicious at >= 2 signals
  3. a control change on a crown jewel (signing policy, beneficiary allowlist, limits, delegation,
     key policy) scored on: no change ticket, outside the window, no dual control  ->  malicious
     at >= 2 signals; hold the signer's outbound payments and revert the change

Who is privileged: ``AEGIS_PRIVILEGED_USERS`` / ``AEGIS_PRIVILEGED_HOSTS`` (comma-separated; export
them from the IdP's engineering groups and the asset inventory), or a role field on the alert naming
devops / devsecops / sre / platform. Crown jewels: ``AEGIS_CROWN_JEWELS`` (comma-separated
substrings; default payment, signer, hsm, swift, treasury, vault, kms, core-banking). Every
containment waits for a human: these are the bank's own engineers.
"""

from __future__ import annotations

import os
import re
from typing import Any

from ..shared.evidence_chain import EvidenceChain, EvidenceItem, ReasoningStep, RecommendedAction

_ROLE_KEYS = ("user_role", "role", "host_role", "groups", "department", "team")
_ROLE_RX = re.compile(r"\b(devops|devsecops|sre|site[-_ ]reliability|platform[-_ ]eng(ineering)?|platform)\b", re.I)
_DEFAULT_JEWELS = "payment,signer,hsm,swift,treasury,vault,kms,core-banking,corebanking"
_EDR_SOURCES = ("crowdstrike", "falcon", "defender", "sentinelone", "sophos", "carbon black", "edr", "osquery", "sysmon")
_COMPROMISE_EVENTS = {"credential_store_access", "credential_store_read", "lsass_access", "token_theft",
                      "browser_cookie_theft", "infostealer", "tamper_protection_disabled", "sensor_service_stopped",
                      "keychain_dump", "ssh_key_read", "kubeconfig_read"}
_CREDENTIAL_EVENTS = {"credential_store_access", "credential_store_read", "lsass_access", "token_theft",
                      "browser_cookie_theft", "infostealer", "keychain_dump", "ssh_key_read", "kubeconfig_read"}
_ACCESS_EVENTS = {"pods/exec", "pods/attach", "exec", "ssh", "ssh_login", "console_login", "rdp", "session_start",
                  "kubectl_exec", "interactive_login", "sudo"}
_CONTROL_EVENTS = {"signing_policy_changed", "beneficiary_allowlist_updated", "allowlist_changed", "limit_changed",
                   "delegation_granted", "key_policy_changed", "role_binding_created", "clusterrolebinding_created",
                   "approval_rule_changed", "dual_control_disabled"}


def _csv(name: str, default: str = "") -> tuple[str, ...]:
    return tuple(x.strip().lower() for x in os.environ.get(name, default).split(",") if x.strip())


def _s(alert: dict, *keys: str) -> str:
    for k in keys:
        v = alert.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def _user(alert: dict) -> str:
    return _s(alert, "user", "user_id", "principal", "actor_user", "username")


def _host(alert: dict) -> str:
    return _s(alert, "host", "hostname", "device", "src_host")


def is_privileged_user(user: str, alert: dict | None = None) -> bool:
    if user and user.lower() in _csv("AEGIS_PRIVILEGED_USERS"):
        return True
    return bool(alert) and any(_ROLE_RX.search(str((alert or {}).get(k) or "")) for k in _ROLE_KEYS if k != "host_role")


def is_privileged_host(host: str, alert: dict | None = None) -> bool:
    if host and host.lower() in _csv("AEGIS_PRIVILEGED_HOSTS"):
        return True
    return bool(alert) and bool(_ROLE_RX.search(str((alert or {}).get("host_role") or "")))


def _crown(*texts: str) -> str:
    """The crown-jewel keyword a target names, or ''."""
    jewels = _csv("AEGIS_CROWN_JEWELS", _DEFAULT_JEWELS)
    hay = " ".join(t.lower() for t in texts if t)
    return next((j for j in jewels if j in hay), "")


def _events(alert: dict) -> set[str]:
    out = {str(alert.get(k) or "").strip().lower() for k in ("event", "prior_event_30m", "action", "verb_resource")}
    res, verb = str(alert.get("resource") or "").lower(), str(alert.get("verb") or "").lower()
    if res:
        out.add(res)
    if verb and res:
        out.add(f"{verb}:{res}")
    return {e for e in out if e}


def _kind(alert: dict) -> str:
    if not isinstance(alert, dict):
        return ""
    ev = _events(alert)
    target_text = " ".join(_s(alert, k) for k in ("namespace", "name", "target", "system", "dest_host", "resource_name",
                                                   "initiated_from", "actor", "source"))
    if ev & _CONTROL_EVENTS and _crown(target_text):
        return "control_change"
    if ev & _ACCESS_EVENTS and _crown(target_text) and "Core Banking" not in str(alert.get("source", "")):
        return "crown_access"
    src = str(alert.get("source") or "").lower()
    if ev & _COMPROMISE_EVENTS and any(s in src for s in _EDR_SOURCES):
        maint = ((alert.get("context") or {}).get("maintenance_window") or {}) if isinstance(alert.get("context"), dict) else {}
        if isinstance(maint, dict) and maint.get("covers_host"):
            return ""                                   # a ticketed maintenance stop is not this path's
        if is_privileged_host(_host(alert), alert) or is_privileged_user(_user(alert), alert):
            return "endpoint"
    return ""


def is_privileged_event(alert: dict) -> bool:
    return bool(_kind(alert))


def _missing(v: Any) -> bool:
    return v is None or (isinstance(v, str) and not v.strip())


def privileged_chain(alert: dict) -> EvidenceChain:
    kind = _kind(alert) or "endpoint"
    user, host, aid = _user(alert), _host(alert), str(alert.get("id", "unknown"))
    signals: list[str] = []
    if kind == "endpoint":
        ev = _events(alert)
        cred = bool(ev & _CREDENTIAL_EVENTS)
        blind = bool(ev & {"tamper_protection_disabled", "sensor_service_stopped"})
        if cred:
            signals.append("credential material read on the machine")
        if blind:
            signals.append("endpoint protection switched off")
        verdict, conf = ("malicious", 0.92) if (cred and blind) else ("malicious", 0.88) if cred else ("suspicious", 0.80)
        why = f"compromise indicators on the machine of an engineer with production access ({host or user})"
    elif kind == "crown_access":
        jewel = _crown(_s(alert, "namespace"), _s(alert, "name"), _s(alert, "target"), _s(alert, "system"), _s(alert, "dest_host"))
        if alert.get("outside_change_window") is True:
            signals.append("outside the change window")
        if "change_ticket" in alert and _missing(alert.get("change_ticket")):
            signals.append("no change ticket")
        if any(alert.get(k) is True for k in ("first_seen_source_ip_for_user", "new_device", "first_seen_device")):
            signals.append("from a source never used for production access")
        if user and not is_privileged_user(user, alert):
            signals.append(f"{user} is not a known engineer")
        verdict, conf = (("malicious", 0.88) if len(signals) >= 2 else ("suspicious", 0.72) if signals else ("benign", 0.65))
        why = f"interactive access to a {jewel} system by {user or 'an unknown identity'}"
    else:   # control_change
        jewel = _crown(_s(alert, "initiated_from"), _s(alert, "actor"), _s(alert, "source"), _s(alert, "target"), _s(alert, "system"))
        if "change_ticket" in alert and _missing(alert.get("change_ticket")):
            signals.append("no change ticket")
        if alert.get("outside_change_window") is True:
            signals.append("outside the change window")
        if alert.get("dual_control") is False:
            signals.append("no dual control")
        verdict, conf = (("malicious", 0.93) if len(signals) >= 2 else ("suspicious", 0.75) if signals else ("benign", 0.65))
        why = f"control change on a {jewel} system: {str(alert.get('change') or alert.get('event'))[:160]}"

    chain = EvidenceChain(alert_id=aid, investigated_by="privileged", verdict=verdict, confidence=conf)
    chain.evidence.append(EvidenceItem(source=str(alert.get("source") or "audit"), weight="high" if verdict == "malicious" else "medium",
                                       signal=why, raw_data={"kind": kind, "user": user, "host": host}))
    for s in signals:
        chain.evidence.append(EvidenceItem(source="privileged_guard", weight="high", signal=s))
    chain.reasoning.append(ReasoningStep(step=1, action="Privileged-identity fast path (no LLM verdict)",
                                         observation=f"{why}; signals: {', '.join(signals) or 'none'}", conclusion=verdict))

    def act(t: str, target: str, why_: str) -> None:
        chain.recommended_actions.append(RecommendedAction(action_type=t, target=target, requires_hitl=t != "monitor",
                                                           confidence=conf, reasoning=why_))

    if verdict == "benign":
        act("monitor", user or host or aid, "Ticketed, in-window access by a known engineer — keep it on the record")
    elif kind == "endpoint":
        if host:
            act("isolate", host, f"Isolate {host}: it holds an engineer's production access")
        if user:
            act("revoke_sessions", user, f"Revoke {user}'s sessions everywhere — SSO, cloud console, kube, VPN")
            act("rotate_credential", user, f"Rotate what {user} could use: deploy keys, kube tokens, cloud keys, signing credentials")
        act("escalate", aid, "Review everything this identity touched in production in the last 72 h")
    elif kind == "crown_access":
        if user:
            act("revoke_sessions", user, f"End {user}'s session on the {_crown(_s(alert, 'namespace'), _s(alert, 'name'))} system now")
        act("escalate", aid, "Confirm with the engineer out of band; check the signer's audit log for changes made in this session")
    else:
        signer = _s(alert, "actor", "initiated_from") or "the signer"
        act("hold", f"outbound:{signer}", f"Hold payments signed by {signer} until the change is reviewed and reverted")
        act("rotate_credential", signer, f"Rotate {signer}'s credentials: a widened policy means someone could drive it")
        if user:
            act("revoke_sessions", user, f"Revoke {user}'s sessions while the change is reviewed")
        act("escalate", aid, "Revert the change: it widens what the signer is allowed to pay")
    chain.metadata["privileged"] = {"kind": kind, "user": user, "host": host, "signals": signals}
    return chain.finalize()


__all__ = ["is_privileged_event", "is_privileged_host", "is_privileged_user", "privileged_chain"]
