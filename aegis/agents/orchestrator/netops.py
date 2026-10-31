"""Network-fault fast path: the assurance detector's one root cause → a chain with closed-loop remediation.

``aegis.agents.netops.assurance`` has already done the correlation: one alert per root cause, the
downstream symptoms folded into it. This path turns that into an evidence chain — no LLM — and
proposes the remediation an operator would run, **shadow first, a human approves**:

    link_down            critical when devices are behind it; ``escalate`` (field dispatch: fibre / SFP /
                         far end) + ``monitor`` the peer; a redundant path, when the topology has one, is
                         noted so the operator knows the blast radius is already contained
    link_flap            ``interface_shutdown`` the flapping port (err-disable it before it takes the
                         routing adjacency down with it) + ``escalate`` to check the cable / optic
    adjacency_loss       ``escalate`` — check the peer, the link, and any recent change on either end
    bad_config_push      ``config_rollback`` to the golden / last-known-good + ``revoke_sessions`` for
                         the user who pushed without a ticket + ``escalate``: a change broke the network
    config_drift         no ticket → ``config_rollback`` + ``escalate``; ticketed → ``monitor`` (drift
                         is expected to be reconciled by the change)
    interface_errors     ``escalate`` (dirty optic / bad cable, fix before it flaps) + ``monitor``
    congestion           ``throttle`` is not ours to apply on a trunk — ``escalate`` to capacity / QoS,
                         ``monitor`` the port
    device_unreachable   critical when devices are behind it; ``escalate`` (power / console / OOB)
    device_restart / hardware_fault   ``escalate`` + ``snapshot_forensic`` (crashinfo / show tech)

Verdicts are operational, not security: a fault is ``malicious`` only when it is a **bad config push
with no ticket** or **drift with no ticket** (someone changed a device outside change control —
also what an attacker's foothold on a network device looks like); everything else is ``suspicious``
(needs an operator) or ``benign`` (a ticketed change). Every remediation waits for a human.
"""

from __future__ import annotations

from ..shared.evidence_chain import EvidenceChain, EvidenceItem, ReasoningStep, RecommendedAction


def is_network_fault(alert: dict) -> bool:
    return isinstance(alert, dict) and alert.get("alert_type") == "network_fault" and isinstance(alert.get("netops"), dict)


def network_fault_chain(alert: dict) -> EvidenceChain:
    n = dict(alert.get("netops") or {})
    fault, device, iface = str(n.get("fault") or "fault"), str(n.get("device") or alert.get("device") or "?"), n.get("iface")
    downstream, users = list(n.get("downstream") or []), int(n.get("users_affected") or 0)
    nd = int(n.get("downstream_count") or len(downstream))
    suppressed, ticket = int(n.get("suppressed") or 0), n.get("change_ticket")
    aid = str(alert.get("id", "unknown"))
    role, site = str(n.get("role") or alert.get("role") or "unknown"), alert.get("site")

    if fault in ("bad_config_push",) or (fault == "config_drift" and not ticket):
        verdict, conf = "malicious", 0.88 if fault == "bad_config_push" else 0.80
    elif fault == "config_drift":
        verdict, conf = "benign", 0.70
    elif fault in ("link_down", "device_unreachable"):
        verdict, conf = "suspicious", 0.90 if nd else 0.75
    elif fault in ("link_flap", "adjacency_loss", "hardware_fault", "device_restart"):
        verdict, conf = "suspicious", 0.80
    else:
        verdict, conf = "suspicious", 0.70

    chain = EvidenceChain(alert_id=aid, investigated_by="netops", verdict=verdict, confidence=conf)
    chain.evidence.append(EvidenceItem(
        source=str(alert.get("source") or "Network Assurance"), weight="high",
        signal=f"{fault.replace('_', ' ')} on {device}" + (f" {iface}" if iface else "") + f": {n.get('root_cause', '')}",
        raw_data={k: n.get(k) for k in ("fault", "device", "iface", "role", "peer", "protocol", "mnemonic", "msg", "transitions",
                                        "errors_per_min", "util_pct", "silent_s", "golden_hash", "config_hash", "change_ticket",
                                        "user", "source_ip")}))
    if nd:
        chain.evidence.append(EvidenceItem(
            source="topology", weight="high",
            signal=f"{nd} device(s) behind it lose their path to the core" + (f" — {users:,} users" if users else "")
                   + (": " + ", ".join(downstream[:6]) + (" …" if nd > 6 else "")),
            raw_data={"downstream": downstream[:64], "users_affected": users}))
    if suppressed:
        chain.evidence.append(EvidenceItem(
            source="correlation", weight="medium",
            signal=f"{suppressed} downstream alarm(s) folded into this one (" + ", ".join(dict.fromkeys(n.get("symptoms") or [])) + ")"))
    if fault in ("bad_config_push", "config_drift"):
        chain.evidence.append(EvidenceItem(
            source="change_control", weight="high" if not ticket else "low",
            signal=(f"change ticket {ticket}" if ticket else "no change ticket for this configuration change")
                   + (f"; changed by {n['user']}" if n.get("user") else "") + (f" from {n['source_ip']}" if n.get("source_ip") else "")))
    chain.reasoning.append(ReasoningStep(step=1, action="Network-fault fast path (no LLM verdict)",
                                         observation=str(n.get("root_cause") or fault), conclusion=verdict))

    def act(t: str, target: str, why: str, hitl: bool = True) -> None:
        chain.recommended_actions.append(RecommendedAction(action_type=t, target=target, requires_hitl=hitl, confidence=conf, reasoning=why))

    port = f"{device}:{iface}" if iface else device
    peer = n.get("peer")
    if fault == "link_down":
        act("escalate", aid, f"Dispatch: {iface or 'the link'} on {device}" + (f" to {peer}" if peer else "") + " is down — check the optic / fibre at both ends"
            + (f"; {nd} device(s) and {users:,} users are behind it" if nd else ""))
        if peer:
            act("monitor", str(peer), f"Watch {peer}: if its side reports the same port, the fault is the medium, not either device", hitl=False)
    elif fault == "link_flap":
        act("interface_shutdown", port, f"Shut {iface} on {device} ({n.get('transitions')} transitions): a flapping port churns the routing "
            "protocol on everything behind it — err-disable it until the cable / optic is replaced")
        act("escalate", aid, "Replace the optic or cable; re-enable the port once it holds link for 15 min")
    elif fault == "adjacency_loss":
        act("escalate", aid, f"{n.get('protocol') or 'Routing'} adjacency with {peer or 'the neighbour'} lost on {device}: "
            "check the link, the peer, and any configuration change on either end in the last hour")
        if peer:
            act("monitor", str(peer), f"Watch {peer} for its view of the session", hitl=False)
    elif fault == "bad_config_push":
        act("config_rollback", device, f"Roll {device} back to its golden / last-known-good configuration: a change with no ticket was followed "
            "by loss of connectivity")
        if n.get("user"):
            act("revoke_sessions", str(n["user"]), f"End {n['user']}'s device sessions until the change is explained — an untracked push to "
                "network gear is also what an attacker with a foothold does")
        act("escalate", aid, "Confirm with the network team who pushed the change and why; if nobody did, treat the device as compromised")
    elif fault == "config_drift":
        if ticket:
            act("monitor", device, f"Drift under ticket {ticket}: expected to be reconciled by the change", hitl=False)
        else:
            act("config_rollback", device, f"Running config on {device} no longer matches the golden and no ticket covers it: roll back")
            act("escalate", aid, "Find who changed it" + (f" ({n['user']})" if n.get("user") else "") + " and whether the golden should move")
    elif fault == "interface_errors":
        act("escalate", aid, f"{n.get('errors_per_min')} errors/min on {iface}: clean or replace the optic / cable before the port starts flapping")
        act("monitor", port, "Watch the error rate", hitl=False)
    elif fault == "congestion":
        act("escalate", aid, f"{iface} on {device} at {n.get('util_pct')}% sustained: capacity or QoS review; check for a backup job or a "
            "misrouted flow filling the trunk")
        act("monitor", port, "Watch utilisation and output discards", hitl=False)
    elif fault == "device_unreachable":
        act("escalate", aid, f"{device} silent for {n.get('silent_s')} s" + (f"; {nd} device(s) and {users:,} users behind it" if nd else "")
            + ": check power, the console / out-of-band, and the upstream port")
    else:
        act("escalate", aid, f"{fault.replace('_', ' ')} on {device}: {n.get('root_cause', '')}")
        act("snapshot_forensic", device, "Collect crashinfo / show tech before the evidence rolls over")

    chain.metadata["netops"] = {"fault": fault, "device": device, "iface": iface, "role": role, "site": site, "downstream": nd,
                                "users_affected": users, "suppressed": suppressed, "change_ticket": ticket}
    return chain.finalize()


__all__ = ["is_network_fault", "network_fault_chain"]
