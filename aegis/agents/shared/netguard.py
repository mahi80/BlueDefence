"""Never-block guardrail — enforcement must never cut off its own infra or the lab.

A response action that severs or quarantines a target *by address* (block, isolate,
throttle, …) is refused — for AUTO and HUMAN-APPROVED actions alike — when the target is:

  * loopback (``127.0.0.0/8``, ``::1``): in a loopback lab this is the SOC's own ingest,
    the shim's alert sink and every agent's source address, so a block here blinds the SOC
    mid-run; it is never a real attacker either way;
  * link-local / unspecified / multicast / reserved space: never a valid unicast target;
  * anything the operator lists in ``AEGIS_NEVER_BLOCK`` (CIDRs — e.g. the SOC's own prod
    subnet / management plane) or ``AEGIS_NEVER_BLOCK_HOSTS`` (host names).

This is deliberately NARROWER than the auto-block guard in ``autonomy.py``: a human may
legitimately isolate a *compromised internal host* (RFC1918), so private space is **not**
refused here — only the ranges that are never a valid enforcement target. Non-address
targets (attacker host names, TLS fingerprints, user principals) are out of scope and pass
through — this guard is specifically about not shooting your own infra by IP.
"""

from __future__ import annotations

import ipaddress
import os
from typing import Tuple

# Never a valid enforcement target, even on human approval. RFC1918 is deliberately absent
# (isolating a compromised internal host is a core SOC action and must stay possible).
_HARD_NETS = [ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "::1/128",                    # loopback
    "0.0.0.0/8", "::/128",                       # unspecified
    "169.254.0.0/16", "fe80::/10",               # link-local
    "224.0.0.0/4", "240.0.0.0/4", "ff00::/8",    # multicast / reserved
)]

# Actions that cut a target off or quarantine it by address — the self-DoS risk set.
# Non-address actions (challenge, monitor, escalate, revoke_sessions, lock_account …) are
# not gated here: they do not sever infra, and the last two target a principal, not an IP.
DENY_ACTIONS = frozenset({
    "block", "block_egress", "isolate", "throttle", "quarantine", "drop", "sinkhole",
})


def _extra_nets() -> list:
    out = []
    for tok in os.environ.get("AEGIS_NEVER_BLOCK", "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            out.append(ipaddress.ip_network(tok, strict=False))
        except ValueError:
            continue  # a malformed operator entry must not crash enforcement
    return out


def _never_block_hosts() -> set:
    return {h.strip().lower() for h in os.environ.get("AEGIS_NEVER_BLOCK_HOSTS", "").split(",") if h.strip()}


def never_block_target(target: str) -> Tuple[bool, str]:
    """``(refuse, reason)``. True when enforcing against this target would risk own/lab infra.

    Only IP / CIDR targets and operator-named hosts match; attacker host names, fingerprints
    and principals return ``(False, "")`` — out of scope for this guard.
    """
    t = str(target or "").strip()
    if not t:
        return False, ""
    if t.lower() in _never_block_hosts():
        return True, f"{t} is on AEGIS_NEVER_BLOCK_HOSTS"
    host = t
    # strip a :port off a bare IPv4 like 127.0.0.1:8787 (IPv6 has >1 colon, left intact)
    if host.count(":") == 1 and "." in host and host.rsplit(":", 1)[1].isdigit():
        host = host.rsplit(":", 1)[0]
    try:
        net = ipaddress.ip_network(host, strict=False)
    except ValueError:
        return False, ""  # not an IP/CIDR — out of scope here
    for n in _HARD_NETS + _extra_nets():
        if net.version == n.version and net.subnet_of(n):
            return True, f"{t}: loopback/reserved/operator-listed — never blocked (would risk own infra)"
    return False, ""


def enforcement_refused(action_type: str, target: str) -> Tuple[bool, str]:
    """``(refuse, reason)``. True when this action against this target must be refused.

    Gates only the connectivity-severing ``DENY_ACTIONS``; everything else passes through.
    """
    if str(action_type) not in DENY_ACTIONS:
        return False, ""
    return never_block_target(target)


__all__ = ["never_block_target", "enforcement_refused", "DENY_ACTIONS"]
