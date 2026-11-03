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
from typing import Any, Tuple

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
    hosts = _never_block_hosts()
    if hosts:
        name = _host_of(t)
        # the listed host itself, anything under it, or a parent that would cover it ("examplebank.in" or
        # ".examplebank.in" blocks netbanking.examplebank.in); scheme, path, port, case and a trailing dot
        # no longer get a listed host past the guard
        for h in hosts:
            h = h.rstrip(".")
            if name and (name == h or name.endswith("." + h) or h.endswith("." + name)):
                return True, f"{t} covers {h}, which is on AEGIS_NEVER_BLOCK_HOSTS"
    host = t.strip("[]")
    # strip a :port off a bare IPv4 like 127.0.0.1:8787 (IPv6 has >1 colon, left intact); [v6]:port too
    if host.count(":") == 1 and "." in host and host.rsplit(":", 1)[1].isdigit():
        host = host.rsplit(":", 1)[0]
    elif host.startswith("[") or ("]:" in t):
        host = t.split("]")[0].lstrip("[")
    try:
        net = ipaddress.ip_network(host, strict=False)
    except ValueError:
        return False, ""  # not an IP/CIDR — out of scope here
    for cand in {net, unwrap(net)}:
        for n in _HARD_NETS + _extra_nets():
            # overlap, not only subset: a supernet (0.0.0.0/0, 126.0.0.0/7) covers protected space too
            if cand.version == n.version and cand.overlaps(n):
                return True, f"{t}: covers loopback/reserved/operator-listed space — never blocked (would risk own infra)"
    return False, ""


def unwrap(addr: Any) -> Any:
    """The IPv4 address hiding in an IPv4-mapped (::ffff:a.b.c.d), 6to4 (2002::/16) or NAT64 (64:ff9b::/96)
    IPv6 address — otherwise ``addr`` unchanged. Works for addresses and networks."""
    if isinstance(addr, (ipaddress.IPv6Network,)):
        inner = unwrap(addr.network_address)
        if inner is not addr.network_address and isinstance(inner, ipaddress.IPv4Address):
            if addr.network_address.ipv4_mapped is not None or addr.network_address in _NAT64:
                bits = max(0, addr.prefixlen - 96)
            else:                                  # 6to4 carries the v4 address in bits 16..48
                bits = max(0, min(32, addr.prefixlen - 16))
            return ipaddress.ip_network(f"{inner}/{bits}", strict=False)
        return addr
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return addr.ipv4_mapped
        if addr.sixtofour is not None:
            return addr.sixtofour
        if addr in _NAT64:
            return ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    return addr


_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def _host_of(t: str) -> str:
    import re as _re
    h = _re.sub(r"^[a-z][a-z0-9+.-]*://", "", t.strip().lower())
    h = h.split("/", 1)[0].split("?", 1)[0]
    if h.count(":") == 1:
        h = h.split(":", 1)[0]
    return h.strip(".").lstrip("*.")


def enforcement_refused(action_type: str, target: str) -> Tuple[bool, str]:
    """``(refuse, reason)``. True when this action against this target must be refused.

    Gates only the connectivity-severing ``DENY_ACTIONS``; everything else passes through.
    """
    if str(action_type) not in DENY_ACTIONS:
        return False, ""
    return never_block_target(target)


__all__ = ["never_block_target", "enforcement_refused", "DENY_ACTIONS"]
