"""What an action may touch when no human approves it.

A specialist's recommended action comes from a model that read attacker-controlled text. With a person in
the loop that is fine — the analyst sees the target. Without one (auto-safe actions, tiered auto-block, the
outflow breaker, the HITL-timeout fallback) three checks apply (code review 2026-11-03, W1/W2/W3/W8/W14):

* **grounded** — the target must be one of the alert's own entities (a source IP, a user, a host, a
  fingerprint, a sender account), or a narrow network containing one. ``throttle 0.0.0.0/0`` or
  ``force_logout svc_payments`` written into a payload is not in the alert, so it waits for a human.
* **narrow** — an IP target is at most a /24 (IPv4) or /48 (IPv6), never internal or reserved space; a
  domain needs at least two labels; a principal is never on ``AEGIS_UNATTENDED_DENY_PRINCIPALS``
  (``admin``, ``root``, service accounts …).
* **no injection** — when the chain carries prompt-injection evidence, nothing runs unattended.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import os
import re
from typing import Any

from ..shared.netguard import unwrap

_IP_RX = re.compile(r"(?<![\w.:])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|(?<![\w:])[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}(?![\w:])")
_PREFIXES = ("host:", "user:", "session:", "device:", "account:", "outbound:", "principal:", "url:", "domain:")

_INTERNAL = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4", "::1/128", "::/128", "fc00::/7", "fe80::/10", "ff00::/8")]
# two-label public suffixes a destination block must never be (blocking "co.in" blocks every .co.in site)
_SHARED_SUFFIXES = {"co.in", "net.in", "org.in", "gov.in", "nic.in", "ac.in", "res.in", "firm.in", "gen.in", "ind.in",
                    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.jp", "com.sg", "com.br", "co.za"}
_DEFAULT_DENY = "admin,administrator,root,krbtgt,system,sa,svc_*,svc-*,service-*,*$,domain admins,enterprise admins"




def _internal_nets() -> list:
    extra = []
    for tok in os.environ.get("AEGIS_INTERNAL_NETS", "").replace(";", ",").split(","):
        try:
            extra.append(ipaddress.ip_network(tok.strip(), strict=False))
        except ValueError:
            continue
    return _INTERNAL + extra


def is_internal(net: Any) -> bool:
    """True when the network touches internal / reserved space at all (overlap, not only subset)."""
    net = unwrap(net)
    return any(net.version == n.version and net.overlaps(n) for n in _internal_nets())


def _strip(target: str) -> str:
    t = str(target or "").strip()
    low = t.lower()
    for p in _PREFIXES:
        if low.startswith(p):
            return t[len(p):].strip()
    return t


def _as_net(t: str):
    try:
        return unwrap(ipaddress.ip_network(t.strip().strip("[]"), strict=False))
    except ValueError:
        return None


def narrow(action_type: str, target: str) -> tuple[bool, str]:
    """Is this target narrow enough to act on with no human?"""
    from ..shared.fingerprint import is_fingerprint_target
    t = _strip(target)
    if not t:
        return False, "empty target"
    if is_fingerprint_target(t):
        return True, ""                       # autonomy._narrow_external judges fingerprints for block
    net = _as_net(t)
    if net is not None:
        if net.prefixlen < (24 if net.version == 4 else 48):
            return False, f"{t}: /{net.prefixlen} is wider than an unattended action may touch"
        if is_internal(net):
            return False, f"{t} is internal / reserved space — never acted on without a human"
        return True, ""
    low = t.lower().rstrip(".")
    if action_type in ("block_egress", "block") and ("." in low or "/" in low):
        host = re.sub(r"^[a-z][a-z0-9+.-]*://", "", low).split("/", 1)[0].split(":", 1)[0].strip(".").lstrip("*.")
        labels = [x for x in host.split(".") if x]
        if len(labels) < 2 or ".".join(labels) in _SHARED_SUFFIXES or ".".join(labels[-2:]) == host and labels[0] in ("www",):
            return False, f"{t} is too broad a destination"
        return True, ""
    deny = [d.strip().lower() for d in os.environ.get("AEGIS_UNATTENDED_DENY_PRINCIPALS", _DEFAULT_DENY).split(",") if d.strip()]
    if any(fnmatch.fnmatch(low, d) for d in deny):
        return False, f"{t} is a privileged / service principal — never acted on without a human"
    return True, ""


def alert_entities(alert: Any, *, depth: int = 4) -> tuple[set[str], list]:
    """Lower-cased scalar values of the alert (and IPs found inside them), for grounding checks."""
    values: set[str] = set()
    ips: list = []

    def walk(o: Any, d: int) -> None:
        if d < 0 or len(values) > 5000:
            return
        if isinstance(o, dict):
            for v in o.values():
                walk(v, d - 1)
        elif isinstance(o, (list, tuple)):
            for v in o[:200]:
                walk(v, d - 1)
        elif isinstance(o, (str, int)) and not isinstance(o, bool):
            s = str(o).strip()
            if s and len(s) <= 2048:
                values.add(s.lower())
                for m in _IP_RX.findall(s)[:20]:
                    a = _as_net(m)
                    if a is not None:
                        ips.append(a)
    walk(alert, depth)
    return values, ips


def grounded(target: str, entities: tuple[set[str], list]) -> tuple[bool, str]:
    """Is the target one of the alert's own entities (or a narrow network around one)?"""
    from ..shared.fingerprint import is_fingerprint_target, parse_target
    values, ips = entities
    t = _strip(target)
    if not t:
        return False, "empty target"
    if is_fingerprint_target(t):
        try:
            _kind, value, ua = parse_target(t)
        except ValueError:
            return False, "malformed fingerprint target"
        if str(value).lower() in values and (not ua or ua.lower() in values):
            return True, ""
        return False, "fingerprint not present in the alert"
    net = _as_net(t)
    if net is not None:
        if any(a.version == net.version and a.subnet_of(net) for a in ips):
            return True, ""
        return False, f"{t} is not an address in the alert"
    if t.lower() in values:
        return True, ""
    return False, f"{t!r} does not appear in the alert"


def injection_flagged(chain: Any) -> bool:
    if any(getattr(e, "source", "") == "injection_defense" for e in getattr(chain, "evidence", None) or []):
        return True
    md = getattr(chain, "metadata", None) or {}
    tm = md.get("_triage_metadata") or md.get("triage_metadata") or {}
    return bool(isinstance(tm, dict) and tm.get("injection_detected"))


def unattended_ok(action: Any, chain: Any, entities: tuple[set[str], list] | None) -> tuple[bool, str]:
    """All three checks for one action that would run with no human. ``entities`` None = no alert to check
    against (a caller that did not pass it): grounding cannot be shown, so the action waits for a human."""
    if injection_flagged(chain):
        return False, "prompt-injection evidence on this chain — nothing runs unattended"
    ok, why = narrow(str(action.action_type), str(action.target))
    if not ok:
        return False, why
    if entities is None:
        return False, "no alert to ground the target against"
    return grounded(str(action.target), entities)


def chain_entities(chain: Any) -> tuple[set[str], list]:
    """Fallback entity set from the chain's own evidence when the raw alert is not available."""
    raw: list[Any] = [getattr(e, "raw_data", None) for e in getattr(chain, "evidence", None) or []]
    return alert_entities(raw)


__all__ = ["alert_entities", "chain_entities", "grounded", "injection_flagged", "is_internal", "narrow",
           "unattended_ok", "unwrap"]

