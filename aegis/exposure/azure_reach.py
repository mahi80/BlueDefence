"""Azure reachability for the exposure engine: VMs, their NICs, subnet + NIC NSGs, public load balancers.

NSGs are evaluated the way Azure does: rules (custom + the built-in defaults) in priority order, the
first rule matching the source and port decides. Inbound traffic must be allowed by the **subnet** NSG
*and* the **NIC** NSG when both exist. With no NSG at all a Standard-SKU public IP is closed to the
internet (secure by default), while traffic inside the VNet is open.

Input: the Azure posture bundle (``python -m aegis.posture export-azure``), which carries
``virtual_machines``, ``network_interfaces``, ``virtual_networks``, ``network_security_groups`` and
``load_balancers``.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from ..agents.orchestrator.walkers.graph import SENSITIVITY
from .engine import ALL_PORTS, Asset, PortRanges

INTERNET_SRC = {"*", "internet", "any", "0.0.0.0/0", "::/0"}
VNET_SRC = {"*", "virtualnetwork", "any"}
PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")]

# Azure's built-in inbound rules, appended when an export omits defaultSecurityRules.
DEFAULT_INBOUND = [
    {"name": "AllowVnetInBound", "priority": 65000, "direction": "Inbound", "access": "Allow",
     "sourceAddressPrefix": "VirtualNetwork", "destinationPortRange": "*"},
    {"name": "AllowAzureLoadBalancerInBound", "priority": 65001, "direction": "Inbound", "access": "Allow",
     "sourceAddressPrefix": "AzureLoadBalancer", "destinationPortRange": "*"},
    {"name": "DenyAllInBound", "priority": 65500, "direction": "Inbound", "access": "Deny",
     "sourceAddressPrefix": "*", "destinationPortRange": "*"},
]


def _p(o: dict) -> dict:
    return {**o, **(o.get("properties") or {})}


def _id(x: Any) -> str:
    return str((x or {}).get("id") if isinstance(x, dict) else x or "").lower()


# ---- interval arithmetic --------------------------------------------------------------------------

def _subtract(r: tuple[int, int], taken: PortRanges) -> PortRanges:
    out = [r]
    for lo, hi in taken:
        nxt = []
        for a, b in out:
            if hi < a or lo > b:
                nxt.append((a, b))
                continue
            if a < lo:
                nxt.append((a, lo - 1))
            if b > hi:
                nxt.append((hi + 1, b))
        out = nxt
    return out


def _intersect(x: PortRanges, y: PortRanges) -> PortRanges:
    return [(max(a, c), min(b, d)) for a, b in x for c, d in y if max(a, c) <= min(b, d)]


def _ports(rule: dict) -> PortRanges:
    vals = [rule.get("destinationPortRange")] + list(rule.get("destinationPortRanges") or [])
    out: PortRanges = []
    for v in vals:
        if v in (None, ""):
            continue
        if str(v) == "*":
            return list(ALL_PORTS)
        lo, _, hi = str(v).partition("-")
        try:
            out.append((int(lo), int(hi or lo)))
        except ValueError:
            continue
    return out


def _matches(rule: dict, src_class: str) -> bool:
    srcs = [rule.get("sourceAddressPrefix")] + list(rule.get("sourceAddressPrefixes") or [])
    for s in (str(x) for x in srcs if x is not None):
        low = s.lower()
        if src_class == "internet" and low in INTERNET_SRC:
            return True
        if src_class == "vnet":
            if low in VNET_SRC:
                return True
            try:
                net = ipaddress.ip_network(s, strict=False)
                if any(net.subnet_of(p) for p in PRIVATE if p.version == net.version):
                    return True
            except ValueError:
                pass
    return False


def nsg_allowed(nsg: dict | None, src_class: str) -> PortRanges | None:
    """Ports this NSG lets in from ``internet`` or ``vnet`` sources; None when there is no NSG."""
    if nsg is None:
        return None
    n = _p(nsg)
    rules = [_p(r) for r in (n.get("securityRules") or [])]
    rules += [_p(r) for r in (n.get("defaultSecurityRules") or DEFAULT_INBOUND)]
    rules = sorted((r for r in rules if str(r.get("direction", "")).lower() == "inbound"), key=lambda r: int(r.get("priority", 99999)))
    decided: PortRanges = []
    allowed: PortRanges = []
    for r in rules:
        if not _matches(r, src_class):
            continue
        for rng in _ports(r):
            fresh = _subtract(rng, decided)
            decided += fresh
            if str(r.get("access", "")).lower() == "allow":
                allowed += fresh
    return allowed


def _effective(subnet_nsg: dict | None, nic_nsg: dict | None, src_class: str) -> PortRanges:
    a, b = nsg_allowed(subnet_nsg, src_class), nsg_allowed(nic_nsg, src_class)
    if a is None and b is None:
        return [] if src_class == "internet" else list(ALL_PORTS)
    if a is None:
        return b or []
    if b is None:
        return a
    return _intersect(a, b)


# ---- assets ---------------------------------------------------------------------------------------

def assets_from_azure(bundle: dict) -> list[Asset]:
    nsgs = {_id(n): n for n in bundle.get("network_security_groups") or []}
    subnet_nsg: dict[str, dict | None] = {}
    for vnet in bundle.get("virtual_networks") or []:
        for sn in _p(vnet).get("subnets") or []:
            sn = _p(sn)
            subnet_nsg[_id(sn)] = nsgs.get(_id(sn.get("networkSecurityGroup")))
    nics = {_id(n): _p(n) for n in bundle.get("network_interfaces") or []}

    def nic_reach(nic: dict) -> tuple[PortRanges, PortRanges, str]:
        nic_nsg = nsgs.get(_id(nic.get("networkSecurityGroup")))
        cfgs = [_p(c) for c in nic.get("ipConfigurations") or []]
        sid = _id((cfgs[0] if cfgs else {}).get("subnet"))
        sub = subnet_nsg.get(sid)
        zone = sid.split("/subnets/")[0] if "/subnets/" in sid else sid
        return _effective(sub, nic_nsg, "internet"), _effective(sub, nic_nsg, "vnet"), zone

    out: list[Asset] = []
    by_nic: dict[str, Asset] = {}
    internet_by_nic: dict[str, PortRanges] = {}
    for vm in bundle.get("virtual_machines") or []:
        v = _p(vm)
        name = v.get("name") or _id(vm).rsplit("/", 1)[-1]
        tags = v.get("tags") or {}
        nic_ids = [_id(n) for n in ((v.get("networkProfile") or {}).get("networkInterfaces") or [])]
        internet: PortRanges = []
        lateral: PortRanges = []
        zone = ""
        for nid in nic_ids:
            if nid in nics:
                i, l, z = nic_reach(nics[nid])
                internet_by_nic[nid] = i
                internet += i
                lateral += l
                zone = zone or z
        pub = [x.strip() for x in str(v.get("publicIps") or "").split(",") if x.strip()]
        priv = [x.strip() for x in str(v.get("privateIps") or "").split(",") if x.strip()]
        role = tags.get("aegis-role") or tags.get("aegis:role") or "server"
        a = Asset(id=_id(vm) or name, name=name, keys={name, *pub, *priv, _id(vm)} - {""}, zone=zone,
                  role=role if role in SENSITIVITY else "server", public=bool(pub),
                  internet_ports=internet if pub else [], lateral=[(lo, hi, frozenset({"*"})) for lo, hi in lateral],
                  waf=str(tags.get("aegis-waf", "")).lower() == "true", edr=str(tags.get("aegis-edr", "")).lower() == "true",
                  source="azure")
        out.append(a)
        for nid in nic_ids:
            by_nic[nid] = a

    # public load balancers: frontend with a public IP → backend port on every pool member whose NSGs admit internet traffic
    for lb in bundle.get("load_balancers") or []:
        p = _p(lb)
        name = p.get("name") or _id(lb).rsplit("/", 1)[-1]
        public_fe = {_id(fe) for fe in p.get("frontendIPConfigurations") or [] if _p(fe).get("publicIPAddress")}
        pools = {_id(bp): [_id(c).split("/ipconfigurations/")[0] for c in _p(bp).get("backendIPConfigurations") or []]
                 for bp in p.get("backendAddressPools") or []}
        for rule in p.get("loadBalancingRules") or []:
            r = _p(rule)
            if _id(r.get("frontendIPConfiguration")) not in public_fe:
                continue
            bport, fport = r.get("backendPort"), r.get("frontendPort")
            for nid in pools.get(_id(r.get("backendAddressPool")), []):
                a = by_nic.get(nid)
                if a is None or bport is None:
                    continue
                # the backend's NSGs (subnet ∩ NIC) still have to admit internet sources on the backend port
                if not any(lo <= int(bport) <= hi for lo, hi in internet_by_nic.get(nid, [])):
                    continue
                rng = (int(bport), int(bport))
                if rng not in a.internet_ports:
                    a.internet_ports.append(rng)
                a.internet_via.setdefault(rng, f"load balancer {name} (frontend :{fport} → port {bport})")
                a.fronted_by.add(name)
                a.public = True
    return out
