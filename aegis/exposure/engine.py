"""Exposure scoring: which vulnerabilities are exploitable, reachable and undefended — and why.

Every (vulnerability, asset) pair gets four answers and a tier:

* **exploitable** — CISA KEV listed, EPSS at or above the threshold, or a public exploit;
* **reachable** — ``internet`` (a public address and a network rule open to the world on the
  vulnerability's port), ``one_hop`` (reachable from an internet-facing asset in the same network
  zone / VPC), ``local`` (no network-facing port: needs a foothold first) or ``isolated``;
* **defended** — ``full`` (a virtual-patch / IPS rule for this CVE on this asset), ``partial`` (a WAF in
  front of a web port, or EDR on the host) or ``none``;
* **crown-jewel distance** — 0 when the asset *is* a crown jewel, 1 when it shares a zone with one.

Tiers: **ACT_NOW** = exploitable ∧ internet-reachable ∧ undefended. **ACT** = exploitable and reachable
but partly defended, or one hop from the internet and undefended, or one hop and next to a crown jewel.
**SCHEDULE** = exploitable but isolated / fully defended / local only, or a non-exploited critical
facing the internet. **MONITOR** = the rest. Every exposure carries its reason chain, so an analyst
(and an auditor) sees why it is in its tier.

Reachability here is reasoned from network configuration, not proven by packets.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any

from ..agents.orchestrator.walkers.graph import CRITICAL, SENSITIVITY
from ..agents.vuln_discovery.tools import compute_risk_score

TIERS = ("ACT_NOW", "ACT", "SCHEDULE", "MONITOR")
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}
REACH_RANK = {"internet": 3, "one_hop": 2, "local": 1, "isolated": 0}


PortRanges = list[tuple[int, int]]
ALL_PORTS: PortRanges = [(0, 65535)]
# Image / package findings (Trivy) have no port: the component may sit behind any port the workload exposes.
ANY_PORT = -1


def in_ranges(port: int, ranges: PortRanges) -> bool:
    return any(lo <= port <= hi for lo, hi in ranges)


@dataclass
class Vuln:
    asset: str                 # asset key: hostname, IP or instance id — matched against Asset.keys
    cve: str | None
    title: str
    port: int | None = None    # None = local only, ANY_PORT = package finding (behind whatever the workload exposes)
    protocol: str = "tcp"
    cvss: float | None = None
    epss: float | None = None
    kev: bool = False
    poc: bool = False
    source: str = ""
    asset_alt: list[str] = field(default_factory=list)   # other identifiers for the same asset (IP, FQDN, uuid)


@dataclass
class Asset:
    id: str
    name: str = ""
    keys: set[str] = field(default_factory=set)      # every identifier a scanner might use for it
    zone: str = ""                                   # VPC id, subnet, or the bank's zone name
    role: str = "server"                             # a blast-graph SENSITIVITY key (core_banking_db, payment_api, …)
    public: bool = False
    internet_ports: PortRanges = field(default_factory=list)   # port ranges open to the internet
    internet_via: dict[tuple[int, int], str] = field(default_factory=dict)  # range -> "via load balancer X" etc.
    fronted_by: set[str] = field(default_factory=set)   # LB names / DNS names / ingress hosts in front of it
    opened_by: dict[tuple[int, int], set[str]] = field(default_factory=dict)  # range -> SG / NSG ids that open it
    entry_port: dict[tuple[int, int], int] = field(default_factory=dict)      # range -> the port the internet hits (LB listener)
    # (lo, hi, sources) reachable from inside the zone; sources = security-group ids allowed in, or "*" (any
    # host in the zone — a private CIDR rule, or the inventory's lateral_ports)
    lateral: list[tuple[int, int, frozenset[str]]] = field(default_factory=lambda: [(0, 65535, frozenset({"*"}))])
    groups: frozenset[str] = frozenset()                       # security groups this asset is in
    waf: bool = False
    edr: bool = False
    source: str = ""

    def open_to_internet(self, port: int) -> bool:
        return self.public and in_ranges(port, self.internet_ports)

    def reachable_from(self, port: int, src: Asset) -> bool:
        """Can ``src`` (an asset in the same zone) reach this asset on ``port``?"""
        return any(lo <= port <= hi and ("*" in srcs or bool(src.groups & srcs)) for lo, hi, srcs in self.lateral)

    @property
    def sensitivity(self) -> float:
        return SENSITIVITY.get(self.role, SENSITIVITY["unknown"])


@dataclass
class Exposure:
    tier: str
    cve: str | None
    title: str
    asset: str
    asset_name: str
    port: int | None
    exploitable: bool
    reach: str
    defended: str
    crown_distance: int | None
    risk_score: float
    reasons: list[str]
    vuln_source: str = ""
    path: dict = field(default_factory=dict)   # what opens / fronts the path — remediation builds its commands from it

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class Settings:
    epss_threshold: float = 0.1
    # CVE -> asset ids / names / "*" that carry a virtual-patch or IPS rule for it
    virtual_patches: dict[str, list[str]] = field(default_factory=dict)
    # WAF / virtual-patch coverage exported from the vendors (coverage.Protection)
    coverage: list[Any] = field(default_factory=list)


def _exploitable(v: Vuln, s: Settings) -> tuple[bool, str]:
    why = []
    if v.kev:
        why.append("listed in CISA KEV (exploited in the wild)")
    if v.epss is not None and v.epss >= s.epss_threshold:
        why.append(f"EPSS {v.epss:.2f} ≥ {s.epss_threshold:.2f}")
    if v.poc:
        why.append("public exploit available")
    if why:
        return True, "exploitable: " + "; ".join(why)
    detail = f"EPSS {v.epss:.2f}" if v.epss is not None else "no EPSS data"
    return False, f"no exploitation signal (not in KEV, {detail}, no public exploit)"


def _internet_range(a: Asset, port: int) -> tuple[int, int] | None:
    if not a.public:
        return None
    return next((r for r in a.internet_ports if r[0] <= port <= r[1]), None)


def _via(a: Asset, r: tuple[int, int]) -> str:
    v = a.internet_via.get(r)
    return f"via {v}" if v else f"on {a.name or a.id} ({a.source})"


def _zl(zone: str) -> str:
    """Short zone label for reasons: an Azure VNet resource id prints as its name."""
    return zone.rstrip("/").rsplit("/", 1)[-1] if "/" in zone else zone


def _reach(v: Vuln, a: Asset, internet_assets_by_zone: dict[str, list[Asset]]) -> tuple[str, str]:
    neighbours = [x for x in internet_assets_by_zone.get(a.zone, []) if x.id != a.id] if a.zone else []
    if v.port == ANY_PORT:
        # package-level finding: judge by what the workload exposes at all
        if a.public and a.internet_ports:
            r = a.internet_ports[0]
            return "internet", (f"image / package finding on a workload reachable from the internet {_via(a, r)} "
                                f"(port {r[0]}{'-' + str(r[1]) if r[1] != r[0] else ''})")
        entry = [x for x in neighbours if any(a.reachable_from(lo, x) for lo, _hi, _s in a.lateral)]
        if entry:
            return "one_hop", f"image / package finding; workload reachable inside zone {_zl(a.zone)} from internet-facing {', '.join(x.name or x.id for x in entry[:3])}"
        return "isolated", f"image / package finding; nothing exposes this workload to the internet or to internet-facing neighbours in {_zl(a.zone) or '?'}"
    if v.port is None:
        return "local", "no network-facing port: exploitable only after a foothold on the host"
    r = _internet_range(a, v.port)
    if r:
        return "internet", f"port {v.port} is reachable from the internet {_via(a, r)}"
    entry = [x for x in neighbours if a.reachable_from(v.port, x)]
    if entry:
        return "one_hop", (f"port {v.port} reachable inside zone {_zl(a.zone)} from internet-facing "
                           f"{', '.join(x.name or x.id for x in entry[:3])}")
    if not neighbours:
        return "isolated", f"no internet path: nothing in zone {_zl(a.zone) or '?'} faces the internet and port {v.port} is not exposed"
    return "isolated", (f"port {v.port} is not exposed to the internet, and the internet-facing assets in zone {_zl(a.zone)} "
                        f"({', '.join(x.name or x.id for x in neighbours[:3])}) are not allowed to reach it")


def _defended(v: Vuln, a: Asset, s: Settings) -> tuple[str, str]:
    keys = a.keys | {a.id, a.name} | a.fronted_by
    prots = [p for p in s.coverage if p.covers(keys, v.port)]
    blocking = [p for p in prots if p.mode == "block"]
    monitor = [p for p in prots if p.mode == "monitor"]
    note = ""
    if monitor:
        note = (f"; {', '.join(f'{p.vendor} {p.name}' for p in monitor[:2])} in front but in MONITOR mode: "
                "it logs the attack and lets it through")
    for p in blocking:
        if v.cve and v.cve.upper() in p.virtual_patches:
            return "full", f"virtual-patch rule for {v.cve} on {p.vendor} {p.name} (blocking mode)"
    targets = s.virtual_patches.get(v.cve or "", [])
    if v.cve and ("*" in targets or a.id in targets or a.name in targets or a.keys & set(targets)):
        return "full", f"virtual-patch / IPS rule for {v.cve} in front of this asset"
    # Only controls that can stop the exploit count as a defence. EDR detects post-exploitation activity
    # but does not block the exploit itself, so it is reported, never used to lower the tier.
    edr = "; EDR on the host will see post-exploitation activity (detection, not prevention)" if a.edr else ""
    web = v.port in WEB_PORTS or (v.port == ANY_PORT and any(lo <= p <= hi for lo, hi in a.internet_ports for p in WEB_PORTS))
    if web and (a.waf or blocking):
        who = f"{blocking[0].vendor} {blocking[0].name} in blocking mode" if blocking else "WAF in front of the web port"
        return "partial", f"{who} (generic rules, no CVE-specific virtual patch)" + note + edr
    if v.port is None:
        return "none", "no network control applies to a local vulnerability; patching is the fix" + note + edr
    return "none", "no blocking control in front: no WAF or virtual patch for this port" + note + edr


def _path(v: Vuln, a: Asset, s: Settings) -> dict:
    """The facts a fix is built from: which rule opens the port, what fronts it, which WAF covers it."""
    r = _internet_range(a, v.port) if v.port not in (None, ANY_PORT) else None
    keys = a.keys | {a.id, a.name} | a.fronted_by
    return {"source": a.source, "zone": a.zone, "range": list(r) if r else None,
            "via": a.internet_via.get(r) if r else None,
            "opened_by": sorted(a.opened_by.get(r, set())) if r else [],
            "entry_port": a.entry_port.get(r) if r else None,
            "fronted_by": sorted(a.fronted_by),
            "protections": [{"name": p.name, "vendor": p.vendor, "mode": p.mode}
                            for p in s.coverage if p.covers(keys, v.port)]}


def _tier(exploitable: bool, reach: str, defended: str, crown: int | None, cvss: float | None) -> str:
    if exploitable:
        if reach == "internet" and defended == "none":
            return "ACT_NOW"
        if reach == "internet" and defended == "partial":
            return "ACT"
        if reach == "one_hop" and (defended == "none" or (crown is not None and crown <= 1 and defended != "full")):
            return "ACT"
        return "SCHEDULE"
    if reach == "internet" and (cvss or 0) >= 9.0 and defended != "full":
        return "SCHEDULE"
    return "MONITOR"


def assess(vulns: list[Vuln], assets: list[Asset], settings: Settings | None = None) -> tuple[list[Exposure], list[str]]:
    """Score every vulnerability against the asset it sits on. Returns (exposures, notes)."""
    s = settings or Settings()
    by_key: dict[str, Asset] = {}
    ambiguous: set[str] = set()
    for a in assets:
        for k in {a.id, a.name, *a.keys} - {""}:
            kl = k.lower()
            if kl in by_key and by_key[kl] is not a:
                ambiguous.add(kl)          # e.g. the same private IP in two VPCs: it identifies neither
            by_key.setdefault(kl, a)
    for kl in ambiguous:
        by_key.pop(kl, None)
    internet_by_zone: dict[str, list[Asset]] = {}
    crown_zones: set[str] = set()
    for a in assets:
        if a.public and a.internet_ports:
            internet_by_zone.setdefault(a.zone, []).append(a)
        if a.sensitivity >= CRITICAL and a.zone:
            crown_zones.add(a.zone)

    out: list[Exposure] = []
    unmatched: Counter[str] = Counter()
    for v in vulns:
        a = next((by_key[k.lower()] for k in [v.asset, *v.asset_alt] if k and k.lower() in by_key), None)
        if a is None:
            unmatched[v.asset] += 1
            continue
        exploitable, why_x = _exploitable(v, s)
        reach, why_r = _reach(v, a, internet_by_zone)
        defended, why_d = _defended(v, a, s)
        crown = 0 if a.sensitivity >= CRITICAL else (1 if a.zone and a.zone in crown_zones else None)
        why_c = ("the asset is a crown jewel" if crown == 0 else
                 f"shares zone {_zl(a.zone)} with a crown-jewel asset" if crown == 1 else "no crown jewel in its zone")
        tier = _tier(exploitable, reach, defended, crown, v.cvss)
        if v.port == ANY_PORT and tier == "ACT_NOW":
            # a package CVE is not proven to sit on the exposed path (e.g. a libc flaw in a web image)
            tier = "ACT"
            why_r += "; capped at ACT until the vulnerable component is confirmed on the exposed path"
        out.append(Exposure(
            tier=tier, cve=v.cve, title=v.title, asset=a.id, asset_name=a.name or a.id, port=v.port,
            exploitable=exploitable, reach=reach, defended=defended, crown_distance=crown,
            risk_score=compute_risk_score(cvss=v.cvss, epss=v.epss, kev=v.kev, poc_available=v.poc),
            reasons=[why_x, why_r, why_d, why_c], vuln_source=v.source, path=_path(v, a, s)))

    rank = {t: i for i, t in enumerate(TIERS)}
    def crown_weight(e: Exposure) -> int:
        return 0 if e.crown_distance is None else 2 - e.crown_distance

    out.sort(key=lambda e: (rank[e.tier], -crown_weight(e), -REACH_RANK[e.reach], -e.risk_score, e.asset_name, e.cve or ""))
    notes = []
    if unmatched:
        top = ", ".join(f"{k} ({n})" for k, n in unmatched.most_common(5))
        notes.append(f"{sum(unmatched.values())} findings on {len(unmatched)} assets not in the asset model were "
                     f"left out (add them to the inventory): {top}")
    return out, notes


def funnel(exposures: list[Exposure], raw_total: int) -> dict[str, int]:
    """raw → exploitable → reachable → undefended → ACT NOW: the headline reduction."""
    ex = [e for e in exposures if e.exploitable]
    reach = [e for e in ex if e.reach in ("internet", "one_hop")]
    undef = [e for e in reach if e.defended == "none"]
    return {"raw": raw_total, "scored": len(exposures), "exploitable": len(ex), "reachable": len(reach),
            "undefended": len(undef), "act_now": sum(e.tier == "ACT_NOW" for e in exposures)}


def summarize(exposures: list[Exposure]) -> dict[str, int]:
    c = Counter(e.tier for e in exposures)
    return {t: c.get(t, 0) for t in TIERS}


__all__ = ["ALL_PORTS", "ANY_PORT", "TIERS", "Asset", "Exposure", "Settings", "Vuln", "assess", "funnel", "in_ranges", "summarize"]
