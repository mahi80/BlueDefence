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

from ..agents.orchestrator.walkers.graph import CRITICAL, SENSITIVITY
from ..agents.vuln_discovery.tools import compute_risk_score

TIERS = ("ACT_NOW", "ACT", "SCHEDULE", "MONITOR")
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}
REACH_RANK = {"internet": 3, "one_hop": 2, "local": 1, "isolated": 0}


PortRanges = list[tuple[int, int]]
ALL_PORTS: PortRanges = [(0, 65535)]


def in_ranges(port: int, ranges: PortRanges) -> bool:
    return any(lo <= port <= hi for lo, hi in ranges)


@dataclass
class Vuln:
    asset: str                 # asset key: hostname, IP or instance id — matched against Asset.keys
    cve: str | None
    title: str
    port: int | None = None
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

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class Settings:
    epss_threshold: float = 0.1
    # CVE -> asset ids / names / "*" that carry a virtual-patch or IPS rule for it
    virtual_patches: dict[str, list[str]] = field(default_factory=dict)


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


def _reach(v: Vuln, a: Asset, internet_assets_by_zone: dict[str, list[Asset]]) -> tuple[str, str]:
    if v.port is None:
        return "local", "no network-facing port: exploitable only after a foothold on the host"
    if a.open_to_internet(v.port):
        return "internet", f"port {v.port} is open to the internet on {a.name or a.id} ({a.source})"
    neighbours = [x for x in internet_assets_by_zone.get(a.zone, []) if x.id != a.id] if a.zone else []
    entry = [x for x in neighbours if a.reachable_from(v.port, x)]
    if entry:
        return "one_hop", (f"port {v.port} reachable inside zone {a.zone} from internet-facing "
                           f"{', '.join(x.name or x.id for x in entry[:3])}")
    if not neighbours:
        return "isolated", f"no internet path: nothing in zone {a.zone or '?'} faces the internet and port {v.port} is not exposed"
    return "isolated", (f"port {v.port} is not exposed to the internet, and the internet-facing assets in zone {a.zone} "
                        f"({', '.join(x.name or x.id for x in neighbours[:3])}) are not allowed to reach it")


def _defended(v: Vuln, a: Asset, s: Settings) -> tuple[str, str]:
    targets = s.virtual_patches.get(v.cve or "", [])
    if v.cve and ("*" in targets or a.id in targets or a.name in targets or a.keys & set(targets)):
        return "full", f"virtual-patch / IPS rule for {v.cve} in front of this asset"
    # Only controls that can stop the exploit count as a defence. EDR detects post-exploitation activity
    # but does not block the exploit itself, so it is reported, never used to lower the tier.
    edr = "; EDR on the host will see post-exploitation activity (detection, not prevention)" if a.edr else ""
    if a.waf and v.port in WEB_PORTS:
        return "partial", "WAF in front of the web port (generic rules, no CVE-specific virtual patch)" + edr
    if v.port is None:
        return "none", "no network control applies to a local vulnerability; patching is the fix" + edr
    return "none", "no blocking control in front: no WAF or virtual patch for this port" + edr


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
    for a in assets:
        for k in {a.id, a.name, *a.keys} - {""}:
            by_key.setdefault(k.lower(), a)
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
                 f"shares zone {a.zone} with a crown-jewel asset" if crown == 1 else "no crown jewel in its zone")
        tier = _tier(exploitable, reach, defended, crown, v.cvss)
        out.append(Exposure(
            tier=tier, cve=v.cve, title=v.title, asset=a.id, asset_name=a.name or a.id, port=v.port,
            exploitable=exploitable, reach=reach, defended=defended, crown_distance=crown,
            risk_score=compute_risk_score(cvss=v.cvss, epss=v.epss, kev=v.kev, poc_available=v.poc),
            reasons=[why_x, why_r, why_d, why_c], vuln_source=v.source))

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


__all__ = ["ALL_PORTS", "TIERS", "Asset", "Exposure", "Settings", "Vuln", "assess", "funnel", "in_ranges", "summarize"]
