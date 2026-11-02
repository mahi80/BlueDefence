"""Inputs for the exposure engine — all offline files the bank already has or can export.

* **Vulnerabilities** — a Tenable.io / Tenable.sc vulns export (JSON array or JSONL, one record per
  plugin × asset × port), or a simple CSV (``asset,cve,title,port,cvss,epss,kev,poc``) for any other
  scanner (Qualys, Rapid7, Nessus CSV exports reshaped in a spreadsheet).
* **Threat intel** — the CISA KEV catalogue JSON and the FIRST EPSS CSV; both are free daily downloads
  and can be mirrored into an air-gapped SOC.
* **Assets and reachability** — the AWS posture bundle (``python -m aegis.posture export-aws``): instances,
  their security groups and public addresses; plus an inventory CSV for on-prem assets and anything the
  cloud collectors do not see yet (zones, roles, WAF / EDR coverage).
"""

from __future__ import annotations

import csv
import ipaddress
import json
from pathlib import Path
from typing import Any

from ..agents.orchestrator.walkers.graph import SENSITIVITY
from ..posture.cspm import _open_ranges, _ports
from ..posture.sources import PostureSourceError
from .engine import ALL_PORTS, ANY_PORT, Asset, PortRanges, Settings, Vuln

_TRUE = {"1", "true", "yes", "y"}
PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")]


def _b(v: Any) -> bool:
    return str(v).strip().lower() in _TRUE


def _f(v: Any) -> float | None:
    try:
        return float(v) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _port(v: Any) -> int | None:
    try:
        p = int(v)
    except (TypeError, ValueError):
        return None
    return p if p > 0 else None  # Tenable reports host-level findings on port 0


def _parse_ports(s: str | None, default: PortRanges) -> PortRanges:
    if s is None or str(s).strip() == "":
        return list(default)
    s = str(s).strip().lower()
    if s in ("all", "*", "any"):
        return list(ALL_PORTS)
    if s in ("none", "-"):
        return []
    out: PortRanges = []
    for part in s.replace(",", ";").split(";"):
        part = part.strip()
        if not part:
            continue
        lo, _, hi = part.partition("-")
        out.append((int(lo), int(hi or lo)))
    return out


# ---- vulnerabilities ------------------------------------------------------------------------------

def _read_records(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    if text[0] == "[":
        return json.loads(text)
    if text[0] == "{" and "\n" not in text:
        obj = json.loads(text)
        return obj.get("vulnerabilities") or obj.get("findings") or [obj]
    try:
        obj = json.loads(text)
        return obj.get("vulnerabilities") or obj.get("findings") or [obj]
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]  # JSONL


def _from_tenable(r: dict) -> list[Vuln]:
    if str(r.get("state", "OPEN")).upper() == "FIXED" or str(r.get("severity", "")).lower() == "info":
        return []
    asset, plugin, port = r.get("asset") or {}, r.get("plugin") or {}, r.get("port") or {}
    ips = asset.get("ipv4") or []
    ips = [ips] if isinstance(ips, str) else list(ips)
    keys = [k for k in [asset.get("hostname"), *ips, asset.get("fqdn"), asset.get("uuid"),
                        *(asset.get("aws_ec2_instance_id") and [asset["aws_ec2_instance_id"]] or [])] if k]
    if not keys:
        return []
    cves = plugin.get("cve") or [None]
    vpr = plugin.get("vpr") or {}
    return [Vuln(asset=keys[0], asset_alt=keys[1:], cve=c, title=plugin.get("name") or str(plugin.get("id", "?")),
                 port=_port(port.get("port")), protocol=str(port.get("protocol", "tcp")).lower(),
                 cvss=_f(plugin.get("cvss3_base_score") or plugin.get("cvss_base_score")),
                 epss=_f(plugin.get("epss_score")), kev=_b(plugin.get("cisa_known_exploited") or vpr.get("kev")),
                 poc=bool(plugin.get("exploit_available")), source=f"tenable:{plugin.get('id', '?')}") for c in cves]


def _image_keys(ref: str) -> list[str]:
    """``registry.bank/team/app:1.2`` also matches ``app:1.2`` (how many scanners print it)."""
    ref = ref.split("@")[0]
    short = ref.rsplit("/", 1)[-1]
    return [ref] + ([short] if short != ref else [])


def _from_trivy(doc: dict) -> list[Vuln]:
    """Trivy image report (``trivy image -f json``): package CVEs, judged by what the workload exposes."""
    image = doc.get("ArtifactName") or "?"
    keys = _image_keys(image)
    out = []
    for res in doc.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            if str(v.get("Severity", "")).upper() in ("UNKNOWN", "LOW"):
                continue
            cvss = None
            for src in (v.get("CVSS") or {}).values():
                cvss = max(cvss or 0.0, float(src.get("V3Score") or 0)) or cvss
            out.append(Vuln(asset=keys[0], asset_alt=keys[1:], cve=v.get("VulnerabilityID"),
                            title=f"{v.get('PkgName', '?')} {v.get('InstalledVersion', '')}: {v.get('Title') or v.get('VulnerabilityID')}".strip(),
                            port=ANY_PORT, cvss=cvss, source=f"trivy:{res.get('Target', image)}"))
    return out


def load_vulns(path: str | Path) -> list[Vuln]:
    p = Path(path)
    try:
        if p.suffix.lower() == ".csv":
            with p.open(newline="", encoding="utf-8") as fh:
                return [Vuln(asset=row["asset"].strip(), cve=(row.get("cve") or "").strip() or None,
                             title=(row.get("title") or row.get("cve") or "?").strip(), port=_port(row.get("port")),
                             cvss=_f(row.get("cvss")), epss=_f(row.get("epss")), kev=_b(row.get("kev")),
                             poc=_b(row.get("poc")), source="csv")
                        for row in csv.DictReader(fh) if (row.get("asset") or "").strip()]
        text = p.read_text(encoding="utf-8").lstrip()
        if text.startswith("{") and '"Results"' in text[:20000] and '"ArtifactName"' in text[:20000]:
            return _from_trivy(json.loads(text))
        out: list[Vuln] = []
        for r in _read_records(p):
            out += _from_tenable(r) if "plugin" in r else [Vuln(
                asset=r["asset"], cve=r.get("cve"), title=r.get("title", r.get("cve") or "?"), port=_port(r.get("port")),
                cvss=_f(r.get("cvss")), epss=_f(r.get("epss")), kev=bool(r.get("kev")), poc=bool(r.get("poc")), source="json")]
        return out
    except FileNotFoundError as e:
        raise PostureSourceError(f"vulnerability export not found: {path}") from e
    except (KeyError, ValueError, json.JSONDecodeError) as e:
        raise PostureSourceError(f"cannot parse vulnerability export {path}: {e}") from e


def apply_intel(vulns: list[Vuln], *, kev: str | Path | None = None, epss: str | Path | None = None) -> list[str]:
    """Fill KEV / EPSS from the official feeds. Scanner-supplied values are kept when already set."""
    notes = []
    if kev:
        try:
            data = json.loads(Path(kev).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise PostureSourceError(f"cannot read KEV catalogue {kev}: {e}") from e
        kev_ids = {v.get("cveID") for v in data.get("vulnerabilities", [])}
        for v in vulns:
            v.kev = v.kev or (v.cve in kev_ids)
        notes.append(f"KEV catalogue: {len(kev_ids)} CVEs ({data.get('catalogVersion', 'version ?')})")
    if epss:
        scores: dict[str, float] = {}
        try:
            with Path(epss).open(encoding="utf-8") as fh:
                lines = [ln for ln in fh if not ln.startswith("#")]   # FIRST prefixes a #model_version line
            for row in csv.DictReader(lines):
                if row.get("cve") and _f(row.get("epss")) is not None:
                    scores[row["cve"]] = float(row["epss"])
        except OSError as e:
            raise PostureSourceError(f"cannot read EPSS file {epss}: {e}") from e
        for v in vulns:
            if v.epss is None and v.cve in scores:
                v.epss = scores[v.cve]
        notes.append(f"EPSS scores: {len(scores)} CVEs")
    if not kev and not epss:
        notes.append("no KEV / EPSS feed supplied: exploitability uses only what the scanner reported")
    return notes


# ---- assets ---------------------------------------------------------------------------------------

def _lateral_sources(perm: dict) -> frozenset[str]:
    """Who inside the network may use this rule: the referenced security groups, and "*" when a
    private CIDR is allowed (any host in the zone)."""
    srcs = {p.get("GroupId") for p in perm.get("UserIdGroupPairs") or [] if p.get("GroupId")}
    if _private_cidr(perm):
        srcs.add("*")
    return frozenset(srcs)


def _private_cidr(perm: dict) -> bool:
    for r in perm.get("IpRanges", []):
        try:
            net = ipaddress.ip_network(r.get("CidrIp", ""), strict=False)
        except ValueError:
            continue
        if any(net.subnet_of(p) for p in PRIVATE):
            return True
    return False


def assets_from_aws(bundle: dict) -> list[Asset]:
    """One Asset per running EC2 instance: public address + the union of its security groups' rules."""
    sgs = {g.get("GroupId"): g for g in bundle.get("security_groups", [])}
    out = []
    for i in bundle.get("instances", []):
        if (i.get("State") or {}).get("Name") in ("terminated", "stopped"):
            continue
        tags = {t.get("Key"): t.get("Value") for t in i.get("Tags") or []}
        iid = i.get("InstanceId", "?")
        internet: PortRanges = []
        lateral: list[tuple[int, int, frozenset[str]]] = []
        groups = frozenset(ref.get("GroupId") for ref in i.get("SecurityGroups") or [] if ref.get("GroupId"))
        for gid in groups:
            for perm in (sgs.get(gid) or {}).get("IpPermissions", []):
                pr = _ports(perm)
                lo, hi = (0, 65535) if pr is None else pr
                if _open_ranges(perm):
                    internet.append((lo, hi))
                if srcs := _lateral_sources(perm):
                    lateral.append((lo, hi, srcs))
        role = tags.get("aegis:role") or tags.get("Role") or tags.get("role") or "server"
        keys = {iid, *(x for x in (i.get("PrivateIpAddress"), i.get("PublicIpAddress"), i.get("PrivateDnsName"), tags.get("Name")) if x)}
        out.append(Asset(id=iid, name=tags.get("Name") or iid, keys=keys, zone=i.get("VpcId") or "",
                         role=role if role in SENSITIVITY else "server", public=bool(i.get("PublicIpAddress")),
                         internet_ports=internet, lateral=lateral, groups=groups,
                         waf=_b(tags.get("aegis:waf")), edr=_b(tags.get("aegis:edr")), source="aws"))
    _apply_aws_load_balancers(bundle, sgs, out)
    return out


def _apply_aws_load_balancers(bundle: dict, sgs: dict, assets: list[Asset]) -> None:
    """An internet-facing ALB / NLB makes its targets reachable on the target port, even when the
    instance itself has no public address. ALB listeners must also be open in the LB's security
    groups; an NLB without security groups passes every listener. An AWS WAF web ACL on the ALB
    counts as a WAF in front of its targets."""
    by_key = {k: a for a in assets for k in a.keys | {a.id}}
    for lb in bundle.get("load_balancers") or []:
        if lb.get("Scheme") != "internet-facing":
            continue
        name = lb.get("LoadBalancerName") or lb.get("LoadBalancerArn", "?")
        lb_sgs = lb.get("SecurityGroups") or []
        open_ranges: PortRanges = []
        for gid in lb_sgs:
            for perm in (sgs.get(gid) or {}).get("IpPermissions", []):
                if _open_ranges(perm):
                    pr = _ports(perm)
                    open_ranges.append((0, 65535) if pr is None else pr)
        for lst in lb.get("listeners") or []:
            lp = lst.get("Port")
            if lp is None or (lb_sgs and not any(lo <= lp <= hi for lo, hi in open_ranges)):
                continue
            for t in lb.get("targets") or []:
                a = by_key.get(t.get("Id"))
                tp = t.get("Port") or lp
                if a is None:
                    continue
                r = (tp, tp)
                if r not in a.internet_ports:
                    a.internet_ports.append(r)
                a.internet_via.setdefault(r, f"load balancer {name} (listener {lp} → port {tp})")
                a.public = True
                if lb.get("web_acl"):
                    a.waf = True


def assets_from_inventory(path: str | Path) -> list[Asset]:
    """Inventory CSV: ``asset,name,ips,hostname,zone,role,public,internet_ports,lateral_ports,waf,edr``.

    ``internet_ports`` / ``lateral_ports``: ``443;8443``, ``8000-8100``, ``all`` or empty
    (internet: none, lateral: all). ``role`` is a blast-graph role such as ``core_banking_db``,
    ``payment_api``, ``swift_gateway``, ``jump_host`` (unknown roles count as ``server``)."""
    out = []
    try:
        with Path(path).open(newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                aid = (row.get("asset") or "").strip()
                if not aid:
                    continue
                role = (row.get("role") or "server").strip()
                keys = {aid, *(x.strip() for x in (row.get("ips") or "").replace(",", ";").split(";") if x.strip())}
                if (row.get("hostname") or "").strip():
                    keys.add(row["hostname"].strip())
                out.append(Asset(id=aid, name=(row.get("name") or aid).strip(), keys=keys, zone=(row.get("zone") or "").strip(),
                                 role=role if role in SENSITIVITY else "server", public=_b(row.get("public")),
                                 internet_ports=_parse_ports(row.get("internet_ports"), []),
                                 lateral=[(lo, hi, frozenset({"*"})) for lo, hi in _parse_ports(row.get("lateral_ports"), ALL_PORTS)],
                                 waf=_b(row.get("waf")), edr=_b(row.get("edr")), source="inventory"))
    except FileNotFoundError as e:
        raise PostureSourceError(f"inventory not found: {path}") from e
    except ValueError as e:
        raise PostureSourceError(f"cannot parse inventory {path}: {e}") from e
    return out


def merge_assets(*groups: list[Asset]) -> list[Asset]:
    """Later groups (the inventory) override earlier ones (cloud) for the same asset id or key —
    the bank's own record of role / WAF / EDR wins over what the collector inferred."""
    merged: dict[str, Asset] = {}
    for g in groups:
        for a in g:
            hit = next((k for k, m in merged.items() if k == a.id or (m.keys & a.keys)), None)
            if hit is None:
                merged[a.id] = a
                continue
            m = merged[hit]
            m.keys |= a.keys
            if a.role != "server":
                m.role = a.role
            m.waf, m.edr = m.waf or a.waf, m.edr or a.edr
            if a.zone and not m.zone:
                m.zone = a.zone
            if a.source == "inventory" and a.internet_ports:
                m.internet_ports, m.public = a.internet_ports, a.public or m.public
    return list(merged.values())


def load_settings(path: str | Path | None) -> Settings:
    if not path:
        return Settings()
    import yaml

    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as e:
        raise PostureSourceError(f"cannot read exposure settings {path}: {e}") from e
    vp = {str(k): [str(x) for x in (v if isinstance(v, list) else [v])] for k, v in (raw.get("virtual_patches") or {}).items()}
    return Settings(epss_threshold=float(raw.get("epss_threshold", 0.1)), virtual_patches=vp)
