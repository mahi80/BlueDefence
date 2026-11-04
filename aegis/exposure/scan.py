"""The exposure engine as a VAPT-loop scan (``type: exposure`` in ``posture.yaml``).

Each exposure becomes a ``PostureFinding`` so the runner's tracking applies unchanged — new / still open /
resolved, the remediation SLA, the waiver register and the dated report. The tier maps to severity
(ACT_NOW → critical, ACT → high, SCHEDULE → medium, MONITOR → low); the finding id is the CVE and the
component is ``asset:port``, so a finding that changes tier (a WAF goes in front, a CVE lands in KEV)
keeps its history instead of looking new.

    - name: exposure-prod
      type: exposure
      vulns: [exports/tenable.json, exports/trivy]        # files or directories of JSON / CSV
      aws_bundles: [exports/aws-prod-aps1.json]
      azure_bundles: [exports/azure-prod.json]
      k8s_exports: [eks-payments=exports/eks-payments.json]
      inventory: exports/onprem-assets.csv
      kev: feeds/known_exploited_vulnerabilities.json
      epss: feeds/epss_scores.csv
      waf_coverage: [exports/imperva.json, exports/edge.json]
      settings: exposure.yaml
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..posture.base import PostureFinding
from ..posture.sources import PostureSourceError, load_json
from . import loaders
from .azure_reach import assets_from_azure
from .engine import ANY_PORT, WEB_PORTS, Exposure, assess, funnel, summarize
from .k8s_reach import assets_from_k8s

SEVERITY = {"ACT_NOW": "critical", "ACT": "high", "SCHEDULE": "medium", "MONITOR": "low"}


def _files(paths: list[Any]) -> list[Path]:
    out: list[Path] = []
    for p in map(Path, paths):
        out += sorted(x for x in p.iterdir() if x.suffix.lower() in (".json", ".jsonl", ".csv")) if p.is_dir() else [p]
    return out


def _fix(e: Exposure) -> str:
    target = f"{e.cve or e.title} on {e.asset_name}"
    if e.tier in ("ACT_NOW", "ACT"):
        stopgap = []
        web = e.port in WEB_PORTS or bool((e.path or {}).get("protections"))   # a WAF only stops HTTP
        if e.defended != "full" and e.cve and web:
            stopgap.append(f"a blocking WAF virtual patch for {e.cve}")
        if e.reach == "internet" and e.port and e.port > 0:
            stopgap.append(f"closing port {e.port} to the internet")
        elif e.reach == "one_hop" and e.port and e.port > 0:
            stopgap.append(f"restricting port {e.port} to the hosts that need it")
        return f"Patch {target}" + (f"; until it is patched, cut the path: {' or '.join(stopgap)}" if stopgap else "")
    if e.tier == "SCHEDULE":
        return f"Patch {target} in the next maintenance window; keep the compensating control in place"
    return f"Track {target}; re-assess if it is exploited in the wild or its exposure changes"


def to_finding(e: Exposure) -> PostureFinding:
    comp = e.asset_name + (f":{e.port}" if e.port and e.port > 0 else " (image)" if e.port == ANY_PORT else "")
    return PostureFinding(
        id=e.cve or f"VULN {e.title[:40]}", severity=SEVERITY[e.tier], confidence=0.9, category="exposure",
        affected_component=comp, resource=e.asset, scanner="exposure", control=f"Exposure tier {e.tier}",
        evidence=" · ".join(e.reasons), recommended_remediation=_fix(e), risk_score=e.risk_score,
        extra={"tier": e.tier, "reach": e.reach, "defended": e.defended, "exploitable": e.exploitable,
               "crown_distance": e.crown_distance, "port": e.port, "title": e.title, "reasons": e.reasons,
               "source": e.vuln_source, "path": e.path})


def run_scan(o: dict) -> tuple[list[PostureFinding], list[str], dict]:
    if not o.get("vulns"):
        raise PostureSourceError("exposure scan needs vulns (scanner exports)")
    files = _files(o["vulns"])
    if not files:
        raise PostureSourceError(f"exposure scan: no vulnerability export found in {o['vulns']}")
    vulns = []
    for f in files:
        fmt, got = loaders.load_vulns_with_format(f)
        if not got and fmt in loaders.NATIVE_FORMATS and not o.get("allow_empty"):
            # one scanner's export came back empty while the others had findings: every exposure on that scanner's
            # assets would be resolved and approved remediations marked verified (review round 6 X-1)
            raise PostureSourceError(f"exposure scan: the {fmt} export {f} contains no findings — refusing to treat "
                                     "that as clean (allow_empty: true to accept)")
        vulns += got
    if not vulns and not o.get("allow_empty"):
        # An export with no findings at all is far more often a broken export (an expired API key writing
        # "[]", a filter that matched nothing) than a clean estate — and treating it as clean resolves every
        # open exposure and marks approved remediations verified. Fail the scan instead (the runner carries
        # the previous findings forward as stale); set allow_empty: true for an estate that is truly clean.
        raise PostureSourceError(f"exposure scan: the vulnerability export(s) {', '.join(str(f) for f in files)} "
                                 "contain no findings — refusing to treat that as a clean estate (allow_empty: true to accept)")
    notes = loaders.apply_intel(vulns, kev=o.get("kev"), epss=o.get("epss"))
    sourced: list[tuple[str, Any]] = [(f"aws bundle {b}", loaders.assets_from_aws(load_json(b))) for b in o.get("aws_bundles") or []]
    sourced += [(f"azure bundle {b}", assets_from_azure(load_json(b))) for b in o.get("azure_bundles") or []]
    for spec in o.get("k8s_exports") or []:
        name, _, path = str(spec).rpartition("=") if "=" in str(spec) else ("", "", str(spec))
        sourced.append((f"k8s export {path}", assets_from_k8s(load_json(path), cluster=name or "k8s",
                                                              public_nodes=bool(o.get("public_nodes")))))
    if o.get("inventory"):
        sourced.append((f"inventory {o['inventory']}", loaders.assets_from_inventory(o["inventory"])))
    empty = [what for what, g in sourced if not g]
    if empty:
        # One broken source (an AWS bundle that came back "{}", a kubectl run against the wrong context) dropped
        # that account's assets; the scan still said ok because the others had assets, and approved remediations
        # on the dropped assets were marked verified_closed (review round 4 D4-5). Fail the scan: the runner
        # carries the previous findings forward as stale.
        raise PostureSourceError(f"exposure scan: {', '.join(empty)} gave no assets — refusing to treat its estate as clean")
    groups = [g for _w, g in sourced]
    if not groups:
        raise PostureSourceError("exposure scan needs an asset model: aws_bundles / azure_bundles / k8s_exports / inventory")
    assets = loaders.merge_assets(*groups)
    if not assets:
        # every exposure needs an asset to land on: with none, all of them were dropped, the scan said "ok", and
        # approved remediation proposals were marked verified_closed (review round 3 G6-2)
        raise PostureSourceError("exposure scan: the asset model is empty (bundles / exports / inventory gave no assets) "
                                 "— refusing to treat that as a clean estate")
    settings = loaders.with_coverage(loaders.load_settings(o.get("settings")), o.get("waf_coverage") or [])
    exposures, more = assess(vulns, assets, settings)
    meta = {"funnel": funnel(exposures, len(vulns)), "tiers": summarize(exposures), "assets": len(assets),
            "protections": len(settings.coverage),
            "monitor_only": sum(p.mode == "monitor" for p in settings.coverage)}
    return [to_finding(e) for e in exposures], notes + more, meta
