"""CLI: score a vulnerability export against the asset model and print the funnel + ACT NOW list.

Exit codes: 0 ok, 1 when ``--fail-on-act-now`` and any ACT_NOW exposure exists, 2 bad input.
"""

from __future__ import annotations

import argparse
import json
import sys

from ..posture.sources import PostureSourceError, load_json
from . import loaders
from .azure_reach import assets_from_azure
from .engine import assess, funnel, summarize
from .k8s_reach import assets_from_k8s


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m aegis.exposure", description="Exploitable × reachable × undefended prioritisation")
    ap.add_argument("--vulns", required=True, action="append",
                    help="Tenable vulns export (JSON / JSONL), Trivy image report (JSON) or CSV; repeatable")
    ap.add_argument("--aws-bundle", action="append", default=[], help="posture bundle from `python -m aegis.posture export-aws`; repeatable")
    ap.add_argument("--azure-bundle", action="append", default=[], help="posture bundle from `python -m aegis.posture export-azure`; repeatable")
    ap.add_argument("--k8s-export", action="append", default=[], metavar="[NAME=]FILE",
                    help="kubectl export (see `python -m aegis.posture k8s --help`), optionally named; repeatable")
    ap.add_argument("--public-nodes", action="store_true", help="Kubernetes nodes have public IPs (NodePort Services are internet-facing)")
    ap.add_argument("--inventory", help="asset inventory CSV (on-prem assets, zones, roles, WAF / EDR coverage)")
    ap.add_argument("--kev", help="CISA KEV catalogue JSON (known_exploited_vulnerabilities.json)")
    ap.add_argument("--epss", help="FIRST EPSS scores CSV (epss_scores-YYYY-MM-DD.csv)")
    ap.add_argument("--settings", help="exposure.yaml: epss_threshold, virtual_patches {CVE: [asset, ...]}")
    ap.add_argument("--top", type=int, default=15, help="exposures to print (text mode)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on-act-now", action="store_true", help="exit 1 if any exposure is ACT_NOW")
    args = ap.parse_args(argv)

    try:
        vulns = [v for p in args.vulns for v in loaders.load_vulns(p)]
        notes = loaders.apply_intel(vulns, kev=args.kev, epss=args.epss)
        groups = [loaders.assets_from_aws(load_json(b)) for b in args.aws_bundle]
        groups += [assets_from_azure(load_json(b)) for b in args.azure_bundle]
        for spec in args.k8s_export:
            name, _, path = spec.rpartition("=") if "=" in spec else ("", "", spec)
            groups.append(assets_from_k8s(load_json(path), cluster=name or "k8s", public_nodes=args.public_nodes))
        if args.inventory:
            groups.append(loaders.assets_from_inventory(args.inventory))
        if not groups:
            raise PostureSourceError("pass at least one --aws-bundle / --azure-bundle / --k8s-export / --inventory: "
                                     "reachability needs an asset model")
        assets = loaders.merge_assets(*groups)
        exposures, more = assess(vulns, assets, loaders.load_settings(args.settings))
        notes += more
    except PostureSourceError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    fn = funnel(exposures, raw_total=len(vulns))
    if args.json:
        print(json.dumps({"funnel": fn, "tiers": summarize(exposures), "assets": len(assets), "notes": notes,
                          "exposures": [e.as_dict() for e in exposures]}, indent=2))
    else:
        print(f"funnel: {fn['raw']} findings → {fn['exploitable']} exploitable → {fn['reachable']} reachable → "
              f"{fn['undefended']} undefended → {fn['act_now']} ACT NOW   ({len(assets)} assets)")
        print("tiers: " + ", ".join(f"{k} {v}" for k, v in summarize(exposures).items()))
        for e in exposures[: args.top]:
            port = f":{e.port}" if e.port and e.port > 0 else " (image)" if e.port == -1 else ""
            print(f"\n{e.tier:9} {e.cve or '-':16} {e.asset_name}{port}  [{e.reach}, defended={e.defended}, risk {e.risk_score}]\n"
                  f"          {e.title}")
            for r in e.reasons:
                print(f"          · {r}")
        for n in notes:
            print("note:", n)
    return 1 if args.fail_on_act_now and any(e.tier == "ACT_NOW" for e in exposures) else 0


if __name__ == "__main__":
    sys.exit(main())
