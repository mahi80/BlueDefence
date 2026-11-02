"""Helpers for deploy/floci/run.sh — read BlueDefence's outputs, never change them.

    python deploy/floci/report.py matrix BUNDLE [--crash LOG]      collector section → ok / unsupported / error
    python deploy/floci/report.py tiers EXPOSURE.json               one line per scored finding
    python deploy/floci/report.py revoke-cmds EXPOSURE.json ASSET PORT
                                                                    the `cut_path` commands remediation.build_options
                                                                    generates for that finding (one per line)
    python deploy/floci/report.py summary OUTDIR                    markdown summary (support matrix, tiers before/after,
                                                                    known-bug checks) → stdout and OUTDIR/summary.md
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# The sections collect_aws_cspm() builds, in its order. load_balancer_waf is not a bundle key: it is
# the per-ALB wafv2 lookup, which records its own error without dropping load_balancers.
SECTIONS = ("account_public_access_block", "buckets", "security_groups", "instances", "volumes",
            "ebs_encryption_by_default", "vpcs", "db_instances", "trails", "kms_keys", "guardduty_detectors",
            "config_recorders", "load_balancers", "load_balancer_waf", "password_policy")
UNSUPPORTED_CODES = {"InvalidAction", "UnknownOperation", "UnknownOperationException", "UnsupportedOperation",
                     "NotImplemented", "NotImplementedException", "UnsupportedOperationException", "501", "404"}
# What the estate should look like, and what a correct engine would say about each designed finding.
DESIGN = [
    # (asset, port, CVE, correct tier, why it is in the estate)
    ("bank-web", 22, "CVE-2024-6387", "ACT_NOW", "SSH open to 0.0.0.0/0 on a public host; revoked mid-run"),
    ("bank-mgmt", 8443, "CVE-2022-22965", "SCHEDULE", "bug (b): public host whose SG opens only ICMP"),
    ("bank-app", 8080, "CVE-2021-44228", "ACT_NOW", "bug (d): reached via ALB 443 → 8080"),
    ("bank-db", 5432, "CVE-2024-10979", "ACT", "one hop: 5432 allowed from the web SG only"),
    ("bank-db", 6379, "CVE-2022-0543", "ACT", "bug (a): private host, 6379 open to 0.0.0.0/0 → web host can reach it"),
    ("bank-ipv6", 443, "CVE-2023-44487", "ACT_NOW", "bug (c): IPv6-only public API, 443 open to ::/0"),
]


def _load(p: Path) -> dict | None:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _count(v: object) -> str:
    if isinstance(v, list):
        return f"{len(v)} item(s)"
    if v is None:
        return "none set"
    if isinstance(v, dict):
        return "present"
    return repr(v)


def matrix(bundle: dict | None) -> list[tuple[str, str, str]]:
    if bundle is None:
        return [(s, "not run", "export-aws did not produce a bundle") for s in SECTIONS]
    errs = bundle.get("collection_errors") or {}
    rows = []
    for s in SECTIONS:
        if s in errs:
            code = str(errs[s]).split(":", 1)[0].strip()
            low = str(errs[s]).lower()
            unsupported = code in UNSUPPORTED_CODES or "not implemented" in low or "not supported" in low \
                or "unknown operation" in low or "no such operation" in low
            rows.append((s, "unsupported" if unsupported else "error", str(errs[s])[:160]))
        elif s == "load_balancer_waf":
            ok = "load_balancers" in bundle
            n = sum(1 for lb in bundle.get("load_balancers") or [] if lb.get("Type") == "application")
            rows.append((s, "ok" if ok and n else "not exercised", f"{n} ALB(s) looked up" if ok else "load_balancers failed"))
        elif s in bundle:
            rows.append((s, "ok", _count(bundle[s])))
        else:
            rows.append((s, "missing", "not in bundle and no collection_error recorded"))
    return rows


def _exposures(doc: dict | None) -> list[dict]:
    return (doc or {}).get("exposures") or []


def _find(doc: dict | None, asset: str, port: int) -> dict | None:
    return next((e for e in _exposures(doc) if e.get("asset_name") == asset and e.get("port") == port), None)


def revoke_cmds(doc: dict, asset: str, port: int) -> list[str]:
    from aegis.exposure.remediation import build_options

    e = _find(doc, asset, port)
    if e is None:
        return []
    # the shape the posture runner stores for an exposure finding (row.extra = the exposure)
    row = {"id": e.get("cve"), "resource": e.get("asset"), "affected_component": f"{e.get('asset_name')}:{port}",
           "extra": e}
    return [c for o in build_options(row) if o["kind"] == "cut_path" for c in o["commands"]]


def fidelity(bundle: dict | None) -> list[str]:
    """What the emulator returned that matters for the exposure model."""
    if not bundle:
        return []
    out = []
    by_name = {}
    for i in bundle.get("instances") or []:
        name = next((t.get("Value") for t in i.get("Tags") or [] if t.get("Key") == "Name"), i.get("InstanceId"))
        by_name[name] = i
    for n in ("bank-web", "bank-mgmt", "bank-db", "bank-app", "bank-ipv6"):
        i = by_name.get(n)
        if i is None:
            out.append(f"{n}: not returned by DescribeInstances")
            continue
        v6 = [a.get("Ipv6Address") for ni in i.get("NetworkInterfaces") or [] for a in ni.get("Ipv6Addresses") or []]
        out.append(f"{n}: state={(i.get('State') or {}).get('Name')} public_ip={i.get('PublicIpAddress') or '-'} "
                   f"private_ip={i.get('PrivateIpAddress') or '-'} vpc={i.get('VpcId') or '-'} "
                   f"sgs={','.join(g.get('GroupId', '?') for g in i.get('SecurityGroups') or [])} ipv6={','.join(v6) or '-'}")
    for g in bundle.get("security_groups") or []:
        if not str(g.get("GroupName", "")).startswith("bank-"):
            continue
        rules = []
        for p in g.get("IpPermissions") or []:
            src = [r.get("CidrIp") for r in p.get("IpRanges") or []] + [r.get("CidrIpv6") for r in p.get("Ipv6Ranges") or []] \
                + [r.get("GroupId") for r in p.get("UserIdGroupPairs") or []]
            rules.append(f"{p.get('IpProtocol')}/{p.get('FromPort')}-{p.get('ToPort')}<-{'+'.join(str(s) for s in src)}")
        out.append(f"{g.get('GroupName')} ({g.get('GroupId')}): {'; '.join(rules) or 'no ingress'}")
    for lb in bundle.get("load_balancers") or []:
        out.append(f"{lb.get('LoadBalancerName')}: scheme={lb.get('Scheme')} sgs={lb.get('SecurityGroups')} "
                   f"listeners={lb.get('listeners')} targets={lb.get('targets')} waf={lb.get('web_acl')}")
    return out


def bug_checks(before: dict | None, after: dict | None, bundle: dict | None) -> list[tuple[str, str, str]]:
    rows = []
    e = _find(before, "bank-db", 6379)
    if e is None:
        rows.append(("(a) open-to-world private host not laterally reachable", "not tested", "bank-db:6379 not scored"))
    else:
        shown = e["reach"] == "isolated"
        rows.append(("(a) open-to-world private host not laterally reachable", "EXPOSED" if shown else "not shown",
                     f"bank-db:6379 reach={e['reach']} tier={e['tier']} (correct: one_hop / ACT)"))
    e = _find(before, "bank-mgmt", 8443)
    if e is None:
        rows.append(("(b) ICMP / -1 rule read as all ports", "not tested", "bank-mgmt:8443 not scored"))
    else:
        shown = e["reach"] == "internet"
        rows.append(("(b) ICMP / -1 rule read as all ports", "EXPOSED" if shown else "not shown",
                     f"bank-mgmt:8443 reach={e['reach']} tier={e['tier']} via range {e.get('path', {}).get('range')} "
                     "(correct: not reachable, its SG opens only ICMP)"))
    e = _find(before, "bank-ipv6", 443)
    inst = next((i for i in (bundle or {}).get("instances") or []
                 if any(t.get("Value") == "bank-ipv6" for t in i.get("Tags") or [])), None)
    has_v6 = bool(inst and any(ni.get("Ipv6Addresses") for ni in inst.get("NetworkInterfaces") or []))
    if e is None:
        rows.append(("(c) IPv6-only public instance never internet-reachable", "not tested", "bank-ipv6:443 not scored"))
    else:
        shown = e["reach"] != "internet"
        how = "emulator assigned an IPv6 address" if has_v6 else "emulator did NOT assign an IPv6 address (IPv6 not modelled)"
        rows.append(("(c) IPv6-only public instance never internet-reachable",
                     ("EXPOSED" if has_v6 else "EXPOSED (partly: no IPv6 address)") if shown else "not shown",
                     f"bank-ipv6:443 reach={e['reach']} tier={e['tier']}; {how}; the loader reads only PublicIpAddress"))
    b, a = _find(before, "bank-app", 8080), _find(after, "bank-app", 8080)
    if b is None:
        rows.append(("(d) ALB-target revoke names target port on the ALB SG", "not tested", "bank-app:8080 not scored"))
    else:
        cmds = revoke_cmds(before, "bank-app", 8080)
        on = b.get("path", {}).get("opened_by")
        still = a is not None and a["tier"] == b["tier"]
        shown = bool(cmds) and all("--port 8080" in c or "FromPort=8080" in c for c in cmds) and still
        rows.append(("(d) ALB-target revoke names target port on the ALB SG", "EXPOSED" if shown else "not shown",
                     f"bank-app:8080 {b['tier']} opened_by={on}; generated `{cmds[0] if cmds else '-'}`; "
                     f"after executing it: {a['tier'] if a else 'not scored'}"))
    return rows


def _md_table(head: tuple[str, ...], rows: list[tuple]) -> list[str]:
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    out += ["| " + " | ".join(str(c).replace("|", "/").replace("\n", " ") for c in r) + " |" for r in rows]
    return out


def summary(outdir: Path) -> str:
    bundle = _load(outdir / "bundle-before.json")
    bundle_after = _load(outdir / "bundle-after.json")
    before, after = _load(outdir / "exposure-before.json"), _load(outdir / "exposure-after.json")
    L = ["# Floci integration spike — BlueDefence AWS posture collector + exposure engine", ""]
    crashes = (outdir / "crashes.txt").read_text(encoding="utf-8").strip() if (outdir / "crashes.txt").exists() else ""
    L += [f"**BlueDefence crashes:** {crashes.replace(chr(10), '; ') if crashes else 'none'}", ""]
    L += ["## Collector support matrix (export-aws against Floci)", ""]
    L += _md_table(("section", "status", "detail"), matrix(bundle))
    est = (outdir / "estate-errors.tsv").read_text(encoding="utf-8").strip() if (outdir / "estate-errors.tsv").exists() else ""
    L += ["", "## Provisioning calls the emulator refused", ""]
    L += _md_table(("call", "error"), [tuple(x.split("\t", 1) + [""])[:2] for x in est.splitlines()]) if est else ["none"]
    L += ["", "## Tiers before / after executing the generated revoke for bank-web:22", ""]
    rows = []
    for asset, port, cve, correct, why in DESIGN:
        b, a = _find(before, asset, port), _find(after, asset, port)
        rows.append((f"{asset}:{port}", cve, b["tier"] if b else "-", b["reach"] if b else "-",
                     a["tier"] if a else "-", a["reach"] if a else "-", correct, why))
    L += _md_table(("finding", "CVE", "before", "reach", "after", "reach", "correct", "why it is here"), rows)
    for label, doc in (("before", before), ("after", after)):
        if doc:
            L += ["", f"tiers {label}: " + ", ".join(f"{k} {v}" for k, v in (doc.get("tiers") or {}).items())
                  + f"; funnel {doc.get('funnel')}"]
    rv = (outdir / "revoke.log").read_text(encoding="utf-8").strip() if (outdir / "revoke.log").exists() else ""
    L += ["", "## Generated revoke commands executed against Floci", "", "```", rv or "(none)", "```"]
    L += ["", "## Known-bug checks", ""]
    L += _md_table(("bug", "result", "evidence"), bug_checks(before, after, bundle))
    L += ["", "## What Floci returned (estate as the collector saw it, before the revoke)", "", "```"]
    L += fidelity(bundle) or ["(no bundle)"]
    L += ["```"]
    if bundle_after:
        web = next((g for g in bundle_after.get("security_groups") or [] if g.get("GroupName") == "bank-web-sg"), None)
        if web is not None:
            L += ["", "bank-web-sg after the revoke: " + "; ".join(
                f"{p.get('IpProtocol')}/{p.get('FromPort')}-{p.get('ToPort')}" for p in web.get("IpPermissions") or [])]
    text = "\n".join(L) + "\n"
    (outdir / "summary.md").write_text(text, encoding="utf-8")
    return text


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    cmd, rest = argv[0], argv[1:]
    if cmd == "matrix":
        for s, st, d in matrix(_load(Path(rest[0]))):
            print(f"{st:13} {s:28} {d}")
        return 0
    if cmd == "tiers":
        doc = _load(Path(rest[0]))
        for e in _exposures(doc):
            print(f"{e['tier']:9} {e['asset_name']}:{e['port']:<5} {e.get('cve') or '-':16} reach={e['reach']:8} "
                  f"defended={e['defended']:7} opened_by={e.get('path', {}).get('opened_by')}")
        print("tiers:", (doc or {}).get("tiers"))
        return 0
    if cmd == "revoke-cmds":
        for c in revoke_cmds(_load(Path(rest[0])) or {}, rest[1], int(rest[2])):
            print(c)
        return 0
    if cmd == "summary":
        print(summary(Path(rest[0])))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
