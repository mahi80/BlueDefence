"""CLI for the posture scanners.

    python -m aegis.posture iam  --auth-details F [--credential-report F] [--live] [--json] [--fail-on SEV]
    python -m aegis.posture cspm --bundle F [--live --region R] [--json] [--fail-on SEV]
    python -m aegis.posture azure --bundle F [--live --subscription S] [--json] [--fail-on SEV]
    python -m aegis.posture export-azure --out F [--subscription S]        # run by the bank, with its own `az login`
    python -m aegis.posture k8s  --export F [--live --context C] [--include-system] [--json] [--fail-on SEV]
    python -m aegis.posture iac  [--plan F] [--k8s PATH ...] [--waivers F] [--changed-only] [--json] [--fail-on SEV]
    python -m aegis.posture run  --config posture.yaml [--store DIR] [--loop] [--fail-on SEV] [--fail-on-overdue]
    python -m aegis.posture export-aws --out F [--region R]     # run by the bank, with its own read-only creds

Exit codes: 0 ok, 1 a finding at or above ``--fail-on``, 2 bad or missing input. The same command
works as a scheduled report and as a pipeline gate.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from . import azure_cspm, cspm, iac_policy, iam_review, k8s_posture, runner, sources
from .base import SEVERITY_ORDER, sort_findings, summarize


def _iam(args: argparse.Namespace) -> tuple[list, list[str]]:
    if args.live:
        details, report = sources.live_aws_iam()
    else:
        if not args.auth_details:
            raise sources.PostureSourceError("pass --auth-details FILE (aws iam get-account-authorization-details) or --live")
        details = sources.load_json(args.auth_details)
        report = sources.load_credential_report(args.credential_report) if args.credential_report else None
    findings = iam_review.review(details, report, trusted_accounts=args.trusted_account or ())
    note = iam_review.coverage_note(report)
    return findings, [note] if note else []


def _cspm(args: argparse.Namespace) -> tuple[list, list[str]]:
    if args.live:
        bundle = sources.collect_aws_cspm(args.region)
    elif args.bundle:
        bundle = sources.load_json(args.bundle)
    else:
        raise sources.PostureSourceError("pass --bundle FILE (from `python -m aegis.posture export-aws`) or --live")
    if not isinstance(bundle, dict):
        raise sources.PostureSourceError("bundle must be a JSON object")
    gaps = cspm.coverage_gaps(bundle)
    return cspm.scan(bundle), [f"not in bundle, not checked: {', '.join(gaps)}"] if gaps else []


def _azure(args: argparse.Namespace) -> tuple[list, list[str]]:
    if args.live:
        bundle = sources.collect_azure(args.subscription)
    elif args.bundle:
        bundle = sources.load_json(args.bundle)
    else:
        raise sources.PostureSourceError("pass --bundle FILE (from `python -m aegis.posture export-azure`) or --live")
    if not isinstance(bundle, dict):
        raise sources.PostureSourceError("bundle must be a JSON object")
    return azure_cspm.scan(bundle), [f"not in bundle, not checked: {', '.join(azure_cspm.coverage_gaps(bundle))}"]


def _k8s(args: argparse.Namespace) -> tuple[list, list[str]]:
    if args.live:
        export = sources.collect_k8s(args.context)
    elif args.export:
        export = sources.load_json(args.export)
    else:
        raise sources.PostureSourceError(f"pass --export FILE ({k8s_posture.EXPORT_COMMAND} > FILE) or --live")
    if not isinstance(export, (dict, list)):
        raise sources.PostureSourceError("export must be a kubectl JSON List")
    return (k8s_posture.scan(export, include_system=args.include_system),
            k8s_posture.notes(export, include_system=args.include_system))


def _iac(args: argparse.Namespace) -> tuple[list, list[str]]:
    if not args.plan and not args.k8s:
        raise sources.PostureSourceError("pass --plan FILE (terraform show -json plan.out > FILE) and/or --k8s PATH")
    findings = []
    if args.plan:
        plan = sources.load_json(args.plan)
        if not isinstance(plan, dict) or "resource_changes" not in plan:
            raise sources.PostureSourceError(f"{args.plan} is not a Terraform plan JSON (terraform show -json plan.out)")
        findings += iac_policy.scan_plan(plan, changed_only=args.changed_only)
    if args.k8s:
        findings += iac_policy.scan_manifests(iac_policy.load_manifests(args.k8s))
    findings = sort_findings(findings)
    notes: list[str] = []
    if args.waivers:
        findings, args.waived, notes = iac_policy.apply_waivers(findings, iac_policy.load_waivers(args.waivers))
    return findings, notes


SCANS = {"iam": _iam, "cspm": _cspm, "azure": _azure, "k8s": _k8s, "iac": _iac}


def _report(scan: str, findings: list, notes: list[str], as_json: bool, waived: list | None = None) -> None:
    waived = waived or []
    if as_json:
        print(json.dumps({"scan": scan, "summary": summarize(findings), "notes": notes,
                          "findings": [f.as_dict() for f in findings],
                          "waived": [{**f.as_dict(), "waiver": {"reason": w.reason, "approved_by": w.approved_by,
                                                                "expires": w.expires.isoformat()}} for f, w in waived]}, indent=2))
        return
    for f in findings:
        ctl = f"  [{f.control}]" if f.control else ""
        print(f"{f.severity.upper():8} {f.id:32} {f.affected_component}{ctl}\n         {f.evidence}\n         fix: {f.recommended_remediation}")
    for f, w in waived:
        print(f"WAIVED   {f.id:32} {f.affected_component}\n         {w.reason} (approved by {w.approved_by}, expires {w.expires})")
    print("summary:", ", ".join(f"{k} {v}" for k, v in summarize(findings).items()) + (f", waived {len(waived)}" if waived else ""))
    for n in notes:
        print("note:", n)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m aegis.posture", description="BlueDefence posture scans")
    sub = ap.add_subparsers(dest="scan", required=True)

    iam = sub.add_parser("iam", help="AWS IAM review")
    iam.add_argument("--auth-details", help="aws iam get-account-authorization-details > FILE")
    iam.add_argument("--credential-report", help="aws iam get-credential-report > FILE (JSON, base64 or CSV)")
    iam.add_argument("--trusted-account", action="append", help="external AWS account ID approved for cross-account trust (repeatable)")

    cs = sub.add_parser("cspm", help="AWS cloud security posture (S3, network, compute, databases, logging)")
    cs.add_argument("--bundle", help="JSON bundle from `python -m aegis.posture export-aws`")
    cs.add_argument("--region", help="region for --live (default: the SDK's configured region)")

    az = sub.add_parser("azure", help="Azure posture (storage, NSGs, databases, Key Vault, AKS, Defender, logging, RBAC)")
    az.add_argument("--bundle", help="JSON bundle from `python -m aegis.posture export-azure`")
    az.add_argument("--subscription", help="subscription id or name for --live (default: az's current one)")

    k8 = sub.add_parser("k8s", help="Kubernetes posture (workloads, RBAC, network policy)",
                        epilog=f"offline export: {k8s_posture.EXPORT_COMMAND} > FILE   (never export secrets)")
    k8.add_argument("--export", help="kubectl JSON List (see epilog for the command)")
    k8.add_argument("--context", help="kubeconfig context for --live")
    k8.add_argument("--include-system", action="store_true", help="also scan kube-system / kube-public / kube-node-lease workloads")

    ia = sub.add_parser("iac", help="policy-as-code gate on a Terraform plan and/or Kubernetes manifests (pre-deploy)")
    ia.add_argument("--plan", help="terraform show -json plan.out > FILE")
    ia.add_argument("--k8s", action="append", help="Kubernetes manifest file or directory (repeatable)")
    ia.add_argument("--waivers", help="waivers.yaml: approved exceptions (id, resource, reason, approved_by, expires)")
    ia.add_argument("--changed-only", action="store_true", help="judge only resources the plan creates or updates")
    ia.add_argument("--json", action="store_true", help="machine-readable output")
    ia.add_argument("--fail-on", choices=SEVERITY_ORDER, help="exit 1 if any unwaived finding is this severe or worse")

    for p in (iam, cs, az, k8):
        p.add_argument("--live", action="store_true", help="collect via read-only APIs (needs AEGIS_POSTURE_LIVE=1)")
        p.add_argument("--json", action="store_true", help="machine-readable output")
        p.add_argument("--fail-on", choices=SEVERITY_ORDER, help="exit 1 if any finding is this severe or worse")

    exz = sub.add_parser("export-azure", help="write an Azure bundle using the caller's own `az login` (Reader + Security Reader)")
    exz.add_argument("--out", required=True, help="output JSON file")
    exz.add_argument("--subscription", help="subscription id or name (default: az's current one)")

    rn = sub.add_parser("run", help="the VAPT loop: every scan in posture.yaml, tracked over time, with a report")
    rn.add_argument("--config", required=True, help="posture.yaml (scans, waivers, SLA days, store, interval)")
    rn.add_argument("--store", help="override the store directory (latest.json, runs/, state.json)")
    rn.add_argument("--loop", action="store_true", help="keep running every interval_minutes")
    rn.add_argument("--fail-on", choices=SEVERITY_ORDER, help="exit 1 if any open finding is this severe or worse")
    rn.add_argument("--fail-on-overdue", action="store_true", help="exit 1 if any open finding is past its SLA")

    ex = sub.add_parser("export-aws", help="write a CSPM bundle using the caller's own read-only AWS credentials")
    ex.add_argument("--out", required=True, help="output JSON file")
    ex.add_argument("--region", help="region to export (default: the SDK's configured region)")

    args = ap.parse_args(argv)
    try:
        if args.scan == "run":
            cfg = runner.load_config(args.config, store=args.store)
            if args.loop:
                logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
                runner.loop(cfg)
                return 0
            r = runner.run_once(cfg)
            c = r["counts"]
            for sc in r["scans"]:
                print(f"{sc['status'].upper():5} {sc['name']:28} {sc['type']:5} " + (sc.get("error") or ", ".join(f"{k} {v}" for k, v in sc["summary"].items() if v) or "clean"))
            print(f"run {r['run_id']}: {c['open']} open ({', '.join(f'{k} {v}' for k, v in r['summary'].items() if v) or 'none'}), "
                  f"{c['new']} new, {c['resolved']} resolved, {c['overdue']} past SLA, {c['waived']} waived, {c['stale']} stale")
            print(f"report: {cfg.store / 'runs' / (r['run_id'] + '.md')}")
            limit = SEVERITY_ORDER.index(args.fail_on) if args.fail_on else -1
            failing = any(SEVERITY_ORDER.index(o["severity"]) <= limit for o in r["open"]) or (args.fail_on_overdue and c["overdue"])
            return 1 if failing else 0
        if args.scan == "export-azure":
            bundle = sources.collect_azure(args.subscription, require_flag=False)
            Path(args.out).write_text(json.dumps(bundle, indent=1, default=str), encoding="utf-8")
            sub = bundle.get("subscription") or {}
            print(f"wrote {args.out}: subscription {sub.get('name')} ({sub.get('id')}), "
                  f"{len(bundle.get('storage_accounts', []))} storage accounts, {len(bundle.get('network_security_groups', []))} NSGs")
            return 0
        if args.scan == "export-aws":
            bundle = sources.collect_aws_cspm(args.region, require_flag=False)
            Path(args.out).write_text(json.dumps(bundle, indent=1, default=str), encoding="utf-8")
            print(f"wrote {args.out}: account {bundle.get('account_id')} region {bundle.get('region')}, "
                  f"{len(bundle.get('buckets', []))} buckets, {len(bundle.get('security_groups', []))} security groups")
            return 0
        findings, notes = SCANS[args.scan](args)
    except sources.PostureSourceError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    _report(args.scan, findings, notes, args.json, getattr(args, "waived", None))
    if args.fail_on:
        limit = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f.severity) <= limit for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
