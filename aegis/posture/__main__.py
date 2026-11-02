"""CLI for the posture scanners.

    python -m aegis.posture iam  --auth-details F [--credential-report F] [--live] [--json] [--fail-on SEV]
    python -m aegis.posture cspm --bundle F [--live --region R] [--json] [--fail-on SEV]
    python -m aegis.posture export-aws --out F [--region R]     # run by the bank, with its own read-only creds

Exit codes: 0 ok, 1 a finding at or above ``--fail-on``, 2 bad or missing input. The same command
works as a scheduled report and as a pipeline gate.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import cspm, iam_review, sources
from .base import SEVERITY_ORDER, summarize


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


SCANS = {"iam": _iam, "cspm": _cspm}


def _report(scan: str, findings: list, notes: list[str], as_json: bool) -> None:
    if as_json:
        print(json.dumps({"scan": scan, "summary": summarize(findings), "notes": notes,
                          "findings": [f.as_dict() for f in findings]}, indent=2))
        return
    for f in findings:
        ctl = f"  [{f.control}]" if f.control else ""
        print(f"{f.severity.upper():8} {f.id:32} {f.affected_component}{ctl}\n         {f.evidence}\n         fix: {f.recommended_remediation}")
    print("summary:", ", ".join(f"{k} {v}" for k, v in summarize(findings).items()))
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

    for p in (iam, cs):
        p.add_argument("--live", action="store_true", help="collect via read-only APIs (needs AEGIS_POSTURE_LIVE=1)")
        p.add_argument("--json", action="store_true", help="machine-readable output")
        p.add_argument("--fail-on", choices=SEVERITY_ORDER, help="exit 1 if any finding is this severe or worse")

    ex = sub.add_parser("export-aws", help="write a CSPM bundle using the caller's own read-only AWS credentials")
    ex.add_argument("--out", required=True, help="output JSON file")
    ex.add_argument("--region", help="region to export (default: the SDK's configured region)")

    args = ap.parse_args(argv)
    try:
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

    _report(args.scan, findings, notes, args.json)
    if args.fail_on:
        limit = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f.severity) <= limit for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
