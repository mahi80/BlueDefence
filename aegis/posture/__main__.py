"""CLI: ``python -m aegis.posture iam [--auth-details F] [--credential-report F] [--live] [--json]``.

Exit code is 1 when any finding is at or above ``--fail-on`` (default: never fail), so the same
command works as a scheduled report and as a pipeline gate.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import iam_review, sources
from .base import SEVERITY_ORDER, summarize


def _iam(args: argparse.Namespace) -> tuple[list, str | None]:
    if args.live:
        details, report = sources.live_aws_iam()
    else:
        if not args.auth_details:
            raise sources.PostureSourceError("pass --auth-details FILE (aws iam get-account-authorization-details) or --live")
        details = sources.load_json(args.auth_details)
        report = sources.load_credential_report(args.credential_report) if args.credential_report else None
    findings = iam_review.review(details, report, trusted_accounts=args.trusted_account or ())
    return findings, iam_review.coverage_note(report)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m aegis.posture", description="BlueDefence posture scans")
    sub = ap.add_subparsers(dest="scan", required=True)
    iam = sub.add_parser("iam", help="AWS IAM review")
    iam.add_argument("--auth-details", help="aws iam get-account-authorization-details > FILE")
    iam.add_argument("--credential-report", help="aws iam get-credential-report > FILE (JSON, base64 or CSV)")
    iam.add_argument("--trusted-account", action="append", help="external AWS account ID approved for cross-account trust (repeatable)")
    for p in (iam,):
        p.add_argument("--live", action="store_true", help="collect via read-only APIs (needs AEGIS_POSTURE_LIVE=1)")
        p.add_argument("--json", action="store_true", help="machine-readable output")
        p.add_argument("--fail-on", choices=SEVERITY_ORDER, help="exit 1 if any finding is this severe or worse")
    args = ap.parse_args(argv)

    try:
        findings, note = {"iam": _iam}[args.scan](args)
    except sources.PostureSourceError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({"scan": args.scan, "summary": summarize(findings), "note": note,
                          "findings": [f.as_dict() for f in findings]}, indent=2))
    else:
        for f in findings:
            ctl = f"  [{f.control}]" if f.control else ""
            print(f"{f.severity.upper():8} {f.id:28} {f.affected_component}{ctl}\n         {f.evidence}\n         fix: {f.recommended_remediation}")
        print("summary:", ", ".join(f"{k} {v}" for k, v in summarize(findings).items()))
        if note:
            print("note:", note)

    if args.fail_on:
        limit = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f.severity) <= limit for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
