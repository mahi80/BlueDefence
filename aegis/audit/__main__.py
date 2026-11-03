from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from aegis.agents.shared.audit import AuditLog


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m aegis.audit", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="verify the hash chain (exit 0 = intact, 1 = broken)")
    v.add_argument("--audit", default=os.environ.get("AEGIS_AUDIT_PATH", "aegis/_audit_log.jsonl"))
    v.add_argument("--all", action="store_true", help="include rotated segments (audit.jsonl.<ts>) as one chain")
    v.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    path = Path(args.audit)
    if not path.exists() and not any(path.parent.glob(path.name + ".*")):
        # a typo'd path or a cron with the wrong cwd printed "intact: 0 entries" and exited 0 (review round 4 D4-13)
        print(f"no audit log at {path} — nothing was verified", file=sys.stderr)
        return 2
    log = AuditLog(path, repair=False)
    rep = log.verify_report(all_files=args.all)
    if rep["ok"] and not args.all and AuditLog.anchor_path() is not None:
        # anchors are only checked against the whole chain: without --all a log cut back past its anchors
        # verified "intact" (review round 4 D4-13)
        whole = log.verify_report(all_files=True)
        if not whole["ok"]:
            rep = whole
    if args.json:
        print(json.dumps(rep))
    elif rep["ok"]:
        print(f"intact: {rep['entries']} entries across {len(rep['files'])} file(s) · tail {rep.get('tail', '')[:16]}")
    else:
        print(f"BROKEN at {rep['broken_at']} after {rep['entries']} intact entries")
    return 0 if rep["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
