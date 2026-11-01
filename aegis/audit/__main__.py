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
    log = AuditLog(Path(args.audit), repair=False)
    rep = log.verify_report(all_files=args.all)
    if args.json:
        print(json.dumps(rep))
    elif rep["ok"]:
        print(f"intact: {rep['entries']} entries across {len(rep['files'])} file(s) · tail {rep.get('tail', '')[:16]}")
    else:
        print(f"BROKEN at {rep['broken_at']} after {rep['entries']} intact entries")
    return 0 if rep["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
