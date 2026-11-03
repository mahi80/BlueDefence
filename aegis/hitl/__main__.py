"""``python -m aegis.hitl decide <approval_id> approve|reject --by <name> [--reason …] [--dir …]``

Records a signed decision for an approval on this host's file queue — for an operator deciding outside the
console. The row is signed with the same key the console uses (``AEGIS_DECISION_KEY`` or one derived from
``AEGIS_CONSOLE_TOKEN``), so it needs the host's environment; a hand-appended unsigned line is ignored.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from .signing import enabled, sign, trusted_approver


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m aegis.hitl")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("decide", help="record a signed approve / reject")
    d.add_argument("approval_id")
    d.add_argument("status", choices=("approve", "reject"))
    d.add_argument("--by", required=True, help="who decides (role:name)")
    d.add_argument("--reason", default="")
    d.add_argument("--dir", default=os.environ.get("AEGIS_HITL_DIR", ""), help="HITL directory (AEGIS_HITL_DIR)")
    a = ap.parse_args(argv)
    ok, why = trusted_approver(a.by)
    if not ok:
        print(f"error: {why}", file=sys.stderr)
        return 2
    if not a.dir:
        print("error: no HITL directory (--dir or AEGIS_HITL_DIR)", file=sys.stderr)
        return 2
    if not enabled():
        print("warning: no signing key in this environment (AEGIS_CONSOLE_TOKEN / AEGIS_DECISION_KEY); "
              "the row is written unsigned", file=sys.stderr)
    row = sign({"approval_id": a.approval_id, "status": "approved" if a.status == "approve" else "rejected",
                "decided_by": a.by[:120], "reason": a.reason[:500], "ts": time.time(), "via": "cli"})
    path = Path(a.dir) / "decisions.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"recorded {row['status']} for {a.approval_id} by {a.by}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
