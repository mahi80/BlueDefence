"""``python -m aegis.store stats | reindex [--audit PATH] [--hitl DIR] [--url URL]``

``reindex`` exits 1 when the chain breaks or an insert failed (the index is then partial and marked stale).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import IndexStore, default_url, HAVE_SQLALCHEMY


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="aegis.store")
    ap.add_argument("cmd", choices=["stats", "reindex"])
    ap.add_argument("--audit", default=os.environ.get("AEGIS_AUDIT_PATH", "/var/lib/aegis/audit.jsonl"))
    ap.add_argument("--hitl", default=os.environ.get("AEGIS_HITL_DIR", ""))
    ap.add_argument("--url", default=os.environ.get("AEGIS_INDEX_URL", ""))
    a = ap.parse_args(argv)
    if not HAVE_SQLALCHEMY:
        print("SQLAlchemy is not installed: pip install 'bluedefence[index]'", file=sys.stderr)
        return 2
    audit = Path(a.audit)
    store = IndexStore(a.url or default_url(audit))
    if a.cmd == "stats":
        print(json.dumps(store.stats(), indent=2))
        return 0
    res = store.reindex(audit, hitl_dir=Path(a.hitl) if a.hitl else None)
    print(json.dumps({**res, **store.stats()}, indent=2))
    # a broken chain or a failed insert leaves the index partial: cron / CI must see that (review round 8 R8-6)
    if res.get("broken_at") or res.get("stale"):
        print(f"reindex incomplete: broken_at={res.get('broken_at')} stale={res.get('stale')} — "
              "run python -m aegis.audit verify --all", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
