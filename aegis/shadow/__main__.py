"""CLI — ``python -m aegis.shadow report``.

    # against the dashboard (ACP_DASHBOARD_URL / ACP_API_KEY): receipts + chains + analyst decisions
    python -m aegis.shadow report --dashboard [--since 2026-10-01T00:00:00Z]

    # offline, from the agent host's files
    python -m aegis.shadow report --receipts aegis/_receipts.jsonl --audit aegis/_audit_log.jsonl

    # thresholds (defaults = roadmap 1.5: 20 receipts, 10 reviewed, 14 days, 95 % agreement)
    python -m aegis.shadow report --dashboard --min-n 50 --window-days 14 --json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Iterator, Optional

from .report import Thresholds, build_report, render_text, to_json


def _headers(api_key: str) -> dict:
    h = {"Accept": "application/json"}
    if api_key:
        h["X-API-Key"] = api_key
    return h


def iter_dashboard_receipts(dashboard_url: str, api_key: str, *, since: Optional[str] = None,
                            page_size: int = 500, transport: Any = None, timeout: float = 30.0,
                            max_pages: int = 10_000) -> Iterator[dict]:
    """Yield receipt rows from ``GET /api/soc/receipts``, following cursors."""
    from aegis.dataset.sources import _httpx_transport
    tr = transport or _httpx_transport
    base = dashboard_url.rstrip("/")
    cursor: Optional[str] = None
    for _ in range(max_pages):
        q = f"limit={int(page_size)}"
        if since:
            q += f"&since={since}"
        if cursor:
            q += f"&cursor={cursor}"
        data = tr("GET", f"{base}/api/soc/receipts?{q}", None, _headers(api_key), timeout)
        if data.get("error"):
            raise RuntimeError(f"dashboard refused: {data['error']}")
        for r in data.get("receipts") or []:
            if isinstance(r, dict):
                yield r
        cursor = data.get("next_cursor")
        if not cursor:
            return


def load_dashboard(dashboard_url: str, api_key: str, *, since: Optional[str] = None,
                   transport: Any = None) -> tuple[list[dict], list[dict]]:
    from aegis.dataset.sources import iter_dashboard_pages
    receipts = list(iter_dashboard_receipts(dashboard_url, api_key, since=since, transport=transport))
    chains = list(iter_dashboard_pages(dashboard_url, api_key, since=since, transport=transport))
    return receipts, chains


def load_local(receipts_path: Optional[str], audit_path: Optional[str]) -> tuple[list[dict], list[dict]]:
    from aegis.agents.response.receipts import ReceiptLog
    receipts = ReceiptLog.latest_per_receipt(ReceiptLog.read(receipts_path)) if receipts_path else []
    chains: list[dict] = []
    if audit_path and Path(audit_path).exists():
        latest: dict[str, dict] = {}
        for line in Path(audit_path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                c = json.loads(line)
            except json.JSONDecodeError:
                continue
            latest[str(c.get("alert_id") or len(latest))] = c
        chains = list(latest.values())
    return receipts, chains


def load_local_decisions(hitl_dir: str | None) -> dict[str, list[dict]]:
    """Analyst decisions from the file transport (``cards.jsonl`` + ``decisions.jsonl``), keyed by alert id.
    The local report had no decision source, so nothing was ever "reviewed" and the 1.5 window could not
    reach ``ready`` off the dashboard (code review 2026-11-03 C8). Only rows that pass the same signature
    check the service applies count."""
    if not hitl_dir:
        return {}
    from aegis.hitl.signing import trusted_approver, verify
    d = Path(hitl_dir)
    cards: dict[str, dict] = {}
    out: dict[str, list[dict]] = {}

    def rows(path: Path):
        if not path.exists():
            return
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                r = json.loads(line)
            except (json.JSONDecodeError, RecursionError):
                continue
            if isinstance(r, dict):
                yield r
    for c in rows(d / "cards.jsonl"):
        if c.get("kind") == "approval" and c.get("id"):
            cards[str(c["id"])] = c.get("args") or {}
    for r in rows(d / "decisions.jsonl"):
        args = cards.get(str(r.get("approval_id") or ""))
        status = str(r.get("status") or "").lower()
        if not args or status not in ("approved", "rejected") or not verify(r)[0] or not trusted_approver(r.get("decided_by"))[0]:
            continue
        out.setdefault(str(args.get("alert_id") or ""), []).append(
            {"action_type": args.get("action_type"), "target": args.get("target"), "decision": status,
             "decided_by": r.get("decided_by")})
    return out


def cmd_report(args: argparse.Namespace) -> int:
    th = Thresholds(min_n=args.min_n, min_reviewed=args.min_reviewed, window_days=args.window_days,
                    agreement=args.agreement, max_failed=args.max_failed)
    if args.dashboard:
        url = os.environ.get("ACP_DASHBOARD_URL", "").strip()
        if not url:
            print("--dashboard needs ACP_DASHBOARD_URL (and ACP_API_KEY)", file=sys.stderr)
            return 2
        receipts, chains = load_dashboard(url, os.environ.get("ACP_API_KEY", ""), since=args.since)
        decisions = None
    else:
        receipts, chains = load_local(args.receipts, args.audit)
        decisions = load_local_decisions(args.hitl_dir or os.environ.get("AEGIS_HITL_DIR", "").strip() or None)
    protected = [p.strip() for p in os.environ.get("AEGIS_PROTECTED_TARGETS", "").split(",") if p.strip()]
    rep = build_report(receipts, chains, thresholds=th, protected_targets=protected, decisions_by_alert=decisions)
    print(to_json(rep) if args.json else render_text(rep))
    if args.out:
        Path(args.out).write_text(to_json(rep) + "\n", encoding="utf-8")
    if args.fail_unless_ready and not rep.summary.get("ready"):
        return 1        # a scheduled check can now tell "nothing ready" from "ready" (it always exited 0)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m aegis.shadow", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    rp = sub.add_parser("report", help="compare receipts with analyst decisions; list what is ready to flip live")
    rp.add_argument("--dashboard", action="store_true", help="read receipts + chains + decisions from ACP_DASHBOARD_URL")
    rp.add_argument("--since", default=None, help="ISO timestamp; only rows created after it (dashboard mode)")
    rp.add_argument("--receipts", default=None, help="local receipts JSONL (aegis/_receipts.jsonl)")
    rp.add_argument("--audit", default=None, help="local audit JSONL (aegis/_audit_log.jsonl)")
    rp.add_argument("--min-n", type=int, default=20)
    rp.add_argument("--min-reviewed", type=int, default=10)
    rp.add_argument("--window-days", type=float, default=14.0)
    rp.add_argument("--agreement", type=float, default=0.95)
    rp.add_argument("--max-failed", type=int, default=0)
    rp.add_argument("--hitl-dir", default=None, help="file-transport HITL directory for analyst decisions "
                                                       "(local mode; default AEGIS_HITL_DIR)")
    rp.add_argument("--fail-unless-ready", action="store_true", help="exit 1 when no group is ready to flip live")
    rp.add_argument("--json", action="store_true", help="print JSON instead of the table")
    rp.add_argument("--out", default=None, help="also write the JSON report to this path")
    rp.set_defaults(fn=cmd_report)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
