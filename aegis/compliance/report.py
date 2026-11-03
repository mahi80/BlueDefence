"""Compliance reporter — walks the audit log, emits regulator-ready output.

Bank regulators (RBI, CERT-In, DPDP authority, PCI-DSS auditors) all
need a per-decision evidence trail. The audit log is hash-chained and
contains every EvidenceChain the agentic layer ever produced; this CLI
walks it, computes summary statistics, verifies integrity, and emits
two formats:

  - report.json: machine-readable, suitable for ingestion into a GRC
    platform (Archer, MetricStream, ServiceNow GRC).
  - report.md:   human-readable summary for the bank's compliance
    officer or an external auditor.

Filters:
  --since YYYY-MM-DD       only decisions on or after this date
  --until YYYY-MM-DD       only decisions on or before this date
  --verdict {malicious,...}  filter to one verdict class
  --specialist NAME        filter to one investigating agent
  --customer-id ID         only decisions whose alert.user_id matched

The integrity status is the LEAD finding — if the hash chain breaks,
nothing else in the report can be trusted.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from aegis.agents.shared.audit import AuditLog


def _parse_date(s: str) -> datetime:
    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)


def _load_entries(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out: list[dict] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def _filter_entries(entries: list[dict], *,
                    since: Optional[datetime] = None,
                    until: Optional[datetime] = None,
                    verdict: Optional[str] = None,
                    specialist: Optional[str] = None,
                    customer_id: Optional[str] = None) -> list[dict]:
    out: list[dict] = []
    for e in entries:
        ts_str = e.get("started_at")
        if ts_str:
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except ValueError:
                ts = None
        else:
            ts = None
        if since and ts and ts < since:
            continue
        if until and ts and ts > until:
            continue
        if verdict and e.get("verdict") != verdict:
            continue
        if specialist and e.get("investigated_by") != specialist:
            continue
        if customer_id:
            ev = e.get("evidence", []) or []
            actions = e.get("recommended_actions", []) or []
            hit = any(customer_id in (a.get("target") or "") for a in actions)
            if not hit:
                hit = any(customer_id in json.dumps(it.get("raw_data", {})) for it in ev)
            if not hit:
                continue
        out.append(e)
    return out


def _summary(entries: list[dict]) -> dict:
    if not entries:
        return {"total": 0, "by_verdict": {}, "by_specialist": {},
                "with_hitl_action": 0, "high_impact_action_count": 0}
    by_verdict = Counter(e.get("verdict", "?") for e in entries)
    by_specialist = Counter(e.get("investigated_by", "?") for e in entries)
    with_hitl = 0
    high_impact = 0
    for e in entries:
        actions = e.get("recommended_actions") or []
        if any(a.get("requires_hitl") for a in actions):
            with_hitl += 1
        for a in actions:
            t = a.get("action_type")
            if t in ("block", "isolate", "lock_account", "revoke_sessions",
                     "trigger_self_heal", "kill_process", "quarantine_file",
                     "escalate_to_fraud_team", "hold"):
                high_impact += 1
    confs = [float(e.get("confidence", 0.0)) for e in entries if e.get("confidence") is not None]
    confidence_p50 = sorted(confs)[len(confs)//2] if confs else 0.0
    confidence_p99 = sorted(confs)[max(0, int(len(confs)*0.99) - 1)] if confs else 0.0
    return {
        "total": len(entries),
        "by_verdict": dict(by_verdict),
        "by_specialist": dict(by_specialist),
        "with_hitl_action": with_hitl,
        "high_impact_action_count": high_impact,
        "confidence_p50": round(confidence_p50, 3),
        "confidence_p99": round(confidence_p99, 3),
    }


def _markdown(report: dict) -> str:
    lines: list[str] = []
    lines.append(f"# AEGIS Compliance Report")
    lines.append(f"")
    lines.append(f"**Generated:** {report['generated_at']}  ")
    lines.append(f"**Audit log:** `{report['audit_log_path']}`  ")
    lines.append(f"**Hash-chain integrity:** {'PASS' if report['integrity_pass'] else '**FAIL** — DO NOT RELY ON THIS REPORT'}")
    lines.append("")
    if report.get("filters"):
        lines.append(f"**Filters applied:** {report['filters']}")
        lines.append("")
    s = report["summary"]
    lines.append(f"## Summary")
    lines.append(f"")
    lines.append(f"- **Decisions:** {s['total']}")
    lines.append(f"- **HITL-gated:** {s['with_hitl_action']} ({100*s['with_hitl_action']/max(s['total'],1):.1f}%)")
    lines.append(f"- **High-impact actions recommended:** {s['high_impact_action_count']}")
    lines.append(f"- **Confidence P50/P99:** {s.get('confidence_p50', 0):.3f} / {s.get('confidence_p99', 0):.3f}")
    lines.append(f"")
    lines.append(f"### By verdict")
    for v, n in sorted(s.get("by_verdict", {}).items(), key=lambda x: -x[1]):
        lines.append(f"- `{v}`: {n}")
    lines.append(f"")
    lines.append(f"### By specialist")
    for sp, n in sorted(s.get("by_specialist", {}).items(), key=lambda x: -x[1]):
        lines.append(f"- `{sp}`: {n}")
    lines.append(f"")
    lines.append(f"## Decisions")
    lines.append(f"")
    for e in report.get("decisions", []):
        ts = e.get("started_at", "?")
        verdict = e.get("verdict", "?")
        conf = e.get("confidence", 0)
        actions = ", ".join(
            f"{a['action_type']}{'(HITL)' if a.get('requires_hitl') else ''}"
            for a in (e.get("recommended_actions") or [])
        ) or "(none)"
        ihash = (e.get("integrity_hash") or "")[:16]
        lines.append(f"- **{e.get('alert_id')}** — {ts}")
        lines.append(f"  - verdict: `{verdict}` (confidence {conf:.2f})")
        lines.append(f"  - investigated_by: `{e.get('investigated_by')}`")
        lines.append(f"  - actions: {actions}")
        lines.append(f"  - integrity: `{ihash}...`")
        lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(
        "_This report is generated from the AEGIS audit log "
        "(append-only, SHA-256 hash-chained per entry). "
        "Integrity is verified at generation time; any subsequent "
        "tampering breaks the chain and is detected by the next "
        "verification run._"
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--audit", default="aegis/_audit_log.jsonl",
                   help="Path to the audit log JSONL")
    p.add_argument("--since", help="ISO date (YYYY-MM-DD)")
    p.add_argument("--until", help="ISO date (YYYY-MM-DD)")
    p.add_argument("--verdict", choices=["benign", "suspicious", "malicious", "uncertain"])
    p.add_argument("--specialist")
    p.add_argument("--customer-id")
    p.add_argument("--out-json", default="compliance_report.json")
    p.add_argument("--out-md", default="compliance_report.md")
    args = p.parse_args()

    audit_path = Path(args.audit)
    if not audit_path.exists():
        # a typo'd path reported "integrity PASS" over zero decisions — a clean-looking report of nothing
        # (review round 3 G6-3)
        print(f"audit log {audit_path} does not exist — no report", file=sys.stderr)
        return 2
    log = AuditLog(audit_path, repair=False)
    # the whole chain, rotated segments included: only the live segment was checked, so a rewritten older
    # segment still read PASS
    rep = log.verify_report(all_files=True)
    integrity = bool(rep.get("ok"))
    entries = [e for f in [*log.rotated_files(), audit_path] for e in _load_entries(f)]

    since = _parse_date(args.since) if args.since else None
    until = _parse_date(args.until) if args.until else None
    filtered = _filter_entries(
        entries, since=since, until=until,
        verdict=args.verdict, specialist=args.specialist,
        customer_id=args.customer_id,
    )

    filters = {
        k: v for k, v in {
            "since": args.since, "until": args.until,
            "verdict": args.verdict, "specialist": args.specialist,
            "customer_id": args.customer_id,
        }.items() if v
    }

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "audit_log_path": str(audit_path),
        "integrity_pass": integrity,
        "filters": filters,
        "summary": _summary(filtered),
        "decisions": filtered,
    }

    out_json = Path(args.out_json)
    out_json.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    out_md = Path(args.out_md)
    out_md.write_text(_markdown(report), encoding="utf-8")

    print(f"Compliance report written:")
    print(f"  JSON:  {out_json} ({len(filtered)} decisions)")
    print(f"  MD:    {out_md}")
    print(f"  Audit integrity: {'PASS' if integrity else 'FAIL'}")
    return 0 if integrity else 1


if __name__ == "__main__":
    sys.exit(main())
