"""The VAPT loop — run every configured posture scan on a schedule, track each finding over time.

One ``posture.yaml`` lists the scans (IAM, CSPM per account/region, Kubernetes per cluster, IaC per
repo). Each run:

1. executes every scan (offline export or live, exactly as the CLI would);
2. applies the bank's single waiver register to all of them;
3. fingerprints every finding and compares with the previous run → **new**, **still open** (with its
   first-seen date and age) and **resolved**;
4. checks each open finding against the remediation SLA for its severity and flags breaches;
5. writes ``runs/<run_id>.json`` + a VAPT-style ``runs/<run_id>.md`` report, and ``latest.json`` (what
   the SOC console's Posture page reads).

A scan that **fails** (missing export, permission denied) never makes its findings look resolved: its
previous open findings are carried forward marked ``stale`` and the run records the error.

    python -m aegis.posture run --config posture.yaml            # one run
    python -m aegis.posture run --config posture.yaml --loop     # every interval_minutes
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from . import azure_cspm, cspm, iac_policy, iam_review, k8s_posture, sources
from .base import SEVERITY_ORDER, PostureFinding, summarize

logger = logging.getLogger("aegis.posture.runner")

DEFAULT_SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180, "info": 365}
SCAN_TYPES = ("iam", "cspm", "azure", "k8s", "iac", "exposure")


@dataclass
class ScanConfig:
    name: str
    type: str
    opts: dict[str, Any] = field(default_factory=dict)


@dataclass
class RunnerConfig:
    store: Path
    scans: list[ScanConfig]
    waivers: Path | None = None
    sla_days: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_SLA_DAYS))
    interval_minutes: int = 1440
    keep_runs: int = 90
    remediation: dict[str, Any] = field(default_factory=dict)   # exposure proposals: {enabled, tiers}


def load_config(path: str | Path, *, store: str | Path | None = None) -> RunnerConfig:
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as e:
        raise sources.PostureSourceError(f"cannot read posture config {path}: {e}") from e
    base = Path(path).resolve().parent

    def rel(p: Any) -> Path:
        q = Path(str(p)).expanduser()
        return q if q.is_absolute() else base / q

    scans, names = [], set()
    for i, s in enumerate(raw.get("scans") or [], 1):
        if not isinstance(s, dict) or not s.get("name") or s.get("type") not in SCAN_TYPES:
            raise sources.PostureSourceError(f"scan #{i} needs a unique name and a type in {SCAN_TYPES}")
        if s["name"] in names:
            raise sources.PostureSourceError(f"duplicate scan name {s['name']!r}")
        names.add(s["name"])
        opts = {k: v for k, v in s.items() if k not in ("name", "type")}
        for k in ("auth_details", "credential_report", "bundle", "export", "plan", "inventory", "kev", "epss", "settings"):
            if opts.get(k):
                opts[k] = rel(opts[k])
        for k in ("vulns", "aws_bundles", "azure_bundles", "waf_coverage"):
            if opts.get(k):
                opts[k] = [rel(x) for x in (opts[k] if isinstance(opts[k], list) else [opts[k]])]
        if opts.get("k8s_exports"):
            opts["k8s_exports"] = [(f"{n}={rel(p)}" if "=" in str(x) else str(rel(x)))
                                   for x in opts["k8s_exports"] for n, _, p in [str(x).rpartition("=")]]
        if opts.get("k8s"):
            opts["k8s"] = [rel(p) for p in (opts["k8s"] if isinstance(opts["k8s"], list) else [opts["k8s"]])]
        scans.append(ScanConfig(s["name"], s["type"], opts))
    if not scans:
        raise sources.PostureSourceError("posture config lists no scans")
    store_path = Path(store) if store else rel(raw.get("store") or "posture-store")
    sla = {**DEFAULT_SLA_DAYS, **{k: int(v) for k, v in (raw.get("sla_days") or {}).items() if k in SEVERITY_ORDER}}
    return RunnerConfig(store=store_path, scans=scans, waivers=rel(raw["waivers"]) if raw.get("waivers") else None,
                        sla_days=sla, interval_minutes=int(raw.get("interval_minutes") or 1440),
                        keep_runs=int(raw.get("keep_runs") or 90), remediation=dict(raw.get("remediation") or {}))


# ---- executing one scan ---------------------------------------------------------------------------

def execute(scan: ScanConfig) -> tuple[list[PostureFinding], list[str]] | tuple[list[PostureFinding], list[str], dict]:
    o = scan.opts
    if scan.type == "exposure":
        from ..exposure.scan import (
            run_scan,
        )
        return run_scan(o)
    if scan.type == "iam":
        if o.get("live"):
            details, report = sources.live_aws_iam()
        else:
            if not o.get("auth_details"):
                raise sources.PostureSourceError("iam scan needs auth_details (or live: true)")
            details = sources.load_json(o["auth_details"])
            report = sources.load_credential_report(o["credential_report"]) if o.get("credential_report") else None
        note = iam_review.coverage_note(report)
        return iam_review.review(details, report, trusted_accounts=o.get("trusted_accounts") or ()), [note] if note else []
    if scan.type == "cspm":
        bundle = sources.collect_aws_cspm(o.get("region")) if o.get("live") else sources.load_json(_need(o, "bundle", scan))
        gaps = cspm.coverage_gaps(bundle)
        meta = {"unchecked_sections": cspm.unchecked_sections(bundle)}
        return cspm.scan(bundle), ([f"not in bundle, not checked: {', '.join(gaps)}"] if gaps else []), meta
    if scan.type == "azure":
        bundle = sources.collect_azure(o.get("subscription")) if o.get("live") else sources.load_json(_need(o, "bundle", scan))
        return (azure_cspm.scan(bundle), [f"not in bundle, not checked: {', '.join(azure_cspm.coverage_gaps(bundle))}"],
                {"unchecked_sections": azure_cspm.unchecked_sections(bundle)})
    if scan.type == "k8s":
        export = sources.collect_k8s(o.get("context")) if o.get("live") else sources.load_json(_need(o, "export", scan))
        inc = bool(o.get("include_system"))
        return k8s_posture.scan(export, include_system=inc), k8s_posture.notes(export, include_system=inc)
    # iac
    findings: list[PostureFinding] = []
    if o.get("plan"):
        findings += iac_policy.scan_plan(sources.load_json(o["plan"]), changed_only=bool(o.get("changed_only")))
    if o.get("k8s"):
        findings += iac_policy.scan_manifests(iac_policy.load_manifests(o["k8s"]))
    if not o.get("plan") and not o.get("k8s"):
        raise sources.PostureSourceError("iac scan needs plan and/or k8s")
    return findings, []


def _need(o: dict, key: str, scan: ScanConfig) -> Path:
    if not o.get(key):
        raise sources.PostureSourceError(f"{scan.type} scan {scan.name!r} needs {key} (or live: true)")
    return o[key]


# ---- tracking over time ---------------------------------------------------------------------------

def fingerprint(scan: str, f: PostureFinding | dict) -> str:
    g = f if isinstance(f, dict) else f.as_dict()
    key = "|".join(str(g.get(k) or "") for k in ("id", "resource", "affected_component"))
    return hashlib.sha256(f"{scan}|{key}".encode()).hexdigest()[:16]


def _iso(t: datetime) -> str:
    return t.astimezone(UTC).isoformat(timespec="seconds")


def _parse(s: str) -> datetime:
    return datetime.fromisoformat(s)


def _read_json(p: Path, default: Any) -> Any:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _write_atomic(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, p)


_FROM_ENV = object()


def _remediation_hitl(hitl: Any) -> Any:
    if hitl is not _FROM_ENV:
        return hitl
    from ..hitl.dashboard import hitl_from_env
    try:
        return hitl_from_env()
    except Exception as e:  # noqa: BLE001 - no approval channel still leaves the proposals visible
        logger.warning("remediation approval channel unavailable: %s", e)
        return None


def run_once(cfg: RunnerConfig, *, now: datetime | None = None, hitl: Any = _FROM_ENV) -> dict:
    """Execute every scan, diff against the previous run, persist, and return the run record.

    With an exposure scan configured, ACT NOW findings also get remediation proposals filed through
    ``hitl`` (default: the deployment's ``AEGIS_HITL_TRANSPORT``) and approved ones are re-tested."""
    now = now or datetime.now(UTC)
    store = cfg.store
    run_id = now.strftime("%Y%m%dT%H%M%S") + f"{now.microsecond // 1000:03d}Z"
    n = 1
    while (store / "runs" / f"{run_id}.json").exists():  # never overwrite a previous run's record
        n += 1
        run_id = now.strftime("%Y%m%dT%H%M%S") + f"{now.microsecond // 1000:03d}Z-{n}"
    prev = _read_json(store / "latest.json", {})
    prev_open = {o["fingerprint"]: o for o in prev.get("open", [])}
    state: dict[str, dict] = _read_json(store / "state.json", {})

    scans_out, current = [], []  # current: (scan_name, finding)
    failed: set[str] = set()
    partial: dict[str, tuple[set[str], Any]] = {}   # scan -> (bundle sections not collected, section_of)
    for sc in cfg.scans:
        t0 = time.monotonic()
        try:
            res = execute(sc)
            findings, notes = res[0], res[1]
            meta = res[2] if len(res) > 2 else {}
            if meta.get("unchecked_sections"):
                mod = cspm if sc.type == "cspm" else azure_cspm
                partial[sc.name] = (set(meta["unchecked_sections"]), mod.section_of)
                meta = {k: v for k, v in meta.items() if k != "unchecked_sections"}
            current += [(sc.name, f) for f in findings]
            scans_out.append({"name": sc.name, "type": sc.type, "status": "ok", "notes": notes, **({"meta": meta} if meta else {}),
                              "summary": summarize(findings), "seconds": round(time.monotonic() - t0, 2),
                              "live": bool(sc.opts.get("live"))})
        except Exception as e:  # noqa: BLE001 - one broken scan must not stop the others
            failed.add(sc.name)
            logger.warning("posture scan %s failed: %s", sc.name, e)
            scans_out.append({"name": sc.name, "type": sc.type, "status": "error", "error": str(e)[:400],
                              "seconds": round(time.monotonic() - t0, 2), "live": bool(sc.opts.get("live"))})

    # one waiver register for every scan
    waiver_notes: list[str] = []
    waived_rows: list[dict] = []
    waivers: list = []
    if cfg.waivers:
        try:
            waivers = iac_policy.load_waivers(cfg.waivers)
        except sources.PostureSourceError as e:
            # fail safe: an unreadable register waives nothing, so every finding stays visible
            waiver_notes.append(f"WAIVER REGISTER NOT APPLIED — {e}")
    if waivers:
        kept, waived, notes = iac_policy.apply_waivers([f for _, f in current], waivers, today=now.date())
        waiver_notes += notes
        keep_ids = {id(f) for f in kept}
        scan_of = {id(f): s for s, f in current}
        waived_rows = [{**f.as_dict(), "scan": scan_of[id(f)], "fingerprint": fingerprint(scan_of[id(f)], f),
                        "waiver": {"reason": w.reason, "approved_by": w.approved_by, "expires": w.expires.isoformat()}}
                       for f, w in waived]
        current = [(s, f) for s, f in current if id(f) in keep_ids]
        # keep the true first-seen date while waived: when the waiver lapses the SLA clock has not reset
        for w in waived_rows:
            state.setdefault(w["fingerprint"], {"first_seen": _iso(now)})["last_seen"] = _iso(now)
            w["first_seen"] = state[w["fingerprint"]]["first_seen"]

    open_rows: list[dict] = []
    seen_now: set[str] = set()
    for scan_name, f in current:
        fp = fingerprint(scan_name, f)
        if fp in seen_now:
            continue
        seen_now.add(fp)
        st = state.setdefault(fp, {"first_seen": _iso(now)})
        st["last_seen"] = _iso(now)
        first = _parse(st["first_seen"])
        due = first + timedelta(days=cfg.sla_days.get(f.severity, 365))
        open_rows.append({**f.as_dict(), "scan": scan_name, "fingerprint": fp, "first_seen": st["first_seen"],
                          "age_days": (now - first).days, "sla_due": _iso(due), "overdue": now > due,
                          "new": fp not in prev_open and fp not in {w["fingerprint"] for w in prev.get("waived", [])},
                          "stale": False})

    # carry forward the previous findings of scans that failed this run — unknown is not fixed — and of
    # bundle sections the collector could not read this run (an SCP deny on one API is not a fix either)
    def _unread(o: dict) -> bool:
        if o.get("scan") in failed:
            return True
        part = partial.get(o.get("scan"))
        return bool(part) and part[1](o.get("id", "")) in part[0]

    for fp, o in prev_open.items():
        if _unread(o) and fp not in seen_now:
            due = _parse(o["sla_due"])
            open_rows.append({**o, "stale": True, "new": False, "overdue": now > due,
                              "age_days": (now - _parse(o["first_seen"])).days})
            seen_now.add(fp)

    waived_fps = {w["fingerprint"] for w in waived_rows}
    resolved = [{"fingerprint": fp, "id": o["id"], "resource": o.get("resource"), "scan": o.get("scan"),
                 "severity": o["severity"], "affected_component": o.get("affected_component"),
                 "first_seen": o.get("first_seen"), "resolved_at": _iso(now)}
                for fp, o in prev_open.items() if fp not in seen_now and fp not in waived_fps]
    for r in resolved:
        state.pop(r["fingerprint"], None)  # if it comes back, it is new again

    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    open_rows.sort(key=lambda r: (rank[r["severity"]], not r["overdue"], not r["new"], r["scan"], r["id"], r.get("resource") or ""))
    record = {
        "run_id": run_id, "started_at": _iso(now), "finished_at": _iso(datetime.now(UTC)),
        "scans": scans_out, "summary": _summary(open_rows), "sla_days": cfg.sla_days,
        "counts": {"open": len(open_rows), "new": sum(r["new"] for r in open_rows), "resolved": len(resolved),
                   "overdue": sum(r["overdue"] for r in open_rows), "waived": len(waived_rows),
                   "stale": sum(r["stale"] for r in open_rows), "scans_failed": len(failed)},
        "open": open_rows, "resolved": resolved, "waived": waived_rows, "notes": waiver_notes,
    }

    rem_cfg = cfg.remediation
    if any(sc.type == "exposure" for sc in cfg.scans) and rem_cfg.get("enabled", True):
        from ..exposure import remediation
        tiers = tuple(str(t).upper() for t in rem_cfg.get("tiers") or ["ACT_NOW"])
        section = remediation.reconcile(store, record, hitl=_remediation_hitl(hitl), now=now, tiers=tiers,
                                        review_days=int(rem_cfg.get("review_days", 30)))
        record["remediation"] = section
        record["notes"] = record["notes"] + section["notes"]
        remediation.save(store, section)

    _write_atomic(store / "runs" / f"{run_id}.json", json.dumps(record, indent=1))
    _write_atomic(store / "runs" / f"{run_id}.md", report_markdown(record))
    _write_atomic(store / "state.json", json.dumps(state, indent=1))
    _write_atomic(store / "latest.json", json.dumps(record, indent=1))
    _prune(store / "runs", cfg.keep_runs)
    return record


def _summary(rows: list[dict]) -> dict[str, int]:
    return {s: sum(1 for r in rows if r["severity"] == s) for s in SEVERITY_ORDER}


def _prune(runs: Path, keep: int) -> None:
    ids = sorted({p.stem for p in runs.glob("*.json")})
    for rid in ids[:-keep] if keep > 0 else []:
        for ext in (".json", ".md"):
            (runs / f"{rid}{ext}").unlink(missing_ok=True)


# ---- the report -----------------------------------------------------------------------------------

def report_markdown(r: dict) -> str:
    c, s = r["counts"], r["summary"]
    L = [f"# Posture assessment — run {r['run_id']}", "",
         (f"Run at {r['started_at']} · {len(r['scans'])} scans ({c['scans_failed']} failed) · "
          f"{c['open']} open findings · {c['new']} new · {c['resolved']} resolved since the last run · "
          f"{c['overdue']} past SLA · {c['waived']} waived"), "",
         "## Summary", "", "| Severity | Open | SLA (days) |", "|---|---|---|"]
    L += [f"| {sev} | {s[sev]} | {r['sla_days'].get(sev, '—')} |" for sev in SEVERITY_ORDER if sev != "info" or s[sev]]
    L += ["", "## Scope", "", "| Scan | Type | Mode | Status | Result |", "|---|---|---|---|---|"]
    for sc in r["scans"]:
        res = ", ".join(f"{k} {v}" for k, v in sc.get("summary", {}).items() if v) or ("—" if sc["status"] == "ok" else sc.get("error", ""))
        L.append(f"| {sc['name']} | {sc['type']} | {'live' if sc.get('live') else 'export'} | {sc['status']} | {res} |")
    for sc in r["scans"]:
        fn = (sc.get("meta") or {}).get("funnel")
        if fn:
            L += ["", f"Exposure funnel — {sc['name']}: {fn['raw']} findings → {fn['exploitable']} exploitable → "
                      f"{fn['reachable']} reachable → {fn['undefended']} undefended → **{fn['act_now']} ACT NOW**"
                      + (f" ({sc['meta']['monitor_only']} WAF protection(s) in monitor mode do not count)" if sc["meta"].get("monitor_only") else "")]
    gaps = [(sc["name"], n) for sc in r["scans"] for n in sc.get("notes", [])]
    if gaps:
        L += ["", "Coverage notes:", ""] + [f"- **{n}** — {t}" for n, t in gaps]

    def table(rows: list[dict], title: str) -> None:
        if not rows:
            return
        nonlocal L
        L += ["", f"## {title}", "", "| Severity | Finding | Resource | Scan | Age | SLA due | Control |", "|---|---|---|---|---|---|---|"]
        for o in rows:
            flags = " ⚠ overdue" if o["overdue"] else ""
            flags += " (stale: scan failed)" if o.get("stale") else ""
            L.append(f"| {o['severity']}{flags} | {o['id']} | {o['affected_component']} | {o['scan']} | {o['age_days']}d | "
                     f"{o['sla_due'][:10]} | {o.get('control') or '—'} |")

    table([o for o in r["open"] if o["overdue"]], "Past remediation SLA")
    table([o for o in r["open"] if o["new"]], "New since the last run")
    if r["open"]:
        L += ["", "## All open findings", ""]
        for o in r["open"]:
            L += [f"### {o['severity'].upper()} · {o['id']} · {o['affected_component']}", "",
                  f"- **Scan:** {o['scan']}  **First seen:** {o['first_seen'][:10]}  **SLA due:** {o['sla_due'][:10]}"
                  + ("  **OVERDUE**" if o["overdue"] else "") + ("  _(stale: this scan failed; last known state)_" if o.get("stale") else ""),
                  f"- **Evidence:** {o['evidence']}", f"- **Remediation:** {o['recommended_remediation']}"]
            if o.get("control"):
                L.append(f"- **Control:** {o['control']}")
            L.append("")
    if r["resolved"]:
        L += ["## Resolved since the last run", "", "| Severity | Finding | Resource | Scan | First seen |", "|---|---|---|---|---|"]
        L += [f"| {x['severity']} | {x['id']} | {x['affected_component']} | {x['scan']} | {(x.get('first_seen') or '')[:10]} |" for x in r["resolved"]]
    if r["waived"]:
        L += ["", "## Accepted risk (waivers in force)", "", "| Finding | Resource | Reason | Approved by | Expires |", "|---|---|---|---|---|"]
        L += [f"| {w['id']} | {w['affected_component']} | {w['waiver']['reason']} | {w['waiver']['approved_by']} | {w['waiver']['expires']} |" for w in r["waived"]]
    if r.get("remediation"):
        from ..exposure.remediation import markdown as remediation_md
        L += remediation_md(r["remediation"])
    if r["notes"]:
        L += ["", "## Notes", ""] + [f"- {n}" for n in r["notes"]]
    L += ["", "---", ("Method: automated configuration review against CIS AWS Foundations v2.0, CIS Kubernetes v1.9 and the "
                      "Kubernetes Pod Security Standards, plus BlueDefence policy rules. Read-only collection. Penetration testing of "
                      "production remains with the bank's empanelled auditor; this report tracks configuration exposure continuously "
                      "between those engagements.")]
    return "\n".join(L) + "\n"


def loop(cfg: RunnerConfig, *, stop: Any = None) -> None:
    """Run forever (or until ``stop.is_set()``), one run every ``interval_minutes``."""
    while True:
        try:
            r = run_once(cfg)
            logger.info("posture run %s: %s open, %s new, %s resolved, %s overdue",
                        r["run_id"], r["counts"]["open"], r["counts"]["new"], r["counts"]["resolved"], r["counts"]["overdue"])
        except Exception:  # keep the loop alive; the next run retries
            logger.exception("posture run failed")
        wait = cfg.interval_minutes * 60
        if stop is not None:
            if stop.wait(wait):
                return
        else:
            time.sleep(wait)


__all__ = ["RunnerConfig", "ScanConfig", "execute", "fingerprint", "load_config", "loop", "report_markdown", "run_once"]
