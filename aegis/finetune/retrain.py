"""Scheduled retrain pipeline (roadmap 3.5): export → build → train → gate → shadow → human-approved promotion.

The model gets the same "updates automatically" loop the rules have (3.1), with the same rule:
**a model never promotes itself.** Every stage leaves a file; a failed stage keeps the last good
model exactly like a feed outage keeps the last good rules.

    python -m aegis.finetune.retrain run     --runs ~/aegis-runs --base-data ~/aegis-runs/public-v4 --dashboard
    python -m aegis.finetune.retrain shadow  --runs ~/aegis-runs --run retrain-2026-10-29 --dashboard
    python -m aegis.finetune.retrain propose --runs ~/aegis-runs --run retrain-2026-10-29 --dashboard
    python -m aegis.finetune.retrain sync    --runs ~/aegis-runs --dashboard        # accepted proposal → current pointer
    python -m aegis.finetune.retrain status  --runs ~/aegis-runs
    python -m aegis.finetune.retrain promote --runs ~/aegis-runs --run ... --approved-by ... --rationale ...   # offline fallback

Stages per run (``$RUNS/retrain/state.json``):
    exported  → analyst-labelled rows pulled from the dashboard since the last export (``--since`` auto)
    built     → merged with the realistic base set (the public build) into ``$RUNS/<run>/data``
    trained   → LoRA adapter under ``$RUNS/<run>/adapter`` (``aegis.finetune.train``)
    gated     → ``aegis.finetune.gate`` PASS (≤ 5 misses / 37, 0 injection leaks) — FAIL ends the run, last good model stays
    shadowed  → candidate vs current on analyst-decided alerts *newer than its training export* (never on its own data):
                n ≥ 20 and candidate agreement ≥ current − 2 pt → ``ready``
    proposed  → a ``model_promotion`` proposal in the dashboard approvals queue (same path as rule acceptance)
    promoted  → a human accepted it (``sync`` sees the accepted rule) → ``$RUNS/retrain/current.json``; the SOC
                host reads ``AEGIS_MODEL`` from that pointer at the next restart

Weekly cron on the GPU box:  ``0 2 * * 1  cd ~/rbi && python -m aegis.finetune.retrain run --runs ~/aegis-runs --base-data ~/aegis-runs/public-v4 --dashboard && python -m aegis.finetune.retrain shadow --runs ~/aegis-runs --dashboard && python -m aegis.finetune.retrain propose --runs ~/aegis-runs --dashboard``
"""

from __future__ import annotations

import logging
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from aegis.finetune.digest import adapter_digest, verify_adapter

logger = logging.getLogger("aegis.retrain")

SHADOW_MIN_N = 20
SHADOW_TOLERANCE = 0.02          # candidate may trail the current model by at most 2 points of agreement
GATE_MAX_MISSES = 5
MIN_NEW_ROWS = 50                # fewer new analyst rows than this → no retrain (nothing learned yet)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- state

@dataclass
class State:
    path: Path
    current: dict | None = None              # {"run", "adapter", "sha256", "promoted_at", "approved_by", ...}
    runs: dict[str, dict] = field(default_factory=dict)
    last_export: str | None = None
    history: list[dict] = field(default_factory=list)

    @classmethod
    def load(cls, runs_dir: Path) -> "State":
        p = runs_dir / "retrain" / "state.json"
        st = cls(p)
        if p.exists():
            d = json.loads(p.read_text(encoding="utf-8"))
            st.current, st.runs, st.last_export, st.history = d.get("current"), d.get("runs", {}), d.get("last_export"), d.get("history", [])
        return st

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"current": self.current, "runs": self.runs, "last_export": self.last_export,
                                         "history": self.history[-200:]}, indent=2, sort_keys=True), encoding="utf-8")
        if self.current:
            (self.path.parent / "current.json").write_text(json.dumps(self.current, indent=2), encoding="utf-8")

    def log(self, run: str, stage: str, **info) -> None:
        self.history.append({"ts": _now(), "run": run, "stage": stage, **info})
        if run in self.runs:
            self.runs[run]["stage"] = stage
            self.runs[run].setdefault("stages", {})[stage] = {"ts": _now(), **info}


def _sha256_dir(d: Path) -> str:
    return adapter_digest(d)            # full content of every file (the old digest read only the first 4 MiB)


# --------------------------------------------------------------------------- stages (each injectable for tests)

def _sh(cmd: list[str], *, dry_run: bool, cwd: Path | None = None) -> int:
    print("  $ " + " ".join(cmd))
    if dry_run:
        return 0
    return subprocess.call(cmd, cwd=str(cwd) if cwd else None)


def export_stage(out: Path, *, since: str | None, dashboard: bool, dry_run: bool, runner=None) -> dict:
    """Pull analyst-labelled chains from the dashboard (strong labels only — the default export)."""
    runner = runner or _sh
    cmd = [sys.executable, "-m", "aegis.dataset", "export", "--out", str(out), "--no-eval", "--notes", "retrain"]
    if dashboard:
        cmd.append("--dashboard")
    if since:
        cmd += ["--since", since]
    rc = runner(cmd, dry_run=dry_run)
    rows = 0
    f = out / "sft" / "triage.jsonl"
    if f.exists():
        rows = sum(1 for line in f.read_text(encoding="utf-8").splitlines() if line.strip() and '"label_source": "human' in line)
    return {"rc": rc, "dir": str(out), "human_rows": rows, "since": since}


def build_stage(data: Path, base_data: Path | None, export_dir: Path, *, dry_run: bool) -> dict:
    """Merge the new analyst rows with the realistic base set. Analyst rows are the point of the
    retrain, so they are oversampled ×3 (bounded) against the much larger public set."""
    data.mkdir(parents=True, exist_ok=True)
    (data / "sft").mkdir(exist_ok=True)
    out = data / "sft" / "triage.jsonl"
    counts = {"base": 0, "human": 0, "human_oversampled": 0}
    if dry_run:
        return {"dir": str(data), **counts, "dry_run": True}
    with out.open("w", encoding="utf-8") as w:
        base = (base_data / "sft" / "triage.jsonl") if base_data else None
        if base and base.exists():
            for line in base.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    w.write(line + "\n"); counts["base"] += 1
        exp = export_dir / "sft" / "triage.jsonl"
        if exp.exists():
            for line in exp.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                row = json.loads(line)
                if not str(row.get("label_source", "")).startswith("human"):
                    continue
                reps = 3 if counts["base"] > 20 * max(1, counts["human"]) else 1
                for _ in range(reps):
                    w.write(line + "\n")
                counts["human"] += 1; counts["human_oversampled"] += reps
    (data / "manifest.json").write_text(json.dumps({"name": data.name, "format": "aegis-retrain-merge", "counts": counts,
                                                     "base": str(base_data) if base_data else None, "export": str(export_dir)}, indent=2))
    return {"dir": str(data), **counts}


def train_stage(data: Path, adapter: Path, *, preset: str, epochs: int, max_rows: int, dry_run: bool, runner=None) -> dict:
    runner = runner or _sh
    cmd = [sys.executable, "-m", "aegis.finetune.train", "--data", str(data), "--preset", preset, "--epochs", str(epochs),
           "--max-rows", str(max_rows), "--allow-synthetic", "--out", str(adapter)]
    rc = runner(cmd, dry_run=dry_run)
    return {"rc": rc, "adapter": str(adapter)}


def gate_stage(adapter: Path, *, dry_run: bool, runner=None) -> dict:
    runner = runner or _sh
    from .gate import gate_report_path
    rep = gate_report_path(adapter)
    # a report from an earlier run in the same directory must not stand in for this one (review round 3 G5-6)
    for stale in (rep, adapter / "gate.json"):
        stale.unlink(missing_ok=True)
    cmd = [sys.executable, "-m", "aegis.finetune.gate", "--adapter", str(adapter), "--max-misses", str(GATE_MAX_MISSES)]
    rc = runner(cmd, dry_run=dry_run)
    if rep.exists():
        d = json.loads(rep.read_text(encoding="utf-8"))
        # both the exit code and the report must say pass
        return {"rc": rc, "passes": rc == 0 and bool(d.get("passes")), "summary": d.get("summary", ""),
                "tracked": d.get("tracked", {})}
    return {"rc": rc, "passes": rc == 0 and dry_run, "summary": "(no gate report)" if not dry_run else "(dry run)"}


def _shadow_rows(export_dir: Path) -> list[dict]:
    f = export_dir / "sft" / "triage.jsonl"
    if not f.exists():
        return []
    out = []
    for line in f.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if not str(row.get("label_source", "")).startswith("human"):
            continue
        try:
            alert = json.loads(row["messages"][1]["content"]); verdict = json.loads(row["messages"][2]["content"])["verdict"]
        except Exception as exc:  # noqa: BLE001 — a malformed export row is skipped, counted in the log
            logger.debug("[retrain] skipped malformed shadow row %s: %s", row.get("id"), exc)
            continue
        out.append({"id": row.get("id"), "alert": alert, "analyst_verdict": verdict})
    return out


def shadow_compare(rows: list[dict], candidate: Callable[[dict], str], current: Callable[[dict], str] | None) -> dict:
    """Agreement with the analyst's verdict, candidate vs current, on rows neither has trained on."""
    n = len(rows); agree_c = agree_k = 0; disagreements = []
    for r in rows:
        try:
            vc = str(candidate(r["alert"])).lower()
        except Exception as e:  # noqa: BLE001
            vc = f"error:{type(e).__name__}"
        agree_c += vc == r["analyst_verdict"]
        vk = None
        if current is not None:
            try:
                vk = str(current(r["alert"])).lower()
            except Exception as e:  # noqa: BLE001
                vk = f"error:{type(e).__name__}"
            agree_k += vk == r["analyst_verdict"]
        if vc != r["analyst_verdict"]:
            disagreements.append({"id": r["id"], "analyst": r["analyst_verdict"], "candidate": vc, "current": vk})
    cand_rate = agree_c / n if n else 0.0
    cur_rate = (agree_k / n if n else 0.0) if current is not None else None
    if n < SHADOW_MIN_N:
        verdict, why = "not_yet", f"{n} analyst-decided alerts since the training export; need ≥ {SHADOW_MIN_N}"
    elif cur_rate is not None and cand_rate < cur_rate - SHADOW_TOLERANCE:
        verdict, why = "worse", f"candidate {cand_rate:.0%} vs current {cur_rate:.0%}"
    else:
        verdict, why = "ready", f"candidate {cand_rate:.0%}" + (f" vs current {cur_rate:.0%}" if cur_rate is not None else " (no current model)")
    return {"n": n, "candidate_agreement": round(cand_rate, 3), "current_agreement": None if cur_rate is None else round(cur_rate, 3),
            "verdict": verdict, "why": why, "disagreements": disagreements[:50], "ts": _now()}


def _adapter_triage(adapter: str) -> Callable[[dict], str]:
    from aegis.finetune.gate import AdapterTriage
    return AdapterTriage(adapter)


def promotion_proposal(run: str, info: dict) -> dict:
    """The proposal a human sees in the approvals queue. Same shape as a meta-agent proposal so the
    dashboard needs nothing new; ``change_type=model_promotion`` is NOT in the evolve ``PATCHABLE``
    allowlist, so the runtime applier ignores it — only ``retrain sync`` acts on acceptance."""
    gate = info.get("stages", {}).get("gated", {}); shadow = info.get("stages", {}).get("shadowed", {})
    return {
        "proposal_id": f"model-promotion:{run}",
        "change_type": "model_promotion",
        "target_module": "aegis.finetune",
        "target": "triage first-pass model",
        "title": f"Promote triage model {run}",
        "change": {"run": run, "adapter": info.get("adapter"), "sha256": info.get("sha256"),
                   "gate": gate.get("summary"), "shadow": {k: shadow.get(k) for k in ("n", "candidate_agreement", "current_agreement", "verdict")}},
        "rationale": (f"Gate: {gate.get('summary', '?')}. Shadow: {shadow.get('why', '?')} on {shadow.get('n', 0)} analyst-decided alerts "
                      f"newer than the training export. Trained on {info.get('data_counts', {}).get('human', 0)} new analyst rows + base set."),
        "evidence_case_ids": [d["id"] for d in shadow.get("disagreements", [])[:10]],
        "observation": "scheduled retrain (roadmap 3.5)",
    }


def _hitl_dir(a: Any = None) -> Path:
    raw = getattr(a, "hitl_dir", None) or os.environ.get("AEGIS_HITL_DIR") or str(Path.cwd() / ".aegis-hitl")
    return Path(raw).expanduser()


def _ship_local(proposal: dict, dry_run: bool, hitl_dir: Path) -> dict | None:
    """Standalone: append the proposal to ``<hitl>/proposals.jsonl`` — the SOC console's Model loop lists it
    (``/api/soc/proposals``) and an analyst accepts or rejects it there (``proposal-decisions.jsonl``)."""
    if dry_run:
        print("  (dry run) would queue locally:", json.dumps(proposal)[:300]); return {"status": "dry_run"}
    row = {"id": proposal["proposal_id"], "change_type": proposal["change_type"], "summary": proposal["title"],
           "rationale": proposal["rationale"], "change": proposal["change"], "status": "pending_hitl",
           "validation_passed": True, "ts": time.time()}
    hitl_dir.mkdir(parents=True, exist_ok=True)
    with (hitl_dir / "proposals.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps(row) + "\n")
    return {"status": "pending_hitl", "queue": str(hitl_dir / "proposals.jsonl")}


def _accepted_local(dry_run: bool, hitl_dir: Path) -> list[dict]:
    """Standalone: model_promotion proposals an analyst accepted in the SOC console."""
    if dry_run:
        return []
    def rows(name: str) -> list[dict]:
        f = hitl_dir / name
        if not f.exists():
            return []
        out = []
        for line in f.read_text(encoding="utf-8").splitlines():
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if isinstance(r, dict):
                out.append(r)
        return out
    from aegis.hitl.signing import trusted_approver, verify
    decided: dict[str, dict] = {}
    for d in rows("proposal-decisions.jsonl"):
        ok, why = verify(d)
        if ok:
            ok, why = trusted_approver(d.get("decided_by"))
        if not ok:          # a promotion is accepted only by a decision the console signed for a signed-in analyst
            print(f"  ignored decision for {d.get('proposal_id')}: {why}")
            continue
        decided[str(d.get("proposal_id"))] = d
    out = []
    for p in rows("proposals.jsonl"):
        d = decided.get(str(p.get("id")))
        if p.get("change_type") == "model_promotion" and d and d.get("decision") == "accept":
            out.append({"change_type": "model_promotion", "change": p.get("change") or {}, "proposal_id": p.get("id"),
                        "decided_by": d.get("decided_by"), "decision_rationale": d.get("rationale")})
    return out


def _ship(proposal: dict, dry_run: bool) -> dict | None:
    if dry_run:
        print("  (dry run) would ship:", json.dumps(proposal)[:300]); return {"status": "dry_run"}
    from aegis.persist.dashboard import DashboardSink
    sink = DashboardSink(sync=True)                      # ACP_DASHBOARD_URL / ACP_API_KEY from the environment
    digest = hashlib.sha256(json.dumps(proposal, sort_keys=True).encode()).hexdigest()
    return sink.ship_proposal(proposal, {"passed": True, "checks": ["gate", "shadow"]}, digest)


def _accepted_model_rules(dry_run: bool) -> list[dict]:
    if dry_run:
        return []
    from aegis.evolve.feed import RuleFeed
    snap = RuleFeed().fetch()                            # same feed the runtime applier polls; it ignores this change_type
    return [r for r in (snap.rules if snap else []) if r.get("change_type") == "model_promotion"]


# --------------------------------------------------------------------------- commands

def cmd_run(a) -> int:
    runs = Path(a.runs).expanduser(); st = State.load(runs)
    run = a.run or f"retrain-{datetime.now(timezone.utc):%Y-%m-%d}"
    root = runs / run; root.mkdir(parents=True, exist_ok=True)
    st.runs[run] = {"created": _now(), "preset": a.preset, "base_data": a.base_data, "stage": "started"}
    since = a.since or st.last_export
    print(f"== retrain {run} (since {since or 'the beginning'})")
    ex = export_stage(root / "export", since=since, dashboard=a.dashboard, dry_run=a.dry_run)
    st.log(run, "exported", **ex)
    if ex["rc"] != 0:
        st.log(run, "failed", reason="export failed"); st.save(); return 1
    if not a.dry_run and ex["human_rows"] < a.min_new_rows:
        st.log(run, "skipped", reason=f"{ex['human_rows']} new analyst rows < {a.min_new_rows}; nothing to learn yet"); st.save()
        print(f"  skipped: {st.runs[run]['stages']['skipped']['reason']}"); return 0
    bd = build_stage(root / "data", Path(a.base_data).expanduser() if a.base_data else None, root / "export", dry_run=a.dry_run)
    st.runs[run]["data_counts"] = {k: bd.get(k, 0) for k in ("base", "human", "human_oversampled")}
    st.log(run, "built", **bd)
    tr = train_stage(root / "data", root / "adapter", preset=a.preset, epochs=a.epochs, max_rows=a.max_rows, dry_run=a.dry_run)
    if tr["rc"] != 0:
        st.log(run, "failed", reason="training failed"); st.save(); return 1
    st.runs[run]["adapter"] = tr["adapter"]
    st.runs[run]["sha256"] = _sha256_dir(root / "adapter") if (root / "adapter").exists() else None
    st.log(run, "trained", **tr)
    g = gate_stage(root / "adapter", dry_run=a.dry_run)
    st.log(run, "gated", **g)
    if not g["passes"]:
        st.log(run, "failed", reason=f"gate FAIL: {g['summary']} — last good model stays"); st.save()
        print(f"  gate FAIL — {g['summary']}; current model unchanged"); return 1
    if not a.dry_run:
        st.last_export = _now()
    st.save()
    print(f"  gate PASS — {g['summary']}\n  next: python -m aegis.finetune.retrain shadow --runs {runs} --run {run} --dashboard")
    return 0


def cmd_shadow(a, *, candidate_loader=_adapter_triage, current_loader=_adapter_triage) -> int:
    runs = Path(a.runs).expanduser(); st = State.load(runs)
    run = a.run or _latest(st, "gated")
    if not run or run not in st.runs:
        print("no gated run to shadow"); return 1
    info = st.runs[run]
    export_ts = info.get("stages", {}).get("exported", {}).get("ts")
    sdir = runs / run / "shadow-export"
    if a.rows:
        rows = _shadow_rows(Path(a.rows).expanduser())
    else:
        ex = export_stage(sdir, since=export_ts, dashboard=a.dashboard, dry_run=a.dry_run)
        rows = _shadow_rows(sdir) if ex["rc"] == 0 else []
    if a.dry_run:
        st.log(run, "shadowed", n=len(rows), verdict="dry_run"); st.save(); return 0
    cand = candidate_loader(info["adapter"])
    cur = current_loader(st.current["adapter"]) if st.current and st.current.get("adapter") else None
    rep = shadow_compare(rows, cand, cur)
    st.log(run, "shadowed", **rep); st.save()
    print(f"  shadow {rep['verdict']}: {rep['why']}")
    return 0 if rep["verdict"] == "ready" else 1


def cmd_propose(a, *, ship=None) -> int:
    if ship is None:
        ship = _ship if getattr(a, "dashboard", False) else (lambda p, d: _ship_local(p, d, _hitl_dir(a)))
    runs = Path(a.runs).expanduser(); st = State.load(runs)
    run = a.run or _latest(st, "shadowed")
    if not run or run not in st.runs:
        print("no shadowed run to propose"); return 1
    info = st.runs[run]
    if info.get("stages", {}).get("shadowed", {}).get("verdict") not in ("ready", "dry_run"):
        print(f"  {run}: shadow verdict is {info.get('stages', {}).get('shadowed', {}).get('verdict')!r}, not proposing"); return 1
    p = promotion_proposal(run, info)
    res = ship(p, a.dry_run)
    st.log(run, "proposed", proposal_id=p["proposal_id"], result=res); st.save()
    where = "dashboard approvals queue" if getattr(a, "dashboard", False) else "SOC console model loop (local queue)"
    print(f"  proposed {p['proposal_id']} → {where} ({(res or {}).get('status')})")
    return 0


def cmd_sync(a, *, accepted=None) -> int:
    """Accepted `model_promotion` proposals → current pointer. The only path that changes `current`
    besides the offline `promote` (which records who approved it)."""
    if accepted is None:
        accepted = _accepted_model_rules if getattr(a, "dashboard", False) else (lambda d: _accepted_local(d, _hitl_dir(a)))
    runs = Path(a.runs).expanduser(); st = State.load(runs)
    refused = 0
    for rule in accepted(a.dry_run):
        change = rule.get("change") or {}
        run = change.get("run")
        if not run or run not in st.runs or st.runs[run].get("stage") == "promoted":
            continue
        info = st.runs[run]
        # an accepted proposal can only promote a run that passed its gate and shadow, and only the adapter
        # that was proposed: a rule naming a failed run (or one whose adapter changed since) is refused
        if info.get("stage") not in ("shadowed", "proposed") or not _shadow_ready(info):
            print(f"  refused {run}: stage {info.get('stage')!r}, shadow verdict {_shadow_verdict(info)!r} — only a "
                  "gated run whose last shadow said 'ready' can be promoted")
            refused += 1
            continue
        if change.get("sha256") and info.get("sha256") and change["sha256"] != info["sha256"]:
            print(f"  refused {run}: adapter digest changed since it was proposed")
            refused += 1
            continue
        ok, why = verify_adapter(info.get("adapter") or "", info.get("sha256"))
        if not ok:                       # the files on disk must still be the ones that were gated and proposed
            print(f"  refused {run}: {why}")
            refused += 1
            continue
        if st.current and st.current.get("run") == run:
            continue
        _promote(st, run, approved_by=rule.get("decided_by") or "dashboard", rationale=rule.get("decision_rationale") or rule.get("rationale", ""),
                 proposal_id=rule.get("proposal_id"))
        print(f"  promoted {run} (accepted in the dashboard)")
    st.save()
    if st.current:
        print(f"  current: {st.current['run']} → AEGIS_MODEL={st.current['adapter']}")
    # an accepted promotion that was refused is a failure the operator must see: cron reported success while
    # nothing was promoted (review C10)
    return 1 if refused else 0


def _shadow_verdict(info: dict) -> str:
    return str(((info.get("stages") or {}).get("shadowed") or {}).get("verdict") or "")


def _shadow_ready(info: dict) -> bool:
    """A run re-shadowed as `worse` (or never shadowed) used to be promotable by an accepted rule or by
    `promote` at stage `gated` (review round 3 G5-7)."""
    return _shadow_verdict(info) == "ready"


def cmd_promote(a) -> int:
    runs = Path(a.runs).expanduser(); st = State.load(runs)
    if a.run not in st.runs:
        print(f"unknown run {a.run}"); return 1
    if st.runs[a.run].get("stage") not in ("shadowed", "proposed") or not _shadow_ready(st.runs[a.run]):
        print(f"{a.run} is at stage {st.runs[a.run].get('stage')!r} (shadow verdict "
              f"{_shadow_verdict(st.runs[a.run])!r}); promote only a gated run whose shadow said 'ready'"); return 1
    ok, why = verify_adapter(st.runs[a.run].get("adapter") or "", st.runs[a.run].get("sha256"))
    if not ok:
        print(f"refused {a.run}: {why}"); return 1
    _promote(st, a.run, approved_by=a.approved_by, rationale=a.rationale, proposal_id=None)
    st.save(); print(f"  promoted {a.run} (offline approval by {a.approved_by}) → AEGIS_MODEL={st.current['adapter']}")
    return 0


def _promote(st: State, run: str, *, approved_by: str, rationale: str, proposal_id: str | None) -> None:
    info = st.runs[run]
    prev = st.current
    st.current = {"run": run, "adapter": info.get("adapter"), "sha256": info.get("sha256"), "promoted_at": _now(),
                  "approved_by": approved_by, "rationale": rationale[:500], "proposal_id": proposal_id,
                  "previous": {k: prev.get(k) for k in ("run", "adapter", "sha256")} if prev else None}
    st.log(run, "promoted", approved_by=approved_by, previous=(prev or {}).get("run"))


def cmd_status(a) -> int:
    st = State.load(Path(a.runs).expanduser())
    print(f"current: {st.current['run'] + ' → ' + str(st.current['adapter']) if st.current else '(none promoted)'}")
    print(f"last export: {st.last_export or '-'}")
    for run, info in sorted(st.runs.items()):
        g = info.get("stages", {}).get("gated", {}).get("summary", ""); s = info.get("stages", {}).get("shadowed", {})
        print(f"  {run:24s} {info.get('stage', '?'):10s} {g[:60]}" + (f"  shadow {s.get('verdict')} ({s.get('why')})" if s else ""))
    return 0


def _latest(st: State, stage: str) -> str | None:
    cands = [r for r, i in st.runs.items() if i.get("stage") == stage]
    return sorted(cands)[-1] if cands else None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Scheduled retrain: export → build → train → gate → shadow → human-approved promotion (roadmap 3.5).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    def common(p):
        p.add_argument("--runs", default=str(Path.home() / "aegis-runs"))
        p.add_argument("--run", default=None)
        p.add_argument("--dashboard", action="store_true", help="use the ACP dashboard (ACP_DASHBOARD_URL / ACP_API_KEY) "
                       "instead of this host's local queue")
        p.add_argument("--hitl-dir", default=None, help="local approvals queue (default AEGIS_HITL_DIR or ./.aegis-hitl)")
        p.add_argument("--dry-run", action="store_true")
    r = sub.add_parser("run", help="export → build → train → gate"); common(r)
    r.add_argument("--base-data", default=None, help="realistic base set (a build-public directory)")
    r.add_argument("--preset", default="qwen3-8b"); r.add_argument("--epochs", type=int, default=2)
    r.add_argument("--max-rows", type=int, default=0); r.add_argument("--since", default=None)
    r.add_argument("--min-new-rows", type=int, default=MIN_NEW_ROWS)
    s = sub.add_parser("shadow", help="candidate vs current on analyst-decided alerts newer than the training export"); common(s)
    s.add_argument("--rows", default=None, help="an export directory to use instead of pulling (tests / offline)")
    p = sub.add_parser("propose", help="ship the model_promotion proposal to the approvals queue"); common(p)
    y = sub.add_parser("sync", help="accepted model_promotion proposals → current pointer"); common(y)
    m = sub.add_parser("promote", help="offline promotion with a recorded approver"); common(m)
    m.add_argument("--approved-by", required=True); m.add_argument("--rationale", required=True)
    t = sub.add_parser("status"); common(t)
    a = ap.parse_args(argv)
    return {"run": cmd_run, "shadow": cmd_shadow, "propose": cmd_propose, "sync": cmd_sync, "promote": cmd_promote, "status": cmd_status}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
