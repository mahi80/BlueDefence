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
from datetime import UTC, datetime, timezone
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

class StateError(RuntimeError):
    """``state.json`` is unsigned or was altered outside this CLI: nothing is promoted, synced or signed from it."""


class PromotionRefused(RuntimeError):
    """The run's adapter on disk is not the one its gate and shadow judged."""


_STATE_DOMAIN = b"aegis-retrain-state-v1|"


def _state_key() -> bytes | None:
    from aegis.hitl.signing import _key
    return _key()


def _state_sig(body: dict, k: bytes) -> str:
    import hmac
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hmac.new(k, _STATE_DOMAIN + raw, hashlib.sha256).hexdigest()


def read_signed_state(p: Path) -> dict:
    """The retrain state body, after its HMAC is checked (round 8 T8-2). With a signing key configured, an unsigned
    or altered ``state.json`` raises :class:`StateError`: the routine ``sync`` used to sign whatever ``current`` the
    file held, so anyone who could write it chose the SOC's model. ``AEGIS_RETRAIN_ADOPT_STATE=1`` accepts an
    unsigned file once (an install upgraded from an older release) after an operator has reviewed it; the next save
    signs it."""
    import hmac
    d = json.loads(Path(p).read_text(encoding="utf-8"))
    if not isinstance(d, dict):
        raise StateError(f"{p} is not a retrain state object")
    sig = d.pop("sig", None)
    k = _state_key()
    if k is None:
        return d
    if not sig:
        if os.environ.get("AEGIS_RETRAIN_ADOPT_STATE", "") == "1":
            logger.warning("[retrain] adopting unsigned %s (AEGIS_RETRAIN_ADOPT_STATE=1); it is signed on the next save", p)
            return d
        raise StateError(f"{p} is not signed (written by an older release or by hand); review it and run once with "
                         "AEGIS_RETRAIN_ADOPT_STATE=1 to adopt it")
    if not hmac.compare_digest(str(sig), _state_sig(d, k)):
        raise StateError(f"{p} was altered outside the retrain CLI (signature mismatch) — refusing to act on it")
    return d


@dataclass
class State:
    path: Path
    current: dict | None = None              # {"run", "adapter", "sha256", "promoted_at", "approved_by", ...}
    runs: dict[str, dict] = field(default_factory=dict)
    last_export: str | None = None
    history: list[dict] = field(default_factory=list)
    # pointer writes queued by the promote / rollback paths; applied by save() (nothing else writes the pointer)
    pending: list[tuple[dict | None, list[str]]] = field(default_factory=list, repr=False)

    @classmethod
    def load(cls, runs_dir: Path) -> "State":
        p = runs_dir / "retrain" / "state.json"
        st = cls(p)
        if p.exists():
            d = read_signed_state(p)
            st.current, st.runs, st.last_export, st.history = d.get("current"), d.get("runs", {}), d.get("last_export"), d.get("history", [])
        return st

    @property
    def pointer(self) -> Path:
        return self.path.parent / "current.json"

    def save(self) -> None:
        """Write the signed state, then any pointer change the promote / rollback paths queued. A routine save never
        touches the pointer: it used to sign whatever ``current`` the (unsigned) state held (round 8 T8-2)."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        from aegis.finetune.pointer_trust import RELEASE_APPROVER, commit_pointer
        for cur, deny in self.pending:
            if cur is None:
                # Rolled back to the base model. The same file is the pointer the fleet updater and serving share
                # (AEGIS_MODEL_POINTER): remove it only when it names one of THIS loop's runs (review round 5 Y5-8).
                try:
                    on_disk = json.loads(self.pointer.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    on_disk = None
                if not (isinstance(on_disk, dict) and on_disk.get("run") in self.runs
                        and on_disk.get("approved_by") != RELEASE_APPROVER):
                    continue
            role = (cur or {}).get("role") or "triage"
            if cur is None and self.runs:
                role = next(iter(self.runs.values())).get("role") or "triage"
            commit_pointer(self.pointer, cur, role=role, deny=deny)
        self.pending = []
        body = {"current": self.current, "runs": self.runs, "last_export": self.last_export,
                "history": self.history[-200:]}
        k = _state_key()
        out = {**body, "sig": _state_sig(json.loads(json.dumps(body, default=str)), k)} if k is not None else body
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps(out, indent=2, sort_keys=True, default=str), encoding="utf-8")
        os.replace(tmp, self.path)

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


def _alert_key(row: dict, line: str) -> str:
    """One key per alert: the alert's ``id`` when the prompt parses to one, else a digest of the prompt."""
    msgs = row.get("messages") or []
    prompt = msgs[1].get("content") if len(msgs) > 1 and isinstance(msgs[1], dict) else None
    if isinstance(prompt, str):
        try:
            a = json.loads(prompt)
            if isinstance(a, dict) and a.get("id") not in (None, ""):
                return "id:" + str(a["id"])
        except ValueError:
            pass
    return "h:" + hashlib.sha256((prompt if isinstance(prompt, str) else line).encode("utf-8")).hexdigest()


def _human_rows(f: Path | None) -> dict[str, str]:
    """Analyst-labelled rows of a triage jsonl, one per alert (a later row for the same alert wins)."""
    out: dict[str, str] = {}
    if not f or not f.exists():
        return out
    for line in f.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict) or not str(row.get("label_source", "")).startswith("human"):
            continue
        k = _alert_key(row, line)
        out.pop(k, None)
        out[k] = line
    return out


ANALYST_SET = "analyst-set.jsonl"


def build_stage(data: Path, base_data: Path | None, export_dir: Path, *, dry_run: bool,
                prior: Path | None = None) -> dict:
    """Merge the analyst rows with the realistic base set. Analyst rows are the point of the retrain, so they are
    oversampled ×3 (bounded) against the much larger public set.

    The analyst rows are the **cumulative** set: every correction accepted in earlier runs (``prior``, the
    ``$RUNS/retrain/analyst-set.jsonl`` the loop keeps) plus this export, one row per alert, the newest label
    winning. Each run trains a fresh LoRA from the base model, so an October correction that was only in October's
    export was missing from every later model (round 8 T8-6). The merged set is written next to the data
    (``analyst-set.jsonl``) so shadow can measure retention on it."""
    data.mkdir(parents=True, exist_ok=True)
    (data / "sft").mkdir(exist_ok=True)
    out = data / "sft" / "triage.jsonl"
    counts = {"base": 0, "human": 0, "human_oversampled": 0, "human_prior": 0}
    if dry_run:
        return {"dir": str(data), **counts, "dry_run": True}
    merged = _human_rows(prior)
    counts["human_prior"] = len(merged)
    # one row per alert (the prompt is the alert): an export that overlaps the relabel window must not oversample
    # the same alert twice (round 7 T-5), and a re-labelled alert replaces its earlier label
    for k, line in _human_rows(export_dir / "sft" / "triage.jsonl").items():
        merged.pop(k, None)
        merged[k] = line
    with out.open("w", encoding="utf-8") as w:
        base = (base_data / "sft" / "triage.jsonl") if base_data else None
        if base and base.exists():
            for line in base.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    w.write(line + "\n"); counts["base"] += 1
        for line in merged.values():
            reps = 3 if counts["base"] > 20 * max(1, counts["human"]) else 1
            for _ in range(reps):
                w.write(line + "\n")
            counts["human"] += 1; counts["human_oversampled"] += reps
    (data / ANALYST_SET).write_text("".join(line + "\n" for line in merged.values()), encoding="utf-8")
    (data / "manifest.json").write_text(json.dumps({"name": data.name, "format": "aegis-retrain-merge", "counts": counts,
                                                     "base": str(base_data) if base_data else None, "export": str(export_dir),
                                                     "prior": str(prior) if prior else None}, indent=2))
    return {"dir": str(data), **counts}


def train_stage(data: Path, adapter: Path, *, preset: str, epochs: int, max_rows: int, dry_run: bool, runner=None) -> dict:
    runner = runner or _sh
    cmd = [sys.executable, "-m", "aegis.finetune.train", "--data", str(data), "--preset", preset, "--epochs", str(epochs),
           "--max-rows", str(max_rows), "--allow-synthetic", "--out", str(adapter)]
    rc = runner(cmd, dry_run=dry_run)
    return {"rc": rc, "adapter": str(adapter)}


def judge_data_stage(triage_data: Path, out: Path, *, dry_run: bool, runner=None) -> dict:
    """Reviewer rows from the merged triage set (``aegis.dataset build-judge``) — a judge learns concur/dissent on
    finished verdicts, never the triage task the model it checks was trained on."""
    runner = runner or _sh
    rc = runner([sys.executable, "-m", "aegis.dataset", "build-judge", str(triage_data), "--out", str(out)], dry_run=dry_run)
    return {"rc": rc, "dir": str(out)}


def gate_stage(adapter: Path, *, dry_run: bool, runner=None, role: str = "triage") -> dict:
    runner = runner or _sh
    from .gate import gate_report_path
    rep = gate_report_path(adapter)
    # a report from an earlier run in the same directory must not stand in for this one (review round 3 G5-6)
    for stale in (rep, adapter / "gate.json"):
        stale.unlink(missing_ok=True)
    cmd = ([sys.executable, "-m", "aegis.finetune.judge_gate", "--adapter", str(adapter)] if role == "judge" else
           [sys.executable, "-m", "aegis.finetune.gate", "--adapter", str(adapter), "--max-misses", str(GATE_MAX_MISSES)])
    rc = runner(cmd, dry_run=dry_run)
    if rep.exists():
        d = json.loads(rep.read_text(encoding="utf-8"))
        # both the exit code and the report must say pass
        return {"rc": rc, "passes": rc == 0 and bool(d.get("passes")), "summary": d.get("summary", ""),
                "tracked": d.get("tracked", {})}
    return {"rc": rc, "passes": rc == 0 and dry_run, "summary": "(no gate report)" if not dry_run else "(dry run)"}


def _shadow_rows(export_dir: Path) -> list[dict]:
    return _rows_from(export_dir / "sft" / "triage.jsonl")


def _rows_from(f: Path) -> list[dict]:
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


PRIOR_EVAL_MAX = 200


def _with_retention(rep: dict, prior_file: Path, held_out: list[dict], cand, cur) -> dict:
    """Shadow also scores both models on the earlier analyst corrections the candidate was trained with — the
    held-out rows only measure new alerts, so a candidate that forgot last month's fixes still read ``ready``
    (round 8 T8-6). Candidate retention below the current model's by more than the tolerance is ``worse``."""
    seen = {str(r.get("id")) for r in held_out if r.get("id")} | {json.dumps(r["alert"], sort_keys=True) for r in held_out}
    prior = [r for r in _rows_from(prior_file)
             if str(r.get("id")) not in seen and json.dumps(r["alert"], sort_keys=True) not in seen]
    try:
        cap = int(os.environ.get("AEGIS_RETRAIN_PRIOR_EVAL_MAX", PRIOR_EVAL_MAX))
    except ValueError:
        cap = PRIOR_EVAL_MAX
    prior = prior[-cap:] if cap > 0 else []
    if not prior:
        return {**rep, "retention": {"n": 0}}
    r = shadow_compare(prior, cand, cur)
    ret = {k: r[k] for k in ("n", "candidate_agreement", "current_agreement")}
    ret["forgotten"] = r["disagreements"][:20]
    out = {**rep, "retention": ret}
    if rep.get("verdict") == "ready" and r["current_agreement"] is not None and \
            r["candidate_agreement"] < r["current_agreement"] - SHADOW_TOLERANCE:
        out["verdict"] = "worse"
        out["why"] = (f"{rep.get('why')}; but forgets earlier analyst corrections: retention "
                      f"{r['candidate_agreement']:.0%} vs current {r['current_agreement']:.0%} on {r['n']}")
    return out


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

def _since_with_relabel_window(last_export: str | None) -> str | None:
    """The export filter. The dashboard filters on a chain's creation time, so a chain created before the last
    export but labelled by an analyst after it (ordinary HITL latency) was never exported again (round 7 T-5): each
    export re-reads ``AEGIS_RETRAIN_RELABEL_DAYS`` (default 7) before the watermark; ``build_stage`` keeps one row
    per alert, so a re-read chain is not oversampled twice."""
    if not last_export:
        return None
    try:
        days = max(0.0, float(os.environ.get("AEGIS_RETRAIN_RELABEL_DAYS", "7") or 7))
        ts = datetime.fromisoformat(str(last_export))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        from datetime import timedelta
        return (ts - timedelta(days=days)).isoformat()
    except (ValueError, OverflowError):
        return last_export


def _runs_dir(a) -> Path:
    return Path(a.runs or str(Path.home() / "aegis-runs")).expanduser()


def _state_guard(fn):
    """A command run against an unsigned / altered ``state.json`` refuses (exit 2) instead of acting on it."""
    import functools

    @functools.wraps(fn)
    def wrapped(*args, **kw):
        try:
            return fn(*args, **kw)
        except StateError as e:
            print(f"refused: {e}")
            return 2
    return wrapped


@_state_guard
def cmd_run(a) -> int:
    role = getattr(a, "role", "triage") or "triage"
    runs = Path(a.runs or str(Path.home() / "aegis-runs" / ("judge" if role == "judge" else ""))).expanduser()
    st = State.load(runs)
    cur_role = (st.current or {}).get("role") or ("triage" if st.current else None)
    other = {i.get("role") or "triage" for i in st.runs.values()} - {role}
    if (cur_role and cur_role != role) or other:
        # one --runs directory per model: a judge run in the triage directory used to overwrite the triage pointer
        # and share its adapter dir and export watermark (review round 6 J-2)
        print(f"refused: {runs} holds {cur_role or min(other)} runs; use a separate --runs directory for the "
              f"{role} model (default for judge: ~/aegis-runs/judge)")
        return 2
    cur_run = (st.current or {}).get("run")
    if a.run:
        run = a.run
        # never train into an existing run: its adapter dir may be the one the promotion pointer names, and the
        # human-approved weights were overwritten in place (round 7 T-2)
        if run in st.runs or ((runs / run).exists() and any((runs / run).iterdir())):
            print(f"refused: run {run!r} already exists in {runs}"
                  f"{' and is the promoted model' if run == cur_run else ''}; pick a new --run name")
            return 2
    else:
        # unique per invocation: the trainer daemon restarting on the same day reused `retrain-<role>-<date>` and
        # retrained into the promoted run's adapter dir (round 7 T-2)
        stamp = f"retrain-{role}-{datetime.now(timezone.utc):%Y-%m-%dT%H%M%SZ}"
        run, n = stamp, 1
        while run in st.runs or (runs / run).exists():
            n += 1
            run = f"{stamp}-{n}"
    root = runs / run; root.mkdir(parents=True, exist_ok=True)
    st.runs[run] = {"created": _now(), "preset": a.preset, "base_data": a.base_data, "stage": "started", "role": role}
    since = a.since or _since_with_relabel_window(st.last_export)
    print(f"== retrain {run} (since {since or 'the beginning'})")
    export_started = _now()          # the watermark is the moment of the export, not the end of training (T-5)
    ex = export_stage(root / "export", since=since, dashboard=a.dashboard, dry_run=a.dry_run)
    st.log(run, "exported", **ex)
    if ex["rc"] != 0:
        st.log(run, "failed", reason="export failed"); st.save(); return 1
    if not a.dry_run and ex["human_rows"] < a.min_new_rows:
        st.log(run, "skipped", reason=f"{ex['human_rows']} new analyst rows < {a.min_new_rows}; nothing to learn yet"); st.save()
        print(f"  skipped: {st.runs[run]['stages']['skipped']['reason']}"); return 0
    cumulative = runs / "retrain" / ANALYST_SET
    bd = build_stage(root / "data", Path(a.base_data).expanduser() if a.base_data else None, root / "export",
                     dry_run=a.dry_run, prior=cumulative)
    st.runs[run]["data_counts"] = {k: bd.get(k, 0) for k in ("base", "human", "human_oversampled", "human_prior")}
    if not a.dry_run and (root / "data" / ANALYST_SET).exists():
        # analyst labels are truth whatever this run's model turns out like: keep them for every later run (T8-6)
        cumulative.parent.mkdir(parents=True, exist_ok=True)
        tmp = cumulative.with_name(cumulative.name + ".tmp")
        tmp.write_text((root / "data" / ANALYST_SET).read_text(encoding="utf-8"), encoding="utf-8")
        os.replace(tmp, cumulative)
    st.log(run, "built", **bd)
    train_data = root / "data"
    if role == "judge":
        jd = judge_data_stage(root / "data", root / "judge-data", dry_run=a.dry_run)
        st.log(run, "judge_data", **jd)
        if jd["rc"] != 0:
            st.log(run, "failed", reason="judge data build failed"); st.save(); return 1
        train_data = root / "judge-data"
    tr = train_stage(train_data, root / "adapter", preset=a.preset, epochs=a.epochs, max_rows=a.max_rows, dry_run=a.dry_run)
    if tr["rc"] != 0:
        st.log(run, "failed", reason="training failed"); st.save(); return 1
    st.runs[run]["adapter"] = tr["adapter"]
    st.runs[run]["sha256"] = _sha256_dir(root / "adapter") if (root / "adapter").exists() else None
    st.log(run, "trained", **tr)
    g = gate_stage(root / "adapter", dry_run=a.dry_run, role=role)
    st.log(run, "gated", **g)
    if not g["passes"]:
        st.log(run, "failed", reason=f"gate FAIL: {g['summary']} — last good model stays"); st.save()
        print(f"  gate FAIL — {g['summary']}; current model unchanged"); return 1
    if not a.dry_run:
        st.last_export = export_started
    st.save()
    if role == "judge":
        print(f"  judge gate PASS — {g['summary']}\n  next: python -m aegis.finetune.retrain promote --runs {runs} --run {run} "
              "--approved-by <you> --rationale '…'   (then point AEGIS_VOTER_POINTER / an @pointer voter at "
              f"{runs}/retrain/current.json)")
        return 0
    print(f"  gate PASS — {g['summary']}\n  next: python -m aegis.finetune.retrain shadow --runs {runs} --run {run} --dashboard")
    return 0


@_state_guard
def cmd_shadow(a, *, candidate_loader=_adapter_triage, current_loader=_adapter_triage) -> int:
    runs = _runs_dir(a); st = State.load(runs)
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
    rep = _with_retention(rep, runs / run / "data" / ANALYST_SET, rows, cand, cur)
    st.log(run, "shadowed", **rep); st.save()
    print(f"  shadow {rep['verdict']}: {rep['why']}")
    return 0 if rep["verdict"] == "ready" else 1


@_state_guard
def cmd_propose(a, *, ship=None) -> int:
    if ship is None:
        ship = _ship if getattr(a, "dashboard", False) else (lambda p, d: _ship_local(p, d, _hitl_dir(a)))
    runs = _runs_dir(a); st = State.load(runs)
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


@_state_guard
def cmd_sync(a, *, accepted=None) -> int:
    """Accepted `model_promotion` proposals → current pointer. The only path that changes `current`
    besides the offline `promote` (which records who approved it)."""
    if accepted is None:
        accepted = _accepted_model_rules if getattr(a, "dashboard", False) else (lambda d: _accepted_local(d, _hitl_dir(a)))
    runs = _runs_dir(a); st = State.load(runs)
    refused = 0
    for rule in accepted(a.dry_run):
        change = rule.get("change") or {}
        run = change.get("run")
        if not run or run not in st.runs or st.runs[run].get("stage") == "promoted":
            continue
        info = st.runs[run]
        if info.get("denied"):
            continue                     # rolled back by a person: its old acceptance never promotes it again
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
        try:
            _promote(st, run, approved_by=rule.get("decided_by") or "dashboard",
                     rationale=rule.get("decision_rationale") or rule.get("rationale", ""), proposal_id=rule.get("proposal_id"))
        except PromotionRefused as e:
            print(f"  refused {e}")
            refused += 1
            continue
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


@_state_guard
def cmd_promote(a) -> int:
    runs = _runs_dir(a); st = State.load(runs)
    if a.run not in st.runs:
        print(f"unknown run {a.run}"); return 1
    if st.runs[a.run].get("denied"):
        print(f"{a.run} was rolled back — denied for good"); return 1
    info = st.runs[a.run]
    judge_ok = info.get("role") == "judge" and info.get("stage") == "gated" and \
        bool(info.get("stages", {}).get("gated", {}).get("passes"))
    # A reviewer has no analyst-labelled shadow set yet: it is promoted only offline, by a named person, after its
    # own gate (never by `sync` from an accepted proposal — that path still needs a shadow verdict).
    if not judge_ok and (info.get("stage") not in ("shadowed", "proposed") or not _shadow_ready(info)):
        print(f"{a.run} is at stage {st.runs[a.run].get('stage')!r} (shadow verdict "
              f"{_shadow_verdict(st.runs[a.run])!r}); promote only a gated run whose shadow said 'ready'"); return 1
    ok, why = verify_adapter(st.runs[a.run].get("adapter") or "", st.runs[a.run].get("sha256"))
    if not ok:
        print(f"refused {a.run}: {why}"); return 1
    try:
        _promote(st, a.run, approved_by=a.approved_by, rationale=a.rationale, proposal_id=None)
    except PromotionRefused as e:
        print(f"refused {e}"); return 1
    st.save(); print(f"  promoted {a.run} (offline approval by {a.approved_by}) → AEGIS_MODEL={st.current['adapter']}")
    return 0


def _verify_run_artefacts(info: dict) -> tuple[bool, str]:
    """The adapter on disk must be the one this run recorded at training time (signed state) and, when its gate
    report is there, the one that gate judged (``adapter_digest`` in the report)."""
    adapter = info.get("adapter") or ""
    ok, why = verify_adapter(adapter, info.get("sha256"))
    if not ok:
        return False, why
    try:
        from .gate import gate_report_path
        rep = gate_report_path(adapter)
        if rep.exists():
            d = json.loads(rep.read_text(encoding="utf-8"))
            gd = d.get("adapter_digest")
            if gd and gd != info.get("sha256"):
                return False, f"gate report judged adapter {gd}, not the recorded {info.get('sha256')}"
            if "passes" in d and not d.get("passes"):
                return False, "the run's gate report says FAIL"
    except (OSError, ValueError) as e:
        return False, f"gate report unreadable ({e})"
    return True, ""


def _promote(st: State, run: str, *, approved_by: str, rationale: str, proposal_id: str | None) -> None:
    """Make ``run`` current and queue its signed pointer (written by ``st.save()``). The only path that signs a
    pointer for a new run — after re-checking the adapter against the run's own recorded/gated digest (T8-2)."""
    info = st.runs[run]
    if info.get("denied"):
        raise PromotionRefused(f"{run} was rolled back — denied for good")
    ok, why = _verify_run_artefacts(info)
    if not ok:
        raise PromotionRefused(f"{run}: {why}")
    prev = st.current
    st.current = {"run": run, "role": info.get("role") or "triage", "adapter": info.get("adapter"),
                  "sha256": info.get("sha256"), "promoted_at": _now(),
                  "approved_by": approved_by, "rationale": rationale[:500], "proposal_id": proposal_id,
                  "previous": {k: prev.get(k) for k in ("run", "adapter", "sha256")} if prev else None}
    st.pending.append((dict(st.current), []))
    st.log(run, "promoted", approved_by=approved_by, previous=(prev or {}).get("run"))


@_state_guard
def cmd_rollback(a) -> int:
    """Undo the current promotion: the previous model becomes current again (or the base model, if there was
    none) and the rolled-back run is recorded as denied — in the signed state and in the pointer's signed record,
    so neither ``sync``, ``promote`` nor a restored copy of the old pointer brings it back (D4-8, T8-1)."""
    runs = _runs_dir(a); st = State.load(runs)
    if not st.current:
        print("nothing is promoted"); return 1
    bad = st.current.get("run")
    prev = st.current.get("previous") or None
    if bad in st.runs:
        st.runs[bad]["denied"] = {"ts": _now(), "by": a.approved_by, "rationale": a.rationale[:500]}
    st.log(bad, "denied", approved_by=a.approved_by, rationale=a.rationale[:500])
    if prev and prev.get("run"):
        pinfo = st.runs.get(prev["run"]) or {}
        why = ""
        if pinfo.get("denied"):
            why = "it was rolled back earlier"
        elif pinfo and pinfo.get("sha256") and pinfo.get("sha256") != prev.get("sha256"):
            why = "its recorded digest differs from the one the pointer remembers"
        else:
            _, why = verify_adapter(prev.get("adapter") or "", prev.get("sha256"))
        if why:
            print(f"  previous model {prev.get('run')} cannot be restored ({why}); rolling back to the base model")
            prev = None
    st.current = ({"run": prev["run"], "role": (st.runs.get(prev["run"]) or {}).get("role") or "triage",
                   "adapter": prev.get("adapter"), "sha256": prev.get("sha256"),
                   "promoted_at": _now(), "approved_by": a.approved_by, "rationale": a.rationale[:500],
                   "rolled_back_from": bad, "previous": None} if prev else None)
    st.pending.append((dict(st.current) if st.current else None, [bad] if bad else []))
    st.save()
    print(f"  rolled back {bad} → {st.current['run'] if st.current else 'base model (no adapter)'}")
    return 0


@_state_guard
def cmd_status(a) -> int:
    st = State.load(_runs_dir(a))
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
        p.add_argument("--runs", default=None, help="runs directory (default ~/aegis-runs; ~/aegis-runs/judge for "
                       "`run --role judge`) — one per model")
        p.add_argument("--run", default=None)
        p.add_argument("--dashboard", action="store_true", help="use the ACP dashboard (ACP_DASHBOARD_URL / ACP_API_KEY) "
                       "instead of this host's local queue")
        p.add_argument("--hitl-dir", default=None, help="local approvals queue (default AEGIS_HITL_DIR or ./.aegis-hitl)")
        p.add_argument("--dry-run", action="store_true")
    r = sub.add_parser("run", help="export → build → train → gate"); common(r)
    r.add_argument("--base-data", default=None, help="realistic base set (a build-public directory)")
    r.add_argument("--preset", default="qwen3-8b"); r.add_argument("--epochs", type=int, default=2)
    r.add_argument("--role", choices=("triage", "judge"), default="triage",
                   help="triage (the first-pass model) or judge (a reviewer/voter: trained on build-judge rows, judge "
                        "gate). Keep one --runs directory per model so each has its own current.json pointer")
    r.add_argument("--max-rows", type=int, default=0); r.add_argument("--since", default=None)
    r.add_argument("--min-new-rows", type=int, default=MIN_NEW_ROWS)
    s = sub.add_parser("shadow", help="candidate vs current on analyst-decided alerts newer than the training export"); common(s)
    s.add_argument("--rows", default=None, help="an export directory to use instead of pulling (tests / offline)")
    p = sub.add_parser("propose", help="ship the model_promotion proposal to the approvals queue"); common(p)
    y = sub.add_parser("sync", help="accepted model_promotion proposals → current pointer"); common(y)
    m = sub.add_parser("promote", help="offline promotion with a recorded approver"); common(m)
    m.add_argument("--approved-by", required=True); m.add_argument("--rationale", required=True)
    b = sub.add_parser("rollback", help="undo the current promotion; the run is denied for good"); common(b)
    b.add_argument("--approved-by", required=True); b.add_argument("--rationale", required=True)
    t = sub.add_parser("status"); common(t)
    a = ap.parse_args(argv)
    try:
        return _dispatch(a)
    except StateError as e:
        print(f"refused: {e}")
        return 2


def _dispatch(a) -> int:
    return {"run": cmd_run, "shadow": cmd_shadow, "propose": cmd_propose, "sync": cmd_sync, "promote": cmd_promote,
            "rollback": cmd_rollback, "status": cmd_status}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
