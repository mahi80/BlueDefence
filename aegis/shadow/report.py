"""Shadow-mode comparison — "would have done" receipts vs. what the SOC decided (roadmap 1.5).

Inputs
- **receipts** — the connector registry's receipts (latest state per
  ``receipt_id``): shadow (vendor connector, dry-run), live, or log-only.
- **chains** — the orchestrator's verdicts and recommended actions per alert.
- **decisions** — the analysts' approve / reject decisions from the dashboard
  approvals queue, per alert.

For every receipt the report asks: *did a human agree with this?* An approved
decision on the same alert and action type is the strongest signal; a decision
on the same alert but another action type is taken at alert level (the analyst
confirmed or disputed the agent's read of the alert); otherwise the receipt is
unreviewed. Grouped by (connector, action type, mode), a group is **ready to
flip live** when it has enough receipts, over a long enough window, with
enough reviews, no disagreement and no vendor failures. Action types the
``ResponseAgent`` always routes to a human (block, isolate, …) are reported as
``hitl_only``: for them "live" means one-click approval, never autonomy.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

try:  # the policy sets live with the ResponseAgent; mirror them if it is not importable
    from aegis.agents.response.agent import _ALWAYS_HITL_ACTIONS, _AUTO_SAFE_ACTIONS
except Exception:  # noqa: BLE001
    _AUTO_SAFE_ACTIONS = frozenset({"allow", "monitor", "challenge", "throttle", "notify_user", "redact",
                                    "force_logout", "quarantine_message"})
    _ALWAYS_HITL_ACTIONS = frozenset({"block", "isolate", "lock_account", "revoke_sessions", "trigger_self_heal",
                                      "kill_process", "quarantine_file", "escalate_to_fraud_team", "hold",
                                      "block_export", "recall_message", "rotate_credential", "escalate_to_hr",
                                      "snapshot_forensic", "block_egress"})

#: the order the roadmap flips things live: lowest blast radius first
FLIP_ORDER = ("throttle", "challenge", "monitor", "notify_user", "redact", "quarantine_message", "force_logout",
              "block", "block_egress", "block_export", "lock_account", "revoke_sessions", "isolate", "kill_process")


@dataclass
class Thresholds:
    min_n: int = 20            # receipts in the group
    min_reviewed: int = 10     # receipts with a human signal (agree + disagree)
    window_days: float = 14.0  # first → last receipt
    agreement: float = 0.95    # agree / (agree + disagree)
    max_failed: int = 0        # vendor failures tolerated


@dataclass
class Group:
    connector: str
    action_type: str
    mode: str
    n: int = 0
    agree: int = 0
    disagree: int = 0
    unreviewed: int = 0
    failed: int = 0
    active: int = 0
    rolled_back: int = 0
    expired: int = 0
    targets: set = field(default_factory=set)
    protected_hits: int = 0
    first_at: Optional[float] = None
    last_at: Optional[float] = None
    verdict: str = ""
    reasons: list = field(default_factory=list)

    @property
    def reviewed(self) -> int:
        return self.agree + self.disagree

    @property
    def agreement(self) -> Optional[float]:
        return (self.agree / self.reviewed) if self.reviewed else None

    @property
    def window_days(self) -> float:
        if self.first_at is None or self.last_at is None:
            return 0.0
        return max(0.0, (self.last_at - self.first_at) / 86400.0)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["targets"] = len(self.targets)
        d["reviewed"] = self.reviewed
        d["agreement"] = None if self.agreement is None else round(self.agreement, 3)
        d["window_days"] = round(self.window_days, 2)
        d["first_at"] = _iso(self.first_at)
        d["last_at"] = _iso(self.last_at)
        return d


@dataclass
class ActionRequests:
    action_type: str
    asked_auto: int = 0
    asked_hitl: int = 0
    approved: int = 0
    rejected: int = 0
    pending: int = 0

    @property
    def approval_rate(self) -> Optional[float]:
        d = self.approved + self.rejected
        return (self.approved / d) if d else None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["approval_rate"] = None if self.approval_rate is None else round(self.approval_rate, 3)
        return d


@dataclass
class ShadowReport:
    generated_at: str
    thresholds: Thresholds
    summary: dict
    groups: list[Group]
    requests: list[ActionRequests]
    flip_candidates: list[dict]

    def to_dict(self) -> dict:
        return {
            "generated_at": self.generated_at,
            "thresholds": asdict(self.thresholds),
            "summary": self.summary,
            "groups": [g.to_dict() for g in self.groups],
            "requests": [r.to_dict() for r in self.requests],
            "flip_candidates": self.flip_candidates,
        }


# ------------------------------------------------------------------ build --

def _iso(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _epoch(v: Any) -> Optional[float]:
    if v is None or v == "":
        return None
    if isinstance(v, (int, float)):
        return float(v)
    try:
        dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        return None


def _mode_of(r: dict) -> str:
    m = str(r.get("mode") or "").lower()
    if m in ("shadow", "live", "log", "auto-shadow"):
        return m
    if str(r.get("connector") or "") == "log":
        return "log"
    return "shadow" if r.get("dry_run") else "live"


def _target_matches(target: str, patterns: Iterable[str]) -> bool:
    try:
        from aegis.agents.response.agent import _target_matches as tm
        return tm(target, list(patterns))
    except Exception:  # noqa: BLE001
        import fnmatch
        return any(fnmatch.fnmatch(target, p) for p in patterns)


def _human_signal(action_type: str, decisions: list[dict]) -> str:
    """``agree`` / ``disagree`` / ``unreviewed`` for one receipt.

    Only a decision on this same action type counts: approving ``monitor`` on an alert says nothing about
    the ``throttle`` that was shadowed on it (the old fallback to any decision let one action's approvals
    justify flipping another live)."""
    pool = [d for d in decisions if str(d.get("action_type") or "") == action_type]
    if not pool:
        return "unreviewed"
    states = {str(d.get("decision") or d.get("status") or "").lower() for d in pool}
    if "rejected" in states:
        return "disagree"
    if "approved" in states:
        return "agree"
    return "unreviewed"


def build_report(receipts: Iterable[dict], chains: Iterable[dict] = (), *,
                 decisions_by_alert: Optional[dict[str, list[dict]]] = None,
                 thresholds: Optional[Thresholds] = None,
                 protected_targets: Iterable[str] = ()) -> ShadowReport:
    th = thresholds or Thresholds()
    latest_chains, decisions_by_alert = _normalize_chains(chains, decisions_by_alert)
    chains = list(latest_chains.values())

    groups: dict[tuple[str, str, str], Group] = {}
    n_receipts = 0
    protected = [p for p in protected_targets if p]
    for r in receipts:
        if not isinstance(r, dict) or not r.get("receipt_id"):
            continue
        status = str(r.get("status") or "")
        if status == "unsupported":
            continue
        n_receipts += 1
        key = (str(r.get("connector") or ""), str(r.get("action_type") or ""), _mode_of(r))
        g = groups.get(key)
        if g is None:
            g = groups[key] = Group(*key)
        g.n += 1
        signal = _human_signal(key[1], decisions_by_alert.get(str(r.get("alert_id") or ""), []))
        setattr(g, signal, getattr(g, signal) + 1)
        if status == "failed":
            g.failed += 1
        elif status in ("applied", "dry_run", "renewed"):
            g.active += 1
        elif status == "rolled_back":
            g.rolled_back += 1
        elif status == "expired":
            g.expired += 1
        target = str(r.get("target") or "")
        g.targets.add(target)
        if protected and _target_matches(target, protected):
            g.protected_hits += 1
        ts = _epoch(r.get("applied_at")) or _epoch(r.get("recorded_at")) or _epoch(r.get("created_at"))
        if ts is not None:
            g.first_at = ts if g.first_at is None else min(g.first_at, ts)
            g.last_at = ts if g.last_at is None else max(g.last_at, ts)

    for g in groups.values():
        _judge(g, th)

    requests = _requests(chains, decisions_by_alert)
    ordered = sorted(groups.values(), key=lambda g: (_flip_rank(g.action_type), g.connector, g.mode))
    candidates = [
        {"connector": g.connector, "action_type": g.action_type, "n": g.n, "agreement": g.agreement,
         "window_days": round(g.window_days, 1), "next_step": _next_step(g)}
        for g in ordered if g.verdict == "ready"
    ]
    n_decisions = sum(len(v) for v in decisions_by_alert.values())
    modes = defaultdict(int)
    for g in groups.values():
        modes[g.mode] += g.n
    summary = {
        "receipts": n_receipts, "chains": len(chains), "decisions": n_decisions,
        "by_mode": dict(modes), "groups": len(groups),
        "ready": sum(1 for g in groups.values() if g.verdict == "ready"),
        "not_yet": sum(1 for g in groups.values() if g.verdict == "not_yet"),
        "hitl_only": sum(1 for g in groups.values() if g.verdict == "hitl_only"),
        "live": sum(1 for g in groups.values() if g.verdict == "live"),
        "log_only": sum(1 for g in groups.values() if g.verdict == "log_only"),
    }
    return ShadowReport(generated_at=datetime.now(timezone.utc).isoformat(), thresholds=th, summary=summary,
                        groups=ordered, requests=requests, flip_candidates=candidates)


def _unwrap(entry: dict) -> tuple[dict, list[dict]]:
    """Accept a bare chain, a dashboard row (``{"chain": {...}}``) or a dataset-feed entry
    (``{"chain": {row…, "chain": {...}}, "human": [...]}``); return (chain, decisions)."""
    human = entry.get("human") if isinstance(entry.get("human"), list) else []
    inner = entry.get("chain") if isinstance(entry.get("chain"), dict) else None
    if inner is not None and isinstance(inner.get("chain"), dict):
        return inner["chain"], human
    if inner is not None and ("recommended_actions" in inner or "verdict" in inner):
        return inner, human
    return entry, human


def _normalize_chains(chains: Iterable[dict], explicit: Optional[dict[str, list[dict]]]
                      ) -> tuple[dict[str, dict], dict[str, list[dict]]]:
    """Latest chain per alert id; decisions merged from the entries and the explicit map, deduped."""
    latest: dict[str, dict] = {}
    seen: dict[str, dict[str, dict]] = defaultdict(dict)
    for c in chains:
        if not isinstance(c, dict):
            continue
        chain, human = _unwrap(c)
        aid = str(chain.get("alert_id") or "")
        if not aid:
            continue
        latest[aid] = chain                      # feeds are ascending by created_at → last wins
        for h in human:
            if isinstance(h, dict):
                seen[aid][_decision_key(h)] = h
    for aid, items in (explicit or {}).items():
        for h in items or []:
            if isinstance(h, dict):
                seen[str(aid)][_decision_key(h)] = h
    return latest, {aid: list(d.values()) for aid, d in seen.items()}


def _decision_key(h: dict) -> str:
    return str(h.get("approval_id") or f"{h.get('action_type')}|{h.get('target')}|{h.get('decision') or h.get('status')}|{h.get('decided_at')}")


def _judge(g: Group, th: Thresholds) -> None:
    reasons: list[str] = []
    if g.mode == "live":
        g.verdict, g.reasons = "live", ["already live"]
        return
    if g.mode == "log":
        g.verdict = "log_only"
        g.reasons = ["logging fallback — no vendor connector routes this action yet (roadmap 1.2/1.3)"]
        return
    if g.action_type in _ALWAYS_HITL_ACTIONS and g.mode != "auto-shadow":
        g.verdict = "hitl_only"
        g.reasons = ["always needs a human: live = one-click approval, never autonomous"]
        return
    if g.n < th.min_n:
        reasons.append(f"n={g.n} < {th.min_n}")
    if g.window_days < th.window_days:
        reasons.append(f"window {g.window_days:.1f} d < {th.window_days:g} d")
    if g.reviewed < th.min_reviewed:
        reasons.append(f"reviewed {g.reviewed} < {th.min_reviewed} ({g.unreviewed} unreviewed)")
    if g.disagree > 0 or (g.agreement is not None and g.agreement < th.agreement):
        reasons.append(f"agreement {0 if g.agreement is None else g.agreement:.0%} < {th.agreement:.0%} ({g.disagree} disagreement(s))")
    if g.failed > th.max_failed:
        reasons.append(f"{g.failed} vendor failure(s)")
    g.verdict = "ready" if not reasons else "not_yet"
    g.reasons = reasons or ["meets every threshold"]


def _flip_rank(action_type: str) -> int:
    try:
        return FLIP_ORDER.index(action_type)
    except ValueError:
        return len(FLIP_ORDER)


def _next_step(g: Group) -> str:
    if g.action_type in _AUTO_SAFE_ACTIONS:
        return (f"flip {g.connector} live for {g.action_type} (AEGIS_ENFORCEMENT_MODE=live on that connector); "
                f"keep TTLs, watch rollbacks for a week")
    return f"enable one-click approval for {g.action_type} via {g.connector}"


def _requests(chains: list[dict], decisions_by_alert: dict[str, list[dict]]) -> list[ActionRequests]:
    by_action: dict[str, ActionRequests] = {}
    for chain in chains:
        aid = str(chain.get("alert_id") or "")
        for a in chain.get("recommended_actions") or []:
            if not isinstance(a, dict):
                continue
            at = str(a.get("action_type") or "")
            req = by_action.setdefault(at, ActionRequests(at))
            if a.get("requires_hitl"):
                req.asked_hitl += 1
            else:
                req.asked_auto += 1
        for d in decisions_by_alert.get(aid, []):
            at = str(d.get("action_type") or "")
            req = by_action.setdefault(at, ActionRequests(at))
            state = str(d.get("decision") or d.get("status") or "").lower()
            if state == "approved":
                req.approved += 1
            elif state == "rejected":
                req.rejected += 1
            else:
                req.pending += 1
    return sorted(by_action.values(), key=lambda r: (_flip_rank(r.action_type), r.action_type))


# ----------------------------------------------------------------- render --

def render_text(rep: ShadowReport) -> str:
    s = rep.summary
    th = rep.thresholds
    lines = [
        f"AEGIS shadow-mode report — {rep.generated_at}",
        f"  receipts={s['receipts']} by mode {s['by_mode']}  chains={s['chains']}  analyst decisions={s['decisions']}",
        f"  thresholds: n≥{th.min_n}, reviewed≥{th.min_reviewed}, window≥{th.window_days:g} d, "
        f"agreement≥{th.agreement:.0%}, vendor failures≤{th.max_failed}",
        "",
        f"  {'connector':<10} {'action':<18} {'mode':<11} {'n':>4} {'agree':>5} {'dis':>4} {'unrev':>5} {'fail':>4} "
        f"{'win d':>6}  verdict    why",
    ]
    for g in rep.groups:
        lines.append(
            f"  {g.connector:<10} {g.action_type:<18} {g.mode:<11} {g.n:>4} {g.agree:>5} {g.disagree:>4} {g.unreviewed:>5} "
            f"{g.failed:>4} {g.window_days:>6.1f}  {g.verdict:<9}  {'; '.join(g.reasons)}"
        )
    if not rep.groups:
        lines.append("  (no receipts yet — run the agent with AEGIS_RECEIPTS=1 (default) and a connector registry)")
    lines += ["", "  what the agent asked for vs. what analysts said:",
              f"  {'action':<18} {'auto':>5} {'hitl':>5} {'appr':>5} {'rej':>4} {'pend':>5}  approval"]
    for r in rep.requests:
        rate = "-" if r.approval_rate is None else f"{r.approval_rate:.0%}"
        lines.append(f"  {r.action_type:<18} {r.asked_auto:>5} {r.asked_hitl:>5} {r.approved:>5} {r.rejected:>4} {r.pending:>5}  {rate}")
    lines.append("")
    if rep.flip_candidates:
        lines.append("  READY TO FLIP LIVE (lowest blast radius first):")
        for c in rep.flip_candidates:
            lines.append(f"   - {c['action_type']} via {c['connector']}: n={c['n']}, agreement={c['agreement']:.0%}, "
                         f"{c['window_days']} d → {c['next_step']}")
    else:
        lines.append("  Nothing is ready to flip live yet (see 'why' per row).")
    return "\n".join(lines)


def to_json(rep: ShadowReport) -> str:
    return json.dumps(rep.to_dict(), indent=2, sort_keys=True)


__all__ = ["Thresholds", "Group", "ActionRequests", "ShadowReport", "build_report", "render_text", "to_json",
           "FLIP_ORDER"]
