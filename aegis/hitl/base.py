"""The HITL transport contract — what the ResponseAgent needs from *any* approval channel.

    request(action, chain) -> approval_id | None     file the card (None → the stdout card fallback)
    sync(response_agent)   -> [Decision]              poll decisions; approved ones execute via response_agent.approve()
    attach_investigation(alert_id, card) -> int       async tier updates the card in place (optional)
    enabled, pending, decisions

``BaseHITL`` holds the bookkeeping (idempotency per (alert, action, target), pending queue,
settle, and a **restart-safe journal** of pending approvals); a transport implements ``_file(card) -> external id``, ``_poll(pending) -> (status,
decided_by, reason) | None`` and optionally ``_annotate(pending, card)``. Editions pick the
transport with ``AEGIS_HITL_TRANSPORT=dashboard|servicenow|file|stdout`` (``aegis.edition``).

Journal: every filed approval and every settlement is appended to a small JSONL file
(``AEGIS_HITL_STATE``; default ``<AEGIS_HITL_DIR or ./.aegis-hitl>/pending.jsonl``;
``off`` disables it). On start the journal is replayed, so an approval filed before a restart
is still polled, approved and executed after it — before this, a restart mid-incident silently
dropped every pending decision. The journal is compacted to the live set on load. Entries
written by a different transport are ignored.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("aegis.hitl")

_ARGS_TEXT_CAP = 2000
# chain metadata the HITL timeout policy decides on — kept in the journal so a restart does not change the answer
_JOURNALED_METADATA = ("vote_concur", "vote_tally", "swarm_vote_concur", "verdict_raised_by_swarm")


@dataclass
class PendingApproval:
    approval_id: str
    alert_id: str
    action: Any
    chain: Any
    requested_at: float = field(default_factory=time.time)
    external_id: str = ""              # ticket sys_id / row id on the other side
    first_approver: str = ""           # two-person rule: the approval already given, waiting for a second
    approved_by: str = ""              # a human approval the service is still trying to execute (retry)
    second_by: str = ""                # ... and its second approver, when the two-person rule applied
    attempts: int = 0                  # execution attempts of that approval
    unfiled: bool = False              # the channel refused the card; sync() files it again (review E3)
    # Could this action have run with no human when it was filed (grounded in the alert, narrow, no injection
    # evidence)? Only then may the HITL-timeout fallback run it. Journaled, so a restart cannot turn a held card
    # into an executable one; a card restored from an older journal has no flag and holds (review round 3 G1-1/2).
    timeout_ok: bool = False
    card: dict | None = None           # the card to re-file while unfiled


@dataclass
class Decision:
    approval_id: str
    alert_id: str
    action_type: str
    target: str
    status: str                 # approved | rejected | expired | failed (approved, could not run)
    decided_by: str = ""
    reason: str = ""
    executed: Optional[Any] = None   # ExecutedAction when approved


def _slug(s: str) -> str:
    return "".join(ch if ch.isalnum() else "-" for ch in s)[:32].strip("-") or "x"


def card_args(action: Any, chain: Any) -> dict:
    """What the approver sees: enough to decide, no raw payload. Shared by every transport."""
    return {
        "source": "aegis",
        "alert_id": str(getattr(chain, "alert_id", "")),
        "action_type": str(action.action_type),
        "target": str(action.target)[:256],
        "action_confidence": round(float(getattr(action, "confidence", 0.0) or 0.0), 2),
        "reasoning": str(getattr(action, "reasoning", ""))[:_ARGS_TEXT_CAP],
        "verdict": str(getattr(chain, "verdict", "")),
        "chain_confidence": round(float(getattr(chain, "confidence", 0.0) or 0.0), 2),
        "investigated_by": str(getattr(chain, "investigated_by", "")),
        "specialists": list(getattr(chain, "specialist_invocations", []) or [])[:10],
        "evidence_count": len(getattr(chain, "evidence", []) or []),
        "integrity_hash": str(getattr(chain, "integrity_hash", "") or ""),
        "governance_block": (getattr(chain, "metadata", {}) or {}).get("governance_block"),
    }


def execution_outcome(executed: Any) -> tuple[bool, str]:
    """(ran, why-not) for whatever ``response_agent.approve`` returned.

    An ``ExecutedAction`` ran only when its status is ``executed``; a dict ran unless it carries an
    ``error``; anything else (a test stub, a commitment recorder) counts as ran."""
    status = getattr(executed, "status", None)
    if status is not None:
        return (status == "executed"), str(getattr(executed, "note", "") or status)[:300]
    if isinstance(executed, dict) and executed.get("error"):
        return False, str(executed["error"])[:300]
    return True, ""


# A rate cap or a vendor/transport error is temporary: the approval stays pending and is executed again on
# the next sync (up to these limits) instead of being settled ``failed`` and lost.
_RETRY_LIMIT = {"rate_cap": 60, "connector_failed": 3, "error": 3}


def _retry_kind(executed: Any) -> str:
    """'' (do not retry), or the reason an approval that did not run may run on a later attempt."""
    reason = str(getattr(executed, "reason", "") or "")
    if reason in _RETRY_LIMIT:
        return reason
    if isinstance(executed, dict) and executed.get("error"):
        return "error"
    return ""


def _with_why(executed: Any, why: str) -> Any:
    if hasattr(executed, "note"):
        executed.note = why
        return executed
    return {"error": why}


def _state_path(explicit: Optional[str | Path], transport_dir: Optional[Path], scope: str = "soc") -> Optional[Path]:
    """The approvals journal. Each scope has its own file: the posture/exposure runner and the SOC used to
    share ``pending.jsonl`` under the same transport name, so the runner restored the SOC's cards and settled
    them through its own recorder — a SOC block card became ``approved`` with nothing applied (code review
    2026-11-03 C2)."""
    raw = str(explicit) if explicit is not None else os.environ.get("AEGIS_HITL_STATE", "").strip()
    if raw.lower() in ("off", "0", "none", "false"):
        return None
    if raw:
        path = Path(raw)
    else:
        base = transport_dir or Path(os.environ.get("AEGIS_HITL_DIR") or (Path.cwd() / ".aegis-hitl"))
        path = Path(base) / "pending.jsonl"
    if scope and scope != "soc":
        path = path.with_name(f"{path.stem}-{scope}{path.suffix}")
    return path


def action_text(action_type: Any, target: Any) -> str:
    """What a decision binds to: the FULL ``type -> target``. The card's ``args.target`` is cut at 256 chars for
    display; binding to that cut text dropped every decision on a long target (review round 4 R4-2)."""
    return f"{action_type} -> {target}"


def _sync_budget_s() -> float:
    """``AEGIS_HITL_SYNC_BUDGET_S`` (default 30; 0 = no limit): wall-clock spent polling approvals per sync. A slow
    channel with a backlog used to hold the service thread for minutes per cycle (R4-13)."""
    try:
        v = float(os.environ.get("AEGIS_HITL_SYNC_BUDGET_S", "30") or 0)
    except ValueError:
        return 30.0
    return v if v > 0 and v == v else 0.0


def _watchdog() -> None:
    try:
        from ..ops import sdnotify
        sdnotify.watchdog()
    except Exception:  # noqa: BLE001 — best-effort keep-alive
        pass


def _action_dict(action: Any) -> dict:
    if hasattr(action, "model_dump"):
        return action.model_dump()
    return {k: getattr(action, k, None) for k in ("action_type", "target", "reasoning", "requires_hitl", "confidence")}


class BaseHITL:
    name = "base"
    scope = "soc"          # whose approvals these are; set before first use (the exposure runner uses "exposure")

    def __init__(self, *, state_path: Optional[str | Path] = None) -> None:
        self._pending: dict[str, PendingApproval] = {}
        self._by_key: dict[tuple[str, str, str], str] = {}
        self.decisions: list[Decision] = []
        self._state_arg = state_path
        self._journal: Optional[Path] = None
        self._loaded = False
        self._jlock = threading.Lock()
        self.restored = 0
        self._timeout_noted: set[str] = set()   # approvals already shadow-logged / escalated by the timeout policy
        self._poll_failed: set[tuple[str, str]] = set()   # (approval, error) pairs already warned about
        self._last_polled: dict[str, float] = {}

    # ---- journal
    def _journal_dir(self) -> Optional[Path]:
        """Transports with their own directory keep the journal there (``FileHITL``)."""
        return None

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        self._journal = _state_path(self._state_arg, self._journal_dir(), self.scope)
        if self._journal is None or not self._journal.exists():
            return
        live: dict[str, dict] = {}
        bad = 0
        try:
            for line in self._journal.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    bad += 1; continue
                if row.get("transport") not in (None, self.name):
                    continue
                if row.get("op") == "filed" and row.get("approval_id"):
                    live[str(row["approval_id"])] = row
                elif row.get("op") == "settled":
                    live.pop(str(row.get("approval_id")), None)
                elif row.get("op") == "progress" and str(row.get("approval_id")) in live:
                    live[str(row["approval_id"])].update({k: row[k] for k in ("first_approver", "approved_by", "second_by", "attempts",
                                                                              "external_id", "unfiled", "timeout_ok",
                                                                              "requested_at")
                                                          if k in row})
        except OSError as e:
            logger.warning("[hitl:%s] approvals journal %s unreadable (%s); starting with none pending", self.name, self._journal, e)
            return
        for aid, row in live.items():
            try:
                pa = self._restore(row)
            except Exception as e:  # noqa: BLE001 — one corrupt row must not lose the others
                bad += 1
                logger.warning("[hitl:%s] journal row %s not restorable: %s", self.name, aid, str(e)[:120]); continue
            self._pending[aid] = pa
            self._by_key[(pa.alert_id, str(pa.action.action_type), str(pa.action.target))] = aid
        self.restored = len(self._pending)
        if bad:
            logger.warning("[hitl:%s] approvals journal: %d unreadable row(s) skipped", self.name, bad)
        if self.restored:
            logger.info("[hitl:%s] restored %d pending approval(s) from %s", self.name, self.restored, self._journal)
        self._compact()

    def _restore(self, row: dict) -> PendingApproval:
        from ..agents.shared.evidence_chain import EvidenceChain, RecommendedAction
        action = RecommendedAction(**row["action"])
        c = row.get("chain") or {}
        chain = EvidenceChain(alert_id=str(c.get("alert_id") or row.get("alert_id") or ""),
                              investigated_by=str(c.get("investigated_by") or "restored"),
                              verdict=c.get("verdict") or "uncertain", confidence=float(c.get("confidence") or 0.0))
        chain.metadata.update({k: v for k, v in (c.get("metadata") or {}).items() if k in _JOURNALED_METADATA})
        chain.metadata["restored_from_journal"] = True
        return PendingApproval(approval_id=str(row["approval_id"]), alert_id=str(row.get("alert_id") or chain.alert_id),
                               action=action, chain=chain, requested_at=float(row.get("requested_at") or time.time()),
                               external_id=str(row.get("external_id") or ""),
                               first_approver=str(row.get("first_approver") or ""),
                               approved_by=str(row.get("approved_by") or ""), second_by=str(row.get("second_by") or ""),
                               attempts=int(row.get("attempts") or 0), unfiled=bool(row.get("unfiled")),
                               card=row.get("card") if isinstance(row.get("card"), dict) else None,
                               timeout_ok=row.get("timeout_ok") is True)

    def _journal_append(self, row: dict) -> None:
        if self._journal is None:
            return
        try:
            with self._jlock:
                self._journal.parent.mkdir(parents=True, exist_ok=True)
                data = (json.dumps({"transport": self.name, "ts": time.time(), **row}, ensure_ascii=False, default=str) + "\n").encode()
                with self._journal.open("ab") as f:
                    start = f.tell()
                    try:
                        f.write(data)
                        f.flush()
                    except OSError:
                        # a fragment left by ENOSPC would swallow the next row (code review 2026-11-03 E8)
                        try:
                            f.truncate(start)
                        except OSError:
                            pass
                        raise
        except OSError as e:
            # the approval is still filed and pending in memory; only restart-safety is lost — say so
            logger.warning("[hitl:%s] approvals journal write failed (%s): pending decisions will not survive a restart",
                           self.name, e)

    def _compact(self) -> None:
        if self._journal is None:
            return
        try:
            with self._jlock:
                tmp = self._journal.with_suffix(self._journal.suffix + ".tmp")
                with tmp.open("w", encoding="utf-8") as f:
                    for p in self._pending.values():
                        f.write(json.dumps(self._filed_row(p), ensure_ascii=False, default=str) + "\n")
                tmp.replace(self._journal)
        except OSError as e:
            logger.warning("[hitl:%s] approvals journal compaction failed: %s", self.name, e)

    def _filed_row(self, p: PendingApproval) -> dict:
        return {"transport": self.name, "op": "filed", "approval_id": p.approval_id, "alert_id": p.alert_id,
                "external_id": p.external_id, "requested_at": p.requested_at, "action": _action_dict(p.action),
                "chain": {"alert_id": str(getattr(p.chain, "alert_id", p.alert_id)), "verdict": str(getattr(p.chain, "verdict", "")),
                          "confidence": float(getattr(p.chain, "confidence", 0.0) or 0.0),
                          "investigated_by": str(getattr(p.chain, "investigated_by", "")),
                          # the timeout policy reads these; without them a restored card looked like a concurring vote
                          "metadata": {k: (getattr(p.chain, "metadata", None) or {}).get(k)
                                       for k in _JOURNALED_METADATA
                                       if k in (getattr(p.chain, "metadata", None) or {})}},
                # progress survives journal compaction too
                "first_approver": p.first_approver, "approved_by": p.approved_by, "second_by": p.second_by,
                "attempts": p.attempts, "timeout_ok": p.timeout_ok,
                **({"unfiled": True, "card": p.card} if p.unfiled else {})}

    # ---- contract
    @property
    def enabled(self) -> bool:
        return True

    @property
    def pending(self) -> list[PendingApproval]:
        self._ensure_loaded()
        return list(self._pending.values())

    def request(self, action: Any, chain: Any, *, timeout_ok: bool = False) -> Optional[str]:
        if not self.enabled:
            return None
        self._ensure_loaded()
        key = (str(getattr(chain, "alert_id", "")), str(action.action_type), str(action.target))
        if key in self._by_key and self._by_key[key] in self._pending:
            return self._by_key[key]
        approval_id = f"aegis_{_slug(key[0])}_{_slug(key[1])}_{uuid.uuid4().hex[:6]}"
        card = {"id": approval_id, "action": action_text(action.action_type, action.target), "args": card_args(action, chain),
                "severity": str(getattr(chain, "verdict", "")), "alert_id": key[0]}
        try:
            external_id = self._file(card)
            why = "" if external_id is not None else "the channel returned no id"
        except Exception as e:  # noqa: BLE001 — channel down is a runtime condition
            external_id, why = None, f"{type(e).__name__}: {str(e)[:160]}"
        if external_id is None:
            # Keep it, journal it and file it again on every sync until the channel takes it (code review
            # 2026-11-03 E3: a dashboard ConnectError used to lose `isolate host-7` for good). It never times
            # out into an execution while unfiled — no analyst has seen it. None still tells the caller to
            # print the stdout card now.
            pa = PendingApproval(approval_id=approval_id, alert_id=key[0], action=action, chain=chain,
                                 unfiled=True, card=card, timeout_ok=bool(timeout_ok))
            self._pending[approval_id] = pa
            self._by_key[key] = approval_id
            row = self._filed_row(pa)
            row.pop("transport", None)
            self._journal_append(row)
            logger.error("[hitl:%s] could not file approval %s for %s on alert %s (%s) — kept and retried every sync",
                         self.name, approval_id, key[1], key[0], why)
            return None
        pa = PendingApproval(approval_id=approval_id, alert_id=key[0], action=action, chain=chain, external_id=str(external_id),
                             timeout_ok=bool(timeout_ok))
        self._pending[approval_id] = pa
        self._by_key[key] = approval_id
        row = self._filed_row(pa)
        row.pop("transport", None)
        self._journal_append(row)
        logger.info("[hitl:%s] approval %s filed for %s on alert %s", self.name, approval_id, key[1], key[0])
        return approval_id

    def _refile(self, p: PendingApproval) -> bool:
        """File an approval the channel refused earlier. True once it is filed."""
        card = p.card or {"id": p.approval_id, "action": action_text(p.action.action_type, p.action.target),
                          "args": card_args(p.action, p.chain), "severity": str(getattr(p.chain, "verdict", "")),
                          "alert_id": p.alert_id}
        try:
            external_id = self._file(card)
        except Exception as e:  # noqa: BLE001
            key = (p.approval_id, "refile:" + str(e)[:80])
            if key not in self._poll_failed:
                self._poll_failed.add(key)
                logger.warning("[hitl:%s] approval %s still not filed: %s", self.name, p.approval_id, str(e)[:160])
            return False
        if external_id is None:
            return False
        # the wait window starts when an analyst can first see the card, not when the channel first refused it: a
        # card refused for 10 min used to time out into an execution on the sync right after it was filed (R4-9)
        p.external_id, p.unfiled, p.card, p.requested_at = str(external_id), False, None, time.time()
        self._journal_append({"op": "progress", "approval_id": p.approval_id, "external_id": p.external_id,
                              "unfiled": False, "requested_at": p.requested_at})
        logger.info("[hitl:%s] approval %s filed after a retry", self.name, p.approval_id)
        return True

    def sync(self, response_agent: Any, *, max_age_sec: Optional[float] = None,
             timeout_policy: Any = None) -> list[Decision]:
        """Pull decisions and act on them.

        A human decision always wins. ``timeout_policy`` (opt-in; default off) is the
        few-analyst fallback for an approval nobody has decided: an eligible reversible
        action past its wait window auto-executes, everything else is held (and escalated
        on hard expiry). With no ``timeout_policy`` the behaviour is byte-identical to
        before — ``max_age_sec`` still expires an old approval outright.
        """
        self._ensure_loaded()
        made: list[Decision] = []
        now = time.time()
        budget = _sync_budget_s()
        t0 = time.monotonic()
        # least-recently polled first, so a budget cut-off never starves the same cards every cycle (R4-13)
        order = sorted(self._pending.items(), key=lambda kv: self._last_polled.get(kv[0], 0.0))
        for n, (approval_id, p) in enumerate(order):
            if n and budget and time.monotonic() - t0 > budget:
                logger.warning("[hitl:%s] sync stopped after %.0f s with %d approval(s) not polled this cycle "
                               "(AEGIS_HITL_SYNC_BUDGET_S)", self.name, budget, len(order) - n)
                break
            _watchdog()
            self._last_polled[approval_id] = time.time()
            age = now - p.requested_at
            expired = max_age_sec is not None and age > max_age_sec
            # Preserve the original path exactly when the timeout policy is not in use.
            if expired and timeout_policy is None:
                made.append(self._settle(p, "expired", "", f"no decision within {int(max_age_sec)} s")); continue
            # a card the channel refused: file it again; nothing is decided (or timed out) on a card nobody has seen
            if p.unfiled:
                if expired:
                    logger.error("[hitl:%s] approval %s for %s on alert %s expired without ever reaching the channel",
                                 self.name, approval_id, p.action.action_type, p.alert_id)
                    made.append(self._settle(p, "expired", "", "never filed: the approval channel refused it until it expired"))
                    continue
                self._refile(p)
                continue
            # 0) an approval already given that has not run yet (rate cap, vendor error): try it again — but read the
            # channel first. A rejection made after the approval used to be ignored while the retry ran for up to 60
            # cycles (R4-7); an unreadable channel holds the retry, as it holds the timeout.
            if p.approved_by:
                try:
                    res = self._poll(p)
                except Exception as e:  # noqa: BLE001
                    key = (approval_id, "retry:" + str(e)[:80])
                    if key not in self._poll_failed:
                        self._poll_failed.add(key)
                        logger.warning("[hitl:%s] poll failed for %s; approved retry held: %s", self.name, approval_id,
                                       str(e)[:160])
                    continue
                if res and res[0] == "rejected":
                    made.append(self._settle(p, "rejected", res[1] or self.name,
                                             res[2] or f"rejected after approval by {p.approved_by} (not yet run)"))
                    continue
                d = self._execute_approved(p, response_agent, p.approved_by, second=p.second_by or None)
                if d is not None:
                    made.append(d)
                continue
            # 1) a human decision always wins
            try:
                res = self._poll(p)
            except Exception as e:  # noqa: BLE001
                # loud, once per approval per failure message: a wedged transport must not look like "nobody decided yet"
                key = (approval_id, str(e)[:80])
                if key not in self._poll_failed:
                    self._poll_failed.add(key)
                    logger.warning("[hitl:%s] poll failed for %s: %s", self.name, approval_id, str(e)[:160])
                # We could not read the human's decision, so we do not know there isn't one: the analyst may
                # have rejected it. Never fall through to the timeout auto-execute on an unreadable channel.
                continue
            if res:
                status, decided_by, reason = res
                if status == "approved":
                    if _anonymous(decided_by) and (p.first_approver or bool(
                            getattr(response_agent, "two_person_required", lambda a: False)(p.action))):
                        # an approval nobody can be named for cannot be one of two people (R4-6)
                        key = (approval_id, "unattributed")
                        if key not in self._poll_failed:
                            self._poll_failed.add(key)
                            logger.warning("[hitl:%s] approval of %s has no attributable approver; a two-person "
                                           "action needs named approvers — waiting", self.name, approval_id)
                        continue
                    who = decided_by or self.name
                    if p.first_approver:
                        from .signing import same_person
                        if same_person(who, p.first_approver):
                            continue                          # the same person again: still waiting for a second
                        d = self._execute_approved(p, response_agent, p.first_approver, second=who)
                    else:
                        d = self._execute_approved(p, response_agent, who, second=None)
                    if d is not None:
                        made.append(d)
                    continue
                if status == "rejected":
                    made.append(self._settle(p, "rejected", decided_by or self.name, reason)); continue
                if status == "expired":
                    # the channel closed the card to humans: settle it, never time it out into an execution (R4-12)
                    made.append(self._settle(p, "expired", decided_by or self.name,
                                             reason or "expired at the approval channel")); continue
                if status == "contested":
                    # a decision arrived that names another action (e.g. a mismatched target): somebody decided
                    # something, so the timer must not decide instead (R4-2). Hold for a decision that matches.
                    if p.timeout_ok:
                        p.timeout_ok = False
                        self._journal_append({"op": "progress", "approval_id": p.approval_id, "timeout_ok": False})
                    continue
            # 2) no human decision — timeout auto-execute policy (opt-in). Never for an action that was sent to a
            # human because it could not run unattended (ungrounded / wide / injection / plan step), and never for
            # a two-person card: the timer is not a person, and it used to settle half-approved cards `failed`.
            if timeout_policy is not None:
                two_person = bool(p.first_approver) or bool(
                    getattr(response_agent, "two_person_required", lambda a: False)(p.action))
                if not p.timeout_ok:
                    decision, why = "hold", "was sent to a human because it could not run unattended"
                elif two_person:
                    decision, why = "hold", "two-person action — the timer is not an approver"
                else:
                    protected = bool(getattr(response_agent, "_is_protected", lambda t: False)(str(p.action.target)))
                    decision, why = timeout_policy.evaluate(p.action, p.chain, age_sec=age, protected=protected)
                if decision == "execute":
                    try:
                        executed = response_agent.approve(p.action, approver="aegis:hitl-timeout", source_alert_id=p.alert_id)
                    except Exception as e:  # noqa: BLE001
                        executed = {"error": str(e)[:200]}
                    logger.warning("[hitl:%s] timeout auto-execute: %s on alert %s — %s",
                                   self.name, p.action.action_type, p.alert_id, why)
                    made.append(self._settle_approved(p, "aegis:hitl-timeout", why, executed)); continue
                if decision == "shadow" and approval_id not in self._timeout_noted:
                    self._timeout_noted.add(approval_id)
                    logger.info("[hitl:%s] timeout-shadow: would auto-execute %s on alert %s — %s",
                                self.name, p.action.action_type, p.alert_id, why)
                if expired:
                    if approval_id not in self._timeout_noted:
                        self._timeout_noted.add(approval_id)
                        logger.warning("[hitl:%s] timeout-hold: %s on alert %s expired with no human decision — %s",
                                       self.name, p.action.action_type, p.alert_id, why)
                    made.append(self._settle(p, "expired", "", f"no decision within {int(max_age_sec)} s")); continue
        return made

    def attach_investigation(self, alert_id: str, card: Optional[dict]) -> int:
        if not self.enabled or not card:
            return 0
        self._ensure_loaded()
        n = 0
        for p in [p for p in self._pending.values() if p.alert_id == str(alert_id)]:
            try:
                if self._annotate(p, card):
                    n += 1
            except Exception as e:  # noqa: BLE001 — the card keeps its verdict-time content
                logger.warning("[hitl:%s] could not update card %s: %s", self.name, p.approval_id, str(e)[:160])
        if n:
            logger.info("[hitl:%s] investigation attached to %d card(s) for alert %s", self.name, n, alert_id)
        return n

    # ---- transport hooks
    def _file(self, card: dict) -> Optional[str]:
        raise NotImplementedError

    def _poll(self, p: PendingApproval) -> Optional[tuple[str, str, str]]:
        raise NotImplementedError

    def _record_settled(self, p: PendingApproval, status: str, decided_by: str, reason: str) -> None:
        """Transport hook: note that an approval is no longer pending (expired, timed out, decided), so a
        reader of the transport's own files (the console) does not show it as open forever."""
        return None

    def _annotate(self, p: PendingApproval, card: dict) -> bool:
        return False

    # ---- helpers
    def _execute_approved(self, p: PendingApproval, response_agent: Any, approver: str, *,
                          second: str | None) -> Decision | None:
        """Run a human-approved action. Returns the settled Decision, or None while it stays pending: waiting
        for a second approver (two-person rule), or a temporary failure (rate cap, vendor error) that the
        next sync retries. Before, both settled ``failed`` at once and the approval was lost."""
        kw = {"second_approver": second} if second else {}
        try:
            executed = response_agent.approve(p.action, approver=approver, source_alert_id=p.alert_id, **kw)
        except Exception as e:  # noqa: BLE001 — one connector failure must not stall every other pending decision
            executed = {"error": str(e)[:200]}
        if getattr(executed, "reason", "") == "needs_second_approver" and not second:
            from .signing import same_person
            if not same_person(p.first_approver, approver):
                p.first_approver, p.approved_by, p.second_by = approver, "", ""
                self._journal_append({"op": "progress", "approval_id": p.approval_id, "first_approver": approver,
                                      "approved_by": "", "second_by": "", "attempts": p.attempts})
                logger.warning("[hitl:%s] %s -> %s on alert %s approved by %s; a second, different approver is "
                               "required (protected target)", self.name, p.action.action_type, p.action.target,
                               p.alert_id, approver)
                try:
                    self._record_awaiting_second(p, approver)
                except Exception as e:  # noqa: BLE001 — the console marker is best-effort
                    logger.debug("[hitl:%s] awaiting marker not written for %s: %s", self.name, p.approval_id, str(e)[:120])
            return None
        decided_by = approver if not second else f"{approver}+{second}"
        ok, why = execution_outcome(executed)
        kind = "" if ok else _retry_kind(executed)
        if kind:
            p.attempts += 1
            if p.attempts < _RETRY_LIMIT[kind]:
                if not p.approved_by:
                    logger.warning("[hitl:%s] %s -> %s on alert %s approved by %s did not run yet (%s); retrying "
                                   "on the next cycle", self.name, p.action.action_type, p.action.target, p.alert_id,
                                   decided_by, why[:160])
                p.approved_by, p.second_by = approver, second or ""
                self._journal_append({"op": "progress", "approval_id": p.approval_id, "first_approver": p.first_approver,
                                      "approved_by": p.approved_by, "second_by": p.second_by, "attempts": p.attempts})
                return None
            why = f"{why} (gave up after {p.attempts} attempt(s))"
        return self._settle_approved(p, decided_by, "", executed if ok else _with_why(executed, why))

    def _record_awaiting_second(self, p: PendingApproval, first: str) -> None:
        """Transport hook: show that the first of two approvals has been given."""

    def _settle_approved(self, p: PendingApproval, decided_by: str, reason: str, executed: Any) -> Decision:
        """Settle an approval by what actually happened. ``approved`` only when the action ran; a skipped
        action (rate cap, ACP block, never-block guard), a connector failure, or a two-person rule still
        waiting for its second approver settles as ``failed`` — loudly — so nothing downstream (the
        containment loop, the console, the receipts) treats it as done."""
        ok, why = execution_outcome(executed)
        if ok:
            return self._settle(p, "approved", decided_by, reason, executed=executed)
        logger.error("[hitl:%s] %s -> %s on alert %s was approved by %s but NOT executed: %s", self.name,
                     p.action.action_type, p.action.target, p.alert_id, decided_by, why)
        return self._settle(p, "failed", decided_by, f"approved but not executed: {why}"[:500], executed=executed)

    def _settle(self, p: PendingApproval, status: str, decided_by: str, reason: str, executed: Any = None) -> Decision:
        self._pending.pop(p.approval_id, None)
        self._by_key.pop((p.alert_id, str(p.action.action_type), str(p.action.target)), None)
        self._timeout_noted.discard(p.approval_id)
        self._last_polled.pop(p.approval_id, None)
        self._journal_append({"op": "settled", "approval_id": p.approval_id, "status": status})
        try:
            self._record_settled(p, status, decided_by, reason)
        except Exception as e:  # noqa: BLE001 — a console marker is best-effort; the decision itself is already made
            logger.debug("[hitl:%s] settled marker not written for %s: %s", self.name, p.approval_id, str(e)[:120])
        d = Decision(approval_id=p.approval_id, alert_id=p.alert_id, action_type=str(p.action.action_type), target=str(p.action.target),
                     status=status, decided_by=decided_by, reason=reason, executed=executed)
        self.decisions.append(d)
        logger.info("[hitl:%s] %s %s on alert %s by %s%s", self.name, status, d.action_type, d.alert_id, decided_by or "-",
                    f" ({reason})" if reason else "")
        return d


#: names a transport used to stand in for "nobody we can name" — never one of two people (review round 7 A-8)
_PLACEHOLDER_DECIDERS = frozenset({"", "console", "file", "dashboard", "servicenow", "slack", "-", "unknown"})


def _anonymous(decided_by: Any) -> bool:
    return str(decided_by or "").strip().lower() in _PLACEHOLDER_DECIDERS


__all__ = ["BaseHITL", "Decision", "PendingApproval", "action_text", "card_args"]
