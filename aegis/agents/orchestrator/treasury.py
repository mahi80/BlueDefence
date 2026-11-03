"""Outflow guard fast path: high-value transfers to new beneficiaries, and the burst that is a drain.

The fraud toolkit is built for customer fraud — mule lists, structuring just under thresholds,
velocity against a customer's own baseline. A compromised **payment signer** looks nothing like
that: a treasury or service account with no customer baseline sends very large transfers to
beneficiaries nobody has paid before, many in a few minutes (the Oct 2026 Binance drain: ~USD 6.3B
in ~20 minutes, every transfer signed by the exchange's own signer). Each tool then reports
"nothing known", and nothing known used to read as "normal". This path fails **closed**:

    a transfer of at least AEGIS_HIGH_VALUE_INR (default INR 1 crore) to a beneficiary not known
    to be existing                                               -> this path
      from a treasury / nostro / settlement / service account     suspicious 0.85, hold it (human)
      from any other account                                      suspicious 0.75, hold it (human)
    AEGIS_OUTFLOW_BURST_N (3) such transfers from one sender within
    AEGIS_OUTFLOW_WINDOW_S (1800 s)                                malicious 0.95, the drain pattern:
                                                                  hold ALL outbound from the sender

The burst ``hold`` on ``outbound:<sender>`` is the one the outflow circuit breaker may run without
waiting (``aegis/agents/response/breaker.py``, ``AEGIS_OUTFLOW_BREAKER``, shadow by default); every
other hold waits for a human, as ``hold`` always has. A transfer to a known beneficiary, or under the
threshold, is not this path's — the transaction specialist keeps it.

Treasury senders: ``AEGIS_TREASURY_ACCOUNTS`` (comma-separated ids or prefixes) plus any account id
containing TREASURY, NOSTRO, VOSTRO or SETTLEMENT; a sending user id starting ``svc_`` is a service
identity and counts the same.
"""

from __future__ import annotations

import os
import threading
import time
from collections import deque
from datetime import datetime
from typing import Any

from ..shared.bounded import BoundedDict
from ..shared.evidence_chain import (
    EvidenceChain,
    EvidenceItem,
    ReasoningStep,
    RecommendedAction,
)

_TREASURY_MARKERS = ("TREASURY", "NOSTRO", "VOSTRO", "SETTLEMENT")
_SENDER_KEYS = ("sender_account", "debit_account", "from_account", "source_account")


def _num(v: Any) -> float | None:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if f == f and f not in (float("inf"), float("-inf")) else None


def high_value_inr() -> float:
    return _num(os.environ.get("AEGIS_HIGH_VALUE_INR")) or 1e7


def _burst_n() -> int:
    try:
        return max(2, int(os.environ.get("AEGIS_OUTFLOW_BURST_N", "3")))
    except ValueError:
        return 3


def _window_s() -> float:
    return _num(os.environ.get("AEGIS_OUTFLOW_WINDOW_S")) or 1800.0


def _treasury_list() -> tuple[str, ...]:
    return tuple(x.strip().upper() for x in os.environ.get("AEGIS_TREASURY_ACCOUNTS", "").split(",") if x.strip())


def _sender(alert: dict) -> str:
    for k in _SENDER_KEYS:
        v = alert.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return str(alert.get("user_id") or alert.get("user") or "unknown")


def is_treasury_sender(alert: dict) -> bool:
    acct = _sender(alert).upper()
    if any(m in acct for m in _TREASURY_MARKERS) or any(acct.startswith(p) for p in _treasury_list()):
        return True
    return str(alert.get("user_id") or "").lower().startswith("svc_")


def _beneficiary_known(alert: dict) -> bool | None:
    """True / False from the fraud toolkit's beneficiary register; None if it could not say."""
    try:
        from ..transaction import tools
        for r in tools.run_all_tools(alert):
            if r.name == "beneficiary_risk":
                known = r.data.get("known")
                if known is not None:
                    return bool(known)
                # the register only sets known=False for an account it has never seen; a registered payee comes
                # back with its profile (first_seen_days …) and no "known" key — it used to read as "unknown → new"
                if "first_seen_days" in r.data:
                    return True
                return None
    except Exception:  # noqa: BLE001 — a toolkit failure must not open the gate
        return None
    return None


def is_new_beneficiary(alert: dict) -> bool:
    """Fail closed: an explicit ``new_beneficiary`` flag, or a beneficiary the register does not know."""
    if alert.get("new_beneficiary") is True:
        return True
    if alert.get("new_beneficiary") is False:
        return False
    return _beneficiary_known(alert) is not True


def _ts(alert: dict) -> float:
    for k in ("timestamp", "event_time", "@timestamp"):
        v = alert.get(k)
        if isinstance(v, str) and v:
            try:
                return datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
            except ValueError:
                continue
    return time.time()


class _OutflowBook:
    """Per-sender ledger of recent high-value transfers to new beneficiaries (in-process)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # senders with a high-value transfer in the window; the least recently active is evicted past the cap,
        # and a sender whose window empties is dropped (the defaultdict used to keep every sender ever seen)
        self._by_sender: BoundedDict = BoundedDict(int(os.environ.get("AEGIS_OUTFLOW_MAX_SENDERS", "100000")))

    def add(self, sender: str, ts: float, amount: float, txn_id: str, window: float) -> tuple[int, float]:
        with self._lock:
            q = self._by_sender.get(sender)
            if q is None:
                q = self._by_sender[sender] = deque(maxlen=1000)
            else:
                self._by_sender.move_to_end(sender)
            if not any(t == txn_id for _, _, t in q):
                q.append((ts, amount, txn_id))
            cutoff = max(ts, max((x[0] for x in q), default=ts)) - window
            while q and q[0][0] < cutoff:
                q.popleft()
            n, total = len(q), sum(a for _, a, _ in q)
            if not q:
                self._by_sender.pop(sender, None)
            return n, total

    def reset(self) -> None:
        with self._lock:
            self._by_sender.clear()


BOOK = _OutflowBook()


def is_treasury_outflow(alert: dict) -> bool:
    if not isinstance(alert, dict):
        return False
    amount = _num(alert.get("amount_inr"))
    if amount is None or amount < high_value_inr():
        return False
    return is_new_beneficiary(alert)


def _crore(inr: float) -> str:
    return f"INR {inr / 1e7:,.1f} crore"


def treasury_outflow_chain(alert: dict) -> EvidenceChain:
    amount = _num(alert.get("amount_inr")) or 0.0
    sender, txn = _sender(alert), str(alert.get("id", "unknown"))
    treasury = is_treasury_sender(alert)
    count, total = BOOK.add(sender, _ts(alert), amount, txn, _window_s())
    burst = count >= _burst_n()
    s_geo, b_geo = str(alert.get("sender_geo") or ""), str(alert.get("beneficiary_geo") or "")
    offshore = bool(s_geo and b_geo and s_geo != b_geo)
    window_min = _window_s() / 60

    if burst:
        verdict, conf = "malicious", 0.95
        why = (f"{count} high-value transfers to new beneficiaries from {sender} within {window_min:.0f} min "
               f"({_crore(total)}) — the shape of a drain by a compromised signer")
    elif treasury:
        verdict, conf = "suspicious", 0.85
        why = f"{_crore(amount)} from treasury / service account {sender} to a new beneficiary"
    else:
        verdict, conf = "suspicious", 0.75
        why = f"{_crore(amount)} to a new beneficiary"

    chain = EvidenceChain(alert_id=txn, investigated_by="treasury", verdict=verdict, confidence=conf)
    chain.evidence.append(EvidenceItem(
        source=str(alert.get("source") or "txn_stream"), weight="high",
        signal=f"{_crore(amount)} via {alert.get('rail', '?')} from {sender} to new beneficiary "
               f"{alert.get('beneficiary_account', '?')}" + (f" ({s_geo} → {b_geo})" if offshore else ""),
        raw_data={"amount_inr": amount, "sender": sender, "beneficiary": alert.get("beneficiary_account"),
                  "rail": alert.get("rail"), "treasury_sender": treasury, "offshore": offshore}))
    chain.evidence.append(EvidenceItem(
        source="outflow_ledger", weight="high" if burst else "medium",
        signal=f"{count} high-value new-beneficiary transfer(s) from {sender} in the last {window_min:.0f} min, {_crore(total)}"))
    if treasury:
        chain.evidence.append(EvidenceItem(source="sender_profile", weight="medium",
                                           signal=f"{sender} is a treasury / service account: no customer baseline, "
                                                  "so velocity and rail checks cannot speak for it"))
    chain.reasoning.append(ReasoningStep(step=1, action="Outflow guard fast path (no LLM verdict)", observation=why,
                                         conclusion=verdict))

    if burst:
        chain.recommended_actions.append(RecommendedAction(
            action_type="hold", target=f"outbound:{sender}", requires_hitl=False, confidence=conf,
            reasoning=(f"Hold ALL outbound payments from {sender}: {why}. Reversible — release once the signer "
                       "is verified clean. Runs without waiting only when the outflow circuit breaker is live.")))
        chain.recommended_actions.append(RecommendedAction(
            action_type="escalate_to_fraud_team", target=sender, requires_hitl=True, confidence=conf,
            reasoning="Recall the transfers already sent (SWIFT gpi recall / beneficiary-bank freeze) — minutes matter"))
        chain.recommended_actions.append(RecommendedAction(
            action_type="escalate", target=txn, requires_hitl=True, confidence=conf,
            reasoning=("Treat the payment signer as compromised: check its audit log for policy or allowlist changes "
                       "and who had interactive access to it in the last 48 h")))
    else:
        chain.recommended_actions.append(RecommendedAction(
            action_type="hold", target=txn, requires_hitl=True, confidence=conf,
            reasoning=f"Hold this transfer pending a call-back to a known contact: {why}"))
        chain.recommended_actions.append(RecommendedAction(
            action_type="escalate_to_fraud_team", target=sender, requires_hitl=True, confidence=conf,
            reasoning="Verify the new beneficiary out of band before release"))
    chain.metadata["treasury"] = {"sender": sender, "treasury_sender": treasury, "burst": burst, "count": count,
                                  "window_s": _window_s(), "total_inr": total, "offshore": offshore}
    if burst:
        chain.metadata["outflow_breaker"] = True
    return chain.finalize()


__all__ = ["BOOK", "high_value_inr", "is_new_beneficiary", "is_treasury_outflow", "is_treasury_sender",
           "treasury_outflow_chain"]
