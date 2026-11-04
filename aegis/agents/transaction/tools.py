"""Tools for the Transaction/Fraud specialist.

Indian bank context: UPI (real-time, high-volume, mostly retail), NEFT
(batched, low-cost), RTGS (gross settlement, high-value), IMPS (24x7
P2P), SWIFT (cross-border). Customers usually have a stable rail
preference; rail-switching can be a control-evasion signal.

Production swaps (per the project plan):
  - mule_pattern_check -> graph DB query (Neo4j / Tigergraph) over the
    account-relationship graph
  - beneficiary_risk -> internal risk service + sanctions / PEP screen
  - velocity_check -> feature store (Redis aggregates by user / device)
  - aml_structuring_check -> AML platform integration (Actimize, Mantas)
"""
from __future__ import annotations

import re
import statistics
from dataclasses import dataclass

from ..shared.tool_guard import isolated


@dataclass
class ToolResult:
    name: str
    data: dict
    weight: str


# ---- Mule pattern --------------------------------------------------

# Stand-in account graph: a mule pattern is rapid in-then-out with
# no other activity, and the fan-in/fan-out edges go to many distinct
# parties (vs a normal customer's narrow set of regular counterparties).
_MOCK_ACCOUNT_GRAPH = {
    "ACC-MULE-001": {
        "incoming_24h_count": 12,           # 12 different senders in 24h
        "outgoing_24h_count": 11,           # near-immediate forwarding
        "in_out_lag_seconds_p50": 180,      # ~3 min average pass-through
        "balance_idle_p50": 50,             # rarely holds money
    },
    "ACC-NORMAL-001": {
        "incoming_24h_count": 1,
        "outgoing_24h_count": 2,
        "in_out_lag_seconds_p50": 86400,    # spends the next day, not minutes
        "balance_idle_p50": 25000,
    },
}


def mule_pattern_check(beneficiary_account: str | None) -> ToolResult:
    if not beneficiary_account:
        return ToolResult(name="mule_pattern", data={
            "verdict": "insufficient_data",
        }, weight="low")
    profile = _MOCK_ACCOUNT_GRAPH.get(beneficiary_account)
    if profile is None:
        return ToolResult(name="mule_pattern", data={
            "account": beneficiary_account,
            "in_graph": False,
        }, weight="low")
    # Mule indicators: high fan-in/fan-out, fast pass-through, low idle balance
    is_mule_shape = (
        profile["incoming_24h_count"] >= 5
        and profile["outgoing_24h_count"] >= 5
        and profile["in_out_lag_seconds_p50"] <= 600
        and profile["balance_idle_p50"] <= 1000
    )
    return ToolResult(name="mule_pattern", data={
        "account": beneficiary_account,
        "profile": profile,
        "is_mule_shape": is_mule_shape,
    }, weight="high" if is_mule_shape else "low")


# ---- Beneficiary risk ----------------------------------------------

# Stand-in beneficiary risk DB.
_BENEFICIARY_RISK = {
    # PEP / sanctioned / known high-risk geography
    "ACC-MULE-001":   {"sanctioned": False, "pep": False, "geo": "IN", "first_seen_days": 1},
    "ACC-FOREIGN-99": {"sanctioned": False, "pep": False, "geo": "RU", "first_seen_days": 0},
    "ACC-NORMAL-001": {"sanctioned": False, "pep": False, "geo": "IN", "first_seen_days": 1825},
}


def beneficiary_risk(beneficiary_account: str | None,
                     sender_geo: str | None = None) -> ToolResult:
    if not beneficiary_account:
        return ToolResult(name="beneficiary_risk", data={
            "verdict": "insufficient_data",
        }, weight="low")
    info = _BENEFICIARY_RISK.get(beneficiary_account)
    if info is None:
        return ToolResult(name="beneficiary_risk", data={
            "account": beneficiary_account,
            "known": False,
            "verdict": "unknown_beneficiary",
        }, weight="medium")
    # Risk signals
    high_risk_geos = {"RU", "KP", "IR", "SY"}
    is_high_risk_geo = info["geo"] in high_risk_geos
    is_new_beneficiary = info["first_seen_days"] <= 7
    cross_border = sender_geo and info["geo"] != sender_geo
    weight = "low"
    if info["sanctioned"]:
        weight = "high"
    elif is_high_risk_geo:
        weight = "high"
    elif info["pep"] and (is_new_beneficiary or cross_border):
        weight = "medium"
    elif is_new_beneficiary and cross_border:
        weight = "medium"
    return ToolResult(name="beneficiary_risk", data={
        "account": beneficiary_account,
        **info,
        "is_high_risk_geo": is_high_risk_geo,
        "is_new_beneficiary": is_new_beneficiary,
        "cross_border": bool(cross_border),
    }, weight=weight)


# ---- Velocity ------------------------------------------------------

# Mock baselines: customer's typical txn count + amount per 24h.
_VELOCITY_BASELINES = {
    "u_42891":  {"txn_count_24h_p99": 4,  "txn_total_24h_p99_inr": 50000},
    "u_77104":  {"txn_count_24h_p99": 12, "txn_total_24h_p99_inr": 500000},
}


def velocity_check(user_id: str | None,
                   recent_24h_count: int | None,
                   recent_24h_total_inr: float | None) -> ToolResult:
    if not user_id or recent_24h_count is None:
        return ToolResult(name="velocity", data={
            "verdict": "insufficient_data",
        }, weight="low")
    baseline = _VELOCITY_BASELINES.get(user_id)
    if baseline is None:
        return ToolResult(name="velocity", data={
            "user_id": user_id, "baseline_known": False,
        }, weight="low")
    # a count / total sent as text ("12", "9,50,000", "₹9,50,000") used to raise or read as 0 (round 7 D-14)
    # an amount that was sent but cannot be read is unknown, not 0: it never lowers the risk (round 8 D8-13)
    cnt, tot = _amount(recent_24h_count), _amount(recent_24h_total_inr)
    unknown = (cnt is None) or (tot is None and recent_24h_total_inr not in (None, ""))
    count_ratio = (cnt or 0.0) / max(baseline["txn_count_24h_p99"], 1)
    amt_ratio = (tot or 0.0) / max(baseline["txn_total_24h_p99_inr"], 1)
    over_count = count_ratio > 1.0
    over_amount = amt_ratio > 1.0
    # 2x p99 is suspicious; 5x is high-confidence anomaly
    weight = "low"
    if count_ratio >= 5.0 or amt_ratio >= 5.0:
        weight = "high"
    elif over_count or over_amount or unknown:
        weight = "medium"
    return ToolResult(name="velocity", data={
        "user_id": user_id,
        "count_ratio_p99": round(count_ratio, 2),
        "amount_ratio_p99": round(amt_ratio, 2),
        "over_p99": over_count or over_amount,
        "amount_unknown": unknown,
    }, weight=weight)


# ---- Payment rail anomaly ------------------------------------------

# Customer's typical rail mix from history. Switching rails for a
# large transfer is a known evasion technique (e.g., RTGS to dodge
# UPI's per-txn limits, or NEFT for delayed settlement).
_RAIL_BASELINES = {
    "u_42891": {"primary_rail": "UPI",  "rails_used": {"UPI", "NEFT"}},
    "u_77104": {"primary_rail": "NEFT", "rails_used": {"NEFT", "RTGS"}},
}


def payment_rail_anomaly(user_id: str | None, rail: str | None,
                         amount_inr: float | None) -> ToolResult:
    if not user_id or not rail:
        return ToolResult(name="payment_rail", data={
            "verdict": "insufficient_data",
        }, weight="low")
    baseline = _RAIL_BASELINES.get(user_id)
    if baseline is None:
        return ToolResult(name="payment_rail", data={
            "user_id": user_id, "baseline_known": False,
        }, weight="low")
    # `upi` and `UPI` are one rail (it was "novel" by case alone; review round 3 S3-23)
    rail = str(rail).strip().upper()
    novel_rail = rail not in {str(r).upper() for r in baseline["rails_used"]}
    amount = _amount(amount_inr)                      # "₹1,50,000" is 150000, not 0 (S3-22, round 7 D-14)
    # an amount that cannot be read is unknown: it is judged as if large, never as 0 (round 8 D8-13)
    amount_unknown = amount is None and amount_inr not in (None, "")
    high_value = amount_unknown or (amount or 0.0) >= 100000  # 1L INR threshold for "large"
    weight = "high" if (novel_rail and high_value) else "medium" if novel_rail else "low"
    return ToolResult(name="payment_rail", data={
        "user_id": user_id, "rail": rail,
        "primary_rail": baseline["primary_rail"],
        "novel_rail": novel_rail,
        "high_value": high_value,
        "amount_unknown": amount_unknown,
    }, weight=weight)


# ---- AML structuring (smurfing) check ------------------------------

# Indian threshold context: Cash Transaction Reports trigger at
# Rs 10L (1 million); structuring is splitting just under the
# threshold to evade (e.g., 9.5L + 9.5L + 9.5L on consecutive days).
def _flag(v: object) -> bool:
    """A telemetry flag: ``"true"`` is True and ``"false"`` is False (bool("false") is True)."""
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "y", "on")
    return bool(v)


_CURRENCY_RX = re.compile(r"^(?:₹|₨|inr|rs\.?|rupees?)\s*|\s*(?:₹|₨|inr|rs\.?|rupees?)$")
_MULTIPLIER = {"lakh": 1e5, "lakhs": 1e5, "lac": 1e5, "lacs": 1e5, "l": 1e5,
               "crore": 1e7, "crores": 1e7, "cr": 1e7, "k": 1e3, "thousand": 1e3}
_AMOUNT_RX = re.compile(r"^([+-]?(?:[0-9][0-9,_ ]*(?:\.[0-9]*)?|\.[0-9]+)(?:e[+-]?[0-9]+)?)\s*([a-z]+)?$")


def _amount(v: object) -> float | None:
    """An INR amount as banks and statements write it, or ``None`` when it cannot be read. ``9,50,000``,
    ``₹9,50,000/-``, ``Rs.9,50,000.00 CR``, ``INR 9,50,000.00 Dr``, ``₨9,50,000``, ``9.5 lakh``, ``9.5L``,
    ``1 Cr`` (round 7 D-14, round 8 D8-13). ``Dr`` / ``Cr`` after a statement-formatted figure (paise or digit
    grouping) is the debit / credit marker, otherwise ``Cr`` is crore."""
    import math
    if isinstance(v, bool):
        return None
    try:
        if isinstance(v, str):
            t = " ".join(v.strip().lower().split())[:64]
            if t.endswith("/-"):
                t = t[:-2].rstrip()
            for _ in range(2):                                      # currency before and / or after the figure
                t = _CURRENCY_RX.sub("", t).strip()
            if t.endswith("/-"):
                t = t[:-2].rstrip()
            m = _AMOUNT_RX.match(t)
            if not m:
                return None
            num, word = m.group(1), m.group(2) or ""
            statement_fmt = "," in num or re.search(r"\.\d{2}$", num.strip()) is not None
            mult = 1.0
            if word in ("dr", "cr") and (statement_fmt or word == "dr"):
                mult = 1.0                                          # debit / credit marker
            elif word in _MULTIPLIER:
                mult = _MULTIPLIER[word]
            elif word:
                return None
            f = float(re.sub(r"[,\s_]", "", num)) * mult
        else:
            f = float(v)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError):
        return None
    return f if math.isfinite(f) else None


def aml_structuring_check(recent_amounts_inr: list[float] | None,
                          *, threshold_inr: float = 1_000_000.0) -> ToolResult:
    if not recent_amounts_inr or len(recent_amounts_inr) < 3:
        return ToolResult(name="aml_structuring", data={
            "verdict": "insufficient_data",
        }, weight="low")
    parsed = [_amount(x) for x in recent_amounts_inr]
    amounts = [a for a in parsed if a is not None]   # "950000" counts (S4-15)
    n_unknown = len(parsed) - len(amounts)
    just_under_threshold = [
        a for a in amounts
        if 0.85 * threshold_inr <= a < threshold_inr
    ]
    structuring_pattern = (
        len(just_under_threshold) >= 3
        and statistics.stdev(just_under_threshold) / statistics.mean(just_under_threshold) < 0.10
    )
    # amounts that could not be read could complete the pattern: unknown, never "clean" (round 8 D8-13)
    weight = "high" if structuring_pattern else (
        "medium" if n_unknown and len(just_under_threshold) + n_unknown >= 3 else "low")
    return ToolResult(name="aml_structuring", data={
        "n_recent": len(amounts),
        "n_just_under": len(just_under_threshold),
        "n_unparseable": n_unknown,
        "threshold_inr": threshold_inr,
        "structuring_pattern": structuring_pattern,
    }, weight=weight)


# ---- SWIFT-specific check (LAU verification, RMA changes) ----------

# SWIFT's critical event classes that aren't visible to a generic
# fraud check: LAU (Local Authentication) MAC verification failures,
# RMA (Relationship Management Application) authorization changes,
# Alliance Access user role grants, BIC-blacklist hits.

_SWIFT_CRITICAL_EVENTS = {
    "lau:mac_verification_fail",
    "rma:authorization_added",
    "rma:authorization_removed",
    "alliance:user_role_grant",
    "alliance:user_login_failed_burst",
    "fin:bic_blacklist_hit",
    "fin:mt103_amount_above_internal_threshold",
}


def swift_specific_check(alert: dict) -> ToolResult:
    """Reads SWIFT-specific event flags. Most banks log these via
    SWIFT Alliance Access -> SIEM; the orchestrator pre-routes by
    rail=SWIFT into here.
    """
    rail = (alert.get("rail") or "").upper()
    if rail != "SWIFT":
        return ToolResult(name="swift_specific", data={"rail": rail, "tracked": False}, weight="low")

    event_type = alert.get("swift_event_type") or ""
    bic = alert.get("beneficiary_bic") or ""
    mac_fail = _flag(alert.get("lau_mac_verification_failed", False))
    rma_change = _flag(alert.get("rma_change", False))
    bic_blacklisted = _flag(alert.get("bic_blacklisted", False))

    severity = sum([
        event_type in _SWIFT_CRITICAL_EVENTS,
        mac_fail,
        rma_change,
        bic_blacklisted,
    ])

    if mac_fail or bic_blacklisted:
        weight = "high"
    elif rma_change:
        weight = "high"
    elif severity >= 1:
        weight = "medium"
    else:
        weight = "low"

    return ToolResult(name="swift_specific", data={
        "rail": "SWIFT",
        "event_type": event_type,
        "beneficiary_bic": bic,
        "lau_mac_verification_failed": mac_fail,
        "rma_change": rma_change,
        "bic_blacklisted": bic_blacklisted,
        "severity": severity,
    }, weight=weight)


def run_all_tools(alert: dict) -> list[ToolResult]:
    return [
        isolated(lambda: mule_pattern_check(alert.get("beneficiary_account")), "mule_pattern_check", ToolResult),
        isolated(lambda: beneficiary_risk(
            alert.get("beneficiary_account"),
            alert.get("sender_geo"),
        ), "beneficiary_risk", ToolResult),
        isolated(lambda: velocity_check(
            alert.get("user_id"),
            alert.get("recent_24h_count"),
            alert.get("recent_24h_total_inr"),
        ), "velocity_check", ToolResult),
        isolated(lambda: payment_rail_anomaly(
            alert.get("user_id"),
            alert.get("rail"),
            alert.get("amount_inr"),
        ), "payment_rail_anomaly", ToolResult),
        isolated(lambda: aml_structuring_check(alert.get("recent_amounts_inr")), "aml_structuring_check", ToolResult),
        isolated(lambda: swift_specific_check(alert), "swift_specific_check", ToolResult),
    ]
