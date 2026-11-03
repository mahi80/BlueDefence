"""Tools for the Auth/IAM specialist.

Walking-skeleton implementations are mocks. Production swaps:
  - impossible_travel  → geoIP service + session DB
  - device_fingerprint → fingerprint store (BioCatch / Castle / in-house)
  - peer_baseline      → feature store keyed on user role
  - mfa_failure_pattern → IAM event stream (Okta / Entra)
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from ..shared.tool_guard import isolated


@dataclass
class ToolResult:
    name: str
    data: dict
    weight: str


# ---- Tool: impossible-travel detector ----------------------------------

# Lat/lon by mock geo code. Production: MaxMind / IP2Location.
_GEO_COORDS = {
    "IN-MH": (19.07, 72.87),  # Mumbai
    "IN-KA": (12.97, 77.59),  # Bengaluru
    "IN-DL": (28.61, 77.20),  # Delhi
    "US-CA": (37.77, -122.42),
    "US-NY": (40.71, -74.00),
    "DE-BE": (52.52, 13.40),
    "RU-MO": (55.75, 37.62),
    "CN-BJ": (39.90, 116.40),
    "BR-SP": (-23.55, -46.63),
}


def _haversine_km(a: tuple[float, float], b: tuple[float, float]) -> float:
    lat1, lon1 = math.radians(a[0]), math.radians(a[1])
    lat2, lon2 = math.radians(b[0]), math.radians(b[1])
    dlat, dlon = lat2 - lat1, lon2 - lon1
    h = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return 6371 * 2 * math.asin(math.sqrt(h))


def impossible_travel(prev_geo: str | None, curr_geo: str | None, minutes_since: float) -> ToolResult:
    # Guard against non-string geo (e.g. a red-team alert supplying a dict):
    # `dict in _GEO_COORDS` raises "unhashable type: 'dict'". Treat any
    # non-string / unknown location as insufficient_data rather than crash.
    if not (
        isinstance(prev_geo, str)
        and isinstance(curr_geo, str)
        and prev_geo in _GEO_COORDS
        and curr_geo in _GEO_COORDS
    ):
        return ToolResult(
            name="impossible_travel",
            data={"verdict": "insufficient_data"},
            weight="low",
        )
    distance_km = _haversine_km(_GEO_COORDS[prev_geo], _GEO_COORDS[curr_geo])
    # Conservative ceiling: commercial flight ~900 km/h
    required_speed_kmh = (distance_km / max(minutes_since, 1)) * 60.0
    impossible = required_speed_kmh > 900.0
    return ToolResult(
        name="impossible_travel",
        data={
            "prev": prev_geo,
            "curr": curr_geo,
            "distance_km": round(distance_km, 1),
            "minutes_since": minutes_since,
            "required_speed_kmh": round(required_speed_kmh, 1),
            "impossible": impossible,
        },
        weight="high" if impossible else "low",
    )


# ---- Tool: device fingerprint diff -------------------------------------

# Stand-in: known device fingerprints per user.
_KNOWN_DEVICES = {
    "u_42891": [
        {"id": "dev_a1", "ua": "Mozilla/5.0 (Windows) Chrome/130", "screen": "1920x1080", "tz": "Asia/Kolkata"},
        {"id": "dev_a2", "ua": "Mozilla/5.0 (iPhone) Safari/17", "screen": "390x844", "tz": "Asia/Kolkata"},
    ],
    "u_77104": [
        {"id": "dev_b1", "ua": "Mozilla/5.0 (Macintosh) Safari/17", "screen": "2560x1440", "tz": "America/Los_Angeles"},
    ],
}


def device_fingerprint_diff(user_id: str | None, current_fp: dict | None) -> ToolResult:
    # Guard types: user_id is used as a dict key, current_fp is .get()'d.
    if not (isinstance(user_id, str) and isinstance(current_fp, dict)):
        return ToolResult(name="device_fingerprint", data={"known": False, "reason": "missing"}, weight="low")
    known = _KNOWN_DEVICES.get(user_id, [])
    matches = [
        d for d in known
        if d.get("ua") == current_fp.get("ua") and d.get("screen") == current_fp.get("screen")
    ]
    if matches:
        return ToolResult(
            name="device_fingerprint",
            data={"known": True, "matched": matches[0]["id"]},
            weight="low",
        )
    # Unknown device: degree of dissimilarity
    diffs = []
    for d in known:
        diffs.append(sum(1 for k in ("ua", "screen", "tz") if d.get(k) != current_fp.get(k)))
    min_diff = min(diffs) if diffs else 3
    return ToolResult(
        name="device_fingerprint",
        data={"known": False, "min_attribute_diffs": min_diff, "current": current_fp},
        weight="medium" if min_diff >= 2 else "low",
    )


# ---- Tool: peer baseline ----------------------------------------------

_PEER_BASELINES = {
    "retail_customer": {
        "typical_endpoints": ["/api/balance", "/api/transfer", "/api/profile", "/api/statements"],
        "max_failed_logins_24h_99p": 5,
        "session_count_24h_99p": 12,
    },
    "wealth_advisor": {
        "typical_endpoints": ["/api/portfolio", "/api/orders", "/api/clients"],
        "max_failed_logins_24h_99p": 3,
        "session_count_24h_99p": 30,
    },
}


def peer_baseline(role: str | None, observed: dict) -> ToolResult:
    # Guard: role is used as a dict key (must be a hashable str); observed is .get()'d.
    if not isinstance(role, str) or role not in _PEER_BASELINES:
        return ToolResult(name="peer_baseline", data={"role": role, "matched": False}, weight="low")
    if not isinstance(observed, dict):
        observed = {}
    bl = _PEER_BASELINES[role]
    deviations = []
    if observed.get("failed_logins_24h", 0) > bl["max_failed_logins_24h_99p"]:
        deviations.append("failed_logins_above_99p")
    if observed.get("session_count_24h", 0) > bl["session_count_24h_99p"]:
        deviations.append("sessions_above_99p")
    endpoint = observed.get("endpoint", "")
    if endpoint and endpoint not in bl["typical_endpoints"]:
        deviations.append("atypical_endpoint")
    return ToolResult(
        name="peer_baseline",
        data={"role": role, "deviations": deviations, "baseline": bl},
        weight="high" if len(deviations) >= 2 else "medium" if deviations else "low",
    )


# ---- Tool: MFA failure pattern ----------------------------------------

def mfa_failure_pattern(failure_history: list[float]) -> ToolResult:
    """failure_history: list of timestamps (seconds) of recent MFA failures."""
    # Guard: an LLM-generated alert may supply an int, None, or a list with
    # non-numbers here — coerce to a clean list of numeric timestamps so len()
    # and the sort/subtraction below can't crash.
    if not isinstance(failure_history, (list, tuple)):
        failure_history = []
    else:
        failure_history = [x for x in failure_history if isinstance(x, (int, float))]
    n = len(failure_history)
    if n == 0:
        return ToolResult(name="mfa_failure_pattern", data={"failures": 0}, weight="low")
    burst = False
    if n >= 5:
        # 5+ failures within 60s of each other = burst (likely automated)
        sorted_h = sorted(failure_history)
        burst = (sorted_h[-1] - sorted_h[-5]) <= 60.0
    return ToolResult(
        name="mfa_failure_pattern",
        data={"failures": n, "burst_pattern": burst},
        weight="high" if burst else "medium" if n >= 3 else "low",
    )


def run_all_tools(alert: dict) -> list[ToolResult]:
    # Lazy import — biometrics module re-exports the same ToolResult
    # shape so the auth agent's _summarize() picks it up uniformly.
    from .biometrics import privileged_user_baseline_check
    results = [
        isolated(lambda: impossible_travel(
            alert.get("prev_geo"),
            alert.get("curr_geo"),
            alert.get("minutes_since_prev_login", 60.0),
        ), "impossible_travel", ToolResult),
        isolated(lambda: device_fingerprint_diff(alert.get("user_id"), alert.get("device_fingerprint")), "device_fingerprint_diff", ToolResult),
        isolated(lambda: peer_baseline(alert.get("user_role"), alert.get("observed", {})), "peer_baseline", ToolResult),
        isolated(lambda: mfa_failure_pattern(alert.get("mfa_failures", [])), "mfa_failure_pattern", ToolResult),
        isolated(lambda: privileged_user_baseline_check(
            alert.get("user_id"),
            alert.get("user_role"),
            alert.get("observed", {}),
        ), "privileged_user_baseline_check", ToolResult),
    ]
    # Behavioral biometrics — only run if telemetry is present in the alert
    if isinstance(alert.get("behavioral_telemetry"), dict):
        results.append(isolated(lambda: _biometrics(alert), "behavioral_biometrics", ToolResult))
    return results


def _biometrics(alert: dict) -> ToolResult:
    """Behavioural biometrics — only when telemetry is present in the alert."""
    # Production: route through BioCatch (or vendor) when configured;
    # offline / dev: same call shape via MockBioCatchClient that
    # internally calls behavioral_baseline_diff.
    from .biocatch_client import get_client as _bc_client
    client = _bc_client()
    telemetry = dict(alert["behavioral_telemetry"])
    # The mock needs user_id to look up the local baseline; the real
    # client carries this through session_id mapping on its side.
    telemetry.setdefault("user_id", alert.get("user_id"))
    score = client.score(
        session_id=alert.get("session_id") or alert.get("id", "?"),
        telemetry=telemetry,
    )
    weight = ("high" if score.risk_score >= 0.6 else
              "medium" if score.risk_score >= 0.3 else "low")
    return ToolResult(
        name="behavioral_biometrics",
        data={
            "vendor": client.name,
            "session_id": score.session_id,
            "risk_score": score.risk_score,
            "drift_score": score.risk_score,    # alias for legacy auth-agent summary
            "drift_severe": score.risk_score >= 0.6,
            "is_bot_likelihood": score.is_bot_likelihood,
            "anomalies": score.behavioral_anomalies,
            "confidence": score.confidence,
        },
        weight=weight,
    )
