"""Tools for the Mobile-app specialist."""
from __future__ import annotations

from dataclasses import dataclass

from ..shared.tool_guard import isolated


@dataclass
class ToolResult:
    name: str
    data: dict
    weight: str


# ---- Jailbreak / root detection -------------------------------------

def _flag(v: object) -> bool:
    """A telemetry flag: bool("false") is True, so a string "false" jailbreak flag scored high (round 3 S3-23)."""
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "y", "on")
    return bool(v)


def _number(v: object) -> float | None:
    import math
    try:
        f = float(v)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) else None


def jailbreak_root_check(device_telemetry: dict | None) -> ToolResult:
    if not device_telemetry:
        return ToolResult(name="jailbreak_root", data={"verdict": "no_data"}, weight="low")
    is_jailbroken = _flag(device_telemetry.get("is_jailbroken"))
    is_rooted = _flag(device_telemetry.get("is_rooted"))
    has_frida = _flag(device_telemetry.get("frida_detected"))
    has_xposed = _flag(device_telemetry.get("xposed_detected"))
    weight = "high" if (is_jailbroken or is_rooted or has_frida or has_xposed) else "low"
    return ToolResult(name="jailbreak_root", data={
        "is_jailbroken": is_jailbroken,
        "is_rooted": is_rooted,
        "frida_detected": has_frida,
        "xposed_detected": has_xposed,
        "tampered": is_jailbroken or is_rooted or has_frida or has_xposed,
    }, weight=weight)


# ---- SDK integrity check --------------------------------------------

def sdk_integrity_check(sdk_telemetry: dict | None) -> ToolResult:
    if not sdk_telemetry:
        return ToolResult(name="sdk_integrity", data={"verdict": "no_data"}, weight="low")
    expected_signature = "ABCD1234EXPECTED"   # mock — production: signed-build registry
    observed = sdk_telemetry.get("sdk_signature", "")
    pinning_failed = _flag(sdk_telemetry.get("ssl_pinning_failed"))
    repackaged = observed and observed != expected_signature
    weight = "high" if (repackaged or pinning_failed) else "low"
    return ToolResult(name="sdk_integrity", data={
        "expected_signature": expected_signature,
        "observed_signature": observed,
        "repackaged": repackaged,
        "ssl_pinning_failed": pinning_failed,
    }, weight=weight)


# ---- SIM-swap check -------------------------------------------------

def sim_swap_check(mno_signals: dict | None,
                   user_id: str | None) -> ToolResult:
    if not mno_signals:
        return ToolResult(name="sim_swap", data={"verdict": "no_data"}, weight="low")
    last_swap_hours_ago = mno_signals.get("last_sim_swap_hours_ago")
    swap_recent = isinstance(last_swap_hours_ago, (int, float)) and last_swap_hours_ago < 24
    porting = _flag(mno_signals.get("number_porting_in_progress"))
    weight = "high" if (swap_recent or porting) else "low"
    return ToolResult(name="sim_swap", data={
        "user_id": user_id,
        "last_sim_swap_hours_ago": last_swap_hours_ago,
        "swap_within_24h": swap_recent,
        "number_porting_in_progress": porting,
    }, weight=weight)


# ---- Mobile session anomaly -----------------------------------------

def mobile_session_anomaly_check(session: dict | None) -> ToolResult:
    if not session:
        return ToolResult(name="mobile_session", data={"verdict": "no_data"}, weight="low")
    # string flags and numbers ("true", "950") are telemetry too: sum() over a "true" raised, and the tool failure
    # scored the overlay-fraud session low (round 4 S4-15)
    velocity_kmh = _number(session.get("device_velocity_kmh")) or 0.0
    app_version_age_days = _number(session.get("app_version_age_days"))
    os_eol = _flag(session.get("os_eol", False))
    side_loaded = _flag(session.get("side_loaded", False))
    overlay_detected = _flag(session.get("screen_overlay_detected", False))
    impossible_velocity = velocity_kmh > 900
    stale = app_version_age_days is not None and app_version_age_days > 365
    severity = sum([
        impossible_velocity,
        os_eol,
        side_loaded,
        overlay_detected,
    ])
    if overlay_detected:
        weight = "high"
    elif severity >= 2:
        weight = "high"
    elif severity == 1 or stale:
        weight = "medium"
    else:
        weight = "low"
    return ToolResult(name="mobile_session", data={
        "device_velocity_kmh": velocity_kmh,
        "impossible_velocity": impossible_velocity,
        "app_version_age_days": app_version_age_days,
        "stale_version": stale,
        "os_eol": os_eol,
        "side_loaded": side_loaded,
        "screen_overlay_detected": overlay_detected,
    }, weight=weight)


def run_all_tools(alert: dict) -> list[ToolResult]:
    return [
        isolated(lambda: jailbreak_root_check(alert.get("device_telemetry")), "jailbreak_root_check", ToolResult),
        isolated(lambda: sdk_integrity_check(alert.get("sdk_telemetry")), "sdk_integrity_check", ToolResult),
        isolated(lambda: sim_swap_check(alert.get("mno_signals"), alert.get("user_id")), "sim_swap_check", ToolResult),
        isolated(lambda: mobile_session_anomaly_check(alert.get("session")), "mobile_session_anomaly_check", ToolResult),
    ]
