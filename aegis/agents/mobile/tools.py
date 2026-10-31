"""Tools for the Mobile-app specialist."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ToolResult:
    name: str
    data: dict
    weight: str


# ---- Jailbreak / root detection -------------------------------------

def jailbreak_root_check(device_telemetry: dict | None) -> ToolResult:
    if not device_telemetry:
        return ToolResult(name="jailbreak_root", data={"verdict": "no_data"}, weight="low")
    is_jailbroken = bool(device_telemetry.get("is_jailbroken"))
    is_rooted = bool(device_telemetry.get("is_rooted"))
    has_frida = bool(device_telemetry.get("frida_detected"))
    has_xposed = bool(device_telemetry.get("xposed_detected"))
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
    pinning_failed = bool(sdk_telemetry.get("ssl_pinning_failed"))
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
    porting = bool(mno_signals.get("number_porting_in_progress"))
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
    velocity_kmh = session.get("device_velocity_kmh", 0)
    app_version_age_days = session.get("app_version_age_days")
    os_eol = session.get("os_eol", False)
    side_loaded = session.get("side_loaded", False)
    overlay_detected = session.get("screen_overlay_detected", False)
    impossible_velocity = velocity_kmh and velocity_kmh > 900
    stale = isinstance(app_version_age_days, (int, float)) and app_version_age_days > 365
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
        jailbreak_root_check(alert.get("device_telemetry")),
        sdk_integrity_check(alert.get("sdk_telemetry")),
        sim_swap_check(alert.get("mno_signals"), alert.get("user_id")),
        mobile_session_anomaly_check(alert.get("session")),
    ]
