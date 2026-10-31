"""Behavioral biometrics for the Auth/IAM specialist.

The project plan flags this as a key defense against AI-class attackers:
typing rhythm, mouse curves, request timing — signals that are HARDER
for an attacker AI to fake than HTTP headers or session tokens. An
attacker with stolen creds + a fresh session token can pass the
identity layer; making them also pass behavioral signature is what
separates "stolen creds" from "stolen creds + stolen-from-keyboard
behavior."

Production swaps in BioCatch / Castle / Onfido / in-house JS
instrumentation. The walking skeleton ships:

  - A behavioral_baseline_diff() tool that compares observed session
    telemetry against the user's historical baseline.
  - Mock baselines per user_id.
  - A weighted distance score; anything > 0.6 is suspicious.

The auth specialist's tools.py imports this and calls it from
run_all_tools when the alert carries a `behavioral_telemetry` field.
"""
from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass
class ToolResult:
    name: str
    data: dict
    weight: str


# Mock baselines. Production: feature store keyed by user_id.
# Values are the user's historical median for each signal.
_BIOMETRIC_BASELINES = {
    "u_42891": {
        "typing_dwell_ms_p50":     108.0,    # avg key-down duration
        "typing_flight_ms_p50":    125.0,    # avg between-key gap
        "mouse_curve_smoothness":  0.78,     # 0-1; 1.0 = perfectly natural arcs
        "request_interarrival_ms": 2400.0,   # avg between successive HTTP requests
        "scroll_velocity_pps":     720.0,    # pixels/sec on long pages
    },
    "u_77104": {
        "typing_dwell_ms_p50":     94.0,
        "typing_flight_ms_p50":    110.0,
        "mouse_curve_smoothness":  0.82,
        "request_interarrival_ms": 1900.0,
        "scroll_velocity_pps":     580.0,
    },
}


def _z_distance(observed: float, baseline: float, *, scale: float) -> float:
    """Normalized distance — how many `scale` units away from baseline."""
    if baseline == 0:
        return 0.0
    return abs(observed - baseline) / scale


def behavioral_baseline_diff(user_id: str | None,
                             telemetry: dict | None) -> ToolResult:
    if not user_id or not telemetry:
        return ToolResult(name="behavioral_biometrics", data={
            "user_id": user_id, "verdict": "insufficient_data",
        }, weight="low")
    baseline = _BIOMETRIC_BASELINES.get(user_id)
    if baseline is None:
        return ToolResult(name="behavioral_biometrics", data={
            "user_id": user_id, "verdict": "no_baseline",
        }, weight="low")

    # Per-signal normalized distance. Scale tuned per signal.
    distances: dict[str, float] = {}
    if "typing_dwell_ms_p50" in telemetry:
        distances["typing_dwell"] = _z_distance(
            float(telemetry["typing_dwell_ms_p50"]),
            baseline["typing_dwell_ms_p50"], scale=40.0,
        )
    if "typing_flight_ms_p50" in telemetry:
        distances["typing_flight"] = _z_distance(
            float(telemetry["typing_flight_ms_p50"]),
            baseline["typing_flight_ms_p50"], scale=50.0,
        )
    if "mouse_curve_smoothness" in telemetry:
        distances["mouse_curve"] = _z_distance(
            float(telemetry["mouse_curve_smoothness"]),
            baseline["mouse_curve_smoothness"], scale=0.25,
        )
    if "request_interarrival_ms" in telemetry:
        distances["request_interarrival"] = _z_distance(
            float(telemetry["request_interarrival_ms"]),
            baseline["request_interarrival_ms"], scale=900.0,
        )
    if "scroll_velocity_pps" in telemetry:
        distances["scroll_velocity"] = _z_distance(
            float(telemetry["scroll_velocity_pps"]),
            baseline["scroll_velocity_pps"], scale=300.0,
        )

    if not distances:
        return ToolResult(name="behavioral_biometrics", data={
            "user_id": user_id, "verdict": "no_signals_provided",
        }, weight="low")

    # Composite distance: Euclidean over the normalized signals.
    composite = math.sqrt(sum(d * d for d in distances.values()) / len(distances))
    drift_score = round(min(composite, 1.0), 3)

    if drift_score >= 0.6:
        weight = "high"
    elif drift_score >= 0.3:
        weight = "medium"
    else:
        weight = "low"

    return ToolResult(name="behavioral_biometrics", data={
        "user_id": user_id,
        "per_signal_distance": {k: round(v, 3) for k, v in distances.items()},
        "drift_score": drift_score,
        "drift_severe": drift_score >= 0.6,
    }, weight=weight)


# ---- Privileged-user baseline ---------------------------------------
#
# Admin / SRE / cloud-engineer / firewall-admin accounts have a
# legitimately different work pattern than retail customers — they do
# log in at 3 AM during change windows, they do hit admin endpoints,
# they do issue mass IAM operations during environment provisioning.
# Treating them with the retail-customer baseline floods the queue
# with false positives.
#
# At the same time, admins are also the highest-value target — once
# compromised, the blast radius is enormous (the actor essentially
# becomes the bank). So the privileged baseline differs from the
# normal baseline in two ways:
#
#   1. *Wider tolerance* for usual admin work (off-hours, admin
#      endpoints, large action volumes) — but
#   2. *Narrower tolerance* for behavior that is wrong EVEN for an
#      admin (no associated change ticket, hitting unfamiliar
#      services, geographic shifts, behavioral biometric drift).
#
# The output complements peer_baseline / impossible_travel — those
# still run; this one adds the privileged-aware nuance the orchestrator
# needs to avoid the high FP rate that plagued the auth-anomaly
# pipeline pre-AEGIS.

_PRIVILEGED_ROLES = {
    # AWS / Azure / GCP cloud admin
    "cloud_admin", "cloud_engineer", "sre", "platform_engineer",
    # Network / firewall admin (Panorama, Checkpoint, Juniper)
    "firewall_admin", "network_admin",
    # Identity / IAM admin
    "iam_admin", "directory_admin",
    # On-prem / OS admin
    "domain_admin", "linux_admin",
    # Bank-specific privileged roles
    "core_banking_admin", "swift_admin", "atm_switch_admin",
}


# Privileged-user baselines. Admin pattern is wider on time-of-day,
# narrower on no-change-ticket high-impact actions.
_PRIVILEGED_BASELINES: dict[str, dict] = {
    # cloud_admin: legitimately works late, hits admin endpoints, but
    # always associated with a change ticket for high-impact actions.
    "cloud_admin": {
        "off_hours_acceptable":      True,
        "expected_source_subnets":   ("10.50.0.0/16",),   # bastion / jump host CIDR
        "high_impact_requires_ticket": True,
        "max_session_count_24h_99p": 60,
        "max_failed_logins_24h_99p": 8,
        "expected_endpoints":        ("/api/admin/*", "/iam/*", "/cloudformation/*"),
    },
    "firewall_admin": {
        "off_hours_acceptable":      True,
        "expected_source_subnets":   ("10.50.0.0/16",),
        "high_impact_requires_ticket": True,
        "max_session_count_24h_99p": 30,
        "max_failed_logins_24h_99p": 5,
        "expected_endpoints":        ("/panorama/*", "/checkpoint-mgmt/*", "/juniper-space/*"),
    },
    "iam_admin": {
        "off_hours_acceptable":      True,
        "expected_source_subnets":   ("10.50.0.0/16",),
        "high_impact_requires_ticket": True,
        "max_session_count_24h_99p": 40,
        "max_failed_logins_24h_99p": 5,
        "expected_endpoints":        ("/iam/*", "/okta/*", "/directory/*"),
    },
}


def _ip_in_subnet(ip: str, cidr: str) -> bool:
    """Cheap CIDR membership check without ipaddress dep noise."""
    if "/" not in cidr:
        return ip == cidr
    base, prefix = cidr.split("/", 1)
    try:
        prefix_n = int(prefix)
        ip_int = sum(int(p) << (24 - 8 * i) for i, p in enumerate(ip.split(".")))
        base_int = sum(int(p) << (24 - 8 * i) for i, p in enumerate(base.split(".")))
        mask = (0xFFFFFFFF << (32 - prefix_n)) & 0xFFFFFFFF
        return (ip_int & mask) == (base_int & mask)
    except (ValueError, AttributeError):
        return False


def privileged_user_baseline_check(user_id: str | None,
                                   role: str | None,
                                   observed: dict | None) -> ToolResult:
    """Check whether an admin's activity is consistent with the
    privileged baseline. Designed to *reduce* false positives on
    legitimate admin work AND *raise* the bar on activity that's wrong
    EVEN for an admin.

    Inputs (all optional, all defensive):
      user_id, role: identifies the principal; if role isn't privileged
        the tool returns insufficient_data (the standard peer_baseline
        already covers retail roles).
      observed: { hour_of_day, source_ip, endpoint, change_ticket_id,
                  high_impact_action, failed_logins_24h, session_count_24h,
                  geo, behavioral_drift_score }

    Reports a list of `red_flags` (admin-specific anomalies) and
    `expected_admin_signals` (signals that look anomalous for retail
    but are normal for admin). The auth specialist reads both — the
    LLM is told to weight red_flags as malicious-grade evidence and
    expected_admin_signals as benign context.
    """
    if not user_id:
        return ToolResult(name="privileged_baseline", data={
            "verdict": "insufficient_data",
        }, weight="low")
    if not role or role not in _PRIVILEGED_ROLES:
        return ToolResult(name="privileged_baseline", data={
            "user_id": user_id, "role": role, "is_privileged": False,
            "verdict": "non_privileged_role",
        }, weight="low")

    # Pick baseline; fall back to cloud_admin if a privileged role isn't
    # in the table yet (graceful default — narrow tolerance, off-hours OK).
    bl = _PRIVILEGED_BASELINES.get(role) or _PRIVILEGED_BASELINES["cloud_admin"]
    obs = dict(observed or {})

    expected_admin_signals: list[str] = []
    red_flags: list[str] = []

    # 1. Off-hours: normal for admins, suspicious for retail.
    hour = obs.get("hour_of_day")
    if isinstance(hour, (int, float)) and (hour < 6 or hour >= 22):
        if bl["off_hours_acceptable"]:
            expected_admin_signals.append(f"off_hours_login_{int(hour)}h_normal_for_admin")
        else:
            red_flags.append(f"off_hours_login_{int(hour)}h")

    # 2. Source subnet. Admin should be on bastion/jump host. If not,
    #    that's a red flag even at 10am.
    src_ip = obs.get("source_ip")
    if isinstance(src_ip, str):
        in_expected = any(_ip_in_subnet(src_ip, cidr)
                          for cidr in bl["expected_source_subnets"])
        if not in_expected:
            red_flags.append(f"admin_login_outside_bastion_subnet:{src_ip}")
        else:
            expected_admin_signals.append("login_from_bastion_subnet")

    # 3. High-impact action without change ticket. The single highest-
    #    value privileged-baseline signal — covers the entire class of
    #    "compromised admin runs IAM/firewall changes off-the-book".
    if obs.get("high_impact_action") and bl["high_impact_requires_ticket"]:
        ticket = obs.get("change_ticket_id")
        if not ticket:
            red_flags.append("high_impact_action_without_change_ticket")
        else:
            expected_admin_signals.append(f"high_impact_with_ticket:{ticket}")

    # 4. Endpoint expectation.
    endpoint = obs.get("endpoint", "")
    if endpoint:
        endpoint_match = any(
            (e.endswith("/*") and endpoint.startswith(e[:-2])) or e == endpoint
            for e in bl["expected_endpoints"]
        )
        if not endpoint_match:
            red_flags.append(f"admin_hitting_unexpected_endpoint:{endpoint}")

    # 5. Volume. Admin baseline is wider, but extreme outliers still flag.
    if obs.get("failed_logins_24h", 0) > bl["max_failed_logins_24h_99p"]:
        red_flags.append("failed_logins_above_admin_99p")
    if obs.get("session_count_24h", 0) > bl["max_session_count_24h_99p"]:
        red_flags.append("session_count_above_admin_99p")

    # 6. Behavioral drift on an admin account is much more concerning
    #    than on a retail account — admin keystrokes are unique enough
    #    that drift typically means "different person at the keyboard".
    bdrift = obs.get("behavioral_drift_score")
    if isinstance(bdrift, (int, float)) and bdrift >= 0.45:
        # Lower threshold than the retail 0.6 — admins are tighter baseline
        red_flags.append(f"admin_behavioral_drift_{bdrift:.2f}")

    # Weight: high if any unticketed high-impact OR multiple red flags,
    # medium for one flag, low otherwise.
    has_unticketed_high_impact = any(
        f.startswith("high_impact_action_without") for f in red_flags
    )
    if has_unticketed_high_impact or len(red_flags) >= 2:
        weight = "high"
    elif len(red_flags) == 1:
        weight = "medium"
    else:
        weight = "low"

    return ToolResult(name="privileged_baseline", data={
        "user_id": user_id,
        "role": role,
        "is_privileged": True,
        "red_flags": red_flags,
        "expected_admin_signals": expected_admin_signals,
        "baseline_used": role if role in _PRIVILEGED_BASELINES else "cloud_admin",
    }, weight=weight)
