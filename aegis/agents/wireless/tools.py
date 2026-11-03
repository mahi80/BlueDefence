"""Tools for the Wireless specialist."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ToolResult:
    name: str
    data: dict
    weight: str


# Bank's authorized SSIDs (mock — production: pulled from CMDB).
_AUTHORIZED_SSIDS = {
    "BankWiFi-Staff": {"vlan": "staff", "auth": "wpa3-eap"},
    "BankWiFi-Guest": {"vlan": "guest", "auth": "captive-portal"},
    "BankWiFi-PoS":   {"vlan": "pos",   "auth": "wpa3-eap"},   # highest-value
}

# OUI prefixes of bank's authorized AP vendors.
_AUTHORIZED_AP_OUIS = {"00-1A-1E", "B4-99-BA", "F4-EA-67"}   # Aruba, Cisco, Meraki examples


def rogue_ap_check(ap_record: dict | None) -> ToolResult:
    if not ap_record:
        return ToolResult(name="rogue_ap", data={"verdict": "no_data"}, weight="low")
    bssid = str(ap_record.get("bssid") or "").upper()
    ssid = ap_record.get("ssid") or ""
    is_authorized_ssid = ssid in _AUTHORIZED_SSIDS
    # controllers write BSSIDs as b4:99:ba:…, B4-99-BA-…, b499.ba… or b499ba…; the table uses dashes. Comparing
    # the first 8 characters raw flagged every colon-formatted authorised AP as rogue (review round 3 G7-12).
    hexes = "".join(c for c in bssid if c in "0123456789ABCDEF")
    oui = "-".join(hexes[i:i + 2] for i in (0, 2, 4)) if len(hexes) >= 6 else ""
    is_authorized_oui = oui in _AUTHORIZED_AP_OUIS
    rogue_announcing_authorized_ssid = is_authorized_ssid and not is_authorized_oui
    weight = "high" if rogue_announcing_authorized_ssid else "low"
    return ToolResult(name="rogue_ap", data={
        "bssid": bssid, "ssid": ssid,
        "ssid_authorized": is_authorized_ssid,
        "oui_authorized": is_authorized_oui,
        "rogue_with_authorized_ssid": rogue_announcing_authorized_ssid,
    }, weight=weight)


def evil_twin_check(ap_record: dict | None) -> ToolResult:
    if not ap_record:
        return ToolResult(name="evil_twin", data={"verdict": "no_data"}, weight="low")
    ssid = ap_record.get("ssid") or ""
    bssid = (ap_record.get("bssid") or "").upper()
    captive_portal = bool(ap_record.get("captive_portal_detected"))
    matches_pos = ssid == "BankWiFi-PoS"
    # Evil-twin shape: identical SSID to authorized but different BSSID,
    # or a captive portal added to a branch SSID (the customer-facing
    # phishing pattern).
    twin_match = ssid in _AUTHORIZED_SSIDS and bssid not in (ap_record.get("known_bssids") or set())
    if twin_match and matches_pos:
        weight = "high"
    elif twin_match:
        weight = "high" if captive_portal else "medium"
    else:
        weight = "low"
    return ToolResult(name="evil_twin", data={
        "ssid": ssid, "bssid": bssid,
        "twin_match": twin_match,
        "captive_portal": captive_portal,
        "targets_pos_ssid": matches_pos,
    }, weight=weight)


def deauth_burst_check(deauth_metrics: dict | None) -> ToolResult:
    if not deauth_metrics:
        return ToolResult(name="deauth_burst", data={"verdict": "no_data"}, weight="low")
    deauths_per_min = deauth_metrics.get("deauth_frames_per_min", 0)
    distinct_targets = deauth_metrics.get("distinct_target_clients", 0)
    if deauths_per_min >= 200 or distinct_targets >= 20:
        weight = "high"
    elif deauths_per_min >= 50 or distinct_targets >= 5:
        weight = "medium"
    else:
        weight = "low"
    return ToolResult(name="deauth_burst", data={
        "deauths_per_min": deauths_per_min,
        "distinct_targets": distinct_targets,
        "burst_pattern": deauths_per_min >= 50 or distinct_targets >= 5,
    }, weight=weight)


def wpa_attack_check(wpa_signals: dict | None) -> ToolResult:
    if not wpa_signals:
        return ToolResult(name="wpa_attack", data={"verdict": "no_data"}, weight="low")
    handshake_capture_attempts = wpa_signals.get("handshake_capture_attempts", 0)
    pmkid_capture_attempts = wpa_signals.get("pmkid_capture_attempts", 0)
    krack_indicators = bool(wpa_signals.get("krack_indicators"))
    if handshake_capture_attempts >= 3 or pmkid_capture_attempts >= 1 or krack_indicators:
        weight = "high"
    elif handshake_capture_attempts >= 1:
        weight = "medium"
    else:
        weight = "low"
    return ToolResult(name="wpa_attack", data={
        "handshake_capture_attempts": handshake_capture_attempts,
        "pmkid_capture_attempts": pmkid_capture_attempts,
        "krack_indicators": krack_indicators,
        "active_attack": handshake_capture_attempts >= 1 or pmkid_capture_attempts >= 1 or krack_indicators,
    }, weight=weight)


def run_all_tools(alert: dict) -> list[ToolResult]:
    return [
        rogue_ap_check(alert.get("ap_record")),
        evil_twin_check(alert.get("ap_record")),
        deauth_burst_check(alert.get("deauth_metrics")),
        wpa_attack_check(alert.get("wpa_signals")),
    ]
