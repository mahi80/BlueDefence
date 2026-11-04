"""Tools for the Wireless specialist."""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from ..shared.tool_guard import isolated


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


# Latin look-alikes an attacker swaps into a broadcast SSID ("BankWiFi-PоS" with a Cyrillic о).
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "А": "a", "В": "b", "Е": "e", "К": "k", "М": "m", "Н": "h", "О": "o", "Р": "p", "С": "c", "Т": "t",
    "Х": "x", "І": "i", "Ј": "j", "Ѕ": "s", "ο": "o", "Ο": "o", "α": "a", "Α": "a", "Β": "b", "Ε": "e",
    "Ζ": "z", "Η": "h", "Ι": "i", "Κ": "k", "Μ": "m", "Ν": "n", "Ρ": "p", "Τ": "t", "Υ": "y", "Χ": "x",
    "ν": "v", "ρ": "p", "τ": "t", "υ": "u", "ι": "i", "κ": "k", "‐": "-", "‑": "-", "‒": "-", "–": "-",
    "—": "-", "−": "-", "_": "-", "0": "o", "1": "l", "|": "l",
})


def _ssid_fold(ssid: str) -> str:
    t = unicodedata.normalize("NFKC", str(ssid or "")[:64])
    t = "".join(c for c in t if not c.isspace() and unicodedata.category(c) not in ("Cf", "Cc", "Mn", "Zs"))
    return t.casefold()


def _ssid_key(ssid: str) -> str:
    """NFKC, drop invisible / whitespace characters, fold case and look-alikes (round 7 D-13)."""
    return _ssid_fold(ssid).translate(_CONFUSABLES)


#: one trailing decoration an AP name gets (or an attacker adds to look like a second radio / extender):
#: ``-2``, ``5G``, ``_5GHz``, ``2.4G``, ``-guest``, ``-ext`` (round 8 D8-17)
_SSID_SUFFIX = re.compile(r"[-_.]?(?:\d(?:\.\d)?ghz|\d(?:\.\d)?g|guest|ext|extender|repeater|\d{1,2})$")


def _ssid_variants(ssid: str) -> list[str]:
    """The SSID's key, then the key with one, two, three trailing decorations removed."""
    t = _ssid_fold(ssid)
    out = [t.translate(_CONFUSABLES)]
    for _ in range(3):
        nxt = _SSID_SUFFIX.sub("", t)
        if nxt == t or not nxt:
            break
        t = nxt
        out.append(t.translate(_CONFUSABLES))
    return out


def _edit_le(a: str, b: str, k: int) -> bool:
    """Optimal-string-alignment distance (adjacent swaps count once) of at most ``k``; banded, so linear in the
    (short) SSID."""
    if abs(len(a) - len(b)) > k:
        return False
    prev2: list[int] | None = None
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [k + 1] * len(b)
        for j in range(max(1, i - k), min(len(b), i + k) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            v = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                v = min(v, prev2[j - 2] + 1)
            cur[j] = v
        if min(cur) > k:
            return False
        prev2, prev = prev, cur
    return prev[len(b)] <= k


def _edit1(a: str, b: str) -> bool:
    if a == b or abs(len(a) - len(b)) > 1:
        return a == b
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diff) == 1 or (len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]]
                                  and a[diff[1]] == b[diff[0]])
    if len(a) > len(b):
        a, b = b, a
    return any(b[:i] + b[i + 1:] == a for i in range(len(b)))


_AUTH_KEYS = None


def _ssid_match(ssid: str) -> tuple[str | None, str]:
    """Return (authorised SSID it names, how): ``exact``, ``normalised`` (same after folding invisibles / case /
    look-alikes) or ``lookalike`` (one edit away). A trailing zero-width space or a Cyrillic letter made a PoS
    evil twin "not an authorised SSID" and so not a twin at all (round 7 D-13)."""
    global _AUTH_KEYS
    if ssid in _AUTHORIZED_SSIDS:
        return ssid, "exact"
    if _AUTH_KEYS is None:
        _AUTH_KEYS = {_ssid_key(k): k for k in _AUTHORIZED_SSIDS}
    variants = [v for v in _ssid_variants(ssid) if v]
    if not variants:
        return None, ""
    if variants[0] in _AUTH_KEYS:
        return _AUTH_KEYS[variants[0]], "normalised"
    # a decorated name (`BankWiFi-PoS-2`, `BankWiFi-PoS 5G`, `BankWiFi-PoS_5GHz`) and up to two edits on a long
    # name are look-alikes too (round 8 D8-17)
    for k in variants:
        if k in _AUTH_KEYS:
            return _AUTH_KEYS[k], "lookalike"
        for ak, name in _AUTH_KEYS.items():
            if len(ak) >= 6 and _edit_le(k, ak, 2 if len(ak) >= 10 else 1):
                return name, "lookalike"
    return None, ""


def _mac(v: object) -> str:
    return "".join(c for c in str(v or "").upper() if c in "0123456789ABCDEF")


def rogue_ap_check(ap_record: dict | None) -> ToolResult:
    if not ap_record:
        return ToolResult(name="rogue_ap", data={"verdict": "no_data"}, weight="low")
    bssid = str(ap_record.get("bssid") or "").upper()
    ssid = ap_record.get("ssid") or ""
    named, how = _ssid_match(ssid)
    is_authorized_ssid = named is not None
    lookalike = how in ("normalised", "lookalike")
    # controllers write BSSIDs as b4:99:ba:…, B4-99-BA-…, b499.ba… or b499ba…; the table uses dashes. Comparing
    # the first 8 characters raw flagged every colon-formatted authorised AP as rogue (review round 3 G7-12).
    hexes = "".join(c for c in bssid if c in "0123456789ABCDEF")
    oui = "-".join(hexes[i:i + 2] for i in (0, 2, 4)) if len(hexes) >= 6 else ""
    is_authorized_oui = oui in _AUTHORIZED_AP_OUIS
    # The OUI is three bytes the attacker types: when the controller sent its list of real BSSIDs, that list is
    # the authority (round 7 D-13); without it a PoS SSID on a "vendor" OUI is unverified, not trusted.
    known_raw = ap_record.get("known_bssids") or ()
    known = {_mac(k) for k in ([known_raw] if isinstance(known_raw, str) else known_raw)}
    not_known = bool(known) and _mac(bssid) not in known
    rogue_announcing_authorized_ssid = is_authorized_ssid and (not is_authorized_oui or not_known or lookalike)
    unverified = is_authorized_ssid and not known and is_authorized_oui and not lookalike
    if rogue_announcing_authorized_ssid:
        weight = "high"
    elif unverified and named == "BankWiFi-PoS":
        weight = "medium"
    else:
        weight = "low"
    return ToolResult(name="rogue_ap", data={
        "bssid": bssid, "ssid": ssid,
        "ssid_authorized": is_authorized_ssid,
        "ssid_named": named, "ssid_match": how,
        "oui_authorized": is_authorized_oui,
        "bssid_unverified": unverified,
        "rogue_with_authorized_ssid": rogue_announcing_authorized_ssid,
    }, weight=weight)


def evil_twin_check(ap_record: dict | None) -> ToolResult:
    if not ap_record:
        return ToolResult(name="evil_twin", data={"verdict": "no_data"}, weight="low")
    ssid = ap_record.get("ssid") or ""
    bssid = (ap_record.get("bssid") or "").upper()
    captive_portal = bool(ap_record.get("captive_portal_detected"))
    named, how = _ssid_match(ssid)
    matches_pos = named == "BankWiFi-PoS"
    # Evil-twin shape: identical SSID to authorized but different BSSID,
    # or a captive portal added to a branch SSID (the customer-facing
    # phishing pattern).
    # BSSIDs in one normal form on both sides: `b4:99:ba:…` from the controller vs `B4-99-BA-…` from the sensor
    # made every authorised PoS AP an evil twin (round 4 S4-16 / G7-12)
    known = ap_record.get("known_bssids") or ()
    known = {_mac(k) for k in ([known] if isinstance(known, str) else known)}
    # a look-alike of an authorised SSID is a twin whatever its BSSID (round 7 D-13)
    twin_match = named is not None and (_mac(bssid) not in known or how != "exact")
    if twin_match and matches_pos:
        weight = "high"
    elif twin_match:
        weight = "high" if captive_portal else "medium"
    else:
        weight = "low"
    return ToolResult(name="evil_twin", data={
        "ssid": ssid, "bssid": bssid,
        "twin_match": twin_match,
        "ssid_named": named, "ssid_match": how,
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
        isolated(lambda: rogue_ap_check(alert.get("ap_record")), "rogue_ap_check", ToolResult),
        isolated(lambda: evil_twin_check(alert.get("ap_record")), "evil_twin_check", ToolResult),
        isolated(lambda: deauth_burst_check(alert.get("deauth_metrics")), "deauth_burst_check", ToolResult),
        isolated(lambda: wpa_attack_check(alert.get("wpa_signals")), "wpa_attack_check", ToolResult),
    ]
