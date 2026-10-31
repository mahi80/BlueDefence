"""Endpoint-security gaps Sigma does not cover: sensor tampering & inventory drift, ransomware-rate
telemetry with canary files, the infostealer → session-replay chain, removable media, mobile
banking-trojan posture, and branch / ATM / kiosk whitelisting. Six profiles in the EDR / MDM /
kiosk vendors' field vocabularies, labelled by the corroboration rule (≥2 strong or 1 strong +
≥2 weak → malicious; 1 strong or ≥2 weak → suspicious; else benign). Contexts that explain the
same telemetry — maintenance / imaging window, approved USB exception, enrolled developer
device, scheduled ATM servicing — neutralise only what they can explain. Values are categorical
and numeric; no command lines or payloads anywhere.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass

from ..export import TRIAGE_SYSTEM_PROMPT
from ..schema import fingerprint, split_for
from ..synth import ALWAYS_HITL
from . import _products as P

LABEL_SOURCE = "public:endpoint"
ORIGIN = "endpoint/v1"


@dataclass
class Sig:
    text: str
    strength: str      # strong | weak | none
    category: str
    technique: str = ""


def _acts(pairs):
    return [{"action_type": a, "target": t, "requires_hitl": a in ALWAYS_HITL} for a, t in pairs]


def _edr(r):
    return r.choice(("CrowdStrike Falcon", "Sophos Central", "Microsoft Defender for Endpoint"))


# --------------------------------------------------------------------------- 1. sensor tampering + inventory drift

def sensor_tamper(r: random.Random):
    host = P._host(r); user = P._user(r)
    event = r.choice(("sensor_uninstall_attempt", "sensor_service_stopped", "tamper_protection_disabled", "av_realtime_disabled",
                      "sensor_offline", "unmanaged_device_seen", "sensor_version_downgraded"))
    offline_min = r.choice((0, r.randint(5, 40), r.randint(120, 3000))) if event == "sensor_offline" else 0
    by = r.choice(("local_admin", "SYSTEM", "domain_admin", "unknown", "sccm_service"))
    maint = r.random() < .18; imaging = r.random() < .1
    prior = r.choice((None, None, None, "credential_store_access", "shadow_copy_delete", "new_local_admin"))
    a = {"source": _edr(r), "event": event, "host": host, "user": user, "initiated_by": by, "sensor_offline_minutes": offline_min,
         "host_last_seen_minutes_ago": offline_min or r.randint(0, 5), "asset_in_inventory": event != "unmanaged_device_seen",
         "host_role": r.choice(("laptop", "laptop", "server", "vdi", "jump-host")), "prior_event_30m": prior,
         "os_patch_age_days": r.randint(0, 120), "disk_encrypted": r.random() < .9}
    if maint: a["context"] = {"maintenance_window": {"ticket": f"CHG-{r.randint(100000, 999999)}", "covers_host": True}}
    if imaging: a["context"] = {**a.get("context", {}), "it_imaging_job": {"job": f"IMG-{r.randint(1000, 9999)}", "by": "sccm_service"}}
    s = []
    if event in ("sensor_uninstall_attempt", "tamper_protection_disabled", "av_realtime_disabled", "sensor_version_downgraded"):
        s.append(Sig(f"{event.replace('_', ' ')} by {by}", "strong", "tamper", "T1562.001"))
    if event == "sensor_service_stopped":
        s.append(Sig(f"sensor service stopped by {by}", "strong" if by in ("local_admin", "unknown") else "weak", "tamper", "T1562.001"))
    if event == "sensor_offline" and offline_min >= 120:
        s.append(Sig(f"sensor silent for {offline_min} min while host still on the network", "strong", "tamper", "T1562.001"))
    elif event == "sensor_offline":
        s.append(Sig(f"sensor offline {offline_min} min", "weak", "tamper"))
    if event == "unmanaged_device_seen":
        s.append(Sig("device on the corporate network with no sensor and not in inventory", "strong", "inventory", "T1200"))
    if prior:
        s.append(Sig(f"preceded by {prior.replace('_', ' ')} within 30 min", "strong", "chain", {"credential_store_access": "T1003", "shadow_copy_delete": "T1490", "new_local_admin": "T1136.001"}[prior]))
    if a["host_role"] in ("server", "jump-host"): s.append(Sig(f"{a['host_role']} — high-value host", "weak", "asset"))
    if by == "unknown": s.append(Sig("initiator could not be attributed", "weak", "tamper"))
    s.append(Sig(f"patch age {a['os_patch_age_days']} d, disk encryption, last-seen timestamp", "none", "context"))
    neutral = {}
    if maint: neutral["maintenance_window"] = {"tamper"}
    if imaging: neutral["it_imaging_job"] = {"tamper", "inventory"}
    return a, s, neutral, [("isolate", host), ("revoke_sessions", user), ("snapshot_forensic", host)], [("monitor", host), ("notify_user", "endpoint-team")], host, "endpoint/sensor-tamper"


# --------------------------------------------------------------------------- 2. ransomware-rate telemetry + canary files

def ransomware_rate(r: random.Random):
    host = P._host(r); user = P._user(r)
    renames = r.choice((r.randint(0, 20), r.randint(50, 300), r.randint(800, 20000)))
    entropy = round(r.choice((r.uniform(3.5, 5.5), r.uniform(6.5, 7.2), r.uniform(7.6, 8.0))), 2)
    canary = r.random() < .2; smb_hosts = r.choice((0, 1, r.randint(5, 60))); backup_fail = r.random() < .2
    shadow = r.random() < .15; ext_change = r.random() < .3; backup_job = r.random() < .12; archive = r.random() < .1
    a = {"source": _edr(r), "event": "file_activity_burst", "host": host, "user": user, "files_renamed_per_min": renames,
         "avg_write_entropy": entropy, "extension_changed_ratio": round(r.uniform(.6, 1.0) if ext_change else r.uniform(0, .1), 2),
         "canary_file_modified": canary, "smb_hosts_written_10m": smb_hosts, "backup_job_failures_1h": r.randint(1, 6) if backup_fail else 0,
         "shadow_copies_deleted": shadow, "process_signed": r.random() < .6, "host_role": r.choice(("laptop", "file-server", "vdi"))}
    if backup_job: a["context"] = {"scheduled_backup_job": {"agent": r.choice(("Veeam", "Commvault")), "window_active": True}}
    if archive: a["context"] = {**a.get("context", {}), "approved_archive_job": {"ticket": f"CHG-{r.randint(100000, 999999)}"}}
    s = []
    if renames >= 800 and entropy >= 7.6: s.append(Sig(f"{renames} renames/min at entropy {entropy} — mass encryption", "strong", "rate", "T1486"))
    elif renames >= 50 and (entropy >= 6.5 or a["extension_changed_ratio"] >= .6): s.append(Sig(f"{renames} renames/min, extension change ratio {a['extension_changed_ratio']}", "weak", "rate", "T1486"))
    else: s.append(Sig(f"{renames} renames/min at entropy {entropy} — ordinary file activity", "none", "rate"))
    if canary:   # a tripwire: backup agents READ canaries, nothing legitimate ever modifies one — counts as confirmed on its own
        s.append(Sig("canary file modified — backups read canaries, nothing legitimate ever writes one", "strong", "canary", "T1486"))
        s.append(Sig("tripwire semantics: a modified canary is a confirmed encryptor, not a hint", "strong", "canary", "T1486"))
    if shadow: s.append(Sig("shadow copies deleted", "strong", "recovery", "T1490"))
    if smb_hosts >= 5: s.append(Sig(f"writes to {smb_hosts} SMB hosts in 10 min", "strong", "spread", "T1021.002"))
    elif smb_hosts == 1: s.append(Sig("writes to one network share", "weak", "spread"))
    if backup_fail: s.append(Sig(f"{a['backup_job_failures_1h']} backup job failures in the hour", "weak", "recovery"))
    if not a["process_signed"] and renames >= 50: s.append(Sig("writer process unsigned", "weak", "rate"))
    s.append(Sig("host role, user id", "none", "context"))
    neutral = {}
    if backup_job: neutral["scheduled_backup_job"] = {"rate", "spread"}
    if archive: neutral["approved_archive_job"] = {"rate"}
    return a, s, neutral, [("isolate", host), ("kill_process", host), ("snapshot_forensic", host)], [("monitor", host), ("notify_user", user), ("hold", f"{host} shares")], host, "endpoint/ransomware-rate"


# --------------------------------------------------------------------------- 3. infostealer → session replay (EDR ↔ identity chain)

def infostealer_chain(r: random.Random):
    host = P._host(r); user = P._user(r)
    store = r.choice((None, None, "browser_cookie_db", "browser_credential_store", "os_credential_vault", "vpn_profile"))
    replay = r.random() < .35; replay_geo_far = replay and r.random() < .6; replay_min = r.randint(2, 90)
    new_dev = replay and r.random() < .8; archive_out = r.random() < .25; signed = r.random() < .5
    pwmgr = r.random() < .12
    a = {"source": _edr(r), "event": "credential_store_read", "host": host, "user": user, "store_read": store,
         "reader_process_signed": signed, "reader_reputation": r.choice(("known-good", "unknown", "unknown", "malicious")),
         "archive_created_then_uploaded": archive_out,
         "identity": {"session_token_reused_from_new_device": new_dev, "reuse_minutes_after_read": replay_min if replay else None,
                      "reuse_geo": r.choice(("RU", "NG", "BR")) if replay_geo_far else ("IN-MH" if replay else None),
                      "mfa_prompt_on_reuse": False if replay else None}}
    if pwmgr: a["context"] = {"approved_password_manager": {"product": r.choice(("1Password", "Bitwarden")), "process_matches": True}}
    s = []
    if store and a["reader_reputation"] == "malicious": s.append(Sig(f"{store} read by a process with malicious reputation", "strong", "steal", "T1555.003"))
    elif store and not signed: s.append(Sig(f"{store} read by an unsigned process", "strong", "steal", "T1555.003"))
    elif store: s.append(Sig(f"{store} read by a signed process of unknown reputation", "weak", "steal", "T1555.003"))
    else: s.append(Sig("no credential store access", "none", "steal"))
    if replay and new_dev: s.append(Sig(f"the same session token used from a new device {replay_min} min later{' from ' + a['identity']['reuse_geo'] if replay_geo_far else ''}, no MFA", "strong", "replay", "T1550.004"))
    elif replay: s.append(Sig(f"session token reused {replay_min} min later from a known device", "weak", "replay"))
    if archive_out: s.append(Sig("archive created then uploaded within minutes of the read", "strong" if store else "weak", "exfil", "T1560"))
    s.append(Sig("host id, user id, reader process name", "none", "context"))
    neutral = {"approved_password_manager": {"steal"}} if pwmgr else {}
    return a, s, neutral, [("isolate", host), ("revoke_sessions", user), ("rotate_credential", user), ("snapshot_forensic", host)], [("challenge", user), ("monitor", host), ("notify_user", user)], host, "endpoint/infostealer-chain"


# --------------------------------------------------------------------------- 4. removable media / peripherals

def removable_media(r: random.Random):
    host = P._host(r); user = P._user(r)
    kind = r.choice(("usb_mass_storage", "usb_mass_storage", "usb_hid", "bluetooth_pairing", "usb_network_adapter"))
    bytes_out = r.choice((0, r.randint(1_000_000, 40_000_000), r.randint(500_000_000, 60_000_000_000)))
    hid_cps = r.randint(600, 4000) if kind == "usb_hid" and r.random() < .5 else r.randint(2, 9)
    sens = r.choice(("none", "internal", "confidential", "customer-pii")); exception = r.random() < .15
    serial_known = r.random() < .4; vendor = r.choice(("SanDisk", "Kingston", "Unknown", "Generic", "Logitech"))
    a = {"source": _edr(r), "event": "peripheral_connected", "host": host, "user": user, "device_class": kind, "vendor": vendor,
         "device_serial_known": serial_known, "bytes_written_to_device": bytes_out, "classification_of_files_copied": sens,
         "hid_chars_per_second": hid_cps if kind == "usb_hid" else None, "host_role": r.choice(("laptop", "branch-pc", "teller-pc", "server")),
         "dlp_block_applied": r.random() < .5}
    if exception: a["context"] = {"approved_usb_exception": {"ticket": f"CHG-{r.randint(100000, 999999)}", "device_serial": "matches"}}
    s = []
    if kind == "usb_hid" and hid_cps >= 600: s.append(Sig(f"HID device typing at {hid_cps} chars/s — scripted keystroke injection", "strong", "media", "T1200"))
    if kind == "usb_mass_storage" and bytes_out >= 500_000_000 and sens in ("confidential", "customer-pii"): s.append(Sig(f"{bytes_out // 1_000_000} MB of {sens} written to removable media", "strong", "media", "T1052.001"))
    elif kind == "usb_mass_storage" and bytes_out >= 1_000_000: s.append(Sig(f"{bytes_out // 1_000_000} MB written to removable media", "weak", "media", "T1052.001"))
    if kind == "usb_network_adapter": s.append(Sig("unexpected USB network adapter on a managed host", "strong", "media", "T1200"))
    if kind == "bluetooth_pairing" and a["host_role"] in ("teller-pc", "server"): s.append(Sig(f"bluetooth pairing on a {a['host_role']}", "weak", "media"))
    if not serial_known and vendor in ("Unknown", "Generic") and kind != "bluetooth_pairing": s.append(Sig("unknown-vendor device, serial never seen", "weak", "media"))
    if a["host_role"] in ("teller-pc", "server") and kind in ("usb_mass_storage", "usb_hid", "usb_network_adapter"): s.append(Sig(f"{kind.replace('_', ' ')} on a {a['host_role']}", "weak", "asset"))
    s.append(Sig("vendor name, host id, DLP block flag", "none", "context"))
    neutral = {"approved_usb_exception": {"media"}} if exception else {}
    return a, s, neutral, [("isolate", host), ("block", f"{host} usb"), ("notify_user", "hr")], [("monitor", host), ("notify_user", user)], host, "endpoint/removable-media"


# --------------------------------------------------------------------------- 5. mobile posture (banking-trojan pattern)

def mobile_posture(r: random.Random):
    dev = f"MOB-{r.randint(10000, 99999)}"; user = P._user(r)
    rooted = r.random() < .2; sideload = r.random() < .3; access_svc = r.random() < .25; overlay = r.random() < .2
    sms_reader = r.random() < .2; pinning = r.random() < .8; dev_device = r.random() < .1
    app_store = "sideloaded" if sideload else r.choice(("Play Store", "App Store"))
    a = {"source": r.choice(("Microsoft Intune", "VMware Workspace ONE", "App Shield SDK")), "device_id": dev, "user": user,
         "platform": r.choice(("Android 14", "Android 13", "iOS 17")), "rooted_or_jailbroken": rooted,
         "banking_app": {"install_source": app_store, "cert_pinning_active": pinning, "overlay_detected_on_login": overlay},
         "accessibility_service_granted_to_unknown_app": access_svc, "sms_read_permission_unknown_app": sms_reader,
         "unknown_app_installed_days_ago": r.randint(0, 30) if (access_svc or sms_reader) else None,
         "screen_recording_active": r.random() < .08, "device_compliance": r.choice(("compliant", "compliant", "non-compliant"))}
    if dev_device: a["context"] = {"enrolled_developer_device": {"program": "mobile-dev", "user_in_program": True}}
    s = []
    if overlay: s.append(Sig("overlay drawn over the banking app's login screen", "strong", "trojan", "T1417.002"))
    if access_svc: s.append(Sig("accessibility service granted to an unknown app", "strong", "trojan", "T1417.001"))
    if sms_reader: s.append(Sig("unknown app can read SMS (OTP interception)", "strong", "trojan", "T1417.002"))
    if rooted: s.append(Sig("device rooted / jailbroken", "weak" if not dev_device else "none", "posture"))
    if sideload: s.append(Sig("banking app side-loaded, not from the store", "weak", "posture"))
    if not pinning: s.append(Sig("certificate pinning inactive", "weak", "posture"))
    if a["screen_recording_active"]: s.append(Sig("screen recording active during the session", "weak", "trojan"))
    s.append(Sig("platform version, compliance label, device id", "none", "context"))
    neutral = {"enrolled_developer_device": {"posture"}} if dev_device else {}
    return a, s, neutral, [("lock_account", user), ("revoke_sessions", user), ("notify_user", user)], [("challenge", user), ("notify_user", user), ("monitor", dev)], dev, "endpoint/mobile-posture"


# --------------------------------------------------------------------------- 6. branch / ATM / kiosk endpoints

def branch_kiosk(r: random.Random):
    kind = r.choice(("atm", "kiosk", "teller-pc", "branch-server"))
    dev = f"{kind.upper()}-{r.randint(100, 999)}"; branch = f"BR-{r.randint(100, 999)}"
    wl_viol = r.choice((0, 0, 1, r.randint(3, 30))); breakout = kind == "kiosk" and r.random() < .2
    xfs = kind == "atm" and r.random() < .2; svc_logon = r.random() < .25; hour = r.randint(0, 23)
    servicing = r.random() < .15; usb = r.random() < .15
    a = {"source": r.choice(("Sophos Central", "Microsoft Defender for Endpoint", "ATM Monitoring")), "device": dev, "device_class": kind, "branch": branch,
         "whitelisting_violations_1h": wl_viol, "kiosk_shell_escape_detected": breakout, "xfs_command_anomaly": xfs,
         "service_logon_outside_window": svc_logon, "local_hour": hour, "usb_mass_storage_connected": usb,
         "cash_dispense_without_transaction": kind == "atm" and r.random() < .08}
    if servicing: a["context"] = {"scheduled_servicing": {"ticket": f"SVC-{r.randint(10000, 99999)}", "vendor_engineer": True, "window_active": True}}
    s = []
    if wl_viol >= 3: s.append(Sig(f"{wl_viol} application-whitelisting violations in an hour", "strong", "whitelist", "T1204.002"))
    elif wl_viol == 1: s.append(Sig("one whitelisting violation", "weak", "whitelist"))
    if breakout: s.append(Sig("kiosk shell escape detected", "strong", "kiosk", "T1211"))
    if xfs: s.append(Sig("XFS command outside any transaction flow", "strong", "atm", "T1200"))
    if a["cash_dispense_without_transaction"]: s.append(Sig("cash dispensed with no matching transaction", "strong", "atm", "T1565"))
    if svc_logon: s.append(Sig(f"service logon at {hour:02d}:00 outside the servicing window", "weak", "access"))
    if usb and kind in ("atm", "kiosk"): s.append(Sig(f"USB mass storage connected to a {kind}", "strong" if kind == "atm" else "weak", "media", "T1200"))
    if 0 <= hour < 5 and kind != "atm": s.append(Sig(f"activity at {hour:02d}:00 on a {kind}", "weak", "access"))
    s.append(Sig("branch code, device id", "none", "context"))
    neutral = {"scheduled_servicing": {"whitelist", "access", "media", "atm"}} if servicing else {}
    return a, s, neutral, [("isolate", dev), ("escalate", "branch-ops"), ("snapshot_forensic", dev)], [("monitor", dev), ("notify_user", "branch-ops")], dev, "endpoint/branch-kiosk"


PROFILES = {"sensor_tamper": sensor_tamper, "ransomware_rate": ransomware_rate, "infostealer_chain": infostealer_chain,
            "removable_media": removable_media, "mobile_posture": mobile_posture, "branch_kiosk": branch_kiosk}


def decide(s: list[Sig], neutral: dict[str, set], contain, verify, actor, r: random.Random):
    gone = set().union(*neutral.values()) if neutral else set()
    live = [x for x in s if x.strength in ("strong", "weak") and x.category not in gone]
    dropped = [x for x in s if x.strength in ("strong", "weak") and x.category in gone]
    strong = [x for x in live if x.strength == "strong"]; weak = [x for x in live if x.strength == "weak"]
    none = [x for x in s if x.strength == "none"]
    texts = [f"strong: {x.text}" for x in strong] + [f"weak: {x.text}" for x in weak]
    for k, cats in neutral.items():
        texts.append(f"context: {k.replace('_', ' ')} explains " + (", ".join(sorted({x.category for x in dropped if x.category in cats})) or "nothing here"))
    if none: texts.append("not signals: " + "; ".join(x.text for x in none[:2]))
    techs = list(dict.fromkeys(x.technique for x in live if x.technique))
    if len(strong) >= 2 or (len(strong) == 1 and len(weak) >= 2):
        head = (f"Two independent strong signals — {strong[0].text}; {strong[1].text} — corroborate each other" if len(strong) >= 2
                else f"One strong signal ({strong[0].text}) corroborated by two independent weak ones ({weak[0].text}; {weak[1].text})")
        return "malicious", r.uniform(.85, .96), texts, _acts(contain), techs, head + ". Contain now; the actions need an analyst's approval."
    if len(strong) == 1 or len(weak) >= 2:
        lead = strong[0].text if strong else f"{weak[0].text}; {weak[1].text}"
        return "suspicious", r.uniform(.56, .74), texts, _acts(verify), techs, \
            (f"One strong signal ({lead})" if strong else f"Weak signals only ({lead})") + " — verify with the owner and watch; admins, backup agents and IT jobs produce the same single field."
    why = ("Explained by " + ", ".join(k.replace("_", " ") for k in neutral) + "; nothing outside that context." if neutral
           else "Within the host's normal pattern; the identifying fields carry no weight. No action.")
    return "benign", r.uniform(.78, .92), texts, _acts([("allow", actor)] + ([("monitor", actor)] if weak or dropped else [])), [], why


def generate_endpoint(n: int, *, seed: int = 7, val_pct: int = 15) -> list[dict]:
    r = random.Random(seed)
    names = list(PROFILES); per = n // len(names) + 1
    quota = {d: {"benign": int(per * .35) + 1, "suspicious": int(per * .35) + 1, "malicious": int(per * .3) + 1} for d in names}
    rows: list[dict] = []; seen: set[str] = set(); guard = 0
    while len(rows) < n and guard < n * 40:
        guard += 1
        name = r.choice(names)
        a, s, neutral, contain, verify, actor, profile = PROFILES[name](r)
        verdict, conf, sig, acts, techs, why = decide(s, neutral, contain, verify, actor, r)
        if quota[name][verdict] <= 0:
            continue
        alert = {"id": f"EPT-{r.getrandbits(24):06X}", "observed_at": P._ts(r), **a}
        fp = fingerprint(alert)
        if fp in seen:
            continue
        seen.add(fp); quota[name][verdict] -= 1
        target = {"verdict": verdict, "confidence": round(conf, 2), "key_signals": sig, "recommended_actions": acts, "techniques": techs, "rationale": why}
        rows.append({"id": f"ept-{fp[:16]}", "split": split_for(fp, val_pct), "label_source": LABEL_SOURCE, "origin": ORIGIN,
                     "provenance": {"profile": profile, "strong": sum(1 for x in s if x.strength == "strong"),
                                    "weak": sum(1 for x in s if x.strength == "weak"), "contexts": sorted(neutral)},
                     "messages": [{"role": "system", "content": TRIAGE_SYSTEM_PROMPT},
                                  {"role": "user", "content": json.dumps(alert, sort_keys=True, ensure_ascii=False)},
                                  {"role": "assistant", "content": json.dumps(target, ensure_ascii=False)}]})
    return rows


__all__ = ["LABEL_SOURCE", "ORIGIN", "PROFILES", "decide", "generate_endpoint"]
