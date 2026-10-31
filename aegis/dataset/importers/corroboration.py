"""The corroboration policy, taught on raw-field alerts with no detection name.

Every public-corpus row carries a product verdict of some kind — a Sigma rule title, a Defender
alert class, a DBotScore. The alerts a triage model actually gets wrong are the ones where
nobody has said "attack": an identity-provider sign-in with odd fields, an API call with the
wrong owner, a firewall rule change, a transaction stream. On those the SOC rule is simple and
general, and this generator teaches it directly:

    count the INDEPENDENT strong signals in the raw fields
        ≥ 2 strong                      → malicious  (contain; HITL)
        1 strong, or ≥ 2 weak           → suspicious (verify; hold / challenge)
        0 strong, ≤ 1 weak              → benign
    an approved-change context (ticket inside its window from the expected place) removes
    the change-related strong signals but never a credential/exfil one.

Seven raw-field domains, each with a pool of strong and weak signals that are drawn
independently, so no single field — and no field *name* — predicts the verdict. Field names
are the vendors' own but deliberately NOT the same set as the held-out eval cases (fingerprint
guard applies regardless). Rows carry ``label_source="public:corroboration"``.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field

from ..export import TRIAGE_SYSTEM_PROMPT
from ..schema import fingerprint, split_for
from ..synth import ALWAYS_HITL
from . import _products as P

LABEL_SOURCE = "public:corroboration"
ORIGIN = "corroboration/v1"


@dataclass
class Sig:
    text: str
    strength: str                  # strong | weak | none (an ordinary field the model must learn to ignore)
    technique: str = ""
    change_related: bool = False   # neutralised by an approved-change context


@dataclass
class Built:
    alert: dict
    signals: list = field(default_factory=list)   # [Sig]
    contain: list = field(default_factory=list)   # malicious actions (action, target)
    verify: list = field(default_factory=list)    # suspicious actions
    actor: str = "actor"
    domain: str = ""


def _acts(pairs):
    return [{"action_type": a, "target": t, "requires_hitl": a in ALWAYS_HITL} for a, t in pairs]


# --------------------------------------------------------------------------- domains

_GEO_FAR = {"RU-MO": 5000, "NG-LA": 7800, "BR-SP": 14000, "CN-SH": 4300, "VN-HN": 3200, "US-NY": 12500, "AE-DU": 1900}
_GEO_HOME = ("IN-MH", "IN-KA", "IN-DL", "IN-UP", "IN-TN")
_UAS = ("Mozilla/5.0 (Windows) Chrome/130", "Mozilla/5.0 (Linux) Firefox/115", "Mozilla/5.0 (iPhone) Safari/17",
        "Mozilla/5.0 (Macintosh) Chrome/129", "okhttp/4.12 (Android 14)")
_SCREENS = ("1920x1080", "1366x768", "2560x1440", "390x844", "1440x900")
_TZS = ("Asia/Kolkata", "Asia/Kolkata", "UTC", "Europe/Moscow", "America/Sao_Paulo")


def identity(r: random.Random) -> Built:
    """IdP sign-in with RAW values — the model must derive travel, device novelty and MFA abuse
    itself — rendered in one of three vendor vocabularies, with distractor fields present."""
    idp = r.choice(("Okta", "Microsoft Entra ID", "Ping Identity"))
    user = P._user(r); role = r.choice(("retail_customer", "retail_customer", "branch_staff", "treasury_ops", "cloud_admin", "db_admin"))
    home = r.choice(_GEO_HOME)
    s: list[Sig] = []
    far = r.random() < .35; domestic_move = (not far) and r.random() < .3
    curr = r.choice(list(_GEO_FAR)) if far else (r.choice([g for g in _GEO_HOME if g != home]) if domestic_move else home)
    mins = r.randint(3, 40) if far else r.randint(45, 3000)
    known_fp = {"ua": r.choice(_UAS[:2]), "screen": r.choice(_SCREENS[:3]), "tz": "Asia/Kolkata"}
    new_dev = r.random() < .4
    fp = {"ua": r.choice(_UAS), "screen": r.choice(_SCREENS), "tz": r.choice(_TZS)} if new_dev else dict(known_fp)
    if new_dev and fp == known_fp:
        fp["ua"] = _UAS[3]
    mfa_fail = r.choice((0, 0, 0, 1, 4, 9)); legacy = r.random() < .15; anon = r.random() < .15
    post_change = r.random() < .25; hour = r.choice((2, 3, 4)) if r.random() < .3 else r.randint(9, 19); spray = r.random() < .1
    sessions = r.randint(1, 12); baseline_sessions = r.randint(3, 10)
    vocab = r.choice(("flat", "raw", "nested"))
    if vocab == "flat":
        a = {"source": idp, "event_type": "user.session.start", "user_id": user, "user_role": role,
             "prev_geo": home, "curr_geo": curr, "minutes_since_prev_login": mins,
             "device_fingerprint": fp, "known_device_fingerprints": [known_fp], "client_type": r.choice(("web", "mobile", "api")),
             "auth_protocol": "legacy_basic" if legacy else "oidc", "mfa_failures": mfa_fail,
             "ip_is_anonymizer": anon, "login_hour_local": hour,
             "profile_changed_after_login": r.choice(("recovery_email", "mfa_device", "phone")) if post_change else None,
             "distinct_accounts_from_ip_1h": r.randint(30, 400) if spray else r.randint(1, 3),
             "sessions_24h": sessions, "sessions_24h_baseline": baseline_sessions, "locale": "en-IN"}
    elif vocab == "raw":
        a = {"source": idp, "eventType": "user.authentication.sso", "actor": {"id": user, "type": role},
             "client": {"geographicalContext": {"region": curr}, "userAgent": fp["ua"], "device": {"screen": fp["screen"], "timezone": fp["tz"]},
                        "ipAnonymizer": anon},
             "previous": {"geographicalContext": {"region": home}, "minutesAgo": mins, "device": known_fp},
             "authenticationContext": {"protocol": "basic" if legacy else "oidc", "mfaFailedAttempts": mfa_fail},
             "outcome": {"result": "SUCCESS"}, "postLoginChange": r.choice(("recovery_email", "mfa_device", "phone")) if post_change else None,
             "debugContext": {"accountsFromIp1h": r.randint(30, 400) if spray else r.randint(1, 3), "sessions24h": sessions,
                              "sessions24hBaseline": baseline_sessions, "localHour": hour}}
    else:
        a = {"source": idp, "activity": "SignIn", "userPrincipalName": f"{user}@bank.in", "userRole": role,
             "location": {"countryRegion": curr}, "previousSignIn": {"countryRegion": home, "minutesBefore": mins},
             "deviceDetail": {"browser": fp["ua"], "displayResolution": fp["screen"], "timeZone": fp["tz"], "isKnown": not new_dev},
             "legacyProtocol": legacy, "mfaDetail": {"failedBeforeSuccess": mfa_fail}, "riskEventTypes": ["anonymizedIPAddress"] if anon else [],
             "securityInfoChangedAfterSignIn": r.choice(("recovery_email", "mfa_device", "phone")) if post_change else None,
             "accountsFromSameIp1h": r.randint(30, 400) if spray else r.randint(1, 3), "signIns24h": sessions,
             "signIns24hBaseline": baseline_sessions, "localHour": hour}
    if far:
        s.append(Sig(f"{home} → {curr} in {mins} min (~{_GEO_FAR[curr]} km) — impossible travel", "strong", "T1078"))
    elif domestic_move:
        s.append(Sig(f"{home} → {curr} after {mins} min — ordinary domestic movement", "none"))
    if new_dev:
        diffs = [k for k in fp if fp[k] != known_fp[k]]
        s.append(Sig(f"device fingerprint differs from every known device ({', '.join(diffs)})", "weak"))
    else:
        s.append(Sig("device fingerprint matches a known device", "none"))
    if mfa_fail >= 4: s.append(Sig(f"{mfa_fail} MFA failures before success", "strong", "T1621"))
    elif mfa_fail == 1: s.append(Sig("one MFA failure", "weak"))
    if legacy: s.append(Sig("legacy auth protocol (MFA bypassed)", "strong", "T1078"))
    if anon: s.append(Sig("anonymised network egress", "weak"))
    if post_change: s.append(Sig("security settings changed right after login", "strong", "T1098"))
    if hour < 6: s.append(Sig(f"sign-in at {hour:02d}:00 local", "weak"))
    if spray: s.append(Sig("dozens of accounts from the same IP in an hour", "strong", "T1110.003"))
    if sessions >= 2 * baseline_sessions: s.append(Sig(f"{sessions} sessions in 24 h vs baseline {baseline_sessions}", "weak"))
    else: s.append(Sig(f"{sessions} sessions in 24 h — within baseline", "none"))
    s.append(Sig(f"screen size / locale / client type", "none"))
    return Built(a, s, [("lock_account", user), ("revoke_sessions", user)], [("challenge", user), ("notify_user", user)], user, "identity")


def api(r: random.Random) -> Built:
    gw = r.choice(("Apigee", "Kong Gateway", "AWS API Gateway", "Azure APIM"))
    caller = P._user(r); owner = caller if r.random() < .5 else P._user(r)
    role = r.choice(("retail_customer", "retail_customer", "wealth_advisor", "support_agent", "partner_api", "internal_batch"))
    method = r.choice(("GET", "GET", "PUT", "POST", "DELETE"))
    s: list[Sig] = []
    baseline_x = r.choice((1, 1, 2, 40, 220)); priv_param = r.random() < .15; scope_miss = r.random() < .2; stale = r.random() < .15
    enum_pattern = r.random() < .2
    a = {"source": gw, "api": r.choice(("/v2/customers/{id}", "/v2/accounts/{id}/limits", "/v2/cards/{id}", "/v2/beneficiaries")),
         "http_method": method, "caller_id": caller, "caller_role": role, "resource_owner_id": owner,
         "calls_per_min": baseline_x * r.randint(3, 8), "calls_per_min_baseline_multiple": baseline_x,
         "request_contains_privilege_field": priv_param, "token_scope_matches_resource": not scope_miss,
         "token_age_hours": r.randint(100, 900) if stale else r.randint(0, 12), "sequential_id_pattern": enum_pattern,
         "response_status": r.choice((200, 200, 403, 404))}
    cross = owner != caller and role in ("retail_customer", "partner_api", "support_agent", "wealth_advisor")
    if cross and method in ("PUT", "POST", "DELETE"): s.append(Sig(f"{role} {method} on an object owned by another customer — write across tenants", "strong", "T1190"))
    elif cross: s.append(Sig("reading another customer's object", "weak"))
    elif owner == caller: s.append(Sig("caller owns the object", "none"))
    a["response_time_ms"] = r.randint(20, 400); a["user_agent"] = r.choice(_UAS); s.append(Sig("response time / user agent", "none"))
    if priv_param: s.append(Sig("privilege field in request body", "strong", "T1548"))
    if scope_miss: s.append(Sig("token scope does not cover the resource", "strong", "T1550.001"))
    if baseline_x >= 40: s.append(Sig(f"{baseline_x}× baseline call rate", "weak"))
    if enum_pattern: s.append(Sig("sequential id enumeration", "weak", "T1595"))
    if stale: s.append(Sig(f"token {a['token_age_hours']} h old", "weak"))
    return Built(a, s, [("revoke_sessions", caller), ("block", caller)], [("throttle", caller), ("monitor", caller)], caller, "api")


def netpolicy(r: random.Random) -> Built:
    mgr = r.choice(("Palo Alto Panorama", "FortiManager", "Check Point SmartConsole", "Azure NSG", "AWS Security Group", "OpenStack Neutron"))
    actor = f"{P._user(r)}@bank.in"
    src = r.choice(("any", "any", "10.20.0.0/16", "partner-vpn")); dst = r.choice(("any", "dmz-web", "core-banking-db", "mgmt-vlan"))
    svc = r.choice(("any", "tcp/443", "tcp/3389", "tcp/22", "tcp/1433")); action = r.choice(("allow", "allow", "deny"))
    ticket = r.random() < .45; in_window = ticket and r.random() < .8; from_bastion = r.random() < .6
    tmp_name = r.random() < .3; logging_off = r.random() < .1
    s: list[Sig] = []
    a = {"source": mgr, "operation": r.choice(("rule.create", "rule.modify")), "operator": actor, "rule": {"name": f"{'tmp-' if tmp_name else 'chg-'}{r.randint(100, 999)}",
         "source": src, "destination": dst, "service": svc, "action": action, "logging": not logging_off},
         "change_ticket": f"CHG-{r.randint(100000, 999999)}" if ticket else None, "inside_change_window": in_window,
         "operator_source": "bastion" if from_bastion else r.choice(("corporate-lan", "vpn", "internet")), "commit_pushed": r.random() < .8}
    if r.random() < .5:   # vendor-raw rendering of the same change
        a = {"source": mgr, "event": {"eventName": f"{mgr.split()[0].lower()}:{a['operation']}", "requestParameters": {
                 "rule_name": a["rule"]["name"], "source": src, "destination": dst, "service": svc, "rule_action": action, "log_end": not logging_off}},
             "principal": actor, "change_ticket": a["change_ticket"], "inside_change_window": in_window, "operator_source": a["operator_source"]}
    broad = src == "any" and svc == "any" and action == "allow"
    critical_open = dst in ("core-banking-db", "mgmt-vlan") and src in ("any", "partner-vpn") and action == "allow"
    if broad:
        s.append(Sig("any → any / any service / allow", "strong", "T1562.004", change_related=True))
        s.append(Sig("the rule negates the perimeter entirely — equivalent to a confirmed exposure", "strong", "T1562.004", change_related=True))
    if critical_open: s.append(Sig(f"{src} opened to {dst} ({svc})", "strong", "T1562.004", change_related=True))
    if svc in ("tcp/3389", "tcp/22") and src == "any" and action == "allow": s.append(Sig(f"internet → {svc}", "strong", "T1133", change_related=True))
    if not from_bastion: s.append(Sig(f"change made from {a['operator_source']}, not the bastion", "weak"))
    if tmp_name: s.append(Sig("temporary-looking rule name", "weak"))
    if logging_off: s.append(Sig("rule logging disabled", "strong", "T1562.001"))
    if not ticket: s.append(Sig("no change ticket", "weak"))
    rule_name = a["rule"]["name"] if "rule" in a else a["event"]["requestParameters"]["rule_name"]
    return Built(a, s, [("revoke_sessions", actor), ("hold", rule_name), ("snapshot_forensic", mgr)],
                 [("hold", rule_name), ("notify_user", "network-cab")], actor, "netpolicy")


def dlp(r: random.Random) -> Built:
    prod = r.choice(("Microsoft Purview DLP", "Symantec DLP", "Forcepoint DLP"))
    user = P._user(r); dept = r.choice(P._DEPTS)
    rows = r.choice((r.randint(1, 40), r.randint(300, 2000), r.randint(10000, 300000)))
    dest = r.choice(("corporate-sharepoint", "corporate-sharepoint", "usb-removable", "personal-cloud", "personal-email", "print"))
    status = r.choice(("active", "active", "active", "notice-period", "contractor-ending"))
    sens = r.choice(("internal", "confidential", "customer-pii", "customer-kyc"))
    s: list[Sig] = []
    a = {"source": prod, "policy": f"{sens}-egress", "user_id": user, "department": dept, "employment_status": status,
         "records_matched": rows, "records_baseline_daily": r.randint(5, 200), "destination_class": dest, "sensitivity": sens,
         "local_hour": r.randint(0, 23), "distinct_tables_touched": r.randint(1, 12), "encrypted_container": r.random() < .2}
    bulk = rows >= 10000; external = dest in ("usb-removable", "personal-cloud", "personal-email")
    if bulk and sens in ("customer-pii", "customer-kyc"): s.append(Sig(f"{rows} {sens} records", "strong", "T1530"))
    elif rows >= 300: s.append(Sig(f"{rows} records, {rows // max(1, a['records_baseline_daily'])}× daily baseline", "weak"))
    if external and sens != "internal": s.append(Sig(f"destination {dest}", "strong", "T1567" if dest != "usb-removable" else "T1052.001"))
    elif external: s.append(Sig(f"destination {dest}", "weak"))
    if status != "active": s.append(Sig(f"user on {status}", "strong", "T1530"))
    if a["local_hour"] < 6: s.append(Sig(f"activity at {a['local_hour']:02d}:00", "weak"))
    if a["encrypted_container"]: s.append(Sig("content inside an encrypted container", "weak", "T1560"))
    if a["distinct_tables_touched"] >= 8: s.append(Sig(f"{a['distinct_tables_touched']} distinct tables", "weak"))
    return Built(a, s, [("block_export", user), ("revoke_sessions", user), ("notify_user", "hr")], [("hold", user), ("notify_user", user)], user, "dlp")


def transaction(r: random.Random) -> Built:
    prod = r.choice(("Finacle FRM", "Core Banking (txn stream)", "Flexcube AML", "UPI switch"))
    acct = f"ACC{r.randint(10**9, 10**10 - 1)}"
    rail = r.choice(("UPI", "IMPS", "NEFT", "RTGS")); amount = r.choice((r.randint(500, 40000), r.randint(150000, 900000), r.randint(1500000, 9000000)))
    bene_age = r.choice((r.randint(0, 2), r.randint(0, 2), r.randint(30, 900))); bene_fanin = r.choice((1, 1, r.randint(15, 200)))
    near_threshold = r.random() < .25; after_takeover = r.random() < .2; foreign = r.random() < .15; velocity = r.choice((1, 2, r.randint(8, 30)))
    s: list[Sig] = []
    a = {"source": prod, "account": acct, "rail": rail, "amount_inr": amount, "beneficiary_added_days_ago": bene_age,
         "beneficiary_inbound_senders_7d": bene_fanin, "near_reporting_threshold": near_threshold,
         "customer_session_flagged_takeover": after_takeover, "beneficiary_country": "AE" if foreign else "IN",
         "transfers_last_24h": velocity, "customer_segment": r.choice(("retail", "retail", "hni", "sme"))}
    if bene_fanin >= 15: s.append(Sig(f"beneficiary receives from {bene_fanin} senders in 7 d (mule shape)", "strong", "T1657"))
    if after_takeover: s.append(Sig("sent from a session already flagged as account takeover", "strong", "T1657"))
    if near_threshold and velocity >= 8: s.append(Sig(f"{velocity} near-threshold transfers in 24 h (structuring)", "strong", "T1657"))
    elif near_threshold: s.append(Sig("amount just under the reporting threshold", "weak"))
    if bene_age <= 2 and amount >= 150000: s.append(Sig(f"₹{amount} to a beneficiary added {bene_age} d ago", "weak"))
    if foreign and amount >= 1500000: s.append(Sig("large transfer to a new foreign beneficiary", "weak"))
    if velocity >= 8 and not near_threshold: s.append(Sig(f"{velocity} transfers in 24 h", "weak"))
    return Built(a, s, [("hold", acct), ("escalate_to_fraud_team", acct)], [("hold", acct), ("notify_user", acct)], acct, "transaction")


def wireless(r: random.Random) -> Built:
    prod = r.choice(("Cisco WLC", "Aruba Central", "Cisco WIPS"))
    ssid = r.choice(("Bank-Corp", "Bank-PoS", "Bank-Guest"))
    s: list[Sig] = []
    rogue = r.random() < .35; portal = r.random() < .25; deauth = r.choice((0, 0, r.randint(50, 3000))); known = r.random() < .5
    clients = r.choice((0, 0, r.randint(1, 40))); wrong_sec = r.random() < .2
    a = {"source": prod, "detected_ssid": ssid, "detected_bssid": f"{r.randint(0, 255):02X}-" * 5 + f"{r.randint(0, 255):02X}",
         "bssid_in_inventory": known, "security": "open" if wrong_sec else "wpa2-enterprise", "captive_portal_seen": portal,
         "deauth_frames_last_10m": deauth, "corporate_clients_associated": clients, "rssi_dbm": r.randint(-85, -35),
         "location": r.choice(("Mumbai HQ L3", "Noida DC lobby", "Branch MH-0231"))}
    if rogue and not known: s.append(Sig(f"{ssid} broadcast from a BSSID not in inventory", "strong", "T1557"))
    if portal and ssid != "Bank-Guest": s.append(Sig("captive portal on a corporate SSID", "strong", "T1557"))
    if deauth >= 50: s.append(Sig(f"{deauth} deauth frames in 10 min", "strong", "T1499"))
    if wrong_sec and ssid != "Bank-Guest": s.append(Sig("open security on a corporate SSID", "weak"))
    if clients > 0 and not known: s.append(Sig(f"{clients} corporate clients associated to it", "weak"))
    return Built(a, s, [("block", a["detected_bssid"]), ("notify_user", "facilities"), ("snapshot_forensic", prod)],
                 [("monitor", a["detected_bssid"]), ("notify_user", "facilities")], a["detected_bssid"], "wireless")


def cloudctl(r: random.Random) -> Built:
    prod = r.choice(("AWS CloudTrail", "Azure Activity Log", "GCP Audit Log"))
    ident = r.choice(("human_admin", "human_admin", "workload_identity", "ci_pipeline", "contractor"))
    op = r.choice(("logging.stop", "iam.key.create", "storage.policy.public", "network.ingress.open", "iam.user.create", "compute.describe", "secret.read"))
    s: list[Sig] = []
    mfa = r.random() < .6; ext = r.random() < .3; ticket = r.random() < .4; first = r.random() < .3; burst = r.choice((1, 1, r.randint(10, 80)))
    prior = r.choice((None, None, None, "logging.stop", "iam.key.create", "role.assume.from_unusual_principal", "policy.attach.admin"))
    a = {"source": prod, "operation": op, "identity_type": ident, "mfa_present": mfa, "source_network": "external" if ext else "corporate",
         "prior_operation_last_10m": prior,
         "change_ticket": f"CHG-{r.randint(100000, 999999)}" if ticket else None, "first_time_for_identity": first,
         "api_calls_last_5m": burst, "region": r.choice(("ap-south-1", "ap-south-1", "us-east-1", "eu-north-1"))}
    actor = f"{ident}-{r.randint(10, 99)}"
    if op == "logging.stop": s.append(Sig("audit logging stopped", "strong", "T1562.008"))
    if op in ("storage.policy.public", "network.ingress.open"): s.append(Sig(f"{op} widens exposure", "strong", "T1562", change_related=True))
    if op in ("iam.key.create", "iam.user.create") and ident in ("workload_identity", "contractor"): s.append(Sig(f"{op} by a {ident}", "strong", "T1098"))
    if op == "secret.read" and burst >= 10: s.append(Sig(f"{burst} secret reads in 5 min", "strong", "T1552"))
    if prior and prior != op: s.append(Sig(f"preceded by {prior} within 10 min", "strong", {"logging.stop": "T1562.008", "iam.key.create": "T1098",
                                            "role.assume.from_unusual_principal": "T1078.004", "policy.attach.admin": "T1098.003"}[prior]))
    if not mfa and ident.startswith("human"): s.append(Sig("no MFA on a human identity", "weak"))
    if ext: s.append(Sig("call from an external network", "weak"))
    if first: s.append(Sig("first time this identity performed the operation", "weak"))
    if a["region"] not in ("ap-south-1",): s.append(Sig(f"unused region {a['region']}", "weak"))
    return Built(a, s, [("revoke_sessions", actor), ("rotate_credential", actor), ("snapshot_forensic", prod)],
                 [("monitor", actor), ("notify_user", "cloud-security")], actor, "cloudctl")


DOMAINS = {"identity": identity, "api": api, "netpolicy": netpolicy, "dlp": dlp, "transaction": transaction,
           "wireless": wireless, "cloudctl": cloudctl}


# --------------------------------------------------------------------------- the policy

def decide(b: Built, r: random.Random) -> tuple[str, float, list, list, list, str]:
    approved = bool(b.alert.get("change_ticket")) and b.alert.get("inside_change_window", True) and \
        b.alert.get("operator_source", "bastion") == "bastion"
    live = [s for s in b.signals if not (approved and s.change_related)]
    strong = [s for s in live if s.strength == "strong"]; weak = [s for s in live if s.strength == "weak"]
    none = [s for s in b.signals if s.strength == "none"]
    texts = [f"strong: {s.text}" for s in strong] + [f"weak: {s.text}" for s in weak]
    if none:
        texts.append("not signals: " + "; ".join(s.text for s in none[:3]))
    if not strong and not weak:
        texts.insert(0, "no anomalous field — values within the actor's baseline")
    techs = list(dict.fromkeys(s.technique for s in live if s.technique))
    if approved and any(s.change_related for s in b.signals):
        texts.append(f"change covered by {b.alert['change_ticket']} inside its window from the bastion")
    ignore = (f" Ordinary fields ({'; '.join(s.text for s in none[:2])}) carry no weight." if none else "")
    if len(strong) >= 2 or (len(strong) == 1 and len(weak) >= 2):
        if len(strong) >= 2:
            why = (f"Two independent strong signals — {strong[0].text}; {strong[1].text} — corroborate each other, and neither has a benign "
                   f"explanation that also explains the other.")
        else:
            why = (f"One strong signal ({strong[0].text}) corroborated by two independent weak ones ({weak[0].text}; {weak[1].text}) — "
                   f"together they rule out the innocent explanation.")
        why += " That is the bar for containment; the actions need an analyst's approval." + ignore
        return "malicious", r.uniform(.84, .96), texts, _acts(b.contain), techs, why
    if len(strong) == 1 or len(weak) >= 2:
        lead = strong[0].text if strong else f"{weak[0].text}; {weak[1].text}"
        why = (f"One strong signal ({lead}) " if strong else f"Weak signals only ({lead}) ") + \
              "— enough to verify with the owner and hold the sensitive action, not enough to call it an attack: misconfiguration, travel and automation produce the same single field." + ignore
        return "suspicious", r.uniform(.56, .74), texts, _acts(b.verify), techs, why
    why = ("The change is ticketed, inside its window and from the expected place; the alert fired on impact, not on wrongdoing." if approved
           else "Nothing in the fields departs from this actor's normal pattern beyond ordinary noise; " +
                (f"{weak[0].text} alone is not corroborated. " if weak else "") +
                "Screen sizes, session counts within baseline, locales and response times are not signals. No action.")
    return "benign", r.uniform(.78, .92), texts, _acts([("allow", b.actor)] + ([("monitor", b.actor)] if weak else [])), [], why


def generate_corroboration(n: int, *, seed: int = 7, val_pct: int = 15) -> list[dict]:
    """``n`` raw-field rows, rejection-balanced to ~35/35/30 across the three verdicts per domain."""
    r = random.Random(seed)
    names = list(DOMAINS); per = n // len(names) + 1
    quota = {d: {"benign": int(per * .35) + 1, "suspicious": int(per * .35) + 1, "malicious": int(per * .3) + 1} for d in names}
    rows: list[dict] = []; seen: set[str] = set(); guard = 0
    while len(rows) < n and guard < n * 40:
        guard += 1
        d = r.choice(names)
        b = DOMAINS[d](r)
        verdict, conf, sig, acts, techs, why = decide(b, r)
        if quota[d][verdict] <= 0:
            continue
        alert = {"id": f"COR-{r.getrandbits(24):06X}", "observed_at": P._ts(r), **b.alert}
        fp = fingerprint(alert)
        if fp in seen:
            continue
        seen.add(fp); quota[d][verdict] -= 1
        target = {"verdict": verdict, "confidence": round(conf, 2), "key_signals": sig, "recommended_actions": acts,
                  "techniques": techs, "rationale": why}
        rows.append({"id": f"cor-{fp[:16]}", "split": split_for(fp, val_pct), "label_source": LABEL_SOURCE, "origin": ORIGIN,
                                  "provenance": {"domain": d, "strong": sum(1 for s in b.signals if s.strength == "strong"),
                                    "weak": sum(1 for s in b.signals if s.strength == "weak")},
                     "messages": [{"role": "system", "content": TRIAGE_SYSTEM_PROMPT},
                                  {"role": "user", "content": json.dumps(alert, sort_keys=True, ensure_ascii=False)},
                                  {"role": "assistant", "content": json.dumps(target, ensure_ascii=False)}]})
    return rows


__all__ = ["DOMAINS", "LABEL_SOURCE", "ORIGIN", "decide", "generate_corroboration"]
