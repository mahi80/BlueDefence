"""Profile-driven rows for the products Sigma covers thinly (CISO assessment stack).

Sigma gives us ~30 proxy and ~13 web-server rules, nothing for ZPA, Defender for Identity /
Cloud Apps / Office 365, Sophos Firewall, or native XSOAR incidents. These generators fill
those with each product's *real field vocabulary* and — the important part — a verdict that
is a function of the **combination** of field values, never of one field:

    WAF        attack class × action × rate × signatures × bot class × target × pen-test ticket
    Zscaler    category × action × domain age × beacon regularity × DLP hit × device posture
    ZPA        app sensitivity × device posture × geo/time × policy decision × travel
    MDI        alert class × privileged account × source role × evidence × honeytoken × approved replication
    MDCA       OAuth scope × publisher × consent count × mass-download rate × sanctioned app
    MDO        delivery action × click × detonation verdict × user report × sender auth
    Sophos FW  IPS class × direction × action × zones × ATP call-home
    XSOAR      DBotScore on the key indicator × active × duplicate-of-closed

Severity fields come from overlapping per-verdict ranges (never a label). Every row carries
``label_source="public:products"`` and ``provenance.profile``. No payloads anywhere — attack
classes are categorical, exactly as the products report them.
"""

from __future__ import annotations

import json
import random

from ..export import TRIAGE_SYSTEM_PROMPT
from ..schema import fingerprint, split_for
from ..synth import ALWAYS_HITL
from . import _products as P
from .tls_identity import ct_event, tls_block

LABEL_SOURCE = "public:products"
ORIGIN = "products/v1"


def _acts(pairs):
    return [{"action_type": a, "target": t, "requires_hitl": a in ALWAYS_HITL} for a, t in pairs]


def _row(alert: dict, verdict: str, conf: float, signals: list, actions: list, techniques: list, rationale: str,
         profile: str, val_pct: int) -> dict:
    target = {"verdict": verdict, "confidence": round(conf, 2), "key_signals": signals, "recommended_actions": actions,
              "techniques": techniques if verdict != "benign" else [], "rationale": rationale}
    fp = fingerprint(alert)
    return {"id": f"prod-{fp[:16]}", "split": split_for(fp, val_pct), "label_source": LABEL_SOURCE, "origin": ORIGIN,
            "provenance": {"profile": profile},
            "messages": [{"role": "system", "content": TRIAGE_SYSTEM_PROMPT},
                         {"role": "user", "content": json.dumps(alert, sort_keys=True, ensure_ascii=False)},
                         {"role": "assistant", "content": json.dumps(target, ensure_ascii=False)}]}


# --------------------------------------------------------------------------- WAF (Imperva / F5)

_WAF_CLASSES = ("SQL Injection", "Cross Site Scripting", "Remote File Inclusion", "Path Traversal", "Command Injection",
                "Illegal Resource Access", "Bot Access Control", "Credential Stuffing", "DDoS", "Scanner Activity")
_WAF_TARGETS = (("/login", "auth"), ("/api/transfer", "payment"), ("/api/cards/limit", "payment"), ("/static/js/app.js", "static"),
                ("/robots.txt", "static"), ("/api/accounts/statement", "data"), ("/.env", "probe"), ("/wp-admin", "probe"))


def waf(r: random.Random, val_pct: int) -> dict:
    cls = r.choice(_WAF_CLASSES)
    url, tclass = r.choice(_WAF_TARGETS)
    action = r.choices(("blocked", "alerted", "passed"), weights=(0.55, 0.25, 0.20))[0]
    rate = r.choice((r.randint(1, 8), r.randint(10, 60), r.randint(80, 300), r.randint(300, 1500)))
    sigs = r.choice((1, 1, r.randint(2, 6), r.randint(8, 60)))
    bot = r.choice(("Human", "Unclassified", "Known Bad Bot", "Headless browser", "Good Bot"))
    rep = r.choice(("clean", "clean", "known_scanner", "tor_exit", "cloud_hosting"))
    pt = r.random() < .12
    distinct_users = r.randint(1, 3) if cls != "Credential Stuffing" else r.randint(40, 3000)
    status = r.choice((200, 403, 404, 500))
    vendor = r.choice(("imperva", "f5"))
    ev = {"c-uri": url, "cs-method": "POST" if tclass in ("auth", "payment") else "GET"}
    base = (P.imperva if vendor == "imperva" else P.f5_asm)(r, "suspicious", ev, title=cls, attack_type=cls)
    base["action" if vendor == "imperva" else "request_status"] = {"blocked": "REQ_BLOCKED_SECURITY", "alerted": "REQ_CHALLENGE",
                                                                    "passed": "REQ_PASSED"}[action] if vendor == "imperva" else action
    base["requests_per_min"] = rate; base["distinct_signatures"] = sigs; base["bot_classification"] = bot
    base["client_reputation"] = rep; base["target_class"] = tclass; base["http_status"] = status
    base["distinct_usernames_attempted"] = distinct_users
    if pt:
        base["pentest_window"] = {"ticket": f"PT-{r.randint(1000, 9999)}", "source_in_approved_range": r.random() < .85}
    proxy = r.random() < .15
    tls, tls_sig = tls_block(r, user_agent=base.get("user_agent", ""), tokens=False,
                             context={"known_inspection_proxy": "Zscaler ZIA egress"} if proxy else {})
    base["tls_identity"] = tls
    if proxy:
        base["source_known_inspection_proxy"] = "Zscaler ZIA egress"
    tls_strong = [t for t in tls_sig if t[1] == "strong"]; tls_weak = [t for t in tls_sig if t[1] == "weak"]
    ip = base.get("client_ip") or base.get("ip_client")
    # ---- policy: the combination decides
    if pt and base["pentest_window"]["source_in_approved_range"]:
        v, c = "benign", r.uniform(.8, .92)
        sig = [f"{cls} during approved pen-test window {base['pentest_window']['ticket']}", "source inside the approved range"]
        acts = _acts([("allow", ip), ("monitor", ip)]); tech = []
        why = "Attack-class traffic inside an approved penetration-test window from the approved source range is the test itself. Allow and keep the window under watch."
    elif action == "passed" and tclass in ("auth", "payment", "data") and status == 200 and cls not in ("Scanner Activity", "DDoS", "Bot Access Control"):
        v, c = "malicious", r.uniform(.85, .96)
        sig = [f"{cls} request reached {url} unblocked", "HTTP 200 on a sensitive endpoint", f"client reputation {rep}"]
        acts = _acts([("block", ip), ("snapshot_forensic", url), ("notify_user", "app-owner")]); tech = ["T1190"]
        why = f"A {cls.lower()} request passed the WAF and the sensitive endpoint answered 200 — possible successful exploitation, not a probe. Block the source and preserve the request for the app team."
    elif cls == "Credential Stuffing" and distinct_users >= 40 and action != "blocked":
        v, c = "malicious", r.uniform(.84, .95)
        sig = [f"{distinct_users} distinct usernames from one source", f"{rate}/min against {url}", f"bot class {bot}"]
        acts = _acts([("block", ip), ("throttle", url), ("notify_user", "fraud-team")]); tech = ["T1110.004"]
        why = "Many distinct usernames from one automated source against the login endpoint is credential stuffing in progress; block the source and warn fraud so matching successes can be reviewed."
    elif rate >= 300 and sigs >= 8:
        v, c = "malicious", r.uniform(.82, .93)
        sig = [f"sustained {rate}/min with {sigs} distinct signatures", f"target class {tclass}", f"action {action}"]
        acts = _acts([("block", ip), ("throttle", url)]); tech = ["T1190", "T1595.002"]
        why = f"A sustained multi-signature campaign ({sigs} signatures at {rate}/min) is a tooling-driven attack even while blocked; block the source so it cannot find the gap the WAF misses."
    elif rep == "known_scanner" and action == "blocked" and tclass in ("static", "probe"):
        v, c = "benign", r.uniform(.78, .9)
        sig = ["known internet scanner", f"blocked probe of {url}", "no sensitive target"]
        acts = _acts([("allow", ip), ("monitor", ip)]); tech = []
        why = "Blocked background scanning of a non-sensitive path from a known scanner is internet noise; nothing to act on beyond the block already applied."
    elif action == "blocked" and sigs <= 2 and rate < 60:
        v, c = "suspicious", r.uniform(.55, .7)
        sig = [f"single {cls} signature, blocked", f"{rate}/min", f"reputation {rep}"]
        acts = _acts([("throttle", ip), ("monitor", ip)]); tech = ["T1595"]
        why = "One blocked signature at a low rate is a probe, not a compromise; slow the source and watch for escalation rather than block outright."
    else:
        v, c = "suspicious", r.uniform(.58, .74)
        sig = [f"{cls} {action} at {rate}/min", f"bot class {bot}", f"target {url}"]
        acts = _acts([("throttle", ip), ("monitor", url), ("notify_user", "app-owner")]); tech = ["T1190"]
        why = f"{cls} traffic at a moderate rate with mixed indicators — enough to throttle and watch the endpoint, not enough to call it a confirmed attack."
    # TLS identity corroborates: a lying client turns a probe into an attacker, a clean one adds nothing
    sig += [f"tls: {t[0]}" for t in tls_strong + tls_weak] + [f"not a signal: {t[0]}" for t in tls_sig if t[1] == "none"][:1]
    tech += [t[2] for t in tls_strong if t[2] and t[2] not in tech]
    if tls_strong and v == "suspicious":
        v, c = "malicious", r.uniform(.84, .94)
        acts = _acts([("block", ip), ("snapshot_forensic", url), ("notify_user", "app-owner")])
        why += f" The TLS identity settles it: {tls_strong[0][0]} — a client that lies about what it is, combined with the probe, is an attacker, not a scanner."
    elif tls_strong and v == "benign" and not pt:
        v, c = "suspicious", r.uniform(.58, .72)
        acts = _acts([("throttle", ip), ("monitor", ip)])
        why = f"Traffic itself is unremarkable, but {tls_strong[0][0]}. One strong identity signal: throttle and watch for a second."
    elif len(tls_weak) >= 2 and v == "benign" and not pt:
        v, c = "suspicious", r.uniform(.55, .66)
        acts = _acts([("monitor", ip)])
        why = f"Weak TLS signals only ({tls_weak[0][0]}; {tls_weak[1][0]}) — watch, nothing more."
    return _row(base, v, c, sig, acts, tech, why, f"waf/{vendor}", val_pct)


# --------------------------------------------------------------------------- Zscaler ZIA / ZPA

def zia(r: random.Random, val_pct: int) -> dict:
    cat = r.choice(("Newly Registered Domains", "Malicious Content", "Anonymizer", "File Sharing", "Web Mail", "Finance",
                    "Business and Economy", "Internet Services", "Unknown"))
    action = r.choice(("Allowed", "Blocked", "Cautioned"))
    domain_age_days = r.choice((r.randint(0, 6), r.randint(7, 90), r.randint(400, 5000)))
    reqs_last_hour = r.choice((r.randint(1, 5), r.randint(20, 59), r.randint(60, 120)))
    interval_sd = round(r.choice((r.uniform(0.0, 1.5), r.uniform(5, 60), r.uniform(100, 900))), 1)
    dlp = r.choice(("None", "None", "None", "PAN", "Aadhaar", "Customer KYC"))
    dlp_count = 0 if dlp == "None" else r.choice((r.randint(1, 4), r.randint(50, 5000)))
    managed = r.random() < .8
    exception = r.random() < .1
    bytes_out = r.choice((r.randint(200, 4000), r.randint(50_000, 900_000), r.randint(5_000_000, 400_000_000)))
    base = P.zscaler(r, "suspicious", {"url": f"https://{'h' + str(r.randint(10, 99))}.example-net.{r.choice(('io', 'xyz', 'com'))}/{r.choice(('', 'c/', 'api/', 'dl/'))}"}, title=cat)
    base.update({"urlcategory": cat, "action": action, "domain_age_days": domain_age_days, "requests_last_hour": reqs_last_hour,
                 "request_interval_stddev_s": interval_sd, "dlpdictionaries": dlp, "dlp_match_count": dlp_count,
                 "device_managed": managed, "bytes_out": bytes_out, "ssl_inspected": r.random() < .85,
                 "referer_present": r.random() < .6})
    if exception:
        base["category_exception"] = {"ticket": f"CHG-{r.randint(100000, 999999)}", "approved_by": "sec-ops"}
    host = base["clientIP"]; user = base["user"]; dom = base["url"].split("/")[2]
    if exception:
        v, c = "benign", r.uniform(.8, .92)
        sig = [f"category {cat} covered by approved exception {base['category_exception']['ticket']}"]
        acts = _acts([("allow", user), ("monitor", user)]); tech = []
        why = "The category hit is covered by an approved policy exception; this is the exception working as designed."
    elif action == "Allowed" and domain_age_days < 7 and reqs_last_hour >= 20 and interval_sd < 1.5 and bytes_out < 4000:
        v, c = "malicious", r.uniform(.86, .96)
        sig = [f"domain registered {domain_age_days} days ago", f"{reqs_last_hour} requests/hour at fixed intervals (sd {interval_sd}s)",
               "tiny payloads, no referer" if not base["referer_present"] else "tiny payloads"]
        acts = _acts([("isolate", host), ("block", dom), ("snapshot_forensic", host)]); tech = ["T1071.001", "T1568"]
        why = "Metronomic small requests to a days-old domain is beaconing, not browsing. Isolate the host and block the domain; the regularity is the tell."
    elif dlp != "None" and dlp_count >= 50 and cat in ("File Sharing", "Web Mail") and action != "Blocked":
        v, c = "malicious", r.uniform(.84, .95)
        sig = [f"{dlp_count} {dlp} matches leaving to {cat}", f"{bytes_out} bytes out", "personal destination" ]
        acts = _acts([("block_export", user), ("revoke_sessions", user), ("notify_user", "dpo")]); tech = ["T1567.002"]
        why = f"Bulk {dlp} data ({dlp_count} matches) uploaded to a personal {cat.lower()} destination is exfiltration of regulated data; stop the export and preserve the session."
    elif cat == "Malicious Content" and action == "Blocked":
        v, c = "suspicious", r.uniform(.56, .72)
        sig = ["malicious-content download blocked", f"user {user}", f"device managed={managed}"]
        acts = _acts([("notify_user", user), ("monitor", host)]); tech = ["T1204.001"]
        why = "The download was blocked, so nothing executed — but the user reached a malicious page, so warn them and watch the host for a retry."
    elif cat == "Anonymizer" and action != "Blocked" and managed:
        v, c = "suspicious", r.uniform(.58, .74)
        sig = ["anonymizer traffic from a managed device", f"{bytes_out} bytes out"]
        acts = _acts([("monitor", user), ("notify_user", user), ("throttle", host)]); tech = ["T1090.003"]
        why = "Proxy/anonymizer use from a managed device evades inspection; usually policy breach rather than compromise — monitor and ask the user."
    elif dlp != "None" and dlp_count < 5 and cat in ("Finance", "Business and Economy", "Internet Services"):
        v, c = "benign", r.uniform(.78, .9)
        sig = [f"{dlp_count} {dlp} match(es) to a sanctioned business destination"]
        acts = _acts([("allow", user), ("monitor", user)]); tech = []
        why = "A handful of regulated-data matches sent to a sanctioned business destination is ordinary work (a form, a statement); no action."
    elif action == "Allowed" and domain_age_days > 400 and reqs_last_hour < 20:
        v, c = "benign", r.uniform(.8, .93)
        sig = ["established domain", "human-paced browsing", f"category {cat}"]
        acts = _acts([("allow", user)]); tech = []
        why = "Human-paced traffic to an established domain in a routine category — normal browsing."
    else:
        v, c = "suspicious", r.uniform(.55, .7)
        sig = [f"category {cat} {action.lower()}", f"domain age {domain_age_days}d", f"{reqs_last_hour}/h"]
        acts = _acts([("monitor", host), ("notify_user", user)]); tech = ["T1071.001"]
        why = "Mixed indicators — unusual category or young domain without the regularity or volume of an attack; watch and ask the user."
    return _row(base, v, c, sig, acts, tech, why, "zscaler/zia", val_pct)


_ZPA_APPS = (("core-banking-admin", "critical"), ("cbs-reporting", "high"), ("hr-portal", "medium"), ("wiki", "low"),
             ("jump-host-prod", "critical"), ("jira", "low"), ("swift-gateway", "critical"))


def zpa(r: random.Random, val_pct: int) -> dict:
    app, sens = r.choice(_ZPA_APPS)
    posture = r.choice(("managed_compliant", "managed_compliant", "managed_noncompliant", "unmanaged"))
    decision = r.choice(("allow", "allow", "block"))
    hour = r.randint(0, 23)
    geo = r.choice(("IN-MH", "IN-UP", "IN-KA", "SG", "AE", "RU", "NG"))
    prev_geo = r.choice(("IN-MH", "IN-UP", "IN-KA"))
    mins_since_prev = r.choice((r.randint(2, 30), r.randint(120, 600)))
    privileged = r.random() < .3
    ticket = f"CHG-{r.randint(100000, 999999)}" if r.random() < .25 else None
    alert = {"source": "Zscaler ZPA", "timestamp": P._ts(r), "event": "AppAccess", "application": app, "app_sensitivity": sens,
             "user": f"{P._user(r)}@bank.in", "user_privileged": privileged, "device_posture": posture,
             "posture_profile": r.choice(("crowdstrike_running", "disk_encrypted", "os_patched", "none")),
             "policy_decision": decision, "client_geo": geo, "previous_session_geo": prev_geo,
             "minutes_since_previous_session": mins_since_prev, "local_hour": hour, "connector_group": r.choice(("mum-dc1", "noida-dc2")),
             "change_ticket": ticket, "session_duration_s": r.randint(10, 7200)}
    user = alert["user"]
    far = geo not in ("IN-MH", "IN-UP", "IN-KA")
    if decision == "block":
        v, c = "benign" if sens in ("low", "medium") else "suspicious", r.uniform(.7, .88)
        sig = [f"policy blocked access to {app}", f"posture {posture}"]
        acts = _acts([("monitor", user)] + ([("notify_user", user)] if v == "suspicious" else [])); tech = [] if v == "benign" else ["T1078"]
        why = ("Zero-trust policy already denied the request; " + ("low-sensitivity app, nothing further." if v == "benign" else
               "a denied attempt at a critical app is worth a look at who tried and why."))
    elif far and mins_since_prev <= 30 and sens in ("critical", "high") and decision == "allow":
        v, c = "malicious", r.uniform(.86, .96)
        sig = [f"session from {geo} {mins_since_prev} min after one from {prev_geo}", f"access allowed to {app} ({sens})", f"posture {posture}"]
        acts = _acts([("revoke_sessions", user), ("lock_account", user), ("notify_user", "soc-lead")]); tech = ["T1078", "T1021"]
        why = f"Impossible travel straight into a {sens}-sensitivity private app is a stolen session or credential, not a user; revoke and lock while the SOC confirms."
    elif posture == "unmanaged" and sens == "critical" and decision == "allow" and not ticket:
        v, c = "malicious" if (hour < 6 or hour > 22) else "suspicious", r.uniform(.6, .9)
        sig = [f"unmanaged device allowed into {app}", f"local hour {hour:02d}", "no change ticket"]
        acts = _acts([("revoke_sessions", user), ("challenge", user), ("notify_user", "soc-lead")] if v == "malicious" else [("challenge", user), ("monitor", user)])
        tech = ["T1078"]
        why = ("An unmanaged device reaching a critical app out of hours with no ticket is the posture policy failing open; revoke and step-up." if v == "malicious"
               else "An unmanaged device reaching a critical app is a posture gap; step-up authentication and confirm the user before anything else.")
    elif ticket and privileged and sens == "critical":
        v, c = "benign", r.uniform(.82, .93)
        sig = [f"privileged access to {app} under {ticket}", f"posture {posture}", f"geo {geo}"]
        acts = _acts([("allow", user), ("monitor", user)]); tech = []
        why = "Privileged access to a critical app under a change ticket from a compliant device is the planned work; allow and keep the session logged."
    elif posture == "managed_noncompliant" and sens in ("high", "critical"):
        v, c = "suspicious", r.uniform(.56, .72)
        sig = [f"non-compliant posture ({alert['posture_profile']} failing) into {app}"]
        acts = _acts([("challenge", user), ("notify_user", user), ("monitor", user)]); tech = ["T1078"]
        why = "A managed but non-compliant device in a sensitive app is a hygiene issue more than an attack; step-up and get the device fixed."
    else:
        v, c = "benign", r.uniform(.8, .94)
        sig = [f"routine access to {app}", f"compliant posture, geo {geo}"]
        acts = _acts([("allow", user)]); tech = []
        why = "Compliant device, home geography, normal hours, allowed by policy — routine private-app access."
    return _row(alert, v, c, sig, acts, tech, why, "zscaler/zpa", val_pct)


# --------------------------------------------------------------------------- Microsoft Defender family

def mdi(r: random.Random, val_pct: int) -> dict:
    cls = r.choice(("Suspected DCSync attack (replication of directory services)", "Suspected identity theft (pass-the-ticket)",
                    "Suspicious additions to sensitive groups", "Honeytoken activity", "Suspected brute-force attack (Kerberos, NTLM)",
                    "Remote code execution attempt", "Suspected overpass-the-hash attack"))
    src_role = r.choice(("workstation", "workstation", "member_server", "backup_server", "domain_controller"))
    privileged = r.random() < .4
    honeytoken = cls.startswith("Honeytoken")
    failures = r.randint(0, 5000) if "brute" in cls else 0
    success_after = failures > 0 and r.random() < .3
    ticket = f"CHG-{r.randint(100000, 999999)}" if r.random() < .2 else None
    evidence = r.randint(1, 6)
    alert = {"source": "Microsoft Defender for Identity", "AlertId": f"mdi-{r.getrandbits(32):08x}", "Timestamp": P._ts(r),
             "Title": cls, "Severity": P._sev(r, "suspicious", "Low", "Medium", "High"),
             "SourceComputer": {"name": f"{P._host(r)}.corp.bank.in", "role": src_role},
             "DestinationComputer": f"DC{r.randint(1, 4)}.corp.bank.in", "Account": {"name": P._user(r), "privileged": privileged,
             "honeytoken": honeytoken}, "EvidenceCount": evidence, "FailedAttempts": failures, "SuccessAfterFailures": success_after,
             "ChangeTicket": ticket, "Status": "New"}
    host = alert["SourceComputer"]["name"]; user = alert["Account"]["name"]
    if honeytoken:
        v, c = "malicious", r.uniform(.9, .98)
        sig = ["honeytoken account used — no legitimate use exists", f"from {host}"]
        acts = _acts([("isolate", host), ("revoke_sessions", user), ("snapshot_forensic", host)]); tech = ["T1078.002"]
        why = "A honeytoken has exactly one legitimate use: none. Any activity is an attacker who found it. Isolate the source and preserve evidence."
    elif "DCSync" in cls and src_role in ("backup_server", "domain_controller") and ticket:
        v, c = "benign", r.uniform(.8, .92)
        sig = [f"replication from {src_role} under {ticket}"]
        acts = _acts([("allow", host), ("monitor", host)]); tech = []
        why = "Directory replication from a backup server or DC during a ticketed change is the backup product doing its job; the detection fires on the API, not on intent."
    elif "DCSync" in cls or "pass-the-ticket" in cls or "overpass" in cls:
        v, c = "malicious", r.uniform(.86, .96)
        sig = [f"{cls} from a {src_role}", f"account privileged={privileged}", f"{evidence} evidences"]
        acts = _acts([("isolate", host), ("revoke_sessions", user), ("rotate_credential", "krbtgt" if "DCSync" in cls else user)]); tech = ["T1003.006" if "DCSync" in cls else "T1550.003"]
        why = f"{cls.split(' (')[0]} from a {src_role.replace('_', ' ')} has no benign explanation; the attacker already holds domain-level material. Isolate, revoke and rotate."
    elif "brute" in cls and success_after:
        v, c = "malicious", r.uniform(.84, .94)
        sig = [f"{failures} failures then a success", f"account {user}", f"privileged={privileged}"]
        acts = _acts([("lock_account", user), ("revoke_sessions", user), ("isolate", host)]); tech = ["T1110"]
        why = "A success after thousands of failures means the password was found; lock the account and revoke every session before the attacker uses it."
    elif "brute" in cls:
        v, c = "suspicious", r.uniform(.58, .74)
        sig = [f"{failures} failed authentications, no success", f"from {host}"]
        acts = _acts([("monitor", host), ("notify_user", user), ("throttle", host)]); tech = ["T1110"]
        why = "Failures without a success are an attempt, not a breach — and sometimes a misconfigured service account; watch the source and confirm with the owner."
    elif "sensitive groups" in cls and ticket:
        v, c = "benign", r.uniform(.78, .9)
        sig = [f"group change under {ticket}"]
        acts = _acts([("allow", user), ("monitor", user)]); tech = []
        why = "Sensitive-group membership changed under a change ticket is routine identity administration."
    else:
        v, c = "suspicious", r.uniform(.6, .76)
        sig = [cls, f"source {src_role}", f"{evidence} evidences", "no ticket"]
        acts = _acts([("challenge", user), ("monitor", host), ("notify_user", "iam-team")]); tech = ["T1098"]
        why = f"{cls.split(' (')[0]} without a ticket deserves verification with the identity team before anyone is locked out."
    return _row(alert, v, c, sig, acts, tech, why, "defender/identity", val_pct)


def mdca(r: random.Random, val_pct: int) -> dict:
    kind = r.choice(("oauth_consent", "mass_download", "impossible_travel", "unsanctioned_app"))
    scopes = r.sample(("Mail.Read", "Mail.ReadWrite", "Files.ReadWrite.All", "User.Read", "offline_access", "Directory.ReadWrite.All", "Calendars.Read"), r.randint(1, 4))
    verified = r.random() < .6
    consenting = r.choice((1, 1, r.randint(2, 40)))
    files = r.choice((r.randint(1, 20), r.randint(200, 900), r.randint(2000, 50000)))
    window_min = r.choice((5, 15, 60, 480))
    sanctioned = r.random() < .6
    dept = r.choice(P._DEPTS)
    alert = {"source": "Microsoft Defender for Cloud Apps", "AlertId": f"mcas-{r.getrandbits(32):08x}", "Timestamp": P._ts(r),
             "PolicyName": {"oauth_consent": "Risky OAuth app consent", "mass_download": "Mass download by a single user",
                            "impossible_travel": "Impossible travel activity", "unsanctioned_app": "Unsanctioned app usage"}[kind],
             "Severity": P._sev(r, "suspicious", "Low", "Medium", "High"), "User": f"{P._user(r)}@bank.in", "Department": dept,
             "App": r.choice(("Microsoft SharePoint Online", "Microsoft Exchange Online", "Salesforce", "Dropbox", "WeTransfer", "Box")),
             "AppSanctioned": sanctioned}
    if kind == "oauth_consent":
        alert.update({"OAuthApp": {"name": f"{r.choice(('Mail Helper', 'Calendar Sync', 'PDF Tools', 'Signature Pro'))} {r.randint(1, 9)}",
                                   "publisher_verified": verified, "permissions": scopes, "users_consented": consenting,
                                   "first_seen_days_ago": r.choice((r.randint(0, 3), r.randint(30, 900)))}})
    if kind == "mass_download":
        alert.update({"FilesDownloaded": files, "WindowMinutes": window_min, "UserResigning": r.random() < .2,
                      "SensitivityLabels": r.sample(("Confidential", "Internal", "Customer PII", "Public"), r.randint(1, 2))})
    if kind == "impossible_travel":
        alert.update({"Locations": [r.choice(("IN-MH", "IN-KA")), r.choice(("RU", "NG", "SG", "US"))], "MinutesApart": r.randint(5, 180),
                      "DeviceKnown": r.random() < .5})
    user = alert["User"]
    if kind == "oauth_consent":
        broad = any(s.endswith(".All") or s.startswith("Mail.Read") for s in scopes)
        if not verified and broad and alert["OAuthApp"]["first_seen_days_ago"] <= 3:
            v, c = "malicious", r.uniform(.84, .95)
            sig = ["unverified publisher", f"broad scopes {scopes}", f"app first seen {alert['OAuthApp']['first_seen_days_ago']} days ago"]
            acts = _acts([("revoke_sessions", user), ("block", alert["OAuthApp"]["name"]), ("notify_user", "iam-team")]); tech = ["T1528", "T1550.001"]
            why = "A days-old, unverified app granted mailbox/file-wide scopes is consent phishing; revoke the grant and the user's tokens before the mailbox is read."
        elif broad and not verified:
            v, c = "suspicious", r.uniform(.6, .76)
            sig = ["unverified publisher", f"scopes {scopes}", f"{consenting} user(s) consented"]
            acts = _acts([("notify_user", "iam-team"), ("monitor", user), ("challenge", user)]); tech = ["T1528"]
            why = "Broad scopes from an unverified publisher need the identity team's review; established apps can be legitimate, so verify before revoking."
        else:
            v, c = "benign", r.uniform(.8, .92)
            sig = ["verified publisher" if verified else "narrow scopes", f"scopes {scopes}"]
            acts = _acts([("allow", user), ("monitor", user)]); tech = []
            why = "Narrow scopes or a verified publisher on an established app — ordinary SaaS consent."
    elif kind == "mass_download":
        if files >= 2000 and window_min <= 60 and ("Customer PII" in alert["SensitivityLabels"] or alert["UserResigning"]):
            v, c = "malicious", r.uniform(.86, .96)
            sig = [f"{files} files in {window_min} min", f"labels {alert['SensitivityLabels']}", f"resigning={alert['UserResigning']}"]
            acts = _acts([("block_export", user), ("revoke_sessions", user), ("notify_user", "hr")]); tech = ["T1530", "T1567"]
            why = "Thousands of labelled files pulled in under an hour by a user with a departure flag or on customer PII is insider exfiltration; stop it and involve HR."
        elif files >= 200 and window_min <= 60:
            v, c = "suspicious", r.uniform(.58, .74)
            sig = [f"{files} files in {window_min} min", f"department {dept}"]
            acts = _acts([("monitor", user), ("notify_user", user), ("hold", user)]); tech = ["T1530"]
            why = "A burst of downloads can be a sync client or a migration; hold further exports and confirm with the user and their manager."
        else:
            v, c = "benign", r.uniform(.8, .92)
            sig = [f"{files} files over {window_min} min — within normal working volume"]
            acts = _acts([("allow", user)]); tech = []
            why = "Download volume within a normal working pattern for the department; no action."
    elif kind == "impossible_travel":
        if alert["MinutesApart"] <= 60 and not alert["DeviceKnown"]:
            v, c = "malicious", r.uniform(.84, .95)
            sig = [f"{alert['Locations']} {alert['MinutesApart']} min apart", "unknown device"]
            acts = _acts([("revoke_sessions", user), ("lock_account", user)]); tech = ["T1078.004"]
            why = "Two countries within the hour on an unknown device is a stolen session; revoke and lock while the user is contacted."
        else:
            v, c = "suspicious", r.uniform(.56, .72)
            sig = [f"{alert['Locations']} {alert['MinutesApart']} min apart", f"device known={alert['DeviceKnown']}"]
            acts = _acts([("challenge", user), ("notify_user", user)]); tech = ["T1078.004"]
            why = "Impossible travel on a known device is usually a VPN or mobile carrier egress; step-up and confirm rather than lock."
    else:
        if not sanctioned and alert["App"] in ("WeTransfer", "Dropbox"):
            v, c = "suspicious", r.uniform(.55, .7)
            sig = [f"unsanctioned {alert['App']} used by {dept}"]
            acts = _acts([("notify_user", user), ("monitor", user)]); tech = ["T1567.002"]
            why = "Unsanctioned file-sharing is a policy gap; notify and watch for volume before treating it as exfiltration."
        else:
            v, c = "benign", r.uniform(.8, .92)
            sig = [f"{alert['App']} sanctioned={sanctioned}"]
            acts = _acts([("allow", user)]); tech = []
            why = "Approved SaaS use; nothing to triage."
    return _row(alert, v, c, sig, acts, tech, why, f"defender/cloudapps/{kind}", val_pct)


def mdo(r: random.Random, val_pct: int) -> dict:
    delivery = r.choice(("Delivered", "Junked", "Blocked", "Replaced", "Delivered"))
    clicked = r.random() < .35
    detonation = r.choice(("Clean", "Clean", "Malicious", "Suspicious", "NotApplicable"))
    reported = r.random() < .25
    spf, dkim, dmarc = (r.choice(("pass", "fail")) for _ in range(3))
    lookalike = r.random() < .3
    recipients = r.choice((1, r.randint(2, 15), r.randint(40, 600)))
    exec_target = r.random() < .15
    zap = r.random() < .3
    alert = {"source": "Microsoft Defender for Office 365", "AlertId": f"mdo-{r.getrandbits(32):08x}", "Timestamp": P._ts(r),
             "Title": r.choice(("Email messages containing malicious URL removed after delivery", "A potentially malicious URL click was detected",
                                "Email reported by user as malware or phish", "Suspicious email sending patterns", "Phish delivered due to an ETR override")),
             "Severity": P._sev(r, "suspicious", "Informational", "Medium", "High"), "DeliveryAction": delivery, "UrlClicked": clicked,
             "DetonationVerdict": detonation, "UserReported": reported, "SenderAuth": {"spf": spf, "dkim": dkim, "dmarc": dmarc},
             "SenderDomainLookalike": lookalike, "RecipientCount": recipients, "TargetsExecutives": exec_target, "ZapApplied": zap,
             "Recipient": f"{P._user(r)}@bank.in", "AttachmentType": r.choice(("none", "pdf", "xlsx", "html", "iso", "zip"))}
    user = alert["Recipient"]
    if clicked and detonation == "Malicious" and delivery in ("Delivered", "Replaced"):
        v, c = "malicious", r.uniform(.88, .97)
        sig = ["URL clicked", "detonation verdict Malicious", f"delivery {delivery}", f"lookalike sender={lookalike}"]
        acts = _acts([("isolate", "recipient-host"), ("revoke_sessions", user), ("quarantine_message", user), ("notify_user", user)]); tech = ["T1566.002", "T1204.001"]
        why = "The user clicked a link that detonates as malicious and the message was delivered — assume credentials or the host are compromised; isolate, revoke, quarantine."
    elif detonation == "Malicious" and delivery == "Delivered" and recipients >= 40:
        v, c = "malicious", r.uniform(.84, .94)
        sig = [f"malicious detonation delivered to {recipients} recipients", f"DMARC {dmarc}"]
        acts = _acts([("quarantine_message", "campaign"), ("block", "sender-domain"), ("notify_user", "all-recipients")]); tech = ["T1566"]
        why = "A delivered campaign with a malicious detonation across dozens of mailboxes needs campaign-level quarantine and a sender block, before clicks accumulate."
    elif delivery in ("Blocked", "Junked") or zap:
        v, c = "benign" if not clicked else "suspicious", r.uniform(.62, .9)
        sig = [f"delivery {delivery}" + (" + ZAP" if zap else ""), f"clicked={clicked}"]
        acts = _acts([("allow", user)] if v == "benign" else [("notify_user", user), ("monitor", user)]); tech = [] if v == "benign" else ["T1566.002"]
        why = ("The filter stopped it; nothing reached the user." if v == "benign" else "Removed after delivery but the user had already clicked — warn them and watch the account.")
    elif reported and detonation in ("Clean", "NotApplicable") and not lookalike:
        v, c = "benign", r.uniform(.76, .88)
        sig = ["user-reported", "clean detonation", "sender auth " + ("pass" if spf == dkim == dmarc == "pass" else "mixed")]
        acts = _acts([("allow", user), ("notify_user", user)]); tech = []
        why = "A user report with a clean detonation and authenticated sender is a false alarm — thank the reporter, close."
    elif lookalike and exec_target and delivery == "Delivered":
        v, c = "suspicious", r.uniform(.62, .78)
        sig = ["lookalike sender domain", "executive recipient", f"attachment {alert['AttachmentType']}"]
        acts = _acts([("quarantine_message", user), ("notify_user", user), ("monitor", user)]); tech = ["T1566.001", "T1656"]
        why = "A lookalike domain writing to an executive is a BEC setup even with nothing malicious attached; quarantine and brief the recipient."
    else:
        v, c = "suspicious", r.uniform(.55, .7)
        sig = [f"delivery {delivery}", f"detonation {detonation}", f"auth spf={spf} dkim={dkim} dmarc={dmarc}"]
        acts = _acts([("monitor", user), ("notify_user", user)]); tech = ["T1566"]
        why = "Delivered with a mixed signal set and no click — monitor the recipient and let the detonation result settle."
    return _row(alert, v, c, sig, acts, tech, why, "defender/office365", val_pct)


# --------------------------------------------------------------------------- Sophos Firewall + XDR

def sophos_fw(r: random.Random, val_pct: int) -> dict:
    kind = r.choice(("ips", "atp", "web"))
    direction = r.choice(("inbound", "outbound", "lateral"))
    action = r.choice(("drop", "drop", "allow", "reset"))
    src_zone, dst_zone = r.choice((("WAN", "DMZ"), ("LAN", "WAN"), ("LAN", "SERVER"), ("GUEST", "LAN"), ("WAN", "LAN")))
    sig_class = r.choice(("web-application-attack", "attempted-admin", "trojan-activity", "policy-violation", "misc-activity", "scan"))
    hits = r.choice((1, r.randint(2, 20), r.randint(100, 5000)))
    alert = {"source": "Sophos Firewall", "log_type": {"ips": "IDP", "atp": "ATP", "web": "Content Filtering"}[kind], "timestamp": P._ts(r),
             "device_name": f"SFOS-{r.choice(('MUM', 'NOI'))}-{r.randint(1, 4)}", "src_ip": P._ip_int(r) if src_zone != "WAN" else P._ip_ext(r),
             "dst_ip": P._ip_ext(r) if dst_zone == "WAN" else P._ip_int(r), "src_zone": src_zone, "dst_zone": dst_zone,
             "direction": direction, "action": action, "hits_last_hour": hits, "severity": P._sev(r, "suspicious", "Low", "Medium", "High"),
             "user": P._user(r)}
    if kind == "ips":
        alert.update({"signature_class": sig_class, "signature_id": r.randint(10000, 99999), "protocol": r.choice(("TCP", "UDP"))})
    if kind == "atp":
        alert.update({"threat_type": r.choice(("C2/Generic-A", "Mal/Generic-S", "Troj/Beacon-X")), "event": "Call home detected",
                      "domain_reputation": r.choice(("malicious", "suspicious", "unknown"))})
    if kind == "web":
        alert.update({"category": r.choice(("Malware", "Phishing", "Proxies", "Business", "News")), "url_host": f"h{r.randint(1, 999)}.example-net.io"})
    host = alert["src_ip"] if src_zone != "WAN" else alert["dst_ip"]; ip = alert["src_ip"]
    if kind == "atp" and action == "allow":
        v, c = "malicious", r.uniform(.86, .96)
        sig = ["ATP call-home allowed through", f"reputation {alert['domain_reputation']}", f"{hits} hits/hour"]
        acts = _acts([("isolate", host), ("block", alert["dst_ip"]), ("snapshot_forensic", host)]); tech = ["T1071", "T1573"]
        why = "An allowed call-home to a flagged destination means a host inside is talking to C2; isolate it and block the destination at the edge."
    elif kind == "atp":
        v, c = "suspicious", r.uniform(.6, .76)
        sig = ["ATP call-home dropped", f"from {host}", f"{hits} attempts"]
        acts = _acts([("monitor", host), ("notify_user", alert["user"]), ("kill_process", host)]); tech = ["T1071"]
        why = "The firewall dropped the beacon, but something on the host is trying — it needs cleaning even though no data left."
    elif kind == "ips" and direction == "lateral" and sig_class in ("attempted-admin", "trojan-activity") and action == "allow":
        v, c = "malicious", r.uniform(.84, .95)
        sig = [f"{sig_class} LAN→{dst_zone} allowed", f"{hits} hits"]
        acts = _acts([("isolate", ip), ("block", ip), ("snapshot_forensic", ip)]); tech = ["T1210", "T1021"]
        why = "Exploit-class traffic moving laterally inside and allowed through is an intruder already past the perimeter; isolate the source."
    elif kind == "ips" and src_zone == "WAN" and action in ("drop", "reset") and sig_class in ("scan", "misc-activity", "web-application-attack") and hits < 100:
        v, c = "benign", r.uniform(.78, .9)
        sig = [f"inbound {sig_class} dropped at the edge", f"{hits} hits"]
        acts = _acts([("allow", ip), ("monitor", ip)]); tech = []
        why = "Dropped inbound scanning at the perimeter is background internet noise the firewall exists to absorb."
    elif kind == "ips" and hits >= 100:
        v, c = "suspicious", r.uniform(.58, .74)
        sig = [f"{hits} {sig_class} hits/hour", f"{src_zone}→{dst_zone} {action}"]
        acts = _acts([("throttle", ip), ("monitor", ip)]); tech = ["T1595"]
        why = "Sustained volume is a targeted sweep even when dropped; throttle the source and watch for a change in technique."
    elif kind == "web" and alert["category"] in ("Malware", "Phishing") and action == "allow":
        v, c = "suspicious", r.uniform(.6, .76)
        sig = [f"{alert['category']} site reached", f"user {alert['user']}"]
        acts = _acts([("notify_user", alert["user"]), ("monitor", host), ("block", alert["url_host"])]); tech = ["T1566.002"]
        why = "A user reached a malware/phishing-categorised site through the filter; warn them, block the host and watch for follow-on activity."
    else:
        v, c = "benign", r.uniform(.8, .93)
        sig = [f"{alert['log_type']} event {action}", f"{src_zone}→{dst_zone}"]
        acts = _acts([("allow", ip)]); tech = []
        why = "Policy-conformant traffic logged for audit; nothing to triage."
    return _row(alert, v, c, sig, acts, tech, why, f"sophos/firewall/{kind}", val_pct)


# --------------------------------------------------------------------------- Cortex XSOAR native

def xsoar_native(r: random.Random, val_pct: int) -> dict:
    itype = r.choice(("Phishing", "Malware", "Access", "Cloud Alert", "Threat Intel Match", "Vulnerability"))
    score = r.choice((0, 1, 2, 3, 3))
    active = r.random() < .6
    dup_closed = r.random() < .15
    linked = r.randint(0, 6)
    alert = {"source": "Cortex XSOAR", "incident_id": str(r.randint(100000, 999999)), "type": itype, "occurred": P._ts(r),
             "severity": r.randint(0, 4), "status": "Pending", "playbook": f"{itype.replace(' ', '-')}-Investigation",
             "owner": "", "labels": [{"type": "Brand", "value": r.choice(("Sentinel", "CrowdStrike", "Zscaler", "Imperva"))}],
             "indicators": [{"type": r.choice(("IP", "Domain", "File SHA256", "URL", "Account")), "dbot_score": score,
                             "sources": r.sample(("VirusTotal", "Recorded Future", "AlienVault OTX", "Internal TI"), r.randint(1, 3)),
                             "first_seen_days": r.randint(0, 400)}],
             "indicator_active_in_env": active, "linked_incidents": linked,
             "duplicate_of_closed": {"incident_id": str(r.randint(100000, 999999)), "close_reason": "False Positive"} if dup_closed else None}
    ind = alert["indicators"][0]; tgt = f"{ind['type']} indicator"
    if dup_closed and score <= 1:
        v, c = "benign", r.uniform(.78, .9)
        sig = [f"duplicate of incident {alert['duplicate_of_closed']['incident_id']} closed as False Positive", f"DBotScore {score}"]
        acts = _acts([("allow", tgt), ("monitor", tgt)]); tech = []
        why = "Same indicator as an incident already closed as a false positive with no new reputation — close as duplicate."
    elif score == 3 and active:
        v, c = "malicious", r.uniform(.86, .96)
        sig = [f"DBotScore 3 ({', '.join(ind['sources'])})", "indicator currently active in the environment", f"{linked} linked incidents"]
        acts = _acts([("block", tgt), ("isolate", "affected-host"), ("snapshot_forensic", "affected-host")]); tech = ["T1071" if ind["type"] in ("IP", "Domain", "URL") else "T1204"]
        why = "A bad-reputation indicator that is live in the estate is an active compromise path; block it and isolate what touched it."
    elif score == 3:
        v, c = "suspicious", r.uniform(.6, .76)
        sig = [f"DBotScore 3 but not observed active", f"first seen {ind['first_seen_days']} days ago"]
        acts = _acts([("block", tgt), ("monitor", tgt)]); tech = ["T1071"]
        why = "Known-bad reputation with no current activity: pre-emptive block is cheap; no host action until something talks to it."
    elif score == 2 and (active or linked >= 2):
        v, c = "suspicious", r.uniform(.56, .72)
        sig = [f"DBotScore 2 (suspicious)", f"active={active}", f"{linked} linked incidents"]
        acts = _acts([("monitor", tgt), ("notify_user", "ti-team")]); tech = ["T1071"]
        why = "Suspicious reputation plus activity or repeat sightings earns a watch and a TI review, not containment."
    else:
        v, c = "benign", r.uniform(.78, .92)
        sig = [f"DBotScore {score}", f"active={active}", f"{linked} linked"]
        acts = _acts([("allow", tgt)]); tech = []
        why = "Low or unknown reputation with no activity — close without action."
    return _row(alert, v, c, sig, acts, tech, why, f"xsoar/{itype}", val_pct)


# --------------------------------------------------------------------------- forged tokens / mTLS at the API gateway

def token_forgery(r: random.Random, val_pct: int) -> dict:
    gw = r.choice(("Apigee", "Kong Gateway", "AWS API Gateway", "Azure APIM"))
    ua = r.choice(("okhttp/4.12 (Android 14)", "Mozilla/5.0 (Windows NT 10.0; Win64) Chrome/130", "python-requests/2.32", "curl/8.4.0"))
    rotation = r.random() < .15; monitor = r.random() < .1
    ctx = {}
    if rotation: ctx["key_rotation_window"] = True
    if monitor: ctx["monitor_allowlisted"] = True
    tls, sig_t = tls_block(r, user_agent=ua, tokens=True, mtls=r.random() < .5, context=ctx)
    ip = P._ip_ext(r); principal = P._user(r)
    a = {"source": gw, "api": r.choice(("/v2/accounts/{id}", "/v2/transfer", "/v2/cards/{id}", "/v2/kyc/{id}")), "client_ip": ip,
         "principal_id": principal, "user_agent": ua, "tls_identity": tls, "requests_15m": r.randint(3, 900),
         "responses_401_15m": tls["tokens"]["signature_failures_15m"] if "tokens" in tls else 0,
         "responses_200_15m": r.randint(0, 50), "response_time_ms": r.randint(20, 300)}
    if rotation: a["context"] = {"key_rotation_window": {"started_minutes_ago": r.randint(1, 20), "old_kid": "k-2026-09"}}
    if monitor: a["context"] = {**a.get("context", {}), "synthetic_monitor": {"vendor": "Datadog Synthetics", "allowlisted_source": True}}
    strong = [t for t in sig_t if t[1] == "strong"]; weak = [t for t in sig_t if t[1] == "weak"]; none = [t for t in sig_t if t[1] == "none"]
    sig = [f"strong: {t[0]}" for t in strong] + [f"weak: {t[0]}" for t in weak] + (["not signals: " + "; ".join(t[0] for t in none[:2])] if none else [])
    tech = list(dict.fromkeys(t[2] for t in strong if t[2]))
    if len(strong) >= 2 or (len(strong) == 1 and len(weak) >= 2):
        v, c = "malicious", r.uniform(.86, .96)
        acts = _acts([("block", ip), ("revoke_sessions", principal), ("rotate_credential", "api-signing-key" if any("confusion" in t[0] or "alg=none" in t[0] for t in strong) else principal), ("notify_user", "iam-team")])
        why = (f"Forged identity at the gateway: {strong[0][0]}; " + (strong[1][0] if len(strong) > 1 else f"{weak[0][0]}; {weak[1][0]}") +
               ". A client that forges tokens or presents keys that are not ours is an attacker by construction; block, revoke, and rotate what it touched.")
    elif len(strong) == 1 or len(weak) >= 2:
        v, c = "suspicious", r.uniform(.56, .74)
        acts = _acts([("throttle", ip), ("challenge", principal), ("monitor", principal)])
        why = (f"One identity signal ({strong[0][0] if strong else weak[0][0] + '; ' + weak[1][0]}) — a misconfigured client and an attacker look the same here; throttle and step up before blocking.")
    else:
        v, c = "benign", r.uniform(.8, .93)
        acts = _acts([("allow", principal)])
        why = ("Tokens verify, certificate is ours, fingerprint matches the client" + (" — failures are the key-rotation cache, expected" if rotation else "") + ". No action.")
    return _row(a, v, c, sig, acts, tech, why, "gateway/token-forgery", val_pct)


def ct_watch(r: random.Random, val_pct: int) -> dict:
    a, sig_t, domain = ct_event(r)
    a = {**a, "observed_by": r.choice(("crt.sh poll", "Sentinel CT connector", "Censys watch"))}
    strong = [t for t in sig_t if t[1] == "strong"]; weak = [t for t in sig_t if t[1] == "weak"]; none = [t for t in sig_t if t[1] == "none"]
    sig = [f"strong: {t[0]}" for t in strong] + [f"weak: {t[0]}" for t in weak] + ([f"not signals: {none[0][0]}"] if none else [])
    tech = list(dict.fromkeys(t[2] for t in strong if t[2]))
    if len(strong) >= 2:
        key_leak = a["event"] == "cert_seen_on_host"
        v, c = "malicious", r.uniform(.86, .96)
        acts = _acts([("rotate_credential", f"{domain} private key"), ("escalate", "ciso"), ("notify_user", "ca-contact")] if key_leak
                     else [("escalate", "ciso"), ("notify_user", "ca-contact"), ("block", domain)])
        why = (f"{strong[0][0]}; {strong[1][0]}. " + ("Our key is being used where we are not: treat the private key as compromised — rotate, then ask the CA to revoke."
               if key_leak else "A certificate for our name from a CA we never use, with no ACME account of ours behind it, is impersonation in progress: escalate and get it revoked."))
    elif strong:
        v, c = "suspicious", r.uniform(.6, .76)
        acts = _acts([("monitor", domain), ("notify_user", "brand-protection"), ("block", domain)])
        why = f"{strong[0][0]}. Lookalike certificates precede phishing campaigns; block the domain at the proxy and hand it to brand protection — nothing of ours is compromised."
    else:
        v, c = "benign", r.uniform(.82, .94)
        acts = _acts([("allow", domain)])
        why = "Our CA, our ACME account, on schedule — the renewal we planned."
    return _row(a, v, c, sig, acts, tech, why, "ct/watch", val_pct)


PROFILES = {"waf": waf, "token_forgery": token_forgery, "ct_watch": ct_watch, "zia": zia, "zpa": zpa, "mdi": mdi, "mdca": mdca, "mdo": mdo, "sophos_fw": sophos_fw, "xsoar": xsoar_native}


_VERDICT_MIX = {"benign": 0.35, "suspicious": 0.35, "malicious": 0.30}


def generate_products(n: int, *, seed: int = 7, val_pct: int = 15, weights: dict[str, float] | None = None) -> list[dict]:
    """``n`` rows spread across the product profiles (equal weights by default), de-duplicated by
    alert and **rebalanced per profile** to roughly 35/35/30 benign/suspicious/malicious by rejection
    sampling — the feature space draws malicious combinations rarely (as reality does), but a
    triage model needs to see enough of them."""
    import json as _json
    r = random.Random(seed)
    names = list(PROFILES)
    w = [float((weights or {}).get(k, 1.0)) for k in names]
    total_w = sum(w)
    quota = {k: {v: int(n * wk / total_w * share) + 1 for v, share in _VERDICT_MIX.items()} for k, wk in zip(names, w)}
    rows: list[dict] = []; seen: set[str] = set(); guard = 0
    while len(rows) < n and guard < n * 40:
        guard += 1
        name = r.choices(names, weights=w)[0]
        row = PROFILES[name](r, val_pct)
        verdict = _json.loads(row["messages"][2]["content"])["verdict"]
        if row["id"] in seen or quota[name][verdict] <= 0:
            continue
        quota[name][verdict] -= 1
        seen.add(row["id"]); rows.append(row)
    return rows


__all__ = ["LABEL_SOURCE", "ORIGIN", "PROFILES", "generate_products"]
