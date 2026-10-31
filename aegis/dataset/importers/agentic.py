"""Agentic-attacker domain: campaign-shaped alerts from AI-agent-driven attacks on the client side.

An attacker's AI agent rarely brings a new exploit; it brings **machine cadence and breadth**:
it fingerprints the stack in its first requests, harvests what that stack leaks (source maps,
debug routes, introspection, keys baked into bundles), enumerates endpoints without any page-load
chain, mutates when the WAF blocks it, and moves from recon to exploitation in minutes. The
framework (React, Angular, Vue, Django, PHP, mobile, GraphQL) decides *what* it harvests; the
behaviour is the same everywhere — so here ``stack`` is a **context field that varies across
rows and is never a signal**, while the labelled signals are behavioural.

Rows are shaped like the *campaign summary* the swarm's campaign-context worker (roadmap 2.8)
will build: one alert carrying a window of what the same source / session did in the last
N minutes. The policy is the corroboration rule with the agentic additions:

    strong  recon artefacts from a non-dev source · enumeration with no referer chain ·
            automation fingerprint (headless + uniform timing, IP rotation under one token) ·
            adaptive mutation after blocks (≥ 8 distinct signatures) · exploit passed on a
            sensitive endpoint · cross-owner write · client-integrity break (unknown script
            domain, new service worker, new inline hash) · beaconing to a young domain ·
            **recon → exploit in ≤ 10 min (the agentic tell)**
    weak    one recon artefact · moderate enumeration · unclassified bot with tight timing ·
            a blocked probe · a few cross-owner reads · SRI failures alone · one young-domain post
    none    stack / framework, TLS and HTTP versions, CDN PoP, locale, page size

    ≥ 2 strong, or 1 strong + ≥ 2 weak → malicious · 1 strong or ≥ 2 weak → suspicious · else benign

Benign look-alikes carry the context that explains them, and that context neutralises only
the signal classes it can explain: an approved pen-test (recon, enumeration, automation, WAF,
access, speed — never client integrity or egress), an allow-listed synthetic monitor
(enumeration, automation), a developer VPN range (recon only), a release deploy window
(client integrity, automation, enumeration, speed).
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from ..export import TRIAGE_SYSTEM_PROMPT
from ..schema import fingerprint, split_for
from ..synth import ALWAYS_HITL
from . import _products as P
from .tls_identity import tls_block

LABEL_SOURCE = "public:agentic"
ORIGIN = "agentic/v1"

STACKS = {
    "react":   {"framework": "react", "render": "spa", "bundler": "webpack", "api_style": "rest",
                "debug_routes": ("/static/js/main.chunk.js.map", "/asset-manifest.json", "/.env", "/api/v1/__debug"),
                "fingerprint": "data-reactroot / chunk names"},
    "nextjs":  {"framework": "nextjs", "render": "ssr", "bundler": "turbopack", "api_style": "rest",
                "debug_routes": ("/_next/static/chunks/pages/_app.js.map", "/api/__health", "/.env.local", "/_next/data/"),
                "fingerprint": "__NEXT_DATA__"},
    "angular": {"framework": "angular", "render": "spa", "bundler": "esbuild", "api_style": "rest",
                "debug_routes": ("/main.js.map", "/assets/environment.prod.json", "/swagger-ui/", "/ngsw.json"),
                "fingerprint": "ng-version attribute"},
    "vue":     {"framework": "vue", "render": "spa", "bundler": "vite", "api_style": "rest",
                "debug_routes": ("/assets/index.js.map", "/.env", "/api/docs", "/__vite_ping"),
                "fingerprint": "data-v-* attributes"},
    "nuxt":    {"framework": "nuxt", "render": "ssr", "bundler": "vite", "api_style": "rest",
                "debug_routes": ("/_nuxt/entry.js.map", "/__nuxt_error", "/.env", "/api/_content"),
                "fingerprint": "__NUXT__ state"},
    "django":  {"framework": "django", "render": "server", "bundler": None, "api_style": "drf",
                "debug_routes": ("/admin/", "/api/schema/", "/api/?format=api", "/__debug__/", "/static/debug_toolbar/"),
                "fingerprint": "csrftoken cookie / DRF browsable API"},
    "laravel": {"framework": "laravel", "render": "server", "bundler": "vite", "api_style": "rest",
                "debug_routes": ("/telescope", "/_ignition/health-check", "/.env", "/storage/logs/laravel.log", "/vendor/"),
                "fingerprint": "laravel_session cookie / X-Powered-By"},
    "symfony": {"framework": "symfony", "render": "server", "bundler": "webpack-encore", "api_style": "rest",
                "debug_routes": ("/_profiler/", "/_wdt/", "/.env", "/app_dev.php", "/config/"),
                "fingerprint": "sf_redirect / _profiler"},
    "php":     {"framework": "php", "render": "server", "bundler": None, "api_style": "rest",
                "debug_routes": ("/phpinfo.php", "/.env", "/backup.zip", "/admin.php", "/.git/config"),
                "fingerprint": "PHPSESSID / X-Powered-By"},
    "mobile":  {"framework": "mobile-android-ios", "render": "native", "bundler": None, "api_style": "rest",
                "debug_routes": ("/api/v1/internal/", "/api/v2/beta/", "/api/config/keys", "/api/v1/debug/env"),
                "fingerprint": "app user agent without pinning"},
    "graphql": {"framework": "react", "render": "spa", "bundler": "webpack", "api_style": "graphql",
                "debug_routes": ("/graphql?query=%7B__schema", "/graphiql", "/playground", "/static/js/main.js.map"),
                "fingerprint": "/graphql endpoint"},
}
_SITES = ("netbanking.bank.in", "cards.bank.in", "api.bank.in", "loans.bank.in", "wealth.bank.in")
_SENSITIVE = ("/api/accounts/{id}", "/api/transfer", "/api/cards/{id}/limit", "/api/kyc/{id}", "/api/beneficiaries")


@dataclass
class Sig:
    text: str
    strength: str          # strong | weak | none
    category: str          # recon | enumeration | automation | waf | access | integrity | egress | speed | context
    technique: str = ""


def _acts(pairs):
    return [{"action_type": a, "target": t, "requires_hitl": a in ALWAYS_HITL} for a, t in pairs]


def _ts(r, base: datetime, minutes: int) -> str:
    return (base + timedelta(minutes=minutes)).isoformat()


def build(r: random.Random) -> tuple[dict, list[Sig], dict]:
    """One campaign-shaped alert, its graded signals, and the context flags."""
    stack_key = r.choice(list(STACKS)); st = STACKS[stack_key]
    site = r.choice(_SITES); ip = P._ip_ext(r) if r.random() < .8 else P._ip_int(r)
    base = datetime(2026, 9, 1, tzinfo=UTC) + timedelta(minutes=r.randint(0, 70000))
    window = r.choice((5, 15, 30, 60))
    s: list[Sig] = []
    # ---- contexts (benign look-alikes) ----
    ctx = {"pentest": r.random() < .10, "monitor": r.random() < .12, "dev_range": r.random() < .12, "deploy": r.random() < .10,
           "proxy": r.random() < .10}
    ctx_block = {
        "pentest": {"recon", "enumeration", "automation", "waf", "access", "speed"},
        "monitor": {"enumeration", "automation", "tls"},
        "dev_range": {"recon"},
        "deploy": {"integrity", "automation", "enumeration", "speed"},
        "proxy": {"tls"},
    }
    sections = {k: r.random() < p for k, p in (("recon", .55), ("enumeration", .6), ("automation", .55), ("waf", .5),
                                                 ("access", .35), ("integrity", .3), ("egress", .3), ("tls", .45))}
    single = r.random() < .25                     # a single-event alert rather than a campaign window
    if single:
        keep = r.choice([k for k, v in sections.items() if v] or ["enumeration"])
        sections = {k: (k == keep) for k in sections}

    a: dict = {"source": r.choice(("Imperva Cloud WAF", "F5 ASM", "API Gateway", "CSP Report Collector", "Microsoft Sentinel")),
               "alert_type": "single_event" if single else "campaign_summary", "site": site,
               "stack": {k: st[k] for k in ("framework", "render", "bundler", "api_style")},
               "stack_fingerprint_seen": st["fingerprint"], "source_ip": ip,
               "session_id": f"s_{r.getrandbits(40):010x}", "user_agent": r.choice(
                   ("Mozilla/5.0 (Windows NT 10.0; Win64) Chrome/130", "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/129",
                    "python-requests/2.32", "Mozilla/5.0 (Macintosh) Safari/17", "okhttp/4.12", "Datadog Synthetics",
                    "Mozilla/5.0 (Linux) Firefox/115")),
               "window_minutes": window,
               "tls_version": r.choice(("1.2", "1.3")), "http_version": r.choice(("1.1", "2", "3")),
               "cdn_pop": r.choice(("BOM", "DEL", "SIN", "FRA")), "browser_locale": r.choice(("en-IN", "en-US", "hi-IN", "ru-RU")),
               "avg_page_bytes": r.randint(2000, 900000)}
    s.append(Sig(f"stack {st['framework']}/{st['render']}, TLS {a['tls_version']}, HTTP/{a['http_version']}, locale, CDN PoP, page size", "none", "context"))

    # ---- recon ----
    if sections["recon"]:
        maps = r.choice((0, 0, 1, 3, 12)); probes = r.sample(st["debug_routes"], r.choice((0, 1, 1, 2, 4)))
        introspect = st["api_style"] == "graphql" and r.random() < .6
        env_probe = any(p_.endswith(".env") or ".env" in p_ for p_ in probes)
        a["recon"] = {"source_map_fetches": maps, "debug_route_probes": probes, "graphql_introspection": introspect,
                      "openapi_fetch": r.random() < .3, "keys_in_bundle_found": r.random() < .15 and maps > 0}
        kinds = (maps >= 3) + (len(probes) >= 2) + introspect + env_probe
        if kinds >= 2 or (maps >= 3 and not ctx["dev_range"]):
            s.append(Sig(f"harvesting client-side artefacts: {maps} source-map fetches, probes {probes[:3]}"
                         f"{', GraphQL introspection' if introspect else ''}", "strong", "recon", "T1592.002"))
        elif kinds == 1 or maps == 1 or len(probes) == 1:
            s.append(Sig(f"one recon artefact ({'source map' if maps else probes[0] if probes else 'openapi'})", "weak", "recon", "T1595.002"))
        else:
            s.append(Sig("no recon artefacts beyond ordinary asset loads", "none", "recon"))
    # ---- enumeration ----
    if sections["enumeration"]:
        distinct = r.choice((r.randint(2, 12), r.randint(20, 45), r.randint(50, 400)))
        no_ref = round(r.choice((r.uniform(0, .2), r.uniform(.3, .7), r.uniform(.8, 1.0))), 2)
        seq = r.random() < .3
        a["enumeration"] = {"distinct_endpoints": distinct, "requests": distinct * r.randint(1, 6), "no_referer_ratio": no_ref,
                            "sequential_id_pattern": seq, "endpoints_never_seen_from_browsers": r.randint(0, distinct // 2)}
        if distinct >= 50 and no_ref >= .8:
            s.append(Sig(f"{distinct} distinct endpoints in {window} min with {int(no_ref * 100)} % no page-load chain", "strong", "enumeration", "T1595.003"))
        elif distinct >= 20 or seq:
            s.append(Sig(f"{distinct} endpoints{', sequential ids' if seq else ''}", "weak", "enumeration", "T1595.003"))
        else:
            s.append(Sig(f"{distinct} endpoints — ordinary browsing breadth", "none", "enumeration"))
    # ---- automation ----
    if sections["automation"]:
        bot = r.choice(("Human", "Human", "Unclassified", "Headless browser", "Known Bad Bot", "Good Bot"))
        sd = r.choice((r.randint(5, 45), r.randint(60, 190), r.randint(300, 4000)))
        rot = r.choice((0, 0, 1, r.randint(5, 40))); webdriver = r.random() < .2; mouse = 0 if r.random() < .35 else r.randint(5, 300)
        a["automation"] = {"bot_verdict": bot, "inter_request_stddev_ms": sd, "ip_rotations_same_session": rot,
                           "webdriver_flag": webdriver, "mouse_events_per_page": mouse}
        if (bot in ("Headless browser", "Known Bad Bot") and sd < 50) or rot >= 5 or webdriver:
            why_ = "headless with uniform timing" if sd < 50 and bot != "Human" else f"{rot} IP rotations under one session" if rot >= 5 else "webdriver flag"
            s.append(Sig(f"automation fingerprint: {why_}", "strong", "automation", "T1583.006"))
        elif (bot == "Unclassified" and sd < 200) or mouse == 0:
            s.append(Sig("tight request timing, no pointer events", "weak", "automation"))
        else:
            s.append(Sig(f"bot verdict {bot}, human-like timing", "none", "automation"))
    # ---- waf ----
    if sections["waf"]:
        sigs = r.choice((0, 1, 1, r.randint(2, 6), r.randint(8, 40))); blocked = r.randint(0, 3) if sigs <= 1 else r.randint(sigs, sigs * 6)
        passed = r.random() < .12; classes = r.sample(("SQL Injection", "Cross Site Scripting", "Path Traversal", "Command Injection",
                                                     "Illegal Resource Access", "Scanner Activity"), min(3, max(1, sigs)))
        target = r.choice(_SENSITIVE) if passed else r.choice(_SENSITIVE + ("/static/app.js", "/robots.txt"))
        a["waf"] = {"blocked": blocked, "distinct_signatures": sigs, "attack_classes": classes,
                    "passed_on_sensitive_endpoint_200": passed, "target": target}
        if passed:
            s.append(Sig(f"an attack-class request passed the WAF to {target} and got 200", "strong", "waf", "T1190"))
        elif sigs >= 8:
            s.append(Sig(f"{sigs} distinct signatures after {blocked} blocks — the attacker mutates on every block", "strong", "waf", "T1190"))
        elif blocked >= 1:
            s.append(Sig(f"{blocked} blocked probe(s), {sigs} signature(s)", "weak", "waf", "T1595"))
        else:
            s.append(Sig("no WAF matches", "none", "waf"))
    # ---- access ----
    if sections["access"]:
        reads = r.choice((0, 0, r.randint(1, 4), r.randint(5, 60))); writes = r.choice((0, 0, 0, r.randint(1, 5)))
        a["access"] = {"cross_owner_reads": reads, "cross_owner_writes": writes, "caller_role": r.choice(("retail_customer", "partner_api", "support_agent"))}
        if writes >= 1:
            s.append(Sig(f"{writes} write(s) to objects owned by other customers", "strong", "access", "T1190"))
        elif reads >= 5:
            s.append(Sig(f"{reads} reads of other customers' objects", "strong", "access", "T1190"))
        elif reads >= 1:
            s.append(Sig(f"{reads} cross-owner read(s)", "weak", "access"))
        else:
            s.append(Sig("every object accessed belongs to the caller", "none", "access"))
    # ---- client integrity ----
    if sections["integrity"]:
        unknown = r.sample(("cdn-metrics.example-net.xyz", "static-assets.example-cdn.io", "js.example-tag.co"), r.choice((0, 0, 0, 1, 2)))
        sw = r.random() < .15; new_hash = r.random() < .25; csp = r.choice((0, 0, r.randint(1, 30), r.randint(200, 5000))); sri = r.choice((0, 0, r.randint(1, 40)))
        a["client_integrity"] = {"csp_violations": csp, "unknown_script_src_domains": unknown, "sri_failures": sri,
                                 "new_service_worker_registered": sw, "new_inline_script_hash": new_hash,
                                 "pages_affected": r.choice(("/checkout", "/login", "/transfer", "/dashboard"))}
        if unknown or sw or (new_hash and csp >= 1):
            s.append(Sig(f"client-integrity break on {a['client_integrity']['pages_affected']}: "
                         f"{'script from ' + unknown[0] if unknown else 'new service worker' if sw else 'new inline script hash'}", "strong", "integrity", "T1059.007"))
        elif sri >= 1 or csp >= 1:
            s.append(Sig(f"{sri} SRI failure(s), {csp} CSP report(s) — could be a CDN hiccup", "weak", "integrity"))
        else:
            s.append(Sig("page integrity unchanged", "none", "integrity"))
    # ---- egress ----
    if sections["egress"]:
        posts = r.choice((0, 0, 1, r.randint(10, 120))); age = r.choice((r.randint(0, 6), r.randint(30, 900))); sd_s = round(r.choice((r.uniform(0, 1.5), r.uniform(5, 90))), 1)
        bytes_ = r.choice((r.randint(100, 2000), r.randint(50_000, 900_000))); dns_txt = r.choice((0, 0, r.randint(50, 900)))
        a["egress"] = {"posts_to_new_domain": posts, "domain_age_days": age, "post_interval_stddev_s": sd_s,
                       "payload_bytes_avg": bytes_, "dns_txt_queries": dns_txt}
        if (posts >= 10 and age < 7 and sd_s < 2) or dns_txt >= 50:
            s.append(Sig("beaconing / exfil: " + (f"{posts} metronomic posts to a {age}-day-old domain" if dns_txt < 50 else f"{dns_txt} DNS TXT queries"),
                         "strong", "egress", "T1048.003" if dns_txt >= 50 else "T1071.001"))
        elif posts >= 1 and age < 30:
            s.append(Sig(f"{posts} post(s) to a {age}-day-old domain", "weak", "egress", "T1071.001"))
        else:
            s.append(Sig("egress to established domains only", "none", "egress"))
    # ---- TLS / key identity ----
    if sections["tls"]:
        tctx = {}
        if ctx["proxy"]: tctx["known_inspection_proxy"] = "Zscaler ZIA egress"
        if ctx["monitor"]: tctx["monitor_allowlisted"] = True
        blk, tsig = tls_block(r, user_agent=a["user_agent"], context=tctx)
        a["tls_identity"] = blk
        for text, strength, tech in tsig:
            s.append(Sig(text, strength, "tls", tech))
    # ---- speed (only meaningful for a window with recon + something later) ----
    later = any(sections[k] for k in ("waf", "access", "integrity", "egress"))
    if not single and sections["recon"] and later:
        gap = r.choice((r.randint(1, 9), r.randint(12, 55), r.randint(90, 3000)))
        a["timeline"] = {"first_recon_at": _ts(r, base, 0), "first_exploit_at": _ts(r, base, gap), "recon_to_exploit_minutes": gap}
        if gap <= 10:
            s.append(Sig(f"recon → exploitation in {gap} min — machine cadence", "strong", "speed"))
        elif gap <= 60:
            s.append(Sig(f"recon → exploitation in {gap} min", "weak", "speed"))
        else:
            s.append(Sig(f"recon → exploitation {gap} min apart — human pace", "none", "speed"))
    # ---- context fields ----
    c: dict = {}
    if ctx["pentest"]:
        c["pentest_window"] = {"ticket": f"PT-{r.randint(1000, 9999)}", "source_in_approved_range": True, "scope_includes_site": True}
    if ctx["monitor"]:
        c["synthetic_monitor"] = {"vendor": r.choice(("Datadog Synthetics", "Pingdom", "Dynatrace")), "allowlisted_source": True}
        a["user_agent"] = c["synthetic_monitor"]["vendor"]
    if ctx["dev_range"]:
        c["source_in_dev_range"] = True
    if ctx["deploy"]:
        c["deploy_window"] = {"release": f"v{r.randint(40, 90)}.{r.randint(0, 30)}", "ci_runner_source": True, "started_minutes_ago": r.randint(1, 40)}
    if ctx["proxy"]:
        c["known_inspection_proxy"] = "Zscaler ZIA egress"
    if c:
        a["context"] = c
    return a, s, {k: v for k, v in ctx_block.items() if ctx[k]}


def decide(a: dict, s: list[Sig], neutralise: dict[str, set], r: random.Random):
    neutralised = set().union(*neutralise.values()) if neutralise else set()
    live = [x for x in s if x.strength in ("strong", "weak") and x.category not in neutralised]
    dropped = [x for x in s if x.strength in ("strong", "weak") and x.category in neutralised]
    strong = [x for x in live if x.strength == "strong"]; weak = [x for x in live if x.strength == "weak"]
    none = [x for x in s if x.strength == "none"]
    texts = [f"strong: {x.text}" for x in strong] + [f"weak: {x.text}" for x in weak]
    ctx_names = {"pentest": "approved pen-test window", "monitor": "allow-listed synthetic monitor",
                 "dev_range": "developer VPN range", "deploy": "release deploy window", "proxy": "known TLS-inspection proxy"}
    for k in neutralise:
        texts.append(f"context: {ctx_names[k]} explains " + ", ".join(sorted({x.category for x in dropped if x.category in neutralise[k]}) or ["nothing here"]))
    texts.append("not signals: " + "; ".join(x.text for x in none[:3]))
    if not strong and not weak and not dropped:
        texts.insert(0, "no anomalous behaviour in the window")
    techs = list(dict.fromkeys(x.technique for x in live if x.technique))
    ip = a["source_ip"]; sess = a["session_id"]; site = a["site"]
    stack_note = f" The stack ({a['stack']['framework']}) only says what an agent would harvest here; it is context, not a signal."
    if len(strong) >= 2 or (len(strong) == 1 and len(weak) >= 2):
        head = (f"Two independent strong signals — {strong[0].text}; {strong[1].text} — corroborate each other" if len(strong) >= 2
                else f"One strong signal ({strong[0].text}) corroborated by two independent weak ones ({weak[0].text}; {weak[1].text})")
        cadence = " The cadence and breadth are an automated attacker, not a person: contain at machine speed." if any(x.category in ("speed", "automation") for x in strong + weak) else ""
        acts = [("block", ip), ("revoke_sessions", sess), ("snapshot_forensic", site), ("notify_user", "app-owner")]
        if any(x.category == "integrity" for x in strong):
            acts.insert(1, ("hold", f"{site} release"))
        if any(x.category == "egress" for x in strong):
            acts.insert(1, ("block", "egress-domain"))
        return ("malicious", r.uniform(.85, .96), texts, _acts(acts), techs,
                head + ". That is the bar for containment; the actions need an analyst's approval." + cadence + stack_note)
    if len(strong) == 1 or len(weak) >= 2:
        lead = strong[0].text if strong else f"{weak[0].text}; {weak[1].text}"
        return ("suspicious", r.uniform(.56, .74), texts, _acts([("throttle", ip), ("challenge", sess), ("monitor", site)]), techs,
                (f"One strong signal ({lead})" if strong else f"Weak signals only ({lead})") +
                " — slow the source and step up the session; a scanner, a crawler and an attacker's first minute look the same until a second signal arrives." + stack_note)
    why = ("Behaviour fully explained by " + ", ".join(ctx_names[k] for k in neutralise) + "; nothing outside that context." if neutralise
           else "Breadth, timing and access are all within ordinary browsing; framework, TLS/HTTP versions, locale and page size carry no weight.")
    return ("benign", r.uniform(.78, .92), texts, _acts([("allow", ip)] + ([("monitor", ip)] if weak or dropped else [])), [], why + stack_note)


def generate_agentic(n: int, *, seed: int = 7, val_pct: int = 15) -> list[dict]:
    """``n`` rows, rejection-balanced to ~35/35/30 and spread across the stacks."""
    r = random.Random(seed)
    quota = {"benign": int(n * .35) + 1, "suspicious": int(n * .35) + 1, "malicious": int(n * .3) + 1}
    rows: list[dict] = []; seen: set[str] = set(); guard = 0
    while len(rows) < n and guard < n * 40:
        guard += 1
        a, s, neutralise = build(r)
        verdict, conf, sig, acts, techs, why = decide(a, s, neutralise, r)
        if quota[verdict] <= 0:
            continue
        alert = {"id": f"AGT-{r.getrandbits(24):06X}", "observed_at": P._ts(r), **a}
        fp = fingerprint(alert)
        if fp in seen:
            continue
        seen.add(fp); quota[verdict] -= 1
        target = {"verdict": verdict, "confidence": round(conf, 2), "key_signals": sig, "recommended_actions": acts,
                  "techniques": techs, "rationale": why}
        rows.append({"id": f"agt-{fp[:16]}", "split": split_for(fp, val_pct), "label_source": LABEL_SOURCE, "origin": ORIGIN,
                     "provenance": {"stack": a["stack"]["framework"], "alert_type": a["alert_type"],
                                    "strong": sum(1 for x in s if x.strength == "strong"), "weak": sum(1 for x in s if x.strength == "weak"),
                                    "contexts": sorted(neutralise)},
                     "messages": [{"role": "system", "content": TRIAGE_SYSTEM_PROMPT},
                                  {"role": "user", "content": json.dumps(alert, sort_keys=True, ensure_ascii=False)},
                                  {"role": "assistant", "content": json.dumps(target, ensure_ascii=False)}]})
    return rows


__all__ = ["LABEL_SOURCE", "ORIGIN", "STACKS", "build", "decide", "generate_agentic"]
