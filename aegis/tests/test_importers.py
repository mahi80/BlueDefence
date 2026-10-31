"""aegis.dataset.importers — Sigma rules and Security-Datasets scenarios → realistic labelled rows.
No network: a tiny in-repo fixture corpus stands in for the real checkouts."""

from __future__ import annotations

import json
import random
import textwrap
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

from aegis.dataset.importers import build_mixed, generate_mordor, generate_sigma, load_rules, load_scenarios  # noqa: E402
from aegis.dataset.importers import _products as P  # noqa: E402
from aegis.dataset.importers.sigma import materialise  # noqa: E402

_RULES = {
    "windows/process_creation/proc_a.yml": """
        title: Suspicious Tool Started From Temp
        id: 11111111-1111-1111-1111-111111111111
        status: test
        description: Detects a renamed admin tool launched from a user-writable path
        tags: [attack.execution, attack.t1059.001]
        logsource: {product: windows, category: process_creation}
        detection:
          selection:
            Image|endswith: ['\\\\tool.exe', '\\\\helper.exe']
            CommandLine|contains: ' -quiet '
          filter_main_installer:
            ParentImage|endswith: '\\\\msiexec.exe'
          condition: selection and not 1 of filter_main_*
        falsepositives: [Software installers, Administrator activity]
        level: high
    """,
    "cloud/aws/cloudtrail/aws_b.yml": """
        title: AWS Trail Changed
        id: 22222222-2222-2222-2222-222222222222
        description: Detects disabling or updating of a trail
        tags: [attack.defense-evasion, attack.t1562.008]
        logsource: {product: aws, service: cloudtrail}
        detection:
          selection:
            eventSource: cloudtrail.amazonaws.com
            eventName: [StopLogging, UpdateTrail]
          condition: selection
        falsepositives: [Valid change in a Trail]
        level: medium
    """,
    "web/proxy_c.yml": """
        title: Odd User Agent
        id: 33333333-3333-3333-3333-333333333333
        description: Detects a user agent ending with padding
        tags: [attack.command-and-control, attack.t1071.001]
        logsource: {category: proxy}
        detection:
          selection:
            c-useragent|endswith: '=='
          condition: selection
        level: low
    """,
    "windows/registry/reg_d_regex.yml": """
        title: Regex Only Rule
        id: 44444444-4444-4444-4444-444444444444
        tags: [attack.persistence]
        logsource: {product: windows, category: registry_set}
        detection:
          selection:
            Details|re: '^x+$'
          condition: selection
        level: high
    """,
}

_SCENARIO = """
    title: Cloud Bank Breach Emulation
    id: SDAWS-000000000000
    platform: [AWS]
    description: This dataset represents adversaries abusing a proxy to obtain keys and exfiltrate files from a bucket.
    attack_mappings:
      - technique: T1078
        sub-technique: "004"
        tactics: [TA0001, TA0003]
      - technique: T1530
        tactics: [TA0009]
    files:
      - type: cloud
        link: https://example.invalid/datasets/atomic/aws/collection/x.zip
"""
_SCENARIO_DISCOVERY = """
    title: Enumerate Local Users
    id: SDWIN-000000000001
    platform: [Windows]
    description: This dataset represents adversaries enumerating local users on an endpoint
    attack_mappings:
      - technique: T1087
        sub-technique: "001"
        tactics: [TA0007]
    files:
      - type: Host
        link: https://example.invalid/datasets/atomic/windows/discovery/host/y.zip
"""


@pytest.fixture
def corpora(tmp_path: Path):
    sig = tmp_path / "sigma" / "rules"
    for rel, body in _RULES.items():
        p = sig / rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(textwrap.dedent(body))
    mor = tmp_path / "Security-Datasets" / "datasets" / "atomic" / "_metadata"; mor.mkdir(parents=True)
    (mor / "SDAWS-000000000000.yaml").write_text(textwrap.dedent(_SCENARIO))
    (mor / "SDWIN-000000000001.yaml").write_text(textwrap.dedent(_SCENARIO_DISCOVERY))
    return tmp_path / "sigma", tmp_path / "Security-Datasets"


def _alert(row): return json.loads(row["messages"][1]["content"])
def _target(row): return json.loads(row["messages"][2]["content"])


def test_load_rules_parses_tags_level_and_logsource(corpora):
    rules = load_rules(corpora[0])
    assert {r.title for r in rules} == {"Suspicious Tool Started From Temp", "AWS Trail Changed", "Odd User Agent", "Regex Only Rule"}
    a = next(r for r in rules if r.title.startswith("Suspicious"))
    assert a.technique_ids == ["T1059.001"] and a.tactic == "execution" and a.level == "high" and a.falsepositives


def test_materialise_positive_satisfies_selection_and_filters_are_honoured(corpora):
    rules = {r.title: r for r in load_rules(corpora[0])}
    r = random.Random(1)
    m = materialise(rules["Suspicious Tool Started From Temp"], r, "positive")
    assert m and m.event["Image"].endswith(("\\tool.exe", "\\helper.exe")) and " -quiet " in m.event["CommandLine"]
    assert "ParentImage" not in m.event                                   # positives do not trip the filter
    fh = materialise(rules["Suspicious Tool Started From Temp"], r, "filter_hit")
    assert fh and fh.event["ParentImage"].endswith("\\msiexec.exe") and fh.kind == "filter_hit"
    assert materialise(rules["Regex Only Rule"], r, "positive") is None  # unsupported modifier → skipped, not garbage
    assert materialise(rules["AWS Trail Changed"], r, "filter_hit") is None  # no filters → cannot build a filter-hit


def test_sigma_rows_label_by_level_and_kind_in_product_envelopes(corpora):
    rules = load_rules(corpora[0])
    rows = generate_sigma(rules, seed=3, variants=40, benign_pct=40)
    assert rows
    seen_products = set(); seen = set()
    for row in rows:
        a, t, prov = _alert(row), _target(row), row["provenance"]
        assert row["label_source"] == "public:sigma" and row["split"] in ("train", "val")
        seen_products.add(a["source"]); seen.add((prov["level"], prov["kind"], t["verdict"]))
        for act in t["recommended_actions"]:
            if act["action_type"] in ("isolate", "lock_account", "revoke_sessions", "block", "kill_process", "snapshot_forensic"):
                assert act["requires_hitl"] is True
        if t["verdict"] == "benign":
            assert t["techniques"] == [] and any(x["action_type"] == "allow" for x in t["recommended_actions"])
        else:
            assert "rule match" in t["key_signals"][0]
    assert ("high", "positive", "malicious") in seen and ("medium", "positive", "suspicious") in seen
    assert ("low", "positive", "suspicious") in seen                    # low-confidence rules never auto-malicious
    assert ("high", "filter_hit", "benign") in seen and ("high", "near_miss", "benign") in seen
    assert seen_products >= {"CrowdStrike Falcon", "Sophos Central", "Microsoft Defender for Endpoint", "Microsoft Sentinel",
                             "Zscaler ZIA", "Cortex XSOAR"}


def test_product_severity_is_not_a_label():
    r = random.Random(5)
    sev = {v: set() for v in ("benign", "suspicious", "malicious")}
    for v in sev:
        for _ in range(60):
            sev[v].add(P.crowdstrike(r, v, {}, tactic="x", technique_id="", technique_name="", title="t")["max_severity_displayname"])
    assert all(s == {"Low", "Medium", "High"} for s in sev.values())


def test_mordor_scenarios_become_sentinel_incidents_with_chain_labels(corpora):
    sc = load_scenarios(corpora[1])
    assert len(sc) == 2 and sc[0]["techniques"] == ["T1078.004", "T1530"] and sc[0]["tactics"][:2] == ["initial_access", "persistence"]
    rows = generate_mordor(sc, seed=2, variants=3)
    by_title = {}
    for row in rows:
        a, t = _alert(row), _target(row)
        inner = a["rawJSON"] if a["source"] == "Cortex XSOAR" else a
        assert inner["source"] == "Microsoft Sentinel" and inner["AnalyticsRuleName"]
        by_title.setdefault(inner["Title"], set()).add(t["verdict"])
        assert row["label_source"] == "public:mordor" and row["provenance"]["telemetry"] == "sampled"
        assert "adversary_view" not in json.dumps(a)                   # the attack transcript is never copied
    assert by_title["Multi-stage activity: Cloud Bank Breach Emulation"] == {"malicious"}
    assert by_title["Enumerate Local Users"] == {"suspicious"}         # single-tactic discovery is held, not contained


def test_build_mixed_shares_dedup_and_injections(corpora):
    rows, st = build_mixed(sigma_root=corpora[0], mordor_root=corpora[1], total=400, seed=11)
    assert st["rows"] >= 300 and st["by_split"]["train"] > st["by_split"]["val"]
    srcs = st["by_source"]
    assert {"public:sigma", "public:mordor", "synthetic", "public:sigma+injection"} <= set(srcs)
    for row in rows:
        a, t = _alert(row), _target(row)
        if row["label_source"].endswith("+injection"):
            assert t["injection_detected"] and t["verdict"] != "benign" and "AML.T0051" in t["techniques"]
            assert not any(x["action_type"] == "allow" for x in t["recommended_actions"])
            assert any(k in a for k in ("note", "comment", "message", "user_comment", "ticket_note", "commit_message",
                                        "subject", "description", "free_text", "remarks"))
    fps = [json.dumps(_alert(r_), sort_keys=True) for r_ in rows]
    assert len(fps) == len(set(fps))                                   # no duplicate alerts


def test_trainer_refuses_public_rows_without_flag(tmp_path, corpora):
    from aegis.finetune.data import DataError, load_sft
    rows, _ = build_mixed(sigma_root=corpora[0], mordor_root=corpora[1], total=60, seed=1)
    d = tmp_path / "ds"; (d / "sft").mkdir(parents=True)
    with (d / "sft" / "triage.jsonl").open("w") as fh:
        for r_ in rows:
            fh.write(json.dumps(r_) + "\n")
    with pytest.raises(DataError):
        load_sft(d)
    assert load_sft(d, allow_synthetic=True)


# ---------------- products_gen: the CISO-stack gaps ----------------
def test_products_cover_every_ciso_platform_with_balanced_verdicts():
    from aegis.dataset.importers.products_gen import PROFILES, generate_products
    rows = generate_products(1600, seed=5)
    assert len(rows) >= 1500
    by_src = {}; by_profile = {}
    for row in rows:
        a, t = _alert(row), _target(row)
        by_src.setdefault(a["source"], set()).add(t["verdict"])
        by_profile[row["provenance"]["profile"].split("/")[0]] = by_profile.get(row["provenance"]["profile"].split("/")[0], 0) + 1
        for act in t["recommended_actions"]:
            if act["action_type"] in ("isolate", "lock_account", "revoke_sessions", "block", "kill_process", "block_export", "rotate_credential", "hold"):
                assert act["requires_hitl"] is True
        if t["verdict"] == "benign":
            assert t["techniques"] == []
        assert t["rationale"] and t["key_signals"]
    expected = {"Imperva Cloud WAF", "F5 ASM", "Zscaler ZIA", "Zscaler ZPA", "Microsoft Defender for Identity",
                "Microsoft Defender for Cloud Apps", "Microsoft Defender for Office 365", "Sophos Firewall", "Cortex XSOAR"}
    assert expected <= set(by_src)
    for src in expected:                                                   # every product sees all three verdicts
        assert by_src[src] == {"benign", "suspicious", "malicious"}, (src, by_src[src])
    assert set(PROFILES) == {"waf", "token_forgery", "ct_watch", "zia", "zpa", "mdi", "mdca", "mdo", "sophos_fw", "xsoar"}


def test_products_verdict_is_a_combination_not_one_field():
    """Spot-check the policies that cost the gate most: ticketed pen-test → benign; passed exploit
    on a sensitive endpoint → malicious; beaconing → malicious; honeytoken → malicious."""
    from aegis.dataset.importers.products_gen import generate_products
    rows = generate_products(3000, seed=9)
    seen = set()
    for row in rows:
        a, t = _alert(row), _target(row)
        if a["source"] in ("Imperva Cloud WAF", "F5 ASM"):
            if a.get("pentest_window", {}).get("source_in_approved_range"):
                assert t["verdict"] == "benign"; seen.add("pt")
            if (a.get("action") == "REQ_PASSED" or a.get("request_status") == "passed") and a["target_class"] in ("auth", "payment", "data") \
               and a["http_status"] == 200 and a["attack_type"] not in ("Scanner Activity", "DDoS", "Bot Access Control") \
               and not a.get("pentest_window", {}).get("source_in_approved_range"):      # an approved pen-test wins
                assert t["verdict"] == "malicious"; seen.add("passed")
        if a["source"] == "Zscaler ZIA" and "category_exception" not in a and a["action"] == "Allowed" and a["domain_age_days"] < 7 \
           and a["requests_last_hour"] >= 20 and a["request_interval_stddev_s"] < 1.5 and a["bytes_out"] < 4000:
            assert t["verdict"] == "malicious" and "isolate" in {x["action_type"] for x in t["recommended_actions"]}; seen.add("beacon")
        if a["source"] == "Microsoft Defender for Identity" and a["Account"]["honeytoken"]:
            assert t["verdict"] == "malicious"; seen.add("honey")
        if a["source"] == "Zscaler ZPA" and a["change_ticket"] and a["user_privileged"] and a["app_sensitivity"] == "critical" \
           and a["policy_decision"] == "allow" and a["client_geo"] in ("IN-MH", "IN-UP", "IN-KA"):
            assert t["verdict"] == "benign"; seen.add("zpa-ticket")
    assert seen >= {"pt", "passed", "beacon", "honey", "zpa-ticket"}


def test_build_mixed_includes_products_and_injects_into_them(corpora):
    rows, st = build_mixed(sigma_root=corpora[0], mordor_root=corpora[1], total=1200, seed=4)
    assert st["by_source"].get("public:products", 0) >= 250
    assert st["by_source"].get("public:products+injection", 0) >= 20
    prods = {_alert(r_)["source"] for r_ in rows if r_["label_source"].startswith("public:products")}
    assert {"Zscaler ZPA", "Microsoft Defender for Identity", "Sophos Firewall"} <= prods


# ---------------- corroboration: the rule the gate kept catching ----------------
def test_corroboration_rule_counts_independent_strong_signals():
    from aegis.dataset.importers.corroboration import DOMAINS, generate_corroboration
    rows = generate_corroboration(2100, seed=3)
    assert len(rows) >= 2000
    per_domain = {}
    for row in rows:
        a, t, prov = _alert(row), _target(row), row["provenance"]
        per_domain.setdefault(prov["domain"], set()).add(t["verdict"])
        assert "detection" not in json.dumps(a).lower() or a["source"]          # no rule/detection name field
        if t["verdict"] == "malicious":
            assert prov["strong"] >= 2 or (prov["strong"] == 1 and prov["weak"] >= 2)
            assert all(x["requires_hitl"] for x in t["recommended_actions"] if x["action_type"] in ("lock_account", "revoke_sessions", "block", "hold", "block_export"))
            assert "corroborate" in t["rationale"]
        if t["verdict"] == "benign":
            assert t["techniques"] == [] and any(x["action_type"] == "allow" for x in t["recommended_actions"])
    assert set(per_domain) == set(DOMAINS)
    assert all(v == {"benign", "suspicious", "malicious"} for v in per_domain.values())


def test_corroboration_approved_change_neutralises_only_change_signals():
    from aegis.dataset.importers.corroboration import Built, Sig, decide
    r = random.Random(1)
    base = {"change_ticket": "CHG-1", "inside_change_window": True, "operator_source": "bastion"}
    b = Built(dict(base), [Sig("any→any allow", "strong", "T1562.004", change_related=True),
                           Sig("internet → tcp/3389", "strong", "T1133", change_related=True)], [("hold", "x")], [("hold", "x")], "x", "netpolicy")
    assert decide(b, r)[0] == "benign"                                           # both signals are the ticketed change
    b2 = Built(dict(base), [Sig("any→any allow", "strong", "T1562.004", change_related=True),
                            Sig("rule logging disabled", "strong", "T1562.001")], [("hold", "x")], [("hold", "x")], "x", "netpolicy")
    assert decide(b2, r)[0] == "suspicious"                                      # logging-off is not covered by a ticket
    b3 = Built({**base, "operator_source": "internet"}, b.signals, [("hold", "x")], [("hold", "x")], "x", "netpolicy")
    assert decide(b3, r)[0] == "malicious"                                       # ticket from the wrong place does not count


def test_corroboration_one_strong_plus_two_weak_is_malicious_and_distractors_are_named():
    from aegis.dataset.importers.corroboration import Built, Sig, decide
    r = random.Random(2)
    b = Built({}, [Sig("9 MFA failures before success", "strong", "T1621"), Sig("sign-in at 02:00", "weak"),
                   Sig("new device", "weak"), Sig("screen size", "none")], [("lock_account", "u")], [("challenge", "u")], "u", "identity")
    v, _, sig, acts, _, why = decide(b, r)
    assert v == "malicious" and "corroborated by two independent weak" in why
    assert any(x.startswith("not signals:") for x in sig) and "Ordinary fields" in why
    b1 = Built({}, [Sig("one MFA failure", "weak"), Sig("screen size", "none"), Sig("sessions within baseline", "none")],
               [("lock_account", "u")], [("challenge", "u")], "u", "identity")
    v1, _, sig1, acts1, _, why1 = decide(b1, r)
    assert v1 == "benign" and "not signals" in why1 and any(x["action_type"] == "allow" for x in acts1)


def test_identity_rows_use_raw_values_in_three_vocabularies():
    from aegis.dataset.importers.corroboration import identity
    r = random.Random(8)
    shapes = set(); derived = 0
    for _ in range(300):
        b = identity(r)
        shapes.add("flat" if "prev_geo" in b.alert else "raw" if "geographicalContext" in json.dumps(b.alert) else "nested")
        assert not any(k in b.alert for k in ("login_region", "device_trust", "impossible_travel"))   # no pre-derived flags
        derived += any("impossible travel" in s.text and "km" in s.text for s in b.signals)
        assert any(s.strength == "none" for s in b.signals)                                           # distractors always present
    assert shapes == {"flat", "raw", "nested"} and derived >= 50


def test_build_mixed_has_corroboration_share(corpora):
    rows, st = build_mixed(sigma_root=corpora[0], mordor_root=corpora[1], total=1000, seed=6)
    assert st["by_source"].get("public:corroboration", 0) >= 100


# ---------------- agentic: AI-agent campaigns on the client side (roadmap 2.8) ----------------
def test_agentic_rows_vary_stack_and_grade_behaviour_not_framework():
    from aegis.dataset.importers.agentic import STACKS, generate_agentic
    rows = generate_agentic(1500, seed=4)
    assert len(rows) >= 1400
    stacks = {}; verdicts_per_stack = {}
    for row in rows:
        a, t, prov = _alert(row), _target(row), row["provenance"]
        fw = a["stack"]["framework"]; stacks[fw] = stacks.get(fw, 0) + 1
        verdicts_per_stack.setdefault(fw, set()).add(t["verdict"])
        assert any(x.startswith("not signals: stack") for x in t["key_signals"])           # framework is named as a non-signal
        assert "context, not a signal" in t["rationale"]
        if t["verdict"] == "malicious":
            assert prov["strong"] >= 2 or (prov["strong"] == 1 and prov["weak"] >= 2) or prov["contexts"]
            assert all(x["requires_hitl"] for x in t["recommended_actions"] if x["action_type"] in ("block", "revoke_sessions", "hold"))
        if t["verdict"] == "benign":
            assert t["techniques"] == [] and any(x["action_type"] == "allow" for x in t["recommended_actions"])
    assert len(stacks) == len({v["framework"] for v in STACKS.values()})
    assert all(v == {"benign", "suspicious", "malicious"} for v in verdicts_per_stack.values())


def test_agentic_contexts_neutralise_only_their_signal_classes():
    from aegis.dataset.importers.agentic import Sig, decide
    r = random.Random(1)
    base = {"source_ip": "203.0.113.1", "session_id": "s_1", "site": "x.bank.in", "stack": {"framework": "react"}}
    recon = Sig("harvesting client-side artefacts", "strong", "recon"); enum = Sig("184 endpoints, no referer", "strong", "enumeration")
    egress = Sig("beaconing to a 1-day-old domain", "strong", "egress"); integ = Sig("new service worker", "strong", "integrity")
    none = Sig("stack react", "none", "context")
    pentest = {"pentest": {"recon", "enumeration", "automation", "waf", "access", "speed"}}
    assert decide(base, [recon, enum, none], pentest, r)[0] == "benign"                 # test covers recon + enumeration
    assert decide(base, [recon, enum, egress, integ, none], pentest, r)[0] == "malicious"  # it never covers persistence/exfil
    assert decide(base, [recon, enum, none], {}, r)[0] == "malicious"
    assert decide(base, [recon, none], {}, r)[0] == "suspicious"
    deploy = {"deploy": {"integrity", "automation", "enumeration", "speed"}}
    assert decide(base, [integ, Sig("headless", "strong", "automation"), none], deploy, r)[0] == "benign"


def test_agentic_eval_corpus_is_consistent_and_tracked_by_gate():
    from aegis.eval.run import HERE
    from aegis.finetune.gate import evaluate
    cases = json.loads((HERE / "agentic_chains" / "cases.json").read_text())
    assert len(cases) >= 10 and {c["expected_verdict"] for c in cases} == {"benign", "suspicious", "malicious"}
    assert len({c["alert"]["stack"]["framework"] for c in cases}) >= 8                   # many stacks in the held-out set
    exp = {c["alert"]["id"]: c["expected_verdict"] for c in json.loads((HERE / "historical_alerts" / "cases.json").read_text()) + cases}
    res = evaluate(lambda a: exp.get(a["id"], "suspicious"), actions=lambda a: ["monitor"])
    assert res.agentic_total == len(cases) and not res.agentic_misses and "agentic" in res.summary()
    bad = evaluate(lambda a: "benign" if a["id"].startswith("AGT") else exp.get(a["id"], "suspicious"), actions=lambda a: ["monitor"])
    assert len(bad.agentic_misses) == sum(1 for c in cases if c["expected_verdict"] != "benign")
    assert bad.passes() == res.passes()                                                  # tracked only: never changes pass/fail


def test_build_mixed_includes_agentic_and_excludes_agentic_eval(corpora):
    from aegis.dataset.schema import fingerprint
    from aegis.eval.run import HERE
    rows, st = build_mixed(sigma_root=corpora[0], mordor_root=corpora[1], total=1000, seed=5)
    assert st["by_source"].get("public:agentic", 0) >= 60
    held = {fingerprint(c["alert"]) for c in json.loads((HERE / "agentic_chains" / "cases.json").read_text())}
    assert not any(fingerprint(_alert(r_)) in held for r_ in rows)


# ---------------- TLS / key identity ----------------
def test_tls_block_grades_identity_and_contexts_neutralise():
    from aegis.dataset.importers.tls_identity import ct_event, tls_block
    r = random.Random(3)
    seen = set(); neutral = 0
    for _ in range(400):
        blk, sig = tls_block(r, user_agent="Mozilla/5.0 (Windows NT 10.0; Win64) Chrome/130")
        assert blk["ja4"] and blk["ja4_family"] and blk["ua_claims_family"] == "chrome"
        for text, strength, _t in sig:
            assert strength in ("strong", "weak", "none")
            seen.add(text.split(" ")[0] + strength)
        if blk["ja4_family"] not in ("chrome", "headless-chrome") and blk["ja4_family"] != "inspection-proxy":
            assert any("lying" in t[0] or "tooling" in t[0] for t in sig if t[1] == "strong")
    for _ in range(200):
        blk, sig = tls_block(r, user_agent="Mozilla/5.0 (Windows NT 10.0; Win64) Chrome/130", tokens=True,
                             context={"known_inspection_proxy": "Zscaler ZIA egress", "key_rotation_window": True})
        if blk["ja4_family"] == "inspection-proxy":
            assert all(t[1] == "none" for t in sig if "proxy" in t[0]); neutral += 1
        if "tokens" in blk and blk["tokens"]["signature_failures_15m"] >= 50:
            assert any("rotation" in t[0] and t[1] == "none" for t in sig)
    assert neutral >= 5
    kinds = {ct_event(r)[0]["event"] for _ in range(50)}
    assert kinds == {"precert_logged", "cert_seen_on_host"}


def test_products_token_forgery_and_ct_watch_profiles():
    from aegis.dataset.importers.products_gen import generate_products
    rows = generate_products(2400, seed=11)
    prof = {}
    for row in rows:
        a, t = _alert(row), _target(row); p = row["provenance"]["profile"]
        prof.setdefault(p.split("/")[0], set()).add(t["verdict"])
        if p == "gateway/token-forgery":
            assert "tls_identity" in a
            if t["verdict"] == "malicious":
                assert any(x["action_type"] in ("rotate_credential", "revoke_sessions") for x in t["recommended_actions"])
        if p == "ct/watch":
            assert a["source"] == "Certificate Transparency Monitor"
            if a["event"] == "cert_seen_on_host":
                assert t["verdict"] == "malicious" and any("private key" in x["target"] for x in t["recommended_actions"])
            if a["matches_renewal_schedule"]:
                assert t["verdict"] == "benign"
        if p.startswith("waf/"):
            assert "tls_identity" in a
            if a.get("source_known_inspection_proxy"):
                assert not any("interception" in s_ for s_ in t["key_signals"])
    assert prof["gateway"] == prof["ct"] == {"benign", "suspicious", "malicious"}


# ---------------- endpoint gaps ----------------
def test_endpoint_profiles_balanced_and_contexts_scoped():
    from aegis.dataset.importers.endpoint import PROFILES, generate_endpoint
    rows = generate_endpoint(2400, seed=6)
    per = {}
    for row in rows:
        a, t, prov = _alert(row), _target(row), row["provenance"]
        per.setdefault(prov["profile"], set()).add(t["verdict"])
        assert any(x.startswith("not signals:") for x in t["key_signals"])
        if t["verdict"] == "malicious":
            assert prov["strong"] >= 2 or (prov["strong"] == 1 and prov["weak"] >= 2) or prov["contexts"]
        if t["verdict"] == "benign":
            assert t["techniques"] == []
        if prov["profile"] == "endpoint/infostealer-chain" and a.get("context", {}).get("approved_password_manager") and a["store_read"] \
           and a["identity"]["session_token_reused_from_new_device"] and a["archive_created_then_uploaded"]:
            assert t["verdict"] == "malicious"                       # the manager explains the read, never the replay + exfil
        if prov["profile"] == "endpoint/ransomware-rate" and a.get("canary_file_modified") and a["files_renamed_per_min"] >= 800 and a["avg_write_entropy"] >= 7.6:
            assert t["verdict"] == "malicious"
    assert len(per) == len(PROFILES) and all(v == {"benign", "suspicious", "malicious"} for v in per.values())


def test_gate_tracks_endpoint_corpus_separately(corpora):
    from aegis.eval.run import HERE
    from aegis.finetune.gate import evaluate
    ept = json.loads((HERE / "endpoint_chains" / "cases.json").read_text())
    assert len(ept) >= 8
    exp = {}
    for name in ("historical_alerts", "agentic_chains", "endpoint_chains"):
        for c in json.loads((HERE / name / "cases.json").read_text()):
            exp[c["alert"]["id"]] = c["expected_verdict"]
    res = evaluate(lambda a: exp.get(a["id"], "suspicious"), actions=lambda a: ["monitor"])
    assert res.tracked["endpoint_chains"]["total"] == len(ept) and not res.tracked["endpoint_chains"]["misses"]
    assert "endpoint" in res.summary() and "agentic" in res.summary() and res.passes()
    rows, st = build_mixed(sigma_root=corpora[0], mordor_root=corpora[1], total=1000, seed=8)
    assert st["by_source"].get("public:endpoint", 0) >= 60


# ---------------- TLS / key-identity held-out corpus ----------------
def test_gate_tracks_tls_corpus_and_holds_it_out_of_training():
    from aegis.dataset.importers.mix import _eval_fps
    from aegis.dataset.schema import fingerprint
    from aegis.eval.run import HERE
    from aegis.finetune.gate import evaluate
    tls = json.loads((HERE / "tls_chains" / "cases.json").read_text())
    assert len(tls) >= 12 and {c["expected_verdict"] for c in tls} == {"benign", "suspicious", "malicious"}
    # every case carries a tls_identity block (WAF / gateway) or is a CT-log observation — the signals the model must read
    for c in tls:
        a = c["alert"]
        assert isinstance(a.get("tls_identity"), dict) or a.get("source") == "Certificate Transparency Monitor"
    exp = {}
    for name in ("historical_alerts", "agentic_chains", "endpoint_chains", "tls_chains"):
        for c in json.loads((HERE / name / "cases.json").read_text()):
            exp[c["alert"]["id"]] = c["expected_verdict"]
    res = evaluate(lambda a: exp.get(a["id"], "suspicious"), actions=lambda a: ["monitor"])
    assert res.tracked["tls_chains"]["total"] == len(tls) and not res.tracked["tls_chains"]["misses"]
    assert "tls" in res.summary() and res.passes()                        # tracked only — never part of pass/fail
    bad = evaluate(lambda a: "benign" if a["id"].startswith("TLS-") else exp.get(a["id"], "suspicious"),
                   actions=lambda a: ["monitor"])
    assert len(bad.tracked["tls_chains"]["misses"]) == sum(1 for c in tls if c["expected_verdict"] != "benign")
    assert bad.passes() == res.passes()                                   # a tracked regression never flips the gate
    # held out of training by construction: every tls_chains fingerprint is in the eval-exclusion set
    held = _eval_fps()
    assert all(fingerprint(c["alert"]) in held for c in tls)
