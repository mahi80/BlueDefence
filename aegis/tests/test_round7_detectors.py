"""Regression tests for review round 7 detector findings D-1 … D-15."""
from __future__ import annotations

import time
from unittest import mock

import pytest

# ---- D-1: Authentication-Results parsing ----------------------------------------------------------------------------


def test_d1_sender_headers_and_mailfrom_injection_do_not_override_trusted_ar(monkeypatch):
    from aegis.agents.email.tools import header_auth_check
    monkeypatch.setenv("AEGIS_MAIL_AUTHSERV_ID", "mx.bank.in")
    gw = "mx.bank.in; spf=fail smtp.mailfrom=ceo@evil.example; dkim=none; dmarc=fail header.from=bank.in"
    r = header_auth_check({"Authentication-Results": gw, "SPF": "pass", "DKIM": "pass", "DMARC": "pass"})
    assert r.weight == "high" and r.data["spf"] == "fail" and r.data["dmarc"] == "fail"
    gw2 = "mx.bank.in; spf=fail smtp.mailfrom=dkim=pass.dmarc=pass@evil.example; dkim=none; dmarc=fail header.from=bank.in"
    r = header_auth_check({"Authentication-Results": gw2})
    assert (r.data["spf"], r.data["dkim"], r.data["dmarc"]) == ("fail", "none", "fail")


# ---- D-2: honeytoken field coverage and normalisation ---------------------------------------------------------------


@pytest.mark.parametrize("alert", [
    {"user_id": "svc_banking_legacy"}, {"username": "SVC_BANKING_LEGACY"}, {"url": "/Admin-Internal-Debug"},
    {"url": "/%2egit/config"}, {"url": "/.git//config"}, {"query_string": "k=AKIA_DECOY_8X4F7Q2N"},
    {"post_body": "key=AKIA_DECOY_8X4F7Q2N"},
    {"request_headers": {"Authorization": "AWS AKIA_DECOY_8X4F7Q2N:sig"}},
])
def test_d2_honeytoken_seen_in_renamed_fields_and_encodings(alert):
    from aegis.agents.deception.honeytoken_monitor import HoneytokenMonitor
    assert HoneytokenMonitor(registry=None).alert_touches_decoy(alert)


def test_d2_ordinary_request_is_not_a_decoy_touch():
    from aegis.agents.deception.honeytoken_monitor import HoneytokenMonitor
    assert not HoneytokenMonitor(registry=None).alert_touches_decoy({"url": "/accounts/summary", "username": "u_42891"})


# ---- D-3: cloud control plane — IAM wildcard grants and S3 public exposure ------------------------------------------


def test_d3_service_wildcard_inline_policy_and_public_s3():
    from aegis.agents.cloud_controlplane import tools as t
    pol = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"arn:aws:iam::111122223333:*"}]}'
    r = t.iam_change_check({"eventName": "PutUserPolicy", "eventSource": "iam.amazonaws.com",
                            "requestParameters": {"policyDocument": pol}})
    assert r.weight == "high" and r.data["admin_grant"]
    grant = {"AccessControlPolicy": {"AccessControlList": {"Grant": [
        {"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}]}}}
    for name in ("DeleteBucketPublicAccessBlock", "PutBucketAcl", "DeletePublicAccessBlock"):
        ws = [x.weight for x in t.run_all_tools({"eventName": name, "eventSource": "s3.amazonaws.com",
                                                  "requestParameters": grant})]
        assert "high" in ws, name


# ---- D-4: peer sync must not refresh last_seen -----------------------------------------------------------------------


def test_d4_sync_ping_pong_does_not_keep_an_ioc_alive():
    from aegis.agents.threat_intel.store import IOC, LLM_TAG, IOCStore
    from aegis.agents.threat_intel.sync import export_for_peer, import_from_peer
    now = [1_800_000_000.0]
    with mock.patch("time.time", lambda: now[0]):
        a, b = IOCStore(), IOCStore()
        a.add(IOC(kind="domain", value="one-off.example.net", confidence=0.6, source="advisory:X",
                  tags=(LLM_TAG,), ttl_seconds=3 * 86400, last_seen=now[0]))
        for _ in range(24 * 5):
            now[0] += 3600
            import_from_peer(b, export_for_peer(a))
            import_from_peer(a, export_for_peer(b))
        assert a._lookup("one-off.example.net", "domain") is None


# ---- D-5: shared provider apexes and opt-in subdomain matching -------------------------------------------------------


def test_d5_provider_apexes_rejected_and_parent_match_is_opt_in():
    from aegis.agents.ndr.egress import EgressDetector
    from aegis.agents.threat_intel.store import IOC, IOCStore
    s = IOCStore()
    for d in ("sharepoint.com", "s3.ap-south-1.amazonaws.com", "azure-api.net", "npci.org.in", "akamaiedge.net"):
        assert not s.add(IOC(kind="domain", value=d, confidence=0.85, source="misp:event:1")), d
    assert s.add(IOC(kind="domain", value="tenant-c2.example", confidence=0.9, source="feed"))
    assert s.add(IOC(kind="domain", value="*.wild-c2.example", confidence=0.9, source="feed"))
    det = EgressDetector(ioc_store=s)

    def hit(sni: str, i: int) -> list:
        out = det.observe({"kind": "tls", "src": f"10.1.2.{i}", "dst": "52.10.10.10", "sni": sni, "dport": 443,
                           "ts": 1_790_000_000 + i})
        return [a for a in out if a and a["alert_type"] == "tls_known_bad"]
    assert hit("tenant-c2.example", 1)                       # exact
    assert not hit("bankcorp.tenant-c2.example", 2)          # parent label, no opt-in
    assert hit("x.wild-c2.example", 3)                       # "*." opted in


def test_d5_misp_search_enforces_warninglists():
    import inspect

    from aegis.agents.threat_intel import misp_client
    assert '"enforceWarninglist": True' in inspect.getsource(misp_client)


# ---- D-6: an AI SNI does not hide an IP beacon -----------------------------------------------------------------------


def test_d6_beacon_to_own_ip_under_ai_sni_is_reported():
    from aegis.agents.ndr.egress import EgressDetector
    det = EgressDetector()
    alerts = []
    for i in range(40):
        alerts += det.observe({"kind": "tls", "src": "10.9.9.9", "dst": "203.0.113.9", "sni": "api.openai.com",
                               "dport": 443, "ts": 1_790_000_000 + 60 * i, "ja4": "t13d1516h2_8daaf6152771_02713d6af862"})
    kinds = {a["alert_type"] for a in alerts if a}
    assert {"shadow_ai", "tls_beacon"} <= kinds


# ---- D-7: syslog severity 0 is an emergency --------------------------------------------------------------------------


@pytest.mark.parametrize("mn", ["ENVM-0-SHUTDOWN", "PLATFORM-0-CHASSIS_FAIL"])
def test_d7_severity_zero_hardware_fault(mn):
    from aegis.agents.netops.assurance import NetworkAssurance
    out = NetworkAssurance().observe({"kind": "syslog", "device": f"core-{mn}", "mnemonic": mn, "severity": 0,
                                      "msg": "x", "ts": time.time()})
    assert [a["netops"]["fault"] for a in out] == ["hardware_fault"]


# ---- D-8: COPY pattern is linear ------------------------------------------------------------------------------------


def test_d8_copy_pattern_no_redos_and_still_matches():
    from aegis.agents.api_abuse import tools as t
    t0 = time.time()
    t.db_direct_query_check("psql", "copy (" * 20_000, 1, "10.0.0.5")
    assert time.time() - t0 < 2.0
    r = t.db_direct_query_check("psql", "COPY (SELECT * FROM (select 1) x) TO '/tmp/a'", 1, "10.0.0.5")
    assert r.data["risky_patterns"] and r.weight == "high"


# ---- D-9: wildcard-DNS SSRF ------------------------------------------------------------------------------------------


@pytest.mark.parametrize("url,want", [
    ("http://127.0.0.1.nip.io/latest/meta-data", "high"), ("http://169.254.169.254.nip.io/", "high"),
    ("http://localtest.me:8080/admin", "high"), ("http://10-0-0-5.sslip.io/", "high"),
    ("http://8.8.8.8.nip.io/", "low"), ("http://www.example.com/", "low"),
])
def test_d9_wildcard_dns_ssrf(url, want):
    from aegis.agents.perimeter.tools import ssrf_probe
    assert ssrf_probe(f"url={url}").weight == want


# ---- D-10: STIX revoked / expired / malformed confidence -------------------------------------------------------------


def test_d10_stix_revoked_expired_and_bad_confidence():
    from aegis.agents.threat_intel import feeds
    from aegis.agents.threat_intel.store import RETRACTED_TAG

    def live(out):                     # round 8 D8-11: revoked / expired come back as retractions, never live
        return [i for i in out if RETRACTED_TAG not in i.tags]
    assert live(feeds.parse_stix_bundle({"objects": [{"type": "indicator", "pattern": "[ipv4-addr:value = '52.66.1.10']",
                                                      "revoked": True, "confidence": 90}]})) == []
    assert live(feeds.parse_stix_bundle({"objects": [{"type": "indicator", "pattern": "[ipv4-addr:value = '52.66.1.11']",
                                                      "valid_until": "2020-01-01T00:00:00Z", "confidence": 90}]})) == []
    out = feeds.parse_stix_bundle({"objects": [
        {"type": "indicator", "pattern": "[ipv4-addr:value = '5.5.5.5']", "confidence": "high"},
        {"type": "indicator", "pattern": "[ipv4-addr:value = '6.6.6.6']"}]})
    assert {i.value for i in out} == {"5.5.5.5", "6.6.6.6"}


# ---- D-11: perimeter honours confidence and canonical IPs ------------------------------------------------------------


def test_d11_low_confidence_ioc_is_not_known_malicious_and_mapped_ip_matches():
    from aegis.agents.perimeter import tools as p
    from aegis.agents.threat_intel.store import IOC, IOCStore
    s = IOCStore()
    s.add(IOC(kind="ip", value="93.184.216.34", confidence=0.02, source="stix_feed"))
    s.merge_into_perimeter()
    r = p.ip_reputation("93.184.216.34")
    assert r.weight == "low" and r.data["verdict"] != "known_malicious"
    assert p.ip_reputation("::ffff:185.220.101.45").data["verdict"] == "known_malicious"


# ---- D-12: EDR IOC matching, sha1/sha256, TCC allow-list -------------------------------------------------------------


def test_d12_edr_ioc_and_tcc():
    from aegis.agents.edr import tools as e
    from aegis.agents.threat_intel.store import IOC, IOCStore
    assert e.ioc_match(None, "x7f3a.c2.attacker.test", None).weight == "high"
    assert e.ioc_match(None, None, "::ffff:203.0.113.66").weight == "high"
    assert e.tcc_grant("kTCCServiceScreenCapture", "com.apple.evil-updater", True,
                       authority="Developer ID Application: Evil (X1)").weight != "low"   # round 8 D8-12
    assert e.tcc_grant("kTCCServiceMicrophone", "/Applications/zoom.us.app.evil/Contents/MacOS/x", True).weight == "high"
    s = IOCStore()
    sha1 = "a" * 40
    assert s.add(IOC(kind="hash_md5", value=sha1, confidence=0.9, source="misp"))       # mislabelled → sha1
    assert s.lookup(sha1, "hash_sha1") is not None
    s.merge_into_edr()
    assert e.ioc_match(None, None, None, hashes={"sha1": sha1}).weight == "high"


# ---- D-13: SSID look-alikes and OUI spoof ----------------------------------------------------------------------------


@pytest.mark.parametrize("ssid", ["BankWiFi-PoS\u200b", "BankWiFi-PoS ", "BankWiFi-PоS"])
def test_d13_lookalike_ssid_is_rogue_and_twin(ssid):
    from aegis.agents.wireless import tools as w
    rec = {"ssid": ssid, "bssid": "de:ad:be:ef:00:01", "known_bssids": ["b4:99:ba:00:00:01"],
           "captive_portal_detected": True}
    assert w.rogue_ap_check(rec).weight == "high" and w.evil_twin_check(rec).weight == "high"


def test_d13_authorised_oui_without_controller_list_is_unverified():
    from aegis.agents.wireless import tools as w
    r = w.rogue_ap_check({"ssid": "BankWiFi-PoS", "bssid": "b4:99:ba:aa:bb:cc"})
    assert r.weight == "medium" and r.data["bssid_unverified"]
    ok = w.rogue_ap_check({"ssid": "BankWiFi-PoS", "bssid": "b4:99:ba:aa:bb:cc", "known_bssids": ["B4-99-BA-AA-BB-CC"]})
    assert ok.weight == "low"


# ---- D-14: formatted rupee amounts ----------------------------------------------------------------------------------


def test_d14_formatted_amounts():
    from aegis.agents.transaction import tools as t
    assert t._amount("₹9,50,000") == 950000 and t._amount("INR 1,50,000.00") == 150000
    assert t.payment_rail_anomaly("u_42891", "RTGS", "₹1,50,000").weight == "high"
    assert t.velocity_check("u_77104", "70", "₹9,50,000").weight == "high"


# ---- D-15: DNS exfil groups by registrable domain -------------------------------------------------------------------


def test_d15_dns_exfil_registrable_domain():
    from aegis.agents.edr.tools import dns_exfil_check
    benign = dns_exfil_check([f"www.bank{i % 7}.co.in" for i in range(60)])
    assert benign.weight == "low" and benign.data["top_domain"] != "co.in"
    tunnel = dns_exfil_check([f"{i:040x}.t.evil.co.in" for i in range(60)])
    assert tunnel.data["top_domain"] == "evil.co.in" and tunnel.data["high_concentration"]
