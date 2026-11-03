"""Round-4 review, group H7: the specialist detectors — attack evasions caught, ordinary bank traffic left alone."""

from __future__ import annotations

import base64
import json
import time

import pytest

# ---- perimeter -----------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("body", [
    '{"txn_time": "2026-11-03T10:30:00+05:30", "vpa": "ravi@okhdfcbank", "amount": "1500.00"}',
    "remarks=meeting at 10:30&neft_cutoff=16:00",
    '{"utr": "SBIN426307123456", "value_date": "2026-11-03 16:00:00"}',
])
def test_upi_and_neft_bodies_are_not_ssrf(body):
    from aegis.agents.perimeter.tools import ssrf_probe
    assert ssrf_probe(body).weight == "low"


def test_internal_service_ref_still_counts():
    from aegis.agents.perimeter.tools import ssrf_probe
    assert ssrf_probe("url=meta:8000/latest").weight == "high"
    assert ssrf_probe("u=10.0.0.5:8080").weight == "high"


def test_base64_after_a_parameter_name_is_decoded():
    from aegis.agents.perimeter.tools import decode_payload
    b64 = base64.b64encode(b"1 union select password from users").decode()
    for raw in (f"q={b64}", f"q={b64.rstrip('=')}", f"q={b64.replace('=', '%3D')}"):
        assert decode_payload(raw).data["primitives"]["sqli"], raw


@pytest.mark.parametrize("raw", [
    "1 union(select(password)from(users))",
    "id=1%20UNION%23x%0ASELECT%201",
    json.dumps({"q": "1'\nOR\n1=1"}),
])
def test_sqli_evasions(raw):
    from aegis.agents.perimeter.tools import decode_payload
    assert decode_payload(raw).data["primitives"]["sqli"], raw


def test_comment_padding_is_linear():
    from aegis.agents.perimeter.tools import decode_payload
    t = time.perf_counter()
    decode_payload("/*a" * 11_000)
    assert time.perf_counter() - t < 1.0


def test_secret_paths_on_segment_boundaries_and_customer_exports():
    from aegis.agents.perimeter.tools import secret_file_probe
    assert secret_file_probe({"url": "/.env"}).weight == "high"
    assert secret_file_probe({"url": "/app/.env.production"}).weight == "high"
    assert secret_file_probe({"url": "/api/.envelope/list"}).weight == "low"
    assert secret_file_probe({"url": "/netbanking/statements/export/oct-2026.zip", "status": 200}).weight == "low"
    assert secret_file_probe({"url": "/export/customers.zip"}).weight == "high"


def test_attack_in_the_middle_of_a_long_payload_survives_the_cut():
    from aegis.ingest import waf as W
    body = "a=" + "x" * 20_000 + "&id=1' UNION SELECT card_no,cvv FROM cards-- &b=" + "y" * 20_000
    out = W._cut_keeping_attack(body)
    assert "UNION SELECT" in out and len(out) < 40_000


# ---- cloud control plane ---------------------------------------------------------------------------------------------------

def test_bucket_policy_as_object_and_azure_public_access():
    from aegis.agents.cloud_controlplane.tools import resource_policy_check
    pol = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                                                   "Resource": "arn:aws:s3:::kyc-docs/*"}]}
    assert resource_policy_check({"eventName": "PutBucketPolicy",
                                  "requestParameters": {"bucketPolicy": pol}}).weight == "high"
    private = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::1:role/app"}, "Action": "s3:*"}]}
    assert resource_policy_check({"eventName": "PutBucketPolicy",
                                  "requestParameters": {"bucketPolicy": private}}).weight == "low"
    assert resource_policy_check({"operationName": "Microsoft.Storage/storageAccounts/write",
                                  "properties": {"publicNetworkAccess": "Enabled"}}).weight == "high"
    assert resource_policy_check({"eventName": "PutBucketPublicAccessBlock", "requestParameters": {
        "PublicAccessBlockConfiguration": {"BlockPublicAcls": False, "IgnorePublicAcls": False,
                                           "BlockPublicPolicy": False, "RestrictPublicBuckets": False}}}).weight == "high"


def test_split_internet_ranges_and_escaped_wildcards():
    from aegis.agents.cloud_controlplane.tools import _is_internet, iam_change_check
    assert _is_internet("0.0.0.0/1") and _is_internet("128.0.0.0/1") and not _is_internet("10.0.0.0/8")
    assert not _is_internet("203.0.113.0/24")
    doc = '{"Statement": [{"Effect": "Allow", "Action": "\\u002a", "Resource": "\\u002a"}]}'
    r = iam_change_check({"eventName": "CreatePolicyVersion", "eventSource": "iam.amazonaws.com",
                          "requestParameters": {"policyDocument": doc}})
    assert r.data["has_wildcard_policy"]


# ---- NDR ----------------------------------------------------------------------------------------------------------------------

def _det():
    from aegis.agents.ndr.ai_usage import AiRegister, AiUsageRegister
    from aegis.agents.ndr.egress import EgressDetector
    from aegis.agents.ndr.tls_intel import TlsIntel
    return EgressDetector(intel=TlsIntel(), ai=AiRegister(), usage=AiUsageRegister(), internal=None)


def test_rotating_sni_beacon_to_one_ip_is_seen():
    d, found = _det(), []
    for i in range(40):
        found += d.observe({"kind": "flow", "src": "10.1.1.5", "dst": "203.0.113.9", "dport": 443,
                            "sni": f"n{i}.cdn-evil.net", "ts": 1_780_000_000.0 + 60 * i, "bytes_out": 800,
                            "bytes_in": 400}) or []
    assert "tls_beacon" in [a["alert_type"] for a in found]


def test_forged_allow_listed_sni_exfil_is_seen(monkeypatch):
    monkeypatch.setenv("AEGIS_NDR_ALLOW_DOMAINS", "windowsupdate.com")
    d, found = _det(), []
    for i in range(100):
        found += d.observe({"kind": "flow", "src": "10.1.1.5", "dst": "203.0.113.9", "dport": 443,
                            "sni": "x.windowsupdate.com", "ts": 1_780_000_000.0 + 10 * i, "bytes_out": 5_000_000,
                            "bytes_in": 2000}) or []
    assert "tls_exfil" in [a["alert_type"] for a in found]


def test_allow_listed_name_does_not_hide_a_known_bad_ip():
    from aegis.agents.ndr.tls_intel import TlsIndicator, TlsIntel
    intel = TlsIntel()
    intel.add(TlsIndicator("ip", "203.0.113.66", "c2", 0.9, "test"))
    intel.add(TlsIndicator("domain", "evil-c2.azurewebsites.net", "c2", 0.9, "test"))
    assert intel.match(sni="evil-c2.azurewebsites.net", ip="203.0.113.66", skip_domain=True).kind == "ip"


# ---- EDR ---------------------------------------------------------------------------------------------------------------------

def test_routine_sysmon_rows_are_not_alerts_and_utc_time_is_read():
    from aegis.agents.edr.normalize import _utc, from_sysmon, to_alert
    assert to_alert({"EventID": 1, "Computer": "br-pc-01", "Image": "C:\\Windows\\notepad.exe",
                     "ParentImage": "C:\\Windows\\explorer.exe", "CommandLine": "notepad.exe"}) is None
    assert to_alert({"EventID": 22, "Computer": "br-pc-01", "QueryName": "intranet.bank.in"}) is None
    a = from_sysmon({"event_id": 3, "host": "h", "DestinationIp": "203.0.113.9", "DestinationPort": "443",
                     "UtcTime": "2026-11-03 10:30:00.123"})
    assert a["egress_ts"] == _utc("2026-11-03 10:30:00.123") and a["egress_ts"] > 0


def test_beacon_scorer_jitter_and_internal_destinations():
    import random

    from aegis.agents.edr.tools import beacon_periodicity
    rnd = random.Random(7)
    t, times = 0.0, []
    for _ in range(30):
        t += 60 * (1 + rnd.uniform(-0.3, 0.3))                 # Cobalt Strike default jitter
        times.append(t)
    assert beacon_periodicity(times, "203.0.113.9").weight == "high"
    assert beacon_periodicity([60.0 * i for i in range(30)], "10.20.0.15").weight == "low"


def test_ioc_match_is_case_insensitive():
    from aegis.agents.edr.tools import ioc_match
    assert ioc_match("44D88612FEA8A8F36DE82E1278ABB02F", "Evil.Example.com.", None).data["n"] == 2


# ---- DLP ---------------------------------------------------------------------------------------------------------------------

def test_upi_settlement_and_neft_payroll_are_not_pii_floods():
    from aegis.agents.dlp.tools import sensitive_data_pattern_check
    rrns = "\n".join(f"{426307000000 + i * 7919},ravi{i}@okaxis,1500.00,SUCCESS" for i in range(600))
    assert sensitive_data_pattern_check(rrns).weight == "low"
    payroll = "\n".join(f"EMP{i},HDFC0001234,50100{i:07d},45000" for i in range(60))
    assert sensitive_data_pattern_check(payroll).weight == "low"


def test_labelled_aadhaar_and_all_text_fields_count():
    from aegis.agents.dlp.tools import _verhoeff, run_all_tools
    nums = [n for n in (f"2345{i:08d}" for i in range(2000)) if _verhoeff(n)][:60]
    rows = "\n".join(f"aadhaar_no,{n}" for n in nums)
    res = {r.name: r for r in run_all_tools({"query": "select 1", "attachment_text": rows})}
    assert res["sensitive_pattern"].data["findings"].get("aadhaar") == len(nums)
    assert res["sensitive_pattern"].weight == "high"


def test_display_form_recipients_are_internal():
    from aegis.agents.dlp.tools import external_recipient_check
    assert external_recipient_check(["Alice <alice@bank.in>", "Bob Kumar <bob@corp.bank.in>"]).data["internal_only"]


# ---- email ---------------------------------------------------------------------------------------------------------------------

def test_header_auth_per_method_and_case(monkeypatch):
    from aegis.agents.email.tools import header_auth_check
    monkeypatch.delenv("AEGIS_MAIL_AUTHSERV_ID", raising=False)
    fwd = {"Authentication-Results": "mx.bank.in; spf=pass smtp.mailfrom=x; dkim=fail; dmarc=pass"}
    assert header_auth_check(fwd).weight == "low"
    ok = {"authentication-results": "mx.bank.in; spf=pass; dkim=pass (signature verified); dmarc=pass"}
    assert header_auth_check(ok).weight == "low"
    assert header_auth_check({"dkim": "pass (signature verified)", "spf": "pass", "dmarc": "pass"}).weight == "low"


def test_only_our_gateways_authentication_results_count(monkeypatch):
    from aegis.agents.email.tools import header_auth_check
    monkeypatch.setenv("AEGIS_MAIL_AUTHSERV_ID", "mx.bank.in")
    forged = {"Authentication-Results": ["evil.example; spf=pass; dkim=pass; dmarc=pass",
                                         "mx.bank.in; spf=fail; dkim=fail; dmarc=fail"]}
    assert header_auth_check(forged).weight == "high"


def test_display_names_and_lookalikes():
    from aegis.agents.email.tools import (
        display_name_spoof_check,
        lookalike_domain_check,
    )
    assert display_name_spoof_check("Harbinder Singh", "harbinder@gmail.com").weight == "low"
    assert display_name_spoof_check("RBI Notice", "notice@rbi-alerts.co").weight == "high"
    assert display_name_spoof_check("CFO", "cfo@evilbank.in").weight == "high"
    for u in ("https://netbanking.sbl.co.in/login", "https://sbi.co.in@sbl-kyc.in/"):
        assert lookalike_domain_check(None, [u]).weight == "high", u
    assert lookalike_domain_check(None, ["https://onlinesbi.sbi.co.in/"]).weight == "low"


# ---- wireless / mobile / transaction / biometrics ------------------------------------------------------------------------

def test_known_bssid_in_another_format_is_not_a_twin():
    from aegis.agents.wireless.tools import evil_twin_check
    r = evil_twin_check({"ssid": "BankWiFi-PoS", "bssid": "B4-99-BA-11-22-33", "known_bssids": ["b4:99:ba:11:22:33"]})
    assert r.weight == "low"


def test_string_flags_and_amounts():
    from aegis.agents.mobile.tools import mobile_session_anomaly_check
    from aegis.agents.transaction.tools import (
        aml_structuring_check,
        swift_specific_check,
    )
    assert mobile_session_anomaly_check({"screen_overlay_detected": "true"}).weight == "high"
    assert mobile_session_anomaly_check({"screen_overlay_detected": "false"}).weight == "low"
    assert swift_specific_check({"rail": "SWIFT", "lau_mac_verification_failed": "true"}).weight == "high"
    assert aml_structuring_check(["950000", "960,000", 955000.0]).weight == "high"


def test_tool_failure_is_not_a_clear_result():
    from aegis.agents.mobile.tools import ToolResult
    from aegis.agents.shared.tool_guard import isolated
    r = isolated(lambda: 1 / 0, "x", ToolResult)
    assert r.weight == "medium" and r.data["tool_failed"]


def test_nan_biometrics_is_far_not_near():
    from aegis.agents.auth.biometrics import (
        _BIOMETRIC_BASELINES,
        behavioral_baseline_diff,
    )
    uid = next(iter(_BIOMETRIC_BASELINES))
    assert behavioral_baseline_diff(uid, {"typing_dwell_ms_p50": float("nan")}).weight == "high"


# ---- API object walk ------------------------------------------------------------------------------------------------------------

def test_object_walk_templates_are_normalised():
    from aegis.agents.api_abuse.object_walk import objects_in
    a = objects_in("/api/v1/Accounts//1002/")[0]
    b = objects_in("/api/v1/accounts/./1003")[0]
    assert a == b == "/api/v1/accounts/{id}"


# ---- edge sender ----------------------------------------------------------------------------------------------------------------

def test_edge_sender_sheds_page_views_before_findings_and_batches():
    import importlib.util
    import sys
    import types
    from pathlib import Path
    p = Path(__file__).resolve().parents[2] / "scripts" / "demo_target.py"
    spec = importlib.util.spec_from_file_location("demo_target_h7", p)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["demo_target_h7"] = mod
    spec.loader.exec_module(mod)
    s = mod._AlertSender(cap=10, batch=4)
    s._thread = types.SimpleNamespace(is_alive=lambda: True)
    s.submit("u", b'{"id":"EXPLOIT"}\n', {}, priority=True)
    for i in range(50):
        s.submit("u", f'{{"id":"pv{i}"}}\n'.encode(), {})
    assert any(b"EXPLOIT" in d for _, d, _ in s._hi) and s.dropped_findings == 0
    batch = s._take()
    assert len(batch) == 4 and b"EXPLOIT" in batch[0][1]
    assert s.stats()["queued"] == 6
