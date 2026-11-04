"""Round-7 ingest / exposure review regressions (G-1 … G-11)."""
from __future__ import annotations

import gzip
import json
import logging
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime

import pytest

from aegis.agents.response.connectors.http import HttpResult
from aegis.exposure import remediation
from aegis.exposure.coverage import from_f5
from aegis.exposure.engine import Asset, Vuln, assess
from aegis.exposure.k8s_reach import _waf_ingress
from aegis.exposure.loaders import assets_from_aws
from aegis.exposure.scan import to_finding
from aegis.ingest.base import CONSUMED, AlertCheckpoint
from aegis.ingest.stream import StreamConsumer, StreamQueue
from aegis.posture.runner import fingerprint


# --------------------------------------------------------------------- G-1 --
def _aws_bundle():
    return {
        "security_groups": [
            {"GroupId": "sg-inst", "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 8080, "ToPort": 8080,
                                                      "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]},
            {"GroupId": "sg-alb", "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                                                     "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}],
        "instances": [{"InstanceId": "i-1", "State": {"Name": "running"}, "PublicIpAddress": "52.1.1.1",
                       "PrivateIpAddress": "10.0.0.5", "VpcId": "vpc-1", "SecurityGroups": [{"GroupId": "sg-inst"}]}],
        "load_balancers": [{"LoadBalancerName": "alb", "Scheme": "internet-facing", "Type": "application",
                            "SecurityGroups": ["sg-alb"], "listeners": [{"Port": 443}],
                            "targets": [{"Id": "i-1", "Port": 80}], "web_acl": "acl"}],
    }


def test_g1_alb_waf_does_not_cover_a_direct_port():
    assets = assets_from_aws(_aws_bundle())
    (direct,), _ = assess([Vuln(asset="i-1", cve="CVE-2099-0001", title="RCE", port=8080, kev=True, cvss=9.8)], assets)
    assert (direct.tier, direct.reach, direct.defended) == ("ACT_NOW", "internet", "none")


def test_g1_modsecurity_detection_only_is_not_a_waf():
    base = "nginx.ingress.kubernetes.io/"
    off = {"metadata": {"annotations": {base + "enable-modsecurity": "true"}}}
    on = {"metadata": {"annotations": {base + "enable-modsecurity": "true",
                                       base + "modsecurity-snippet": "SecRuleEngine   On\nSecAuditEngine On"}}}
    assert not _waf_ingress(off)
    assert _waf_ingress(on)


# --------------------------------------------------------------------- G-2 --
def test_g2_azure_waf_rows_sharing_a_transaction_are_distinct():
    rows = [{"category": "ApplicationGatewayFirewallLog", "properties": {
        "clientIp": "203.0.113.9", "requestUri": "/login?id=1' or 1=1--", "ruleSetType": "OWASP", "ruleId": rid,
        "message": msg, "action": act, "transactionId": "tx-abc"}}
        for rid, msg, act in (("920350", "Host header is a numeric IP address", "Matched"),
                              ("942100", "SQL Injection Attack Detected via libinjection", "Matched"),
                              ("949110", "Inbound Anomaly Score Exceeded", "Blocked"))]
    q = StreamQueue(100)
    q.put_many("waf-azure", [json.dumps(r) for r in rows])
    out = list(StreamConsumer(queue=q, checkpoint=AlertCheckpoint()).iter_alerts())
    assert len(out) == 3 and len({a["id"] for a in out}) == 3
    assert {a.get("correlation_id") for a in out} == {"tx-abc"}


# --------------------------------------------------------------------- G-3 --
def test_g3_sentinel_timespan_covers_the_watermark_gap():
    from aegis.ingest.sentinel import SentinelConfig, SentinelConsumer
    cp = AlertCheckpoint()
    cp.advance("sentinel:ingested", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 3 * 3600)))
    sent = []

    def transport(method, url, body, headers, timeout):
        if "oauth2" in url:
            return 200, json.dumps({"access_token": "t", "expires_in": 3600})
        sent.append(json.loads(body))
        return 200, json.dumps({"tables": []})

    list(SentinelConsumer(SentinelConfig("ws", "tn", "cl", "sec"), checkpoint=cp, transport=transport).iter_alerts())
    span = sent[0]["timespan"]
    assert span.startswith("PT") and span.endswith("S")
    assert int(span[2:-1]) > 3 * 3600                     # the 3 h gap (plus lag allowance) is inside the window


# --------------------------------------------------------------------- G-4 --
def test_g4_edr_long_commandline_on_two_hosts_is_two_alerts():
    cmd = "powershell.exe -nop -w hidden -enc " + "SQBFAFgAIAAoAE4AZQB3AC0A" * 300

    def ev(host, guid, t):
        return {"EventID": 1, "CommandLine": cmd, "Computer": host, "Image": "C:\\powershell.exe",
                "ParentImage": "C:\\WINWORD.EXE", "ProcessGuid": guid, "User": "BANK\\teller", "UtcTime": t}
    q = StreamQueue(100)
    q.put_many("edr", [json.dumps(ev("H1", "{1}", "2026-11-04 09:00:00")), json.dumps(ev("H2", "{2}", "2026-11-04 11:30:00"))])
    c = StreamConsumer(queue=q, checkpoint=AlertCheckpoint())
    out = list(c.iter_alerts())
    assert len(out) == 2 and c.skipped_duplicates == 0


# --------------------------------------------------------------------- G-5 --
def test_g5_epss_drop_on_an_open_path_is_not_verified_closed(tmp_path):
    a = Asset(id="i-1", name="netbank", keys={"i-1"}, zone="vpc", public=True, internet_ports=[(8080, 8080)],
              source="inventory")

    def row(epss):
        (e,), _ = assess([Vuln(asset="i-1", cve="CVE-2099-1", title="RCE", port=8080, epss=epss, cvss=8.1)], [a])
        f = to_finding(e)
        d = f.as_dict()
        d.update(scan="x", fingerprint=fingerprint("x", f))
        return d

    sec = remediation.reconcile(tmp_path, {"open": [row(0.40)]}, now=datetime(2026, 11, 1, tzinfo=UTC))
    p = sec["proposals"][0]
    p["status"], p["approved_at"] = "approved", "2026-11-01T00:00:00Z"
    remediation.save(tmp_path, sec)
    r2 = row(0.08)
    assert r2["extra"]["reach"] == "internet" and r2["extra"]["defended"] == "none"
    sec = remediation.reconcile(tmp_path, {"open": [r2]}, now=datetime(2026, 11, 3, tzinfo=UTC))
    p = sec["proposals"][0]
    assert p["status"] == "approved_still_open" and "still open" in p["verification"]


# --------------------------------------------------------------------- G-6 --
def test_g6_apigw_alert_taken_but_not_handled_is_redelivered():
    from aegis.ingest.apigw import ApiGatewayConsumer

    class Stub:
        def observe(self, ev):
            return {"id": "OBJWALK-1", "alert_type": "object_walk", "object_walk": {}}
    cp = AlertCheckpoint()
    line = json.dumps({"path": "/accounts/1", "method": "GET", "client_ip": "1.2.3.4"})
    g = ApiGatewayConsumer(detector=Stub(), checkpoint=cp).iter_alerts(lines=[line])
    assert next(g)["id"] == "OBJWALK-1"
    g.close()                                               # taken, then the caller died before handling it
    again = list(ApiGatewayConsumer(detector=Stub(), checkpoint=cp).iter_alerts(lines=[line]))
    assert [x["id"] for x in again] == ["OBJWALK-1"]


def test_g6_apigw_event_without_alert_is_consumed():
    from aegis.ingest.apigw import ApiGatewayConsumer

    class Quiet:
        def observe(self, ev):
            return None
    assert ApiGatewayConsumer(detector=Quiet(), checkpoint=AlertCheckpoint()).normalize(
        {"path": "/accounts/1", "method": "GET", "client_ip": "1.2.3.4"}) is CONSUMED


# --------------------------------------------------------------------- G-7 --
class _Fake:
    def __init__(self, routes):
        self.routes = routes

    def __call__(self, method, url, json_body, headers, timeout):
        for (m, frag), body in self.routes.items():
            if m == method and frag in url:
                return HttpResult(200, body)
        return HttpResult(404, {"errors": ["not found"]})


@pytest.mark.parametrize("sig", [
    {"enabled": True, "performStaging": True, "block": True, "signatureReference": {"signatureId": 300000001}},   # staged
    {"enabled": False, "performStaging": False, "block": True, "signatureReference": {"signatureId": 300000001}},  # off
    {"enabled": True, "performStaging": False, "block": False, "signatureReference": {"signatureId": 300000001}},  # alarm only
    {"enabled": True, "performStaging": False, "block": True, "signatureReference": {"signatureId": 999}},         # other sig
])
def test_g7_f5_virtual_patch_needs_an_enforced_signature_on_that_policy(sig):
    t = _Fake({
        ("GET", "/mgmt/tm/asm/signatures"): {"items": [{"name": "VP_CVE-2021-44228_jndi", "signatureId": 300000001}]},
        ("GET", "/mgmt/tm/asm/policies/P1/signatures"): {"items": [sig]},
        ("GET", "/mgmt/tm/ltm/virtual"): {"items": [
            {"fullPath": "/Common/vs", "destination": "/Common/203.0.113.10:443", "pool": ""}]},
        ("GET", "/mgmt/tm/asm/policies"): {"items": [
            {"id": "P1", "name": "nb", "enforcementMode": "blocking", "virtualServers": ["/Common/vs"]}]},
    })
    (cov,) = from_f5("https://bigip", t, token="tok")
    assert cov.mode == "block" and cov.virtual_patches == []


# --------------------------------------------------------------------- G-8 --
def test_g8_acp_requests_all_severities_and_filters_locally():
    from aegis.ingest.acp import AcpGovernanceConsumer
    urls = []

    def transport(method, url, body, headers, timeout):
        urls.append(url)
        return 200, json.dumps({"events": [
            {"id": "e1", "kind": "rogue", "severity": "LOW", "ts": "2026-11-04T00:00:00Z"},
            {"id": "e2", "kind": "rogue", "severity": "HIGH", "ts": "2026-11-04T00:00:01Z"}], "next_since": ""})
    c = AcpGovernanceConsumer("https://dash", "k", checkpoint=AlertCheckpoint(), transport=transport, min_severity="MEDIUM")
    out = list(c.iter_alerts())
    assert "min_severity=INFO" in urls[0]
    assert [a["id"] for a in out] == ["ACP-e2"]
    assert c.normalize({"id": "e3", "severity": "LOW"}) is CONSUMED


# --------------------------------------------------------------------- G-9 --
def test_g9_gzip_bomb_is_413_and_truncated_gzip_is_400(monkeypatch):
    from aegis.ingest.http_push import PushServer
    monkeypatch.setenv("AEGIS_INGEST_MAX_INFLATE_MB", "1")
    s = PushServer(token="t", bind="127.0.0.1:0", queue=StreamQueue(10)).start()

    def post(path, body):
        r = urllib.request.Request(s.url + path, data=body, method="POST", headers={"Authorization": "Bearer t"})
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status
        except urllib.error.HTTPError as e:
            return e.code
    try:
        bomb = gzip.compress(b"A" * (3 * 1024 * 1024))
        trunc = gzip.compress(b'{"a":1}\n' * 1000)[:-20]
        for p in ("/ingest/waf", "/ingest/alerts"):
            assert post(p, bomb) == 413
            assert post(p, trunc) == 400
    finally:
        s.stop()


# -------------------------------------------------------------------- G-10 --
def test_g10_eventhub_warns_without_a_journal(caplog):
    from aegis.ingest.eventhub import EventHubReader
    r = EventHubReader.__new__(EventHubReader)
    r.queue = StreamQueue(10)
    r._run = lambda: None
    assert getattr(r.queue, "journal", None) is None
    with caplog.at_level(logging.WARNING, logger="aegis.ingest.eventhub"):
        r.start()
        r._thread.join(1)
    assert any("AEGIS_STREAM_JOURNAL" in m for m in caplog.messages)


# -------------------------------------------------------------------- G-11 --
def test_g11_splunk_es_escapes_entity_and_ids_are_unique():
    from aegis.infra.splunk_es import SplunkESConsumer
    from aegis.infra.splunk_source import SplunkConfig, SplunkConsumer
    es = SplunkESConsumer(SplunkConfig(base_url="http://splunk:8089", token="t"))
    seen = []

    class Base:
        def iter_alerts(self, *, search, **kw):
            seen.append(search)
            return iter(())
    es._base = Base()
    es.get_risk_score('x" OR risk_object="*')
    assert 'risk_object="x\\" OR risk_object=\\"*"' in seen[0]

    a = es._notable_to_alert({"rule_id": "R1", "rule_name": "Brute force", "src": "1.1.1.1"})
    b = es._notable_to_alert({"rule_id": "R1", "rule_name": "Brute force", "src": "2.2.2.2"})
    assert a["id"] != b["id"] and a["id"].startswith("ES-NOTABLE-")

    # _cd survives the base consumer's underscore strip and becomes the id
    flat = SplunkConsumer(SplunkConfig())._event_to_alert({"_cd": "12:345", "_time": "t", "rule_name": "x"})
    assert es._notable_to_alert(flat)["id"] == "12:345"
