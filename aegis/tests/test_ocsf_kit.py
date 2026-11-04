"""OCSF in/out and the declarative connector kit."""

from __future__ import annotations

import json

import pytest

from aegis.ingest import kit
from aegis.ingest.ocsf import is_ocsf, to_alert, to_detection_finding

DETECTION = {
    "class_uid": 2004, "class_name": "Detection Finding", "time": 1793754000000, "severity_id": 4,
    "metadata": {"uid": "f-001", "product": {"name": "Falcon", "vendor_name": "CrowdStrike"}, "version": "1.3.0"},
    "finding_info": {"uid": "ldt:abc", "title": "Credential dumping", "desc": "lsass access",
                     "attacks": [{"tactic": {"name": "Credential Access"}, "technique": {"uid": "T1003.001"}}]},
    "device": {"hostname": "fin-ws-07", "ip": "10.20.4.15"},
    "actor": {"user": {"name": "ravi.k"}},
    "process": {"name": "rundll32.exe", "cmd_line": "rundll32 comsvcs.dll MiniDump 612 l.dmp full",
                "parent_process": {"name": "cmd.exe"}},
}
AUTH = {"class_uid": 3002, "time": 1793754000000, "severity_id": 3, "status_id": 2, "is_mfa": False,
        "metadata": {"product": {"name": "Okta"}}, "src_endpoint": {"ip": "198.51.100.77"},
        "user": {"name": "priya.sharma@examplebank.in"}}
HTTP = {"class_uid": 4002, "time": 1793754000000, "severity_id": 4, "disposition": "Blocked",
        "metadata": {"product": {"name": "AWS WAF"}}, "src_endpoint": {"ip": "185.220.101.4"},
        "http_request": {"http_method": "GET", "url": {"url_string": "https://netbank.example/login?id=1' OR 1=1--"},
                         "user_agent": "sqlmap/1.8"}}


def test_detection_finding_maps_to_the_fields_specialists_read():
    a = to_alert(DETECTION)
    assert a["id"] == "ocsf:f-001" and a["severity"] == "high" and a["source"] == "Falcon (CrowdStrike)"
    assert a["host"] == "fin-ws-07" and a["user_id"] == "ravi.k"
    assert a["child_process"] == "rundll32.exe" and a["parent_process"] == "cmd.exe" and "comsvcs" in a["cmdline"]
    assert a["techniques"] == ["T1003.001"] and a["timestamp"].startswith("2026-")


def test_auth_and_http_events():
    a = to_alert(AUTH)
    assert a["auth_result"] == "failure" and a["source_ip"] == "198.51.100.77" and a["mfa"] is False
    h = to_alert(HTTP)
    assert h["alert_type"] == "http_activity" and "OR 1=1" in h["url"] and h["blocked"] is True


def test_non_ocsf_is_refused():
    assert not is_ocsf({"id": "x"}) and to_alert({"class_uid": "2004"}) is None


def test_verdict_goes_out_as_a_detection_finding():
    f = to_detection_finding({"chain": {"alert_id": "A1", "verdict": "malicious", "confidence": 0.93,
                                        "integrity_hash": "h", "evidence": [{"source": "waf", "weight": "high", "signal": "UNION"}],
                                        "recommended_actions": [{"action_type": "block", "target": "185.220.101.4"}]}})
    assert f["class_uid"] == 2004 and f["severity_id"] == 4 and f["confidence_score"] == 93
    assert "block -> 185.220.101.4" in f["remediation"]["desc"]


def test_ocsf_push_endpoint_feeds_the_stream():
    from aegis.ingest.base import AlertCheckpoint
    from aegis.ingest.http_push import PushServer
    from aegis.ingest.stream import StreamConsumer, StreamQueue
    q = StreamQueue()
    srv = PushServer(token="t", bind="127.0.0.1:0", queue=q)
    body = (json.dumps(DETECTION) + "\n" + json.dumps([AUTH, HTTP]) + "\n" + json.dumps({"not": "ocsf"})).encode()
    assert srv.ingest_waf(body, "ocsf-falcon")[0] == 200
    alerts = list(StreamConsumer(queue=q, checkpoint=AlertCheckpoint()).iter_alerts())
    assert {a["alert_type"] for a in alerts} == {"detection_finding", "authentication", "http_activity"}
    assert all(a["ingest_source"] == "ocsf-falcon" for a in alerts)


# ---- the kit ----------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", [c["name"] for c in kit.catalogue()])
def test_every_shipped_spec_replays_its_sample(name):
    alerts = kit.replay(name)
    assert alerts and all(a["id"].startswith(f"{name}:") and a["severity"] in ("low", "medium", "high", "critical")
                          and a.get("timestamp") for a in alerts)


def test_catalogue_is_valid_and_states_verification():
    cat = kit.catalogue()
    assert len(cat) >= 5 and not [c for c in cat if "error" in c]
    assert all(c["verified"].startswith(("recorded-sample", "live-tenant")) for c in cat)


def test_specs_must_be_read_only_and_keep_secrets_in_env():
    good = {"name": "x", "title": "x", "read_only": True, "verified": "recorded-sample", "request": {"url": "https://x"},
            "map": {"id": "id"}}
    kit.validate_spec(good)
    for bad in ({**good, "read_only": False},
                {**good, "request": {"url": "https://x", "method": "DELETE"}},
                {**good, "request": {"url": "https://x", "method": "POST"}},
                {**good, "auth": {"type": "header", "name": "Authorization", "value": "SSWS 00abcSECRET"}}):
        with pytest.raises(kit.SpecError):
            kit.validate_spec(bad)


def test_plain_http_to_a_remote_host_is_refused():
    with pytest.raises(kit.SpecError):
        kit._check_url("http://vendor.example/api")
    kit._check_url("http://127.0.0.1:8080/api")


def test_next_link_to_another_host_is_not_followed():
    spec = kit.load_spec("okta")
    pages = [(200, {"link": '<https://evil.example/steal>; rel="next"'}, json.dumps([{"uuid": "1", "published": "2026-11-04T00:00:00Z"}])),
             (200, {}, json.dumps([{"uuid": "2", "published": "2026-11-04T00:00:00Z"}]))]
    seen = []

    def t(method, url, body, headers):
        seen.append(url)
        return pages.pop(0)
    c = kit.KitConsumer(spec, transport=t, env={"OKTA_API_TOKEN": "x", "OKTA_BASE_URL": "https://example.okta.com"})
    assert len(list(c.iter_alerts())) == 1 and len(seen) == 1


def test_watermark_moves_the_next_query(tmp_path):
    from aegis.ingest.base import AlertCheckpoint
    spec = kit.load_spec("okta")
    cp = AlertCheckpoint(tmp_path / "cp.json")
    calls = []

    def t(method, url, body, headers):
        calls.append(url)
        return 200, {}, json.dumps([{"uuid": "9", "published": "2026-11-04T05:00:00Z", "severity": "WARN"}])
    env = {"OKTA_API_TOKEN": "x", "OKTA_BASE_URL": "https://example.okta.com"}
    list(kit.KitConsumer(spec, checkpoint=cp, transport=t, env=env).iter_alerts())
    list(kit.KitConsumer(spec, checkpoint=cp, transport=t, env=env).iter_alerts())
    assert "since=2026-11-04T04%3A55%3A00.000Z" in calls[-1]                  # watermark minus the 5-minute overlap


def test_registry_builds_kit_sources(monkeypatch):
    from aegis.ingest import registry
    monkeypatch.setenv("AEGIS_SOURCES", "kit:okta")
    monkeypatch.setenv("OKTA_API_TOKEN", "x"); monkeypatch.setenv("OKTA_BASE_URL", "https://example.okta.com")
    names = [n for n, _ in registry.sources_from_env()]
    assert "kit-okta" in names
