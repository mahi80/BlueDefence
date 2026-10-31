"""Phase 0.5 — Sentinel + WAF consumers yield alerts the orchestrator already understands."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from aegis.ingest import (
    AlertCheckpoint, SentinelConfig, SentinelConsumer, WafConsumer, parse_cef, parse_f5_kv,
    sources_from_env,
)

FIX = Path(__file__).resolve().parent.parent / "ingest" / "fixtures"


# ----------------------------------------------------------------- sentinel --

class FakeAzure:
    """Token endpoint + Log Analytics query endpoint, with a scripted failure sequence."""

    def __init__(self, *, query_statuses=None, token_status=200):
        self.calls: list[tuple[str, str, dict]] = []
        self.query_statuses = list(query_statuses or [])
        self.token_status = token_status
        self.tokens_issued = 0

    def __call__(self, method, url, body, headers, timeout):
        self.calls.append((method, url, headers))
        if "/oauth2/v2.0/token" in url:
            self.tokens_issued += 1
            if self.token_status != 200:
                return self.token_status, json.dumps({"error": "invalid_client"})
            return 200, json.dumps({"access_token": f"tok{self.tokens_issued}", "expires_in": 3600})
        status = self.query_statuses.pop(0) if self.query_statuses else 200
        if status != 200:
            return status, json.dumps({"error": {"message": "throttled"}})
        return 200, (FIX / "sentinel_query_response.json").read_text(encoding="utf-8")


def _cfg(**kw):
    return SentinelConfig(workspace_id="ws", tenant_id="t", client_id="c", client_secret="s",
                          max_retries=3, **kw)


def test_sentinel_rows_become_specialist_ready_alerts(monkeypatch):
    monkeypatch.setattr("aegis.ingest.sentinel.time.sleep", lambda s: None)
    az = FakeAzure()
    alerts = list(SentinelConsumer(_cfg(), transport=az).iter_alerts())
    assert [a["id"] for a in alerts] == [
        "SENTINEL-0e4d7c1a-5b7a-4c22-9f3e-1a2b3c4d5e6f",
        "SENTINEL-7d1e2f3a-9c8b-4a7d-8e6f-5a4b3c2d1e0f",
        "SENTINEL-c0ffee00-1111-2222-3333-444455556666",
    ]  # the id-less row was dropped
    ato, ps, sqli = alerts
    assert ato["source"] == "Sentinel/Azure Active Directory Identity Protection"
    assert ato["severity"] == "medium" and ato["anomaly_score"] == 0.6
    assert ato["user_id"] == "u_42891" and ato["user_upn"] == "u_42891@bank.in"
    assert ato["source_ip"] == "185.220.101.7" and ato["ips"] == ["185.220.101.7", "103.21.244.9"]
    assert ato["tactics"] == ["InitialAccess"] and ato["techniques"] == ["T1078"]
    assert ato["prev_geo"] == "IN-MH" and ato["curr_geo"] == "RU-MO"

    assert ps["host"] == "FIN-WS-0421" and ps["user_id"] == "u_77104"
    assert ps["parent_process"] == "winword.exe" and ps["child_process"] == "powershell.exe"
    assert ps["cmdline"].startswith("powershell.exe -nop") and ps["file_hash"].startswith("9f2c0d7e")
    assert ps["file_path"].endswith("invoice.docm") and ps["severity"] == "high"

    assert sqli["source_ip"] == "203.0.113.77" and "UNION%20SELECT" in sqli["url"]
    assert "UNION SELECT" in sqli["payload"]  # description text rides along for triage
    assert "Entities" not in sqli["raw"] and sqli["raw"]["AlertType"] == "WAFSQLi"
    # one token, one query
    assert az.tokens_issued == 1 and sum(1 for _, u, _ in az.calls if u.endswith("/query")) == 1
    assert az.calls[-1][2]["Authorization"] == "Bearer tok1"


def test_sentinel_retries_throttling_and_reauths_on_401(monkeypatch):
    monkeypatch.setattr("aegis.ingest.sentinel.time.sleep", lambda s: None)
    az = FakeAzure(query_statuses=[429, 503, 200])
    c = SentinelConsumer(_cfg(), transport=az)
    assert len(list(c.iter_alerts())) == 3
    assert sum(1 for _, u, _ in az.calls if u.endswith("/query")) == 3

    az2 = FakeAzure(query_statuses=[401, 200])
    c2 = SentinelConsumer(_cfg(), transport=az2)
    assert len(list(c2.iter_alerts())) == 3
    assert az2.tokens_issued == 2  # re-authenticated once after the 401

    az3 = FakeAzure(query_statuses=[500, 500, 500, 500])
    with pytest.raises(RuntimeError):
        list(SentinelConsumer(_cfg(), transport=az3).iter_alerts())


def test_sentinel_auth_failure_is_explicit():
    from aegis.ingest.sentinel import SentinelAuthError
    with pytest.raises(SentinelAuthError):
        list(SentinelConsumer(_cfg(), transport=FakeAzure(token_status=401)).iter_alerts())


def test_checkpoint_dedupes_across_polls_and_restarts(monkeypatch):
    monkeypatch.setattr("aegis.ingest.sentinel.time.sleep", lambda s: None)
    with tempfile.TemporaryDirectory() as td:
        ck = AlertCheckpoint(Path(td) / "ck.json")
        c = SentinelConsumer(_cfg(), checkpoint=ck, transport=FakeAzure())
        assert len(list(c.iter_alerts())) == 3
        assert len(list(c.iter_alerts())) == 0 and c.skipped_duplicates == 3  # overlapping window
        assert ck.watermark("sentinel") == "2026-10-21T06:12:04.511Z"
        ck2 = AlertCheckpoint(Path(td) / "ck.json")  # process restart
        c2 = SentinelConsumer(_cfg(), checkpoint=ck2, transport=FakeAzure())
        assert len(list(c2.iter_alerts())) == 0
        assert c2.stats == {"source": "sentinel", "yielded": 0, "duplicates": 3, "invalid": 1}  # the id-less row


# ---------------------------------------------------------------------- waf --

def test_cef_and_f5_parsers():
    cef = parse_cef("CEF:0|Incapsula|SIEMintegration|1|1|Illegal Resource Access|3| src=1.2.3.4 cs1=Scanner cs1Label=Cap Support act=REQ_BLOCKED")
    assert cef["vendor"] == "Incapsula" and cef["name"] == "Illegal Resource Access" and cef["severity"] == "3"
    assert cef["ext"]["src"] == "1.2.3.4" and cef["ext"]["Cap Support"] == "Scanner"
    assert parse_cef("not cef") is None
    kv = parse_f5_kv('attack_type="SQLi",ip_client="1.2.3.4",request="GET /x?a=\\"b\\" HTTP/1.1"')
    assert kv == {"attack_type": "SQLi", "ip_client": "1.2.3.4", "request": 'GET /x?a="b" HTTP/1.1'}
    assert parse_f5_kv('one="1"') is None


def test_waf_export_lines_become_perimeter_alerts():
    alerts = list(WafConsumer().iter_alerts(path=FIX / "waf_events.log"))
    assert len(alerts) == 4  # the junk line is skipped
    f5_cef, f5_kv, imperva_cef, imperva_json = alerts

    assert f5_cef["source"] == "F5 ASM" and f5_cef["id"] == "WAF-1836294834629501234"
    assert f5_cef["source_ip"] == "203.0.113.77" and f5_cef["url"] == "/api/accounts"
    assert "UNION SELECT" in f5_cef["payload"] and f5_cef["attack_type"] == "SQL-Injection"
    assert f5_cef["severity"] == "critical" and f5_cef["anomaly_score"] == 0.95
    assert f5_cef["action"] == "blocked" and f5_cef["geo"] == "RO"

    assert f5_kv["source"] == "F5 ASM" and f5_kv["id"] == "WAF-1836294834629509999"
    assert f5_kv["attack_type"] == "Path Traversal" and "..%2f" in f5_kv["payload"]
    assert f5_kv["source_ip"] == "198.51.100.23" and f5_kv["timestamp"] == "2026-10-21 06:15:40"
    assert f5_kv["severity"] == "high"  # F5 syslog level "Error" → high

    assert imperva_cef["source"] == "Imperva WAF" and imperva_cef["id"] == "WAF-3412341234"
    assert imperva_cef["source_ip"] == "192.0.2.44" and imperva_cef["signature"] == "Scanner-Nikto"
    assert imperva_cef["action"] == "REQ_BLOCKED_SECURITY_RULE" and imperva_cef["user_agent"].startswith("Nikto")
    assert imperva_cef["url"] == "portal.bank.in/api/accounts" and "or 1=1" in imperva_cef["payload"].replace("%3D", "=").replace("%20", " ")
    assert imperva_cef["severity"] == "low"  # CEF 3/10

    assert imperva_json["source"] == "Imperva WAF" and imperva_json["id"] == "WAF-ev-778899"
    assert imperva_json["attack_type"] == "Credential Stuffing" and imperva_json["http_method"] == "POST"
    assert imperva_json["url"] == "/login" and imperva_json["severity"] == "high"
    for a in alerts:
        assert a["user_id"] and a["note"] and a["raw"] and a["payload"]


def test_waf_dedupes_replayed_lines():
    lines = (FIX / "waf_events.log").read_text(encoding="utf-8").splitlines()
    c = WafConsumer()
    assert len(list(c.iter_alerts(lines=lines + lines))) == 4
    assert c.skipped_duplicates == 4 and c.skipped_invalid == 2


# ------------------------------------------------------- through the brain --

def test_every_consumer_alert_runs_through_the_orchestrator(monkeypatch):
    monkeypatch.setattr("aegis.ingest.sentinel.time.sleep", lambda s: None)
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "LLM_BACKEND"):
        monkeypatch.delenv(k, raising=False)
    from aegis.eval.run import _build_orchestrator
    with tempfile.TemporaryDirectory() as td:
        orch = _build_orchestrator(Path(td) / "audit.jsonl")
        alerts = list(SentinelConsumer(_cfg(), transport=FakeAzure()).iter_alerts())
        alerts += list(WafConsumer().iter_alerts(path=FIX / "waf_events.log"))
        routed = {}
        for a in alerts:
            chain = orch.handle(a)
            assert chain.verdict in ("benign", "suspicious", "malicious", "uncertain")
            assert chain.alert_id == a["id"]
            routed[a["id"]] = (chain.investigated_by, chain.verdict)
    # the stub triage routes on the keys we folded in: identity → auth, process → edr, web → perimeter
    assert routed["SENTINEL-0e4d7c1a-5b7a-4c22-9f3e-1a2b3c4d5e6f"][0] == "auth"
    assert routed["SENTINEL-7d1e2f3a-9c8b-4a7d-8e6f-5a4b3c2d1e0f"][0] == "edr"
    assert routed["SENTINEL-c0ffee00-1111-2222-3333-444455556666"][0] == "perimeter"
    assert routed["WAF-1836294834629501234"][0] == "perimeter"
    assert routed["WAF-1836294834629501234"][1] in ("suspicious", "malicious")  # verdict is the stub's call
    assert routed["WAF-1836294834629509999"][0] == "perimeter"


def test_sources_from_env(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_CHECKPOINT", str(tmp_path / "ck.json"))
    monkeypatch.setenv("AEGIS_SOURCES", "sample,waf,sentinel,bogus")
    monkeypatch.setenv("WAF_EVENT_FILE", str(FIX / "waf_events.log"))
    for k in ("SENTINEL_WORKSPACE_ID", "SENTINEL_TENANT_ID", "SENTINEL_CLIENT_ID", "SENTINEL_CLIENT_SECRET"):
        monkeypatch.delenv(k, raising=False)
    srcs = sources_from_env()
    assert [n for n, _ in srcs] == ["sample", "waf"]  # sentinel unconfigured + bogus skipped, never fatal
    assert len(list(dict(srcs)["waf"])) == 4
