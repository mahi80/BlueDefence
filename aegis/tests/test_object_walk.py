"""BOLA / object walking from API-gateway logs: parsers, ownership, detector levels, the
false-positive cases that matter for a bank, the fast path, and the push route."""

from __future__ import annotations

import gzip
import json
import tempfile
import urllib.request

import pytest

from aegis.agents.api_abuse.object_walk import ObjectWalkDetector, mask, objects_in
from aegis.agents.api_abuse.ownership import DictOwnership, FileOwnership, HttpOwnership, NoOwnership, ownership_from_env
from aegis.agents.orchestrator.bola import object_walk_chain
from aegis.ingest.apigw import ApiGatewayConsumer, normalize, reset_shared_detector
from aegis.ingest.base import AlertCheckpoint
from aegis.ingest.stream import StreamConsumer, StreamQueue, reset_stream

T0 = 1_792_650_000.0


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for k in ("AEGIS_OWNERSHIP_FILE", "AEGIS_OWNERSHIP_URL", "AEGIS_BOLA_EXEMPT_PRINCIPALS", "AEGIS_APIGW_PRINCIPAL_FIELD",
              "ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("LLM_BACKEND", "mock")
    monkeypatch.setenv("ACP_HOME", tempfile.mkdtemp())
    reset_stream()
    reset_shared_detector()
    yield
    reset_stream()
    reset_shared_detector()


OWNERS = {**{("account", str(1000 + k)): f"cust-{1000 + k}" for k in range(50)},
          ("account", "5000"): ["cust-1000", "cust-1001"]}            # a joint account


def ev(i, principal, path, *, status=200, ip="203.0.113.10", gap=2.0, method="GET"):
    return {"gateway": "test", "ts": T0 + i * gap, "principal": principal, "client_ip": ip, "user_agent": "python-httpx/0.27",
            "method": method, "path": path, "status": status, "request_id": f"r{i}"}


def run(det, events):
    return [a for a in (det.observe(e) for e in events) if a]


# ------------------------------------------------------------ paths / masking --

def test_objects_in_paths_and_masking():
    assert objects_in("/api/v1/accounts/1002") == ("/api/v1/accounts/{id}", [("account", "1002")])
    t, objs = objects_in("https://api.bank.example/api/v2/customers/770001/accounts/ACC000123/transactions?statementId=9001")
    assert t == "/api/v2/customers/{id}/accounts/{id}/transactions" and objs[-1] == ("account", "ACC000123")
    assert objects_in("/api/v1/accounts/me")[1] == [] and objects_in("/oauth2/token")[1] == []
    assert mask("1234567890") == "••••7890" and mask("12") == "••"


# --------------------------------------------------------------- detector --

def test_confirmed_after_two_foreign_reads_with_masked_sample():
    det = ObjectWalkDetector(DictOwnership(OWNERS), exempt=[])
    alerts = run(det, [ev(i, "cust-1000", f"/api/v1/accounts/{1000 + i}") for i in range(4)])
    assert len(alerts) == 1
    a = alerts[0]
    w = a["object_walk"]
    assert w["level"] == "confirmed" and w["cross_owner_success"] == 2 and w["own_objects"] == 1
    assert a["severity"] == "critical" and a["principal_id"] == "cust-1000" and a["alert_type"] == "object_walk"
    assert w["sample_objects_masked"] == ["••••", "••••"]           # 4-char ids are masked whole; long ones keep the last four
    assert a["url"] == "/api/v1/accounts/{id}"                                  # template, never a raw account number
    assert not any(isinstance(v, str) and "cust-1001" in v for v in json.dumps(a).split('"'))   # victims' ids never leak


def test_attempted_when_authorisation_refuses_and_behavioural_without_ownership():
    det = ObjectWalkDetector(DictOwnership(OWNERS), exempt=[])
    alerts = run(det, [ev(i, "cust-1000", f"/api/v1/accounts/{1001 + i}", status=403) for i in range(6)])
    assert [a["object_walk"]["level"] for a in alerts] == ["attempted"] and alerts[0]["severity"] == "high"
    blind = ObjectWalkDetector(NoOwnership(), exempt=[])
    alerts = run(blind, [ev(i, "cust-1000", f"/api/v1/accounts/{1001 + i}", gap=1.0) for i in range(12)])
    assert alerts and alerts[0]["object_walk"]["level"] == "behavioural" and alerts[0]["object_walk"]["sequential_ids"]


def test_customers_staff_and_corporates_are_not_flagged():
    det = ObjectWalkDetector(DictOwnership({**OWNERS, **{("account", str(3000 + k)): "corp-1" for k in range(30)}}),
                             exempt=["svc-crm-*"])
    # a corporate customer reading its own thirty accounts quickly
    assert run(det, [ev(i, "corp-1", f"/api/v1/accounts/{3000 + i}", gap=0.5) for i in range(30)]) == []
    # a joint-account holder
    assert run(det, [ev(i, "cust-1001", "/api/v1/accounts/5000") for i in range(5)]) == []
    # the bank's CRM service principal reads many customers' accounts by design
    assert run(det, [ev(i, "svc-crm-prod", f"/api/v1/accounts/{1000 + i}", gap=0.2) for i in range(40)]) == []
    assert det.exempted == 40
    # a customer reading one foreign account once (a mistyped link) is not a walk
    assert run(det, [ev(0, "cust-1003", "/api/v1/accounts/1004")]) == []


def test_reemits_on_rotation_and_level_rise_but_not_every_request():
    det = ObjectWalkDetector(DictOwnership(OWNERS), exempt=[])
    evs = [ev(i, "cust-1000", f"/api/v1/accounts/{1001 + i}", status=403) for i in range(5)]           # attempted
    evs += [ev(5 + i, "cust-1000", f"/api/v1/accounts/{1010 + i}") for i in range(2)]                  # → confirmed
    evs += [ev(7 + i, "cust-1000", f"/api/v1/accounts/{1020 + i}") for i in range(3)]                  # same level, same IP
    evs += [ev(10, "cust-1000", "/api/v1/accounts/1030", ip="198.51.100.77")]                        # rotated
    levels = [(a["object_walk"]["level"], a["source_ip"]) for a in run(det, evs)]
    assert levels == [("attempted", "203.0.113.10"), ("confirmed", "203.0.113.10"), ("confirmed", "198.51.100.77")]


def test_state_is_bounded():
    det = ObjectWalkDetector(NoOwnership(), exempt=[], max_principals=10, max_events=5)
    for i in range(100):
        det.observe(ev(i, f"cust-{i}", "/api/v1/accounts/1001"))
    assert len(det._p) == 10
    for i in range(50):
        det.observe(ev(i, "cust-big", f"/api/v1/accounts/{2000 + i}"))
    assert len(det._p["cust-big"].events) <= 5


# --------------------------------------------------------------- ownership --

def test_file_ownership_csv_jsonl_and_http_resolver(tmp_path, caplog):
    csv_path = tmp_path / "owners.csv"
    csv_path.write_text("object_type,object_id,owners\naccounts,1001,cust-1001\naccount,5000,cust-1|cust-2\n,,\n")
    f = FileOwnership(csv_path)
    assert f.owners_of("account", "1001") == frozenset({"cust-1001"}) and f.owners_of("accounts", "5000") == frozenset({"cust-1", "cust-2"})
    jl = tmp_path / "owners.jsonl"
    jl.write_text(json.dumps({"object_type": "card", "object_id": "9", "owner": "c9"}) + "\nnot json\n")
    assert FileOwnership(jl).owners_of("card", "9") == frozenset({"c9"})
    calls = []

    def fetch(url, headers, timeout):
        calls.append(url)
        if "id=bad" in url:
            raise TimeoutError("resolver slow")
        return {"owners": ["cust-77"]}
    h = HttpOwnership("https://owners.bank.internal/lookup", token="t", fetch=fetch)
    assert h.owners_of("accounts", "77") == frozenset({"cust-77"}) and h.owners_of("account", "77") == frozenset({"cust-77"})
    assert len(calls) == 1                                          # cached
    assert h.owners_of("account", "bad") is None and h.failures == 1   # unknown, never a false mismatch


def test_ownership_from_env(tmp_path, monkeypatch):
    assert isinstance(ownership_from_env(), NoOwnership)
    p = tmp_path / "o.csv"
    p.write_text("object_type,object_id,owner\naccount,1,a\n")
    monkeypatch.setenv("AEGIS_OWNERSHIP_FILE", str(p))
    assert ownership_from_env().owners_of("account", "1") == frozenset({"a"})


# ---------------------------------------------------------------- parsers --

APIM = {"time": "2026-10-22T09:00:00Z", "category": "GatewayLogs", "callerIpAddress": "203.0.113.10", "correlationId": "c1",
        "properties": {"method": "GET", "url": "https://api.bank.example/api/v1/accounts/1001", "responseCode": 200,
                       "userId": "cust-1000", "apimSubscriptionId": "mobile-app"}}
APIM_LA = {"TimeGenerated": "2026-10-22T09:00:00Z", "CallerIpAddress": "203.0.113.10", "Method": "GET",
           "Url": "https://api.bank.example/api/v1/accounts/1001", "ResponseCode": 200, "ApimSubscriptionId": "sub-1",
           "UserId": "cust-1000", "CorrelationId": "c2"}
AWS = {"requestId": "r-1", "ip": "203.0.113.10", "httpMethod": "GET", "resourcePath": "/accounts/{id}",
       "path": "/prod/accounts/1001", "status": "200", "requestTimeEpoch": 1792650000000,
       "authorizer": {"claims": {"sub": "cust-1000"}}}
KONG = {"request": {"method": "GET", "uri": "/api/v1/accounts/1001", "headers": {"user-agent": "okhttp", "x-request-id": "k1"}},
        "response": {"status": 200}, "client_ip": "203.0.113.10", "started_at": 1792650000123,
        "consumer": {"id": "uuid-1", "username": "cust-1000"}}
GENERIC = {"timestamp": "2026-10-22T09:00:00Z", "client_ip": "203.0.113.10", "method": "get", "path": "/api/v1/accounts/1001",
           "status": 200, "sub": "cust-1000", "gateway": "Apigee"}


@pytest.mark.parametrize("rec,gw", [(APIM, "Azure APIM"), (APIM_LA, "Azure APIM"), (AWS, "AWS API Gateway"),
                                    (KONG, "Kong"), (GENERIC, "Apigee")])
def test_gateway_records_normalise(rec, gw):
    e = normalize(rec)
    assert e["gateway"] == gw and e["principal"] == "cust-1000" and e["client_ip"] == "203.0.113.10"
    assert e["method"] == "GET" and e["status"] == 200 and e["path"].endswith("/accounts/1001") and e["ts"] > 1.7e9


def test_principal_field_override_and_junk(monkeypatch):
    rec = {**GENERIC, "sub": None, "claims": {"cif": "CIF-9"}}
    monkeypatch.setenv("AEGIS_APIGW_PRINCIPAL_FIELD", "claims.cif")
    assert normalize(rec)["principal"] == "CIF-9"
    assert normalize({"nothing": 1}) is None and normalize("x") is None


def test_consumer_reads_files_with_records_wrapper_and_gzip(tmp_path):
    lines = []
    for i in range(4):
        r = json.loads(json.dumps(APIM))
        r["properties"]["url"] = f"https://api.bank.example/api/v1/accounts/{1000 + i}"
        r["correlationId"] = f"c{i}"
        lines.append(r)
    p = tmp_path / "apim.json.gz"
    with gzip.open(p, "wt") as f:
        f.write(json.dumps({"records": lines[:2]}) + "\n" + "\n".join(json.dumps(x) for x in lines[2:]) + "\nnot json\n")
    c = ApiGatewayConsumer(detector=ObjectWalkDetector(DictOwnership(OWNERS), exempt=[]), checkpoint=AlertCheckpoint())
    alerts = list(c.iter_alerts(path=p))
    assert len(alerts) == 1 and alerts[0]["source"] == "Azure APIM" and c.events == 4 and c.skipped_invalid == 1


# ------------------------------------------------------------- fast path --

def test_fast_path_chain_actions_per_level():
    det = ObjectWalkDetector(DictOwnership(OWNERS), exempt=[])
    a = run(det, [ev(i, "cust-1000", f"/api/v1/accounts/{1000 + i}", ip=("203.0.113.10" if i < 2 else "203.0.113.11"))
                  for i in range(4)])[-1]
    a["ja4"] = "t13d_agent"
    c = object_walk_chain(a)
    acts = {(x.action_type, x.target, x.requires_hitl) for x in c.recommended_actions}
    assert c.verdict == "malicious" and c.confidence == 0.95
    assert ("block", "203.0.113.11", False) in acts and ("block", "203.0.113.10", False) in acts
    assert ("revoke_sessions", "cust-1000", True) in acts and any(t == "escalate" for t, _, _ in acts)
    assert ("block", "fp:ja4:t13d_agent;ua:python-httpx%2F0.27", False) in acts
    blind = ObjectWalkDetector(NoOwnership(), exempt=[])
    b = run(blind, [ev(i, "cust-1000", f"/api/v1/accounts/{1001 + i}", gap=1.0) for i in range(12)])[0]
    cb = object_walk_chain(b)
    assert cb.verdict == "suspicious" and not any(x.action_type in ("block", "revoke_sessions") for x in cb.recommended_actions)


def test_orchestrator_routes_object_walk_alerts_to_the_fast_path(tmp_path):
    from aegis.eval.run import _build_orchestrator
    det = ObjectWalkDetector(DictOwnership(OWNERS), exempt=[])
    a = run(det, [ev(i, "cust-1000", f"/api/v1/accounts/{1000 + i}") for i in range(3)])[0]
    chain = _build_orchestrator(tmp_path / "audit.jsonl").handle(a)
    assert chain.investigated_by == "object_walk" and chain.verdict == "malicious"


# ----------------------------------------------------------- stream / push --

def test_pushed_gateway_logs_flow_through_the_detector(monkeypatch, tmp_path):
    from aegis.ingest.http_push import PushServer
    owners = tmp_path / "owners.csv"
    owners.write_text("object_type,object_id,owner\n" + "".join(f"account,{1000 + k},cust-{1000 + k}\n" for k in range(10)))
    monkeypatch.setenv("AEGIS_OWNERSHIP_FILE", str(owners))
    q = StreamQueue(100)
    srv = PushServer(token="t", bind="127.0.0.1:0", queue=q).start()
    try:
        recs = []
        for i in range(4):
            r = json.loads(json.dumps(APIM))
            r["properties"]["url"] = f"https://api.bank.example/api/v1/accounts/{1000 + i}"
            r["correlationId"] = f"p{i}"
            recs.append(json.dumps(r))
        req = urllib.request.Request(f"{srv.url}/ingest/apigw?gateway=apim", data=gzip.compress("\n".join(recs).encode()),
                                     headers={"Authorization": "Bearer t"}, method="POST")
        assert urllib.request.urlopen(req, timeout=5).status == 200
    finally:
        srv.stop()
    c = StreamConsumer(queue=q, checkpoint=AlertCheckpoint())
    alerts = list(c.iter_alerts())
    assert len(alerts) == 1 and alerts[0]["ingest_source"] == "apigw-apim" and alerts[0]["object_walk"]["level"] == "confirmed"
    assert c.skipped_invalid == 0                                              # below-threshold events are not "invalid"
