"""Streaming ingest: push receiver (Cloudflare Logpush / Firehose / forwarders / alerts), the
shared queue with backpressure, the Event Hub reader, and the service loop waking on push."""

from __future__ import annotations

import base64
import gzip
import json
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from aegis.ingest.eventhub import EventHubReader, _split_body
from aegis.ingest.http_push import PushServer, push_server_from_env
from aegis.ingest.stream import StreamConsumer, StreamQueue, get_stream, reset_stream
from aegis.ingest import AlertCheckpoint, sources_from_env

FIX = Path(__file__).resolve().parent.parent / "ingest" / "fixtures"
TOKEN = "t0ken-for-tests"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "AEGIS_INGEST_HTTP", "AEGIS_INGEST_BIND", "AEGIS_INGEST_TOKEN",
              "AEGIS_SOURCES", "AEGIS_EVENTHUB_CONN", "AEGIS_WAF_VENDOR", "AEGIS_SOAR_VENDOR", "AEGIS_ENFORCEMENT_MODE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("LLM_BACKEND", "mock")
    monkeypatch.setenv("ACP_HOME", tempfile.mkdtemp())
    reset_stream()
    yield
    reset_stream()


@pytest.fixture
def server():
    q = StreamQueue(capacity=100)
    srv = PushServer(token=TOKEN, bind="127.0.0.1:0", queue=q).start()
    yield srv, q
    srv.stop()


def _post(url: str, body: bytes, headers: dict | None = None, token: str | None = TOKEN) -> tuple[int, dict]:
    h = {"Content-Type": "application/json", **(headers or {})}
    if token is not None and "X-Amz-Firehose-Access-Key" not in h:
        h["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=body, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def _get(url: str, token: str | None = None) -> tuple[int, dict]:
    h = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def _cf_lines(n: int = 3) -> list[str]:
    return [json.dumps({"RayID": f"8f{i:014x}", "ClientIP": f"203.0.113.{10 + i}", "ClientRequestHost": "nb.bank.example",
                        "ClientRequestMethod": "GET", "ClientRequestPath": "/api/accounts", "ClientRequestQuery": "?id=1%27",
                        "ClientRequestUserAgent": "sqlmap/1.8", "Datetime": "2026-10-22T09:00:00Z", "Action": "block",
                        "Source": "firewallManaged", "Description": "SQLi", "RuleID": "r1", "JA4": "t13d1312h2_aaaa_bbbb"})
            for i in range(n)]


# --------------------------------------------------------------- queue --

def test_queue_is_bounded_atomic_and_wakes_waiters():
    q = StreamQueue(capacity=5)
    assert q.put_many("x", ["a", "b", "c"]) and len(q) == 3
    assert q.put_many("x", ["d", "e", "f"]) is False and len(q) == 3          # all-or-nothing
    assert q.stats.rejected_full == 3 and q.stats.received == 3 and q.stats.high_water == 3
    assert q.wait(0.01) is True
    got = q.drain(2)
    assert [g.line for g in got] == ["a", "b"] and len(q) == 1
    q.drain()
    assert q.wait(0.05) is False
    woke = []
    t = threading.Thread(target=lambda: woke.append(q.wait(2.0)))
    t.start()
    time.sleep(0.05)
    q.put("x", "late")
    t.join(1.0)
    assert woke == [True]


# ------------------------------------------------------- push receiver --

def test_cloudflare_logpush_gzip_batches_become_alerts_with_lag(server):
    srv, q = server
    body = gzip.compress("\n".join(_cf_lines(3)).encode())
    status, out = _post(f"{srv.url}/ingest/cloudflare", body, {"Content-Encoding": "gzip"})
    assert status == 200 and out["accepted"] == 3
    status, out = _post(f"{srv.url}/ingest/cloudflare", b'{"content":"test"}')          # Logpush job validation probe
    assert status == 200 and out["note"] == "logpush validation" and len(q) == 3
    alerts = list(StreamConsumer(queue=q, checkpoint=AlertCheckpoint()).iter_alerts())
    assert [a["source"] for a in alerts] == ["Cloudflare WAF"] * 3
    assert all(a["received_at"] > 0 and a["ingest_lag_ms"] > 0 and a["ingest_source"] == "cloudflare" for a in alerts)
    assert alerts[0]["ja4"] == "t13d1312h2_aaaa_bbbb" and alerts[0]["blocked"] is True
    # a re-delivered batch (vendor retry) dedupes on RayID
    _post(f"{srv.url}/ingest/cloudflare", body, {"Content-Encoding": "gzip"})
    c = StreamConsumer(queue=q, checkpoint=alerts and AlertCheckpoint())
    cp = AlertCheckpoint()
    for a in alerts:
        cp.mark(f"stream:{a['ingest_source']}:{a['id']}")      # per pushed source (round 4 I4-9)
    again = list(StreamConsumer(queue=q, checkpoint=cp).iter_alerts())
    assert again == [] and c is not None


def test_firehose_contract_request_id_echo_base64_records_and_gzip(server):
    srv, q = server
    recs = [{"data": base64.b64encode(ln.encode()).decode()} for ln in _cf_lines(2)]
    # two JSON objects in one record, newline-separated, as WAF→Firehose aggregation produces
    both = "\n".join(_cf_lines(4)[2:])
    recs.append({"data": base64.b64encode(both.encode()).decode()})
    payload = {"requestId": "req-123", "timestamp": 1792650000000, "records": recs}
    status, out = _post(f"{srv.url}/ingest/firehose", gzip.compress(json.dumps(payload).encode()),
                        {"X-Amz-Firehose-Access-Key": TOKEN, "X-Amz-Firehose-Request-Id": "req-123", "Content-Encoding": "gzip"},
                        token=None)
    assert status == 200 and out["requestId"] == "req-123" and isinstance(out["timestamp"], int)
    assert len(q) == 4
    status, out = _post(f"{srv.url}/ingest/firehose", b'{"requestId":"r2","timestamp":1,"records":[{"nodata":1}]}',
                        {"X-Amz-Firehose-Access-Key": TOKEN}, token=None)
    assert status == 400 and out["requestId"] == "r2" and "malformed" in out["errorMessage"]
    status, out = _post(f"{srv.url}/ingest/firehose", b"{}", {"X-Amz-Firehose-Access-Key": "wrong",
                                                              "X-Amz-Firehose-Request-Id": "r3"}, token=None)
    assert status == 401 and out["requestId"] == "r3" and out["errorMessage"] == "unauthorized"


def test_generic_waf_forwarder_cef_f5_and_azure_records(server):
    srv, q = server
    lines = (FIX / "waf_events.log").read_text(encoding="utf-8").splitlines()
    status, out = _post(f"{srv.url}/ingest/waf?source=imperva-relay", "\n".join(lines).encode(), {"Content-Type": "text/plain"})
    assert status == 200 and out["accepted"] == len(lines)
    alerts = list(StreamConsumer(queue=q, checkpoint=AlertCheckpoint()).iter_alerts())
    assert len(alerts) == 4 and {a["source"] for a in alerts} == {"F5 ASM", "Imperva WAF"}
    assert all(a["ingest_source"] == "imperva-relay" for a in alerts)


def test_alerts_passthrough_requires_ids(server):
    srv, q = server
    good = json.dumps({"id": "A-1", "source": "harness", "severity": "high", "source_ip": "203.0.113.5", "payload": "GET /x"})
    status, out = _post(f"{srv.url}/ingest/alerts", (good + "\nnot json\n" + json.dumps({"noid": 1})).encode())
    assert status == 200 and out == {"ok": True, "accepted": 1, "rejected": 2}
    status, _ = _post(f"{srv.url}/ingest/alerts", b'{"noid": true}')
    assert status == 415
    (a,) = list(StreamConsumer(queue=q, checkpoint=AlertCheckpoint()).iter_alerts())
    assert a["id"] == "push:A-1" and a["source"] == "harness" and a["received_at"] > 0


def test_auth_size_and_backpressure(server):
    srv, q = server
    assert _post(f"{srv.url}/ingest/cloudflare", b"{}", token="nope")[0] == 401
    assert _post(f"{srv.url}/ingest/cloudflare", b"{}", token=None)[0] == 401
    big = urllib.request.Request(f"{srv.url}/ingest/waf", data=b"x", headers={"Authorization": f"Bearer {TOKEN}",
                                                                              "Content-Length": str(65 * 1024 * 1024)}, method="POST")
    try:
        urllib.request.urlopen(big, timeout=5)
    except urllib.error.HTTPError as e:
        assert e.code == 413
    except Exception:  # noqa: BLE001 — the server may close the socket after 413 before the client finishes sending
        pass
    status, _ = _post(f"{srv.url}/ingest/waf", "\n".join(f'{{"id":"{i}","client_ip":"1.1.1.{i}"}}' for i in range(100)).encode())
    assert status == 200 and len(q) == 100
    status, out = _post(f"{srv.url}/ingest/cloudflare", "\n".join(_cf_lines(1)).encode())
    assert status == 503 and "retry" in out["error"] and q.stats.rejected_full == 1
    assert set(_get(f"{srv.url}/healthz")[1]) == {"ok", "degraded"}          # the public probe learns liveness only
    assert _get(f"{srv.url}/healthz", TOKEN)[1]["queue"] == 100               # counters need the read token
    assert _get(f"{srv.url}/ingest/blocklist")[0] == 401


def test_blocklist_serves_active_enforcement_for_an_edge():
    from aegis.agents.response.connectors import ConnectorRegistry
    from aegis.agents.response.connectors.cloud_waf import CloudflareWafConnector
    from aegis.agents.response.connectors import mock_cloud_waf as m
    from aegis.agents.shared.evidence_chain import RecommendedAction
    cf = CloudflareWafConnector(api_token="t", zone_id="z", base_url=m.CF_BASE, transport=m.MockCloudflare(token="t"), dry_run=False)
    reg = ConnectorRegistry([cf])
    for t in ("203.0.113.9", "fp:ja4:t13d_x;ua:python-httpx%2F0.27"):
        reg.apply(RecommendedAction(action_type="block", target=t, reasoning="r", requires_hitl=False, confidence=0.9))
    shadow = CloudflareWafConnector(api_token="t", zone_id="z", base_url=m.CF_BASE, transport=m.MockCloudflare(token="t"), dry_run=True)
    shadow.apply(RecommendedAction(action_type="block", target="198.51.100.1", reasoning="r", requires_hitl=False, confidence=0.9))
    srv = PushServer(token=TOKEN, bind="127.0.0.1:0", queue=StreamQueue(10),
                     blocklist=lambda: reg.active_receipts + shadow.active_receipts).start()
    try:
        status, out = _get(f"{srv.url}/ingest/blocklist", TOKEN)
    finally:
        srv.stop()
    assert status == 200
    assert [i["target"] for i in out["ips"]] == ["203.0.113.9"]                     # the shadow (dry-run) one is not served
    assert out["fingerprints"] == [{"action": "block", "expires_at": out["fingerprints"][0]["expires_at"],
                                    "receipt": out["fingerprints"][0]["receipt"], "kind": "ja4", "value": "t13d_x",
                                    "user_agent": "python-httpx/0.27"}]


def test_env_wiring_and_loopback_rule(monkeypatch):
    assert push_server_from_env() is None
    monkeypatch.setenv("AEGIS_INGEST_HTTP", "1")
    assert push_server_from_env() is None                                     # 0.0.0.0 without a token → refused, logged
    monkeypatch.setenv("AEGIS_INGEST_BIND", "127.0.0.1:0")
    srv = push_server_from_env()
    try:
        assert srv is not None and get_stream().enabled
        names = [n for n, _ in sources_from_env()]
        assert "stream" in names                                              # drained without naming it in AEGIS_SOURCES
    finally:
        srv.stop()


# ------------------------------------------------------------ event hub --

class _Ctx:
    def __init__(self, pid):
        self.partition_id = pid
        self.checkpoints = []

    def update_checkpoint(self, ev):
        self.checkpoints.append(ev.sequence_number)


class _Ev:
    def __init__(self, body, seq):
        self._b, self.sequence_number = body, seq

    def body_as_str(self):
        return self._b


def test_eventhub_batches_expand_records_and_checkpoint(tmp_path):
    q = StreamQueue(100)
    cp = tmp_path / "eh.json"
    r = EventHubReader(connection_string="Endpoint=sb://x/;EntityPath=waf", checkpoint_path=cp, queue=q)
    assert r.starting_position() == "@latest"
    afd = {"records": [{"time": "2026-10-22T06:04:00Z", "category": "FrontDoorWebApplicationFirewallLog",
                        "properties": {"clientIP": "203.0.113.40", "requestUri": "/x", "ruleName": "LFI-930100", "action": "Block",
                                       "host": "www.bank.example", "trackingReference": f"trk-{i}"}} for i in range(2)]}
    ctx = _Ctx("0")
    r.on_batch(ctx, [_Ev(json.dumps(afd), 41), _Ev('{"id":"single","source":"x"}', 42)])
    assert len(q) == 3 and r.events == 2 and ctx.checkpoints == [42]
    assert json.loads(cp.read_text())["positions"] == {"0": 42}
    r2 = EventHubReader(connection_string="Endpoint=sb://x/;EntityPath=waf", checkpoint_path=cp, queue=q)
    assert r2.starting_position() == {"0": 42}
    alerts = list(StreamConsumer(queue=q, checkpoint=AlertCheckpoint()).iter_alerts())
    assert [a["source"] for a in alerts][:2] == ["Azure Front Door WAF"] * 2 and alerts[0]["ingest_source"] == "azure-eventhub"
    assert _split_body("") == [] and _split_body("a\nb") == ["a", "b"]


def test_eventhub_reader_reconnects_after_sdk_failure():
    q = StreamQueue(100)
    calls = []

    class FakeClient:
        def __init__(self, **kw):
            calls.append(kw)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def receive_batch(self, on_event_batch, starting_position, **kw):
            if len(calls) == 1:
                raise ConnectionError("amqp link detached")
            on_event_batch(_Ctx("1"), [_Ev('{"id":"e1","source":"s"}', 7)])
            while not r._stop.is_set():
                time.sleep(0.01)

        def close(self):
            pass

    with tempfile.TemporaryDirectory() as td:
        r = EventHubReader(connection_string="c", consumer_group="aegis", checkpoint_path=Path(td) / "cp.json",
                           queue=q, client_factory=FakeClient, backoff_s=0.01)
        r.start()
        deadline = time.time() + 3
        while time.time() < deadline and len(q) < 1:
            time.sleep(0.01)
        r.stop()
    assert len(calls) == 2 and calls[0]["consumer_group"] == "aegis" and len(q) == 1


def test_eventhub_from_env_needs_conn_and_sdk(monkeypatch):
    from aegis.ingest.eventhub import eventhub_from_env
    assert eventhub_from_env() is None
    monkeypatch.setenv("AEGIS_EVENTHUB_CONN", "Endpoint=sb://x/;EntityPath=waf")
    try:
        import azure.eventhub  # noqa: F401
        pytest.skip("azure-eventhub installed; the missing-SDK branch is not reachable here")
    except ImportError:
        assert eventhub_from_env() is None


# ---------------------------------------------------- service wakes on push --

def test_service_handles_a_pushed_alert_before_the_next_poll(monkeypatch, tmp_path):
    from aegis.service import Service, build_pipeline
    monkeypatch.setenv("AEGIS_EDITION", "external")
    monkeypatch.setenv("AEGIS_SOURCES", "stream")
    monkeypatch.setenv("AEGIS_CHECKPOINT", str(tmp_path / "cp.json"))
    monkeypatch.setenv("AEGIS_HITL_DIR", str(tmp_path / "hitl"))
    monkeypatch.setenv("AEGIS_INGEST_BIND", "127.0.0.1:0")
    monkeypatch.setenv("AEGIS_INGEST_TOKEN", TOKEN)
    monkeypatch.setenv("AEGIS_WAF_VENDOR", "mock-cloudflare")
    p = build_pipeline(tmp_path / "audit.jsonl")
    assert p.push_server is not None and "push receiver" in p.banner()
    svc = Service(p, interval=30)                           # a poll every 30 s; the push must not wait for it
    t = threading.Thread(target=svc.run, daemon=True)
    t.start()
    deadline = time.time() + 5
    while time.time() < deadline and svc.cycles < 1:
        time.sleep(0.01)
    t_push = time.time()
    status, _ = _post(f"{p.push_server.url}/ingest/cloudflare", "\n".join(_cf_lines(1)).encode())
    assert status == 200
    while time.time() < deadline and svc.stream_cycles < 1:
        time.sleep(0.01)
    svc.stop()
    t.join(5)
    handled_after = time.time() - t_push
    assert svc.stream_cycles >= 1 and handled_after < 3.0
    st = svc.history[-1]
    assert st.streamed == 1 and st.alerts == 1 and st.max_handle_ms < 3000 and "streamed=1" in st.line()
    entries = [json.loads(ln) for ln in (tmp_path / "audit.jsonl").read_text().splitlines() if ln.strip()]
    assert any(e["alert_id"].startswith("WAF-8f") for e in entries)
