"""Round-3 review, group G4 (high items): the push receiver and the WAF normaliser."""

from __future__ import annotations

import base64
import gzip
import json
import os
import socket
import time
import types

import pytest

TOKEN = "t0ken-for-tests"


@pytest.fixture
def srv():
    from aegis.ingest.http_push import PushServer
    from aegis.ingest.stream import StreamQueue
    s = PushServer(token=TOKEN, bind="127.0.0.1:0", queue=StreamQueue()).start()
    yield s
    s.stop()


def _exchange(srv, req: bytes) -> bytes:
    """Send raw bytes; return everything the server sends before it closes (or 3 s pass)."""
    with socket.create_connection(("127.0.0.1", srv.port), timeout=3) as s:
        s.sendall(req)
        out = b""
        try:
            while chunk := s.recv(65536):
                out += chunk
        except TimeoutError:
            pass
        return out


# ---- G4-1: request smuggling shapes ---------------------------------------------------------------------------------

def test_content_length_with_transfer_encoding_is_refused(srv):
    smuggled = b"GET /ingest/blocklist HTTP/1.1\r\nHost: x\r\n\r\n"
    req = (b"POST /ingest/alerts HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + TOKEN.encode() + b"\r\n"
           b"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n" + smuggled)
    out = _exchange(srv, req)
    assert out.split(b" ")[1] == b"400" and out.count(b"HTTP/1.1 ") == 1    # closed: the tail is never a request


def test_two_different_content_lengths_are_refused(srv):
    req = (b"POST /ingest/alerts HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + TOKEN.encode() + b"\r\n"
           b"Content-Length: 2\r\nContent-Length: 40\r\n\r\n{}")
    assert _exchange(srv, req).split(b" ")[1] == b"400"


@pytest.mark.parametrize("head", [b"GET /healthz HTTP/1.1", b"POST /elsewhere HTTP/1.1"])
def test_an_unread_body_closes_the_connection(srv, head):
    smuggled = b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n"
    req = head + b"\r\nHost: x\r\nContent-Length: " + str(len(smuggled)).encode() + b"\r\n\r\n" + smuggled
    assert _exchange(srv, req).count(b"HTTP/1.1 ") == 1


# ---- G4-2: Firehose is linear ----------------------------------------------------------------------------------------

def test_firehose_with_many_records_is_fast(srv):
    rec = base64.b64encode(json.dumps({"id": "x", "source_ip": "1.2.3.4"}).encode()).decode()
    payload = {"requestId": "r", "records": [{"data": rec}] * 20_000}
    t = time.perf_counter()
    status, _ = srv.ingest_firehose(json.dumps(payload).encode(), {})
    assert status == 200 and time.perf_counter() - t < 3.0


# ---- G4-3: pushed alerts cannot impersonate other sources -----------------------------------------------------------

def test_pushed_ids_are_namespaced_and_internal_keys_stripped(srv):
    body = json.dumps({"id": "WAF-abc123", "source_ip": "1.2.3.4", "deferred_at": 1.0, "campaign_context": {"x": 1}})
    status, out = srv.ingest_alerts(body.encode())
    assert status == 200 and out["accepted"] == 1
    (item,) = srv.queue.drain()
    row = json.loads(item.line)
    assert row["id"] == "push:WAF-abc123" and "deferred_at" not in row and "campaign_context" not in row


# ---- G4-4: AWS WAF ids --------------------------------------------------------------------------------------------------

def _aws(uri, ts=1730600000000, request_id=None):
    req = {"clientIp": "203.0.113.5", "country": "IN", "uri": uri, "httpMethod": "GET", "headers": []}
    if request_id:
        req["requestId"] = request_id
    return {"timestamp": ts, "webaclId": "arn:aws:wafv2:x/webacl/acl/1", "terminatingRuleId": "R", "action": "BLOCK",
            "httpRequest": req}


def _norm(obj):
    from aegis.ingest.waf import WafConsumer
    return WafConsumer().normalize(json.dumps(obj))


def test_aws_requests_in_one_millisecond_stay_separate():
    a, b = _norm(_aws("/a")), _norm(_aws("/b"))
    assert a["id"] != b["id"]


def test_long_vendor_ids_are_not_merged_by_truncation():
    long = "x" * 60
    a, b = _norm(_aws("/a", request_id=long + "1")), _norm(_aws("/a", request_id=long + "2"))
    assert a["id"] != b["id"]


# ---- G4-5: every gzip member is read -------------------------------------------------------------------------------------

def test_multi_member_gzip_is_read_whole():
    from aegis.ingest.stream import lines_from_body
    body = gzip.compress(b'{"id":"a"}\n') + gzip.compress(b'{"id":"b"}\n')
    assert lines_from_body(body) == ['{"id":"a"}', '{"id":"b"}']


# ---- G4-7: storm mode follows analysis time, not a slow dashboard ----------------------------------------------------

def test_slow_dashboard_does_not_start_a_storm():
    from aegis.service import CycleStats, StormControl
    storm = StormControl(types.SimpleNamespace(pending=lambda: 0, path="d.jsonl"), types.SimpleNamespace(stats=None), 60.0)
    storm.occupancy = lambda: 0.0
    slow = CycleStats(alerts=3, seconds=300.0, handle_seconds=1.0)          # 299 s were HITL sync / flush
    assert storm.update(slow) is False
    assert storm.update(CycleStats(alerts=3, seconds=300.0, handle_seconds=120.0)) is True


# ---- G4-8: the licence meter --------------------------------------------------------------------------------------------

def test_one_busy_hour_a_day_never_reaches_over_limit():
    from aegis.license import LicenseMeter
    m = LicenseMeter(eps_limit=10, allowance_s=3 * 86400.0)
    t, over = 0.0, False
    for _day in range(10):
        for h in range(24):
            over = m.observe(20 * 3600 if h == 2 else 3600, t) or over       # 20 eps for one hour, 1 eps otherwise
            t += 3600
    assert over is False


def test_re_fed_alerts_are_not_metered_twice():
    from aegis.service import CycleStats, _meter_license
    seen = []
    meter = types.SimpleNamespace(observe=lambda n, now, dev=None: seen.append(n) or False, peak_eps_24h=0.0,
                                  devices_seen=0, _last_drained=0)
    p = types.SimpleNamespace(license_meter=meter, license=types.SimpleNamespace(status="valid"), stream=None)
    _meter_license(p, CycleStats(alerts=10, refed=10))
    assert seen == [0]


# ---- G4-9 / G4-10: the fallback spill ----------------------------------------------------------------------------------

def test_fallback_spill_lives_in_a_private_state_dir(tmp_path, monkeypatch):
    import os
    import stat

    from aegis.ops.deferred import default_spill
    monkeypatch.delenv("AEGIS_DEFERRED_FALLBACK", raising=False)
    monkeypatch.setenv("STATE_DIRECTORY", str(tmp_path / "state"))
    q = default_spill(tmp_path / "audit" / "audit.jsonl")
    assert q.fallback is not None and q.fallback.path.parent == tmp_path / "state"
    if os.name != "nt":                       # Windows has no POSIX mode bits to check
        assert stat.S_IMODE(os.stat(tmp_path / "state").st_mode) == 0o700


@pytest.mark.skipif(os.name == "nt", reason="creating symlinks needs a privilege Windows CI does not grant")
def test_symlinked_fallback_is_refused(tmp_path, monkeypatch):
    from aegis.ops.deferred import default_spill
    (tmp_path / "elsewhere").write_text("")
    (tmp_path / "fb.jsonl").symlink_to(tmp_path / "elsewhere")
    monkeypatch.setenv("AEGIS_DEFERRED_FALLBACK", str(tmp_path / "fb.jsonl"))
    assert default_spill(tmp_path / "audit.jsonl").fallback is None


def test_fallback_push_does_not_reread_the_file(tmp_path):
    from aegis.ops.deferred import DeferredQueue, SpillQueue
    full = DeferredQueue(tmp_path / "p.jsonl", max_bytes=1)
    fb = DeferredQueue(tmp_path / "f.jsonl")
    calls = []
    fb.pending = lambda: calls.append(1) or 0
    q = SpillQueue(full, fb)
    for i in range(50):
        assert q.push({"id": f"a{i}", "x": "y" * 50})
    assert calls == []
