"""Round 5 (Y5-A): regressions in the round-4 ingest / connector fixes."""

from __future__ import annotations

import json
import socket
import time
import types
from typing import ClassVar

from aegis.ingest.stream import StreamQueue

# ---- Y5-3: restore takes the LAST event per key, never a preview -------------------------------------------------------


def _fake():
    from aegis.agents.response.connectors.base import Connector

    class Fake(Connector):
        name = "fakefw"
        calls: ClassVar[list] = []

        def supports(self, t):
            return t == "block_ip"

        def supports_target(self, t):
            return True

        def _do_apply(self, a, key, ttl):
            Fake.calls.append(("apply", a.target))
            return "ref", "applied", "tok"

        def _do_rollback(self, r):
            Fake.calls.append(("rollback", r.receipt_id))
            return "removed"
    return Fake


def _restart(Fake, log, clock, dry_run=False):
    from aegis.agents.response.connectors.base import ConnectorRegistry
    from aegis.agents.response.receipts import ReceiptLog
    c = Fake(dry_run=dry_run, clock=clock)
    reg = ConnectorRegistry([c], on_receipt=[log])
    reg.restore(ReceiptLog.read(log.path))
    return c, reg


def test_restore_tracks_the_live_receipt_not_the_superseded_shadow(tmp_path):
    from aegis.agents.response.connectors.base import ConnectorRegistry
    from aegis.agents.response.receipts import ReceiptLog
    Fake, now = _fake(), [1000.0]
    log = ReceiptLog(tmp_path / "_receipts.jsonl")
    c = Fake(dry_run=True, clock=lambda: now[0])
    reg = ConnectorRegistry([c], on_receipt=[log])
    act = types.SimpleNamespace(action_type="block_ip", target="203.0.113.9")
    reg.apply(act, ttl_sec=900)
    c.dry_run = False
    live = reg.apply(act, ttl_sec=900)
    assert any(e["event"] == "superseded" for e in ReceiptLog.read(log.path))
    c2, _ = _restart(Fake, log, lambda: now[0])
    assert [r.receipt_id for r in c2.active_receipts] == [live.receipt_id]


def test_restore_after_an_inline_expiry_keeps_the_replacement(tmp_path):
    from aegis.agents.response.connectors.base import ConnectorRegistry
    from aegis.agents.response.receipts import ReceiptLog
    Fake, now = _fake(), [1000.0]
    log = ReceiptLog(tmp_path / "_receipts.jsonl")
    reg = ConnectorRegistry([Fake(dry_run=False, clock=lambda: now[0])], on_receipt=[log])
    act = types.SimpleNamespace(action_type="block_ip", target="203.0.113.9")
    reg.apply(act, ttl_sec=60)
    now[0] += 120
    b = reg.apply(act, ttl_sec=3600)
    c2, reg2 = _restart(Fake, log, lambda: now[0])
    now[0] += 5
    assert reg2.sweep_expired() == [] and [r.receipt_id for r in c2.active_receipts] == [b.receipt_id]


def test_previews_never_become_enforcement(tmp_path):
    from aegis.agents.response.connectors.base import ConnectorRegistry
    from aegis.agents.response.receipts import ReceiptLog
    Fake, now = _fake(), [1000.0]
    log = ReceiptLog(tmp_path / "_receipts.jsonl")
    reg = ConnectorRegistry([Fake(dry_run=True, clock=lambda: now[0])], on_receipt=[log])
    reg.preview(types.SimpleNamespace(action_type="block_ip", target="203.0.113.9"), approver="aegis:auto-shadow")
    c2, _ = _restart(Fake, log, lambda: now[0], dry_run=True)
    assert c2.active_receipts == []


# ---- Y5-4: Sentinel watermark is ingestion time, clamped to now -------------------------------------------------------

def _sentinel(cp, rows, seen):
    from aegis.ingest.sentinel import SentinelConfig, SentinelConsumer
    cols = ["AegisIngested", "TimeGenerated", "SystemAlertId", "AlertName", "AlertSeverity"]

    def transport(method, url, body, headers, timeout):
        if "oauth2" in url or "token" in url:
            return 200, json.dumps({"access_token": "t", "expires_in": 3600})
        seen.append(json.loads(body)["query"])
        return 200, json.dumps({"tables": [{"columns": [{"name": c} for c in cols], "rows": rows}]})
    return SentinelConsumer(SentinelConfig(workspace_id="w", tenant_id="t", client_id="c", client_secret="s"),
                            checkpoint=cp, transport=transport)


def test_sentinel_watermark_follows_ingestion_time_and_never_runs_ahead():
    from aegis.ingest.base import AlertCheckpoint
    cp, seen = AlertCheckpoint(), []
    ing = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 3600))
    skew = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 5.5 * 3600))   # IST written as UTC
    c = _sentinel(cp, [[ing, skew, "a1", "x", "High"]], seen)
    assert [a["id"] for a in c.iter_alerts()] == ["SENTINEL-a1"]
    list(c.fetch())
    q = seen[-1]
    assert "ingestion_time() > datetime(" in q and "AegisIngested" in q
    since = q.split("ingestion_time() > datetime(", 1)[1].split(")", 1)[0]
    assert since < time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())                 # not 5.5 h ahead


# ---- Y5-6: every keep-alive request gets the header deadline -----------------------------------------------------------

def test_header_deadline_applies_to_the_second_request_on_a_connection(monkeypatch):
    from aegis.ingest.http_push import PushServer
    monkeypatch.setenv("AEGIS_INGEST_HEADER_S", "1")
    srv = PushServer(token="t" * 32, bind="127.0.0.1:0", queue=StreamQueue()).start()
    try:
        s = socket.create_connection(("127.0.0.1", srv.port), timeout=5)
        s.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
        time.sleep(0.3)
        assert s.recv(65536).startswith(b"HTTP/1.1 200")
        s.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n")         # never finishes these headers
        time.sleep(1.8)
        s.settimeout(2)
        try:
            assert s.recv(10) == b""
        except ConnectionResetError:
            pass
        assert srv._httpd.header_timeouts >= 1
    finally:
        srv.stop()


# ---- Y5-12: dedupe per feed family, bounded buckets -------------------------------------------------------------------

def test_dedupe_is_per_feed_family_and_bounded():
    from aegis.ingest.base import AlertCheckpoint, _feed_family
    assert _feed_family("edr-relay-a") == _feed_family("edr-relay-b") == "edr"
    cp = AlertCheckpoint(max_ids=10)
    for s in range(200):
        cp.mark(f"stream:src{s}x:id")
    assert len(cp._seen) <= AlertCheckpoint.MAX_BUCKETS + 1


# ---- Y5-13: a failed compaction backs off and leaves no partial copy ---------------------------------------------------

def test_failed_compaction_backs_off(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_STREAM_JOURNAL_COMPACT_MB", "0.001")
    j = tmp_path / "s.jsonl"
    q = StreamQueue(1000, journal=j)
    calls = []

    def boom():
        calls.append(1)
        (tmp_path / "s.jsonl.compact").write_text("partial")
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(q, "_compact", boom)
    q.put_many("w", [json.dumps({"id": i, "pad": "z" * 200}) for i in range(20)])
    for it in q.drain()[:15]:
        q.commit(it, force=True)
    assert len(calls) == 1 and not (tmp_path / "s.jsonl.compact").exists()
