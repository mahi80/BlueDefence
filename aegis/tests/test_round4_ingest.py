"""Round-4 review, group H4: ingest durability and the service loop."""

from __future__ import annotations

import json
import os
import socket
import time
import types

import pytest

from aegis.ingest.stream import StreamQueue

# ---- X4-4 / I4-2: the journal is compacted under steady traffic, offsets stay valid --------------------------------------

def test_journal_compacts_under_steady_load_and_replays_only_the_unhandled(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_STREAM_JOURNAL_COMPACT_MB", "0.01")          # ~10 KB
    j = tmp_path / "stream.jsonl"
    q = StreamQueue(10_000, journal=j)
    for i in range(400):
        assert q.put_many("waf", [json.dumps({"id": f"r{i}", "pad": "x" * 60})])
        if i >= 1:                                                       # the queue is never empty
            (item,) = q.drain(1)
            q.commit(item, force=True)
    assert q.compactions > 0 and j.stat().st_size < 20_000
    left = [it.line for it in q.drain()]
    assert len(left) == 1
    q2 = StreamQueue(10_000, journal=j)                                  # restart: only the unhandled record
    assert [it.line for it in q2.drain()] == left


def test_in_flight_item_commits_correctly_across_a_compaction(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_STREAM_JOURNAL_COMPACT_MB", "0.001")
    j = tmp_path / "s.jsonl"
    q = StreamQueue(1000, journal=j)
    q.put_many("w", [json.dumps({"id": f"a{i}", "pad": "y" * 100}) for i in range(30)])
    items = q.drain()
    for it in items[:20]:
        q.commit(it, force=True)                                         # compacts while 10 are still in hand
    for it in items[20:]:
        q.commit(it, force=True)
    q.flush_commit()
    assert StreamQueue(1000, journal=j).drain() == []


# ---- I4-4: a torn append is cut, and replay trims a torn tail --------------------------------------------------------------

def test_torn_journal_tail_is_trimmed_on_replay(tmp_path):
    j = tmp_path / "s.jsonl"
    q = StreamQueue(100, journal=j)
    q.put_many("w", ['{"id":"x1"}'])
    with j.open("ab") as fh:
        fh.write(b'{"s":"w","l":"{\\"id\\":\\"tor')                      # a crash mid-append
    q2 = StreamQueue(100, journal=j)
    q2.put_many("w", ['{"id":"retried"}'])
    q3 = StreamQueue(100, journal=j)
    assert [json.loads(it.line)["id"] for it in q3.drain()] == ["x1", "retried"]


def test_failed_journal_write_leaves_no_fragment(tmp_path, monkeypatch):
    j = tmp_path / "s.jsonl"
    q = StreamQueue(100, journal=j)
    q.put_many("w", ['{"id":"a"}'])
    real = os.write
    monkeypatch.setattr(os, "write", lambda fd, data: real(fd, bytes(data[:7])) and (_ for _ in ()).throw(OSError(28, "full")))
    assert q.put_many("w", ['{"id":"b"}']) is False
    monkeypatch.setattr(os, "write", real)
    assert q.put_many("w", ['{"id":"c"}'])
    assert [json.loads(it.line)["id"] for it in StreamQueue(100, journal=j).drain()] == ["a", "c"]


# ---- I4-5: a batch larger than the queue fits into an empty queue ---------------------------------------------------------

def test_oversized_batch_fits_an_empty_queue_only():
    q = StreamQueue(100)
    assert q.put_many("cf", [f'{{"id":"{i}"}}' for i in range(150)])
    assert not q.put_many("cf", ['{"id":"x"}' for _ in range(10)])


# ---- I4-10: deferred recycle never replays a handled file ----------------------------------------------------------------

def test_deferred_recycle_crash_does_not_redeliver(tmp_path, monkeypatch):
    from aegis.ops.deferred import DeferredQueue
    q = DeferredQueue(tmp_path / "d.jsonl")
    for i in range(3):
        q.push({"id": f"d{i}"})
    assert len(q.pop(10)) == 3
    real_unlink = os.unlink
    calls = []

    def crash_after_rename(path, *a, **k):                            # crash right after the data was set aside
        calls.append(str(path))
        raise SystemExit("crash")
    monkeypatch.setattr("pathlib.Path.unlink", lambda self, missing_ok=False: crash_after_rename(self))
    with pytest.raises(SystemExit):
        q.ack()
    monkeypatch.setattr("pathlib.Path.unlink", lambda self, missing_ok=False: real_unlink(self) if self.exists() or not missing_ok else None)
    q2 = DeferredQueue(tmp_path / "d.jsonl")
    assert q2.pop(10) == []
    q2.push({"id": "new"})
    assert [r["id"] for r in q2.pop(10)] == ["new"]


def test_deferred_pending_is_a_running_count(tmp_path, monkeypatch):
    from aegis.ops.deferred import DeferredQueue
    q = DeferredQueue(tmp_path / "d.jsonl")
    for i in range(5):
        q.push({"id": i})
    assert q.pending() == 5
    monkeypatch.setattr(q, "_count", lambda: (_ for _ in ()).throw(AssertionError("rescanned")))
    q.push({"id": 9})
    q.pop(2)
    q.ack()
    assert q.pending() == 4


# ---- I4-6: poison attempts survive other alerts, and the body is kept ----------------------------------------------------

def test_poison_alert_reaches_the_limit_and_is_dead_lettered(tmp_path, monkeypatch):
    from aegis.ingest.base import AlertCheckpoint
    monkeypatch.setenv("AEGIS_DEAD_LETTER", str(tmp_path / "dl.jsonl"))
    monkeypatch.setenv("AEGIS_INGEST_POISON_MAX", "3")
    cp_path = tmp_path / "cp.json"
    for _restart in range(3):
        cp = AlertCheckpoint(cp_path)
        assert cp.begin("src:other", {"id": "other"})                  # another alert begun first after restart
        cp.done()
        assert cp.begin("src:bad", {"id": "bad", "x": 1})              # ... then the crasher, which never finishes
    cp = AlertCheckpoint(cp_path)
    assert cp.begin("src:bad", {"id": "bad", "x": 1}) is False
    rows = [json.loads(x) for x in (tmp_path / "dl.jsonl").read_text().splitlines()]
    assert rows[0]["id"] == "bad" and rows[0]["x"] == 1


# ---- I4-9: pushed feeds dedupe per source ---------------------------------------------------------------------------------

def test_stream_lru_is_per_pushed_source():
    from aegis.ingest.base import AlertCheckpoint
    cp = AlertCheckpoint(max_ids=10)
    cp.mark("stream:edr:E-1")
    for i in range(50):
        cp.mark(f"stream:waf:W-{i}")
    assert cp.seen("stream:edr:E-1")


# ---- I4-3: file sources are tailed --------------------------------------------------------------------------------------

def test_file_source_reads_only_new_lines(tmp_path):
    from aegis.ingest.base import AlertCheckpoint
    f = tmp_path / "waf.log"
    f.write_bytes(b"a\nb\n")                                          # bytes: no CRLF translation on Windows
    cp = AlertCheckpoint(tmp_path / "cp.json")
    assert list(cp.tail_lines(f)) == ["a\n", "b\n"]
    with f.open("ab") as fh:
        fh.write(b"c\npartial")
    assert list(cp.tail_lines(f)) == ["c\n"]
    cp.flush()
    assert list(AlertCheckpoint(tmp_path / "cp.json").tail_lines(f)) == []
    f.write_bytes(b"rotated\n")                                        # truncated / rotated: start over
    assert list(cp.tail_lines(f)) == ["rotated\n"]


def test_sentinel_queries_from_the_watermark():
    from aegis.ingest.base import AlertCheckpoint
    from aegis.ingest.sentinel import DEFAULT_KQL, SentinelConfig, SentinelConsumer
    seen = []

    def transport(method, url, body, headers, timeout):
        if "oauth2" in url or "token" in url:
            return 200, json.dumps({"access_token": "t", "expires_in": 3600})
        seen.append(json.loads(body)["query"])
        return 200, json.dumps({"tables": []})
    cp = AlertCheckpoint()
    cp.advance("sentinel:ingested", "2026-11-03T10:00:00+00:00")
    c = SentinelConsumer(SentinelConfig(workspace_id="w", tenant_id="t", client_id="c", client_secret="s"),
                         checkpoint=cp, transport=transport)
    list(c.fetch())
    # round 5 Y5-4: on ingestion_time(), with a 10-minute overlap
    assert "ingestion_time() > datetime(2026-11-03T09:50:00Z)" in seen[-1] and "asc" in seen[-1]
    assert seen[-1] != DEFAULT_KQL


# ---- I4-7: a handler bug sets the alert aside ---------------------------------------------------------------------------

def test_handler_exception_is_dead_lettered(tmp_path, monkeypatch):
    from aegis import service
    monkeypatch.setenv("AEGIS_DEAD_LETTER", str(tmp_path / "dl.jsonl"))
    class _P:
        orch = types.SimpleNamespace(handle=lambda a: (_ for _ in ()).throw(TypeError("odd field")),
                                     is_fast_path=lambda a: False)

        def __getattr__(self, name):
            return None
    p = _P()
    st = service.run_cycle(p, alerts=iter([{"id": "A1"}]), sweep=False, hitl=False)
    assert st.dead_lettered == 1 and "dead_lettered=1" in st.line()
    assert json.loads((tmp_path / "dl.jsonl").read_text())["id"] == "A1"


# ---- I4-11: the receiver bounds connections and slow headers -------------------------------------------------------------

def test_receiver_closes_slow_header_connections(monkeypatch):
    from aegis.ingest.http_push import PushServer
    monkeypatch.setenv("AEGIS_INGEST_HEADER_S", "1")
    srv = PushServer(token="t", bind="127.0.0.1:0", queue=StreamQueue()).start()
    try:
        s = socket.create_connection(("127.0.0.1", srv.port), timeout=5)
        s.sendall(b"POST /ingest/alerts HTTP/1.1\r\nHost: x\r\n")      # never finishes its headers
        time.sleep(1.6)
        s.settimeout(2)
        assert s.recv(10) == b""                                         # closed by the server
    finally:
        srv.stop()


# ---- R4-1: active enforcement survives a restart -------------------------------------------------------------------------

def test_active_receipts_are_restored_from_the_receipt_log(tmp_path):
    from aegis.agents.response.connectors.base import ConnectorRegistry
    from aegis.agents.response.connectors.mock_vendor import MockImperva
    from aegis.agents.response.connectors.waf import ImpervaWafConnector
    from aegis.agents.response.receipts import ReceiptLog
    log = ReceiptLog(tmp_path / "_receipts.jsonl")
    srv = MockImperva()
    reg = ConnectorRegistry([ImpervaWafConnector(site_id="s", api_id="mock", api_key="mock", transport=srv, dry_run=False)],
                            on_receipt=[log])
    r = reg.apply(types.SimpleNamespace(action_type="block", target="203.0.113.9"), ttl_sec=900)
    assert r.active
    reg2 = ConnectorRegistry([ImpervaWafConnector(site_id="s", api_id="mock", api_key="mock", transport=srv, dry_run=False)])
    assert reg2.restore(ReceiptLog.latest_per_receipt(ReceiptLog.read(log.path))) == 1
    assert [x.target for c in reg2.connectors for x in c.active_receipts] == ["203.0.113.9"]


# ---- R4-14: the operator's own SWG entry is never removed ----------------------------------------------------------------

def test_zscaler_keeps_a_pre_existing_entry():
    from aegis.agents.response.connectors.mock_vendor import MockZscaler
    from aegis.agents.response.connectors.swg import ZscalerConnector
    zia = MockZscaler()
    zia.categories["C1"] = {"evil.example"}
    z = ZscalerConnector(base_url="https://zia", category_id="C1", token_provider=lambda: "mock", transport=zia, dry_run=False)
    r = z.apply(types.SimpleNamespace(action_type="block_egress", target="evil.example"))
    z.rollback(r, reason="ttl")
    assert "evil.example" in {u.lower() for u in zia.categories["C1"]}
