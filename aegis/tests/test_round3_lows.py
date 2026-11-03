"""Round-3 review, low items (G4-16 / R3-12..16)."""

from __future__ import annotations

import threading
import time
import types

import pytest


def test_firehose_with_a_non_object_body_is_400():
    from aegis.ingest.http_push import PushServer
    from aegis.ingest.stream import StreamQueue
    srv = PushServer(token="t", bind="127.0.0.1:0", queue=StreamQueue())
    assert srv.ingest_firehose(b"[1, 2, 3]", {})[0] == 400
    assert srv.ingest_firehose(b'"just a string"', {})[0] == 400


@pytest.mark.skipif(not hasattr(time, "tzset"), reason="needs tzset")
def test_naive_vendor_times_are_utc(monkeypatch):
    from aegis.ingest.stream import _vendor_ts
    monkeypatch.setenv("TZ", "Asia/Kolkata")
    time.tzset()
    try:
        assert _vendor_ts({"timestamp": "2026-11-03T10:00:00"}) == _vendor_ts({"timestamp": "2026-11-03T10:00:00Z"})
    finally:
        monkeypatch.delenv("TZ")
        time.tzset()


def test_a_held_chain_lock_is_not_evicted():
    from aegis.agents.orchestrator.walkers import loop
    lk = loop.chain_lock("held-alert")
    with lk:
        for i in range(6000):
            loop.chain_lock(f"other-{i}")
        assert loop.chain_lock("held-alert") is lk


def test_wedged_pool_replacement_is_capped(monkeypatch):
    from aegis.agents.orchestrator.swarm import SwarmOrchestrator as Swarm
    monkeypatch.setenv("AEGIS_SWARM_MAX_ABANDONED", "4")
    sw = object.__new__(Swarm)
    sw._orch = types.SimpleNamespace()
    sw.max_workers = 2
    sw._abandoned, sw._cap_logged = set(), False
    from concurrent.futures import ThreadPoolExecutor
    sw._pool = ThreadPoolExecutor(max_workers=2)
    stuck = threading.Event()
    replaced = 0
    try:
        for _ in range(6):
            sw._hung = {sw._pool.submit(stuck.wait) for _ in range(2)}
            before = sw._pool
            sw._replace_pool_if_wedged()
            replaced += sw._pool is not before
        assert replaced == 2                       # 2 pools x 2 stuck threads = the cap of 4; then it stops
    finally:
        stuck.set()


def test_watermark_compares_times_not_strings(tmp_path):
    from aegis.ingest.base import AlertCheckpoint
    cp = AlertCheckpoint(tmp_path / "cp.json")
    cp.advance("acp", "999")
    cp.advance("acp", "1000")
    assert cp.watermark("acp") == "1000"
    cp.advance("acp2", "2026-11-03T10:00:00+05:30")          # 04:30Z
    cp.advance("acp2", "2026-11-03T05:00:00Z")
    assert cp.watermark("acp2") == "2026-11-03T05:00:00Z"
