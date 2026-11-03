"""Rest of the lost-work group (code review 2026-11-03: E9–E13, E15) and B9."""

from __future__ import annotations

import json
import threading
import time
import types

import pytest

from aegis.ingest.base import AlertCheckpoint, BaseConsumer

# ---- E9: a full queue holds the Event Hub batch instead of dropping it -----------------------------------

class _Ev:
    def __init__(self, body, seq):
        self._b, self.sequence_number = body, seq

    def body_as_str(self):
        return self._b


class _Ctx:
    partition_id = "0"

    def __init__(self):
        self.checkpoints = []

    def update_checkpoint(self, ev):
        self.checkpoints.append(ev.sequence_number)


def test_eventhub_batch_waits_for_room_and_is_never_skipped(tmp_path):
    from aegis.ingest.eventhub import EventHubReader
    from aegis.ingest.stream import StreamQueue
    q = StreamQueue(1)
    q.put_many("x", ['{"id":"filler"}'])
    r = EventHubReader(connection_string="Endpoint=sb://x/;EntityPath=waf", checkpoint_path=tmp_path / "eh.json",
                       queue=q, backoff_s=0.01)
    ctx = _Ctx()
    t = threading.Thread(target=r.on_batch, args=(ctx, [_Ev('{"id":"held","source":"x"}', 7)]))
    t.start()
    time.sleep(7.0)                                         # > 60 tries: the old code dropped the batch here
    assert t.is_alive() and ctx.checkpoints == []
    q.drain()
    t.join(5)
    assert not t.is_alive() and ctx.checkpoints == [7] and len(q) == 1


def test_eventhub_stop_leaves_the_batch_uncheckpointed(tmp_path):
    from aegis.ingest.eventhub import EventHubReader
    from aegis.ingest.stream import StreamQueue
    q = StreamQueue(1)
    q.put_many("x", ['{"id":"filler"}'])
    r = EventHubReader(connection_string="Endpoint=sb://x/;EntityPath=waf", checkpoint_path=tmp_path / "eh.json",
                       queue=q, backoff_s=0.01)
    r._stop.set()
    ctx = _Ctx()
    r.on_batch(ctx, [_Ev('{"id":"held"}', 8)])
    assert ctx.checkpoints == [] and r.starting_position() == "@latest"   # re-read from the source on restart


# ---- E10: hung swarm workers do not wedge every later fan-out --------------------------------------------

def test_hung_workers_get_a_fresh_pool():
    from aegis.agents.orchestrator.swarm import SwarmOrchestrator, WorkerResult
    from aegis.agents.shared.evidence_chain import EvidenceChain
    release = threading.Event()

    def hang(alert, chain, ctx):
        release.wait(30)
        return WorkerResult("hang")

    def quick(alert, chain, ctx):
        return WorkerResult("quick")
    orch = types.SimpleNamespace(handle=lambda a: None, record=lambda a, c: None)
    sw = SwarmOrchestrator(orch, max_workers=2, max_seconds=0.3, workers={"hang": hang, "quick": quick})
    try:
        chain = lambda: EvidenceChain(alert_id="A", investigated_by="t", verdict="malicious", confidence=0.9)
        sw.fan_out({"id": "A1"}, chain())
        sw.fan_out({"id": "A2"}, chain())                  # two hung threads = the whole pool
        c = sw.fan_out({"id": "A3"}, chain())
        w = c.metadata["swarm"]["workers"]
        assert w["quick"]["ok"], w                          # a fresh pool ran it; it used to time out queued
        assert "busy" not in json.dumps(w)
    finally:
        release.set()
        sw._pool.shutdown(wait=False)


# ---- E11: the stream fast path does not wait on the dashboard ----------------------------------------------

def test_fast_path_pass_does_not_flush_the_sink(monkeypatch, tmp_path):
    from aegis.service import build_pipeline, run_cycle
    monkeypatch.setenv("LLM_BACKEND", "mock"); monkeypatch.setenv("AEGIS_INGEST_HTTP", "0")
    monkeypatch.setenv("AEGIS_SOURCES", "sample"); monkeypatch.setenv("AEGIS_SWARM", "0")
    p = build_pipeline(tmp_path / "audit.jsonl", fresh=True)
    calls = []
    p.persist_sink = types.SimpleNamespace(flush=lambda timeout=10.0: calls.append(timeout) or True)
    run_cycle(p, alerts=iter([]), sweep=False, hitl=False)
    assert calls == []
    run_cycle(p, alerts=iter([]), sweep=True, hitl=False)
    assert calls == [2.0]
    p.close()


# ---- E12: a corrupt posture state is refused, not reset ----------------------------------------------------

def test_corrupt_posture_state_is_refused(tmp_path):
    from aegis.posture import runner, sources
    (tmp_path / "state.json").write_text("{torn")
    with pytest.raises(sources.PostureSourceError, match="refusing to reset"):
        runner._read_json(tmp_path / "state.json", {})
    assert runner._read_json(tmp_path / "missing.json", {}) == {}           # a first run is still a first run


# ---- E13: covered in test_acp_bridge.py; the cycle counts it --------------------------------------------

def test_acp_outage_is_a_counted_source_error(monkeypatch, tmp_path):
    from aegis import ingest
    from aegis.ingest.acp import AcpGovernanceConsumer
    from aegis.service import build_pipeline, run_cycle
    monkeypatch.setenv("LLM_BACKEND", "mock"); monkeypatch.setenv("AEGIS_INGEST_HTTP", "0"); monkeypatch.setenv("AEGIS_SWARM", "0")
    p = build_pipeline(tmp_path / "audit.jsonl", fresh=True)
    c = AcpGovernanceConsumer("https://dash.test", "k", checkpoint=AlertCheckpoint(),
                              transport=lambda *a: (401, '{"error":"bad key"}'))
    monkeypatch.setattr(ingest, "sources_from_env", lambda: [("acp", c.iter_alerts())])
    st = run_cycle(p, sweep=False, hitl=False)
    assert st.errors == 1 and st.source_errors == ["acp"]
    p.close()


# ---- E15: an alert is marked seen only after it was handled -----------------------------------------------

class _Feed(BaseConsumer):
    name = "feed"

    def __init__(self, rows, cp):
        super().__init__(cp)
        self.rows = rows

    def fetch(self, **kw):
        yield from self.rows

    def normalize(self, r):
        return r


def test_an_alert_fetched_but_not_handled_is_redelivered():
    cp = AlertCheckpoint()
    rows = [{"id": "a1", "timestamp": "2026-11-03T01:00:00Z"}, {"id": "a2", "timestamp": "2026-11-03T01:01:00Z"}]
    it = _Feed(rows, cp).iter_alerts()
    assert next(it)["id"] == "a1"
    it.close()                                              # stopped (max_alerts / crash) before handling a1
    assert [a["id"] for a in _Feed(rows, cp).iter_alerts()] == ["a1", "a2"]
    assert list(_Feed(rows, cp).iter_alerts()) == []        # handled once, then deduped


# ---- B9: the investigation queue is bounded ----------------------------------------------------------------

def test_investigation_queue_is_bounded(monkeypatch):
    from aegis.agents.orchestrator.walkers.investigation import Investigator
    from aegis.agents.shared.evidence_chain import EvidenceChain
    monkeypatch.setenv("AEGIS_INVESTIGATE_MAX_QUEUED", "3")
    gate = threading.Event()

    class Slow:
        name = "slow"

        def __getattr__(self, item):
            def call(*a, **k):
                gate.wait(10)
                return []
            return call
    inv = Investigator(Slow(), max_workers=1)
    try:
        subs = [inv.submit({"id": f"A{i}", "user": "u"}, EvidenceChain(alert_id=f"A{i}", investigated_by="t",
                                                                      verdict="malicious", confidence=0.9)) for i in range(10)]
        assert sum(1 for s in subs if s is None) >= 5 and inv.skipped >= 5
        assert inv.status("A9")["state"] == "skipped"
    finally:
        gate.set()
        inv.drain(10)
