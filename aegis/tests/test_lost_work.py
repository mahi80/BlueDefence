"""Paths that used to lose alerts or approvals without a trace (code review 2026-11-03, group C:
E1–E8, C1, C2)."""

from __future__ import annotations

import json
import socket
import types
from pathlib import Path

import pytest

from aegis.agents.shared.audit import AuditWriteError
from aegis.agents.shared.evidence_chain import EvidenceChain, RecommendedAction
from aegis.ops.deferred import DeferredQueue, SpillQueue, default_spill

ALERT = {"id": "waf-9", "source": "Imperva WAF", "src_ip": "203.0.113.5", "path": "/login", "severity": "high"}


@pytest.fixture
def pipe(tmp_path, monkeypatch):
    from aegis.service import build_pipeline
    monkeypatch.setenv("LLM_BACKEND", "mock"); monkeypatch.setenv("AEGIS_INGEST_HTTP", "0")
    monkeypatch.setenv("AEGIS_SOURCES", "sample"); monkeypatch.setenv("AEGIS_SWARM", "0")
    monkeypatch.setenv("AEGIS_RECEIPTS_PATH", str(tmp_path / "receipts.jsonl"))
    p = build_pipeline(tmp_path / "audit.jsonl", fresh=True)
    yield p
    p.close()


def _boom(*a, **k):
    raise AuditWriteError("audit log not writable: No space left on device", 28)


# ---- E1: a re-fed alert that fails again is parked again --------------------------------------------

def test_refed_alert_that_fails_again_is_parked_again(pipe, tmp_path, monkeypatch):
    from aegis.service import StormControl, run_cycle
    storm = StormControl(SpillQueue(DeferredQueue(tmp_path / "deferred.jsonl")), pipe.stream, 60.0)
    monkeypatch.setattr(pipe.orch, "handle", _boom)
    run_cycle(pipe, alerts=iter([ALERT]), sweep=False, hitl=False, storm=storm)
    for _ in range(3):                                     # the disk stays full across three re-feed rounds
        batch = storm.queue.pop(10)
        st = run_cycle(pipe, alerts=iter(batch), sweep=False, hitl=False, storm=storm)
        storm.queue.ack()
        assert st.audit_failures == 1 and st.deferred == 1 and st.lost == 0
        assert storm.queue.pending() == 1                  # was 0 after the first re-feed: the alert vanished


# ---- E2: spill on a full audit volume goes to the fallback ------------------------------------------

def test_spill_falls_back_when_the_primary_volume_is_full(tmp_path, monkeypatch):
    full = DeferredQueue(tmp_path / "audit-vol" / "deferred.jsonl", max_bytes=1)
    full.push({"id": "already-here"})                      # primary now at its cap: refuses every push
    q = SpillQueue(full, DeferredQueue(tmp_path / "other-vol" / "deferred.jsonl"))
    assert q.push({"id": "a1"}) and q.push({"id": "a2"})
    assert q.pending() == 3 and q.dropped == 0
    assert [r["id"] for r in q.pop(10)] == ["already-here"]; q.ack()
    assert [r["id"] for r in q.pop(10)] == ["a1", "a2"]; q.ack()
    assert q.pending() == 0


def test_default_spill_has_a_fallback_off_the_audit_volume(tmp_path, monkeypatch):
    monkeypatch.delenv("AEGIS_DEFERRED_PATH", raising=False)
    monkeypatch.setenv("AEGIS_DEFERRED_FALLBACK", str(tmp_path / "fb" / "spill.jsonl"))
    q = default_spill(tmp_path / "audit" / "audit.jsonl")
    assert q.primary.path == tmp_path / "audit" / "deferred.jsonl" and q.fallback.path == tmp_path / "fb" / "spill.jsonl"
    monkeypatch.setenv("AEGIS_DEFERRED_FALLBACK", "off")
    assert default_spill(tmp_path / "audit" / "audit.jsonl").fallback is None


# ---- E8: a torn append is cut back -------------------------------------------------------------------

def test_partial_spill_append_is_truncated(tmp_path, monkeypatch):
    q = DeferredQueue(tmp_path / "d.jsonl")
    assert q.push({"id": "ok-1"})
    real_open = Path.open

    def failing_open(self, mode="r", *a, **k):
        fh = real_open(self, mode, *a, **k)
        if "a" in mode and self.name == "d.jsonl":
            orig = fh.write

            def write(data):
                orig(data[:10]); fh.flush()                # half the row lands, then the disk is full
                raise OSError(28, "No space left on device")
            fh.write = write
        return fh
    monkeypatch.setattr(Path, "open", failing_open)
    assert q.push({"id": "torn"}) is False
    monkeypatch.setattr(Path, "open", real_open)
    assert q.push({"id": "ok-2"})
    assert [r["id"] for r in q.pop(10)] == ["ok-1", "ok-2"]   # the next row did not merge into a fragment


# ---- E6: one failing source does not blind the others ------------------------------------------------

def test_one_failing_source_does_not_stop_the_others(pipe, monkeypatch):
    from aegis import ingest
    from aegis.service import run_cycle

    def sentinel():
        raise RuntimeError("Sentinel 401 Unauthorized")
        yield  # pragma: no cover
    waf = [{**ALERT, "id": f"waf-{i}"} for i in range(3)]
    monkeypatch.setattr(ingest, "sources_from_env", lambda: [("sentinel", sentinel()), ("waf", iter(waf))])
    st = run_cycle(pipe, sweep=False, hitl=False)
    assert st.alerts == 3 and st.errors == 1 and st.source_errors == ["sentinel"]


# ---- E4: a re-seal failure fails closed ---------------------------------------------------------------

def test_swarm_reseal_failure_is_an_audit_failure():
    from aegis.agents.orchestrator.swarm import SwarmOrchestrator

    def record(alert, chain):
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad byte")
    orch = types.SimpleNamespace(record=record, handle=lambda a: None)
    sw = SwarmOrchestrator(orch, max_workers=1, workers={})
    try:
        with pytest.raises(AuditWriteError):
            sw._reseal(ALERT, EvidenceChain(alert_id="waf-9", investigated_by="t", verdict="malicious", confidence=0.9))
    finally:
        sw._pool.shutdown(wait=False)


# ---- E5 / E7: governance outage and orchestrator block ------------------------------------------------

class _Violation(Exception):
    control, code = "Q33", "ACP-733"


class _Guard:
    def __init__(self, pre=None, post=None):
        self.pre, self.post = pre, post

    def begin_task(self, alert_id=None):
        return alert_id

    def pre_tool_call(self, tool, meta, **kw):
        if self.pre:
            raise self.pre

    def post_tool_call(self, tool, **kw):
        if self.post:
            raise self.post


def _governed(monkeypatch, guard, chain):
    import aegis.governance as gov
    monkeypatch.setattr(gov, "_violation_type", lambda: _Violation)
    recorded = []
    orch = types.SimpleNamespace(handle=lambda alert: chain, record=lambda a, c: recorded.append(c))
    return gov._guard_handle(orch, gov.GovernedSOC(guard=guard, agent_code="t")), recorded


def _chain():
    c = EvidenceChain(alert_id="waf-9", investigated_by="t", verdict="malicious", confidence=0.95)
    c.recommended_actions.append(RecommendedAction(action_type="throttle", target="203.0.113.5", reasoning="r",
                                                   requires_hitl=False, confidence=0.9))
    return c


def test_acp_outage_keeps_the_alert_and_holds_every_action(monkeypatch):
    handle, _ = _governed(monkeypatch, _Guard(pre=ConnectionError("ACP down")), _chain())
    c = handle(ALERT)                                       # used to raise, and run_cycle dropped the alert
    assert c.verdict == "malicious" and all(a.requires_hitl for a in c.recommended_actions)
    assert "ConnectionError" in c.metadata["governance_unavailable"]


def test_post_call_timeout_does_not_lose_the_sealed_chain(monkeypatch):
    handle, _ = _governed(monkeypatch, _Guard(post=TimeoutError("post_tool_call timed out")), _chain())
    c = handle(ALERT)
    assert c.verdict == "malicious" and not c.recommended_actions[0].requires_hitl


def test_orchestrator_block_is_recorded_in_the_audit_log(monkeypatch):
    handle, recorded = _governed(monkeypatch, _Guard(pre=_Violation("agent paused")), _chain())
    c = handle(ALERT)
    assert c.metadata.get("governance_block") and recorded == [c]


def test_response_guard_outage_queues_instead_of_raising(monkeypatch):
    import aegis.governance as gov
    from aegis.agents.response.agent import ExecutedAction
    monkeypatch.setattr(gov, "_violation_type", lambda: _Violation)
    resp = types.SimpleNamespace(_execute_auto=lambda a, *x, **k: ExecutedAction(action=a, status="executed"),
                                 approve=lambda a, approver, *x, **k: ExecutedAction(action=a, status="executed"))
    gov._guard_response(resp, _Guard(pre=ConnectionError("ACP down")))
    act = _chain().recommended_actions[0]
    assert resp._execute_auto(act).status == "queued_for_hitl"
    r = resp.approve(act, "ciso")
    assert r.status == "skipped" and r.reason == "error"     # retried by the HITL loop, not lost


# ---- E3: an approval the channel refused is kept and filed again --------------------------------------

def test_unfiled_approval_is_retried_and_survives_a_restart(tmp_path, monkeypatch):
    from aegis.hitl.filequeue import FileHITL
    monkeypatch.delenv("AEGIS_HITL_STATE", raising=False)
    h = FileHITL(tmp_path / "hitl")
    calls = {"n": 0}
    real = h._file

    def flaky(card):
        calls["n"] += 1
        if calls["n"] < 3:
            raise ConnectionError("dashboard unreachable")
        return real(card)
    h._file = flaky
    act = RecommendedAction(action_type="isolate", target="host-7", reasoning="r", requires_hitl=True, confidence=0.9)
    chain = EvidenceChain(alert_id="A7", investigated_by="t", verdict="malicious", confidence=0.9)
    assert h.request(act, chain) is None                    # caller still prints the stdout card
    assert len(h.pending) == 1 and h.pending[0].unfiled
    # a restart before the channel recovers: the unfiled card is restored from the journal
    h2 = FileHITL(tmp_path / "hitl"); h2._file = flaky
    assert len(h2.pending) == 1 and h2.pending[0].unfiled
    agent = types.SimpleNamespace(approve=lambda *a, **k: pytest.fail("nothing may run on an unfiled card"))
    h2.sync(agent)                                          # attempt 2: still down
    assert h2.pending[0].unfiled
    h2.sync(agent)                                          # attempt 3: filed
    assert not h2.pending[0].unfiled and h2.pending[0].external_id
    cards = [json.loads(x) for x in (tmp_path / "hitl" / "cards.jsonl").read_text().splitlines()]
    assert [c["id"] for c in cards if c.get("kind") == "approval"] == [h2.pending[0].approval_id]


def test_unfiled_approval_never_times_out_into_an_execution(tmp_path, monkeypatch):
    from aegis.agents.response.hitl_timeout import HitlTimeoutPolicy
    from aegis.hitl.filequeue import FileHITL
    monkeypatch.delenv("AEGIS_HITL_STATE", raising=False)
    h = FileHITL(tmp_path / "hitl")
    h._file = lambda card: (_ for _ in ()).throw(ConnectionError("down"))
    act = RecommendedAction(action_type="block", target="203.0.113.5", reasoning="r", requires_hitl=True, confidence=0.9)
    chain = EvidenceChain(alert_id="A8", investigated_by="t", verdict="malicious", confidence=0.99)
    chain.metadata["vote_concur"] = True
    h.request(act, chain, timeout_ok=True)
    agent = types.SimpleNamespace(approve=lambda *a, **k: pytest.fail("timed out into an execution"))
    h.pending[0].requested_at -= 10_000
    made = h.sync(agent, max_age_sec=3600, timeout_policy=HitlTimeoutPolicy(mode="live", wait_sec=0))
    assert [d.status for d in made] == ["expired"] and not h.pending


# ---- C2: the exposure runner has its own journal -------------------------------------------------------

def test_exposure_runner_never_restores_or_settles_soc_approvals(tmp_path, monkeypatch):
    from aegis.hitl.filequeue import FileHITL
    from aegis.posture.runner import _FROM_ENV, _remediation_hitl
    monkeypatch.delenv("AEGIS_HITL_STATE", raising=False)
    monkeypatch.setenv("AEGIS_HITL_TRANSPORT", "file"); monkeypatch.setenv("AEGIS_HITL_DIR", str(tmp_path / "hitl"))
    soc = FileHITL(tmp_path / "hitl")
    act = RecommendedAction(action_type="block", target="203.0.113.5", reasoning="r", requires_hitl=True, confidence=0.9)
    soc.request(act, EvidenceChain(alert_id="A9", investigated_by="t", verdict="malicious", confidence=0.9))
    runner = _remediation_hitl(_FROM_ENV)
    assert runner is not None and runner.scope == "exposure"
    assert runner.pending == []                              # used to restore the SOC's block card
    assert runner.sync(types.SimpleNamespace(approve=lambda *a, **k: {"ok": True})) == []
    assert len(FileHITL(tmp_path / "hitl").pending) == 1     # the SOC card is untouched
    assert (tmp_path / "hitl" / "pending.jsonl").exists()


# ---- C1: chunked push bodies ---------------------------------------------------------------------------

def _raw(srv, req: bytes) -> tuple[int, dict]:
    with socket.create_connection((srv.host if srv.host != "0.0.0.0" else "127.0.0.1", srv.port), timeout=5) as s:
        s.sendall(req)
        data = b""
        while b"\r\n\r\n" not in data:
            data += s.recv(4096)
        head, _, body = data.partition(b"\r\n\r\n")
        n = int(next(h.split(b":")[1] for h in head.split(b"\r\n") if h.lower().startswith(b"content-length")))
        while len(body) < n:
            body += s.recv(4096)
        return int(head.split(b" ")[1]), json.loads(body[:n])


@pytest.fixture
def srv():
    from aegis.ingest.http_push import PushServer
    from aegis.ingest.stream import StreamQueue
    s = PushServer(token="t0ken-for-tests", bind="127.0.0.1:0", queue=StreamQueue()).start()
    yield s
    s.stop()


def _chunked(lines: list[bytes], sizes=None) -> bytes:
    body = b"".join(lines)
    out, i = b"", 0
    for n in sizes or [len(body)]:
        out += f"{n:x}\r\n".encode() + body[i:i + n] + b"\r\n"
        i += n
    return out + b"0\r\n\r\n"


def test_chunked_ndjson_is_accepted(srv):
    rows = [json.dumps({**ALERT, "id": f"c{i}"}).encode() + b"\n" for i in range(3)]
    body = _chunked(rows, sizes=[10, 40, sum(map(len, rows)) - 50])
    req = (b"POST /ingest/alerts HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer t0ken-for-tests\r\n"
           b"Content-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\n\r\n" + body)
    code, reply = _raw(srv, req)
    assert code == 200 and reply["accepted"] == 3            # was 200 with accepted=0


@pytest.mark.parametrize("bad", [b"-1\r\nxx\r\n0\r\n\r\n", b"zz\r\n", b"5\r\nab"])
def test_malformed_chunked_body_is_refused(srv, bad):
    req = (b"POST /ingest/alerts HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer t0ken-for-tests\r\n"
           b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n" + bad)
    with socket.create_connection(("127.0.0.1", srv.port), timeout=5) as s:
        s.sendall(req)
        if bad.endswith(b"ab"):
            s.shutdown(socket.SHUT_WR)
        assert s.recv(64).split(b" ")[1] == b"400"
