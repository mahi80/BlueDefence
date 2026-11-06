"""Round-3 review, group G4 (the rest): checkpoint cost, poison alerts, edge control, spill, dead letters."""

from __future__ import annotations

import importlib.util
import ipaddress
import json
import os
import sys
import types
from pathlib import Path

import pytest

from aegis.ingest.base import AlertCheckpoint

# ---- G4-6: the checkpoint ----------------------------------------------------------------------------------------------

def test_checkpoint_is_not_rewritten_per_alert(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_CHECKPOINT_FLUSH_S", "60")
    cp = AlertCheckpoint(tmp_path / "cp.json")
    writes = []
    real = cp._flush
    cp._flush = lambda: (writes.append(1), real())[1]
    for i in range(300):
        cp.mark(f"waf:{i}")
        cp.advance("waf", f"2026-11-03T10:{i // 60:02d}:{i % 60:02d}Z")
    assert len(writes) <= 2
    cp.flush()
    again = AlertCheckpoint(tmp_path / "cp.json")
    assert again.seen("waf:299") and again.watermark("waf") == "2026-11-03T10:04:59Z"


def test_one_noisy_source_does_not_evict_another(tmp_path):
    cp = AlertCheckpoint(tmp_path / "cp.json", max_ids=10)
    cp.mark("sentinel:a1")
    for i in range(100):
        cp.mark(f"waf:{i}")
    assert cp.seen("sentinel:a1")


# ---- G4-13: an alert that crashes the process is not re-delivered forever ---------------------------------------------

def test_a_crash_looping_alert_is_skipped(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_INGEST_POISON_MAX", "2")
    from aegis.ingest.base import BaseConsumer

    class One(BaseConsumer):
        name = "t"

        def fetch(self, **kw):
            yield {"id": "poison"}

        def normalize(self, record):
            return dict(record)

    dead = []                                            # kept suspended: a crash runs no cleanup at all
    for _ in range(2):                                   # two "crashes": handed out, never finished
        cp = AlertCheckpoint(tmp_path / "cp.json")
        it = One(checkpoint=cp).iter_alerts()
        assert next(it)["id"] == "poison"
        dead.append(it)
    cp = AlertCheckpoint(tmp_path / "cp.json")
    assert list(One(checkpoint=cp).iter_alerts()) == []  # third start: skipped and marked


def test_a_caller_stopping_early_is_not_a_crash(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_INGEST_POISON_MAX", "2")
    from aegis.ingest.base import BaseConsumer

    class One(BaseConsumer):
        name = "t"

        def fetch(self, **kw):
            yield {"id": "boundary"}

        def normalize(self, record):
            return dict(record)

    for _ in range(4):                                   # max_alerts stops right after receiving it, every cycle
        it = One(checkpoint=AlertCheckpoint(tmp_path / "cp.json")).iter_alerts()
        next(it)
        it.close()
    assert [a["id"] for a in One(checkpoint=AlertCheckpoint(tmp_path / "cp.json")).iter_alerts()] == ["boundary"]


# ---- G4-11: the edge -------------------------------------------------------------------------------------------------------

def _edge():
    p = Path(__file__).resolve().parents[2] / "scripts" / "aegis_edge.py"
    spec = importlib.util.spec_from_file_location("aegis_edge_t", p)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["aegis_edge_t"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("target", ["0.0.0.0/0", "10.0.0.0/8", "::/0", "127.0.0.1", "169.254.169.254"])
def test_edge_refuses_blocks_that_black_out_everyone(target):
    edge = _edge()
    assert edge.Blocklist(None, None).push(target, None) is False


def test_edge_accepts_an_ordinary_block():
    edge = _edge()
    bl = edge.Blocklist(None, None)
    assert bl.push("203.0.113.7", None) and bl.is_blocked("203.0.113.7")
    assert edge._enforceable(ipaddress.ip_network("198.51.100.0/24"))


def test_edge_control_token_replaces_the_shared_one():
    edge = _edge()
    state = types.SimpleNamespace(token="shared", control_token="ctl")
    h = types.SimpleNamespace(state=state, headers={"Authorization": "Bearer shared"})
    assert edge.Handler._control_authorized(h) is False
    h.headers = {"Authorization": "Bearer ctl"}
    assert edge.Handler._control_authorized(h) is True
    state.control_token = None                                         # no control token: the shared one, as before
    h.headers = {"Authorization": "Bearer shared"}
    assert edge.Handler._control_authorized(h) is True


# ---- G4-12: the spill keeps the evidence ------------------------------------------------------------------------------------

def test_spill_is_private(tmp_path):
    import os
    import stat

    from aegis.ops.deferred import DeferredQueue
    q = DeferredQueue(tmp_path / "d.jsonl")
    q.push({"id": "leak-1", "body": "AWS_SECRET_ACCESS_KEY=abcd1234abcd1234abcd1234abcd1234abcd1234"})
    if os.name != "nt":                       # Windows has no POSIX mode bits to check
        assert stat.S_IMODE(os.stat(tmp_path / "d.jsonl").st_mode) == 0o600
    assert "abcd1234" in q.pop(1)[0]["body"]


@pytest.mark.skipif(os.name == "nt", reason="creating symlinks needs a privilege Windows CI does not grant")
def test_spill_refuses_a_symlink(tmp_path):
    from aegis.ops.deferred import DeferredQueue
    (tmp_path / "elsewhere").write_text("")
    (tmp_path / "d.jsonl").symlink_to(tmp_path / "elsewhere")
    assert DeferredQueue(tmp_path / "d.jsonl").push({"id": "x"}) is False
    assert (tmp_path / "elsewhere").read_text() == ""


# ---- G4-14: a seal failure that will not clear goes to the dead letter, not round and round -----------------------------

def test_non_transient_seal_failure_is_dead_lettered(tmp_path, monkeypatch):
    from aegis import service
    from aegis.agents.shared.audit import AuditWriteError
    monkeypatch.setenv("AEGIS_DEAD_LETTER", str(tmp_path / "dl.jsonl"))
    monkeypatch.setenv("AEGIS_AUDIT_REFEED_MAX", "2")

    def boom(alert):
        raise AuditWriteError("cannot serialise", None)
    pushed = []
    storm = types.SimpleNamespace(active=False, queue=types.SimpleNamespace(push=lambda a, r="": pushed.append(a) or True))
    p = types.SimpleNamespace(orch=types.SimpleNamespace(handle=boom, is_fast_path=lambda a: False),
                              response=types.SimpleNamespace(sync_hitl=list, sweep_expired=list),
                              investigator=None, containment=None, persist_sink=None, license_meter=None, license=None)
    st = service.run_cycle(p, alerts=iter([{"id": "bad-1", "audit_attempts": 1, "audit_deferred": True}]),
                           sweep=False, hitl=False, storm=storm)
    assert st.dead_lettered == 1 and pushed == []
    assert json.loads((tmp_path / "dl.jsonl").read_text())["id"] == "bad-1"
