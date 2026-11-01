"""The derived index: one ORM, several databases; the JSONL stays the record."""

from __future__ import annotations

import json

import pytest

sa = pytest.importorskip("sqlalchemy")

from aegis.agents.shared.audit import AuditLog
from aegis.agents.shared.evidence_chain import EvidenceChain
from aegis.ingest.console_api import ConsoleAPI
from aegis.store import IndexStore, store_from_env


URLS = ["sqlite:///{d}/idx.sqlite"]
try:
    import duckdb_engine  # noqa: F401
    URLS.append("duckdb:///{d}/idx.duckdb")
except ImportError:
    pass


@pytest.fixture(params=URLS)
def store(request, tmp_path):
    return IndexStore(request.param.format(d=tmp_path.as_posix()))


def _chain(i: int, verdict: str = "benign") -> EvidenceChain:
    c = EvidenceChain(alert_id=f"ALR-{i}", investigated_by="perimeter", verdict=verdict, confidence=0.5 + i / 100)
    c.metadata["alert"] = {"source": "aws-waf"}
    c.metadata["summary"] = f"chain {i}"
    return c


def test_audit_append_indexes_and_console_reads_sql(tmp_path, store):
    log = AuditLog(tmp_path / "audit.jsonl", index=store)
    for i in range(5):
        log.append(_chain(i, "malicious" if i == 3 else "benign"))
    st = store.stats()
    assert st["chains"] == 5 and st["stale"] is False
    rows = store.recent(10)
    assert [r["alert_id"] for r in rows] == ["ALR-4", "ALR-3", "ALR-2", "ALR-1", "ALR-0"]       # newest first
    assert rows[1]["verdict"] == "malicious" and rows[1]["source"] == "aws-waf" and rows[1]["note"] == "chain 3"
    assert store.verdict_counts() == {"benign": 4, "malicious": 1}
    assert store.recent(10, verdict="malicious")[0]["alert_id"] == "ALR-3"
    full = store.get(rows[1]["chain_id"])
    assert full["alert_id"] == "ALR-3" and full["integrity_hash"] == rows[1]["chain_id"]
    assert store.get("ALR-0")["alert_id"] == "ALR-0" and store.get("nope") is None
    api = ConsoleAPI(tmp_path / "audit.jsonl", tmp_path / "hitl", index=store)
    out = api.chains(3)
    assert out.get("from") == "index" and len(out["chains"]) == 3 and out["chains"][0]["alert_id"] == "ALR-4"
    assert api.chain(rows[1]["chain_id"])["evidence"] == [] and api.chain("ALR-2")["alert_id"] == "ALR-2"


def test_index_is_idempotent_and_rebuildable(tmp_path, store):
    log = AuditLog(tmp_path / "audit.jsonl", max_bytes=600, index=store)      # rotates
    for i in range(8):
        log.append(_chain(i))
    assert len(log.rotated_files()) >= 1 and store.stats()["chains"] == 8
    # a second index built from the files alone lands on the same rows; running it again adds nothing
    fresh = IndexStore(store.url.replace("idx.", "fresh."))
    r1 = fresh.reindex(tmp_path / "audit.jsonl")
    r2 = fresh.reindex(tmp_path / "audit.jsonl")
    assert r1["chains_added"] == 8 and r1["chains_seen"] == 8 and r2["chains_added"] == 0
    assert [r["alert_id"] for r in fresh.recent(100)] == [r["alert_id"] for r in store.recent(100)]
    # prev_hash links are preserved through the rebuild (the chain is verifiable from the index alone)
    from aegis.store.models import ChainRow
    from sqlalchemy.orm import Session
    with Session(fresh.engine) as s:
        rows = s.scalars(sa.select(ChainRow).order_by(ChainRow.seq)).all()
    assert all(rows[i].prev_hash == rows[i - 1].integrity_hash for i in range(1, len(rows)))


def test_decisions_and_cursors_are_append_only(tmp_path, store):
    assert store.record_decision(approval_id="a1", alert_id="ALR-1", action_type="block", target="1.2.3.4",
                                 status="approved", decided_by="ciso:asha", rationale="contain", via="console")
    assert store.record_decision(approval_id="a1", alert_id="ALR-1", action_type="block", target="1.2.3.4",
                                 status="rejected", decided_by="cio:x", via="console")                  # the first decision stands
    d = store.decisions()
    assert len(d) == 1 and d[0]["status"] == "approved" and d[0]["decided_by"] == "ciso:asha"
    assert not hasattr(store, "delete_chain") and not hasattr(store, "update_chain")
    store.set_cursor("contrib", "1234", 999)
    store.set_cursor("contrib", "1234", 2048)
    assert store.get_cursor("contrib") == {"segment": "1234", "offset": 2048} and store.get_cursor("none") is None


def test_console_decide_records_into_the_index(tmp_path, store):
    hitl = tmp_path / "hitl"; hitl.mkdir()
    (hitl / "cards.jsonl").write_text(json.dumps({"kind": "approval", "ts": 1793500000.0, "id": "aegis_x_block_1", "action": "block -> 9.9.9.9",
                                                  "args": {"alert_id": "ALR-7", "action_type": "block", "target": "9.9.9.9"}, "alert_id": "ALR-7"}) + "\n")
    api = ConsoleAPI(None, hitl, index=store)
    assert api.decide("aegis_x_block_1", "approved", decided_by="ciso:asha", reason="ok")[0] == 200
    d = store.decisions()
    assert d[0]["approval_id"] == "aegis_x_block_1" and d[0]["alert_id"] == "ALR-7" and d[0]["via"] == "console"


def test_store_failures_never_raise_and_console_falls_back(tmp_path, store, monkeypatch):
    log = AuditLog(tmp_path / "audit.jsonl", index=store)
    log.append(_chain(1))
    def boom(*a, **k): raise sa.exc.OperationalError("insert", {}, Exception("db gone"))
    monkeypatch.setattr(sa.orm.Session, "commit", boom)
    log.append(_chain(2))                                                     # the JSONL append still succeeds
    assert len((tmp_path / "audit.jsonl").read_text().splitlines()) == 2 and store.stale is True
    api = ConsoleAPI(tmp_path / "audit.jsonl", None, index=store)
    assert "from" not in api.chains(10) and api.chains(10)["count"] == 2    # stale index → file scan


def test_store_from_env_defaults_and_off(tmp_path):
    env = {"AEGIS_INDEX": "0"}
    assert store_from_env(tmp_path / "audit.jsonl", env) is None
    s = store_from_env(tmp_path / "audit.jsonl", {"AEGIS_INDEX_URL": f"sqlite:///{tmp_path.as_posix()}/x.sqlite"})
    assert s is not None and s.dialect == "sqlite"
    assert store_from_env(tmp_path / "audit.jsonl", {"AEGIS_INDEX_URL": "postgresql+psycopg2://x:y@127.0.0.1:1/none"}) is None   # unreachable → disabled, not fatal
