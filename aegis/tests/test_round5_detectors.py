"""Round 5 (review of the round-4 fixes): treasury ledger, retrain pointer, object-walk window, SSRF short forms."""

from __future__ import annotations

import datetime as dt
import json

import pytest

# ---- Y5-5: the treasury ledger -------------------------------------------------------------------------------------------

_BASE = 1_762_160_000


def _tx(i, amount, t=None, sender="TREASURY-OPS-01"):
    return {"id": f"t{i}", "sender_account": sender, "beneficiary_account": f"B{i}", "amount_inr": amount,
            "new_beneficiary": True, "timestamp": dt.datetime.fromtimestamp(_BASE + (i if t is None else t), dt.UTC).isoformat()}


@pytest.fixture
def tr():
    from aegis.agents.orchestrator import treasury
    treasury.BOOK.reset()
    yield treasury
    treasury.BOOK.reset()


def _route(tr, a):
    return tr.treasury_outflow_chain(a) if tr.is_treasury_outflow(a) else None


def test_payout_run_raises_one_chain_not_one_per_transfer(tr, monkeypatch):
    monkeypatch.setattr(tr, "is_treasury_sender", lambda a: True)
    fired = sum(_route(tr, _tx(i, 50_000)) is not None for i in range(400))
    assert fired == 1


def test_a_long_payout_run_cannot_evict_a_drain(tr, monkeypatch):
    monkeypatch.setattr(tr, "is_treasury_sender", lambda a: True)
    _route(tr, _tx(0, 2e7, 0))
    _route(tr, _tx(1, 2e7, 60))
    for i in range(2, 1100):
        _route(tr, _tx(i, 40_000, 120))
    last = _route(tr, _tx(9999, 2e7, 180))
    assert last.metadata["treasury"]["burst"] is True
    assert any(a.action_type == "hold" and not a.requires_hitl for a in last.recommended_actions)


def test_ledger_dedupes_and_expires(tr):
    book = tr._OutflowBook()
    assert book.add("S", 1000.0, 1e7, "a", 600) == (1, 1e7)
    assert book.add("S", 1001.0, 1e7, "a", 600) == (1, 1e7)            # the same transfer twice
    assert book.add("S", 1002.0, 5e5, "b", 600) == (2, 1.05e7)
    assert book.add("S", 2000.0, 5e5, "c", 600) == (1, 5e5)             # the first two left the window


# ---- Y5-8: a no-op retrain run never deletes the shared model pointer -------------------------------------------------------

def test_retrain_save_keeps_an_installed_release(tmp_path):
    from aegis.finetune.retrain import State
    ptr = tmp_path / "retrain" / "current.json"
    ptr.parent.mkdir(parents=True)
    ptr.write_text(json.dumps({"run": "bd-2026.11.1", "adapter": "/m", "sha256": "ab", "approved_by": "bluedefence-release"}))
    st = State.load(tmp_path)
    st.log("r-1", "skipped", reason="too few rows")
    st.save()
    assert ptr.exists()


def test_retrain_rollback_to_base_still_removes_its_own_pointer(tmp_path):
    from aegis.finetune.retrain import State
    ptr = tmp_path / "retrain" / "current.json"
    ptr.parent.mkdir(parents=True)
    st = State.load(tmp_path)
    st.runs["r-7"] = {"stage": "promoted"}
    st.current = {"run": "r-7", "adapter": "/a", "sha256": "cd"}
    st.pending.append((dict(st.current), []))                          # what _promote queues (round 8 T8-2)
    st.save()
    assert ptr.exists()
    st.current = None                                                  # what `retrain rollback` does with no previous
    st.pending.append((None, ["r-7"]))
    st.save()
    assert not ptr.exists()


# ---- Y5-9: own-account padding cannot hide an object walk -----------------------------------------------------------------

class _Own:
    name = "test"

    def owners_of(self, t, oid):
        return frozenset({"mallory"}) if oid == "5000" else frozenset({f"cust{oid}"})


@pytest.mark.parametrize("padding", [20, 210, 600])
def test_padded_walk_still_alerts(padding):
    from aegis.agents.api_abuse.object_walk import ObjectWalkDetector
    d = ObjectWalkDetector(_Own(), window_s=600)
    ts, fired = 1000.0, None
    for k in range(6):
        for _ in range(padding):
            ts += 0.05
            d.observe({"principal": "mallory", "path": "/api/v1/accounts/5000", "status": 200, "ts": ts})
        ts += 0.05
        fired = fired or d.observe({"principal": "mallory", "path": f"/api/v1/accounts/{7001 + k}", "status": 200, "ts": ts})
    assert fired and fired["object_walk"]["level"] == "confirmed"


def test_own_account_reads_alone_never_alert():
    from aegis.agents.api_abuse.object_walk import ObjectWalkDetector
    d = ObjectWalkDetector(_Own(), window_s=600)
    assert not any(d.observe({"principal": "mallory", "path": "/api/v1/accounts/5000", "status": 200, "ts": 1000 + i})
                   for i in range(500))


# ---- Y5-11: SSRF short / decimal forms, without clock times or amounts ----------------------------------------------------

@pytest.mark.parametrize("payload", ["fetch?u=127.1:6379/", "fetch?u=2130706433:80/", "fetch?u=0177.1:8080/",
                                     "fetch?u=10.1:9200/_cat", "fetch?u=192.168.1.5:8080/"])
def test_short_and_decimal_internal_addresses_are_ssrf(payload):
    from aegis.agents.perimeter.tools import ssrf_probe
    assert ssrf_probe(payload).weight == "high"


@pytest.mark.parametrize("payload", ['{"txn_time":"2026-11-03T10:30:00+05:30","amount":5000}', "meeting at 10:30, cutoff 16:00",
                                     "score 1500:30", "amount 25000:00", "2026:11", "Rs 10.50:00", "ts 10.30:00 ok",
                                     "id 1234:5678"])
def test_times_amounts_and_years_stay_clean(payload):
    from aegis.agents.perimeter.tools import ssrf_probe
    assert ssrf_probe(payload).weight == "low"
