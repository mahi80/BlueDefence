"""Containment loop and investigation tier share chains across threads (code review 2026-11-03 B11, B12)."""

from __future__ import annotations

import threading
import time
import types

from aegis.agents.orchestrator.walkers import investigation as inv_mod
from aegis.agents.orchestrator.walkers.investigation import Investigator
from aegis.agents.orchestrator.walkers.loop import ContainmentLoop, chain_lock
from aegis.agents.orchestrator.walkers.sources import InventorySource
from aegis.agents.shared.evidence_chain import EvidenceChain

ESTATE = [{"a": "u1", "relation": "logged_on", "b": "LT-1", "b_type": "host"},
          {"a": "LT-1", "relation": "lateral_to", "b": "DC-1", "b_type": "domain_controller"}]


def _chain(aid="A1"):
    return EvidenceChain(alert_id=aid, investigated_by="t", verdict="malicious", confidence=0.9)


def test_investigation_holds_the_chain_lock(monkeypatch):
    held = []
    real = inv_mod.investigate

    def spy(alert, chain, *a, **k):
        held.append(chain_lock(chain.alert_id).locked())
        return real(alert, chain, *a, **k)
    monkeypatch.setattr(inv_mod, "investigate", spy)
    inv = Investigator(InventorySource(ESTATE), max_workers=1)
    inv.submit({"id": "A1", "user": "u1"}, _chain()).result(10)
    assert held == [True]


def test_containment_waits_for_a_running_investigation_of_the_same_alert():
    src = InventorySource(ESTATE)
    loop = ContainmentLoop(src, hops=3)
    alert, chain = {"id": "A2", "user": "u1"}, _chain("A2")
    loop.track(alert, chain)
    order = []
    lk = chain_lock("A2")
    lk.acquire()                                       # the investigation is writing the chain

    def act():
        loop.after_action("A2", "force_logout", "u1")
        order.append("containment")
    t = threading.Thread(target=act)
    t.start()
    time.sleep(0.3)
    order.append("investigation done")
    lk.release()
    t.join(10)
    assert order == ["investigation done", "containment"]


def test_containment_check_runs_off_the_calling_thread():
    src = InventorySource(ESTATE)
    loop = ContainmentLoop(src, hops=3)
    alert, chain = {"id": "A3", "user": "u1"}, _chain("A3")
    loop.track(alert, chain)
    gate = threading.Event()
    done = []
    real = loop.after_action

    def slow(*a, **k):
        gate.wait(10)
        return real(*a, **k)
    loop.after_action = slow
    d = types.SimpleNamespace(status="approved", alert_id="A3", action_type="force_logout", target="u1", executed=None)
    t0 = time.perf_counter()
    assert loop.submit_decisions([d], on_done=done.extend) == 1
    assert time.perf_counter() - t0 < 0.5 and done == []          # the caller (ingest) is not blocked
    gate.set()
    loop.drain(10)
    assert len(done) == 1 and chain.metadata["containment"]
    assert loop.submit_decisions([types.SimpleNamespace(status="rejected")]) == 0
