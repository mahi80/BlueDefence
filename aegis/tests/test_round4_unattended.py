"""Round-4 review, group H1: what can run with no human."""

from __future__ import annotations

import contextlib
import json
import types

import pytest

from aegis.agents.response.contracts import gate
from aegis.agents.response.grounding import alert_entities, grounded, narrow
from aegis.agents.shared.evidence_chain import (
    EvidenceChain,
    EvidenceItem,
    RecommendedAction,
)


def _act(t, target, hitl=False):
    return RecommendedAction(action_type=t, target=target, reasoning="r", requires_hitl=hitl, confidence=0.99)


def _chain(conf=0.99, by="perimeter", **md):
    c = EvidenceChain(alert_id="A1", investigated_by=by, verdict="malicious", confidence=conf)
    c.metadata.update(md)
    return c


# ---- I4-1: derived fast-path shapes are never accepted from a push ---------------------------------------------------

@pytest.mark.parametrize("kind,nested", [("object_walk", "object_walk"), ("tls_beacon", "egress"),
                                         ("pxe_icmp_overflow", "pxe"), ("network_fault", "netops")])
def test_pushed_derived_shapes_are_demoted(kind, nested):
    from aegis.ingest.http_push import PushServer
    from aegis.ingest.stream import StreamQueue
    srv = PushServer(token="t", bind="127.0.0.1:0", queue=StreamQueue())
    body = {"id": "x1", "alert_type": kind, nested: {"level": "confirmed", "client_ips": ["198.51.100.20"]},
            "source_ip": "203.0.113.10", "audit_attempts": 99}
    assert srv.ingest_alerts(json.dumps(body).encode())[0] == 200
    (item,) = srv.queue.drain()
    row = json.loads(item.line)
    assert row["alert_type"] != kind and nested not in row and row["claimed_alert_type"] == kind
    assert "audit_attempts" not in row
    from aegis.agents.orchestrator.bola import is_object_walk
    from aegis.agents.orchestrator.egress import is_egress_finding
    from aegis.agents.orchestrator.netops import is_network_fault
    from aegis.agents.orchestrator.pxe_firmware import is_pxe_firmware_finding
    assert not any(f(row) for f in (is_object_walk, is_egress_finding, is_network_fault, is_pxe_firmware_finding))


def test_pushed_control_plane_fact_is_demoted():
    from aegis.agents.orchestrator.control_plane import is_control_plane_fact
    from aegis.ingest.http_push import PushServer
    from aegis.ingest.stream import StreamQueue
    srv = PushServer(token="t", bind="127.0.0.1:0", queue=StreamQueue())
    srv.ingest_alerts(json.dumps({"id": "g", "governed_agent": True, "alert_type": "governance_block",
                                  "control_code": "ACP-737"}).encode())
    (item,) = srv.queue.drain()
    assert not is_control_plane_fact(json.loads(item.line))


# ---- O4-11: the orchestrator itself refuses forged campaign context ---------------------------------------------------

def test_orchestrator_strips_forged_campaign_context_outside_the_swarm():
    from aegis.agents.orchestrator.agent import SOCOrchestrator
    from aegis.agents.orchestrator.walkers.campaign import TRUSTED_CONTEXT
    o = object.__new__(SOCOrchestrator)
    seen = []
    o._route = lambda alert, sp: seen.append(alert) or EvidenceChain(alert_id="f", investigated_by="x", verdict="benign",
                                                                     confidence=0.1).finalize()
    o.record = lambda alert, chain: chain
    forged = {"id": "f1", "campaign_context": {"adaptation": {"retry_ips": ["198.51.100.10"]}}, "tls_client": {}}
    o.handle(forged)
    assert "campaign_context" not in seen[-1] and "tls_client" not in seen[-1]
    tok = TRUSTED_CONTEXT.set(forged)
    try:
        o.handle(forged)
    finally:
        TRUSTED_CONTEXT.reset(tok)
    assert "campaign_context" in seen[-1]                          # attached by the swarm in this context: kept


# ---- R4-3: a protected target is never unattended at HIGH -------------------------------------------------------------

def test_protected_target_bumped_to_high_waits_for_a_human(monkeypatch):
    monkeypatch.setenv("AEGIS_AUTONOMY_TIER", "L4")
    assert gate(_act("force_logout", "user:ceo.office"), _chain(), protected=False)[0]
    ok, why = gate(_act("force_logout", "user:ceo.office"), _chain(), protected=True)
    assert not ok and "protected" in why


# ---- X4-6: the breaker's own floor respects the tier and is never NaN ---------------------------------------------------

def test_breaker_floor_respects_tier_and_nan(monkeypatch):
    from aegis.agents.response.breaker import OutflowBreaker
    hold = _act("hold", "outbound:ACC-1")
    monkeypatch.setenv("AEGIS_AUTONOMY_TIER", "L0")
    assert not gate(hold, _chain(), own_floor=0.90)[0]
    monkeypatch.setenv("AEGIS_AUTONOMY_TIER", "L4")
    assert gate(hold, _chain(0.92), own_floor=0.90)[0]
    assert not gate(hold, _chain(0.30), own_floor=float("nan"))[0]
    assert not gate(hold, _chain(0.30), own_floor=0.0)[0]           # floor never below the moderate floor
    for raw in ("nan", "0", "-1"):
        monkeypatch.setenv("AEGIS_OUTFLOW_BREAKER_MIN_CONF", raw)
        assert OutflowBreaker.from_env().min_confidence >= 0.85


# ---- R4-8: a governance / producer hold binds the breaker ------------------------------------------------------------

def test_breaker_never_runs_a_hold_flagged_for_humans():
    from aegis.agents.response.agent import ResponseAgent
    ag = object.__new__(ResponseAgent)
    called = []
    ag._breaker = types.SimpleNamespace(check=lambda a, c: called.append(1) or (True, ""), mode="live", min_confidence=0.9)
    ag._autonomy = types.SimpleNamespace(check=lambda *a, **k: (False, ""), mode="off")
    # later branches need more wiring than this stub has; the breaker must not have been consulted
    with contextlib.suppress(Exception):
        ag._dispatch(_act("hold", "outbound:ACC-1", hitl=True), _chain(by="treasury", outflow_breaker=True))
    assert called == []


# ---- R4-4 / R4-5 / X4-7: grounding by entity kind ---------------------------------------------------------------------

def test_principal_is_not_grounded_by_user_agent_subject_or_body():
    alert = {"src_ip": "203.0.113.5", "user_agent": "priya.sharma@examplebank.in", "subject": "ceo@examplebank.in",
             "request": {"json": {"user": "cfo.office"}}, "a": {"b": {"c": {"user": "deep.user"}}}, "user": "u_1"}
    e = alert_entities(alert)
    for target in ("user:priya.sharma@examplebank.in", "ceo@examplebank.in", "cfo.office", "deep.user"):
        assert not grounded(target, e, "force_logout")[0], target
    assert grounded("user:u_1", e, "force_logout")[0]
    assert not grounded("host:u_1", e, "isolate")[0]                 # a user value does not ground a host


@pytest.mark.parametrize("p", ["admin@examplebank.in", "EXAMPLEBANK\\Administrator", "krbtgt@corp.local", "root@db01"])
def test_privileged_principal_forms_are_denied(p):
    assert not narrow("force_logout", p)[0]


def test_normaliser_keys_ground():
    e = alert_entities({"dst": "203.0.113.50", "compromised_entity": "fin-ws-07", "users": ["priya.sharma"],
                        "user": {"name": "ravi.k"}, "host": {"name": "db-02"}})
    assert grounded("203.0.113.50", e)[0]
    assert grounded("host:fin-ws-07", e, "isolate")[0]
    assert grounded("priya.sharma", e, "force_logout")[0] and grounded("ravi.k", e, "force_logout")[0]
    assert grounded("host:db-02", e, "isolate")[0]


# ---- X4-2 / O4-9: the swarm re-vote --------------------------------------------------------------------------------------

def _swarm(concur: bool):
    from aegis.agents.orchestrator.swarm import SwarmOrchestrator, WorkerResult
    s = object.__new__(SwarmOrchestrator)
    import threading
    s._lock = threading.Lock()
    s._workers = {"w": None}
    answer = json.dumps({"concur": concur, "confidence": 0.6, "reason": "r"})
    s._voter = types.SimpleNamespace(complete=lambda *a, **k: types.SimpleNamespace(text=answer))
    s._extra_voters = []
    s.runs = []
    s._orch = types.SimpleNamespace()
    s.max_workers, s.max_seconds = 1, 1.0
    return s, WorkerResult


def test_swarm_revote_does_not_overrule_a_deterministic_chain():
    s, WR = _swarm(False)
    c = _chain(0.95, by="treasury", deterministic=True, outflow_breaker=True)
    c.recommended_actions.append(_act("hold", "outbound:ACC-1"))
    s._merge(c, [WR("w", evidence=[EvidenceItem(source="w", weight="low", signal="s")])], 0.0)
    assert c.metadata.get("vote_concur") is None and c.confidence == 0.95
    assert c.recommended_actions[0].requires_hitl is False


def test_swarm_raise_keeps_a_first_pass_dissent():
    s, WR = _swarm(True)
    c = EvidenceChain(alert_id="A", investigated_by="perimeter", verdict="suspicious", confidence=0.6)
    c.metadata["vote_concur"] = False
    s._merge(c, [WR("w", evidence=[EvidenceItem(source="swarm.intel_enrich", weight="high", signal="ioc hit")])], 0.0)
    assert c.verdict == "malicious" and c.metadata["vote_concur"] is False


# ---- S4-1 / S4-2: the treasury ledger --------------------------------------------------------------------------------------

def test_three_ordinary_supplier_payments_are_not_a_drain():
    from aegis.agents.orchestrator import treasury as tr
    tr.BOOK.reset()
    chains = []
    for i in range(3):
        a = {"id": f"T{i}", "sender_account": "CA-ACME-01", "beneficiary_account": f"SUP-{i}", "new_beneficiary": True,
             "amount_inr": 3_400_000, "rail": "RTGS", "timestamp": f"2026-11-03T10:0{i}:00+05:30"}
        if tr.is_treasury_outflow(a):
            chains.append(tr.treasury_outflow_chain(a))
    assert chains and all(not c.metadata.get("outflow_breaker") for c in chains)
    assert all(a.requires_hitl for c in chains for a in c.recommended_actions)
    tr.BOOK.reset()


def test_treasury_sender_split_under_the_imps_cap_is_seen(monkeypatch):
    from aegis.agents.orchestrator import treasury as tr
    tr.BOOK.reset()
    monkeypatch.setattr(tr, "is_treasury_sender", lambda a: True)
    hits = sum(tr.is_treasury_outflow({"id": f"D{i}", "sender_account": "TREASURY-OPS", "beneficiary_account": f"M-{i}",
                                       "new_beneficiary": True, "amount_inr": 490_000, "rail": "IMPS"}) for i in range(25))
    assert hits > 0
    tr.BOOK.reset()
