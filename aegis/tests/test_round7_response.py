"""Review round 7 — response / HITL findings A-1 … A-8 (each test is the reviewer's repro, inverted)."""

from __future__ import annotations

import io
import tempfile
from pathlib import Path
from typing import ClassVar

import pytest

from aegis.agents.response.agent import ResponseAgent
from aegis.agents.response.autonomy import AutonomyPolicy
from aegis.agents.response.breaker import OutflowBreaker
from aegis.agents.response.connectors.base import (
    Connector,
    ConnectorError,
    ConnectorRegistry,
    LoggingConnector,
)
from aegis.agents.response.connectors.edr import CrowdStrikeConnector
from aegis.agents.response.connectors.http import HttpResult
from aegis.agents.response.hitl_timeout import HitlTimeoutPolicy
from aegis.agents.shared.evidence_chain import EvidenceChain, RecommendedAction


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for k in ("AEGIS_NEVER_BLOCK_HOSTS", "AEGIS_PROTECTED_TARGETS", "AEGIS_HITL_STATE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AEGIS_HITL_STATE", "off")
    monkeypatch.setenv("ACP_HOME", tempfile.mkdtemp())


def _agent(connectors, **kw):
    return ResponseAgent(connectors=connectors, hitl_stream=io.StringIO(), autonomy=AutonomyPolicy(mode="off"),
                         breaker=kw.pop("breaker", OutflowBreaker(mode="off")), hitl_timeout=HitlTimeoutPolicy(mode="off"),
                         **kw)


def _act(t, target, hitl=True):
    return RecommendedAction(action_type=t, target=target, reasoning="r", requires_hitl=hitl, confidence=0.9)


def _falcon(resources=None):
    calls = []

    def t(method, url, body, headers, timeout):
        calls.append((method, url, body))
        if "queries/devices" in url:
            return HttpResult(200, {"resources": resources if resources is not None else ["b" * 32]})
        return HttpResult(200, {"batch_id": "B1", "resources": [{"id": "b" * 32, "status": "contained"}]})
    return t, calls


# ------------------------------------------------------------------------------------------------- A-1 --

def test_a1_kill_process_on_a_protected_host_needs_two_people(monkeypatch):
    monkeypatch.setenv("AEGIS_ENFORCEMENT_MODE", "live")
    t, calls = _falcon()
    ra = _agent(ConnectorRegistry([CrowdStrikeConnector(base_url="https://falcon.mock", token_provider=lambda: "t",
                                                        transport=t)]), protected_targets=["db-core", "prod-*"])
    for tgt in ("db-core:4242", "host:db-core:4242", "b" * 32 + ":4242", "prod-web-3:77"):
        a = _act("kill_process", tgt)
        assert ra.two_person_required(a), tgt
        r = ra.approve(a, approver="analyst:alice", source_alert_id="A1")
        assert r.status == "queued_for_hitl" and r.reason == "needs_second_approver", tgt
    assert not any(b and b.get("base_command") == "kill" for _, _, b in calls)
    assert not ra.two_person_required(_act("kill_process", "ws-17:4242"))
    assert not ra.two_person_required(_act("block", "2001:db8::1"))           # an IPv6 tail is not a pid


# ------------------------------------------------------------------------------------------------- A-2 --

class _Heal:
    def __init__(self):
        self.calls = []

    def snapshot_and_sever(self, target, source_alert=None):
        self.calls.append(("sever", target))

    def handle_compromise(self, target, source_alert=None):
        self.calls.append(("heal", target))


def test_a2_live_isolate_without_a_vendor_is_never_executed(monkeypatch):
    monkeypatch.setenv("AEGIS_ENFORCEMENT_MODE", "live")
    heal = _Heal()
    ra = _agent(ConnectorRegistry([]), self_healing=heal)
    for t in ("isolate", "trigger_self_heal"):
        r = ra.approve(_act(t, "host:app-ledger-07"), approver="ciso:asha", source_alert_id="A1")
        assert r.status == "queued_for_hitl" and r.receipt is not None and "no vendor connector" in r.note
    assert heal.calls == []                                                     # the simulation never runs live


def test_a2_shadow_isolate_is_a_labelled_dry_run(monkeypatch):
    monkeypatch.setenv("AEGIS_ENFORCEMENT_MODE", "shadow")
    heal = _Heal()
    ra = _agent(ConnectorRegistry([]), self_healing=heal)
    r = ra.approve(_act("isolate", "host:app-ledger-07"), approver="ciso:asha", source_alert_id="A1")
    assert r.status == "executed" and r.receipt is not None and r.receipt.dry_run
    assert "simulated" in r.note and "no vendor" in r.note and heal.calls == [("sever", "host:app-ledger-07")]


# ------------------------------------------------------------------------------------------------- A-3 --

class _FlakyWaf(Connector):
    name = "flaky"
    actions = frozenset({"block"})

    def __init__(self, fail, **kw):
        super().__init__(**kw)
        self.fail, self.rules = fail, set()

    def _do_apply(self, a, key, ttl):
        self.rules.add(a.target)
        return "r1", "added", "r1"

    def _do_rollback(self, r):
        if self.fail:
            raise ConnectorError("HTTP 503 on DELETE")
        self.rules.discard(r.target)
        return "deleted"


def test_a3_a_failed_rollback_is_retried_after_a_restart(monkeypatch):
    monkeypatch.setenv("AEGIS_ENFORCEMENT_MODE", "live")
    from aegis.agents.response.receipts import ReceiptLog
    now = [1000.0]
    log = ReceiptLog(Path(tempfile.mkdtemp()) / "_receipts.jsonl")
    vendor = _FlakyWaf(fail=True, clock=lambda: now[0])
    reg = ConnectorRegistry([vendor], on_receipt=[log])
    reg.apply(_act("block", "203.0.113.9", hitl=False), alert_id="A1", approver="aegis:auto", ttl_sec=900)
    now[0] += 1000
    assert [r.status for r in reg.sweep_expired()] == ["rollback_failed"]
    vendor2 = _FlakyWaf(fail=False, clock=lambda: now[0] + 10_000)
    vendor2.rules = vendor.rules
    reg2 = ConnectorRegistry([vendor2])
    assert reg2.restore(ReceiptLog.read(log.path)) == 1
    assert [r.status for r in reg2.sweep_expired()] == ["expired"] and vendor2.rules == set()


# ------------------------------------------------------------------------------------------------- A-4 --

def test_a4_a_rejection_after_a_failed_approval_survives_a_restart(monkeypatch):
    monkeypatch.setenv("AEGIS_CONSOLE_TOKEN", "tok")
    monkeypatch.setenv("AEGIS_ENFORCEMENT_MODE", "live")
    from aegis.hitl.filequeue import FileHITL
    from aegis.ingest.console_api import ConsoleAPI

    class Waf(Connector):
        name = "waf"
        actions = frozenset({"block"})
        down = True
        calls: ClassVar[list] = []

        def _do_apply(self, a, key, ttl):
            Waf.calls.append(a.target)
            if Waf.down:
                raise ConnectorError("HTTP 503")
            return "r", "blocked", "r"

        def _do_rollback(self, r):
            return "x"
    d = Path(tempfile.mkdtemp())
    h = FileHITL(d, state_path=d / "pending.jsonl")
    ra = _agent(ConnectorRegistry([Waf()]), hitl=h)
    c = EvidenceChain(alert_id="A1", investigated_by="perimeter", verdict="malicious", confidence=0.9)
    c.recommended_actions.append(_act("block", "203.0.113.9"))
    ra.execute(c)
    aid = h.pending[0].approval_id
    api = ConsoleAPI(None, d)
    assert api.decide(aid, "approved", decided_by="analyst:alice")[0] == 200
    assert ra.sync_hitl() == [] and h.pending[0].approved_by == "analyst:alice"     # vendor 503 -> retry
    assert api.decide(aid, "rejected", decided_by="ciso:bob", reason="false positive")[0] == 200
    Waf.down = False
    h2 = FileHITL(d, state_path=d / "pending.jsonl")
    out = _agent(ConnectorRegistry([Waf()]), hitl=h2).sync_hitl()
    assert [(x.status, x.decided_by) for x in out] == [("rejected", "ciso:bob")]
    assert Waf.calls == ["203.0.113.9"]                                           # never executed after the restart


# ------------------------------------------------------------------------------------------------- A-5 --

@pytest.mark.parametrize("tgt", ["host:*db-core*", "host:x',hostname:'db-core", "host:a b", "host:db,core"])
def test_a5_falcon_refuses_fql_metacharacters(monkeypatch, tgt):
    monkeypatch.setenv("AEGIS_ENFORCEMENT_MODE", "live")
    t, calls = _falcon()
    cs = CrowdStrikeConnector(base_url="https://falcon.mock", token_provider=lambda: "t", transport=t)
    assert not cs.supports_target(tgt)
    r = cs.apply(_act("isolate", tgt))
    assert r.status != "applied" and not any("action_name=contain" in u for _, u, _ in calls)


def test_a5_falcon_encodes_the_filter_and_refuses_ambiguity(monkeypatch):
    monkeypatch.setenv("AEGIS_ENFORCEMENT_MODE", "live")
    t, calls = _falcon(["a" * 32, "c" * 32])
    cs = CrowdStrikeConnector(base_url="https://falcon.mock", token_provider=lambda: "t", transport=t)
    r = cs.apply(_act("isolate", "host:db-core"))
    assert r.status == "failed" and "2 CrowdStrike devices" in (r.error or "")
    assert "filter=hostname%3A%27db-core%27" in calls[0][1]
    assert cs.supports_target("host:db-core") and cs.supports_target("b" * 32) and cs.supports_target("db-core:4242")


# ------------------------------------------------------------------------------------------------- A-6 --

def test_a6_servicenow_second_approval_needs_an_explicit_decision():
    from aegis.hitl.servicenow import ServiceNowHITL
    rec = {"sys_id": "INC1", "state": "1", "close_code": "", "u_aegis_decision": "", "u_aegis_decided_by": "",
           "resolved_by": "", "closed_by": "", "sys_updated_by": "aegis_svc", "sys_created_by": "aegis_svc"}

    def snow(method, url, body, headers, timeout):
        if method == "POST":
            return 201, {"result": dict(rec)}
        if method == "PATCH":
            rec.update(body)
            rec["sys_updated_by"] = "aegis_svc"
            return 200, {"result": dict(rec)}
        return 200, {"result": dict(rec)}
    h = ServiceNowHITL(url="https://bank.service-now.com", user="aegis_svc", password="p", transport=snow)
    ra = _agent(ConnectorRegistry([], fallback=LoggingConnector(dry_run=False)), hitl=h,
                protected_targets=["198.51.100.0/24"])
    c = EvidenceChain(alert_id="A1", investigated_by="perimeter", verdict="malicious", confidence=0.9)
    c.recommended_actions.append(_act("block", "198.51.100.7"))
    ra.execute(c)
    rec.update(state="6", close_code="approved", resolved_by="alice", sys_updated_by="alice")
    assert ra.sync_hitl() == [] and h.pending[0].first_approver == "alice"
    assert rec["state"] == "2" and rec["close_code"] == ""                     # re-opened by the awaiting-second PATCH
    rec.update(u_aegis_decided_by="bob", sys_updated_by="bob")                  # bob only names himself
    assert ra.sync_hitl() == []
    rec.update(u_aegis_decision="approved", u_aegis_decided_by="bob", sys_updated_by="bob")
    assert [(d.status, d.decided_by) for d in ra.sync_hitl()] == [("approved", "alice+bob")]


# ------------------------------------------------------------------------------------------------- A-7 --

def test_a7_a_live_breaker_hold_files_a_keep_or_release_card(monkeypatch):
    monkeypatch.setenv("AEGIS_ENFORCEMENT_MODE", "live")
    from aegis.hitl.filequeue import FileHITL
    class PayHub(Connector):
        name = "payhub"
        actions = frozenset({"hold"})
        held: ClassVar[set] = set()

        def _do_apply(self, a, key, ttl):
            PayHub.held.add(a.target)
            return "H1", "held", "H1"

        def _do_rollback(self, r):
            PayHub.held.discard(r.target)
            return "released"
    d = Path(tempfile.mkdtemp())
    h = FileHITL(d)
    reg = ConnectorRegistry([PayHub()])
    ra = _agent(reg, hitl=h, breaker=OutflowBreaker(mode="live"))
    c = EvidenceChain(alert_id="TXN1", investigated_by="treasury", verdict="malicious", confidence=0.95)
    c.metadata["outflow_breaker"] = True
    c.recommended_actions.append(_act("hold", "outbound:ACC-TREASURY-01", hitl=False))
    s = ra.execute(c, {"sender_account": "ACC-TREASURY-01"})
    assert [e.action.action_type for e in s.executed] == ["hold"]
    assert [p.action.action_type for p in h.pending] == ["hold"] and "RELEASE" in h.pending[0].action.reasoning
    # a rejection releases the breaker's hold
    monkeypatch.setenv("AEGIS_CONSOLE_TOKEN", "tok")
    from aegis.ingest.console_api import ConsoleAPI
    assert ConsoleAPI(None, d).decide(h.pending[0].approval_id, "rejected", decided_by="fraud:ravi",
                                      reason="customer confirmed")[0] == 200
    out = ra.sync_hitl()
    assert [x.status for x in out] == ["rejected"]
    assert not [r for r in reg.active_receipts if r.action_type == "hold"] and PayHub.held == set()


# ------------------------------------------------------------------------------------------------- A-8 --

def test_a8_an_anonymous_decision_is_refused_and_never_a_second_person(monkeypatch):
    from aegis.hitl.base import _anonymous
    from aegis.hitl.filequeue import FileHITL
    from aegis.ingest.console_api import ConsoleAPI
    d = Path(tempfile.mkdtemp())
    h = FileHITL(d)
    ra = _agent(ConnectorRegistry([], fallback=LoggingConnector(dry_run=False)), hitl=h,
                protected_targets=["198.51.100.0/24"])
    c = EvidenceChain(alert_id="A1", investigated_by="perimeter", verdict="malicious", confidence=0.9)
    c.recommended_actions.append(_act("block", "198.51.100.7"))
    ra.execute(c)
    aid = h.pending[0].approval_id
    api = ConsoleAPI(None, d)
    assert api.decide(aid, "approved", decided_by="analyst:alice")[0] == 200
    ra.sync_hitl()
    code, out = api.decide(aid, "approved", decided_by="")
    assert code == 400 and "identity" in out["error"]
    assert ra.sync_hitl() == [] and h.pending                                   # still waiting for a named second
    for name in ("", "console", "file", "Dashboard", None):
        assert _anonymous(name)
    assert not _anonymous("analyst:bob")
