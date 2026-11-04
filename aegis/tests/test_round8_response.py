"""Review round 8 — response / HITL findings A8-1 … A8-6 (each test is the reviewer's repro, inverted)."""

from __future__ import annotations

import io
import tempfile
from pathlib import Path

import pytest

from aegis.agents.response.agent import ResponseAgent
from aegis.agents.response.autonomy import AutonomyPolicy
from aegis.agents.response.breaker import OutflowBreaker
from aegis.agents.response.connectors.base import (
    Connector,
    ConnectorRegistry,
    LoggingConnector,
)
from aegis.agents.response.connectors.http import HttpResult
from aegis.agents.response.hitl_timeout import HitlTimeoutPolicy
from aegis.agents.shared.evidence_chain import EvidenceChain, RecommendedAction


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for k in ("AEGIS_NEVER_BLOCK_HOSTS", "AEGIS_NEVER_BLOCK", "AEGIS_PROTECTED_TARGETS", "AEGIS_CONSOLE_TOKEN",
              "AEGIS_DECISION_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AEGIS_HITL_STATE", "off")
    monkeypatch.setenv("ACP_HOME", tempfile.mkdtemp())
    monkeypatch.setenv("AEGIS_VERIFY_RETRY_S", "0")


def _agent(connectors, **kw):
    return ResponseAgent(connectors=connectors, hitl_stream=io.StringIO(), autonomy=AutonomyPolicy(mode="off"),
                         breaker=kw.pop("breaker", OutflowBreaker(mode="off")), hitl_timeout=HitlTimeoutPolicy(mode="off"),
                         **kw)


def _act(t, target, hitl=True, conf=0.9, why="r"):
    return RecommendedAction(action_type=t, target=target, reasoning=why, requires_hitl=hitl, confidence=conf)


def _chain(alert_id, by="perimeter", verdict="malicious", conf=0.9):
    return EvidenceChain(alert_id=alert_id, investigated_by=by, verdict=verdict, confidence=conf)


# ------------------------------------------------------------------------------------------------ A8-1 --

class _PayHub(Connector):
    name = "payhub"
    actions = frozenset({"hold"})
    reapply_on_human_approval = True

    def __init__(self, **kw):
        super().__init__(**kw)
        self.held = set()

    def _do_apply(self, a, key, ttl):
        self.held.add(a.target)
        return "H1", "held", "H1"

    def _do_rollback(self, r):
        self.held.discard(r.target)
        return "released"


def _breaker_setup(monkeypatch):
    from aegis.hitl.filequeue import FileHITL
    from aegis.ingest.console_api import ConsoleAPI
    monkeypatch.setenv("AEGIS_ENFORCEMENT_MODE", "live")
    monkeypatch.setenv("AEGIS_CONSOLE_TOKEN", "tok")
    d = Path(tempfile.mkdtemp())
    h = FileHITL(d)
    hub = _PayHub()
    reg = ConnectorRegistry([hub])
    ra = _agent(reg, hitl=h, breaker=OutflowBreaker(mode="live"))
    c1 = _chain("TXN1", by="treasury", conf=0.95)
    c1.metadata["outflow_breaker"] = True
    c1.recommended_actions.append(_act("hold", "outbound:ACC-9", hitl=False))
    ra.execute(c1, {"sender_account": "ACC-9"})
    assert "outbound:ACC-9" in hub.held
    return h, hub, reg, ra, ConsoleAPI(None, d)


def test_a8_1_rejecting_an_unrelated_hold_card_keeps_the_breaker_hold(monkeypatch):
    h, hub, _reg, ra, api = _breaker_setup(monkeypatch)
    c2 = _chain("TXN2", by="treasury", verdict="suspicious", conf=0.6)
    c2.recommended_actions.append(_act("hold", "outbound:ACC-9", why="one odd transfer; analyst to decide"))
    ra.execute(c2)
    cards = {p.alert_id: p.approval_id for p in h.pending}
    api.decide(cards["TXN2"], "rejected", decided_by="fraud:ravi", reason="this one transfer is fine")
    ra.sync_hitl()
    assert "outbound:ACC-9" in hub.held
    assert any(p.alert_id == "TXN1" for p in h.pending)            # the breaker's own card still decides
    # ... and rejecting the breaker's OWN card still releases it
    api.decide(cards["TXN1"], "rejected", decided_by="ops:vik", reason="breaker false positive")
    ra.sync_hitl()
    assert "outbound:ACC-9" not in hub.held


def test_a8_1_a_human_approved_hold_survives_rejection_of_the_breaker_card(monkeypatch):
    h, hub, reg, ra, api = _breaker_setup(monkeypatch)
    c3 = _chain("TXN3", by="treasury", verdict="malicious", conf=0.8)
    c3.recommended_actions.append(_act("hold", "outbound:ACC-9", why="signer compromise confirmed by call-back"))
    ra.execute(c3)
    cards = {p.alert_id: p.approval_id for p in h.pending}
    api.decide(cards["TXN3"], "approved", decided_by="fraud:asha", reason="keep it")
    ra.sync_hitl()
    rc = [x for x in reg.active_receipts if x.action_type == "hold"]
    assert rc and "fraud:asha" in rc[0].approver and rc[0].expires_at is None   # asha's identity is on the hold
    api.decide(cards["TXN1"], "rejected", decided_by="ops:vik", reason="breaker false positive")
    ra.sync_hitl()
    assert "outbound:ACC-9" in hub.held
    assert any(x.action_type == "hold" and x.active for x in reg.active_receipts)


# ------------------------------------------------------------------------------------------------ A8-2 --

@pytest.mark.parametrize("name", ["System", "system", " Local User ", "local_user", "anonymous", "Anonymous", "unknown",
                                  "n/a", "N/A", "none", "null", "-", "", None, "guest", "dashboard:System",
                                  "aegis:hitl-timeout", "<script>", "a"])
def test_a8_2_placeholder_deciders_are_anonymous(name):
    from aegis.hitl.base import _anonymous
    assert _anonymous(name)


@pytest.mark.parametrize("name", ["analyst:alice", "analyst.alice@bank.in", "alice", "fraud:asha", "BANK\\jdoe",
                                  "Alice Smith", "E123456", "o'brien"])
def test_a8_2_real_identities_are_not_anonymous(name):
    from aegis.hitl.base import _anonymous
    assert not _anonymous(name)


@pytest.mark.parametrize("placeholder", ["System", "Local User", "anonymous"])
def test_a8_2_dashboard_placeholder_is_never_the_second_approver(monkeypatch, placeholder):
    from aegis.hitl.dashboard import DashboardHITL
    monkeypatch.setenv("AEGIS_ENFORCEMENT_MODE", "shadow")
    state = {"status": "pending", "decided_by": ""}

    def dash(method, url, body, headers, timeout):
        if url.endswith("/api/approvals/create"):
            return {"approval_id": body["id"]}
        if url.endswith("/status"):
            return dict(state)
        return {}

    h = DashboardHITL(dashboard_url="https://dash.mock", api_key="k", transport=dash)
    ra = _agent(ConnectorRegistry([], fallback=LoggingConnector(dry_run=False)), hitl=h,
                protected_targets=["198.51.100.0/24"])
    c = _chain("A1")
    c.recommended_actions.append(_act("block", "198.51.100.7"))
    ra.execute(c)
    state.update(status="approved", decided_by="analyst.alice@bank.in")
    assert ra.sync_hitl() == []
    state.update(status="approved", decided_by=placeholder)
    assert ra.sync_hitl() == [] and h.pending
    state.update(status="approved", decided_by="analyst.bob@bank.in")
    out = ra.sync_hitl()
    assert [d.status for d in out] == ["approved"] and out[0].decided_by == "analyst.alice@bank.in+analyst.bob@bank.in"


# ------------------------------------------------------------------------------------------------ A8-3 --

def test_a8_3_upn_spellings_of_a_protected_account_need_two_people(monkeypatch):
    from aegis.agents.response.connectors.identity import CyberArkConnector
    monkeypatch.setenv("AEGIS_ENFORCEMENT_MODE", "live")
    calls = []

    def ark(method, url, body, headers, timeout):
        calls.append((method, url))
        if "/Accounts?" in url:
            return HttpResult(200, {"value": [{"id": "77_1", "userName": "svc-core", "address": "cbs.bank.in"}],
                                    "count": 1})
        return HttpResult(200, {})

    cy = CyberArkConnector(base_url="https://pvwa.mock", session=lambda: "tok", transport=ark)
    ra = _agent(ConnectorRegistry([cy]), protected_targets=["svc-core", "svc-core@*"])
    for tgt in ("account:svc-core", "user:svc-core", "upn:svc-core", "UPN:svc-core@cbs.bank.in",
                "User:SVC-CORE", "principal:BANK\\svc-core", "upn:svc-core@cbs.bank.in."):
        a = _act("rotate_credential", tgt)
        calls.clear()
        assert ra.two_person_required(a), tgt
        r = ra.approve(a, approver="analyst:alice", source_alert_id="A1")
        assert r.reason == "needs_second_approver", tgt
        assert not any(u.endswith("/Change") for _, u in calls), tgt
    assert not ra.two_person_required(_act("rotate_credential", "upn:svc-other@cbs.bank.in"))


def test_a8_3_fqdn_spellings_of_a_protected_host_need_two_people(monkeypatch):
    from aegis.agents.response.connectors.edr import DefenderConnector
    monkeypatch.setenv("AEGIS_ENFORCEMENT_MODE", "live")
    calls = []

    def mde(method, url, body, headers, timeout):
        calls.append((method, url))
        if "/api/machines?" in url:
            return HttpResult(200, {"value": [{"id": "a" * 40, "computerDnsName": "db-core.bank.local"}]})
        if "/api/machineactions" in url:
            return HttpResult(200, {"value": []})
        return HttpResult(201, {"id": "act1"})

    df = DefenderConnector(base_url="https://mde.mock", token_provider=lambda: "t", transport=mde)
    ra = _agent(ConnectorRegistry([df]), protected_targets=["db-core"])
    for tgt in ("host:db-core", "host:db-core.bank.local", "db-core.bank.local.", "HOST:DB-CORE.bank.local",
                "fqdn:db-core.bank.local", "hostname:db-core"):
        calls.clear()
        r = ra.approve(_act("isolate", tgt), approver="analyst:alice", source_alert_id="A1")
        assert r.reason == "needs_second_approver", tgt
        assert not any(u.endswith("/isolate") for _, u in calls), tgt
    assert not ra.two_person_required(_act("isolate", "host:ws-17.bank.local"))
    # a protected FQDN pattern still matches exactly, not by first label
    ra2 = _agent(ConnectorRegistry([df]), protected_targets=["db-core.bank.local"])
    assert ra2.two_person_required(_act("isolate", "host:DB-CORE.bank.local."))
    assert not ra2.two_person_required(_act("isolate", "host:db-core.other.local"))


def test_a8_3_never_block_host_covers_its_fqdn_and_new_prefixes(monkeypatch):
    from aegis.agents.shared.netguard import enforcement_refused, strip_prefixes
    monkeypatch.setenv("AEGIS_NEVER_BLOCK_HOSTS", "soc-ingest")
    for tgt in ("host:soc-ingest", "host:soc-ingest.bank.local", "soc-ingest.bank.local.", "FQDN:soc-ingest.bank.local"):
        assert enforcement_refused("isolate", tgt)[0], tgt
    assert not enforcement_refused("isolate", "host:soc-ingestor.bank.local")[0]
    assert strip_prefixes("UPN:user:svc-core") == "svc-core"


# ------------------------------------------------------------------------------------------------ A8-4 --

def _snow_case(monkeypatch, refuse):
    """refuse: 'reopen' (the state change is refused, the decision clear is not) or 'all' (every PATCH refused)."""
    from aegis.hitl.servicenow import ServiceNowHITL
    monkeypatch.setenv("AEGIS_ENFORCEMENT_MODE", "shadow")
    rec = {"sys_id": "INC1", "state": "1", "close_code": "", "u_aegis_decision": "", "u_aegis_decided_by": "",
           "resolved_by": "", "closed_by": "", "sys_updated_by": "aegis_svc", "sys_created_by": "aegis_svc"}
    ctl = {"refuse": refuse}

    def snow(method, url, body, headers, timeout):
        if method == "POST":
            return 201, {"result": dict(rec)}
        if method == "PATCH":
            if ctl["refuse"] == "all" and "u_aegis_decision" in body:
                return 403, {"error": {"message": "ACL"}}
            if "state" in body and rec["state"] in ("6", "7"):
                return 403, {"error": {"message": "Data policy: resolved incidents cannot be reopened"}}
            rec.update(body)
            rec["sys_updated_by"] = "aegis_svc"
            return 200, {"result": dict(rec)}
        return 200, {"result": dict(rec)}

    h = ServiceNowHITL(url="https://bank.service-now.com", user="aegis_svc", password="p", transport=snow)
    ra = _agent(ConnectorRegistry([], fallback=LoggingConnector(dry_run=False)), hitl=h,
                protected_targets=["198.51.100.0/24"])
    c = _chain("A1")
    c.recommended_actions.append(_act("block", "198.51.100.7"))
    ra.execute(c)
    rec.update(u_aegis_decision="approved", u_aegis_decided_by="alice", state="6", close_code="approved",
               resolved_by="alice", sys_updated_by="alice")
    assert ra.sync_hitl() == [] and h.pending[0].first_approver == "alice"
    return h, ra, rec, ctl


def test_a8_4_refused_reopen_still_clears_the_decision(monkeypatch):
    h, ra, rec, _ = _snow_case(monkeypatch, "reopen")
    assert rec["u_aegis_decision"] == ""                       # the decision clear landed without the re-open
    rec.update(u_aegis_decided_by="bob", sys_updated_by="bob")
    assert ra.sync_hitl() == [] and h.pending
    rec.update(u_aegis_decision="approved", u_aegis_decided_by="bob", sys_updated_by="bob")
    out = ra.sync_hitl()
    assert [d.status for d in out] == ["approved"] and out[0].decided_by == "alice+bob"


def test_a8_4_failed_reset_fails_closed_until_it_succeeds(monkeypatch):
    h, ra, rec, ctl = _snow_case(monkeypatch, "all")
    assert rec["u_aegis_decision"] == "approved"               # the reset was refused: alice's approval stays
    rec.update(u_aegis_decided_by="bob", sys_updated_by="bob")  # bob only names himself
    for _ in range(3):
        assert ra.sync_hitl() == [] and h.pending               # never settled while the reset has not landed
    ctl["refuse"] = ""                                          # the instance accepts the reset again
    assert ra.sync_hitl() == [] and h.pending                   # this poll retried the reset; nothing accepted
    assert rec["u_aegis_decision"] == ""
    rec.update(u_aegis_decided_by="bob", sys_updated_by="bob")
    assert ra.sync_hitl() == [] and h.pending                   # still only a name, no decision
    rec.update(u_aegis_decision="approved", u_aegis_decided_by="bob", sys_updated_by="bob")
    out = ra.sync_hitl()
    assert [d.status for d in out] == ["approved"] and out[0].decided_by == "alice+bob"


def test_a8_4_a_rejection_is_honoured_while_the_reset_is_pending(monkeypatch):
    h, ra, rec, _ = _snow_case(monkeypatch, "all")
    rec.update(u_aegis_decision="rejected", u_aegis_decided_by="bob", sys_updated_by="bob")
    out = ra.sync_hitl()
    assert [d.status for d in out] == ["rejected"] and not h.pending


# ------------------------------------------------------------------------------------------------ A8-5 --

def test_a8_5_nonce_is_kept_for_as_long_as_its_timestamp_is_accepted():
    from aegis.agents.response.connectors.payhold import (
        NonceCache,
        sign,
        verify_signature,
    )
    key = b"k" * 32
    bank_now = 1_000_000.0
    nonce, path = "ab" * 16, "/aegis/v1/holds/H1"
    for skew in (240, 0, -240, 299):
        ts = str(int(bank_now + skew))
        sig = sign(key, "DELETE", path, ts, nonce, b"")
        nc = NonceCache()
        assert verify_signature(key, "DELETE", path, ts, nonce, b"", sig, nonces=nc, now=bank_now)
        for later in (10, 301, 539, 599):
            if abs(bank_now + later - int(ts)) <= 300:
                assert not verify_signature(key, "DELETE", path, ts, nonce, b"", sig, nonces=nc, now=bank_now + later), (skew, later)
    # with no timestamp the cache keeps a nonce 2 x window + margin
    nc = NonceCache(window_s=300)
    assert nc.fresh("n1", 0.0) and not nc.fresh("n1", 600.0) and nc.fresh("n1", 700.0)


# ------------------------------------------------------------------------------------------------ A8-6 --

@pytest.mark.parametrize("action,target", [
    ("isolate", "host:db-core"), ("trigger_self_heal", "host:db-core"), ("interface_shutdown", "core-sw1:Gi0/1"),
    ("interface_shutdown", "core-sw1.bank.local:GigabitEthernet0/0/1"), ("config_rollback", "core-sw1"),
    ("config_rollback", "device:CORE-SW1"), ("recall_message", "user:db-core"),
])
def test_a8_6_severe_actions_on_protected_targets_need_two_people(monkeypatch, action, target):
    monkeypatch.setenv("AEGIS_ENFORCEMENT_MODE", "shadow")
    ra = _agent(ConnectorRegistry([], fallback=LoggingConnector(dry_run=False)), protected_targets=["core-sw1", "db-core"])
    a = _act(action, target)
    assert ra.two_person_required(a)
    r = ra.approve(a, approver="analyst:alice", source_alert_id="N1")
    assert r.status == "queued_for_hitl" and r.reason == "needs_second_approver"
    r = ra.approve(a, approver="analyst:alice", source_alert_id="N1", second_approver="analyst:bob")
    assert r.status == "executed"


def test_a8_6_unprotected_device_interface_runs_on_one_approval(monkeypatch):
    monkeypatch.setenv("AEGIS_ENFORCEMENT_MODE", "shadow")
    ra = _agent(ConnectorRegistry([], fallback=LoggingConnector(dry_run=False)), protected_targets=["core-sw1"])
    assert not ra.two_person_required(_act("interface_shutdown", "access-sw9:Gi0/7"))
    assert ra.approve(_act("interface_shutdown", "access-sw9:Gi0/7"), approver="analyst:alice").status == "executed"


@pytest.mark.parametrize("action,target", [
    ("interface_shutdown", "core-sw1:Gi0/1"), ("config_rollback", "core-sw1"), ("trigger_self_heal", "host:core-sw1"),
])
def test_a8_6_never_block_covers_severe_actions(monkeypatch, action, target):
    from aegis.agents.shared.netguard import enforcement_refused
    monkeypatch.setenv("AEGIS_ENFORCEMENT_MODE", "shadow")
    monkeypatch.setenv("AEGIS_NEVER_BLOCK_HOSTS", "core-sw1")
    assert enforcement_refused(action, target)[0]
    ra = _agent(ConnectorRegistry([], fallback=LoggingConnector(dry_run=False)))
    r = ra.approve(_act(action, target), approver="analyst:alice", second_approver="analyst:bob")
    assert r.status == "skipped" and r.reason == "never_block"
