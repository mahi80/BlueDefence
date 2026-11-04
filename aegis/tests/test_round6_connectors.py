"""Code review round 6 — connector findings C-1 … C-16 (reproductions from the review, now fixed)."""

from __future__ import annotations

import json
import tempfile

import pytest

from aegis.agents.response.connectors import (
    ActiveDirectoryConnector,
    CyberArkConnector,
    DefenderConnector,
    EntraConnector,
    FeedConnector,
    FortiGateConnector,
    PanosConnector,
    PaymentHoldConnector,
    SentinelOneConnector,
    TrendVisionOneConnector,
    registry_from_env,
)
from aegis.agents.response.connectors.base import STATUS_ROLLED_BACK, canonical_target
from aegis.agents.response.connectors.http import HttpResult
from aegis.agents.response.connectors.identity import _CyberArkSession
from aegis.agents.response.connectors.mock_bank import (
    MockCyberArk,
    MockDefender,
    MockDirectory,
    MockEntra,
    MockFortiGate,
    MockPanos,
    MockPaymentHub,
    MockSentinelOne,
    MockTrend,
)
from aegis.agents.response.connectors.openshell import MockOpenShell, OpenShellConnector
from aegis.agents.shared.evidence_chain import RecommendedAction
from aegis.agents.shared.netguard import never_block_target, strip_prefixes

_VARS = ("AEGIS_ENFORCEMENT_MODE", "AEGIS_IDP_PROTECTED", "AEGIS_NEVER_BLOCK", "AEGIS_NEVER_BLOCK_HOSTS",
         "AEGIS_PROTECTED_TARGETS", "AEGIS_PREFER_FIREWALL", "AEGIS_FW_VENDOR", "AEGIS_WAF_VENDOR", "AEGIS_SWG_VENDOR",
         "AEGIS_EDR_VENDOR", "AEGIS_SOAR_VENDOR", "AEGIS_IDP_VENDOR", "AEGIS_PAM_VENDOR", "AEGIS_PAYHOLD_VENDOR",
         "AEGIS_BLOCK_FEED", "AEGIS_AGENT_SANDBOX")


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for k in _VARS:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ACP_HOME", tempfile.mkdtemp())


def _act(t, target, approver_hint=None):
    return RecommendedAction(action_type=t, target=target, reasoning="r", requires_hitl=True, confidence=0.95)


# C-1 — one-shot actions run at the vendor every time ------------------------------------------------------------------

def test_c1_revoke_and_rotate_run_again_on_every_apply():
    m = MockEntra()
    e = EntraConnector(base_url="https://graph.mock/v1.0", token_provider=lambda: "mock-graph-token", transport=m,
                       dry_run=False)
    r1 = e.apply(_act("revoke_sessions", "user:priya.sharma@bank.in"))
    r2 = e.apply(_act("revoke_sessions", "user:priya.sharma@bank.in"), approver="ciso")
    assert r1.status == r2.status == "applied" and m.revoked == ["priya.sharma@bank.in"] * 2
    assert e.active_receipts == []                       # nothing "in force" for a sweep or read-back to judge
    ca = MockCyberArk()
    c = CyberArkConnector(base_url="https://pvwa.mock", transport=ca, dry_run=False,
                          session=_CyberArkSession("https://pvwa.mock", "aegis", "mock", ca))
    c.apply(_act("rotate_credential", "account:svc_loan"))
    first = ca.changed["12_3"]
    c.apply(_act("rotate_credential", "account:svc_loan"))
    assert sum(1 for m_, u, _ in ca.calls if m_ == "POST" and u.endswith("/Change")) == 2 and ca.changed["12_3"] >= first


def test_c1_restore_never_readopts_a_one_shot_receipt():
    reg = registry_from_env()
    e = EntraConnector(base_url="https://graph.mock/v1.0", token_provider=lambda: "t", transport=MockEntra(), dry_run=False)
    reg._connectors.insert(0, e)
    n = reg.restore([{"connector": "entra", "action_type": "revoke_sessions", "idempotency_key": "k1", "status": "applied",
                      "receipt_id": "r1", "target": "user:a@b.in", "dry_run": False, "applied_at": 1.0, "expires_at": None}])
    assert n == 0 and e.active_receipts == []


# C-2 — LDAPS verifies the DC certificate ------------------------------------------------------------------------------

def test_c2_ldaps_requires_a_verified_certificate(monkeypatch):
    import ssl
    import sys
    import types
    seen = {}
    fake = types.ModuleType("ldap3")
    fake.Tls = lambda **kw: seen.setdefault("tls", kw) or kw
    fake.Server = lambda url, **kw: seen.setdefault("server", kw)
    fake.Connection = lambda server, **kw: types.SimpleNamespace(unbind=lambda: None)
    monkeypatch.setitem(sys.modules, "ldap3", fake)
    monkeypatch.setenv("AEGIS_AD_CA", "/etc/bank/ca.pem")
    from aegis.agents.response.connectors.identity import Directory
    Directory("ldaps://dc1.bank.local", "cn=x", "p")._conn()
    assert seen["tls"]["validate"] == ssl.CERT_REQUIRED and seen["tls"]["ca_certs_file"] == "/etc/bank/ca.pem"
    assert seen["server"]["tls"] is not None and seen["server"]["use_ssl"] is True


# C-3 / C-4 / C-13 / C-14 — payment hold -------------------------------------------------------------------------------

def _hub():
    hub = MockPaymentHub()
    return hub, PaymentHoldConnector(base_url="https://payhub.mock/aegis/v1", token=hub.token,
                                     signing_key=hub.key.decode(), transport=hub, dry_run=False)


def test_c3_a_captured_signature_cannot_be_replayed_or_repointed():
    hub, c = _hub()
    r1 = c.apply(_act("hold", "outbound:ACC-1"))
    r2 = c.apply(_act("hold", "outbound:ACC-2"))
    captured = {}

    def spy(method, url, body, headers, timeout):
        captured.update(headers)
        return hub(method, url, body, headers, timeout)
    c._transport = spy
    c.verify(r1)                                           # a GET for hold 1
    replay = hub("DELETE", f"https://payhub.mock/aegis/v1/holds/{r2.vendor_ref}", None, dict(captured), 5)
    assert replay.status == 401 and hub.holds[r2.vendor_ref]["state"] == "active"
    again = hub("GET", f"https://payhub.mock/aegis/v1/holds/{r1.vendor_ref}", None, dict(captured), 5)
    assert again.status == 401                              # the same nonce twice


def test_c4_renew_follows_a_replaced_hold_and_undo_releases_the_live_one():
    hub, c = _hub()
    r = c.apply(_act("hold", "outbound:ACC-9"), ttl_sec=3600)
    hub.holds[r.vendor_ref]["state"] = "released"            # someone released it at the bank
    c.renew(r, 3600)
    live = [h for h, v in hub.holds.items() if v["state"] == "active"]
    assert live == [r.vendor_ref] == [r.rollback_token]
    assert c.rollback(r).status == STATUS_ROLLED_BACK and all(v["state"] == "released" for v in hub.holds.values())


def test_c13_a_non_active_hold_is_not_applied():
    hub, c = _hub()
    real = hub.handle

    def released(method, url, body, headers):
        res = real(method, url, body, headers)
        if method == "POST":
            return HttpResult(200, {"hold_id": "H9", "state": "released"})
        return res
    hub.handle = released
    r = c.apply(_act("hold", "outbound:ACC-1"))
    assert r.status == "failed" and "not active" in r.error


def test_c14_scope_comes_from_the_prefix_and_bare_refs_are_refused():
    hub, c = _hub()
    assert c.apply(_act("hold", "account:00123")).status == "applied"
    assert next(iter(hub.holds.values()))["scope"] == "account" and next(iter(hub.holds.values()))["ref"] == "00123"
    assert c.apply(_act("hold", "acct-00123")).status == "unsupported"


def test_c14_treasury_single_transfer_hold_is_a_txn_target():
    import inspect

    from aegis.agents.orchestrator import treasury
    assert 'target=f"txn:{txn}"' in inspect.getsource(treasury)


# C-5 — protected principals by every resolved name --------------------------------------------------------------------

def test_c5_protected_principal_by_object_id_upn_and_sam(monkeypatch):
    monkeypatch.setenv("AEGIS_IDP_PROTECTED", "breakglass@bank.in,priya.sharma@bank.local,svc_loan@db-core.bank.local")
    m = MockEntra()
    e = EntraConnector(base_url="https://graph.mock/v1.0", token_provider=lambda: "mock-graph-token", transport=m,
                       dry_run=False)
    assert e.apply(_act("lock_account", "user:u-1003")).status == "failed"          # the object id
    assert m.users["breakglass@bank.in"]["accountEnabled"] is True
    d = MockDirectory()
    ad = ActiveDirectoryConnector(directory=d, base_dn="DC=bank,DC=local", dry_run=False)
    assert ad.apply(_act("lock_account", "user:priya.sharma")).status == "failed"     # sAM form of a UPN entry
    assert ad.apply(_act("lock_account", "user:rootops")).status == "failed"          # renamed RID-500
    ca = MockCyberArk()
    c = CyberArkConnector(base_url="https://pvwa.mock", transport=ca, dry_run=False,
                          session=_CyberArkSession("https://pvwa.mock", "aegis", "mock", ca))
    assert c.apply(_act("rotate_credential", "account:svc_loan")).status == "failed"  # user@address entry
    assert ca.changed == {}


# C-6 / C-8 / C-15 — one prefix rule everywhere ------------------------------------------------------------------------

def test_c6_guard_and_protected_targets_strip_every_prefix(monkeypatch):
    assert strip_prefixes("ip:src:127.0.0.1") == "127.0.0.1"
    assert never_block_target("src:127.0.0.1")[0] and never_block_target("ip:src:127.0.0.1")[0]
    monkeypatch.setenv("AEGIS_NEVER_BLOCK", "10.20.0.0/16")
    assert never_block_target("dst:10.20.1.5")[0]
    from aegis.agents.response.agent import _target_matches
    for t in ("src:10.1.2.3", "dst:10.1.2.3", "10.1.2.3"):
        assert _target_matches(t, ["10.1.2.0/24"])
    for opaque in ("a1" * 20, "1234567890123", "11111111-2222-3333-4444-555555555555", "b" * 32):
        assert _target_matches(f"host:{opaque}", ["db-*"])


def test_c8_one_key_per_address_and_dst_never_gets_the_src_tag():
    assert canonical_target("src:198.51.100.7") == canonical_target("198.51.100.7") == canonical_target("ip:198.51.100.7")
    m = MockPanos()
    c = PanosConnector(base_url="https://panos.mock", api_key="mock-pan-key", transport=m, dry_run=False)
    a = c.apply(_act("block", "198.51.100.7"))
    b = c.apply(_act("block", "src:198.51.100.7"), ttl_sec=60)
    assert b.receipt_id == a.receipt_id                     # one receipt, renewed — not a second key over one tag
    assert c.apply(_act("block", "dst:192.0.2.9")).status == "unsupported"
    assert c.apply(_act("block_egress", "src:192.0.2.9")).status == "unsupported"
    assert c.apply(_act("block_egress", "dst:192.0.2.9")).status == "applied"
    assert m.tags["192.0.2.9"] == {"aegis-block-dst": 3600}
    assert FeedConnector(dry_run=False).apply(_act("block", "dst:192.0.2.9")).status == "unsupported"


def test_c15_sandbox_targets_are_covered_by_never_block_hosts(monkeypatch):
    monkeypatch.setenv("AEGIS_NEVER_BLOCK_HOSTS", "aegis-soc")
    assert never_block_target("agent:aegis-soc")[0] and never_block_target("sandbox:aegis-soc")[0]


# C-7 — read before acting; undo only what AEGIS did -------------------------------------------------------------------

def test_c7_pre_existing_isolations_and_bans_are_left_alone():
    md = MockDefender()
    d = DefenderConnector(base_url="https://mde.mock", token_provider=lambda: "mock-mde-token", transport=md, dry_run=False)
    mid = md.machines["db-core.bank.local"]
    md.actions.append({"id": "x", "machineId": mid, "type": "Isolate", "status": "Succeeded", "creationDateTimeUtc": "2026"})
    r = d.apply(_act("isolate", "db-core.bank.local"))
    assert r.status == "applied" and r.rollback_token.startswith("pre-existing")
    d.rollback(r)
    assert md._isolated(mid)
    ms = MockSentinelOne()
    ms.disconnected.add("1001")
    s1 = SentinelOneConnector(base_url="https://s1.mock", api_token="mock-s1-token", transport=ms, dry_run=False)
    r = s1.apply(_act("isolate", "app-ledger-07"))
    s1.rollback(r)
    assert ms.disconnected == {"1001"}
    mf = MockFortiGate()
    mf.banned["203.0.113.9"] = 0                            # an indefinite ban someone else placed
    f = FortiGateConnector(base_url="https://fgt.mock", token="mock-fgt-token", transport=mf, dry_run=False)
    r = f.apply(_act("block", "203.0.113.9"), ttl_sec=3600)
    assert mf.banned["203.0.113.9"] == 0 and r.rollback_token == "pre-existing"
    f.rollback(r)
    assert "203.0.113.9" in mf.banned


# C-9 — OpenShell drift only reports ---------------------------------------------------------------------------------

def test_c9_openshell_drift_does_not_reopen_endpoints():
    m = MockOpenShell()
    c = OpenShellConnector(runner=m, state_dir=tempfile.mkdtemp(), dry_run=False)
    r = c.apply(_act("isolate", "agent:loan-agent"))
    m.policies["loan-agent"]["network_policies"] = {"llm": {"name": "llm", "endpoints": []}}   # operator re-opens llm only
    c.forget(r, "drift")
    assert list(m.policies["loan-agent"]["network_policies"]) == ["llm"]


# C-10 — Trend read-back is honest -------------------------------------------------------------------------------------

def test_c10_trend_read_back_never_claims_a_console_restore_is_still_isolated():
    m = MockTrend()
    c = TrendVisionOneConnector(base_url="https://trend.mock", token="mock-trend-token", transport=m, dry_run=False)
    r = c.apply(_act("isolate", "app-ledger-07"))
    m.isolated.clear()                                      # restored in the Trend console
    assert c.verify(r) is not True


# C-11 — FortiGate blocks sources only --------------------------------------------------------------------------------

def test_c11_fortigate_does_not_claim_egress():
    f = FortiGateConnector(base_url="https://fgt.mock", token="t", transport=MockFortiGate(), dry_run=False)
    assert not f.supports("block_egress") and f.supports("block")


# C-12 — CyberArk reads every page ------------------------------------------------------------------------------------

def test_c12_cyberark_refuses_when_hits_are_not_all_read():
    ca = MockCyberArk()
    real = ca.handle

    def paged(method, url, body, headers):
        if "/API/Accounts?" in url:
            return HttpResult(200, {"value": [{"id": "1_1", "userName": "admin", "address": "a"}], "count": 7})
        return real(method, url, body, headers)
    ca.handle = paged
    c = CyberArkConnector(base_url="https://pvwa.mock", transport=ca, dry_run=False,
                          session=_CyberArkSession("https://pvwa.mock", "aegis", "mock", ca))
    r = c.apply(_act("rotate_credential", "account:admin"))
    assert r.status == "failed" and "7 hits" in r.error and ca.changed == {}


# C-16 — routing precedence ------------------------------------------------------------------------------------------

def test_c16_prefer_firewall_routes_blocks_to_the_firewall(monkeypatch):
    monkeypatch.setenv("AEGIS_WAF_VENDOR", "mock")
    monkeypatch.setenv("AEGIS_FW_VENDOR", "mock-panos")
    assert registry_from_env().route_action(_act("block", "203.0.113.9")).name != "panos"
    monkeypatch.setenv("AEGIS_PREFER_FIREWALL", "1")
    assert registry_from_env().route_action(_act("block", "203.0.113.9")).name == "panos"


def test_signed_requests_carry_a_fresh_nonce_each_time():
    hub, c = _hub()
    seen = []

    def spy(method, url, body, headers, timeout):
        seen.append(headers["X-AEGIS-Nonce"])
        return hub(method, url, body, headers, timeout)
    c._transport = spy
    r = c.apply(_act("hold", "outbound:ACC-3"))
    c.verify(r)
    assert len(seen) == 2 and len(set(seen)) == 2 and json.dumps(seen)
