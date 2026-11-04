"""Integration plan #5: PAN-OS, FortiGate, Defender for Endpoint, SentinelOne, Entra ID, CyberArk — against the mock
tenants, through the real connector classes."""

from __future__ import annotations

import tempfile

import pytest

from aegis.agents.response.connectors import (
    CyberArkConnector,
    DefenderConnector,
    EntraConnector,
    FortiGateConnector,
    PanosConnector,
    SentinelOneConnector,
    crowdstrike_from_env,
    firewall_from_env,
    idp_from_env,
    pam_from_env,
    registry_from_env,
)
from aegis.agents.response.connectors.base import STATUS_ROLLED_BACK
from aegis.agents.response.connectors.identity import _CyberArkSession
from aegis.agents.response.connectors.mock_bank import (
    MockCyberArk,
    MockDefender,
    MockEntra,
    MockFortiGate,
    MockPanos,
    MockSentinelOne,
)
from aegis.agents.shared.evidence_chain import RecommendedAction

_VARS = ("AEGIS_ENFORCEMENT_MODE", "AEGIS_FW_VENDOR", "AEGIS_IDP_VENDOR", "AEGIS_PAM_VENDOR", "AEGIS_EDR_VENDOR",
         "AEGIS_WAF_VENDOR", "AEGIS_SWG_VENDOR", "AEGIS_SOAR_VENDOR", "AEGIS_AGENT_SANDBOX", "AEGIS_IDP_PROTECTED",
         "AEGIS_FW_URL", "AEGIS_FW_TOKEN", "AEGIS_EDR_URL", "AEGIS_EDR_TOKEN", "AEGIS_PAM_URL")


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for k in _VARS:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ACP_HOME", tempfile.mkdtemp())


def _act(t, target):
    return RecommendedAction(action_type=t, target=target, reasoning="r", requires_hitl=True, confidence=0.95)


# ------------------------------------------------------------------------------------------------ firewalls --

def test_panos_tags_with_timeout_verifies_and_untags():
    m = MockPanos()
    c = PanosConnector(base_url="https://panos.mock", api_key="mock-pan-key", transport=m, dry_run=False)
    r = c.apply(_act("block", "203.0.113.9"), ttl_sec=3600)
    assert r.status == "applied", r.error
    assert m.tags["203.0.113.9"] == {"aegis-block-src": 3600}
    assert c.verify(r) is True
    e = c.apply(_act("block_egress", "198.51.100.7"), ttl_sec=600)
    assert m.tags["198.51.100.7"] == {"aegis-block-dst": 600}
    assert c.rollback(r).status == STATUS_ROLLED_BACK and m.tags["203.0.113.9"] == {}
    assert c._do_verify(r) is False and c.verify(e) is True


def test_panos_refuses_cidr_bad_key_and_xml_injection():
    m = MockPanos()
    c = PanosConnector(base_url="https://panos.mock", api_key="mock-pan-key", transport=m, dry_run=False)
    assert not c.supports_target("10.0.0.0/8") and not c.supports_target("evil.com")
    assert c.apply(_act("block", '1.2.3.4"><x')).status == "unsupported"
    bad = PanosConnector(base_url="https://panos.mock", api_key="wrong", transport=m, dry_run=False)
    r = bad.apply(_act("block", "203.0.113.9"))
    assert r.status == "failed" and "403" in (r.error or "")
    with pytest.raises(ValueError):
        PanosConnector(base_url="https://x", api_key="k", tag_src="bad tag<")


def test_fortigate_bans_with_expiry_and_clears():
    m = MockFortiGate()
    c = FortiGateConnector(base_url="https://fgt.mock", token="mock-fgt-token", vdom="root", transport=m, dry_run=False)
    r = c.apply(_act("block", "203.0.113.9"), ttl_sec=900)
    assert r.status == "applied" and m.banned == {"203.0.113.9": 900}
    assert "vdom=root" in m.calls[0][1]
    assert c.verify(r) is True
    assert c.apply(_act("block_egress", "2001:db8::5"), ttl_sec=60).status == "applied"
    assert "2001:db8::5" in m.banned
    c.rollback(r)
    assert "203.0.113.9" not in m.banned and c._do_verify(r) is False


def test_firewall_from_env(monkeypatch):
    assert firewall_from_env() is None
    monkeypatch.setenv("AEGIS_FW_VENDOR", "panos")
    monkeypatch.setenv("AEGIS_FW_URL", "http://fw.bank.internal")
    monkeypatch.setenv("AEGIS_FW_TOKEN", "k")
    assert firewall_from_env() is None                                         # http refused
    monkeypatch.setenv("AEGIS_FW_URL", "https://fw.bank.internal")
    assert isinstance(firewall_from_env(), PanosConnector)
    monkeypatch.setenv("AEGIS_FW_VENDOR", "fortigate")
    assert isinstance(firewall_from_env(), FortiGateConnector)
    monkeypatch.setenv("AEGIS_FW_VENDOR", "mock-panos")
    assert isinstance(firewall_from_env(), PanosConnector)


# ------------------------------------------------------------------------------------------------------ EDR --

def test_defender_isolates_by_fqdn_or_short_name_and_releases():
    m = MockDefender()
    c = DefenderConnector(base_url="https://mde.mock", token_provider=lambda: "mock-mde-token", transport=m, dry_run=False)
    r = c.apply(_act("isolate", "host:app-ledger-07"))                     # short name → FQDN match
    assert r.status == "applied", r.error
    assert r.vendor_ref == "a1" * 20 and c.verify(r) is True
    assert c.rollback(r).status == STATUS_ROLLED_BACK and c._do_verify(r) is False
    r2 = c.apply(_act("isolate", "db-core.bank.local"))
    assert r2.status == "applied" and c.verify(r2) is True
    assert c.apply(_act("isolate", "ghost")).status == "failed"
    assert not c.supports_target("10.1.1.1") and not c.supports_target("agent:x")
    assert not c.supports("kill_process")


def test_defender_already_isolated_is_not_a_failure():
    m = MockDefender()
    c = DefenderConnector(base_url="https://mde.mock", token_provider=lambda: "mock-mde-token", transport=m, dry_run=False)
    c._do_apply(_act("isolate", "db-core.bank.local"), "k1", None)
    _, detail, _ = c._do_apply(_act("isolate", "db-core.bank.local"), "k1", None)
    assert "isolated" in detail


def test_sentinelone_disconnects_and_reconnects():
    m = MockSentinelOne()
    c = SentinelOneConnector(base_url="https://s1.mock", api_token="mock-s1-token", transport=m, dry_run=False)
    r = c.apply(_act("isolate", "app-ledger-07"))
    assert r.status == "applied" and m.disconnected == {"1001"} and c.verify(r) is True
    c.rollback(r)
    assert m.disconnected == set() and c._do_verify(r) is False
    assert c.apply(_act("isolate", "nope")).status == "failed"


def test_edr_from_env_variants(monkeypatch):
    monkeypatch.setenv("AEGIS_EDR_VENDOR", "mock-defender")
    assert isinstance(crowdstrike_from_env(), DefenderConnector)
    monkeypatch.setenv("AEGIS_EDR_VENDOR", "mock-sentinelone")
    assert isinstance(crowdstrike_from_env(), SentinelOneConnector)
    monkeypatch.setenv("AEGIS_EDR_VENDOR", "sentinelone")
    assert crowdstrike_from_env() is None                                   # needs URL + token
    monkeypatch.setenv("AEGIS_EDR_URL", "https://bank.sentinelone.net")
    monkeypatch.setenv("AEGIS_EDR_TOKEN", "t")
    assert isinstance(crowdstrike_from_env(), SentinelOneConnector)
    monkeypatch.setenv("AEGIS_EDR_VENDOR", "defender")
    assert isinstance(crowdstrike_from_env(), DefenderConnector)


# ------------------------------------------------------------------------------------------------- identity --

def _entra(m=None):
    return EntraConnector(base_url="https://graph.mock/v1.0", token_provider=lambda: "mock-graph-token",
                          transport=m or MockEntra(), dry_run=False)


def test_entra_revoke_is_one_shot():
    m = MockEntra()
    c = _entra(m)
    r = c.apply(_act("revoke_sessions", "user:priya.sharma@bank.in"))
    assert r.status == "applied" and m.revoked == ["priya.sharma@bank.in"] and r.expires_at is None
    assert c.rollback(r).status != STATUS_ROLLED_BACK                        # cannot be undone
    assert c.apply(_act("force_logout", "svc_loan@bank.in")).status == "applied"


def test_entra_lock_disables_revokes_and_undo_restores_only_what_it_changed():
    m = MockEntra()
    c = _entra(m)
    r = c.apply(_act("lock_account", "user:priya.sharma@bank.in"), ttl_sec=3600)
    assert r.status == "applied" and m.users["priya.sharma@bank.in"]["accountEnabled"] is False
    assert "priya.sharma@bank.in" in m.revoked and c.verify(r) is True
    assert c.rollback(r).status == STATUS_ROLLED_BACK and m.users["priya.sharma@bank.in"]["accountEnabled"] is True
    r2 = c.apply(_act("lock_account", "old.leaver@bank.in"))                 # already disabled before AEGIS
    assert r2.rollback_token == "disabled"
    c.rollback(r2)
    assert m.users["old.leaver@bank.in"]["accountEnabled"] is False          # left as it was


def test_entra_refuses_break_glass_and_bad_targets(monkeypatch):
    monkeypatch.setenv("AEGIS_IDP_PROTECTED", "breakglass@bank.in, emergency")
    m = MockEntra()
    c = _entra(m)
    r = c.apply(_act("lock_account", "user:breakglass@bank.in"))
    assert r.status == "failed" and "protected" in (r.error or "")
    assert m.users["breakglass@bank.in"]["accountEnabled"] is True
    assert c.apply(_act("revoke_sessions", "user:ghost@bank.in")).status == "failed"
    assert not c.supports_target("user:a/b") and not c.supports_target("user:x y")


def test_cyberark_rotates_one_exact_account_and_is_permanent(monkeypatch):
    m = MockCyberArk()
    c = CyberArkConnector(base_url="https://pvwa.mock", transport=m, dry_run=False,
                          session=_CyberArkSession("https://pvwa.mock", "aegis", "mock", m))
    r = c.apply(_act("rotate_credential", "account:svc_loan"))
    assert r.status == "applied" and "12_3" in m.changed and r.expires_at is None
    assert c.verify(r) is True
    assert c.rollback(r).status != STATUS_ROLLED_BACK
    amb = c.apply(_act("rotate_credential", "account:svc_batch"))
    assert amb.status == "failed" and "say which" in (amb.error or "")
    assert c.apply(_act("rotate_credential", "account:svc_batch@db-core.bank.local")).status == "applied"
    assert "12_5" in m.changed and "12_4" not in m.changed
    assert c.apply(_act("rotate_credential", "account:svc_lo")).status == "failed"        # substring never matches
    assert m.logons == 1                                                                   # session reused
    monkeypatch.setenv("AEGIS_IDP_PROTECTED", "svc_loan")
    assert c.apply(_act("rotate_credential", "account:svc_loan@db-core.bank.local")).status == "failed"


def test_identity_from_env_and_registry_routing(monkeypatch):
    assert idp_from_env() is None and pam_from_env() is None
    monkeypatch.setenv("AEGIS_PAM_VENDOR", "cyberark")
    monkeypatch.setenv("AEGIS_PAM_URL", "https://pvwa.bank.internal")
    assert pam_from_env() is None                                            # no credentials
    for k, v in (("AEGIS_IDP_VENDOR", "mock"), ("AEGIS_PAM_VENDOR", "mock"), ("AEGIS_FW_VENDOR", "mock-fortigate"),
                 ("AEGIS_EDR_VENDOR", "mock-defender")):
        monkeypatch.setenv(k, v)
    reg = registry_from_env()
    assert reg.route_action(_act("lock_account", "user:priya.sharma@bank.in")).name == "entra"
    assert reg.route_action(_act("rotate_credential", "account:svc_loan")).name == "cyberark"
    assert reg.route_action(_act("block", "203.0.113.9")).name == "fortigate"
    assert reg.route_action(_act("isolate", "db-core.bank.local")).name == "defender"


def test_shadow_mode_calls_no_vendor():
    m = MockEntra()
    c = EntraConnector(base_url="https://graph.mock/v1.0", token_provider=lambda: "mock-graph-token", transport=m)
    r = c.apply(_act("lock_account", "user:priya.sharma@bank.in"))
    assert r.dry_run and m.calls == [] and m.users["priya.sharma@bank.in"]["accountEnabled"] is True
