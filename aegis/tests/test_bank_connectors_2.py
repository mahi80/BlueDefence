"""Integration plan #5b: Trend Vision One, on-prem Active Directory, and the firewall pull feed (Check Point
Network Feed / PAN-OS EDL / FortiGate threat feed)."""

from __future__ import annotations

import base64
import tempfile
import urllib.error
import urllib.request

import pytest

from aegis.agents.response.connectors import (
    ActiveDirectoryConnector,
    FeedConnector,
    TrendVisionOneConnector,
    crowdstrike_from_env,
    idp_from_env,
    registry_from_env,
)
from aegis.agents.response.connectors.base import STATUS_ROLLED_BACK
from aegis.agents.response.connectors.identity import Directory, _ldap_escape
from aegis.agents.response.connectors.mock_bank import MockDirectory, MockTrend
from aegis.agents.shared.evidence_chain import RecommendedAction
from aegis.ingest.http_push import PushServer
from aegis.ingest.stream import StreamQueue


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for k in ("AEGIS_ENFORCEMENT_MODE", "AEGIS_EDR_VENDOR", "AEGIS_IDP_VENDOR", "AEGIS_BLOCK_FEED", "AEGIS_FW_VENDOR",
              "AEGIS_WAF_VENDOR", "AEGIS_SWG_VENDOR", "AEGIS_SOAR_VENDOR", "AEGIS_PAM_VENDOR", "AEGIS_AGENT_SANDBOX",
              "AEGIS_IDP_PROTECTED", "AEGIS_EDR_URL", "AEGIS_EDR_TOKEN", "AEGIS_AD_URL"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ACP_HOME", tempfile.mkdtemp())


def _act(t, target):
    return RecommendedAction(action_type=t, target=target, reasoning="r", requires_hitl=True, confidence=0.95)


# --------------------------------------------------------------------------------------------- Trend Vision One --

def test_trend_isolates_restores_and_reads_the_task():
    m = MockTrend()
    c = TrendVisionOneConnector(base_url="https://trend.mock", token="mock-trend-token", transport=m, dry_run=False)
    r = c.apply(_act("isolate", "host:app-ledger-07"))
    assert r.status == "applied", r.error
    guid = "11111111-2222-3333-4444-555555555555"
    # round 6 C-10: a succeeded task does not prove the endpoint is still isolated -> not verifiable (None)
    assert m.isolated == {guid} and r.vendor_ref.startswith(guid + "#") and c.verify(r) is None
    assert c.rollback(r).status == STATUS_ROLLED_BACK and m.isolated == set()
    assert c.apply(_act("isolate", "ghost")).status == "failed"
    task = r.vendor_ref.partition("#")[2]
    m.tasks[task] = "failed"
    assert c._do_verify(r) is False


def test_trend_from_env(monkeypatch):
    monkeypatch.setenv("AEGIS_EDR_VENDOR", "mock-trend")
    assert isinstance(crowdstrike_from_env(), TrendVisionOneConnector)
    monkeypatch.setenv("AEGIS_EDR_VENDOR", "trend")
    assert crowdstrike_from_env() is None
    monkeypatch.setenv("AEGIS_EDR_URL", "https://api.in.xdr.trendmicro.com")
    monkeypatch.setenv("AEGIS_EDR_TOKEN", "t")
    assert isinstance(crowdstrike_from_env(), TrendVisionOneConnector)


# --------------------------------------------------------------------------------------------- Active Directory --

def _ad(d=None):
    return ActiveDirectoryConnector(directory=d or MockDirectory(), base_dn="DC=bank,DC=local", dry_run=False)


def test_ad_disables_and_undo_restores_only_what_it_changed():
    d = MockDirectory()
    c = _ad(d)
    dn = "CN=Priya Sharma,OU=Staff,DC=bank,DC=local"
    r = c.apply(_act("lock_account", "user:priya.sharma"))
    assert r.status == "applied" and d.users[dn]["userAccountControl"] == 514 and c.verify(r) is True
    assert "Kerberos" in r.detail
    assert c.rollback(r).status == STATUS_ROLLED_BACK and d.users[dn]["userAccountControl"] == 512
    svc = c.apply(_act("lock_account", "svc_loan@bank.local"))                 # by UPN, keeps other UAC bits
    assert d.users["CN=svc_loan,OU=Service,DC=bank,DC=local"]["userAccountControl"] == 66050
    assert svc.status == "applied"
    old = c.apply(_act("lock_account", "old.leaver"))
    assert old.rollback_token == "disabled"
    c.rollback(old)
    assert d.users["CN=Old Leaver,OU=Staff,DC=bank,DC=local"]["userAccountControl"] == 514


def test_ad_refuses_privileged_protected_and_ambiguous(monkeypatch):
    d = MockDirectory()
    c = _ad(d)
    assert c.apply(_act("lock_account", "user:Administrator")).status == "failed"
    assert c.apply(_act("lock_account", "user:krbtgt")).status == "failed"
    monkeypatch.setenv("AEGIS_IDP_PROTECTED", "priya.sharma")
    assert c.apply(_act("lock_account", "user:priya.sharma")).status == "failed"
    assert c.apply(_act("lock_account", "user:nobody")).status == "failed"
    assert not c.supports("revoke_sessions")                                  # AD has no session revoke


def test_ldap_filter_escaping_and_ldaps_only():
    assert _ldap_escape("a*)(cn=*") == r"a\2a\29\28cn=\2a"
    with pytest.raises(ValueError, match="ldaps"):
        Directory("ldap://dc.bank.local", "cn=x", "p")


def test_ad_from_env(monkeypatch):
    monkeypatch.setenv("AEGIS_IDP_VENDOR", "mock-ad")
    assert isinstance(idp_from_env(), ActiveDirectoryConnector)
    monkeypatch.setenv("AEGIS_IDP_VENDOR", "ad")
    assert idp_from_env() is None                                              # incomplete config
    for k, v in (("AEGIS_AD_URL", "ldaps://dc.bank.local"), ("AEGIS_AD_BASE_DN", "DC=bank,DC=local"),
                 ("AEGIS_AD_BIND_DN", "CN=aegis,OU=Svc,DC=bank,DC=local"), ("AEGIS_AD_BIND_PASSWORD", "x")):
        monkeypatch.setenv(k, v)
    assert isinstance(idp_from_env(), ActiveDirectoryConnector)


# --------------------------------------------------------------------------------------------- pull feed --

def test_feed_connector_routes_last_and_serves_text(monkeypatch):
    monkeypatch.setenv("AEGIS_BLOCK_FEED", "1")
    monkeypatch.setenv("AEGIS_ENFORCEMENT_MODE", "live")
    reg = registry_from_env()
    assert reg.route_action(_act("block", "203.0.113.9")).name == "feed"
    monkeypatch.setenv("AEGIS_FW_VENDOR", "mock-panos")
    assert registry_from_env().route_action(_act("block", "203.0.113.9")).name == "panos"    # a direct connector wins
    feed = FeedConnector(dry_run=False)
    r1 = feed.apply(_act("block", "203.0.113.9"))
    feed.apply(_act("block", "198.51.100.0/28"))
    feed.apply(_act("block_egress", "dst:192.0.2.66"))
    feed.apply(_act("block", "fp:ja4:t13d1516h2_8daaf6152771_02713d6af862"))   # never listed (not an IP)
    shadow = FeedConnector(dry_run=True)
    shadow.apply(_act("block", "203.0.113.200"))
    srv = PushServer(token="push", read_token="read", bind="127.0.0.1:0", queue=StreamQueue(),
                     blocklist=lambda: feed.active_receipts + shadow.active_receipts).start()
    try:
        base = f"http://127.0.0.1:{srv.port}/ingest/blocklist?format=txt"

        def get(url, auth=None):
            req = urllib.request.Request(url, headers={"Authorization": auth} if auth else {})
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    return resp.status, resp.read().decode(), resp.headers.get("Content-Type")
            except urllib.error.HTTPError as e:
                return e.code, "", ""
        assert get(base)[0] == 401
        assert get(base, "Bearer push")[0] == 401                               # the push token reads nothing
        code, text, ctype = get(base, "Bearer read")
        assert code == 200 and ctype.startswith("text/plain")
        assert text.splitlines() == ["203.0.113.9", "198.51.100.0/28"]           # no fingerprint, no shadow entry
        basic = "Basic " + base64.b64encode(b"checkpoint:read").decode()
        assert get(base + "&kind=dst", basic)[1].splitlines() == ["192.0.2.66"]
        assert get(base, "Basic " + base64.b64encode(b"checkpoint:wrong").decode())[0] == 401
        feed.rollback(r1)
        assert get(base, "Bearer read")[1].splitlines() == ["198.51.100.0/28"]
    finally:
        srv.stop()
