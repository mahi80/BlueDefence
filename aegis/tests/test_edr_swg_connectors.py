"""Phase 1.3 — CrowdStrike (EDR) and Zscaler ZIA (SWG) connectors against the mock tenants."""

from __future__ import annotations

import tempfile

import pytest

from aegis.agents.response.connectors import (
    ConnectorError, CrowdStrikeConnector, ZscalerConnector,
    crowdstrike_from_env, registry_from_env, zscaler_from_env,
)
from aegis.agents.response.connectors.base import STATUS_EXPIRED, STATUS_FAILED, STATUS_ROLLED_BACK
from aegis.agents.response.connectors.mock_vendor import MockCrowdStrike, MockZscaler
from aegis.agents.shared.evidence_chain import RecommendedAction


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for k in ("AEGIS_ENFORCEMENT_MODE", "AEGIS_EDR_VENDOR", "AEGIS_SWG_VENDOR", "AEGIS_EDR_URL",
              "AEGIS_EDR_CLIENT_ID", "AEGIS_EDR_CLIENT_SECRET", "AEGIS_SWG_URL", "AEGIS_SWG_CATEGORY_ID",
              "AEGIS_SWG_TOKEN", "AEGIS_SOAR_VENDOR", "AEGIS_SOAR_PLAYBOOKS", "AEGIS_WAF_VENDOR"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ACP_HOME", tempfile.mkdtemp())


def _act(t, target, hitl=True):
    return RecommendedAction(action_type=t, target=target, reasoning="r", requires_hitl=hitl, confidence=0.95)


class Clock:
    def __init__(self, t=1_760_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


# --------------------------------------------------- Zscaler ZIA (egress) --

def test_zscaler_block_egress_applies_and_rolls_back():
    mock = MockZscaler()
    c = ZscalerConnector(base_url="https://zia.mock", category_id="CUSTOM_01", token_provider=lambda: "mock",
                         transport=mock, dry_run=False)
    r = c.apply(_act("block_egress", "evil.example.com"))
    assert r.status == "applied" and "evil.example.com" in mock.blocked()
    rb = c.rollback(r)
    assert rb.status == STATUS_ROLLED_BACK and "evil.example.com" not in mock.blocked()


def test_zscaler_strips_scheme_and_owns_only_destinations():
    mock = MockZscaler()
    c = ZscalerConnector(base_url="https://zia.mock", category_id="C", token_provider=lambda: "mock",
                         transport=mock, dry_run=False)
    c.apply(_act("block_egress", "https://bad.test/path/"))
    assert "bad.test/path" in mock.blocked()                 # scheme + trailing slash stripped
    assert c.supports_target("evil.com") and not c.supports_target("fp:ja4:abc")
    assert not c.supports("block")                           # source-IP block is the WAF's lane, not ZIA's


def test_zscaler_shadow_makes_no_vendor_call():
    mock = MockZscaler()
    c = ZscalerConnector(base_url="https://zia.mock", category_id="C", token_provider=lambda: "mock",
                         transport=mock, dry_run=True)
    r = c.apply(_act("block_egress", "evil.com"))
    assert r.dry_run and r.status == "dry_run" and mock.blocked() == set() and mock.calls == []


def test_zscaler_ttl_expiry_sweeps_the_block():
    clk = Clock()
    mock = MockZscaler()
    c = ZscalerConnector(base_url="https://zia.mock", category_id="C", token_provider=lambda: "mock",
                         transport=mock, dry_run=False, default_ttl_sec=300, clock=clk)
    c.apply(_act("block_egress", "evil.com"))
    assert "evil.com" in mock.blocked()
    clk.t += 301
    swept = c.sweep_expired()
    assert swept and swept[0].status == STATUS_EXPIRED and mock.blocked() == set()


# -------------------------------------------- CrowdStrike Falcon (EDR) --

def test_crowdstrike_isolate_contains_and_lifts_by_hostname():
    mock = MockCrowdStrike()
    c = CrowdStrikeConnector(base_url="https://api.crowdstrike.mock", token_provider=lambda: "mock-cs-token",
                             transport=mock, dry_run=False)
    r = c.apply(_act("isolate", "app-ledger-07"))
    assert r.status == "applied" and "a" * 32 in mock.contained and r.vendor_ref == "a" * 32
    rb = c.rollback(r)
    assert rb.status == STATUS_ROLLED_BACK and "a" * 32 not in mock.contained


def test_crowdstrike_accepts_a_device_id_directly():
    mock = MockCrowdStrike()
    c = CrowdStrikeConnector(base_url="https://api.crowdstrike.mock", token_provider=lambda: "mock-cs-token",
                             transport=mock, dry_run=False)
    c.apply(_act("isolate", "c" * 32))
    assert "c" * 32 in mock.contained                        # a 32-hex aid skips the hostname lookup


def test_crowdstrike_kill_process_is_one_shot_and_not_undoable():
    mock = MockCrowdStrike()
    c = CrowdStrikeConnector(base_url="https://api.crowdstrike.mock", token_provider=lambda: "mock-cs-token",
                             transport=mock, dry_run=False)
    r = c.apply(_act("kill_process", "app-ledger-07:4242"))
    assert r.status == "applied" and r.expires_at is None    # permanent: no TTL auto-rollback of a kill
    assert mock.kills and mock.kills[0]["command_string"] == "kill 4242"
    rb = c.rollback(r)
    assert rb.status == STATUS_FAILED and "cannot be undone" in rb.error


def test_crowdstrike_kill_requires_a_pid():
    mock = MockCrowdStrike()
    c = CrowdStrikeConnector(base_url="x", token_provider=lambda: "mock-cs-token", transport=mock, dry_run=False)
    r = c.apply(_act("kill_process", "app-ledger-07"))       # no :pid
    assert r.status == STATUS_FAILED and "pid" in r.error.lower()


def test_crowdstrike_target_narrowing():
    c = CrowdStrikeConnector(base_url="x", token_provider=lambda: "t", transport=MockCrowdStrike(), dry_run=False)
    assert c.supports_target("app-ledger-07") and c.supports_target("host:db-core") and c.supports_target("host-01:999")
    assert not c.supports_target("203.0.113.5") and not c.supports_target("fp:ja4:abc")


def test_crowdstrike_unknown_host_parks_as_failed():
    mock = MockCrowdStrike(hosts={})
    c = CrowdStrikeConnector(base_url="x", token_provider=lambda: "mock-cs-token", transport=mock, dry_run=False)
    r = c.apply(_act("isolate", "ghost-host"))
    assert r.status == STATUS_FAILED and "no CrowdStrike device" in r.error


def test_falcon_oauth_token_is_fetched_once_and_cached():
    from aegis.agents.response.connectors.edr import _FalconToken
    mock = MockCrowdStrike()
    tok = _FalconToken("https://api.crowdstrike.mock", "id", "secret", mock, clock=Clock())
    assert tok() == "mock-cs-token" and tok() == "mock-cs-token"
    fetches = [c for c in mock.calls if c[0] == "POST" and c[1].endswith("/oauth2/token")]
    assert len(fetches) == 1                                  # second call served from cache


# ------------------------------------------------ env wiring + routing --

def test_from_env_builds_mock_connectors(monkeypatch):
    monkeypatch.setenv("AEGIS_EDR_VENDOR", "mock")
    monkeypatch.setenv("AEGIS_SWG_VENDOR", "mock")
    assert crowdstrike_from_env().name == "crowdstrike"
    assert zscaler_from_env().name == "zscaler"
    assert crowdstrike_from_env.__module__  # importable
    # off by default
    monkeypatch.delenv("AEGIS_EDR_VENDOR"); monkeypatch.delenv("AEGIS_SWG_VENDOR")
    assert crowdstrike_from_env() is None and zscaler_from_env() is None


def test_registry_routes_isolate_to_edr_and_block_egress_to_swg(monkeypatch):
    monkeypatch.setenv("AEGIS_EDR_VENDOR", "mock")
    monkeypatch.setenv("AEGIS_SWG_VENDOR", "mock")
    monkeypatch.setenv("AEGIS_ENFORCEMENT_MODE", "live")
    reg = registry_from_env()
    assert reg.route_action(_act("isolate", "app-ledger-07")).name == "crowdstrike"
    assert reg.route_action(_act("block_egress", "evil.com")).name == "zscaler"


def test_soar_playbook_wins_isolate_over_direct_edr(monkeypatch):
    monkeypatch.setenv("AEGIS_SOAR_VENDOR", "mock")          # the mock SOAR seeds an isolate playbook
    monkeypatch.setenv("AEGIS_EDR_VENDOR", "mock")
    reg = registry_from_env()
    # SOAR is registered before the direct EDR, so a configured playbook takes isolate
    assert reg.route_action(_act("isolate", "app-ledger-07")).name == "xsoar"
