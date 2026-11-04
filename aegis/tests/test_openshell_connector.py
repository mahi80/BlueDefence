"""NVIDIA OpenShell — quarantine of a rogue AI agent's sandbox (network policy emptied, restored on undo)."""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

import pytest
import yaml

from aegis.agents.response.connectors import registry_from_env
from aegis.agents.response.connectors.base import STATUS_ROLLED_BACK, STATUS_UNSUPPORTED
from aegis.agents.response.connectors.openshell import (
    MockOpenShell,
    OpenShellConnector,
    openshell_from_env,
)
from aegis.agents.response.grounding import alert_entities, grounded
from aegis.agents.shared.evidence_chain import RecommendedAction


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for k in ("AEGIS_ENFORCEMENT_MODE", "AEGIS_AGENT_SANDBOX", "AEGIS_EDR_VENDOR", "AEGIS_SWG_VENDOR",
              "AEGIS_SOAR_VENDOR", "AEGIS_WAF_VENDOR"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ACP_HOME", tempfile.mkdtemp())


def _act(target, t="isolate"):
    return RecommendedAction(action_type=t, target=target, reasoning="r", requires_hitl=True, confidence=0.95)


def _conn(mock=None, **kw):
    return OpenShellConnector(runner=mock or MockOpenShell(), state_dir=tempfile.mkdtemp(), dry_run=False, **kw)


def test_isolate_empties_network_keeps_filesystem_and_undo_restores():
    mock = MockOpenShell()
    before = yaml.safe_load(yaml.safe_dump(mock.policies["loan-agent"]))
    c = _conn(mock)
    r = c.apply(_act("agent:loan-agent"))
    assert r.status == "applied", r.error
    pol = mock.policies["loan-agent"]
    assert pol["network_policies"] == {}
    assert pol["filesystem_policy"] == before["filesystem_policy"]       # only the network changes
    assert "2 rule(s)" in r.detail and "core_banking" in r.detail
    assert c.verify(r) is True
    saved = r.rollback_token
    assert stat.S_IMODE(os.stat(saved).st_mode) == 0o600
    rb = c.rollback(r)
    assert rb.status == STATUS_ROLLED_BACK
    assert mock.policies["loan-agent"] == before
    assert not os.path.exists(saved)


def test_verify_sees_a_policy_restored_outside_aegis():
    mock = MockOpenShell()
    before = yaml.safe_load(yaml.safe_dump(mock.policies["loan-agent"]))
    c = _conn(mock)
    r = c.apply(_act("sandbox:loan-agent"))
    mock.policies["loan-agent"] = before                                   # someone re-opened it by hand
    assert c.verify(r) is False


def test_only_agent_targets_and_only_isolate():
    c = _conn()
    assert c.supports_target("agent:loan-agent") and c.supports_target("sandbox:x")
    assert not c.supports_target("host:web-01") and not c.supports_target("10.0.0.5")
    assert not c.supports("block")
    assert c.apply(_act("host:web-01")).status == STATUS_UNSUPPORTED


@pytest.mark.parametrize("bad", ["agent:../etc", "agent:a b", "agent:", "agent:-x", "agent:" + "a" * 70])
def test_bad_sandbox_names_are_refused(bad):
    mock = MockOpenShell()
    r = _conn(mock).apply(_act(bad))
    assert r.status == "failed"
    assert not any(call[:2] == ["policy", "set"] for call in mock.calls)


def test_unknown_sandbox_fails_without_a_set():
    mock = MockOpenShell()
    r = _conn(mock).apply(_act("agent:ghost"))
    assert r.status == "failed" and "not found" in (r.error or "")
    assert not any(call[:2] == ["policy", "set"] for call in mock.calls)


def test_non_policy_output_is_refused():
    calls = []

    def runner(args):
        calls.append(args)
        return (0, "hello world", "") if args[:2] == ["policy", "get"] else (0, "", "")
    r = _conn(runner).apply(_act("agent:loan-agent"))
    assert r.status == "failed" and not any(a[:2] == ["policy", "set"] for a in calls)


def test_shadow_mode_never_calls_the_gateway():
    mock = MockOpenShell()
    c = OpenShellConnector(runner=mock, state_dir=tempfile.mkdtemp())   # default: shadow
    r = c.apply(_act("agent:loan-agent"))
    assert r.dry_run and mock.calls == []
    assert mock.policies["loan-agent"]["network_policies"]


def test_from_env_and_registry_routing(monkeypatch):
    assert openshell_from_env() is None
    monkeypatch.setenv("AEGIS_AGENT_SANDBOX", "bogus")
    assert openshell_from_env() is None
    monkeypatch.setenv("AEGIS_AGENT_SANDBOX", "mock")
    monkeypatch.setenv("AEGIS_EDR_VENDOR", "mock")
    assert isinstance(openshell_from_env(), OpenShellConnector)
    reg = registry_from_env()
    assert reg.route_action(_act("agent:loan-agent")).name == "openshell"
    assert reg.route_action(_act("host:web-01")).name != "openshell"          # a host isolate stays with the EDR


def test_crowdstrike_does_not_claim_agent_targets():
    from aegis.agents.response.connectors import CrowdStrikeConnector
    from aegis.agents.response.connectors.mock_vendor import MockCrowdStrike
    cs = CrowdStrikeConnector(base_url="https://falcon.mock", token_provider=lambda: "m", transport=MockCrowdStrike())
    assert not cs.supports_target("agent:loan-agent") and cs.supports_target("web-01")


def test_grounding_agent_target_needs_the_agent_in_the_alert():
    ents = alert_entities({"agent_id": "loan-agent", "user_agent": "evil-agent"})
    assert grounded("agent:loan-agent", ents, "isolate")[0]
    assert not grounded("agent:evil-agent", ents, "isolate")[0]             # a UA string never grounds an agent


def test_reapply_keeps_the_original_policy_for_undo():
    mock = MockOpenShell()
    before = yaml.safe_load(yaml.safe_dump(mock.policies["loan-agent"]))
    c = _conn(mock)
    a = _act("agent:loan-agent")
    key = c.idempotency_key(a)
    c._do_apply(a, key, None)
    _, _, token = c._do_apply(a, key, None)                                # second apply sees an empty policy
    assert yaml.safe_load(Path(token).read_text()) == before
