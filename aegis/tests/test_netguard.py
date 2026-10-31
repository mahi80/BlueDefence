"""Never-block guardrail: enforcement must never sever loopback / reserved / own-infra
space, yet a human may still isolate a compromised internal (RFC1918) host.

The loopback case is the one the 2026-10-27 purple-team run surfaced: in a loopback lab
every source IP is 127.0.0.1 (the SOC's ingest, the shim's sink, every agent), so an
un-gated auto-approved block would blind the SOC mid-run.
"""

from __future__ import annotations

import io

import pytest

from aegis.agents.response.agent import ResponseAgent
from aegis.agents.response.connectors import (
    Connector, ConnectorRegistry, STATUS_REFUSED,
)
from aegis.agents.shared.evidence_chain import RecommendedAction
from aegis.agents.shared.netguard import DENY_ACTIONS, enforcement_refused, never_block_target


def _action(kind="block", target="203.0.113.9"):
    return RecommendedAction(action_type=kind, target=target, reasoning="t",
                             requires_hitl=False, confidence=0.9)


class RecordingWaf(Connector):
    """A connector that records every vendor call so a refusal (no call) is observable."""

    name = "waf-rec"
    actions = frozenset({"block", "throttle", "isolate", "challenge", "quarantine"})

    def __init__(self, **kw):
        super().__init__(**kw)
        self.calls: list[tuple[str, str]] = []

    def _do_apply(self, action, key, ttl_sec):
        self.calls.append((action.action_type, action.target))
        return f"ref-{key[:6]}", f"{action.action_type} {action.target}", f"undo-{key[:6]}"

    def _do_rollback(self, receipt):
        return "removed"


# ----------------------------------------------------- unit: never_block_target -- #

@pytest.mark.parametrize("t", [
    "127.0.0.1", "127.0.0.1:8787", "127.5.5.5", "::1",
    "0.0.0.0", "169.254.169.254", "224.0.0.1", "240.0.0.1",
])
def test_loopback_and_reserved_are_never_block(t):
    refuse, why = never_block_target(t)
    assert refuse is True and why


@pytest.mark.parametrize("t", ["8.8.8.8", "203.0.113.9", "198.51.100.5", "1.1.1.1/32"])
def test_public_is_blockable(t):
    assert never_block_target(t)[0] is False


@pytest.mark.parametrize("t", ["10.1.4.20", "192.168.1.1", "172.16.0.9"])
def test_rfc1918_stays_blockable_so_a_human_can_isolate_an_internal_host(t):
    # deliberately NOT refused — isolating a compromised internal host is a core SOC action.
    assert never_block_target(t)[0] is False


@pytest.mark.parametrize("t", ["fp:ja4:t13d1516h2", "wks-fin-212", "user_42891", ""])
def test_non_address_targets_are_out_of_scope(t):
    assert never_block_target(t)[0] is False


def test_operator_cidr_allowlist(monkeypatch):
    monkeypatch.setenv("AEGIS_NEVER_BLOCK", "203.0.113.0/24, 10.9.0.0/16")
    assert never_block_target("203.0.113.9")[0] is True   # operator pinned the SOC's own subnet
    assert never_block_target("10.9.1.1")[0] is True
    assert never_block_target("8.8.8.8")[0] is False


def test_operator_host_allowlist_is_case_insensitive(monkeypatch):
    monkeypatch.setenv("AEGIS_NEVER_BLOCK_HOSTS", "soc-01, aegis-ingest")
    assert never_block_target("soc-01")[0] is True
    assert never_block_target("SOC-01")[0] is True
    assert never_block_target("some-other-host")[0] is False


def test_malformed_operator_entry_does_not_crash(monkeypatch):
    monkeypatch.setenv("AEGIS_NEVER_BLOCK", "not-a-cidr, 10.9.0.0/16")
    assert never_block_target("10.9.1.1")[0] is True       # the good entry still applies
    assert never_block_target("8.8.8.8")[0] is False


# -------------------------------------------------- unit: enforcement_refused -- #

def test_only_connectivity_actions_are_gated():
    for a in ("block", "isolate", "throttle", "quarantine", "block_egress"):
        assert a in DENY_ACTIONS
        assert enforcement_refused(a, "127.0.0.1")[0] is True
    # these do not sever infra, so they pass even against loopback
    for a in ("challenge", "monitor", "escalate", "revoke_sessions", "lock_account"):
        assert enforcement_refused(a, "127.0.0.1")[0] is False
    # a deny action against a real external target is fine
    assert enforcement_refused("block", "203.0.113.9")[0] is False


# ------------------------------------------- integration: the registry choke point -- #

def test_registry_refuses_loopback_block_without_calling_the_vendor():
    waf = RecordingWaf(dry_run=False)
    reg = ConnectorRegistry([waf])
    r = reg.apply(_action("block", "127.0.0.1"), alert_id="EDGE-1", approver="aegis:auto")
    assert r.status == STATUS_REFUSED and r.active is False
    assert r.connector == "never-block-guard"
    assert waf.calls == []                                  # vendor never touched
    # a real external target still goes all the way through
    r2 = reg.apply(_action("block", "203.0.113.9"))
    assert r2.active and ("block", "203.0.113.9") in waf.calls


def test_registry_refuses_loopback_isolate_and_throttle():
    waf = RecordingWaf(dry_run=False)
    reg = ConnectorRegistry([waf])
    assert reg.apply(_action("isolate", "127.0.0.1")).status == STATUS_REFUSED
    assert reg.apply(_action("throttle", "::1")).status == STATUS_REFUSED
    assert waf.calls == []


# --------------------------------------- integration: approve() incl. self-heal path -- #

def test_approve_refuses_loopback_block():
    waf = RecordingWaf(dry_run=False)
    agent = ResponseAgent(connectors=ConnectorRegistry([waf]), hitl_stream=io.StringIO())
    ex = agent.approve(_action("block", "127.0.0.1"), approver="ciso@bank.in")
    assert ex.status == "skipped"
    assert waf.calls == []


def test_approve_refuses_loopback_isolate_even_with_self_healing(monkeypatch):
    # isolate normally routes to the self-healing back end, bypassing the connector registry;
    # the top-of-approve guard must still refuse it for loopback.
    class FakeHeal:
        def __init__(self):
            self.severed = []

        def snapshot_and_sever(self, target, source_alert=None):
            self.severed.append(target)

    heal = FakeHeal()
    agent = ResponseAgent(connectors=ConnectorRegistry([RecordingWaf(dry_run=False)]),
                          self_healing=heal, hitl_stream=io.StringIO())
    ex = agent.approve(_action("isolate", "127.0.0.1"), approver="ciso@bank.in")
    assert ex.status == "skipped"
    assert heal.severed == []                               # self-heal never severed loopback


def test_approve_still_allows_isolating_a_compromised_internal_host():
    # the report's real case: isolate wks-fin-212 on 10.x — must keep working.
    waf = RecordingWaf(dry_run=False)
    agent = ResponseAgent(connectors=ConnectorRegistry([waf]), hitl_stream=io.StringIO())
    ex = agent.approve(_action("isolate", "10.20.4.51"), approver="ciso@bank.in")
    assert ex.status == "executed"
    assert ("isolate", "10.20.4.51") in waf.calls
