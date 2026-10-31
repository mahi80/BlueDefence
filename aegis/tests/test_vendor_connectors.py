"""Phase 1.2 — WAF (Imperva / F5) and SOAR (XSOAR / Sentinel) connectors against the mock tenants."""

from __future__ import annotations

import tempfile

import pytest

from aegis.agents.response.agent import ResponseAgent
from aegis.agents.response.connectors import (
    F5WafConnector, ImpervaWafConnector, SentinelPlaybookConnector, XsoarConnector,
    parse_playbook_map, registry_from_env,
)
from aegis.agents.response.connectors.http import HttpResult, call
from aegis.agents.response.connectors.mock_vendor import MockF5, MockImperva, MockLogicApp, MockXsoar
from aegis.agents.response.receipts import ReceiptLog
from aegis.agents.shared.evidence_chain import EvidenceChain, RecommendedAction
from aegis.shadow import build_report


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for k in ("AEGIS_ENFORCEMENT_MODE", "AEGIS_WAF_VENDOR", "AEGIS_SOAR_VENDOR", "AEGIS_SOAR_PLAYBOOKS",
              "AEGIS_WAF_SITE_ID", "AEGIS_WAF_API_ID", "AEGIS_WAF_API_KEY", "AEGIS_WAF_URL", "AEGIS_WAF_POLICY_ID",
              "AEGIS_RECEIPTS", "AEGIS_PROTECTED_TARGETS"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ACP_HOME", tempfile.mkdtemp())


def _act(action_type, target, hitl=False):
    return RecommendedAction(action_type=action_type, target=target, reasoning="r", requires_hitl=hitl, confidence=0.9)


class Clock:
    def __init__(self, t=1_760_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


# ------------------------------------------------------------------ http --

def test_http_call_retries_429_and_5xx_then_maps_errors():
    seq = [HttpResult(429, {"message": "slow down"}, {"Retry-After": "0"}), HttpResult(503, "busy"), HttpResult(200, {"ok": 1})]
    calls = []

    def tr(method, url, body, headers, timeout):
        calls.append(method)
        return seq.pop(0)
    res = call(tr, "POST", "https://v.test/x", sleep=lambda s: None)
    assert res.ok and res.json() == {"ok": 1} and len(calls) == 3
    from aegis.agents.response.connectors import ConnectorError
    with pytest.raises(ConnectorError, match="HTTP 403 .*nope"):
        call(lambda *a: HttpResult(403, {"message": "nope"}), "GET", "https://v.test/y?secret=1", sleep=lambda s: None)
    with pytest.raises(ConnectorError, match="after 2 attempts"):
        call(lambda *a: HttpResult(500, "down"), "GET", "https://v.test/y", retries=1, sleep=lambda s: None)

    def boom(*a):
        raise ConnectionError("reset")
    with pytest.raises(ConnectorError, match="ConnectionError"):
        call(boom, "GET", "https://v.test/z", retries=1, sleep=lambda s: None)


# --------------------------------------------------------------- imperva --

def test_imperva_block_challenge_throttle_lifecycle():
    clock = Clock()
    srv = MockImperva(api_id="id1", api_key="k1")
    c = ImpervaWafConnector(site_id="42", api_id="id1", api_key="k1", base_url="https://imperva.test",
                            transport=srv, dry_run=False, default_ttl_sec=600, clock=clock, rate_limit_per_min=30)
    r_block = c.apply(_act("block", "203.0.113.9"), alert_id="A-1")
    assert r_block.status == "applied" and r_block.vendor_ref == "1001" and r_block.rollback_token == "1001"
    assert srv.blocked_ips() == {"203.0.113.9"} and "TTL 600s" in r_block.detail
    r_chal = c.apply(_act("challenge", "198.51.100.0/24"), alert_id="A-2")
    assert srv.rules[r_chal.vendor_ref]["action"] == "RULE_ACTION_CAPTCHA" and "ClientIP == 198.51.100.0" in srv.rules[r_chal.vendor_ref]["filter"]
    r_thr = c.apply(_act("throttle", "203.0.113.77"), alert_id="A-3")
    rule = srv.rules[r_thr.vendor_ref]
    assert rule["action"] == "RULE_ACTION_RATE" and rule["rate_limit"] == 30 and rule["rate_context"] == "IP"
    # idempotent: same (action, target) renews instead of creating a second rule
    again = c.apply(_act("block", "203.0.113.9"), alert_id="A-9")
    assert again.receipt_id == r_block.receipt_id and again.renewals == 1 and len(srv.rules) == 3
    # rollback deletes the rule; a second rollback is a no-op (404 tolerated)
    rb = c.rollback(r_block, reason="analyst")
    assert rb.status == "rolled_back" and "1001" not in srv.rules and "deleted" in rb.detail
    # TTL expiry sweeps the rest
    clock.t += 601
    swept = c.sweep_expired()
    assert {r.status for r in swept} == {"expired"} and srv.rules == {}
    # a non-IP target is refused before any vendor call
    n = len(srv.calls)
    bad = c.apply(_act("block", "user_id"), alert_id="A-4")
    assert bad.status == "failed" and "IP address or CIDR" in bad.error and len(srv.calls) == n


def test_imperva_vendor_failures_become_failed_receipts():
    srv = MockImperva(api_id="id1", api_key="k1")
    wrong = ImpervaWafConnector(site_id="42", api_id="id1", api_key="WRONG", transport=srv, dry_run=False)
    r = wrong.apply(_act("block", "203.0.113.9"))
    assert r.status == "failed" and "401" in r.error and not r.active
    c = ImpervaWafConnector(site_id="42", api_id="id1", api_key="k1", transport=srv, dry_run=False)
    srv.fail_next = [429, 500]
    import time as _time
    orig = _time.sleep
    _time.sleep = lambda s: None
    try:
        r = c.apply(_act("block", "203.0.113.10"))
    finally:
        _time.sleep = orig
    assert r.status == "applied" and srv.blocked_ips() == {"203.0.113.10"}     # retried through 429 + 500


def test_imperva_shadow_mode_touches_nothing():
    srv = MockImperva()
    c = ImpervaWafConnector(site_id="42", api_id="mock", api_key="mock", transport=srv)   # dry_run from env → shadow
    r = c.apply(_act("block", "203.0.113.9"), alert_id="A-1")
    assert r.dry_run and r.status == "dry_run" and srv.calls == [] and "[shadow] would block" in r.detail
    assert c.rollback(r).status == "rolled_back" and srv.calls == []


# -------------------------------------------------------------------- f5 --

def test_f5_block_with_token_login_relogin_and_rollback():
    srv = MockF5(username="admin", password="pw", token_ttl_calls=1)
    c = F5WafConnector(base_url="https://bigip.test", policy_id="pol-1", username="admin", password="pw",
                       transport=srv, dry_run=False, default_ttl_sec=0)
    r1 = c.apply(_act("block", "203.0.113.9"), alert_id="A-1")
    assert r1.status == "applied" and srv.blocked_ips() == {"203.0.113.9"} and "(permanent)" in r1.detail
    assert srv.entries[r1.vendor_ref]["ipMask"] == "255.255.255.255" and srv.entries[r1.vendor_ref]["blockRequests"] == "always"
    r2 = c.apply(_act("block", "10.9.0.0/16"), alert_id="A-2")           # token used up → 401 → relogin → ok
    assert r2.status == "applied" and srv.entries[r2.vendor_ref]["ipMask"] == "255.255.0.0"
    assert sum(1 for m, u, _ in srv.calls if u.endswith("/authn/login")) == 2
    assert not c.supports("throttle") and not c.supports("challenge")
    assert c.rollback(r1).status == "rolled_back" and "203.0.113.9" not in srv.blocked_ips()
    bad = F5WafConnector(base_url="https://bigip.test", policy_id="pol-1", username="admin", password="nope",
                         transport=srv, dry_run=False)
    assert bad.apply(_act("block", "203.0.113.5")).status == "failed"


# ------------------------------------------------------------------ xsoar --

def test_xsoar_playbooks_undo_and_unmapped_actions():
    srv = MockXsoar(api_key="k", known_playbooks={"Isolate-Host", "Release-Host", "Disable-User"})
    pb = parse_playbook_map("isolate=Isolate-Host, isolate.undo=Release-Host,lock_account=Disable-User, bad,=x")
    assert pb == {"isolate": "Isolate-Host", "isolate.undo": "Release-Host", "lock_account": "Disable-User"}
    c = XsoarConnector(base_url="https://xsoar.test/", api_key="k", auth_id="7", playbooks=pb, transport=srv, dry_run=False)
    assert c.actions == frozenset({"isolate", "lock_account"}) and not c.supports("kill_process")
    r = c.apply(_act("isolate", "host-42", hitl=True), alert_id="A-1", approver="ciso@bank.test")
    assert r.status == "applied" and r.expires_at is None and r.vendor_ref == "1001"
    inc = srv.incidents["1001"]
    assert inc["playbookId"] == "Isolate-Host" and inc["severity"] == 3 and inc["customFields"]["aegistarget"] == "host-42"
    assert any(call[0] == "POST" and "x-xdr-auth-id" not in str(call) for call in srv.calls)
    rb = c.rollback(r, reason="false positive")
    assert rb.status == "rolled_back" and srv.incidents["1002"]["playbookId"] == "Release-Host"
    assert srv.incidents["1002"]["customFields"]["aegisundoof"] == "1001"
    r2 = c.apply(_act("lock_account", "u_1", hitl=True), alert_id="A-2")
    rb2 = c.rollback(r2)
    assert rb2.status == "failed" and "no undo playbook" in rb2.error and "human" in rb2.error
    srv.known_playbooks = set()
    r3 = c.apply(_act("lock_account", "u_2", hitl=True))
    assert r3.status == "failed" and "400" in r3.error


# ---------------------------------------------------------------- sentinel --

def test_sentinel_trigger_url_run_ids_and_bad_signature():
    srv = MockLogicApp(valid_sig="sig=ok")
    pb = {"revoke_sessions": "https://prod-11.logic.azure.com/workflows/abc/triggers/manual/paths/invoke?sig=ok",
          "isolate": "https://prod-11.logic.azure.com/workflows/def/triggers/manual/paths/invoke?sig=BAD",
          "kill_process": "http://insecure/trigger"}
    c = SentinelPlaybookConnector(playbooks=pb, transport=srv, dry_run=False)
    r = c.apply(_act("revoke_sessions", "u_7", hitl=True), alert_id="A-1")
    assert r.status == "applied" and r.vendor_ref.startswith("0858") and srv.runs[0]["target"] == "u_7"
    assert c.apply(_act("isolate", "h-1", hitl=True)).status == "failed"            # 401 → failed receipt
    bad = c.apply(_act("kill_process", "p-1", hitl=True))
    assert bad.status == "failed" and "https" in bad.error


# ------------------------------------------------------ env wiring + e2e --

def test_registry_from_env_mock_vendors_shadow_then_live(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_WAF_VENDOR", "mock")
    monkeypatch.setenv("AEGIS_SOAR_VENDOR", "mock")
    reg = registry_from_env()
    assert reg.mode == "shadow" and [c.name for c in reg.connectors] == ["imperva", "xsoar", "log"]
    assert reg.route("block").name == "imperva" and reg.route("isolate").name == "xsoar" and reg.route("allow").name == "log"
    r = reg.apply(_act("block", "203.0.113.9"), alert_id="A-1")
    assert r.dry_run and r.connector == "imperva"

    monkeypatch.setenv("AEGIS_ENFORCEMENT_MODE", "live")
    log = ReceiptLog(tmp_path / "r.jsonl")
    reg = registry_from_env(on_receipt=[log])
    assert reg.mode == "live"
    agent = ResponseAgent(connectors=reg)
    chain = EvidenceChain(alert_id="A-7", investigated_by="perimeter", verdict="malicious", confidence=0.9,
                          recommended_actions=[_act("throttle", "203.0.113.9"), _act("block", "203.0.113.9", hitl=True),
                                               _act("isolate", "host-1", hitl=True)])
    summary = agent.execute(chain)
    assert [e.action.action_type for e in summary.executed] == ["throttle"]
    assert summary.receipts[0].connector == "imperva" and summary.receipts[0].status == "applied"
    agent.approve(_act("block", "203.0.113.9", hitl=True), approver="ciso@bank.test", source_alert_id="A-7")
    agent.approve(_act("isolate", "host-1", hitl=True), approver="ciso@bank.test", source_alert_id="A-7")
    imperva = reg.connectors[0]._transport
    xsoar = reg.connectors[1]._transport
    assert imperva.blocked_ips() == {"203.0.113.9"} and len(imperva.rules) == 2
    assert len(xsoar.runs_of("Isolate-Host")) == 1     # no self-healing pipeline configured → the playbook does it
    entries = ReceiptLog.latest_per_receipt(ReceiptLog.read(log.path))
    assert {(e["connector"], e["action_type"], e["mode"]) for e in entries} == {
        ("imperva", "throttle", "live"), ("imperva", "block", "live"), ("xsoar", "isolate", "live"),
        ("imperva", "block", "auto-shadow")}   # tiered autonomy would have auto-blocked; scored separately
    rep = build_report(entries, [{"alert_id": "A-7", "recommended_actions": []}],
                       decisions_by_alert={"A-7": [{"action_type": "block", "decision": "approved"}]})
    by = {(g.connector, g.action_type, g.mode): g.verdict for g in rep.groups}
    assert by == {("imperva", "throttle", "live"): "live", ("imperva", "block", "live"): "live",
                  ("xsoar", "isolate", "live"): "live",
                  ("imperva", "block", "auto-shadow"): "not_yet"}   # one sample — far from the n / window bar


def test_registry_from_env_ignores_incomplete_vendor_blocks(monkeypatch):
    monkeypatch.setenv("AEGIS_WAF_VENDOR", "imperva")          # no site / keys → skipped, not a crash
    monkeypatch.setenv("AEGIS_SOAR_VENDOR", "xsoar")           # no playbooks → skipped
    reg = registry_from_env()
    assert [c.name for c in reg.connectors] == ["log"] and reg.mode == "log-only"
    monkeypatch.setenv("AEGIS_WAF_VENDOR", "f5")
    monkeypatch.setenv("AEGIS_WAF_URL", "https://bigip.test")
    monkeypatch.setenv("AEGIS_WAF_POLICY_ID", "p1")
    monkeypatch.setenv("AEGIS_SOAR_VENDOR", "sentinel")
    monkeypatch.setenv("AEGIS_SOAR_PLAYBOOKS", "isolate=https://x.logic.azure.com/trigger?sig=1")
    reg = registry_from_env()
    assert [c.name for c in reg.connectors] == ["f5", "sentinel", "log"] and reg.mode == "shadow"
