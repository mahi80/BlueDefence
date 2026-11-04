"""The AEGIS Payment Hold API connector: signed requests, account / transfer holds, settled refusal, release."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
import yaml

from aegis.agents.response.connectors import (
    PaymentHoldConnector,
    payhold_from_env,
    registry_from_env,
)
from aegis.agents.response.connectors.base import STATUS_ROLLED_BACK
from aegis.agents.response.connectors.mock_bank import MockPaymentHub
from aegis.agents.response.connectors.payhold import sign, verify_signature
from aegis.agents.shared.evidence_chain import RecommendedAction


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for k in ("AEGIS_ENFORCEMENT_MODE", "AEGIS_PAYHOLD_VENDOR", "AEGIS_PAYHOLD_URL", "AEGIS_PAYHOLD_TOKEN",
              "AEGIS_PAYHOLD_SIGNING_KEY", "AEGIS_SOAR_VENDOR", "AEGIS_SOAR_PLAYBOOKS", "AEGIS_WAF_VENDOR",
              "AEGIS_EDR_VENDOR", "AEGIS_SWG_VENDOR", "AEGIS_AGENT_SANDBOX", "AEGIS_FW_VENDOR", "AEGIS_IDP_VENDOR",
              "AEGIS_PAM_VENDOR", "AEGIS_BLOCK_FEED"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ACP_HOME", tempfile.mkdtemp())


def _act(target):
    return RecommendedAction(action_type="hold", target=target, reasoning="drain burst", requires_hitl=True, confidence=0.95)


def _conn(hub, **kw):
    return PaymentHoldConnector(base_url="https://payhub.mock/aegis/v1", token=hub.token, signing_key=hub.key.decode(),
                                transport=hub, dry_run=False, **kw)


def test_account_hold_ttl_verify_release():
    hub = MockPaymentHub()
    c = _conn(hub)
    r = c.apply(_act("outbound:TREASURY-OPS-01"), ttl_sec=3600)
    assert r.status == "applied", r.error
    (h,) = hub.holds.values()
    assert h["scope"] == "account" and h["ref"] == "TREASURY-OPS-01" and h["expires_at"] and h["requested_by"] == "aegis"
    assert c.verify(r) is True
    assert c.rollback(r).status == STATUS_ROLLED_BACK and h["state"] == "released"
    assert c._do_verify(r) is False


def test_transaction_hold_and_settled_is_never_applied():
    hub = MockPaymentHub()
    c = _conn(hub)
    assert c.apply(_act("txn:UTR123456789")).status == "applied"
    assert next(iter(hub.holds.values()))["scope"] == "transaction"
    late = c.apply(_act("TXN-SETTLED-1"))
    assert late.status == "failed" and "already settled" in (late.error or "") and "fraud team" in late.error


def test_every_request_is_signed_and_a_bad_key_is_refused():
    hub = MockPaymentHub()
    bad = PaymentHoldConnector(base_url="https://payhub.mock/aegis/v1", token=hub.token,
                               signing_key="wrong-key-but-long-enough", transport=hub, dry_run=False)
    r = bad.apply(_act("outbound:ACC-1"))
    assert r.status == "failed" and hub.rejected_signatures == 1 and hub.holds == {}
    with pytest.raises(ValueError):
        PaymentHoldConnector(base_url="https://x", token="t", signing_key="short")


def test_signature_helpers_reject_stale_and_tampered():
    key, body = b"k" * 32, b'{"a":1}'
    sig = sign(key, "1000", body)
    assert verify_signature(key, "1000", body, sig, now=1100)
    assert not verify_signature(key, "1000", body, sig, now=2000)             # replay outside 300 s
    assert not verify_signature(key, "1000", b'{"a":2}', sig, now=1000)       # tampered body
    assert not verify_signature(key, "nan", body, sig)


def test_bad_refs_and_idempotent_reapply():
    hub = MockPaymentHub()
    c = _conn(hub)
    assert not c.supports_target("outbound:a b") and not c.supports_target("txn:")
    a = _act("outbound:ACC-9")
    key = c.idempotency_key(a)
    first, _, _ = c._do_apply(a, key, 600)
    second, _, _ = c._do_apply(a, key, 1200)
    assert first == second and len(hub.holds) == 1


def test_from_env_and_routes_before_soar(monkeypatch):
    assert payhold_from_env() is None
    monkeypatch.setenv("AEGIS_PAYHOLD_VENDOR", "api")
    monkeypatch.setenv("AEGIS_PAYHOLD_URL", "http://payhub.bank.internal")
    monkeypatch.setenv("AEGIS_PAYHOLD_TOKEN", "t")
    monkeypatch.setenv("AEGIS_PAYHOLD_SIGNING_KEY", "x" * 32)
    assert payhold_from_env() is None                                          # https only
    monkeypatch.setenv("AEGIS_PAYHOLD_URL", "https://payhub.bank.internal/aegis/v1")
    assert isinstance(payhold_from_env(), PaymentHoldConnector)
    monkeypatch.setenv("AEGIS_PAYHOLD_VENDOR", "mock")
    monkeypatch.setenv("AEGIS_SOAR_VENDOR", "mock")
    monkeypatch.setenv("AEGIS_SOAR_PLAYBOOKS", "hold=Payment-Hold,hold.undo=Payment-Release")
    assert registry_from_env().route_action(_act("outbound:ACC-1")).name == "payhold"


def test_openapi_contract_parses():
    spec = yaml.safe_load((Path(__file__).resolve().parents[2] / "deploy" / "payment-hold" / "openapi.yaml").read_text())
    assert set(spec["paths"]) == {"/holds", "/holds/{hold_id}"}
    assert "409" in spec["paths"]["/holds"]["post"]["responses"]
