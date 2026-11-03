"""Round-3 review, group G3: what the vendors actually enforce."""

from __future__ import annotations

import threading
import time
import types

from aegis.agents.response.connectors.base import (
    STATUS_APPLIED,
    STATUS_DRIFTED,
    STATUS_EXPIRED,
    STATUS_UNSUPPORTED,
    ConnectorRegistry,
)
from aegis.agents.response.connectors.mock_vendor import MockImperva, MockZscaler
from aegis.agents.response.connectors.swg import ZscalerConnector
from aegis.agents.response.connectors.waf import ImpervaWafConnector


def _act(t, target):
    return types.SimpleNamespace(action_type=t, target=target)


class _Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


def _imperva(srv, clock=None):
    kw = {"clock": clock} if clock else {}
    return ImpervaWafConnector(site_id="s", api_id="mock", api_key="mock", transport=srv, dry_run=False, **kw)


# ---- G3-1: a missed read-back undoes the rule, and it takes two misses after a grace period -------------------------

def test_drift_needs_two_misses_and_removes_the_rule(monkeypatch):
    monkeypatch.setenv("AEGIS_VERIFY_GRACE_S", "0")
    srv = MockImperva()
    conn = _imperva(srv)
    r = conn.apply(_act("throttle", "203.0.113.7"))
    assert r.status == STATUS_APPLIED and len(srv.rules) == 1
    monkeypatch.setattr(conn, "_do_verify", lambda rec: False)    # the read-back misses a rule that IS there
    assert conn.check_drift() == [] and conn.active_receipts       # one miss: wait and see
    (d,) = conn.check_drift()
    assert d.status == STATUS_DRIFTED and not conn.active_receipts
    assert srv.rules == {}                                         # not orphaned at the vendor


def test_a_fresh_receipt_is_not_judged(monkeypatch):
    monkeypatch.setenv("AEGIS_VERIFY_GRACE_S", "60")
    clock = _Clock()
    conn = _imperva(MockImperva(), clock)
    conn.apply(_act("throttle", "203.0.113.8"))
    monkeypatch.setattr(conn, "_do_verify", lambda rec: False)
    assert conn.check_drift() == [] and conn.check_drift() == []
    clock.t += 61
    conn.check_drift()
    assert len(conn.check_drift()) == 1


def test_zscaler_read_back_compares_normal_forms(monkeypatch):
    zia = MockZscaler()
    z = ZscalerConnector(base_url="https://zia", category_id="C1", token_provider=lambda: "mock", transport=zia, dry_run=False)
    r = z.apply(_act("block_egress", "https://Evil-C2.example/"))
    zia.categories["C1"] = {"EVIL-C2.EXAMPLE/"}                   # how the vendor stored it
    assert z.verify(r) is True


# ---- G3-2: an expired receipt is undone before it is replaced ------------------------------------------------------

def test_expired_unswept_receipt_is_rolled_back_on_reapply():
    srv, clock = MockImperva(), _Clock()
    conn = _imperva(srv, clock)
    first = conn.apply(_act("throttle", "203.0.113.9"), ttl_sec=60)
    clock.t += 120                                                 # expired, the sweep has not run
    second = conn.apply(_act("throttle", "203.0.113.9"), ttl_sec=60)
    assert first.status == STATUS_EXPIRED and second.status == STATUS_APPLIED
    assert list(srv.rules) == [second.vendor_ref]                  # one rule at the vendor, not two


# ---- G3-3: the logging fallback never claims enforcement in live mode -----------------------------------------------

def test_logging_fallback_is_unsupported_in_live_mode(monkeypatch):
    reg = ConnectorRegistry([])
    monkeypatch.setenv("AEGIS_ENFORCEMENT_MODE", "live")
    r = reg.apply(_act("disable_account", "u_42891"))
    assert r.status == STATUS_UNSUPPORTED and "no vendor connector" in r.error
    monkeypatch.setenv("AEGIS_ENFORCEMENT_MODE", "shadow")
    assert reg.apply(_act("disable_account", "u_42891")).status != STATUS_UNSUPPORTED


# ---- G3-4: read-backs do not run on the service thread ---------------------------------------------------------------

def test_drift_check_runs_off_the_service_thread(monkeypatch):
    from aegis import service
    monkeypatch.setenv("AEGIS_VERIFY_EVERY_S", "1")
    monkeypatch.setattr(service, "_last_drift_check", 0.0)
    monkeypatch.setattr(service, "_drift_thread", None)
    release, ran = threading.Event(), []

    def slow():
        ran.append(threading.current_thread().name)
        release.wait(5)
        return []
    p = types.SimpleNamespace(response=types.SimpleNamespace(check_drift=slow))
    t = time.perf_counter()
    service._drift_check(p)
    assert time.perf_counter() - t < 1.0
    monkeypatch.setattr(service, "_last_drift_check", 0.0)
    service._drift_check(p)                                        # still running: no second pass stacked
    release.set()
    service._drift_thread.join(5)
    assert ran == ["aegis-drift-check"]
