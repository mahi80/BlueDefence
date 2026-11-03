"""Rest of the reach group (code review 2026-11-03, W5, W6, W12, W13)."""

from __future__ import annotations

import pytest

from aegis.agents.perimeter.tools import _host_is_internal, ssrf_probe
from aegis.agents.response.connectors.base import (
    STATUS_EXPIRED,
    STATUS_FAILED,
    STATUS_ROLLBACK_FAILED,
    CannotUndo,
    Connector,
    ConnectorError,
    canonical_target,
)
from aegis.agents.response.connectors.http import HttpResult, call
from aegis.agents.shared.evidence_chain import RecommendedAction


class _Vendor(Connector):
    """A WAF with one IP set: apply adds, rollback deletes; ``down`` makes DELETE fail."""
    name = "wafx"
    actions = frozenset({"block", "isolate"})

    def __init__(self, clock):
        super().__init__(dry_run=False, default_ttl_sec=900, clock=clock)
        self.rules: dict[str, str] = {}
        self.down = False
        self.n = 0

    def _do_apply(self, action, key, ttl):
        self.n += 1
        self.rules[key] = f"rule-{self.n}"
        return f"rule-{self.n}", "added", key

    def _do_rollback(self, receipt):
        if receipt.action_type == "isolate":
            raise CannotUndo("isolate has no undo here")
        if self.down:
            raise ConnectorError("HTTP 503 on DELETE")
        self.rules.pop(receipt.rollback_token, None)
        return "deleted"


def _act(target, t="block"):
    return RecommendedAction(action_type=t, target=target, reasoning="r", requires_hitl=False, confidence=0.9)


# ---- W5: a failed TTL rollback is retried, and a later apply does not orphan the rule ------------------------

def test_failed_rollback_is_retried_with_backoff():
    now = [1000.0]
    v = _Vendor(lambda: now[0])
    r = v.apply(_act("203.0.113.7"))
    v.down = True
    now[0] += 901
    (rb,) = v.sweep_expired()
    assert rb.status == STATUS_ROLLBACK_FAILED and v.rules                # still at the vendor, still tracked
    assert v.sweep_expired() == []                                        # backoff: not retried immediately
    v.down = False
    now[0] += 61
    (rb,) = v.sweep_expired()
    assert rb.status == STATUS_EXPIRED and not v.rules and rb is r


def test_apply_after_a_failed_rollback_keeps_the_existing_rule():
    now = [1000.0]
    v = _Vendor(lambda: now[0])
    v.apply(_act("203.0.113.7"))
    v.down = True
    now[0] += 901
    v.sweep_expired()
    r2 = v.apply(_act("203.0.113.7"))
    assert len(v.rules) == 1 and r2.status == "renewed" and not r2.error  # one rule, nothing orphaned
    v.down = False
    now[0] += 901
    assert [x.status for x in v.sweep_expired()] == [STATUS_EXPIRED] and not v.rules


def test_action_with_no_undo_is_not_retried():
    v = _Vendor(lambda: 1000.0)
    r = v.apply(_act("host-7", "isolate"))
    assert v.rollback(r).status == STATUS_FAILED


# ---- W6: one address, one key ---------------------------------------------------------------------------

@pytest.mark.parametrize("a,b", [("198.18.7.4", "198.18.7.4/32"), ("198.18.7.4", "::ffff:198.18.7.4"),
                                 ("Evil.Example.", "evil.example"), ("2001:db8::1", "2001:DB8:0::1/128")])
def test_spellings_of_one_target_share_a_key(a, b):
    assert canonical_target(a) == canonical_target(b)


def test_auto_then_approved_slash32_is_one_receipt():
    now = [1000.0]
    v = _Vendor(lambda: now[0])
    v.apply(_act("198.18.7.4"))
    r2 = v.apply(_act("198.18.7.4/32"), approver="ciso", ttl_sec=0)       # approved, permanent
    now[0] += 901
    assert v.sweep_expired() == [] and v.rules and r2.expires_at is None  # the TTL no longer deletes the approved block


# ---- W12: numeric host spellings --------------------------------------------------------------------------

@pytest.mark.parametrize("host", ["2852039166", "0xa9fea9fe", "127.1", "169.254.169.254.", "0177.0.0.1",
                                  "::ffff:169.254.169.254", "0x7f000001"])
def test_numeric_spellings_of_internal_hosts_are_internal(host):
    assert _host_is_internal(host)[0]


@pytest.mark.parametrize("host", ["example.com", "8.8.8.8", "999.1.1.1", "1.2.3"])
def test_external_hosts_stay_external(host):
    assert not _host_is_internal(host)[0]


def test_ssrf_probe_catches_a_decimal_metadata_url():
    assert ssrf_probe("u=http://2852039166/latest/meta-data/").data["targets"]


# ---- W13: Retry-After is capped ----------------------------------------------------------------------------

def test_huge_retry_after_fails_fast_instead_of_sleeping(monkeypatch):
    slept: list[float] = []
    t = lambda *a: HttpResult(429, {"error": "slow down"}, {"Retry-After": "86400"})
    with pytest.raises(ConnectorError, match="86400"):
        call(t, "DELETE", "https://waf.example/rules/1", sleep=slept.append, retries=3)
    assert slept == []


def test_small_retry_after_is_honoured(monkeypatch):
    monkeypatch.setenv("AEGIS_HTTP_MAX_RETRY_AFTER", "30")
    slept: list[float] = []
    replies = iter([HttpResult(429, {}, {"Retry-After": "5"}), HttpResult(200, {"ok": True}, {})])
    assert call(lambda *a: next(replies), "GET", "https://waf.example/x", sleep=slept.append).ok
    assert slept == [5.0]
