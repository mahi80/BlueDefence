"""Low-and-slow fast path: one client mutating against a single endpoint, paced below the
retry-after-stop cadence so neither the adaptive nor the auth-burst fast path sees it.

Records are Cloudflare Logpush lines pushed through the real WAF consumer and swarm, so ingest
(JA4, action → blocked, query → url), long-window campaign accumulation, the fast path, routing and
the collateral-safe client actions are exercised together. IPs are RFC 5737 ranges; payloads are
abstract markers in the query string.
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aegis.agents.orchestrator.low_and_slow import MIN_STOPS, is_low_and_slow, low_and_slow_chain
from aegis.agents.orchestrator.swarm import SwarmOrchestrator
from aegis.agents.orchestrator.walkers.campaign import EventStore
from aegis.agents.shared.fingerprint import parse_target
from aegis.ingest import WafConsumer

AGENT_JA4 = "t13d1312h2_e8f1e7e78f70_0aaa1111bbbb"
BROWSER_JA4 = "t13d1516h2_8daaf6152771_02713d6af862"
SLOW = 150          # seconds between requests — above the adaptive retry window by design
T0 = datetime(2026, 10, 22, 9, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "AEGIS_ENFORCEMENT_MODE", "AEGIS_AUTO_BLOCK", "AEGIS_FP_ALLOW",
              "AEGIS_PROTECTED_TARGETS", "AEGIS_WAF_VENDOR", "AEGIS_SOAR_VENDOR",
              "AEGIS_LOWSLOW_WINDOW_MIN", "AEGIS_LOWSLOW_MIN_STOPS", "AEGIS_LOWSLOW_MIN_GAP_S"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("LLM_BACKEND", "mock")
    monkeypatch.setenv("ACP_HOME", tempfile.mkdtemp())


def _cf(i, *, ip, at, ua="python-httpx/0.27", ja4=AGENT_JA4, action="block", path="/api/v1/accounts",
        query="", desc="SQL injection (managed rule)"):
    rec = {"RayID": f"8e{i:014x}", "ClientIP": ip, "ClientRequestHost": "netbanking.bank.example",
           "ClientRequestMethod": "GET", "ClientRequestPath": path, "ClientRequestQuery": query,
           "ClientRequestUserAgent": ua, "Datetime": at.isoformat().replace("+00:00", "Z"),
           "Action": action, "Source": "firewallManaged" if action != "allow" else "",
           "Description": desc if action != "allow" else "", "RuleID": "managed-1" if action != "allow" else "",
           "JA4": ja4}
    return json.dumps(rec)


def _run(lines):
    from aegis.eval.run import _build_orchestrator
    orch = _build_orchestrator(Path(tempfile.mkdtemp()) / "audit.jsonl")
    swarm = SwarmOrchestrator(orch, event_store=EventStore(window_min=30))
    return [(a, swarm.handle(a)) for a in WafConsumer().iter_alerts(lines=lines)]


def grinder(n=4, *, ip="203.0.113.10", path="/api/v1/accounts", mutate=True, gap=SLOW):
    """One IP, blocked every time, a new payload marker on each attempt, slow."""
    return [_cf(i, ip=ip, at=T0 + timedelta(seconds=gap * i),
                query=f"?v=sqli-v{i if mutate else 0}", path=path) for i in range(n)]


# ------------------------------------------------------------ detection --

def test_low_and_slow_single_ip_mutation_is_caught():
    out = _run(grinder())
    hits = [(a, c) for a, c in out if c.investigated_by == "low_and_slow"]
    assert hits, "low-and-slow fast path never fired"
    assert out.index(hits[0]) == MIN_STOPS - 1          # fires exactly on the MIN_STOPS-th stop (3rd)
    a, chain = hits[-1]
    assert chain.verdict == "malicious" and chain.confidence >= 0.90
    s = chain.metadata["low_and_slow"]
    assert s["stops_on_endpoint"] >= MIN_STOPS and s["distinct_payloads"] >= 2 and s["sensitive"] is True
    assert s["median_gap_s"] == SLOW
    targets = {(x.action_type, x.target) for x in chain.recommended_actions}
    assert ("block", a["source_ip"]) in targets and any(act == "escalate" for act, _ in targets)
    fp_block = next(t for act, t in targets if act == "block" and t.startswith("fp:"))
    assert parse_target(fp_block) == ("ja4", AGENT_JA4, "python-httpx/0.27")


def test_fast_single_ip_mutation_is_adaptive_not_low_and_slow():
    # the same grind at machine speed is the adaptive fast path's job (dispatched first); the two
    # partition the speed axis, so low-and-slow must not also claim it
    out = _run(grinder(gap=3))
    assert any(c.investigated_by == "adaptive_attacker" for _, c in out)
    assert not any(c.investigated_by == "low_and_slow" for _, c in out)


# --------------------------------------------------------- no collateral --

def test_same_payload_without_mutation_does_not_fire():
    out = _run(grinder(n=5, mutate=False))                 # 5 blocks, one payload → not mutation
    assert not any(c.investigated_by == "low_and_slow" for _, c in out)


def test_scattered_benign_false_positives_do_not_fire():
    # a customer whose client trips a managed rule now and then, on different endpoints — never
    # ``MIN_STOPS`` mutations against one template, so never a campaign
    lines = [_cf(i, ip="198.51.100.77", at=T0 + timedelta(seconds=SLOW * i), ja4=BROWSER_JA4,
                 ua="Mozilla/5.0 (Windows NT 10.0)", path=p, query="?q=1", desc="XSS (managed rule)")
             for i, p in enumerate(("/", "/login", "/help", "/search", "/profile"))]
    out = _run(lines)
    assert not any(c.investigated_by == "low_and_slow" for _, c in out)
    assert not any(c.metadata.get("low_and_slow") for _, c in out)


def test_ip_rotation_is_not_counted_as_one_client():
    # the same grind spread across four IPs: no single source IP accumulates ``MIN_STOPS``, so the
    # per-IP accumulator never fires (slow IP-rotation is a documented gap, not a false negative here)
    lines = [_cf(i, ip=f"203.0.113.{10 + i}", at=T0 + timedelta(seconds=SLOW * i), query=f"?v=sqli-v{i}")
             for i in range(6)]
    out = _run(lines)
    assert not any(c.investigated_by == "low_and_slow" for _, c in out)


# --------------------------------------------------------- detector unit --

def _ctx(stops=3, payloads=3, gap=150.0, sensitive=True, current=True):
    return {"id": "A1", "source_ip": "203.0.113.10", "ja4": AGENT_JA4, "user_agent": "python-httpx/0.27",
            "campaign_context": {"low_and_slow": {
                "current_is_attack_stop": current, "stops_on_endpoint": stops, "distinct_payloads": payloads,
                "median_gap_s": gap, "sensitive": sensitive, "endpoint": "/api/v1/accounts", "span_minutes": 5.0}}}


@pytest.mark.parametrize("kw,fires", [
    ({}, True),
    ({"stops": MIN_STOPS - 1}, False),                 # one short of the threshold
    ({"payloads": 1}, False),                          # no mutation
    ({"gap": 5.0}, False),                             # too fast — that is adaptive's lane
    ({"current": False}, False),                       # the judged request is not itself a stop
])
def test_is_low_and_slow_thresholds(kw, fires):
    assert is_low_and_slow(_ctx(**kw)) is fires


def test_chain_is_malicious_with_escalate_and_no_context_is_inert():
    chain = low_and_slow_chain(_ctx())
    assert chain.verdict == "malicious"
    assert any(x.action_type == "escalate" and x.requires_hitl for x in chain.recommended_actions)
    assert is_low_and_slow({"id": "x"}) is False        # no campaign context → never fires
