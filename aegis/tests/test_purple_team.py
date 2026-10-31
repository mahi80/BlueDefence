"""Purple-team benchmark as a CI gate, plus regressions for what its first runs found."""

from __future__ import annotations

import json
import tempfile
from datetime import timedelta

import pytest

from aegis.agents.orchestrator.walkers.campaign import EventStore, _path_key, campaign_summary
from aegis.eval.purple_team import CAMPAIGNS, Harness, run_all
from aegis.eval.purple_team.harness import Attacker, _denied_by_aegis, render
from aegis.eval.purple_team.scenarios import Campaign, Gate, Goal


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("LLM_BACKEND", "mock")
    monkeypatch.setenv("ACP_HOME", tempfile.mkdtemp())


# ------------------------------------------------------------ the gate --

def test_gated_campaigns_pass_with_auto_block_and_zero_collateral():
    results = run_all(modes=("auto",))
    table = render(results)
    failed = [r for r in results if r.gate_pass is False]
    assert not failed, table
    by = {r.campaign: r for r in results}
    # the rotating agent is caught and contained within a handful of requests, before anything sensitive
    r = by["rotating_sqli_agent"]
    assert r.first_malicious.step <= 6 and r.contained_at is not None and r.sensitive_reached == 0
    assert any(t.startswith("fp:ja4:") for t in r.enforced_targets)          # the whole pool, not one IP
    # the decoy touch is contained on the very next request
    assert by["honeytoken_touch"].contained_at.step == 2
    # customers only: nothing enforced, nothing malicious
    b = by["benign_customers"]
    assert not b.enforced_targets and not b.verdicts.get("malicious") and b.benign_requests >= 30
    assert all(r.p95_ms() < 2000 for r in results)


def test_human_approval_mode_is_measurably_slower_than_auto_block():
    auto = Harness(mode="auto").run(next(c for c in CAMPAIGNS if c.name == "rotating_sqli_agent"))
    human = Harness(mode="human", approval_latency_s=300).run(next(c for c in CAMPAIGNS if c.name == "rotating_sqli_agent"))
    assert auto.first_malicious.step == human.first_malicious.step        # detection is the same
    assert len(human.successes) > len(auto.successes) and human.sensitive_reached > auto.sensitive_reached
    assert human.gate_pass is None                                        # only the auto row is gated
    fast = Harness(mode="human", approval_latency_s=5).run(next(c for c in CAMPAIGNS if c.name == "rotating_sqli_agent"))
    assert fast.contained_at is not None                                  # a 5-second analyst does contain it


def test_known_gaps_are_reported_not_asserted():
    for name in ("bola_waf_logs_only",):
        c = next(x for x in CAMPAIGNS if x.name == name)
        assert c.gate is None
        r = Harness(mode="auto", benign=False).run(c)
        assert r.gate_pass is None and r.to_dict()["campaign"] == name


def test_low_and_slow_is_now_gated_and_caught():
    c = next(x for x in CAMPAIGNS if x.name == "low_and_slow")
    assert c.gate is not None                                            # promoted from a known gap
    r = Harness(mode="auto").run(c)                                      # with benign crowd for collateral
    assert r.gate_pass is True
    assert r.first_malicious is not None and r.first_malicious.investigated_by == "low_and_slow"
    assert r.contained_at is not None and r.sensitive_reached == 0
    assert not r.benign_blocked and not r.benign_challenged              # zero collateral


# ----------------------------------------- regressions the benchmark found --

def _ev(i, ip, path, at, *, ja4="t13d_shared", ua="Mozilla/5.0 (X11)", blocked, sig=""):
    return {"id": f"E{i}", "source_ip": ip, "url": path, "timestamp": at.isoformat(), "ja4": ja4, "user_agent": ua,
            "blocked": blocked, "attack_type": sig, "action": "block" if blocked else "allow"}


def test_customer_sharing_a_fingerprint_is_not_judged_by_the_attackers_retries():
    """A NAT customer with the attacker's browser JA4 used to inherit 'adaptive attacker' and get blocked."""
    from aegis.agents.orchestrator.adaptive import is_adaptive_attacker
    from datetime import datetime, timezone
    t0 = datetime(2026, 10, 22, 9, 0, tzinfo=timezone.utc)
    store = EventStore()
    evs = [_ev(i, f"203.0.113.{10 + i}", "/.env", t0 + timedelta(seconds=3 * i), blocked=True, sig="Sensitive file") for i in range(5)]
    for e in evs:
        store.add(e)
    customer = _ev(99, "198.51.100.200", "/api/v1/accounts/me", t0 + timedelta(seconds=16), blocked=False)
    cc = campaign_summary(customer, store)
    assert cc["adaptation"]["retries_after_stop"] >= 3 and cc["adaptation"]["current_is_retry"] is False
    assert not is_adaptive_attacker({**customer, "campaign_context": cc})
    attacker = _ev(100, "203.0.113.15", "/.env", t0 + timedelta(seconds=17), blocked=True, sig="Sensitive file")
    cc2 = campaign_summary(attacker, store)
    assert cc2["adaptation"]["current_is_retry"] is True and is_adaptive_attacker({**attacker, "campaign_context": cc2})
    assert set(cc2["adaptation"]["retry_ips"]) == {f"203.0.113.{10 + i}" for i in range(6)}


def test_retry_pairs_with_the_same_endpoint_template_not_another_clients_false_positive():
    from datetime import datetime, timezone
    t0 = datetime(2026, 10, 22, 9, 0, tzinfo=timezone.utc)
    store = EventStore()
    store.add(_ev(1, "203.0.113.10", "/api/v1/accounts/1001?v=0", t0, blocked=True, sig="SQLi"))
    store.add(_ev(2, "198.51.100.64", "/api/v1/accounts/me", t0 + timedelta(seconds=1), blocked=True, sig="XSS"))   # a customer's FP
    retry = _ev(3, "203.0.113.11", "/api/v1/accounts/1002?v=1", t0 + timedelta(seconds=3), blocked=True, sig="SQLi")
    cc = campaign_summary(retry, store, min_events=2)
    assert cc["adaptation"]["retry_ips"] == ["203.0.113.10", "203.0.113.11"]      # the FP customer's IP is not in the pool
    assert _path_key("/api/v1/accounts/1002?v=1") == "/api/v1/accounts/{n}" and _path_key("/api/v1/accounts/me") == "/api/v1/accounts/me"


def test_honeytoken_chain_acts_on_the_client_fingerprint():
    from aegis.agents.deception.honeytoken_monitor import HoneytokenMonitor
    alert = {"id": "H1", "source_ip": "198.51.100.10", "url": "/admin-internal-debug", "payload": "GET /admin-internal-debug",
             "ja4": "t13d_agent", "user_agent": "python-httpx/0.27", "user_id": "anonymous"}
    chain = HoneytokenMonitor().build_chain(alert)
    targets = {(a.action_type, a.target) for a in chain.recommended_actions}
    assert ("block", "198.51.100.10") in targets and ("block", "fp:ja4:t13d_agent;ua:python-httpx%2F0.27") in targets
    browser = HoneytokenMonitor().build_chain({**alert, "user_agent": "Mozilla/5.0 (X11)"})
    assert not any(a.target.startswith("fp:") for a in browser.recommended_actions)


# --------------------------------------------------------------- harness --

def test_attacker_adapts_and_gives_up_and_enforcement_matching():
    c = Campaign("t", goals=(Goal("g", "/x", variants=("a", "b", "c"), waf_catches=(True, True, False)),),
                 ip_pool=("203.0.113.1", "203.0.113.2"), user_agents=("u1", "u2"), ja4="j", gate=Gate(5, 5), max_retries=50)
    at = Attacker(c)
    a1 = at.next_attempt(1, 0.0)
    assert a1.waf_caught and a1.ip == "203.0.113.1" and a1.ua == "u1"
    a1.reached_app = False
    assert at.observe(a1) == c.retry_gap_s
    a2 = at.next_attempt(2, 3.0)
    assert a2.ip == "203.0.113.2" and a2.ua == "u2" and a2.variant == "b" and a2.is_retry
    n = 0
    while not at.done:
        x = at.next_attempt(3 + n, 6.0 + 3 * n)
        x.aegis_denied = "block"
        at.observe(x)
        n += 1
    assert at.gave_up and n == 10                                         # GIVE_UP_AFTER consecutive AEGIS denials

    class R:
        def __init__(self, target, action="block", dry=False, conn="cloudflare"):
            self.target, self.action_type, self.dry_run, self.connector = target, action, dry, conn
    rs = [R("203.0.113.0/24"), R("fp:ja4:j;ua:u1", "challenge"), R("10.0.0.1", dry=True), R("198.51.100.5", conn="log")]
    assert _denied_by_aegis(rs, "203.0.113.77", None, "") == "block"
    assert _denied_by_aegis(rs, "192.0.2.1", "j", "u1") == "challenge" and _denied_by_aegis(rs, "192.0.2.1", "j", "u2") == ""
    assert _denied_by_aegis(rs, "10.0.0.1", None, "") == "" and _denied_by_aegis(rs, "198.51.100.5", None, "") == ""


def test_results_serialise(tmp_path):
    r = Harness(mode="auto", benign=False).run(next(c for c in CAMPAIGNS if c.name == "honeytoken_touch"))
    d = r.to_dict()
    json.dumps(d)
    assert d["detected_step"] == 1 and d["detected_by"] == "deception" and d["gate_pass"] is True


# ------------------------------------------------- credential stuffing --

def _login(i, ip, ua, at, *, ja4=None, method="POST", path="/login"):
    e = {"id": f"L{i}", "source_ip": ip, "url": path, "http_method": method, "timestamp": at.isoformat(),
         "user_agent": ua, "blocked": False, "action": "allow"}
    if ja4:
        e["ja4"] = ja4
    return e


def _burst_after(events, current):
    store = EventStore()
    for e in events:
        store.add(e)
    return campaign_summary(current, store, min_events=1)


def test_auth_burst_fires_on_one_client_and_follows_its_fingerprint():
    from datetime import datetime, timezone
    from aegis.agents.orchestrator.auth_abuse import auth_burst_chain, is_auth_burst
    t0 = datetime(2026, 10, 22, 9, 0, tzinfo=timezone.utc)
    evs = [_login(i, f"203.0.113.{10 + i % 3}", "okhttp/4.12", t0 + timedelta(seconds=i), ja4="t13d_bot") for i in range(8)]
    cur = _login(99, "203.0.113.10", "okhttp/4.12", t0 + timedelta(seconds=8), ja4="t13d_bot")
    cc = _burst_after(evs, cur)
    assert cc["auth_burst"]["attempts"] == 9 and cc["auth_burst"]["distinct_ips"] == 3
    a = {**cur, "campaign_context": cc}
    assert is_auth_burst(a)
    chain = auth_burst_chain(a)
    acts = {(x.action_type, x.target) for x in chain.recommended_actions}
    assert ("throttle", "203.0.113.10") in acts and ("challenge", "fp:ja4:t13d_bot;ua:okhttp%2F4.12") in acts
    assert not any(x.action_type == "block" for x in chain.recommended_actions) and chain.verdict == "malicious"


def test_auth_burst_ignores_nat_customers_page_loads_and_a_human_retyping():
    from datetime import datetime, timezone
    from aegis.agents.orchestrator.auth_abuse import is_auth_burst
    t0 = datetime(2026, 10, 22, 9, 0, tzinfo=timezone.utc)
    nat = "198.51.100.200"
    # twelve customers behind one branch NAT log in within a minute — different browsers
    evs = [_login(i, nat, f"Mozilla/5.0 build-{i}", t0 + timedelta(seconds=4 * i)) for i in range(12)]
    cur = _login(99, nat, "Mozilla/5.0 build-3", t0 + timedelta(seconds=50))
    assert not is_auth_burst({**cur, "campaign_context": _burst_after(evs, cur)})
    # a bot hammering GET /login (page loads) is not an auth submission
    gets = [_login(i, "203.0.113.5", "curl/8", t0 + timedelta(seconds=i), method="GET") for i in range(12)]
    cur = _login(99, "203.0.113.5", "curl/8", t0 + timedelta(seconds=12), method="GET")
    assert not is_auth_burst({**cur, "campaign_context": _burst_after(gets, cur)})
    # one person retyping a password four times
    tries = [_login(i, "203.0.113.6", "Mozilla/5.0 (Mac)", t0 + timedelta(seconds=10 * i)) for i in range(4)]
    cur = _login(99, "203.0.113.6", "Mozilla/5.0 (Mac)", t0 + timedelta(seconds=45))
    assert not is_auth_burst({**cur, "campaign_context": _burst_after(tries, cur)})

def test_model_selection_comes_from_the_callers_environment(monkeypatch):
    from aegis.eval.purple_team.harness import model_env, model_label
    monkeypatch.delenv("LLM_BACKEND", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-should-not-be-used")
    assert model_env() == {"LLM_BACKEND": "mock", "ANTHROPIC_API_KEY": "", "OPENAI_API_KEY": ""} and model_label() == "mock"
    monkeypatch.setenv("LLM_BACKEND", "local")
    monkeypatch.setenv("AEGIS_MODEL", "/runs/triage-qwen3-8b-public-v4")
    monkeypatch.setenv("AEGIS_LOCAL_4BIT", "1")
    env = model_env()
    assert env["LLM_BACKEND"] == "local" and env["AEGIS_MODEL"].endswith("public-v4") and env["AEGIS_LOCAL_4BIT"] == "1"
    assert model_label() == "local:/runs/triage-qwen3-8b-public-v4"
