"""TLS / user-agent consistency: a browser user agent on a handshake no browser makes.

Fixtures are sample data (``ingest/fixtures/tls_spoofing.jsonl``, ``ja4_reference.sample.jsonl``):
RFC 5737 IPs, ``.example`` hosts, invented JA4 values.
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

import pytest

from aegis.agents.orchestrator.auth_abuse import auth_burst_chain, is_auth_burst
from aegis.agents.orchestrator.spoofed_client import (
    aegis_enforcement,
    is_spoofed_client,
    spoofed_client_chain,
)
from aegis.agents.orchestrator.swarm import SwarmOrchestrator
from aegis.agents.orchestrator.walkers.campaign import (
    EventStore,
    attach_campaign_context,
    campaign_summary,
)
from aegis.agents.response.autonomy import _narrow_external
from aegis.agents.shared.client_actions import client_actions
from aegis.agents.shared.fingerprint import parse_target
from aegis.agents.shared.tls_client import (
    TlsEstate,
    automation_product,
    claimed_browser,
    load_reference,
    parse_ja4,
    spoofed_browser,
)
from aegis.ingest import WafConsumer

FIXTURES = Path(__file__).resolve().parents[1] / "ingest" / "fixtures"
CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
FIREFOX = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0"
CHROME_JA4 = "t13d1516h2_000000000001_000000000a01"
SPOOF_JA4 = "t13d1810h1_5c2a8e7d1f3b_9e4b6a0c2d71"        # http/1.1 before h2
AGENT_JA4 = "t13d1312h2_e8f1e7e78f70_0aaa1111bbbb"        # HTTP/2-capable library: browser-shaped
MIDDLEBOX_JA4 = "t13d2214h1_7d3f0b9a6e21_1a8c4e2f9b05"
STAFF = (CHROME, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/129.0.0.0 Safari/537.36",
         "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0", FIREFOX)
T0 = datetime(2026, 10, 22, 9, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "AEGIS_ENFORCEMENT_MODE", "AEGIS_AUTO_BLOCK", "AEGIS_FP_ALLOW",
              "AEGIS_JA4_DB", "AEGIS_WAF_VENDOR", "AEGIS_SOAR_VENDOR"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("LLM_BACKEND", "mock")
    monkeypatch.setenv("ACP_HOME", tempfile.mkdtemp())


# ---------------------------------------------------------------- parsing --

def test_ja4_a_section_is_parsed_and_junk_is_not():
    j = parse_ja4("t13d1516h2_8daaf6152771_02713d6af862")
    assert (j.transport, j.version, j.sni, j.ciphers, j.extensions, j.alpn) == ("tcp", "13", True, 15, 16, "h2")
    q = parse_ja4("q13d0310h3_55b375c5d22e_cd85d2d88918")
    assert q.transport == "quic" and q.alpn == "h3"
    for bad in ("", "t13d_bot", "t13d1516h2_xyz_02713d6af862", None, 42, "t13d1516h2_8daaf6152771"):
        assert parse_ja4(bad) is None


def test_browser_claims_by_engine_family():
    assert claimed_browser(CHROME).family == "chromium" and claimed_browser(CHROME).major == 130
    edge = claimed_browser(STAFF[2])
    assert (edge.family, edge.product, edge.major) == ("chromium", "edge", 130)
    assert claimed_browser(FIREFOX).family == "firefox"
    safari = claimed_browser("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
                             "Version/17.5 Safari/605.1.15")
    assert (safari.family, safari.major) == ("webkit", 17)
    # Chrome on iOS runs on WebKit's network stack, not Chromium's
    ios = claimed_browser("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
                          "CriOS/130.0 Mobile/15E148 Safari/604.1")
    assert (ios.family, ios.product) == ("webkit", "chrome-ios")
    for not_a_claim in ("python-httpx/0.27", "okhttp/4.12", "", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                        "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)"):
        assert claimed_browser(not_a_claim) is None
    assert automation_product("partner-sync/3.2 (python-httpx/0.27)") == "partner-sync"
    assert automation_product(CHROME) == "" and automation_product("") == ""


# ------------------------------------------------------------- structure --

@pytest.mark.parametrize("ja4,strength,why", [
    (SPOOF_JA4, "strong", "http/1.1 offered before h2"),
    ("t13d161600_000000000005_000000000a05", "strong", "no ALPN"),
    ("t12d1516h2_000000000006_000000000a06", "strong", "TLS 1.3 not offered"),
    ("t13d1504h2_000000000007_000000000a07", "strong", "4 TLS extensions"),
    ("t13d3416h2_000000000008_000000000a08", "weak", "34 cipher suites"),
    ("t13i1516h2_000000000009_000000000a09", "weak", "no SNI"),
    ("t13i3416h2_00000000000a_000000000a0a", "strong", "no SNI"),       # two half-signals add up
])
def test_structural_signals(ja4, strength, why):
    c = TlsEstate().assess(ja4, CHROME)
    assert c.consistent is False and c.strength == strength and any(why in r for r in c.reasons), c


def test_a_real_browser_handshake_is_consistent():
    for ja4 in (CHROME_JA4, "t13d1715h2_000000000002_000000000a02", "q13d0310h3_55b375c5d22e_cd85d2d88918"):
        c = TlsEstate().assess(ja4, CHROME)
        assert c.consistent is True and c.strength == "" and not c.mismatch
    assert TlsEstate().assess(SPOOF_JA4, "python-httpx/0.27") is None          # no browser claimed → no question
    assert TlsEstate().assess("not-a-ja4", CHROME) is None


# --------------------------------------------------------------- learned --

def test_an_http2_library_is_caught_once_honest_automation_introduces_it():
    e = TlsEstate()
    assert e.assess(AGENT_JA4, CHROME).consistent is True                     # browser-shaped, nothing known yet
    e.observe(AGENT_JA4, "partner-sync/3.2 (python-httpx/0.27)", "198.51.100.150", benign=True)
    assert e.assess(AGENT_JA4, CHROME).consistent is True                     # one IP is not enough
    e.observe(AGENT_JA4, "partner-sync/3.2 (python-httpx/0.27)", "198.51.100.151", benign=True)
    c = e.assess(AGENT_JA4, CHROME)
    assert c.mismatch and c.observed == "library" and "partner-sync" in c.reasons[0]


def test_hostile_traffic_never_teaches_the_model():
    e = TlsEstate()
    for i in range(5):
        e.observe(AGENT_JA4, "partner-sync/3.2", f"203.0.113.{i}", benign=False)
        e.observe(MIDDLEBOX_JA4, STAFF[i % 4], "203.0.113.9", benign=False)
    assert e.learned(AGENT_JA4) == {} and e.benign_ips(AGENT_JA4) == set()
    assert e.assess(MIDDLEBOX_JA4, CHROME).mismatch


def test_a_tls_inspecting_middlebox_is_learned_from_its_many_browsers_and_never_a_spoofer():
    e = TlsEstate()
    for ua in STAFF[:2]:
        e.observe(MIDDLEBOX_JA4, ua, "198.51.100.230", benign=True)
    # cold start: the proxy's handshake looks like a script until three different browsers have
    # come through it (they would pass a challenge meanwhile — documented, not hidden)
    assert e.assess(MIDDLEBOX_JA4, STAFF[3]).mismatch
    e.observe(MIDDLEBOX_JA4, STAFF[2], "198.51.100.230", benign=True)
    c = e.assess(MIDDLEBOX_JA4, STAFF[3])
    assert c.consistent and c.observed == "middlebox" and "3 different browser user agents" in c.reasons[0]
    # a learned shared JA4 also overrides a library association (customers outnumber one tool)
    e.observe(MIDDLEBOX_JA4, "site-monitor/2.0", "198.51.100.5", benign=True)
    e.observe(MIDDLEBOX_JA4, "site-monitor/2.0", "198.51.100.6", benign=True)
    assert e.assess(MIDDLEBOX_JA4, CHROME).consistent


def test_estate_memory_is_bounded():
    e = TlsEstate(max_ja4=3)
    for i in range(6):
        e.observe(f"t13d1516h2_00000000000{i}_000000000a0{i}", CHROME, f"198.51.100.{i}", benign=True)
    assert e.stats()["ja4_known"] == 3


# ------------------------------------------------------------- reference --

def test_reference_file_labels_override_learning(tmp_path):
    ref = load_reference(FIXTURES / "ja4_reference.sample.jsonl")
    assert len(ref) == 7 and ref[MIDDLEBOX_JA4]["label"] == "middlebox"
    e = TlsEstate(reference=ref)
    assert e.assess(MIDDLEBOX_JA4, CHROME).consistent                          # labelled: no cold start
    lib = e.assess(AGENT_JA4, CHROME)
    assert lib.mismatch and lib.observed == "library" and "reference:" in lib.reasons[0]
    # a Firefox TLS stack under a Chrome user agent
    cross = e.assess("t13d1715h2_000000000002_000000000a02", CHROME)
    assert cross.mismatch and "firefox TLS stack" in cross.reasons[0]
    assert e.assess("t13d1715h2_000000000002_000000000a02", FIREFOX).consistent
    bad = tmp_path / "bad.jsonl"
    bad.write_text("not json\n" + "\n".join(json.dumps(r) for r in (
        {"ja4": "t13d_bot", "label": "library"}, {"ja4": SPOOF_JA4, "label": "toaster"},
        {"ja4": SPOOF_JA4, "label": "library", "name": "ok"})) + "\n", encoding="utf-8")
    assert list(load_reference(bad)) == [SPOOF_JA4]
    assert load_reference(tmp_path / "missing.jsonl") == {}


# ------------------------------------------------------ campaign context --

def _cf(i, *, ip, ja4, ua, path, at, method="GET", action="allow", desc="", source=""):
    return json.dumps({"RayID": f"7e{i:014x}", "ClientIP": ip, "ClientRequestHost": "netbanking.bank.example",
                       "ClientRequestMethod": method, "ClientRequestPath": path, "ClientRequestUserAgent": ua,
                       "Datetime": at.isoformat().replace("+00:00", "Z"), "Action": action, "Source": source,
                       "Description": desc, "RuleID": "managed-1" if desc else "", "JA4": ja4})


def _alerts(lines):
    return list(WafConsumer().iter_alerts(lines=lines))


def test_campaign_context_judges_before_learning_and_learns_only_untouched_requests():
    store = EventStore()
    a = _alerts([_cf(1, ip="203.0.113.10", ja4=SPOOF_JA4, ua=CHROME, path="/", at=T0)])[0]
    out = attach_campaign_context(a, store)
    assert out["tls_client"]["consistent"] is False and out["tls_client"]["strength"] == "strong"
    assert "tls_client" not in a                                                # the received alert is untouched
    blocked = _alerts([_cf(2, ip="203.0.113.11", ja4=AGENT_JA4, ua="partner-sync/3.2", path="/x", at=T0,
                           action="block", desc="SQLi", source="firewallManaged")])[0]
    attach_campaign_context(blocked, store)
    assert store.tls.benign_ips(AGENT_JA4) == set()                             # a blocked request teaches nothing
    assert store.tls.benign_ips(SPOOF_JA4) == {"203.0.113.10"}


# ----------------------------------------------------------- fast path --

def _run(lines, orch):
    swarm = SwarmOrchestrator(orch, event_store=EventStore(window_min=60))
    return [(a, swarm.handle(a)) for a in _alerts(lines)]


@pytest.fixture
def orch(tmp_path):
    from aegis.eval.run import _build_orchestrator
    return _build_orchestrator(tmp_path / "audit.jsonl")


def test_sample_fixture_spoofer_is_challenged_and_customers_staff_and_partner_are_not(orch):
    lines = (FIXTURES / "tls_spoofing.jsonl").read_text(encoding="utf-8").splitlines()
    out = _run(lines, orch)
    by_ip: dict[str, list] = {}
    for a, c in out:
        by_ip.setdefault(a["source_ip"], []).append((a, c))
    spoof = [c for ip, rows in by_ip.items() if ip.startswith("203.0.113.") for _, c in rows if c.investigated_by == "spoofed_client"]
    assert len(spoof) == 3                                     # the stopped probe, the login, the stopped SQLi
    first = spoof[0]
    assert first.verdict == "suspicious" and not any(x.action_type == "block" for x in first.recommended_actions)
    ch = [x for x in first.recommended_actions if x.action_type == "challenge"]
    assert len(ch) == 1 and parse_target(ch[0].target) == ("ja4", SPOOF_JA4, CHROME) and not ch[0].requires_hitl
    assert any(x.action_type == "escalate" for x in first.recommended_actions)
    login = spoof[1]
    assert login.confidence == pytest.approx(0.75) and not any(x.action_type == "escalate" for x in login.recommended_actions)
    assert first.metadata["tls_client"]["observed"] == "library"
    # nobody else: real customers (incl. a WAF false positive), the proxy staff (incl. their login
    # and false positive), the partner's integration
    for ip in [x for x in by_ip if not x.startswith("203.0.113.")]:
        for a, c in by_ip[ip]:
            assert c.investigated_by != "spoofed_client", (ip, a.get("url"))
            t = a.get("tls_client") or c.metadata.get("tls_client")
            if ip == "198.51.100.230" and t and a.get("blocked"):
                assert t["consistent"] is True and t["observed"] == "middlebox"
    assert all("tls_client" not in c.metadata for a, c in by_ip["198.51.100.150"])   # honest UA: no claim judged


def test_aegis_own_enforcement_in_the_waf_log_is_not_a_new_attack(orch):
    lines = [_cf(1, ip="203.0.113.20", ja4=SPOOF_JA4, ua=CHROME, path="/api/v1/accounts", at=T0,
                 action="managed_challenge", desc="aegis challenge fp 1a2b3c4d", source="firewallCustom")]
    a = _alerts(lines)[0]
    assert aegis_enforcement(a)
    out = _run(lines, orch)
    assert out[0][1].investigated_by != "spoofed_client"


def test_consistent_browser_waf_false_positive_and_login_do_not_fire(orch):
    lines = [_cf(1, ip="198.51.100.70", ja4=CHROME_JA4, ua=CHROME, path="/api/v1/statements", at=T0, action="block",
                 desc="XSS (managed rule)", source="firewallManaged"),
             _cf(2, ip="198.51.100.70", ja4=CHROME_JA4, ua=CHROME, path="/login", method="POST", at=T0 + timedelta(seconds=5))]
    assert not any(c.investigated_by == "spoofed_client" for _, c in _run(lines, orch))


def test_fast_path_needs_a_strong_mismatch_and_intent():
    base = {"id": "a", "source_ip": "203.0.113.30", "ja4": SPOOF_JA4, "user_agent": CHROME, "url": "/", "http_method": "GET",
            "tls_client": {"ja4": SPOOF_JA4, "claimed": "Chrome 130", "consistent": False, "strength": "strong", "reasons": ["x"]}}
    assert not is_spoofed_client(base)                                          # a quiet page view: evidence only
    assert is_spoofed_client({**base, "blocked": True, "attack_type": "SQL injection"})
    assert is_spoofed_client({**base, "http_method": "POST", "url": "/oauth2/token"})
    weak = {**base, "blocked": True, "tls_client": {**base["tls_client"], "strength": "weak"}}
    assert not is_spoofed_client(weak) and spoofed_browser(weak) is None


def test_allowlisted_spoofer_is_challenged_by_ip_only(monkeypatch):
    monkeypatch.setenv("AEGIS_FP_ALLOW", SPOOF_JA4)
    a = {"id": "a", "source_ip": "203.0.113.31", "ja4": SPOOF_JA4, "user_agent": CHROME, "url": "/login", "http_method": "POST",
         "tls_client": {"ja4": SPOOF_JA4, "claimed": "Chrome 130", "consistent": False, "strength": "strong", "reasons": ["x"]}}
    chain = spoofed_client_chain(a)
    assert [(x.action_type, x.target) for x in chain.recommended_actions] == [("challenge", "203.0.113.31")]


# -------------------------------------------------------- client actions --

def _hostile(ja4, ua, ident, tls=None):
    a = {"id": "h", "source_ip": "203.0.113.40", "ja4": ja4, "user_agent": ua, "campaign_context": {"identity": ident}}
    if tls is not None:
        a["tls_client"] = tls
    return a


def test_client_actions_challenge_a_spoofed_browser_on_the_exact_pair_never_block_it():
    tls = {"ja4": SPOOF_JA4, "claimed": "Chrome 130", "consistent": False, "strength": "strong",
           "reasons": ["http/1.1 offered before h2"]}
    ev: list = []
    acts = client_actions(_hostile(SPOOF_JA4, CHROME, {"distinct_user_agents": 1, "benign_ips_sharing_client": 4}, tls),
                          confidence=0.95, why="test", evidence=ev)
    assert [(x.action_type, x.target.split(";")[0]) for x in acts] == [("block", "203.0.113.40"), ("challenge", f"fp:ja4:{SPOOF_JA4}")]
    assert parse_target(acts[1].target)[2] == CHROME and any("TLS handshake is not a browser's" in e.signal for e in ev)
    # without the mismatch the same browser user agent is held back exactly as before
    acts = client_actions(_hostile(SPOOF_JA4, CHROME, {"distinct_user_agents": 1}), confidence=0.95, why="test")
    assert [x.target for x in acts] == ["203.0.113.40"]
    # and auto-block still refuses any Mozilla/ composite — the spoofed path only ever challenges
    assert _narrow_external(f"fp:ja4:{SPOOF_JA4};ua:Mozilla%2F5.0")[0] is False


def test_composite_and_bare_fingerprint_have_their_own_collateral_measures():
    # a partner shares the TLS stack but not the user agent: the composite block is safe…
    acts = client_actions(_hostile(AGENT_JA4, "python-httpx/0.27", {"distinct_user_agents": 1, "benign_ips_sharing_fingerprint": 2,
                                                                      "benign_ips_sharing_client": 0}), confidence=0.95, why="t")
    assert any(x.action_type == "block" and x.target.startswith("fp:") for x in acts)
    # …a bare-fingerprint challenge is not, whether the partner was seen in this window or only earlier
    for ident in ({"distinct_user_agents": 3, "benign_ips_sharing_fingerprint": 2},
                  {"distinct_user_agents": 3, "benign_ips_sharing_fingerprint": 0, "known_benign_ips_for_fingerprint": 2}):
        ev: list = []
        acts = client_actions(_hostile(AGENT_JA4, "scanner/1", ident), confidence=0.95, why="t", evidence=ev)
        assert not any(x.target.startswith("fp:") for x in acts) and "this window or earlier" in ev[0].signal
    # the exact client seen benignly elsewhere holds the composite back too
    acts = client_actions(_hostile(AGENT_JA4, "python-httpx/0.27", {"distinct_user_agents": 1, "benign_ips_sharing_client": 2}),
                          confidence=0.95, why="t")
    assert not any(x.target.startswith("fp:") for x in acts)


def test_identity_reports_the_estates_longer_memory_minus_the_attackers_own_ips():
    store = EventStore(window_min=30)
    early = _alerts([_cf(i, ip=f"198.51.100.{150 + i}", ja4=AGENT_JA4, ua="partner-sync/3.2", path="/sync",
                         at=T0 - timedelta(minutes=45)) for i in range(2)])
    for a in early:
        attach_campaign_context(a, store)
    now = _alerts([_cf(10 + i, ip="203.0.113.50", ja4=AGENT_JA4, ua=f"scanner/{i}", path="/.env", at=T0 + timedelta(seconds=i),
                       action="block", desc="Sensitive file", source="firewallManaged") for i in range(3)])
    for a in now[:-1]:
        attach_campaign_context(a, store)
    cc = campaign_summary(now[-1], store, min_events=1)
    assert cc["identity"]["benign_ips_sharing_fingerprint"] == 0                # outside the 30-minute window
    assert cc["identity"]["known_benign_ips_for_fingerprint"] == 2              # the estate remembers


# ------------------------------------------------------------ auth burst --

def _login_lines(n, *, ja4, ua, ip_of, start=0):
    return [_cf(100 + start + i, ip=ip_of(i), ja4=ja4, ua=ua, path="/login", method="POST", at=T0 + timedelta(seconds=5 * i))
            for i in range(n)]


def _burst(lines):
    store = EventStore()
    out = [attach_campaign_context(a, store, min_events=1) for a in _alerts(lines)]
    return out[-1]


def test_customers_on_one_browser_build_logging_in_are_a_population_not_one_client():
    last = _burst(_login_lines(10, ja4=CHROME_JA4, ua=CHROME, ip_of=lambda i: f"198.51.100.{60 + i}"))
    assert last["campaign_context"]["auth_burst"]["client"] == "ip+ua" and not is_auth_burst(last)


def test_a_spoofed_browser_stuffing_from_a_pool_is_one_client_and_challenged_on_the_pair():
    last = _burst(_login_lines(10, ja4=SPOOF_JA4, ua=CHROME, ip_of=lambda i: f"203.0.113.{10 + i % 4}"))
    b = last["campaign_context"]["auth_burst"]
    assert b["client"] == "fingerprint+ua" and b["attempts"] == 10 and is_auth_burst(last)
    acts = {(x.action_type, x.target) for x in auth_burst_chain(last).recommended_actions}
    assert ("challenge", f"fp:ja4:{SPOOF_JA4};ua:{quote(CHROME, safe='')}") in acts


# ------------------------------------------------------------ purple team --

def test_purple_team_spoofing_campaigns_are_gated_and_need_the_tls_check(monkeypatch):
    from unittest import mock

    from aegis.eval.purple_team import CAMPAIGNS, Harness
    camp = {c.name: c for c in CAMPAIGNS}
    for name in ("spoofed_browser_agent", "spoofed_browser_http2", "slow_spoofed_stuffing"):
        r = Harness(mode="auto").run(camp[name])
        assert camp[name].gate is not None and r.gate_pass, (name, r.gate_reasons)
        assert r.contained_at.step <= 3 and len(r.successes) <= 1 and not r.benign_challenged and not r.benign_blocked
    with mock.patch("aegis.agents.shared.tls_client.TlsEstate.assess", return_value=None):
        r = Harness(mode="auto").run(camp["slow_spoofed_stuffing"])
    assert r.contained_at is None and len(r.successes) == 12                   # under the auth-burst rate: invisible
