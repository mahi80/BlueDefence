"""Adaptive AI-agent attacker: fingerprint across rotating IPs, retry-after-stop, tiered autonomy.

Scenarios are Cloudflare Logpush records pushed through the real WAF consumer and swarm, so the
ingest fields (JA4, action → blocked), campaign context, fast path, routing and connectors are all
exercised together. IPs are RFC 5737 documentation ranges; payload strings are abstract markers.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

from aegis.agents.orchestrator.swarm import SwarmOrchestrator
from aegis.agents.orchestrator.walkers.campaign import EventStore
from aegis.agents.response.agent import ResponseAgent
from aegis.agents.response.autonomy import AutonomyPolicy
from aegis.agents.response.connectors import ConnectorRegistry
from aegis.agents.response.connectors import mock_cloud_waf as m
from aegis.agents.response.connectors.cloud_waf import AwsWafConnector, CloudflareWafConnector
from aegis.agents.response.connectors.cloud_auth import AwsCredentials
from aegis.agents.response.connectors.waf import ImpervaWafConnector
from aegis.agents.response.connectors.mock_vendor import MockImperva
from aegis.agents.shared.evidence_chain import EvidenceChain, RecommendedAction
from aegis.agents.shared.fingerprint import client_fingerprint, parse_target
from aegis.ingest import WafConsumer

AGENT_JA4 = "t13d1312h2_e8f1e7e78f70_0aaa1111bbbb"
BROWSER_JA4 = "t13d1516h2_8daaf6152771_02713d6af862"
T0 = datetime(2026, 10, 22, 9, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "AEGIS_ENFORCEMENT_MODE", "AEGIS_AUTO_BLOCK", "AEGIS_FP_ALLOW",
              "AEGIS_PROTECTED_TARGETS", "AEGIS_WAF_VENDOR", "AEGIS_SOAR_VENDOR"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("LLM_BACKEND", "mock")
    monkeypatch.setenv("ACP_HOME", tempfile.mkdtemp())


def _cf(i: int, *, ip: str, at: datetime, ja4: str, ua: str, action: str, path: str, desc: str = "") -> str:
    return json.dumps({"RayID": f"8e{i:014x}", "ClientIP": ip, "ClientRequestHost": "netbanking.bank.example",
                       "ClientRequestMethod": "GET", "ClientRequestPath": path, "ClientRequestUserAgent": ua,
                       "Datetime": at.isoformat().replace("+00:00", "Z"), "Action": action, "Source": "firewallManaged",
                       "Description": desc, "RuleID": "r-1", "JA4": ja4})


def rotating_agent(n=8, *, rotate_ua=False, gap_s=4):
    """Blocked every time, back within seconds from the next IP in its pool with a changed request."""
    pool = ["203.0.113.11", "203.0.113.12", "198.51.100.13", "192.0.2.14"]
    return [_cf(i, ip=pool[i % len(pool)], at=T0 + timedelta(seconds=gap_s * i), ja4=AGENT_JA4,
                ua=f"agent-client/{i}" if rotate_ua else "python-httpx/0.27",
                action="block", path=f"/api/v1/accounts/{1000 + i}", desc=f"SQLi variant {i % 3}")
            for i in range(n)]


def patient_human(n=5):
    """Same IP, blocked, comes back ten minutes later each time."""
    return [_cf(100 + i, ip="203.0.113.50", at=T0 + timedelta(minutes=10 * i), ja4=BROWSER_JA4,
                ua="Mozilla/5.0 (X11; Linux x86_64)", action="block", path="/login", desc="SQLi")
            for i in range(n)]


def browser_crowd(n=8):
    """Many customers on the same browser build (same JA4), not stopped."""
    return [_cf(200 + i, ip=f"198.51.100.{60 + i}", at=T0 + timedelta(seconds=3 * i), ja4=BROWSER_JA4,
                ua="Mozilla/5.0 (Windows NT 10.0)", action="log", path="/", desc="")
            for i in range(n)]


def _run(lines, orch):
    swarm = SwarmOrchestrator(orch, event_store=EventStore(window_min=30))
    return [(a, swarm.handle(a)) for a in WafConsumer().iter_alerts(lines=lines)]


@pytest.fixture
def orch(tmp_path):
    from aegis.eval.run import _build_orchestrator
    return _build_orchestrator(tmp_path / "audit.jsonl")


# ------------------------------------------------------------ detection --

def test_rotating_agent_is_caught_and_followed_across_its_pool(orch):
    out = _run(rotating_agent(), orch)
    hits = [(a, c) for a, c in out if c.investigated_by == "adaptive_attacker"]
    assert hits, "adaptive fast path never fired"
    first_hit = out.index(hits[0])
    assert first_hit <= 4                                   # caught within the first handful of requests
    a, chain = hits[-1]
    assert chain.verdict == "malicious" and chain.confidence >= 0.95
    ident = chain.metadata["adaptive_attacker"]["identity"]      # the swarm folds context into a copy
    assert ident["distinct_source_ips"] == 4 and ident["fingerprint"] == f"ja4:{AGENT_JA4}"
    targets = {(x.action_type, x.target) for x in chain.recommended_actions}
    fp_block = next(t for act, t in targets if act == "block" and t.startswith("fp:"))
    assert parse_target(fp_block) == ("ja4", AGENT_JA4, "python-httpx/0.27")
    assert ("block", a["source_ip"]) in targets and any(act == "escalate" for act, _ in targets)


def test_ua_rotating_agent_gets_a_challenge_never_a_bare_fingerprint_block(orch):
    out = _run(rotating_agent(rotate_ua=True), orch)
    chain = [c for _, c in out if c.investigated_by == "adaptive_attacker"][-1]
    fp_actions = [(x.action_type, x.target) for x in chain.recommended_actions if x.target.startswith("fp:")]
    assert fp_actions == [("challenge", f"fp:ja4:{AGENT_JA4}")]


def test_patient_human_and_browser_crowd_do_not_trip_the_fast_path(orch):
    for lines in (patient_human(), browser_crowd()):
        out = _run(lines, orch)
        assert not any(c.investigated_by == "adaptive_attacker" for _, c in out)
        assert not any(c.metadata.get("adaptive_attacker") for _, c in out)


def test_anonymous_user_id_no_longer_lumps_unrelated_clients_into_one_campaign():
    store = EventStore()
    alerts = list(WafConsumer().iter_alerts(lines=browser_crowd(5) + patient_human(1)))
    keys = [store.add(a) for a in alerts]
    assert all(a["user_id"] == "anonymous" for a in alerts)
    assert not any(k.startswith("account:") for ks in keys for k in ks)


def test_fingerprint_extraction_prefers_tls_and_falls_back_to_header_order():
    assert client_fingerprint({"ja4": "x", "ja3": "y", "user_agent": "u"}).key == "ja4:x"
    aws = {"raw": {"httpRequest": {"headers": [{"name": n, "value": "v"} for n in ("Host", "User-Agent", "Accept")]}},
           "user_agent": "u"}
    fp = client_fingerprint(aws)
    assert fp.kind == "headers" and fp.strength == "headers"
    assert client_fingerprint({"user_agent": "only"}) is None


# ------------------------------------------------------ tiered autonomy --

def _chain(target, *, conf=0.95, verdict="malicious", concur=True):
    c = EvidenceChain(alert_id="A1", investigated_by="adaptive_attacker", verdict=verdict, confidence=conf,
                      recommended_actions=[RecommendedAction(action_type="block", target=target, reasoning="r",
                                                             requires_hitl=False, confidence=conf)])
    c.metadata["vote_concur"] = concur
    return c


@pytest.mark.parametrize("target,conf,verdict,concur,ok", [
    ("203.0.113.10", 0.95, "malicious", True, True),
    ("203.0.113.0/24", 0.95, "malicious", True, True),
    ("203.0.0.0/16", 0.95, "malicious", True, False),        # too wide
    ("10.1.2.3", 0.99, "malicious", True, False),            # internal
    ("100.64.0.9", 0.99, "malicious", True, False),          # carrier-grade NAT
    ("203.0.113.10", 0.85, "malicious", True, False),        # not confident enough
    ("203.0.113.10", 0.95, "suspicious", True, False),
    ("203.0.113.10", 0.95, "malicious", False, False),       # voter dissent
    (f"fp:ja4:{AGENT_JA4};ua:python-httpx%2F0.27", 0.95, "malicious", True, True),
    (f"fp:ja4:{AGENT_JA4}", 0.95, "malicious", True, False),  # bare JA4: challenge only
    ("fp:headers:abc;ua:x", 0.95, "malicious", True, False),
])
def test_auto_block_policy(target, conf, verdict, concur, ok):
    pol = AutonomyPolicy(mode="live")
    chain = _chain(target, conf=conf, verdict=verdict, concur=concur)
    got, why = pol.check(chain.recommended_actions[0], chain, protected=lambda t: False)
    assert got is ok, why


def test_auto_block_budget_protected_targets_and_allowlist(monkeypatch):
    pol = AutonomyPolicy(mode="live", max_per_hour=2)
    ch = _chain("203.0.113.10")
    for _ in range(2):
        assert pol.check(ch.recommended_actions[0], ch, protected=lambda t: False)[0]
        pol.take()
    assert pol.check(ch.recommended_actions[0], ch, protected=lambda t: False) == (False, "auto-block budget spent (2/h)")
    pol2 = AutonomyPolicy(mode="live")
    assert pol2.check(ch.recommended_actions[0], ch, protected=lambda t: True) == (False, "protected target")
    monkeypatch.setenv("AEGIS_FP_ALLOW", AGENT_JA4)
    fp = _chain(f"fp:ja4:{AGENT_JA4};ua:x")
    assert pol2.check(fp.recommended_actions[0], fp, protected=lambda t: False)[1] == "fingerprint on AEGIS_FP_ALLOW"


# ----------------------------------------------- end to end, per vendor --

def _cloudflare():
    srv = m.MockCloudflare(token="t")
    return srv, CloudflareWafConnector(api_token="t", zone_id="z", base_url=m.CF_BASE, transport=srv, dry_run=False)


def _aws():
    srv = m.MockAwsWaf()
    c = AwsWafConnector(ip_sets={"block": ("aegis-block", srv.create_ip_set("aegis-block"))}, region="ap-south-1",
                        rule_group=("aegis-fp", srv.create_rule_group("aegis-fp")),
                        credentials=AwsCredentials(m.AWS_KEY, m.AWS_SECRET), endpoint=m.AWS_ENDPOINT,
                        transport=srv, dry_run=False, sleep=lambda s: None)
    return srv, c


def test_live_auto_block_stops_the_whole_pool_on_cloudflare(orch):
    srv, cf = _cloudflare()
    agent = ResponseAgent(connectors=ConnectorRegistry([cf]), autonomy=AutonomyPolicy(mode="live"),
                          hitl_stream=open(os.devnull, "w"))
    for alert, chain in _run(rotating_agent(), orch):
        agent.execute(chain, alert)
    (rule,) = srv.custom_rules()
    assert rule["action"] == "block" and AGENT_JA4 in rule["expression"] and 'http.user_agent eq "python-httpx/0.27"' in rule["expression"]
    assert srv.blocked() and srv.blocked() <= {"203.0.113.11", "203.0.113.12", "198.51.100.13", "192.0.2.14"}
    receipts = [r for r in cf.history if r.approver == "aegis:auto"]
    import time as _t
    assert receipts and all(r.expires_at is not None and r.expires_at <= _t.time() + 900 for r in receipts)  # 15-min TTL, renewed while it persists
    # TTL expiry rolls every auto-block back
    for r in list(cf.active_receipts):
        r.expires_at = r.applied_at
    cf.sweep_expired()
    assert not srv.custom_rules() and not srv.blocked()


def test_live_auto_block_on_aws_uses_the_rule_group(orch):
    srv, aws = _aws()
    agent = ResponseAgent(connectors=ConnectorRegistry([aws]), autonomy=AutonomyPolicy(mode="live"),
                          hitl_stream=open(os.devnull, "w"))
    for alert, chain in _run(rotating_agent(), orch):
        agent.execute(chain, alert)
    (rule,) = srv.fingerprint_rules()
    stmts = rule["Statement"]["AndStatement"]["Statements"]
    assert "JA4Fingerprint" in stmts[0]["ByteMatchStatement"]["FieldToMatch"] and rule["Action"] == {"Block": {}}
    assert stmts[1]["ByteMatchStatement"]["FieldToMatch"] == {"SingleHeader": {"Name": "user-agent"}}
    assert srv.addresses("aegis-block")


def test_ip_only_waf_refuses_fingerprints_and_parks_them_for_a_human(orch):
    srv = MockImperva()
    imp = ImpervaWafConnector(site_id="1", api_id="mock", api_key="mock", base_url="https://i", transport=srv, dry_run=False)
    agent = ResponseAgent(connectors=ConnectorRegistry([imp]), autonomy=AutonomyPolicy(mode="live"),
                          hitl_stream=open(os.devnull, "w"))
    alert, chain = [(a, c) for a, c in _run(rotating_agent(), orch) if c.investigated_by == "adaptive_attacker"][-1]
    summary = agent.execute(chain, alert)
    fp = [x for x in summary.hitl_queue if x.action.target.startswith("fp:")]
    assert fp and fp[0].receipt.status == "unsupported"
    assert srv.blocked_ips()                                # the current IP was still blocked


def test_default_mode_is_shadow_records_and_still_asks_a_human(orch):
    srv, cf = _cloudflare()
    seen = []
    reg = ConnectorRegistry([cf], on_receipt=[lambda ev, r: seen.append((ev, r))])
    agent = ResponseAgent(connectors=reg, hitl_stream=open(os.devnull, "w"))          # AutonomyPolicy.from_env()
    alert, chain = [(a, c) for a, c in _run(rotating_agent(), orch) if c.investigated_by == "adaptive_attacker"][-1]
    summary = agent.execute(chain, alert)
    assert not srv.custom_rules() and not srv.blocked()                               # nothing enforced
    assert {x.action.action_type for x in summary.hitl_queue} >= {"block", "escalate"}
    previews = [r for ev, r in seen if ev == "preview"]
    assert previews and all(r.dry_run and r.approver == "aegis:auto-shadow" for r in previews)


# ------------------------------------- collateral: customers must never be hit --

FIX = __import__("pathlib").Path(__file__).resolve().parent.parent / "ingest" / "fixtures"


def test_mixed_traffic_only_the_agent_is_acted_on(orch):
    """Regression (found on the first live run): customers sharing a browser JA4 with a blocked
    human were counted as that client 'retrying from new IPs' and got blocked / challenged."""
    srv, cf = _cloudflare()
    agent = ResponseAgent(connectors=ConnectorRegistry([cf]), autonomy=AutonomyPolicy(mode="live"),
                          hitl_stream=open(os.devnull, "w"))
    lines = (FIX / "agentic_rotation.jsonl").read_text().splitlines()
    for alert, chain in _run(lines, orch):
        agent.execute(chain, alert)
    customers = {f"198.51.100.{60 + i}" for i in range(8)} | {"203.0.113.50"}
    assert not (srv.blocked() & customers) and not srv.challenged()
    assert all(BROWSER_JA4 not in r["expression"] for r in srv.custom_rules())
    assert [AGENT_JA4 in r["expression"] for r in srv.custom_rules()] == [True]


def test_agent_driving_a_real_browser_gets_ip_actions_only(orch):
    lines = [json.dumps({**json.loads(x), "ClientRequestUserAgent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/130"})
             for x in rotating_agent()]
    chain = [c for _, c in _run(lines, orch) if c.investigated_by == "adaptive_attacker"][-1]
    assert not any(a.target.startswith("fp:") for a in chain.recommended_actions)
    assert any("mainstream browser" in e.signal for e in chain.evidence)
    pol = AutonomyPolicy(mode="live")
    ch = _chain(f"fp:ja4:{AGENT_JA4};ua:Mozilla%2F5.0")
    assert pol.check(ch.recommended_actions[0], ch, protected=lambda t: False)[0] is False


def test_fingerprint_seen_on_benign_clients_is_not_enforced(orch):
    benign = [_cf(300 + i, ip=f"198.51.100.{90 + i}", at=T0 - timedelta(seconds=30 - i), ja4=AGENT_JA4,
                  ua="python-httpx/0.27", action="log", path="/health") for i in range(3)]
    chain = [c for _, c in _run(benign + rotating_agent(), orch) if c.investigated_by == "adaptive_attacker"][-1]
    assert not any(a.target.startswith("fp:") for a in chain.recommended_actions)
    assert chain.metadata["adaptive_attacker"]["identity"]["benign_ips_sharing_fingerprint"] == 3
