"""Cloud WAF connectors (Cloudflare, AWS WAFv2, Azure Front Door / App Gateway) and their log ingest."""

from __future__ import annotations

import datetime as dt
import gzip
import tempfile
from pathlib import Path

import pytest

from aegis.agents.response.connectors import mock_cloud_waf as m
from aegis.agents.response.connectors import registry_from_env
from aegis.agents.response.connectors.base import ConnectorError
from aegis.agents.response.connectors.cloud_auth import (
    AwsCredentials,
    AzureToken,
    sigv4_headers,
)
from aegis.agents.response.connectors.cloud_waf import (
    AwsWafConnector,
    AzureWafConnector,
    CloudflareWafConnector,
    parse_ipset_map,
)
from aegis.agents.shared.evidence_chain import RecommendedAction
from aegis.ingest import WafConsumer

FIX = Path(__file__).resolve().parent.parent / "ingest" / "fixtures"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for k in ("AEGIS_ENFORCEMENT_MODE", "AEGIS_WAF_VENDOR", "AEGIS_SOAR_VENDOR", "AEGIS_CF_API_TOKEN",
              "AEGIS_CF_ZONE_ID", "AEGIS_CF_ACCOUNT_ID", "AEGIS_AWS_WAF_IPSETS", "AEGIS_AWS_REGION", "AWS_REGION",
              "AEGIS_AZURE_SUBSCRIPTION_ID", "AEGIS_AZURE_RESOURCE_GROUP", "AEGIS_AZURE_WAF_POLICY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ACP_HOME", tempfile.mkdtemp())


def _act(action_type, target):
    return RecommendedAction(action_type=action_type, target=target, reasoning="r", requires_hitl=False, confidence=0.9)


# ------------------------------------------------------------------ SigV4 --

def test_sigv4_matches_aws_published_example():
    # AWS docs "Create a signed request" worked example (IAM ListUsers, 2015-08-30)
    h = sigv4_headers("GET", "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", b"",
                      {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
                      creds=AwsCredentials("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
                      region="us-east-1", service="iam", now=dt.datetime(2015, 8, 30, 12, 36, tzinfo=dt.timezone.utc))
    assert h["Authorization"].endswith("Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7")
    assert "SignedHeaders=content-type;host;x-amz-date" in h["Authorization"]


def test_sigv4_session_token_is_signed():
    h = sigv4_headers("POST", "https://wafv2.ap-south-1.amazonaws.com/", b"{}", {"X-Amz-Target": "x"},
                      creds=AwsCredentials("AK", "SK", "TOKEN"), region="ap-south-1", service="wafv2")
    assert h["x-amz-security-token"] == "TOKEN" and "x-amz-security-token" in h["Authorization"]


# ------------------------------------------------------------- Cloudflare --

def _cf(srv=None, **kw):
    srv = srv or m.MockCloudflare(token="t0k")
    return srv, CloudflareWafConnector(api_token="t0k", zone_id="z1", base_url=m.CF_BASE, transport=srv,
                                       dry_run=False, **kw)


def test_cloudflare_block_challenge_throttle_and_rollback():
    srv, c = _cf(rate_limit_per_period=20, rate_period_s=10, mitigation_timeout_s=60)
    rb = c.apply(_act("block", "203.0.113.9"), alert_id="A1")
    assert rb.status == "applied" and rb.rollback_token.startswith("ar:") and srv.blocked() == {"203.0.113.9"}
    rc = c.apply(_act("challenge", "198.51.100.0/24"), alert_id="A2")
    assert rc.status == "applied" and srv.challenged() == {"198.51.100.0/24"}
    assert next(iter(srv.access_rules.values()))["notes"].startswith("aegis block")
    r6 = c.apply(_act("block", "2001:db8::1"), alert_id="A3")
    assert r6.status == "applied" and "2001:db8::1" in srv.blocked()

    rt = c.apply(_act("throttle", "192.0.2.7"), alert_id="A4")
    assert rt.status == "applied" and rt.rollback_token.startswith("rl:")
    (rule,) = srv.rate_rules()
    assert rule["expression"] == "(ip.src eq 192.0.2.7)" and rule["ratelimit"]["requests_per_period"] == 20
    assert rule["ratelimit"]["period"] == 10 and rule["ratelimit"]["mitigation_timeout"] == 60
    # the entrypoint was created once and is reused
    c.apply(_act("throttle", "192.0.2.0/27"), alert_id="A5")
    assert len(srv.rulesets) == 1 and srv.rate_rules()[1]["expression"] == "(ip.src in {192.0.2.0/27})"

    for r in (rb, rc, r6, rt):
        assert c.rollback(r).status == "rolled_back"
    assert not srv.blocked() and not srv.challenged() and len(srv.rate_rules()) == 1


def test_cloudflare_refuses_ranges_it_cannot_express_and_keeps_preexisting_rules():
    srv, c = _cf()
    bad = c.apply(_act("block", "203.0.113.0/28"))
    assert bad.status == "failed" and "/16 or /24" in bad.error and not srv.access_rules
    assert c.apply(_act("block", "user-123")).status == "unsupported"   # not a target kind a WAF acts on
    # an analyst already blocked this IP by hand → Cloudflare says duplicate (10009) → we never delete it
    srv.access_rules["manual"] = {"id": "manual", "scope": ("zones", "z1"), "mode": "block",
                                  "configuration": {"target": "ip", "value": "203.0.113.50"}}
    r = c.apply(_act("block", "203.0.113.50"))
    assert r.status == "applied" and r.rollback_token == "keep:203.0.113.50"
    out = c.rollback(r)
    assert out.status == "rolled_back" and "manual" in srv.access_rules


def test_cloudflare_account_scope_retries_and_auth_errors():
    srv = m.MockCloudflare(token="t0k")
    c = CloudflareWafConnector(api_token="t0k", account_id="acc9", base_url=m.CF_BASE, transport=srv, dry_run=False)
    srv.fail_next = [429, 503]
    r = c.apply(_act("block", "203.0.113.9"))
    assert r.status == "applied" and next(iter(srv.access_rules.values()))["scope"] == ("accounts", "acc9")
    assert c.apply(_act("throttle", "203.0.113.9")).status == "failed"     # rate rules need a zone
    bad = CloudflareWafConnector(api_token="wrong", zone_id="z1", base_url=m.CF_BASE, transport=srv, dry_run=False)
    r = bad.apply(_act("block", "203.0.113.10"))
    assert r.status == "failed" and "10000" in r.error and "Authentication" in r.error


def test_cloudflare_plan_limits_surface_as_failed_receipts():
    _, c = _cf(m.MockCloudflare(token="t0k", plan_period=10), rate_period_s=60)
    r = c.apply(_act("throttle", "192.0.2.7"))
    assert r.status == "failed" and "period must be 10" in r.error


def test_shadow_mode_never_calls_cloudflare():
    srv = m.MockCloudflare(token="t0k")
    c = CloudflareWafConnector(api_token="t0k", zone_id="z1", base_url=m.CF_BASE, transport=srv)  # mode from env → shadow
    r = c.apply(_act("block", "203.0.113.9"))
    assert r.dry_run and r.status == "dry_run" and srv.calls == []


# --------------------------------------------------------------- AWS WAF --

def _aws(srv=None, actions=("block", "throttle"), **kw):
    srv = srv or m.MockAwsWaf()
    ids = {a: srv.create_ip_set(f"aegis-{a}", **kw) for a in actions}
    c = AwsWafConnector(ip_sets={a: (f"aegis-{a}", i) for a, i in ids.items()}, region="ap-south-1",
                        credentials=AwsCredentials(m.AWS_KEY, m.AWS_SECRET), endpoint=m.AWS_ENDPOINT,
                        transport=srv, dry_run=False, sleep=lambda s: None)
    return srv, c


def test_aws_adds_and_removes_addresses_in_the_bank_wired_ip_sets():
    srv, c = _aws()
    assert c.actions == frozenset({"block", "throttle"}) and not c.supports("challenge")
    r1 = c.apply(_act("block", "203.0.113.9"), alert_id="A1")
    r2 = c.apply(_act("block", "198.51.100.0/24"), alert_id="A2")
    r3 = c.apply(_act("throttle", "192.0.2.7"), alert_id="A3")
    assert all(r.status == "applied" for r in (r1, r2, r3))
    assert srv.addresses("aegis-block") == ["203.0.113.9/32", "198.51.100.0/24"]
    assert srv.addresses("aegis-throttle") == ["192.0.2.7/32"] and r1.rollback_token == "203.0.113.9/32"
    assert c.rollback(r1).status == "rolled_back"
    assert srv.addresses("aegis-block") == ["198.51.100.0/24"]


def test_aws_lock_conflicts_reread_and_transients_retry():
    srv, c = _aws()
    srv.race_next = 2                       # two concurrent writers beat us to UpdateIPSet
    r = c.apply(_act("block", "203.0.113.9"))
    assert r.status == "applied" and srv.addresses("aegis-block") == ["203.0.113.9/32"]
    srv.fail_next = [500]
    assert c.apply(_act("block", "203.0.113.10")).status == "applied"
    srv.race_next = 99
    r = c.apply(_act("block", "203.0.113.11"))
    assert r.status == "failed" and "kept changing" in r.error


def test_aws_preexisting_address_left_alone_and_version_mismatch_refused():
    srv = m.MockAwsWaf()
    sid = srv.create_ip_set("aegis-block", addresses=["203.0.113.50/32"])
    c = AwsWafConnector(ip_sets={"block": ("aegis-block", sid)}, region="ap-south-1",
                        credentials=AwsCredentials(m.AWS_KEY, m.AWS_SECRET), endpoint=m.AWS_ENDPOINT,
                        transport=srv, dry_run=False, sleep=lambda s: None)
    r = c.apply(_act("block", "203.0.113.50"))
    assert r.status == "applied" and r.rollback_token.startswith("keep:")
    c.rollback(r)
    assert srv.addresses("aegis-block") == ["203.0.113.50/32"]
    r6 = c.apply(_act("block", "2001:db8::1"))
    assert r6.status == "failed" and "IPV4" in r6.error


def test_aws_bad_signature_and_config_errors():
    srv = m.MockAwsWaf()
    sid = srv.create_ip_set("aegis-block")
    c = AwsWafConnector(ip_sets={"block": ("aegis-block", sid)}, region="ap-south-1",
                        credentials=AwsCredentials(m.AWS_KEY, "wrong-secret"), endpoint=m.AWS_ENDPOINT,
                        transport=srv, dry_run=False, sleep=lambda s: None)
    r = c.apply(_act("block", "203.0.113.9"))
    assert r.status == "failed" and "InvalidSignatureException" in r.error
    assert parse_ipset_map("block=a/1, throttle = b/2") == {"block": ("a", "1"), "throttle": ("b", "2")}
    with pytest.raises(ConnectorError):
        parse_ipset_map("block=nameonly")
    with pytest.raises(ConnectorError):
        AwsWafConnector(ip_sets={"isolate": ("a", "1")}, region="x")
    cf = AwsWafConnector(ip_sets={"block": ("a", "1")}, region="ap-south-1", scope="cloudfront")
    assert cf.region == "us-east-1" and cf.endpoint == "https://wafv2.us-east-1.amazonaws.com/"


# ------------------------------------------------------------- Azure WAF --

def _az(flavor="frontdoor", existing=None, **kw):
    srv = m.MockAzureWaf(flavor=flavor, existing_rules=existing)
    c = AzureWafConnector(subscription_id=m.AZ_SUB, resource_group=m.AZ_RG, policy_name=m.AZ_POLICY, flavor=flavor,
                          token=lambda: m.AZ_TOKEN, arm_url=m.AZ_ARM, transport=srv, dry_run=False, **kw)
    return srv, c


@pytest.mark.parametrize("flavor", ["frontdoor", "appgw"])
def test_azure_creates_its_rule_adds_removes_and_deletes_it_when_empty(flavor):
    existing = [{"name": "bankgeoblock", "priority": 10, "ruleType": "MatchRule", "action": "Block",
                 "matchConditions": [{"matchVariable": "SocketAddr", "operator": "GeoMatch", "matchValue": ["KP"]}
                                     if flavor == "frontdoor" else
                                     {"matchVariables": [{"variableName": "RemoteAddr"}], "operator": "GeoMatch",
                                      "matchValues": ["KP"]}]}]
    srv, c = _az(flavor, existing)
    r1 = c.apply(_act("block", "203.0.113.9"))
    r2 = c.apply(_act("block", "198.51.100.0/24"))
    rt = c.apply(_act("throttle", "192.0.2.7"))
    assert all(r.status == "applied" for r in (r1, r2, rt)), [r.error for r in (r1, r2, rt)]
    assert srv.values("aegisblock") == ["203.0.113.9", "198.51.100.0/24"]
    names = {r["name"]: r for r in srv.rules()}
    assert names["aegisblock"]["priority"] == 11            # 10 was the bank's — next free
    assert names["aegisthrottle"]["ruleType"] == "RateLimitRule" and names["aegisthrottle"]["rateLimitThreshold"] == 100
    assert "bankgeoblock" in names                          # the bank's own rule survives every PUT
    c.rollback(r1)
    assert srv.values("aegisblock") == ["198.51.100.0/24"]
    c.rollback(r2)
    assert "aegisblock" not in {r["name"] for r in srv.rules()} and "bankgeoblock" in {r["name"] for r in srv.rules()}


def test_azure_etag_conflicts_reread_and_challenge_action():
    srv, c = _az()
    srv.race_next = 2
    r = c.apply(_act("challenge", "203.0.113.9"))
    assert r.status == "applied" and srv.values("aegischallenge") == ["203.0.113.9"]
    assert next(x for x in srv.rules() if x["name"] == "aegischallenge")["action"] == "JSChallenge"
    srv.race_next = 99
    r = c.apply(_act("block", "203.0.113.10"))
    assert r.status == "failed" and "kept changing" in r.error


def test_azure_action_subset_and_client_credentials_token():
    srv, c = _az(actions={"block"})
    assert c.supports("block") and not c.supports("challenge")
    tok = AzureToken(tenant_id="ten", client_id="cid", client_secret="mock-secret", transport=srv, login_url="https://login.mock")
    assert tok() == m.AZ_TOKEN and tok() == m.AZ_TOKEN and srv.tokens_issued == 1     # cached
    with pytest.raises(ConnectorError):
        AzureToken(tenant_id="ten", client_id="cid", client_secret="bad", transport=srv, login_url="https://login.mock")()
    with pytest.raises(ConnectorError):
        AzureWafConnector(subscription_id="s", resource_group="r", policy_name="p", flavor="cdn")


# ------------------------------------------------------------------- env --

@pytest.mark.parametrize("vendor,name", [("mock-cloudflare", "cloudflare"), ("mock-aws", "aws-waf"), ("mock-azure", "azure-waf")])
def test_mock_vendors_from_env_run_the_real_connectors(monkeypatch, vendor, name):
    monkeypatch.setenv("AEGIS_WAF_VENDOR", vendor)
    monkeypatch.setenv("AEGIS_ENFORCEMENT_MODE", "live")
    reg = registry_from_env()
    r = reg.apply(_act("block", "203.0.113.9"), alert_id="A1")
    assert r.connector == name and r.status == "applied", r.error
    assert reg.rollback(r).status == "rolled_back"


def test_real_vendor_env_needs_its_settings(monkeypatch):
    for vendor in ("cloudflare", "aws", "azure"):
        monkeypatch.setenv("AEGIS_WAF_VENDOR", vendor)
        assert registry_from_env().mode == "log-only"
    monkeypatch.setenv("AEGIS_WAF_VENDOR", "cloudflare")
    monkeypatch.setenv("AEGIS_CF_API_TOKEN", "x")
    monkeypatch.setenv("AEGIS_CF_ZONE_ID", "z")
    reg = registry_from_env()
    assert reg.route("block").name == "cloudflare" and reg.mode == "shadow"


# ---------------------------------------------------------------- ingest --

def test_cloud_waf_logs_become_perimeter_alerts():
    alerts = list(WafConsumer().iter_alerts(path=FIX / "cloud_waf_events.jsonl"))
    assert [a["source"] for a in alerts] == ["Cloudflare WAF", "Cloudflare WAF", "AWS WAF",
                                             "Azure Front Door WAF", "Azure App Gateway WAF"]
    cf, cf_gql, aws, afd, agw = alerts
    # round 7 G-2: Cloudflare/Azure ids carry a per-rule suffix (several rule rows share one RayID/transactionId);
    # the vendor id itself moves to correlation_id
    assert cf["id"].startswith("WAF-8d1f2a3b4c5d6e7f-") and cf["correlation_id"] == "8d1f2a3b4c5d6e7f"
    assert cf["source_ip"] == "203.0.113.10" and cf["severity"] == "high"
    assert cf["url"].startswith("/api/accounts?id=") and cf["user_agent"].startswith("sqlmap") and cf["action"] == "block"
    assert cf_gql["attack_type"] == "rate limit" and cf_gql["http_method"] == "POST" and cf_gql["url"] == "/login"
    assert aws["attack_type"] == "sql injection" and aws["url"] == "/v1/statements?acct=1%20or%201%3D1"
    assert aws["host"] == "api.bank.example" and aws["web_acl"] == "bank-edge" and aws["id"] == "WAF-1-6717-abcd"
    assert afd["attack_type"].startswith("Path Traversal") and afd["severity"] == "high" and afd["source_ip"] == "203.0.113.40"
    assert agw["source_ip"] == "198.51.100.50" and agw["attack_type"].startswith("XSS") and agw["signature"] == "941100"
    for a in alerts:
        assert a["payload"] and a["note"] and a["raw"] and a["anomaly_score"] > 0


def test_gzipped_exports_are_read(tmp_path):
    gz = tmp_path / "cf.log.gz"
    with gzip.open(gz, "wt", encoding="utf-8") as fh:
        fh.write((FIX / "cloud_waf_events.jsonl").read_text(encoding="utf-8"))
    assert len(list(WafConsumer().iter_alerts(path=gz))) == 5


# ------------------------------------------------- symbolic target fix --

def test_symbolic_targets_resolve_to_alert_values():
    from aegis.agents.shared.evidence_chain import EvidenceChain
    from aegis.agents.shared.targets import resolve_action_targets
    chain = EvidenceChain(alert_id="A", investigated_by="perimeter", verdict="malicious", confidence=0.9)
    for t, target in (("block", "source_ip"), ("challenge", "session"), ("escalate", "A"),
                      ("revoke_sessions", "user_id"), ("throttle", "203.0.113.99"), ("block", "dest_ip")):
        chain.recommended_actions.append(_act(t, target))
    alert = {"id": "A", "source_ip": "203.0.113.10", "user_id": "u-42", "session_id": "s-1"}
    changes = resolve_action_targets(chain, alert)
    assert [a.target for a in chain.recommended_actions] == [
        "203.0.113.10", "203.0.113.10", "A", "u-42", "203.0.113.99", "dest_ip"]
    assert {"action": "challenge", "field": "session", "resolved_from": "source_ip", "value": "203.0.113.10",
            "note": "session acted on at its client IP (WAFs act per IP)"} in changes
    assert {"action": "block", "field": "dest_ip", "unresolved": True} in chain.metadata["target_resolution"]
    # idempotent on re-seal; "anonymous" is not a value
    assert resolve_action_targets(chain, alert) == [{"action": "block", "field": "dest_ip", "unresolved": True}]
    c2 = EvidenceChain(alert_id="B", investigated_by="auth", verdict="malicious", confidence=0.9,
                       recommended_actions=[_act("revoke_sessions", "user_id")])
    resolve_action_targets(c2, {"user_id": "anonymous"})
    assert c2.recommended_actions[0].target == "user_id"


def test_waf_alert_end_to_end_blocks_the_attacker_ip(monkeypatch, tmp_path):
    """Regression: the chain used to carry 'source_ip' to the connector, so a live WAF block always failed."""
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("LLM_BACKEND", "mock")
    from aegis.agents.response.agent import ResponseAgent
    from aegis.agents.response.connectors import ConnectorRegistry
    from aegis.eval.run import _build_orchestrator
    srv, c = _cf()
    orch = _build_orchestrator(tmp_path / "audit.jsonl")
    alert = next(WafConsumer().iter_alerts(path=FIX / "cloud_waf_events.jsonl"))
    chain = orch.handle(alert)
    block = next(a for a in chain.recommended_actions if a.action_type == "block")
    assert block.target == "203.0.113.10"
    agent = ResponseAgent(connectors=ConnectorRegistry([c]), hitl_stream=open("/dev/null", "w"))
    done = agent.approve(block, "analyst", source_alert_id=chain.alert_id)
    assert done.status == "executed" and srv.blocked() == {"203.0.113.10"}
