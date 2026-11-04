"""Round-8 ingest / exposure review regressions (G8-1 … G8-12, G-1 variant b)."""
from __future__ import annotations

import gzip
import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta

import pytest

from aegis.agents.response.connectors.http import HttpResult
from aegis.exposure import remediation
from aegis.exposure.coverage import Protection, from_cloudflare
from aegis.exposure.engine import Asset, Settings, Vuln, assess
from aegis.exposure.k8s_reach import _waf_ingress, modsec_engine
from aegis.exposure.loaders import assets_from_aws, assets_from_inventory, merge_assets
from aegis.exposure.scan import to_finding
from aegis.ingest.base import AlertCheckpoint, JsonTooDeep, json_depth_ok, loads_bounded
from aegis.ingest.stream import (
    InflateTooLarge,
    StreamConsumer,
    StreamQueue,
    gunzip_bounded,
    ocsf_lines_from_body,
)
from aegis.posture.runner import fingerprint

DEEP = "[" * 200_000 + "]" * 200_000


@pytest.fixture(autouse=True)
def _dead_letter(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_DEAD_LETTER", str(tmp_path / "dead-letter.jsonl"))
    logging.getLogger("aegis").setLevel(logging.CRITICAL)
    yield tmp_path / "dead-letter.jsonl"
    logging.getLogger("aegis").setLevel(logging.NOTSET)


# -------------------------------------------------------------------- G8-1 --
def test_g8_1_bounded_json_is_iterative_and_string_aware():
    with pytest.raises(JsonTooDeep):
        loads_bounded(DEEP)
    assert not json_depth_ok("[" * 65 + "]" * 65) and json_depth_ok("[" * 64 + "]" * 64)
    # brackets inside strings are data: a URL full of "[" never gets a normal record rejected
    obj = {"url": "/a?" + "[" * 500, "nested": {"b": [1, 2, {"c": "]]]{{{"}]}}
    assert loads_bounded(json.dumps(obj)) == obj
    lines, bad = ocsf_lines_from_body(DEEP.encode())
    assert lines == [] and bad == 1


class _Msg:
    def __init__(self, t, v, off):
        self.t, self.v, self.off = t, v, off

    def topic(self):
        return self.t

    def value(self):
        return self.v

    def error(self):
        return None

    def partition(self):
        return 0

    def offset(self):
        return self.off


@pytest.mark.parametrize("topic,source,poison", [
    ("sec.ocsf", "ocsf", DEEP.encode()),
    ("waf.cf", "cloudflare", b'{"a":' + DEEP.encode() + b"}"),
    ("waf.raw", "waf", b"[" * 100 + b"]" * 100),
])
def test_g8_1_kafka_poison_message_is_dead_lettered_and_committed_past(topic, source, poison, _dead_letter):
    from aegis.ingest.kafka import KafkaReader
    good = json.dumps({"class_uid": 3002, "time": 1760000000000, "severity_id": 4,
                       "metadata": {"uid": "evt-1", "product": {"name": "Okta"}}}).encode()
    commits = []

    class C:
        def commit(self, asynchronous=True):
            commits.append(1)

    q = StreamQueue(100)
    r = KafkaReader(config={"group.id": "t"}, topics={topic: source}, queue=q, consumer_factory=lambda c: C())
    r._consumer = C()
    assert r.handle([_Msg(topic, poison, 41), _Msg(topic, good, 42)]) is True
    assert commits == [1] and len(q) == 1 and r.poisoned == 1        # the good message is queued, offsets committed
    row = json.loads(_dead_letter.read_text().splitlines()[-1])
    assert row["kind"] == "poison_record" and row["offset"] == 41 and row["topic"] == topic and row["size"] == len(poison)


def test_g8_1_kafka_reader_loop_does_not_stall_on_poison():
    import threading

    from aegis.ingest.kafka import KafkaReader
    made = []

    class C:
        def __init__(self, cfg):
            made.append(1)

        def subscribe(self, t):
            pass

        def consume(self, num_messages, timeout):
            if len(q) >= 2:
                time.sleep(0.01)
                return []
            return [_Msg("t", DEEP.encode(), 1), _Msg("t", b'{"x":1}', 2)]

        def commit(self, asynchronous=True):
            pass

        def close(self):
            pass

    q = StreamQueue(100)
    r = KafkaReader(config={"group.id": "t"}, topics={"t": "waf"}, queue=q, consumer_factory=C, backoff_s=0.01)
    r.start()
    deadline = time.time() + 5
    while len(q) < 1 and time.time() < deadline:
        time.sleep(0.01)
    r.stop()
    assert len(q) >= 1 and len(made) == 1 and threading.active_count() >= 1   # one consumer: never reconnected


def test_g8_1_eventhub_poison_event_skipped_good_ones_queued_and_checkpointed(tmp_path):
    from aegis.ingest.eventhub import EventHubReader

    class Ev:
        def __init__(self, b, n):
            self.b, self.sequence_number = b, n

        def body_as_str(self):
            return self.b

    class Ctx:
        partition_id = "0"

    q = StreamQueue(100)
    r = EventHubReader(connection_string="x", checkpoint_path=tmp_path / "cp.json", queue=q)
    r.on_batch(Ctx(), [Ev(json.dumps({"records": [{"category": "ApplicationGatewayFirewallLog"}]}), 1),
                       Ev('{"records":' + DEEP + "}", 2)])
    assert len(q) == 1 and r._positions == {"0": 2} and r.poisoned == 1


# -------------------------------------------------------------------- G8-3 --
def test_g8_3_push_receiver_rejects_bad_records_and_queues_the_good():
    from aegis.ingest.http_push import PushServer
    q = StreamQueue(100)
    s = PushServer(token="t", bind="127.0.0.1:0", queue=q).start()
    try:
        def post(route, body):
            req = urllib.request.Request(f"{s.url}/ingest/{route}", data=body.encode(), method="POST",
                                         headers={"Authorization": "Bearer t"})
            try:
                with urllib.request.urlopen(req) as resp:
                    return resp.status, json.loads(resp.read())
            except urllib.error.HTTPError as e:
                return e.code, json.loads(e.read() or b"{}")
        st, out = post("ocsf", json.dumps({"class_uid": 3002, "metadata": {"uid": "e1"}}) + "\n" + DEEP)
        assert st == 200 and out["accepted"] == 1 and out["rejected"] == 1 and len(q) == 1
        st, out = post("alerts", json.dumps({"id": "a1", "source": "x"}) + "\n" + '{"id":"a2","x":' + DEEP + "}\nnot json")
        assert st == 200 and out["accepted"] == 1 and out["rejected"] == 2 and len(q) == 2
        assert [e["line"] for e in out["rejected_lines"]] == [2, 3]
    finally:
        s.stop()


# -------------------------------------------------------------------- G8-4 --
def test_g8_4_cef_without_event_id_is_not_keyed_on_its_timestamp():
    lines = [
        "CEF:0|Fortinet|FortiWeb|7.4|20000010|SQL Injection|9|rt=1762230000000 src=203.0.113.9 request=/login?u=1'or'1'='1 act=Alerted",
        "CEF:0|Fortinet|FortiWeb|7.4|30000001|Remote Command Execution|10|rt=1762230000000 src=198.51.100.77 request=/cgi-bin/x;id act=Alerted",
        "CEF:0|Barracuda|WAF|12|SQLI|SQL Injection|8|start=Nov 04 2026 10:00:00 src=192.0.2.1 request=/a?id=1-- act=DENY",
        "CEF:0|Barracuda|WAF|12|OS_CMD|OS Command Injection|9|start=Nov 04 2026 10:00:00 src=192.0.2.200 request=/b?c=;cat act=LOG",
    ]
    cp = AlertCheckpoint()
    q = StreamQueue(100)
    q.put_many("waf", lines)
    c = StreamConsumer(queue=q, checkpoint=cp)
    out = list(c.iter_alerts())
    assert len(out) == 4 and c.skipped_duplicates == 0 and len({a["id"] for a in out}) == 4
    q.put_many("waf", lines)                                  # a replay of the same events still dedupes
    assert list(StreamConsumer(queue=q, checkpoint=cp).iter_alerts()) == []
    # a real event id still wins
    q.put_many("waf", ["CEF:0|Imperva Inc.|SecureSphere|1|x|SQLi|9|deviceExternalId=evt-77 rt=1 src=1.2.3.4"])
    (a,) = list(StreamConsumer(queue=q, checkpoint=AlertCheckpoint()).iter_alerts())
    assert a["id"] == "WAF-evt-77"


# -------------------------------------------------------------------- G8-5 --
def _cf(managed_rule):
    routes = {
        "/dns_records": {"result": [{"type": "A", "proxied": True, "name": "nb.bank.example", "content": "52.1.1.1"}]},
        "/phases/http_request_firewall_managed/entrypoint": {"result": {"rules": [managed_rule]}},
        "/phases/http_request_firewall_custom/entrypoint": {"result": {"rules": []}},
    }

    def t(method, url, json_body, headers, timeout):
        for frag, body in routes.items():
            if frag in url:
                return HttpResult(200, body)
        return HttpResult(404, {})
    (p,) = from_cloudflare(["z1"], "tok", t)
    return p


@pytest.mark.parametrize("overrides,mode", [
    ({"action": "log"}, "monitor"),
    ({"enabled": False}, "monitor"),
    ({"rules": [{"id": "r1", "action": "log"}]}, "monitor"),
    ({"categories": [{"category": "sqli", "action": "skip"}]}, "monitor"),
    ({"action": "block"}, "block"),
    ({"action": "managed_challenge"}, "block"),
    (None, "block"),
])
def test_g8_5_cloudflare_non_blocking_override_is_monitor(overrides, mode):
    rule = {"action": "execute", "enabled": True, "expression": "true", "action_parameters": {"id": "efb7"}}
    if overrides is not None:
        rule["action_parameters"]["overrides"] = overrides
    assert _cf(rule).mode == mode


def test_g8_5_log_override_keeps_act_now():
    p = _cf({"action": "execute", "enabled": True, "action_parameters": {"id": "x", "overrides": {"action": "log"}}})
    a = Asset(id="i-1", name="nb", keys={"52.1.1.1"}, zone="vpc", public=True, internet_ports=[(443, 443)])
    (e,), _ = assess([Vuln(asset="i-1", cve="CVE-2099-0003", title="RCE", port=443, kev=True, cvss=9.8)], [a],
                     Settings(coverage=[p]))
    assert e.tier == "ACT_NOW" and e.defended == "none"


# ------------------------------------------------------------------- G8-11 --
def test_g8_11_portless_front_covers_only_proxied_web_ports():
    a = Asset(id="i-1", name="nb", keys={"52.1.1.1"}, zone="vpc", public=True,
              internet_ports=[(443, 443), (8080, 8080), (9200, 9200)])
    cf = Protection(name="cf", vendor="cloudflare", mode="block", fronts=[{"host": "52.1.1.1", "port": None}],
                    virtual_patches=["CVE-2021-44228"])
    ex, _ = assess([Vuln(asset="i-1", cve="CVE-2099-0001", title="admin RCE", port=8080, kev=True, cvss=9.8),
                    Vuln(asset="i-1", cve="CVE-2021-44228", title="log4shell", port=9200, kev=True, cvss=10.0),
                    Vuln(asset="i-1", cve="CVE-2021-44228", title="log4shell", port=443, kev=True, cvss=10.0)],
                   [a], Settings(coverage=[cf]))
    by_port = {e.port: e for e in ex}
    assert by_port[8080].tier == "ACT_NOW" and by_port[9200].tier == "ACT_NOW" and by_port[9200].defended == "none"
    assert by_port[443].defended == "full"
    cf.ports = [8080]                                         # an exporter that declares 8080 proxied
    assert cf.covers({"52.1.1.1"}, 8080) and not cf.covers({"52.1.1.1"}, 9200)


def test_g8_11_coverage_file_ports(tmp_path):
    from aegis.exposure.coverage import load_coverage
    f = tmp_path / "cov.json"
    f.write_text(json.dumps({"protections": [{"name": "x", "vendor": "imperva", "mode": "block",
                                              "fronts": [{"host": "h"}], "ports": [8443]}]}))
    (p,) = load_coverage(f)
    assert p.covers({"h"}, 8443) and p.covers({"h"}, 443) and not p.covers({"h"}, 22)


# ------------------------------------------------------------------- G8-10 --
@pytest.mark.parametrize("snippet,blocking", [
    ("# SecRuleEngine On  (enable after tuning)\nSecRuleEngine DetectionOnly", False),
    ("SecRuleEngine On\nSecRuleEngine DetectionOnly", False),
    ("SecRuleEngine DetectionOnly\nSecRuleEngine On", True),
    ("SecRuleEngine On", True),
    ("Include /etc/nginx/owasp-modsecurity-crs/nginx-modsecurity.conf", False),
    ("  # SecRuleEngine On", False),
])
def test_g8_10_modsecurity_last_directive_wins(snippet, blocking):
    base = "nginx.ingress.kubernetes.io/"
    ing = {"metadata": {"annotations": {base + "enable-modsecurity": "true", base + "modsecurity-snippet": snippet}}}
    assert _waf_ingress(ing) is blocking
    assert modsec_engine('SecRuleEngine "On"') == "on"


# -------------------------------------------------------------- G-1 var. b --
def test_g1b_port_open_straight_to_instance_gets_no_alb_waf_credit():
    bundle = {
        "security_groups": [
            {"GroupId": "sg-inst", "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
                                                      "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]},
            {"GroupId": "sg-alb", "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                                                     "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}],
        "instances": [{"InstanceId": "i-1", "State": {"Name": "running"}, "PublicIpAddress": "52.1.1.1",
                       "PrivateIpAddress": "10.0.0.5", "VpcId": "vpc-1", "SecurityGroups": [{"GroupId": "sg-inst"}]}],
        "load_balancers": [{"LoadBalancerName": "alb", "Scheme": "internet-facing", "Type": "application",
                            "SecurityGroups": ["sg-alb"], "listeners": [{"Port": 443}],
                            "targets": [{"Id": "i-1", "Port": 80}], "web_acl": "acl"}]}
    assets = assets_from_aws(bundle)
    (e,), _ = assess([Vuln(asset="i-1", cve="CVE-2099-0002", title="RCE", port=80, kev=True, cvss=9.8)], assets)
    assert e.tier == "ACT_NOW" and e.defended == "none" and assets[0].waf_ranges == set()
    assert e.path["opened_by"] == ["sg-inst"] and not e.path["via"]          # the direct path is reported
    # without the direct rule the ALB path keeps its WAF credit
    bundle["security_groups"][0]["IpPermissions"] = []
    assets = assets_from_aws(bundle)
    (e,), _ = assess([Vuln(asset="i-1", cve="CVE-2099-0002", title="RCE", port=80, kev=True, cvss=9.8)], assets)
    assert e.defended == "partial" and assets[0].waf_ranges == {(80, 80)}


# -------------------------------------------------------------------- G8-2 --
_SG = {"GroupId": "sg-web", "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 8080, "ToPort": 8080,
                                                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}
_NETBANK = {"InstanceId": "i-netbank", "State": {"Name": "running"}, "PublicIpAddress": "52.1.1.1",
            "PrivateIpAddress": "10.0.0.5", "VpcId": "vpc-prod", "SecurityGroups": [{"GroupId": "sg-web"}]}
_DEV = {"InstanceId": "i-devbox", "State": {"Name": "running"}, "PrivateIpAddress": "10.0.0.5", "VpcId": "vpc-dev",
        "SecurityGroups": []}


def test_g8_2_shared_private_ip_in_other_vpc_is_not_merged():
    dev = assets_from_aws({"security_groups": [], "instances": [_DEV]})
    prod = assets_from_aws({"security_groups": [_SG], "instances": [_NETBANK]})
    for merged in (merge_assets(dev, prod), merge_assets(prod, dev)):
        assert sorted(a.id for a in merged) == ["i-devbox", "i-netbank"]
        nb = next(a for a in merged if a.id == "i-netbank")
        assert nb.public and nb.internet_ports == [(8080, 8080)]
        (e,), _ = assess([Vuln(asset="i-netbank", asset_alt=["52.1.1.1"], cve="CVE-2099-7777", title="RCE", port=8080,
                               kev=True, cvss=9.8)], merged)
        assert e.tier == "ACT_NOW" and e.asset == "i-netbank"


def test_g8_2_same_instance_from_two_bundles_keeps_its_exposure():
    a = assets_from_aws({"security_groups": [_SG], "instances": [_NETBANK]})
    b = assets_from_aws({"security_groups": [], "instances": [{**_NETBANK, "PublicIpAddress": None, "SecurityGroups": []}]})
    (m,) = merge_assets(b, a)
    assert m.public and m.internet_ports == [(8080, 8080)] and m.opened_by[(8080, 8080)] == {"sg-web"}


def test_g8_2_zoneless_inventory_row_still_overrides_unique_private_ip(tmp_path):
    inv = tmp_path / "inv.csv"
    inv.write_text("asset,ips,role,waf,edr\nlegacy,10.0.0.5,payment_api,yes,yes\n")
    prod = assets_from_aws({"security_groups": [_SG], "instances": [_NETBANK]})
    (m,) = merge_assets(prod, assets_from_inventory(inv))
    assert m.id == "i-netbank" and m.role == "payment_api" and m.edr
    # the same row is NOT merged when two VPCs hold the address: it identifies neither
    prod = assets_from_aws({"security_groups": [_SG], "instances": [_NETBANK]})     # merge updates in place
    dev = assets_from_aws({"security_groups": [], "instances": [_DEV]})
    merged = merge_assets(prod, dev, assets_from_inventory(inv))
    assert len(merged) == 3 and next(a for a in merged if a.id == "i-netbank").role == "server"


# -------------------------------------------------------------------- G8-6 --
def test_g8_6_ambiguous_key_keeps_approved_fix_open(tmp_path):
    vuln = Vuln(asset="10.0.0.5", cve="CVE-2099-7777", title="RCE", port=8080, kev=True, cvss=9.8)

    def rows(instances):
        ex, notes = assess([vuln], assets_from_aws({"security_groups": [_SG], "instances": instances}))
        out = []
        for e in ex:
            d = to_finding(e).as_dict()
            d.update(scan="exposure-prod", fingerprint=fingerprint("exposure-prod", to_finding(e)))
            out.append(d)
        return out, notes, ex

    r1, _, ex1 = rows([_NETBANK])
    assert [e.tier for e in ex1] == ["ACT_NOW"]
    sec = remediation.reconcile(tmp_path, {"open": r1}, now=datetime(2026, 11, 1, tzinfo=UTC))
    p = sec["proposals"][0]
    p["status"], p["approved_at"] = "approved", "2026-11-01T00:00:00Z"
    remediation.save(tmp_path, sec)
    r2, notes, ex2 = rows([_NETBANK, _DEV])
    assert {(e.asset, e.tier) for e in ex2} == {("i-netbank", "ACT_NOW"), ("i-devbox", "SCHEDULE")}
    assert all(e.unverifiable for e in ex2) and any("several assets" in n for n in notes)
    sec = remediation.reconcile(tmp_path, {"open": r2}, now=datetime(2026, 11, 3, tzinfo=UTC))
    assert len(sec["proposals"]) == 1                         # no proposal filed on an ambiguous finding
    p = sec["proposals"][0]
    assert p["status"] == "approved" and p["verification"].startswith("unverifiable (ambiguous asset)")


# -------------------------------------------------------------------- G8-7 --
def _walk_lines():
    from aegis.agents.api_abuse.object_walk import ObjectWalkDetector
    from aegis.agents.api_abuse.ownership import ownership_from_env
    from aegis.ingest.apigw import normalize
    t0 = 1_792_650_000.0
    lines = [json.dumps({"timestamp": t0 + i * 2, "client_ip": "203.0.113.10", "method": "GET",
                         "path": f"/api/v1/accounts/{1000 + i}", "status": 200, "request_id": f"r{i}"}) for i in range(60)]
    d = ObjectWalkDetector(ownership_from_env())
    n = next(i for i, ln in enumerate(lines) if d.observe(normalize(json.loads(ln))))
    return lines[: n + 3]


def test_g8_7_file_source_redelivery_yields_the_object_walk_alert_again(tmp_path):
    from aegis.ingest.apigw import (
        ApiGatewayConsumer,
        reset_shared_detector,
        shared_detector,
    )
    reset_shared_detector()
    f = tmp_path / "apigw.log"
    f.write_text("\n".join(_walk_lines()) + "\n")
    cp = AlertCheckpoint(tmp_path / "cp.json")
    g = ApiGatewayConsumer(detector=shared_detector(), checkpoint=cp).iter_alerts(lines=cp.tail_lines(f))
    first = next(g)
    g.close()                                                  # taken, not handled
    again = list(ApiGatewayConsumer(detector=shared_detector(), checkpoint=cp).iter_alerts(lines=cp.tail_lines(f)))
    assert [a["id"] for a in again] == [first["id"]]
    # handled now: a further replay of the same file is a duplicate, not a new alert
    cp2 = AlertCheckpoint(tmp_path / "cp.json")
    cp2._state.pop("files", None)
    assert list(ApiGatewayConsumer(detector=shared_detector(), checkpoint=cp2).iter_alerts(lines=_walk_lines())) == []
    reset_shared_detector()


def test_g8_7_stream_requeue_yields_the_object_walk_alert_again():
    from aegis.ingest import apigw
    apigw.reset_shared_detector()
    q = StreamQueue(1000)
    q.put_many("apigw", _walk_lines())
    g = StreamConsumer(queue=q, checkpoint=AlertCheckpoint()).iter_alerts()
    first = next(g)
    g.close()
    again = list(StreamConsumer(queue=q, checkpoint=AlertCheckpoint()).iter_alerts())
    assert [a["id"] for a in again] == [first["id"]]
    apigw.reset_shared_detector()


# -------------------------------------------------------------------- G8-9 --
def test_g8_9_low_prefix_cannot_starve_a_critical_acp_event():
    from aegis.ingest.acp import AcpGovernanceConsumer
    t0 = datetime(2026, 11, 4, tzinfo=UTC)
    db = [{"id": f"rogue:{i}", "kind": "rogue_alert", "severity": "LOW", "ts": (t0 + timedelta(seconds=i)).isoformat(),
           "issue_type": "rate_spike"} for i in range(4500)]
    db.append({"id": "rogue:crit", "kind": "rogue_alert", "severity": "CRITICAL",
               "ts": (t0 + timedelta(seconds=5000)).isoformat(), "issue_type": "data_exfiltration", "title": "exfil"})

    def server(method, url, body, headers, timeout):
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        since = (q.get("since") or [""])[0]
        ev = [e for e in db if not since or e["ts"] > since][: int(q["limit"][0])]
        return 200, json.dumps({"events": ev, "next_since": ev[-1]["ts"] if ev else since})

    cp = AlertCheckpoint()
    seen = []
    for _ in range(3):
        seen += [a["id"] for a in AcpGovernanceConsumer("https://dash", "k", checkpoint=cp, transport=server).iter_alerts()]
    assert seen == ["ACP-rogue-crit"]
    assert cp.watermark("acp") == db[-1]["ts"]


def test_g8_9_unhandled_alert_is_reread():
    from aegis.ingest.acp import AcpGovernanceConsumer
    db = [{"id": "a", "kind": "rogue_alert", "severity": "HIGH", "ts": "2026-11-04T00:00:01"},
          {"id": "b", "kind": "rogue_alert", "severity": "HIGH", "ts": "2026-11-04T00:00:02"}]

    def server(method, url, body, headers, timeout):
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        since = (q.get("since") or [""])[0]
        ev = [e for e in db if not since or e["ts"] > since]
        return 200, json.dumps({"events": ev, "next_since": ev[-1]["ts"] if ev else since})

    cp = AlertCheckpoint()
    g = AcpGovernanceConsumer("https://d", "k", checkpoint=cp, transport=server).iter_alerts()
    assert next(g)["id"] == "ACP-a"
    g.close()                                                 # caller stopped before handling it
    assert [a["id"] for a in AcpGovernanceConsumer("https://d", "k", checkpoint=cp, transport=server).iter_alerts()] \
        == ["ACP-a", "ACP-b"]


# -------------------------------------------------------------------- G8-8 --
def test_g8_8_multi_member_gunzip_is_linear_and_capped(monkeypatch):
    m = gzip.compress(b"", mtime=0)
    small = m * 20_000
    big = m * 80_000
    t = time.perf_counter()
    gunzip_bounded(small)
    t_small = time.perf_counter() - t
    t = time.perf_counter()
    gunzip_bounded(big)
    t_big = time.perf_counter() - t
    assert t_big < max(1.0, t_small * 10)                    # 4x the members: ~4x the time, not ~16x
    monkeypatch.setenv("AEGIS_INGEST_MAX_GZIP_MEMBERS", "1000")
    with pytest.raises(InflateTooLarge, match="gzip members"):
        gunzip_bounded(m * 1001)
    data = b"payload-" * 50_000
    assert gunzip_bounded(gzip.compress(data) + gzip.compress(b"tail") + b"\x00\x00") == data + b"tail"
    with pytest.raises(ValueError, match="truncated"):
        gunzip_bounded(gzip.compress(data)[:-30])


# ------------------------------------------------------------------- G8-12 --
def test_g8_12_es_notables_default_includes_critical():
    from aegis.infra.splunk_es import SplunkESConsumer
    from aegis.infra.splunk_source import SplunkConfig
    es = SplunkESConsumer(SplunkConfig(base_url="http://splunk:8089", token="t"))
    seen = []

    class B:
        def iter_alerts(self, *, search, **kw):
            seen.append(search)
            return iter(())
    es._base = B()
    list(es.iter_notable_events())
    assert "urgency IN (critical,high,medium)" in seen[0]
