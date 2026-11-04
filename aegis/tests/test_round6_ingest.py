"""Round-6 review, ingest side (I-1 … I-12 + Kafka regex topics): regression tests built from the reviewer's repros."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from aegis.ingest.base import AlertCheckpoint
from aegis.ingest.http_push import PushServer
from aegis.ingest.kafka import KafkaReader
from aegis.ingest.kit import KitConsumer, SpecError, load_spec, validate_spec
from aegis.ingest.ocsf import to_alert, to_detection_finding
from aegis.ingest.stream import StreamConsumer, StreamQueue, ocsf_lines_from_body

NOW = datetime(2026, 11, 4, 12, 0, 0, tzinfo=UTC).timestamp()
ELASTIC_ENV = {"ELASTIC_API_KEY": "k", "ELASTIC_KIBANA_URL": "https://kb.example"}
GOOD = {"class_uid": 4002, "time": 1762200000000, "severity_id": 3, "src_endpoint": {"ip": "203.0.113.9"},
        "metadata": {"uid": "g", "product": {"name": "WAF"}}}


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------------------- I-1 watermark stall --

def test_i1_capped_pass_resumes_instead_of_rereading_the_overlap():
    alerts = [{"_id": f"a{i}", "_source": {"@timestamp": _iso(NOW - 120 + 0.075 * i), "kibana.alert.severity": "high"}}
              for i in range(800)]

    def transport(method, url, body, headers):
        q = json.loads(body)
        g = datetime.fromisoformat(q["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gt"])
        hits = [a for a in alerts if datetime.fromisoformat(a["_source"]["@timestamp"]) > g]
        return 200, {}, json.dumps({"hits": {"hits": hits[: int(q["size"])]}})

    cp, spec, seen = AlertCheckpoint(), load_spec("elastic"), set()
    for _ in range(4):
        c = KitConsumer(spec, checkpoint=cp, transport=transport, env=ELASTIC_ENV, clock=lambda: NOW)
        seen.update(a["id"] for a in c.iter_alerts())
    assert len(seen) == 800                                       # was stuck at 500 for good


def test_i1_same_millisecond_storm_cannot_pin_the_feed():
    ts = _iso(NOW - 60)
    alerts = [{"_id": f"s{i}", "_source": {"@timestamp": ts}} for i in range(600)] + \
             [{"_id": "later", "_source": {"@timestamp": _iso(NOW - 30)}}]

    def transport(method, url, body, headers):
        q = json.loads(body)
        g = datetime.fromisoformat(q["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gt"])
        hits = [a for a in alerts if datetime.fromisoformat(a["_source"]["@timestamp"]) > g]
        return 200, {}, json.dumps({"hits": {"hits": hits[: int(q["size"])]}})

    cp, spec, seen = AlertCheckpoint(), load_spec("elastic"), set()
    for _ in range(4):
        seen.update(a["id"] for a in KitConsumer(spec, checkpoint=cp, transport=transport, env=ELASTIC_ENV,
                                                 clock=lambda: NOW).iter_alerts())
    assert "elastic:later" in seen                                # progress past the tie, not a loop on it


# ------------------------------------------------------------------------ I-5 commit only after a full pass --

def test_i5_mid_pass_error_does_not_skip_unread_pages():
    mk = lambda i, mins: {"id": f"d{i}", "lastUpdateDateTime": _iso(NOW - mins * 60),
                          "createdDateTime": _iso(NOW - mins * 60), "severity": "high"}
    rows = [mk(4, 40), mk(3, 30), mk(2, 2), mk(1, 1)]
    calls = {"n": 0}

    def t(method, url, body, headers):
        if body and b"grant_type" in body:
            return 200, {}, json.dumps({"access_token": "t", "expires_in": 3600})
        calls["n"] += 1
        if calls["n"] == 2:
            return 429, {}, "throttled"
        q = parse_qs(urlsplit(url).query)
        if "$skiptoken" in q:                                       # the skiptoken carries the original filter
            g, off = q["$skiptoken"][0].split("|")
            off = int(off)
        else:
            assert q["$orderby"] == ["lastUpdateDateTime asc"]
            g, off = q["$filter"][0].split(" gt ")[1], 0
        gd = datetime.fromisoformat(g)
        match = [r for r in rows if datetime.fromisoformat(r["lastUpdateDateTime"]) > gd]
        page = match[off:off + 2]
        nxt = ({"@odata.nextLink": f"https://graph.microsoft.com/v1.0/security/alerts_v2?$skiptoken={g}|{off + 2}"}
               if off + 2 < len(match) else {})
        return 200, {}, json.dumps({"value": page, **nxt})

    cp, spec, got = AlertCheckpoint(), load_spec("msdefender"), set()
    env = {"MSDE_TENANT_ID": "t", "MSDE_CLIENT_ID": "c", "MSDE_CLIENT_SECRET": "s"}
    for _ in range(3):
        try:
            got.update(a["id"] for a in KitConsumer(spec, checkpoint=cp, transport=t, env=env, clock=lambda: NOW).iter_alerts())
        except RuntimeError:
            pass
    assert {"msdefender:d1", "msdefender:d2", "msdefender:d3", "msdefender:d4"} <= got


# ---------------------------------------------------------------------------- I-6 future-stamped records --

def test_i6_future_record_never_moves_the_watermark():
    fut = [{"_id": "x", "_source": {"@timestamp": "2099-01-01T00:00:00Z"}}]
    cp, spec = AlertCheckpoint(), load_spec("elastic")
    list(KitConsumer(spec, checkpoint=cp, transport=lambda m, u, b, h: (200, {}, json.dumps({"hits": {"hits": fut}})),
                     env=ELASTIC_ENV, clock=lambda: NOW).iter_alerts())
    assert cp.watermark("kit-elastic") is None
    cp.advance("kit-elastic", "2099-01-01T00:00:00+00:00")       # one persisted before the cap existed
    ctx = KitConsumer(spec, checkpoint=cp, transport=lambda *a: (200, {}, "{}"), env=ELASTIC_ENV, clock=lambda: NOW)._context()
    assert ctx["watermark"] < "2026-11-05"


# ---------------------------------------------------------------------------- I-10 / I-11 spec safety --

def test_i10_literal_credentials_anywhere_in_request_or_config_are_refused():
    base = load_spec("okta")
    for mutate in (lambda s: s["request"].setdefault("params", {}).__setitem__("api_key", "LITERAL-123"),
                   lambda s: s["request"].__setitem__("url", "https://x.example/api?token=abc123"),
                   lambda s: s.setdefault("config", {}).__setitem__("password", "hunter2")):
        s = json.loads(json.dumps({k: v for k, v in base.items() if k != "_path"}))
        mutate(s)
        with pytest.raises(SpecError):
            validate_spec(s)
    validate_spec(json.loads(json.dumps({k: v for k, v in base.items() if k != "_path"})))   # the shipped spec is fine


def test_i11_next_link_to_another_port_or_scheme_is_not_followed():
    spec = load_spec("okta")
    calls = []

    def t(method, url, body, headers):
        calls.append(url)
        return 200, {"link": '<https://example.okta.com:8443/api/v1/logs?after=1>; rel="next"'}, \
            json.dumps([{"uuid": "1", "published": _iso(NOW - 60), "severity": "WARN"}])
    env = {"OKTA_API_TOKEN": "x", "OKTA_BASE_URL": "https://example.okta.com"}
    list(KitConsumer(spec, transport=t, env=env, clock=lambda: NOW).iter_alerts())
    assert len(calls) == 1


# ----------------------------------------------------------------------------------- OCSF mapping (I-2/3/7/8/9) --

def test_i2_own_verdicts_are_never_reingested():
    chain = {"alert_id": "A1", "verdict": "malicious", "confidence": 0.9, "integrity_hash": "h1",
             "completed_at": "2025-01-01T00:00:05+00:00"}
    finding = to_detection_finding(chain)
    assert to_alert(finding) is None
    stripped = {**finding, "unmapped": {}}
    assert to_alert(stripped) is None                             # product name alone is enough
    assert to_alert({**stripped, "metadata": {"product": {"name": "Okta"}}}) is not None


def test_i3_bad_enum_values_do_not_crash_and_do_not_drop_siblings():
    for bad in ({"severity_id": "--5"}, {"severity_id": "²"}, {"severity_id": "9" * 5000},
                {"class_uid": 3002, "status_id": "Success"}, {"class_uid": 3002, "status_id": [1]}):
        a = to_alert({**GOOD, **bad})
        assert a is not None
    q = StreamQueue(capacity=10)
    q.put("ocsf", json.dumps([GOOD, {**GOOD, "metadata": {"uid": "b"}, "severity_id": "--1"}, {**GOOD, "metadata": {"uid": "c"}}]))
    out = StreamConsumer(queue=q).normalize(q.drain()[0])
    assert len(out) == 3


def test_i7_authentication_user_is_the_target_not_the_logging_host():
    ev = {"class_uid": 3002, "time": 1, "status_id": 2, "actor": {"user": {"name": "DC01$"}}, "user": {"name": "alice"},
          "device": {"ip": "10.0.0.5", "hostname": "dc01"}}
    a = to_alert(ev)
    assert a["user_id"] == "alice" and "source_ip" not in a and a["host"] == "dc01" and a["auth_result"] == "failure"


def test_i8_fallback_ids_use_the_whole_event():
    big = "x" * 9000
    a = to_alert({"class_uid": 6003, "time": 1, "actor": {"user": {"name": big}}, "src_endpoint": {"ip": "1.1.1.1"}})
    b = to_alert({"class_uid": 6003, "time": 1, "actor": {"user": {"name": big}}, "src_endpoint": {"ip": "2.2.2.2"}})
    assert a["id"] != b["id"]


def test_i9_finding_time_is_when_the_verdict_was_reached():
    f = to_detection_finding({"verdict": "benign", "started_at": "2025-01-01T00:00:00", "completed_at": "2025-01-01T00:00:05"})
    assert f["time"] == 1735689605000                             # naive → UTC


# ----------------------------------------------------------------------------------- I-4 OCSF framing --

def test_i4_pretty_arrays_and_big_arrays_are_split_per_event_not_dropped():
    pretty = json.dumps([GOOD, GOOD, GOOD], indent=2).encode()
    lines, bad = ocsf_lines_from_body(pretty)
    assert len(lines) == 3 and bad == 0
    many = json.dumps([{**GOOD, "metadata": {"uid": str(i)}} for i in range(1500)]).encode()
    assert len(ocsf_lines_from_body(many)[0]) == 1500
    lines, bad = ocsf_lines_from_body(b'{"class_uid": 1, "time": 1}\nnot json\n[1, 2]\n')
    assert len(lines) == 1 and bad == 3


def _req(url, *, data=None, token=None, method=None):
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Authorization": f"Bearer {token}"} if token else {})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def test_i4_http_endpoint_counts_rejects_and_refuses_an_all_bad_body():
    q = StreamQueue(capacity=100)
    srv = PushServer(token="push", read_token="read", bind="127.0.0.1:0", queue=q).start()
    try:
        base = f"http://127.0.0.1:{srv.port}/ingest/ocsf"
        code, body = _req(base, data=json.dumps([GOOD, GOOD], indent=2).encode(), token="push")
        assert code == 200 and json.loads(body)["accepted"] == 2 and len(q) == 2
        code, body = _req(base, data=b"not json\nstill not\n", token="push")
        assert code == 400 and json.loads(body)["rejected"] == 2
    finally:
        srv.stop()


# -------------------------------------------------------------------------- I-12 expired / gated block feed --

def test_i12_feed_is_gated_and_expired_entries_are_never_served(monkeypatch):
    now = time.time()
    rs = [SimpleNamespace(action_type="block", target="203.0.113.9", dry_run=False, expires_at=now + 600, receipt_id="r1"),
          SimpleNamespace(action_type="block", target="198.51.100.7", dry_run=False, expires_at=now - 5, receipt_id="r2")]
    srv = PushServer(token="push", read_token="read", bind="127.0.0.1:0", queue=StreamQueue(), blocklist=lambda: rs).start()
    try:
        url = f"http://127.0.0.1:{srv.port}/ingest/blocklist"
        monkeypatch.delenv("AEGIS_BLOCK_FEED", raising=False)
        assert _req(url + "?format=txt", token="read")[0] == 404
        monkeypatch.setenv("AEGIS_BLOCK_FEED", "1")
        assert _req(url + "?format=txt", token="read")[1].splitlines() == ["203.0.113.9"]
        ips = [r["target"] for r in json.loads(_req(url, token="read")[1])["ips"]]
        assert ips == ["203.0.113.9"]
    finally:
        srv.stop()


# --------------------------------------------------------------------------------- Kafka regex topics --

def test_kafka_regex_topic_subscription_keeps_its_source():
    r = KafkaReader(config={"group.id": "t"}, topics={"^sec\\..*": "ocsf", "waf": "cloudflare"}, queue=StreamQueue(),
                    consumer_factory=lambda c: None)
    assert r.source_for("sec.okta") == "ocsf" and r.source_for("waf") == "cloudflare" and r.source_for("other") == "kafka"


def test_watermark_is_committed_once_per_pass(tmp_path):
    rows = [{"_id": f"w{i}", "_source": {"@timestamp": _iso(NOW - 100 + i)}} for i in range(3)]
    cp = AlertCheckpoint(tmp_path / "cp.json")
    c = KitConsumer(load_spec("elastic"), checkpoint=cp, env=ELASTIC_ENV, clock=lambda: NOW,
                    transport=lambda *a: (200, {}, json.dumps({"hits": {"hits": rows}})))
    it = c.iter_alerts()
    next(it)
    next(it)
    assert cp.watermark("kit-elastic") is None                    # nothing committed mid-pass
    list(it)
    assert cp.watermark("kit-elastic") == datetime.fromtimestamp(NOW - 98, UTC).isoformat()
    assert timedelta(0) <= datetime.fromtimestamp(NOW, UTC) - datetime.fromisoformat(cp.watermark("kit-elastic"))
