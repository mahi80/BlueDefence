"""Kafka reader: config safety, topic→source mapping, queue-then-commit, backpressure, OCSF/EDR routing."""

from __future__ import annotations

import json
import threading

import pytest

from aegis.ingest.kafka import KafkaReader, kafka_config, kafka_from_env, parse_topics
from aegis.ingest.stream import StreamConsumer, StreamQueue


class Msg:
    def __init__(self, topic, value, err=None):
        self._t, self._v, self._e = topic, value, err

    def topic(self):
        return self._t

    def value(self):
        return self._v

    def error(self):
        return self._e


class FakeConsumer:
    def __init__(self, batches=()):
        self.batches = list(batches)
        self.commits = 0
        self.subscribed = None
        self.closed = False

    def subscribe(self, topics):
        self.subscribed = topics

    def consume(self, num_messages, timeout):
        return self.batches.pop(0) if self.batches else []

    def commit(self, asynchronous=True):
        assert asynchronous is False
        self.commits += 1

    def close(self):
        self.closed = True


OCSF = {"class_uid": 3002, "time": 1760000000000, "severity_id": 4, "status_id": 2,
        "user": {"name": "priya@bank.in"}, "src_endpoint": {"ip": "203.0.113.9"},
        "metadata": {"uid": "evt-1", "product": {"name": "Okta"}}}


def _reader(q, topics=None, consumer=None):
    r = KafkaReader(config={"group.id": "t"}, topics=topics or {"sec.ocsf": "ocsf"}, queue=q,
                    consumer_factory=lambda cfg: consumer or FakeConsumer(), backoff_s=0.01)
    r._consumer = consumer or FakeConsumer()
    return r


def test_parse_topics():
    assert parse_topics("a=ocsf, b ,c=edr;d=", "kafka") == {"a": "ocsf", "b": "kafka", "c": "edr", "d": "kafka"}
    assert parse_topics("") == {}


def test_config_refuses_plaintext_and_needs_sasl_creds():
    base = {"AEGIS_KAFKA_BOOTSTRAP": "k:9093", "AEGIS_KAFKA_USERNAME": "u", "AEGIS_KAFKA_PASSWORD": "p"}
    cfg = kafka_config(base)
    assert cfg["security.protocol"] == "SASL_SSL" and cfg["sasl.mechanism"] == "SCRAM-SHA-512"
    assert cfg["enable.auto.commit"] is False and cfg["auto.offset.reset"] == "latest"
    with pytest.raises(ValueError, match="unencrypted"):
        kafka_config({**base, "AEGIS_KAFKA_SECURITY_PROTOCOL": "PLAINTEXT"})
    assert kafka_config({**base, "AEGIS_KAFKA_SECURITY_PROTOCOL": "PLAINTEXT",
                         "AEGIS_KAFKA_ALLOW_PLAINTEXT": "1"})["security.protocol"] == "PLAINTEXT"
    with pytest.raises(ValueError, match="USERNAME"):
        kafka_config({"AEGIS_KAFKA_BOOTSTRAP": "k:9093"})
    with pytest.raises(ValueError, match="BOOTSTRAP"):
        kafka_config({})
    ssl = kafka_config({"AEGIS_KAFKA_BOOTSTRAP": "k:9093", "AEGIS_KAFKA_SECURITY_PROTOCOL": "SSL",
                        "AEGIS_KAFKA_CA": "/ca.pem", "AEGIS_KAFKA_START": "earliest"})
    assert ssl["ssl.ca.location"] == "/ca.pem" and "sasl.username" not in ssl and ssl["auto.offset.reset"] == "earliest"


def test_batch_is_queued_then_committed_and_ocsf_becomes_an_alert():
    q = StreamQueue(capacity=100)
    c = FakeConsumer()
    r = _reader(q, consumer=c)
    assert r.handle([Msg("sec.ocsf", json.dumps(OCSF).encode())])
    assert c.commits == 1 and len(q) == 1
    item = q.drain()[0]
    assert item.source == "ocsf"
    alerts = StreamConsumer(queue=q).normalize(item)
    a = alerts[0] if isinstance(alerts, list) else alerts
    assert a["alert_type"] == "authentication" and a["source_ip"] == "203.0.113.9" and a["ingest_source"] == "ocsf"


def test_records_envelope_ndjson_and_multiline_ocsf_array():
    q = StreamQueue(capacity=100)
    r = _reader(q, topics={"waf": "cloudflare", "sec.ocsf": "ocsf"})
    r.handle([Msg("waf", json.dumps({"records": [{"a": 1}, {"a": 2}]}).encode()),
              Msg("waf", b'{"b":1}\n{"b":2}\n'),
              Msg("sec.ocsf", json.dumps([OCSF, OCSF], indent=2).encode())])
    items = q.drain()
    assert [i.source for i in items].count("cloudflare") == 4
    arr = [i for i in items if i.source == "ocsf"]
    # round 6 I-4: an OCSF array (pretty-printed or not) becomes one queue item per event, never one truncated line
    assert len(arr) == 2 and all(json.loads(i.line)["class_uid"] == 3002 for i in arr)


def test_bad_messages_are_skipped_and_errors_do_not_commit_alone():
    q = StreamQueue(capacity=100)
    c = FakeConsumer()
    r = _reader(q, consumer=c)
    r.handle([Msg("sec.ocsf", b"\xff\xfe"), Msg("sec.ocsf", None), Msg("sec.ocsf", b"x" * (9 * 1024 * 1024))])
    assert len(q) == 0 and r.skipped == 2
    r.handle([Msg("sec.ocsf", None, err="broker down")])
    assert c.commits == 1                                    # the error-only batch committed nothing


def test_full_queue_holds_the_batch_and_never_commits_past_it():
    q = StreamQueue(capacity=1)
    q.put("x", '{"filler":1}')
    c = FakeConsumer()
    r = _reader(q, consumer=c)
    done = threading.Event()
    t = threading.Thread(target=lambda: (r.handle([Msg("sec.ocsf", b'{"a":1}\n{"a":2}')]), done.set()))
    t.start()
    assert not done.wait(0.3) and c.commits == 0             # held: no commit while it cannot be queued
    q.drain()
    assert done.wait(5) and c.commits == 1


def test_stop_while_held_returns_without_commit():
    q = StreamQueue(capacity=1)
    q.put("x", '{"filler":1}')
    c = FakeConsumer()
    r = _reader(q, consumer=c)
    r._stop.set()
    assert r.handle([Msg("sec.ocsf", b'{"a":1}\n{"a":2}')]) is False and c.commits == 0


def test_run_loop_consumes_and_closes():
    q = StreamQueue(capacity=100)
    c = FakeConsumer([[Msg("sec.ocsf", json.dumps(OCSF).encode())]])
    r = KafkaReader(config={"group.id": "t"}, topics={"sec.ocsf": "ocsf"}, queue=q, consumer_factory=lambda cfg: c,
                    poll_timeout_s=0.01)
    r.start()
    for _ in range(200):
        if len(q):
            break
        threading.Event().wait(0.01)
    r.stop()
    assert c.subscribed == ["sec.ocsf"] and c.commits == 1 and c.closed and len(q) == 1


def test_from_env(monkeypatch):
    for k in ("AEGIS_KAFKA_BOOTSTRAP", "AEGIS_KAFKA_TOPICS", "AEGIS_KAFKA_SECURITY_PROTOCOL"):
        monkeypatch.delenv(k, raising=False)
    assert kafka_from_env(consumer_factory=lambda c: FakeConsumer()) is None
    monkeypatch.setenv("AEGIS_KAFKA_BOOTSTRAP", "k:9093")
    monkeypatch.setenv("AEGIS_KAFKA_SECURITY_PROTOCOL", "SSL")
    assert kafka_from_env(consumer_factory=lambda c: FakeConsumer()) is None      # no topics
    monkeypatch.setenv("AEGIS_KAFKA_TOPICS", "sec.ocsf=ocsf")
    r = kafka_from_env(queue=StreamQueue(capacity=10), consumer_factory=lambda c: FakeConsumer())
    assert isinstance(r, KafkaReader) and r.topics == {"sec.ocsf": "ocsf"}
    r.stop()
