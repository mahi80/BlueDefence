"""/metrics: Prometheus can scrape the SOC — on the push receiver, or standalone for a poll-only SOC."""

from __future__ import annotations

import re
import urllib.error
import urllib.request

import pytest

from aegis.agents.shared.observability import (
    METRICS, PROMETHEUS_CONTENT_TYPE, MetricsServer, metrics_server_from_env,
)
from aegis.ingest.http_push import PushServer
from aegis.ingest.stream import StreamQueue

_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # loopback, never the proxy
# one exposition sample: name{label="escaped value",...} value
_SAMPLE = re.compile(r'^[a-zA-Z_:][a-zA-Z0-9_:]*(\{([a-zA-Z_][a-zA-Z0-9_]*="(\\.|[^"\\\n])*",?)*\})? [-+0-9.eEinfNa]+$')


def _get(url, token=None):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"} if token else {})
    try:
        with _OPENER.open(req, timeout=5) as r:
            return r.status, r.headers.get("Content-Type"), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type"), e.read().decode()


def _assert_valid_exposition(text):
    for line in text.strip().splitlines():
        if line.startswith("# TYPE "):
            assert line.split()[3] in ("counter", "gauge"), line
            continue
        assert _SAMPLE.match(line), f"not a valid Prometheus sample: {line!r}"


def test_label_values_are_escaped_so_one_odd_label_cannot_break_the_scrape():
    METRICS.set("aegis_feed_silent", 1, source='we"ird\\feed\nname')
    METRICS.inc("aegis_alerts_processed_total", specialist="model_pull")
    text = METRICS.prometheus_text()
    assert 'source="we\\"ird\\\\feed\\nname"' in text
    _assert_valid_exposition(text)
    # one TYPE line per metric, before its samples
    assert text.count("# TYPE aegis_feed_silent gauge") == 1


def test_push_receiver_serves_metrics(monkeypatch):
    monkeypatch.delenv("AEGIS_METRICS_TOKEN", raising=False)
    METRICS.inc("aegis_verdicts_total", verdict="malicious", specialist="egress")
    srv = PushServer(token="", bind="127.0.0.1:0", queue=StreamQueue()).start()
    try:
        status, ctype, body = _get(f"{srv.url}/metrics")
        assert status == 200 and ctype == PROMETHEUS_CONTENT_TYPE
        assert 'aegis_verdicts_total{specialist="egress",verdict="malicious"}' in body
        _assert_valid_exposition(body)
        assert _get(f"{srv.url}/healthz")[0] == 200            # unchanged
    finally:
        srv.stop()


def test_metrics_token_is_enforced_when_set(monkeypatch):
    monkeypatch.setenv("AEGIS_METRICS_TOKEN", "scrape-secret")
    srv = PushServer(token="", bind="127.0.0.1:0", queue=StreamQueue()).start()
    try:
        assert _get(f"{srv.url}/metrics")[0] == 401
        assert _get(f"{srv.url}/metrics", token="wrong")[0] == 401
        assert _get(f"{srv.url}/metrics", token="scrape-secret")[0] == 200
    finally:
        srv.stop()


def test_metrics_scrape_does_not_need_the_ingest_token(monkeypatch):
    """Prometheus gets its own (optional) token; it never holds the token that can push alerts."""
    monkeypatch.delenv("AEGIS_METRICS_TOKEN", raising=False)
    srv = PushServer(token="ingest-secret", bind="127.0.0.1:0", queue=StreamQueue()).start()
    try:
        assert _get(f"{srv.url}/metrics")[0] == 200
        assert _get(f"{srv.url}/ingest/blocklist")[0] == 401     # the ingest side still needs its token
    finally:
        srv.stop()


def test_standalone_metrics_server_for_a_poll_only_soc(monkeypatch):
    monkeypatch.delenv("AEGIS_METRICS_TOKEN", raising=False)
    monkeypatch.setenv("AEGIS_METRICS_BIND", "127.0.0.1:0")
    METRICS.inc("aegis_actions_hitl_queued_total", action="block")
    ms = metrics_server_from_env()
    assert isinstance(ms, MetricsServer)
    try:
        status, ctype, body = _get(f"{ms.url}/metrics")
        assert status == 200 and ctype == PROMETHEUS_CONTENT_TYPE and "aegis_actions_hitl_queued_total" in body
        assert _get(f"{ms.url}/healthz")[0] == 200
        assert _get(f"{ms.url}/nope")[0] == 404
    finally:
        ms.stop()


def test_standalone_server_off_by_default_and_a_bad_bind_is_never_fatal(monkeypatch):
    monkeypatch.delenv("AEGIS_METRICS_BIND", raising=False)
    assert metrics_server_from_env() is None
    monkeypatch.setenv("AEGIS_METRICS_BIND", "203.0.113.250:9")    # not an address on this host
    assert metrics_server_from_env() is None


@pytest.fixture(autouse=True)
def _clean_registry():
    yield
    with METRICS._lock:
        for key in [k for k in METRICS.gauges if k[0] == "aegis_feed_silent"]:
            METRICS.gauges.pop(key, None)
