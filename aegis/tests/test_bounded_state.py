"""In-memory state keyed by attacker-chosen values (IPs, senders, feed names) stays bounded (code review
2026-11-02): each store is driven past its cap and must stay at the cap while still detecting current traffic."""

from __future__ import annotations

import json

from aegis.agents.shared.bounded import BoundedDict


def test_bounded_dict_evicts_least_recently_written():
    evicted = []
    d = BoundedDict(3, on_evict=lambda k, v: evicted.append(k))
    for k in "abc":
        d[k] = 1
    d["a"] = 2                       # rewrite: a is now newest
    d["d"] = 1
    assert list(d) == ["c", "a", "d"] and evicted == ["b"] and d.evicted == 1
    _ = d["c"]                       # reads do not reorder, so serialising while iterating is safe
    assert json.loads(json.dumps(d)) == {"c": 1, "a": 2, "d": 1}
    assert d.setdefault("e", 5) == 5 and len(d) == 3


def test_campaign_store_caps_distinct_keys():
    from aegis.agents.orchestrator.walkers.campaign import EventStore
    st = EventStore(max_keys=50)
    for i in range(500):
        st.add({"id": f"a{i}", "source_ip": f"203.0.{i // 256}.{i % 256}", "url": "/login"}, now=1000.0 + i)
    assert len(st._rings) <= 50
    hot = {"id": "hot", "source_ip": "198.51.100.9", "url": "/login", "payload": "x" * 100_000}
    st.add(hot, now=2000.0)
    assert len(st._rings) <= 50
    assert all(len(e.text) <= 2048 for ring in st._rings.values() for e in ring)


def test_recon_sweep_map_stays_capped_and_still_detects(monkeypatch):
    from aegis.agents.perimeter import tools
    monkeypatch.setattr(tools, "_recon_seen", BoundedDict(100))
    for i in range(1000):
        tools.recon_sweep(f"10.1.{i // 256}.{i % 256}", {"url": f"/p{i}"}, now=1000.0)
    assert len(tools._recon_seen) == 100
    r = None
    for i in range(60):
        r = tools.recon_sweep("198.51.100.7", {"url": f"/admin/{i}"}, now=1001.0 + i * 0.1)
    assert r is not None and r.weight in ("medium", "high")
    assert len(tools._recon_seen) == 100


def test_outflow_book_caps_senders(monkeypatch):
    monkeypatch.setenv("AEGIS_OUTFLOW_MAX_SENDERS", "20")
    from aegis.agents.orchestrator.treasury import _OutflowBook
    book = _OutflowBook()
    for i in range(200):
        book.add(f"S{i}", 1000.0, 1e7, f"t{i}", 3600)
    assert len(book._by_sender) == 20
    n, total = book.add("S199", 1001.0, 1e7, "t-next", 3600)
    assert n == 2 and total == 2e7


def test_stream_counts_new_sources_past_the_cap_as_other():
    from aegis.ingest import stream
    q = stream.StreamQueue(capacity=100_000)
    for i in range(stream.MAX_SOURCES + 50):
        q.put(f"src-{i}", "{}")
    assert len(q.stats.by_source) <= stream.MAX_SOURCES + 1
    assert q.stats.by_source.get("other", 0) == 50


def test_watchdog_caps_feed_names():
    from aegis.ingest import watchdog
    w = watchdog.FeedWatchdog(clock=lambda: 1000.0, on_alert=lambda a: None)
    for i in range(watchdog._MAX_FEEDS + 30):
        w.record(f"feed-{i}")
    assert len(w._count) <= watchdog._MAX_FEEDS + 1 and w._count["other"] == 30


def test_egress_volume_rows_fold_without_losing_bytes():
    from aegis.agents.ndr import egress
    det = egress.EgressDetector()
    base = {"kind": "conn", "src": "10.0.0.5", "dst": "203.0.113.50", "dport": 443}
    n = egress._MAX_VOLUME_ROWS + 500
    for i in range(n):
        det.observe({**base, "ts": 1_793_000_000.0 + i * 0.01, "bytes_out": 1000, "bytes_in": 10})
    p = next(p for p in det._pairs.values() if p.volume)
    assert len(p.volume) <= egress._MAX_VOLUME_ROWS
    assert sum(o for _, o, _ in p.volume) == p.out_sum == 1000 * n


def test_spoofed_hostname_flood_does_not_evict_a_real_device(monkeypatch):
    """2026-11-03 review R11: the LRU evicted the real device that had gone silent; _tele was unbounded."""
    monkeypatch.setenv("AEGIS_NETOPS_MAX_DEVICES", "50")
    from aegis.agents.netops.assurance import NetworkAssurance
    now = [1_000_000.0]
    na = NetworkAssurance(clock=lambda: now[0], silent_s=180)
    na.add_link("core-1", "Te1/1", "dist-1", "Te0/1")
    for d, i in (("core-1", "Te1/1"), ("dist-1", "Te0/1")):
        na.observe({"kind": "telemetry", "device": d, "iface": i, "ts": now[0], "counters": {"in_errors": 0}})
    for i in range(2000):
        na.observe({"kind": "telemetry", "device": f"fake-{i}", "iface": "x", "ts": now[0], "counters": {"in_errors": 0}})
    assert "core-1" in na._last_tele and len(na._last_tele) <= 50 and len(na._tele) <= 400
    now[0] += 600
    out = na.observe({"kind": "telemetry", "device": "dist-1", "iface": "Te0/1", "ts": now[0], "counters": {"in_errors": 0}})
    assert any("core-1" in json.dumps(a) for a in out)


def test_keep_established_and_pinned_eviction():
    d = BoundedDict(3, keep_established=True, pinned=lambda k: k == "inv")
    for k in ("inv", "a", "b"):
        d[k] = 1
    for i in range(10):
        d[f"new{i}"] = 1
    assert "inv" in d and "a" in d and len(d) == 3          # newcomers churn, established keys stay
