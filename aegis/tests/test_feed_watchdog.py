"""Feed-liveness watchdog: a source that was producing and goes quiet must alert,
and recover cleanly. Driven with a fake clock so no test sleeps."""

from __future__ import annotations

from aegis.ingest.watchdog import FeedWatchdog, feed_watchdog_from_env


class Clock:
    def __init__(self, t: float = 1000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> "Clock":
        self.t += dt
        return self


def _wd(clock: Clock, **kw):
    fired: list = []
    kw.setdefault("default_silence_s", 900.0)
    wd = FeedWatchdog(clock=clock, on_alert=fired.append, **kw)
    return wd, fired


def test_arms_on_first_event_then_goes_silent():
    clk = Clock()
    wd, fired = _wd(clk)
    wd.record("sentinel")                       # first event arms the feed
    assert wd.sweep() == []                     # fresh — not silent
    clk.advance(901)
    out = wd.sweep()
    assert len(out) == 1 and out[0].source == "sentinel" and out[0].state == "silent"
    assert [a for a in fired if a.state == "silent"]
    # idempotent: a second sweep while still silent does not re-fire
    assert wd.sweep() == []


def test_recovery_clears_and_can_rearm():
    clk = Clock()
    wd, fired = _wd(clk)
    wd.record("waf")
    clk.advance(1000)
    assert wd.sweep()[0].state == "silent"
    clk.advance(5)
    wd.record("waf")                            # feed comes back
    assert fired[-1].state == "recovered"
    assert wd.status()["silent_count"] == 0
    # silent again only after a fresh window of quiet
    assert wd.sweep() == []
    clk.advance(901)
    assert wd.sweep()[0].state == "silent"


def test_unseen_unexpected_source_never_alarms():
    clk = Clock()
    wd, fired = _wd(clk)
    clk.advance(10_000)
    assert wd.sweep() == [] and fired == []     # nothing armed → nothing to miss


def test_ignored_sources_are_not_watched():
    clk = Clock()
    wd, _ = _wd(clk)
    wd.record("stream")                         # drain placeholder
    wd.record("sample")                         # demo feed
    clk.advance(10_000)
    assert wd.sweep() == []
    assert wd.status()["feeds"] == []


def test_boot_armed_source_respects_grace_then_alarms():
    clk = Clock()
    wd, _ = _wd(clk, expect=["sentinel"], boot_grace_s=1800.0)
    clk.advance(901)                            # past default window, inside boot grace
    assert wd.sweep() == []
    clk.advance(1000)                           # now past the 1800s grace
    out = wd.sweep()
    assert len(out) == 1 and out[0].last_event_at is None   # never produced an event


def test_per_source_window_overrides_default():
    clk = Clock()
    wd, _ = _wd(clk, per_source={"cloudflare": 60.0})
    wd.record("cloudflare")
    clk.advance(61)
    assert wd.sweep()[0].source == "cloudflare"   # 60s window, not the 900s default


def test_sync_stream_counts_only_new_deltas():
    clk = Clock()
    wd, _ = _wd(clk, per_source={"firehose": 100.0})
    wd.sync_stream({"firehose": 5})             # first snapshot arms + marks alive
    clk.advance(50)
    wd.sync_stream({"firehose": 5})             # no new events — cumulative unchanged
    clk.advance(51)                             # 101s since the last *new* event
    out = wd.sweep()
    assert len(out) == 1 and out[0].source == "firehose"
    assert wd.status()["feeds"][0]["events"] == 5


def test_sync_stream_keepalive_prevents_silence():
    clk = Clock()
    wd, fired = _wd(clk, per_source={"cloudflare": 100.0})
    for i in range(1, 6):
        wd.sync_stream({"cloudflare": i})       # a new event every 40s
        clk.advance(40)
        assert wd.sweep() == []
    assert fired == []                          # steady feed never alarms


def test_from_env_off_returns_none():
    assert feed_watchdog_from_env(environ={}) is None
    assert feed_watchdog_from_env(environ={"AEGIS_FEED_WATCHDOG": "0"}) is None


def test_from_env_parses_windows_and_expect():
    clk = Clock()
    wd = feed_watchdog_from_env(clock=clk, environ={
        "AEGIS_FEED_WATCHDOG": "1",
        "AEGIS_FEED_SILENCE_SECONDS": "300",
        "AEGIS_FEED_SILENCE_SENTINEL": "120",
        "AEGIS_FEED_EXPECT": "sentinel, cloudflare",
    })
    assert wd is not None
    assert wd.default_silence_s == 300.0
    assert wd.window_for("sentinel") == 120.0
    assert wd.window_for("waf") == 300.0        # falls back to default
    # both expected feeds are armed from boot
    sources = {f["source"] for f in wd.status()["feeds"]}
    assert {"sentinel", "cloudflare"} <= sources


def test_metrics_gauge_set_on_silence():
    from aegis.agents.shared.observability import METRICS
    clk = Clock()
    wd, _ = _wd(clk)
    wd.record("zeek-ndr-unique-xyz")
    clk.advance(901)
    wd.sweep()
    snap = METRICS.snapshot()
    silent = [g for g in snap["gauges"]
              if g["name"] == "aegis_feed_silent" and g["labels"].get("source") == "zeek-ndr-unique-xyz"]
    assert silent and silent[0]["value"] == 1.0
