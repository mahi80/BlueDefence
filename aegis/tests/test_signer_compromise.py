"""The Binance-pattern kill chain is a gate: every stage caught by its fast path, the drain contained."""

from __future__ import annotations

from aegis.eval.signer_compromise import gate, report, run

INF = float("inf")


def test_signer_compromise_gate():
    lats = (300.0, 3600.0, 28800.0, INF)
    shadow = report(run(breaker="shadow"), lats, breaker="shadow")
    live = report(run(breaker="live"), lats, breaker="live")
    assert gate(shadow, live) == []
    by = {s["stage"]: s for s in shadow["stages"]}
    assert by["2 c2"]["by"] == "egress" and by["2 c2"]["alerts"] >= 1       # the real NDR detector saw the beacon
    assert by["5 drain"]["verdict"] == "malicious"
    # shadow (the default) with no analyst still loses it all — the cost of not arming the breaker, measured
    never_shadow = next(c for c in shadow["containment"] if c["latency_s"] == INF)
    never_live = next(c for c in live["containment"] if c["latency_s"] == INF)
    assert never_shadow["lost_share"] == 1.0 and never_live["lost_share"] < never_shadow["lost_share"]
