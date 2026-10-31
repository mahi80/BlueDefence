"""aegis.service — the long-running SOC loop (roadmap 1.6)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.service import Service, build_pipeline, run_cycle


@pytest.fixture
def pipeline(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)   # stub LLM
    monkeypatch.delenv("ACP_DASHBOARD_URL", raising=False)   # no dashboard, no governance
    monkeypatch.setenv("AEGIS_SWARM", "0")
    monkeypatch.setenv("AEGIS_RECEIPTS_PATH", str(tmp_path / "receipts.jsonl"))
    return build_pipeline(tmp_path / "audit.jsonl", include_mock_intel=True)


def _alerts(n: int) -> list[dict]:
    from aegis.infra.siem_source import iter_sample_alerts
    out = []
    for a in iter_sample_alerts():
        out.append(a)
        if len(out) == n:
            break
    return out


def test_run_cycle_handles_alerts_and_counts(pipeline):
    stats = run_cycle(pipeline, iter(_alerts(3)))
    assert stats.alerts == 3 and stats.errors == 0
    assert sum(stats.verdicts.values()) == 3
    rows = [json.loads(l) for l in Path(pipeline.audit_path).read_text().splitlines() if l.strip()]
    assert len(rows) >= 3                                      # every alert sealed into the audit log
    assert "alerts=3" in stats.line()


def test_one_bad_alert_never_stops_the_cycle(pipeline, monkeypatch):
    real = pipeline.orch.handle
    calls = {"n": 0}

    def flaky(alert):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("specialist exploded")
        return real(alert)

    monkeypatch.setattr(pipeline.orch, "handle", flaky)
    stats = run_cycle(pipeline, iter(_alerts(3)))
    assert stats.alerts == 3 and stats.errors == 1 and sum(stats.verdicts.values()) == 2


def test_max_alerts_caps_a_cycle(pipeline):
    stats = run_cycle(pipeline, iter(_alerts(5)), max_alerts=2)
    assert stats.alerts == 2


def test_service_runs_one_cycle_from_env_and_stops(pipeline, monkeypatch):
    monkeypatch.setenv("AEGIS_SOURCES", "sample")
    svc = Service(pipeline, interval=1, max_alerts=4)
    assert svc.run(once=True) == 0
    assert svc.cycles == 1 and svc.history[0].alerts == 4


def test_service_audit_log_is_append_only_across_restarts(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ACP_DASHBOARD_URL", raising=False)
    monkeypatch.setenv("AEGIS_SWARM", "0")
    monkeypatch.setenv("AEGIS_RECEIPTS", "0")
    audit = tmp_path / "audit.jsonl"
    run_cycle(build_pipeline(audit, include_mock_intel=True), iter(_alerts(2)))
    n1 = len(audit.read_text().splitlines())
    run_cycle(build_pipeline(audit, include_mock_intel=True), iter(_alerts(2)))   # "restart": fresh=False
    n2 = len(audit.read_text().splitlines())
    assert n2 > n1 >= 2
    run_cycle(build_pipeline(audit, fresh=True, include_mock_intel=True), iter(_alerts(1)))   # the demo truncates
    assert len(audit.read_text().splitlines()) < n2


def test_banner_mentions_backend_and_mode(pipeline):
    b = pipeline.banner()
    assert "LLM backend" in b and "connectors " in b   # log-only / shadow / live
