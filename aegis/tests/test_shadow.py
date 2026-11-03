"""Phase 1.5 — receipts logged + shipped, shadow comparison, flip verdicts."""

from __future__ import annotations

import json
import tempfile
import time

import pytest

from aegis.agents.response.agent import ResponseAgent
from aegis.agents.response.connectors import Connector, ConnectorRegistry
from aegis.agents.response.receipts import ReceiptLog, receipt_log_from_env, receipt_mode
from aegis.agents.shared.evidence_chain import EvidenceChain, RecommendedAction
from aegis.shadow import Thresholds, build_report, render_text, to_json
from aegis.shadow.__main__ import load_local, main
from aegis.tests.helpers import alert_for


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for k in ("AEGIS_ENFORCEMENT_MODE", "AEGIS_RECEIPTS", "AEGIS_RECEIPTS_PATH", "AEGIS_PROTECTED_TARGETS",
              "ACP_DASHBOARD_URL"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ACP_HOME", tempfile.mkdtemp())


class WafStub(Connector):
    name = "waf"
    actions = frozenset({"throttle", "challenge", "block"})

    def _do_apply(self, action, key, ttl_sec):
        return f"waf-{key[:6]}", f"[waf] {action.action_type} {action.target}", key

    def _do_rollback(self, receipt):
        return "[waf] undone"


def _chain(alert_id: str, actions: list[tuple[str, str, bool]], verdict="suspicious") -> EvidenceChain:
    return EvidenceChain(
        alert_id=alert_id, investigated_by="perimeter", verdict=verdict, confidence=0.8,
        recommended_actions=[RecommendedAction(action_type=a, target=t, reasoning="r", requires_hitl=h, confidence=0.8)
                             for a, t, h in actions],
    )


class FakeSink:
    enabled = True

    def __init__(self):
        self.shipped: list[tuple[str, dict]] = []

    def ship_receipt(self, receipt, event="apply"):
        self.shipped.append((event, receipt.to_dict()))
        return {"status": "created"}


def test_receipts_are_logged_locally_and_shipped(tmp_path):
    sink = FakeSink()
    log = ReceiptLog(tmp_path / "r.jsonl", sink=sink)
    reg = ConnectorRegistry([WafStub(dry_run=True)], on_receipt=[log])
    agent = ResponseAgent(connectors=reg)
    summary = agent.execute((_c := _chain("A-1", [("throttle", "203.0.113.9", False), ("block", "203.0.113.9", True)])), alert_for(_c))
    assert [e.action.action_type for e in summary.executed] == ["throttle"]
    assert summary.receipts and summary.receipts[0].dry_run and summary.receipts[0].status == "dry_run"
    agent.approve(summary.hitl_queue[0].action, approver="ciso@bank.test", source_alert_id="A-1")
    entries = list(ReceiptLog.read(log.path))
    assert [e["event"] for e in entries] == ["apply", "apply"]
    assert entries[0]["mode"] == "shadow" and entries[0]["action_type"] == "throttle" and entries[0]["alert_id"] == "A-1"
    assert entries[1]["action_type"] == "block" and entries[1]["approver"] == "ciso@bank.test"
    assert [e for e, _ in sink.shipped] == ["apply", "apply"] and log.shipped == 2
    # lifecycle events: rollback via the registry is an event too
    reg.rollback(summary.receipts[0], reason="test")
    entries = list(ReceiptLog.read(log.path))
    assert entries[-1]["event"] == "rollback" and entries[-1]["status"] == "rolled_back"
    latest = ReceiptLog.latest_per_receipt(entries)
    assert len(latest) == 2 and latest[0]["status"] == "rolled_back"
    # a failing subscriber never blocks enforcement
    reg2 = ConnectorRegistry([WafStub(dry_run=True)], on_receipt=[lambda e, r: 1 / 0])
    r = reg2.apply(RecommendedAction(action_type="challenge", target="s", reasoning="r", requires_hitl=False, confidence=0.5))
    assert r.status == "dry_run"
    # logging fallback → mode "log"
    assert receipt_mode(ConnectorRegistry().apply(summary.hitl_queue[0].action, alert_id="A-1")) == "log"


def test_receipt_log_from_env(tmp_path, monkeypatch):
    assert receipt_log_from_env(tmp_path) is not None and receipt_log_from_env(tmp_path).path == tmp_path / "_receipts.jsonl"
    monkeypatch.setenv("AEGIS_RECEIPTS_PATH", str(tmp_path / "x.jsonl"))
    assert receipt_log_from_env(tmp_path).path == tmp_path / "x.jsonl"
    monkeypatch.setenv("AEGIS_RECEIPTS", "0")
    assert receipt_log_from_env(tmp_path) is None


def _receipt(i, action="throttle", connector="waf", mode="shadow", status="dry_run", alert=None, day=0, target=None):
    return {"receipt_id": f"rcpt_{i}", "connector": connector, "action_type": action, "target": target or f"203.0.113.{i % 50}",
            "status": status, "dry_run": mode == "shadow", "mode": mode, "alert_id": alert or f"AL-{i}",
            "applied_at": 1_760_000_000 + day * 86400, "approver": ""}


def test_report_groups_judges_and_orders_flip_candidates():
    receipts, decisions = [], {}
    # throttle via waf: 24 receipts over 16 days, 12 reviewed, all agree → ready
    for i in range(24):
        receipts.append(_receipt(i, day=i * 16 // 23, alert=f"AL-T{i}"))
        if i % 2 == 0:
            decisions[f"AL-T{i}"] = [{"action_type": "throttle", "decision": "approved"}]
    # challenge via waf: enough volume, one explicit rejection → not yet
    for i in range(30):
        receipts.append(_receipt(100 + i, action="challenge", day=i, alert=f"AL-C{i}"))
        decisions[f"AL-C{i}"] = [{"action_type": "challenge", "decision": "approved" if i else "rejected"}]
    # block via waf (always HITL) → hitl_only; block via log fallback → log_only; live group stays live
    receipts.append(_receipt(200, action="block", alert="AL-B1"))
    receipts.append(_receipt(201, action="block", connector="log", mode="log", status="applied", alert="AL-B2"))
    receipts.append(_receipt(202, action="throttle", connector="zscaler", mode="live", status="applied", alert="AL-L1"))
    receipts.append(_receipt(203, action="notify_user", status="failed", alert="AL-F1"))
    receipts.append(_receipt(204, action="monitor", status="unsupported", alert="AL-U1"))    # ignored
    chains = [{"alert_id": "AL-T1", "verdict": "malicious",
               "recommended_actions": [{"action_type": "throttle", "requires_hitl": False},
                                       {"action_type": "block", "requires_hitl": True}]},
              {"chain": {"alert_id": "AL-C0", "recommended_actions": [{"action_type": "challenge", "requires_hitl": False}]},
               "human": [{"action_type": "challenge", "decision": "rejected"}]}]
    rep = build_report(receipts, chains, decisions_by_alert=decisions, protected_targets=["203.0.113.0/24"])
    by = {(g.connector, g.action_type, g.mode): g for g in rep.groups}
    t = by[("waf", "throttle", "shadow")]
    assert (t.n, t.agree, t.disagree, t.unreviewed) == (24, 12, 0, 12) and t.verdict == "ready" and t.window_days >= 14
    assert t.protected_hits == 24 and len(t.targets) == 24
    c = by[("waf", "challenge", "shadow")]
    assert c.verdict == "not_yet" and c.disagree == 1 and any("agreement" in r for r in c.reasons)
    assert by[("waf", "block", "shadow")].verdict == "hitl_only"
    assert by[("log", "block", "log")].verdict == "log_only"
    assert by[("zscaler", "throttle", "live")].verdict == "live"
    f = by[("waf", "notify_user", "shadow")]
    assert f.failed == 1 and f.verdict == "not_yet" and any("vendor failure" in r for r in f.reasons)
    assert ("waf", "monitor", "shadow") not in by
    assert rep.summary["receipts"] == 58 and rep.summary["ready"] == 1 and rep.summary["by_mode"]["shadow"] == 56
    assert rep.flip_candidates[0]["action_type"] == "throttle" and "live" in rep.flip_candidates[0]["next_step"]
    # requests: what was asked vs. decided (chain-carried decisions count too)
    reqs = {r.action_type: r for r in rep.requests}
    assert reqs["throttle"].asked_auto == 1 and reqs["block"].asked_hitl == 1
    assert reqs["challenge"].rejected >= 1 and reqs["challenge"].approval_rate is not None
    text = render_text(rep)
    assert "READY TO FLIP LIVE" in text and "throttle" in text and "hitl_only" in text
    d = json.loads(to_json(rep))
    assert d["summary"]["ready"] == 1 and d["groups"][0]["action_type"] == "throttle"   # flip order first


def test_thresholds_are_applied():
    receipts = [_receipt(i, day=i, alert=f"AL-{i}") for i in range(5)]
    decisions = {f"AL-{i}": [{"action_type": "throttle", "decision": "approved"}] for i in range(5)}
    strict = build_report(receipts, decisions_by_alert=decisions)
    assert strict.groups[0].verdict == "not_yet" and any(r.startswith("n=5") for r in strict.groups[0].reasons)
    loose = build_report(receipts, decisions_by_alert=decisions, thresholds=Thresholds(min_n=5, min_reviewed=5, window_days=4))
    assert loose.groups[0].verdict == "ready"
    empty = build_report([])
    assert empty.summary["receipts"] == 0 and "no receipts yet" in render_text(empty)


def test_cli_local_and_dashboard_modes(tmp_path, monkeypatch, capsys):
    log = ReceiptLog(tmp_path / "r.jsonl")
    reg = ConnectorRegistry([WafStub(dry_run=True)], on_receipt=[log])
    agent = ResponseAgent(connectors=reg)
    agent.execute((_c := _chain("A-1", [("throttle", "203.0.113.9", False)])), alert_for(_c))
    audit = tmp_path / "audit.jsonl"
    audit.write_text(json.dumps({"alert_id": "A-1", "verdict": "suspicious",
                                 "recommended_actions": [{"action_type": "throttle", "requires_hitl": False}]}) + "\n")
    receipts, chains = load_local(str(log.path), str(audit))
    assert len(receipts) == 1 and len(chains) == 1
    assert main(["report", "--receipts", str(log.path), "--audit", str(audit), "--out", str(tmp_path / "rep.json")]) == 0
    out = capsys.readouterr().out
    assert "waf" in out and "throttle" in out and "not_yet" in out
    assert json.loads((tmp_path / "rep.json").read_text())["summary"]["receipts"] == 1
    assert main(["report", "--dashboard"]) == 2                     # no ACP_DASHBOARD_URL

    class Dash:
        def __call__(self, method, url, body, headers, timeout):
            assert headers.get("X-API-Key") == "k3y"
            if "/api/soc/receipts" in url:
                return {"receipts": [_receipt(1, alert="AL-1"), _receipt(2, alert="AL-2")], "next_cursor": None}
            if "/api/soc/dataset" in url:
                return {"records": [{"chain": {"alert_id": "AL-1", "chain": {"alert_id": "AL-1", "recommended_actions": []}},
                                     "human": [{"action_type": "throttle", "decision": "approved"}]}], "next_cursor": None}
            raise AssertionError(url)

    from aegis.shadow.__main__ import load_dashboard
    receipts, chains = load_dashboard("https://dash.test", "k3y", transport=Dash())
    rep = build_report(receipts, chains)
    g = rep.groups[0]
    assert (g.n, g.agree, g.unreviewed) == (2, 1, 1) and rep.summary["decisions"] == 1


def test_main_py_wiring_imports():
    """main.py builds the registry with the receipt log; the names it imports must exist."""
    from aegis.main import receipt_log_from_env as f1, registry_from_env as f2
    assert callable(f1) and callable(f2)
    with tempfile.TemporaryDirectory() as td:
        log = receipt_log_from_env(td)
        reg = f2(on_receipt=[log])
        reg.apply(RecommendedAction(action_type="monitor", target="x", reasoning="r", requires_hitl=False, confidence=0.5),
                  alert_id="A")
        assert log.events == 1 and time.time() - list(ReceiptLog.read(log.path))[0]["recorded_at"] < 60


def test_approving_another_action_is_not_agreement():
    """20 throttle receipts; the analyst only ever approved `monitor` on those alerts → nothing reviewed."""
    receipts = [_receipt(i, day=i, alert=f"AL-{i}") for i in range(20)]
    decisions = {f"AL-{i}": [{"action_type": "monitor", "decision": "approved"}] for i in range(20)}
    rep = build_report(receipts, decisions_by_alert=decisions)
    g = next(g for g in rep.groups if g.action_type == "throttle")
    assert (g.agree, g.unreviewed) == (0, 20) and g.verdict != "ready"
