"""Statuses and exit codes that told the operator the wrong thing (code review 2026-11-03, group E: C4–C11, E14)."""

from __future__ import annotations

import json
import types
import urllib.error
import urllib.request

import pytest

from aegis.ingest.console_api import ConsoleAPI
from aegis.ingest.http_push import PushServer
from aegis.ingest.stream import StreamQueue


def _req(url, token=None, data=None):
    h = {"Authorization": f"Bearer {token}"} if token else {}
    if data is not None:
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=h, method="POST" if data is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


# ---- C5: proposal decisions -----------------------------------------------------------------------------

def _proposals(tmp_path):
    hitl = tmp_path / "hitl"; hitl.mkdir()
    rows = [{"id": "prop-1", "change_type": "model_promotion", "summary": "promote run-7", "ts": 1793500000.0},
            {"id": "prop-2", "change_type": "rule", "summary": "x", "status": "applied", "ts": 1793500001.0}]
    (hitl / "proposals.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    return ConsoleAPI(tmp_path / "audit.jsonl", hitl)


def test_unknown_proposal_is_404(tmp_path):
    api = _proposals(tmp_path)
    assert api.decide_proposal("prop-nope", "accept", decided_by="ciso")[0] == 404
    assert not (tmp_path / "hitl" / "proposal-decisions.jsonl").exists()


def test_second_decision_on_a_proposal_is_409(tmp_path):
    api = _proposals(tmp_path)
    assert api.decide_proposal("prop-1", "accept", decided_by="ciso")[0] == 200
    code, body = api.decide_proposal("prop-1", "reject", decided_by="ciso")
    assert code == 409 and body["status"] == "accepted"
    assert api.decide_proposal("prop-2", "accept", decided_by="ciso")[0] == 409        # applied is final


# ---- C6 / C11 / E14 over HTTP ---------------------------------------------------------------------------

@pytest.fixture
def server(tmp_path):
    def make(hitl_dir, status=None):
        s = PushServer(token="push", read_token="read", console_token="console", bind="127.0.0.1:0", queue=StreamQueue(),
                       console=ConsoleAPI(tmp_path / "audit.jsonl", hitl_dir), status=status).start()
        made.append(s)
        return f"http://127.0.0.1:{s.port}"
    made: list = []
    yield make
    for s in made:
        s.stop()


def test_reads_without_a_hitl_dir_are_503_not_an_empty_queue(server):
    base = server(None)
    assert _req(f"{base}/api/approvals", token="read")[0] == 503
    assert _req(f"{base}/api/soc/proposals", token="read")[0] == 503
    assert _req(f"{base}/api/soc/chains", token="read")[0] == 200


def test_read_token_deciding_is_403_and_a_bad_token_401(server, tmp_path):
    base = server(tmp_path / "hitl")
    url = f"{base}/api/approvals/aegis_A_block_1a2b3c/approve"
    assert _req(url, token="read", data=b"{}")[0] == 403
    assert _req(url, token="push", data=b"{}")[0] == 403
    assert _req(url, token="nope", data=b"{}")[0] == 401
    assert _req(url, data=b"{}")[0] == 401


def test_healthz_is_degraded_when_the_status_check_fails(server, tmp_path):
    def broken():
        raise OSError("audit dir unreadable")
    base = server(tmp_path / "hitl", status=broken)
    code, body = _req(f"{base}/healthz", token="read")
    assert code == 503 and "status check failed" in body["degraded"][0]


# ---- C4: a posture gate does not pass on scans that failed ------------------------------------------------

def test_posture_gate_fails_when_every_scan_failed(monkeypatch, tmp_path, capsys):
    from aegis.posture import __main__ as cli
    rec = {"run_id": "r1", "counts": {"open": 0, "new": 0, "resolved": 0, "overdue": 0, "waived": 0, "stale": 0},
           "summary": {}, "open": [], "scans": [{"name": "aws", "type": "cspm", "status": "error", "error": "AccessDenied"}]}
    monkeypatch.setattr(cli.runner, "load_config", lambda *a, **k: types.SimpleNamespace(store=tmp_path))
    monkeypatch.setattr(cli.runner, "run_once", lambda cfg: rec)
    assert cli.main(["run", "--config", "x.yaml", "--fail-on", "high"]) == 2
    assert "cannot pass" in capsys.readouterr().err
    assert cli.main(["run", "--config", "x.yaml"]) == 0                                # no gate asked for: report only


# ---- C7: a 200 from the control endpoint is not a block -------------------------------------------------

@pytest.mark.parametrize("reply,ok", [({"accepted": True, "pushed": ["203.0.113.5"]}, True),
                                      ({"accepted": False, "pushed": []}, False),
                                      ({"ok": True, "blocked_ips": ["203.0.113.5"]}, True),
                                      ({"ok": False, "blocked_ips": []}, False),
                                      ({"ok": True, "blocked_ips": ["198.51.100.1"]}, False),
                                      ({}, False)])
def test_soc_live_only_claims_containment_the_target_confirms(reply, ok):
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location("soc_live_c7", Path(__file__).resolve().parents[2] / "scripts" / "soc_live.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert (mod._enforcement_refused(reply, "203.0.113.5") == "") is ok


# ---- C8: the local shadow report reads analyst decisions ------------------------------------------------

def test_local_shadow_report_reads_file_transport_decisions(tmp_path, monkeypatch):
    from aegis.shadow.__main__ import load_local_decisions
    monkeypatch.delenv("AEGIS_CONSOLE_TOKEN", raising=False); monkeypatch.delenv("AEGIS_DECISION_KEY", raising=False)
    hitl = tmp_path / "hitl"; hitl.mkdir()
    (hitl / "cards.jsonl").write_text(json.dumps({"kind": "approval", "id": "ap1", "args": {"alert_id": "A1", "action_type": "throttle",
                                                                                          "target": "203.0.113.5"}}) + "\n")
    (hitl / "decisions.jsonl").write_text(
        json.dumps({"approval_id": "ap1", "status": "approved", "decided_by": "ciso"}) + "\n"
        + json.dumps({"approval_id": "ap1", "status": "approved", "decided_by": "aegis:hitl-timeout"}) + "\n"   # not a human
        + json.dumps({"approval_id": "unknown", "status": "approved", "decided_by": "ciso"}) + "\n")
    out = load_local_decisions(str(hitl))
    assert out == {"A1": [{"action_type": "throttle", "target": "203.0.113.5", "decision": "approved", "decided_by": "ciso"}]}


def test_shadow_report_can_fail_when_nothing_is_ready(tmp_path, capsys):
    from aegis.shadow.__main__ import main
    assert main(["report", "--receipts", str(tmp_path / "none.jsonl"), "--fail-unless-ready"]) == 1
    assert main(["report", "--receipts", str(tmp_path / "none.jsonl")]) == 0


# ---- C9: --status tells degraded from unreachable --------------------------------------------------------

def test_status_reports_degraded_not_unreachable(monkeypatch, tmp_path, capsys):
    import io

    from aegis import service

    def fake(url, timeout=5):
        raise urllib.error.HTTPError(url, 503, "Service Unavailable", {}, io.BytesIO(b'{"degraded": ["audit disk full"]}'))
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    assert service.status_main(str(tmp_path / "audit.jsonl")) == 1
    out = capsys.readouterr().out
    assert "DEGRADED" in out and "audit disk full" in out and "unreachable" not in out


# ---- C10: retrain sync fails when an accepted promotion is refused ---------------------------------------

def test_retrain_sync_exits_1_when_a_promotion_was_refused(tmp_path):
    from aegis.finetune import retrain
    st = retrain.State.load(tmp_path)
    st.runs["run-7"] = {"stage": "failed", "adapter": str(tmp_path / "a"), "sha256": "x"}
    st.save()
    a = types.SimpleNamespace(runs=str(tmp_path), dry_run=False)
    rule = {"change": {"run": "run-7"}, "decided_by": "ciso"}
    assert retrain.cmd_sync(a, accepted=lambda dry: [rule]) == 1
    assert retrain.cmd_sync(a, accepted=lambda dry: []) == 0
