"""The analyst console's read/decide API, served by the push receiver from the host's own files."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

import pytest

from aegis.ingest.console_api import ConsoleAPI
from aegis.ingest.http_push import PushServer
from aegis.ingest.stream import StreamQueue


def _chain(alert_id: str, verdict: str, h: str, **meta) -> dict:
    return {
        "alert_id": alert_id, "investigated_by": "perimeter", "started_at": "2026-11-01T05:00:00+00:00",
        "completed_at": "2026-11-01T05:00:02+00:00", "verdict": verdict, "confidence": 0.91,
        "evidence": [{"source": "perimeter", "signal": "sqli in query string", "weight": "high", "raw_data": {"path": "/login.html"}}],
        "reasoning": [{"step": 1, "action": "parse", "observation": "WAF BLOCK", "conclusion": "malicious"}],
        "recommended_actions": [{"action_type": "block", "target": "203.0.113.9", "reasoning": "repeat offender", "requires_hitl": True, "confidence": 0.8}],
        "specialist_invocations": ["perimeter", "intel_enrich"],
        "metadata": {"alert": {"source": "aws-waf"}, "summary": "SQLi probe against the decoy", **meta},
        "integrity_hash": h,
    }


@pytest.fixture
def files(tmp_path):
    audit = tmp_path / "audit.jsonl"
    with audit.open("w") as f:
        f.write(json.dumps(_chain("ALR-1", "malicious", "a" * 64)) + "\n")
        f.write(json.dumps(_chain("ALR-2", "benign", "b" * 64, governance_block={"reason": "x"}, swarm=["ioc_extract"])) + "\n")
        f.write("{not json\n")
        f.write(json.dumps(_chain("ALR-3", "suspicious", "c" * 64)))      # torn tail, no newline
    hitl = tmp_path / "hitl"
    hitl.mkdir()
    (hitl / "cards.jsonl").write_text(
        json.dumps({"kind": "approval", "ts": 1793500000.0, "id": "aegis_ALR-1_block_1a2b3c", "action": "block -> 203.0.113.9",
                    "args": {"alert_id": "ALR-1", "action_type": "block", "target": "203.0.113.9", "reasoning": "repeat offender",
                             "integrity_hash": "a" * 64, "investigated_by": "perimeter"}, "severity": "malicious", "alert_id": "ALR-1"}) + "\n"
        + json.dumps({"kind": "investigation", "ts": 1793500001.0, "approval_id": "aegis_ALR-1_block_1a2b3c", "investigation": {}}) + "\n")
    return audit, hitl


def test_chains_newest_first_and_tolerant(files):
    audit, hitl = files
    api = ConsoleAPI(audit, hitl)
    out = api.chains()
    assert [c["alert_id"] for c in out["chains"]] == ["ALR-2", "ALR-1"]       # torn + junk rows skipped, newest first
    row = out["chains"][0]
    assert row["chain_id"] == "b" * 64 and row["source"] == "aws-waf" and row["governance_blocked"] is True
    assert row["triage"] == "swarm" and row["action_types"] == ["block"] and row["evidence_count"] == 1
    assert out["chains"][1]["triage"] == "heuristic"


def test_chain_detail_by_hash_or_alert(files):
    audit, hitl = files
    api = ConsoleAPI(audit, hitl)
    c = api.chain("a" * 64)
    assert c and c["alert_id"] == "ALR-1" and c["evidence"][0]["signal"] == "sqli in query string"
    assert c["recommended_actions"][0]["requires_hitl"] is True and c["integrity_hash"] == "a" * 64
    assert api.chain("ALR-2")["chain_id"] == "b" * 64
    assert api.chain("nope") is None and api.chain("../etc") is None


def test_approvals_and_decide(files):
    audit, hitl = files
    api = ConsoleAPI(audit, hitl)
    a = api.approvals()["approvals"]
    assert len(a) == 1 and a[0]["status"] == "pending" and a[0]["action_type"] == "block" and a[0]["target"] == "203.0.113.9"
    assert api.decide("unknown", "approved", decided_by="ciso")[0] == 404
    assert api.decide("aegis_ALR-1_block_1a2b3c", "maybe", decided_by="ciso")[0] == 400
    code, out = api.decide("aegis_ALR-1_block_1a2b3c", "rejected", decided_by="ciso", reason="false positive", corrected_verdict="benign")
    assert code == 200
    rows = [json.loads(l) for l in (hitl / "decisions.jsonl").read_text().splitlines()]
    assert rows[0]["approval_id"] == "aegis_ALR-1_block_1a2b3c" and rows[0]["status"] == "rejected"
    assert rows[0]["decided_by"] == "ciso" and rows[0]["corrected_verdict"] == "benign" and rows[0]["via"] == "console"
    a = api.approvals()["approvals"]
    assert a[0]["status"] == "rejected" and a[0]["decided_by"] == "ciso" and a[0]["rationale"] == "false positive"
    assert api.decide("aegis_ALR-1_block_1a2b3c", "approved", decided_by="cio")[0] == 409      # one decision per card


def test_proposals_roundtrip(tmp_path):
    hitl = tmp_path / "h"; hitl.mkdir()
    (hitl / "proposals.jsonl").write_text(json.dumps({"id": "p1", "change_type": "model_promotion", "summary": "promote v5", "validation_passed": True, "ts": time.time()}) + "\n")
    api = ConsoleAPI(None, hitl)
    assert api.proposals()["proposals"][0]["status"] == "pending"
    assert api.decide_proposal("p1", "accept", decided_by="cio", rationale="gate pass")[0] == 200
    p = api.proposals()["proposals"][0]
    assert p["status"] == "accepted" and p["decided_by"] == "cio" and p["rationale"] == "gate pass"
    assert api.chains() == {"chains": [], "count": 0}


def _req(url, *, token=None, user=None, data=None):
    req = urllib.request.Request(url, data=data, method="POST" if data is not None else "GET")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if user:
        req.add_header("X-AEGIS-User", user)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def test_http_routes_and_tokens(files):
    audit, hitl = files
    srv = PushServer(token="push", read_token="read", console_token="console", bind="127.0.0.1:0", queue=StreamQueue(),
                     audit_path=audit, console=ConsoleAPI(audit, hitl)).start()
    try:
        base = f"http://127.0.0.1:{srv.port}"
        assert _req(f"{base}/api/soc/chains")[0] == 401
        assert _req(f"{base}/api/soc/chains", token="push")[0] == 401                     # the push token reads nothing
        code, out = _req(f"{base}/api/soc/chains", token="read")
        assert code == 200 and out["count"] == 2
        code, out = _req(f"{base}/api/soc/chains/" + "a" * 64, token="console")            # console token reads too
        assert code == 200 and out["alert_id"] == "ALR-1"
        assert _req(f"{base}/api/approvals", token="read")[1]["approvals"][0]["status"] == "pending"
        body = json.dumps({"rationale": "contain it"}).encode()
        assert _req(f"{base}/api/approvals/aegis_ALR-1_block_1a2b3c/approve", token="read", data=body)[0] == 401   # read token cannot decide
        code, out = _req(f"{base}/api/approvals/aegis_ALR-1_block_1a2b3c/approve", token="console", user="bu_head:asha", data=body)
        assert code == 200 and out["status"] == "approved"
        d = json.loads((hitl / "decisions.jsonl").read_text().splitlines()[0])
        assert d["decided_by"] == "bu_head:asha" and d["reason"] == "contain it"
        assert _req(f"{base}/api/approvals/x/approve", token="console", data=b"not json")[0] == 400
        assert _req(f"{base}/api/nope", token="read")[0] == 404
    finally:
        srv.stop()


def test_decisions_disabled_without_console_token(files):
    audit, hitl = files
    srv = PushServer(token="push", read_token="read", bind="127.0.0.1:0", queue=StreamQueue(), audit_path=audit,
                     console=ConsoleAPI(audit, hitl)).start()
    try:
        base = f"http://127.0.0.1:{srv.port}"
        assert _req(f"{base}/api/soc/chains", token="read")[0] == 200
        assert _req(f"{base}/api/approvals/aegis_ALR-1_block_1a2b3c/approve", token="read", data=b"{}")[0] == 401
    finally:
        srv.stop()
