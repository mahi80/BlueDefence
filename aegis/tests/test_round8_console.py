"""Round-8 review, console side of the receiver (U8-1 / U8-2).

U8-1: the approval card's ``target`` is the 256-char display cut, so the console never matched a long-target action
to its card (no Approve / Reject). The receiver now also serves ``target_full`` — what the card binds to.
U8-2: an approved card the service has not run yet looked final; the receiver now says ``settled`` so the console can
show "approved — awaiting execution" with Reject while the backend still accepts it.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace as NS

from aegis.hitl.filequeue import FileHITL
from aegis.ingest.console_api import ConsoleAPI

LONG = "https://netbanking.example.in/retail/api/v2/payments/transfer?x=" + "A" * 300


def _setup(tmp_path: Path):
    hitl = tmp_path / "hitl"
    audit = tmp_path / "audit.jsonl"
    chain = NS(alert_id="A-1", verdict="malicious", confidence=0.95, investigated_by="aegis", specialist_invocations=[],
               evidence=[], integrity_hash="h1", metadata={})
    audit.write_text(json.dumps({"alert_id": "A-1", "verdict": "malicious", "confidence": 0.95, "integrity_hash": "h1",
                                 "started_at": time.time(), "recommended_actions": [
                                     {"action_type": "block", "target": LONG, "requires_hitl": False},
                                     {"action_type": "isolate", "target": "host-7", "requires_hitl": True}]}) + "\n")
    q = FileHITL(hitl, state_path=tmp_path / "state.json")
    id_long = q.request(NS(action_type="block", target=LONG, confidence=0.9, reasoning="exfil", requires_hitl=False), chain)
    id_iso = q.request(NS(action_type="isolate", target="host-7", confidence=0.9, reasoning="lateral", requires_hitl=True), chain)
    return q, ConsoleAPI(audit, hitl), id_long, id_iso


def test_u8_1_card_serves_full_target_matching_chain_action(tmp_path):
    _, api, id_long, id_iso = _setup(tmp_path)
    rows = {a["id"]: a for a in api.approvals()["approvals"]}
    chain = api.chain("A-1")
    chain_target = chain["recommended_actions"][0]["target"]
    assert len(chain_target) > 256
    assert len(rows[id_long]["target"]) == 256                 # display cut unchanged
    assert rows[id_long]["target_full"] == chain_target == LONG  # what the console matches on
    assert rows[id_iso]["target_full"] == "host-7"


def test_u8_1_target_full_falls_back_to_display_target_without_action_text(tmp_path):
    hitl = tmp_path / "hitl"
    hitl.mkdir()
    (hitl / "cards.jsonl").write_text(json.dumps({"kind": "approval", "ts": time.time(), "id": "x1", "alert_id": "A",
                                                  "args": {"action_type": "block", "target": "1.2.3.4"}}) + "\n")
    row = ConsoleAPI(None, hitl).approvals()["approvals"][0]
    assert row["target_full"] == "1.2.3.4"


def test_u8_2_settled_marker_reported(tmp_path, monkeypatch):
    q, api, id_long, id_iso = _setup(tmp_path)
    assert api.decide(id_iso, "approved", decided_by="ciso:alice", reason="go")[0] == 200
    rows = {a["id"]: a for a in api.approvals()["approvals"]}
    assert rows[id_iso]["status"] == "approved" and rows[id_iso]["settled"] is False   # approved, not run yet
    assert rows[id_long]["status"] == "pending" and rows[id_long]["settled"] is False
    # still rejectable while unsettled (R4-7) — the console now offers the button
    assert api.decide(id_iso, "rejected", decided_by="ciso:bob", reason="wrong host")[0] == 200
    # once the service writes its settled marker the card is final
    p = q._pending[id_long]
    q._record_settled(p, "approved", "ciso:alice", "")
    rows = {a["id"]: a for a in api.approvals()["approvals"]}
    assert rows[id_long]["settled"] is True and rows[id_long]["status"] == "approved"
    assert api.decide(id_long, "rejected", decided_by="ciso:bob", reason="late")[0] == 409
