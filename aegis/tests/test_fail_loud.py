"""Failures that used to stay quiet (code review 2026-11-02): an intact audit log reported as broken after
rotation, a Splunk 401 that looped forever, and a stale deferred-queue cursor that hid parked alerts."""

from __future__ import annotations

import http.server
import json
import threading

from aegis.agents.shared.audit import AuditLog
from aegis.agents.shared.evidence_chain import EvidenceChain
from aegis.infra.splunk_source import SplunkConfig, SplunkConsumer
from aegis.ops.deferred import DeferredQueue


def _chain(i: int) -> EvidenceChain:
    return EvidenceChain(alert_id=f"A{i}", investigated_by="perimeter", verdict="suspicious", confidence=0.6)


def test_audit_verifies_after_rotation(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl", max_bytes=1500, fsync=False)
    for i in range(12):
        log.append(_chain(i))
    assert log.rotated_files(), "the test must actually rotate"
    assert log.verify()                         # the live segment alone, seeded from the last rotated tail
    assert log.verify(all_files=True)
    # tampering in the live segment is still caught
    rows = (tmp_path / "audit.jsonl").read_text().splitlines()
    row = json.loads(rows[0])
    row["verdict"] = "benign"
    rows[0] = json.dumps(row)
    (tmp_path / "audit.jsonl").write_text("\n".join(rows) + "\n")
    assert not log.verify()


def test_splunk_persistent_401_gives_up_instead_of_looping():
    counts = {"login": 0, "export": 0}

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            self.rfile.read(n)
            if self.path == "/services/auth/login":
                counts["login"] += 1
                body = json.dumps({"sessionKey": "k"}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                counts["export"] += 1
                self.send_response(401)
                self.send_header("Content-Length", "0")
                self.end_headers()

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        c = SplunkConsumer(SplunkConfig(base_url=f"http://127.0.0.1:{srv.server_address[1]}", username="u",
                                        password="p", max_retries=2, initial_backoff_s=0.01, max_backoff_s=0.01))
        done = {}

        def run():
            try:
                list(c.iter_alerts())
                done["r"] = "returned"
            except Exception as e:  # noqa: BLE001
                done["r"] = type(e).__name__
        t = threading.Thread(target=run, daemon=True)
        t.start()
        t.join(5.0)
        assert not t.is_alive(), f"still looping: {counts}"
        assert counts["login"] <= 2 and counts["export"] <= 3
    finally:
        srv.shutdown()


def test_deferred_cursor_without_its_file_is_reset(tmp_path):
    q = DeferredQueue(tmp_path / "deferred.jsonl")
    (tmp_path / "deferred.cursor").write_text("5000")       # a crash left the cursor; the spill file is gone
    q = DeferredQueue(tmp_path / "deferred.jsonl")
    for i in range(3):
        q.push({"id": f"park-{i}"})
    assert q.pending() == 3
    assert [a["id"] for a in q.pop(10)] == ["park-0", "park-1", "park-2"]
