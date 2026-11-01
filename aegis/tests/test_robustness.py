"""Chaos: what an on-prem box does to the service — crash mid-write, disk full, log rotation, restart mid-outage,
absurd clocks, a feed storm. Each test reproduces the fault and asserts the recovery, not just the absence of a crash."""

from __future__ import annotations

import errno
import json
import os
from pathlib import Path

import pytest

from aegis.agents.netops.assurance import NetworkAssurance
from aegis.agents.shared.audit import AuditLog, AuditWriteError
from aegis.agents.shared.evidence_chain import EvidenceChain
from aegis.ingest.netops import parse_syslog_line
from aegis.tests.test_netops import T, _campus, _down, _up


def _chain(i: int) -> EvidenceChain:
    return EvidenceChain(alert_id=f"A{i}", investigated_by="perimeter", verdict="suspicious", confidence=0.7)


# ------------------------------------------------------------------ audit --

def test_torn_tail_is_repaired_and_the_chain_resumes(tmp_path):
    p = tmp_path / "audit.jsonl"
    log = AuditLog(p)
    for i in range(3):
        log.append(_chain(i))
    tail = log.tail_hash
    with p.open("ab") as fh:                                   # the process died mid-write
        fh.write(b'{"alert_id": "A3", "verdict": "susp')
    log2 = AuditLog(p)                                         # restart
    assert log2.tail_hash == tail and log2.verify()
    assert list(tmp_path.glob("audit.jsonl.torn-*")), "the fragment is kept for forensics"
    log2.append(_chain(3))
    assert log2.verify() and sum(1 for _ in p.open()) == 4


def test_disk_full_fails_closed_and_recovers(tmp_path, monkeypatch):
    p = tmp_path / "audit.jsonl"
    log = AuditLog(p)
    log.append(_chain(0))
    tail = log.tail_hash
    real_open = Path.open

    def enospc(self, *a, **k):
        if self == p and "a" in str(a[0] if a else k.get("mode", "")):
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_open(self, *a, **k)
    monkeypatch.setattr(Path, "open", enospc)
    c = _chain(1)
    with pytest.raises(AuditWriteError) as ei:
        log.append(c)
    assert ei.value.errno == errno.ENOSPC and log.degraded and log.write_failures == 1
    assert c.integrity_hash == "" and log.tail_hash == tail, "nothing half-chained"
    monkeypatch.setattr(Path, "open", real_open)               # the operator freed space
    log.append(_chain(1))
    assert not log.degraded and log.verify() and sum(1 for _ in p.open()) == 2


def test_rotation_keeps_one_chain_across_files(tmp_path):
    p = tmp_path / "audit.jsonl"
    log = AuditLog(p, max_bytes=1500)                          # ~3 rows per segment
    for i in range(10):
        log.append(_chain(i))
    seg = log.rotated_files()
    assert len(seg) >= 2 and log.verify(all_files=True)
    rep = log.verify_report(all_files=True)
    assert rep["entries"] == 10 and len(rep["files"]) == len(seg) + 1
    # tamper with a rotated segment → the break is located
    rows = seg[0].read_text().splitlines()
    rows[0] = rows[0].replace('"suspicious"', '"benign"', 1)
    seg[0].write_text("\n".join(rows) + "\n")
    rep = log.verify_report(all_files=True)
    assert not rep["ok"] and rep["broken_at"] == (seg[0].name, 1)
    # a restart after rotation chains from the newest segment's tail, not from genesis
    log2 = AuditLog(p, max_bytes=1500)
    assert log2.tail_hash == log.tail_hash


def test_audit_verify_cli(tmp_path, capsys):
    from aegis.audit.__main__ import main
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    log.append(_chain(0))
    assert main(["verify", "--audit", str(p)]) == 0 and "intact: 1" in capsys.readouterr().out
    p.write_text(p.read_text().replace('"A0"', '"A9"'))
    assert main(["verify", "--audit", str(p)]) == 1


# ------------------------------------------------------------------ netops --

def test_restart_mid_outage_keeps_the_incident_and_does_not_realert(tmp_path):
    d = _campus()
    (a,) = d.observe(_down("DIST-02", "Ethernet1/49", T + 10, nxos=True))
    assert d.observe(_down("ACC-02", "GigabitEthernet1/0/49", T + 12)) == []           # folded
    state = tmp_path / "netops-state.json"
    d.checkpoint(state)
    # kill -9, systemd restarts: a fresh detector with the same topology inputs still to come
    d2 = NetworkAssurance(clock=lambda: T + 60)
    assert d2.restore_from(state) == 1
    # the far end and a stranded switch report again after the restart: still the same outage, no new alert
    assert d2.observe(_down("CORE-01", "Ethernet1/3", T + 61, nxos=True)) == []
    assert d2.observe(_down("ACC-02", "GigabitEthernet1/0/49", T + 62)) == []
    assert d2.incident_for(a["id"])["suppressed"] >= 2
    # and the link-up closes the restored incident
    d2.observe(_up("DIST-02", "Ethernet1/49", T + 700))
    assert next(i for i in d2._incidents if i.alert_id == a["id"]).closed is not None


def test_checkpoint_is_atomic_and_a_corrupt_one_is_ignored(tmp_path):
    d = _campus()
    state = tmp_path / "s.json"
    d.checkpoint(state)
    assert not state.with_suffix(".json.tmp").exists() and json.loads(state.read_text())["version"] == NetworkAssurance.STATE_VERSION
    state.write_text('{"version": 1, "links": [{"a": ')                                 # truncated
    assert NetworkAssurance(clock=lambda: T).restore_from(state) == 0
    state.write_text(json.dumps({"version": 99}))                                        # another version
    assert NetworkAssurance(clock=lambda: T).restore_from(state) == 0


def test_clock_jumps_do_not_strand_or_resurrect_devices():
    d = _campus(silent_s=180)
    for dev in ("CORE-01", "DIST-01"):
        d.observe({"kind": "telemetry", "device": dev, "iface": "x", "ts": T, "counters": {}})
    # an exporter a year ahead, then one a year behind, then NTP jumping the host clock forward a day
    assert d.observe({"kind": "telemetry", "device": "CORE-01", "iface": "x", "ts": T + 400 * 86400, "counters": {}}) == []
    assert d.observe({"kind": "telemetry", "device": "DIST-01", "iface": "x", "ts": T - 400 * 86400, "counters": {}}) == []
    assert d.stats["device_unreachable"] == 0
    d.clock = lambda: T + 86400
    out = d.observe({"kind": "telemetry", "device": "CORE-01", "iface": "x", "ts": T + 86400, "counters": {}})
    # DIST-01 really has been silent a day now by the host clock: one alert, not a storm
    assert [o["device"] for o in out] == ["DIST-01"] and out[0]["netops"]["fault"] == "device_unreachable"


# ------------------------------------------------------------------ storm --

def test_feed_storm_applies_backpressure_instead_of_falling_over():
    from aegis.ingest.stream import StreamQueue
    q = StreamQueue(capacity=1000)
    accepted = 0
    for batch in range(50):                                     # 50 × 100 = 5000 lines against a 1000-line queue
        if q.put_many("alerts", [json.dumps({"id": f"s{batch}-{i}", "source": "storm"}) for i in range(100)], passthrough=True):
            accepted += 100
    assert 900 <= accepted <= 1000 and len(q) == accepted        # full means 503 to the sender, nothing silently dropped
    assert len(q.drain(400)) == 400 and len(q) == accepted - 400          # the loop drains in bounded batches
    assert q.put_many("alerts", ['{"id":"after"}'], passthrough=True)       # and the sender's retry gets in
    q.drain()
    assert len(q) == 0 and q.stats.rejected_full == 5000 - accepted          # every refusal is counted
