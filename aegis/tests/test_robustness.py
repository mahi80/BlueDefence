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


# ---------------------------------------------------------- storm mode / watchdog --

def test_deferred_queue_spills_in_order_survives_restart_and_is_bounded(tmp_path):
    from aegis.ops.deferred import DeferredQueue
    q = DeferredQueue(tmp_path / "deferred.jsonl", max_bytes=400)
    assert q.push({"id": "a"}) and q.push({"id": "b"}) and q.push({"id": "c"})
    assert q.pending() == 3
    got = q.pop(2)
    assert [g["id"] for g in got] == ["a", "b"] and got[0]["deferred_by"] == "storm"
    q_crash = DeferredQueue(tmp_path / "deferred.jsonl")                 # crash before ack: the batch is re-delivered
    assert [g["id"] for g in q_crash.pop(5)] == ["a", "b", "c"]
    q.ack()
    assert q.pending() == 1
    q2 = DeferredQueue(tmp_path / "deferred.jsonl")                      # restart: acked cursor persisted
    assert [g["id"] for g in q2.pop(5)] == ["c"]
    q2.ack()
    assert q2.pending() == 0 and not (tmp_path / "deferred.jsonl").exists()
    # a torn last line (crash mid-append) is cut at open so the next push cannot merge with it
    torn = tmp_path / "torn.jsonl"; torn.write_text('{"id":"t1"}\n{"id":"t2", "pa')
    qt = DeferredQueue(torn)
    assert qt.dropped == 1 and qt.push({"id": "t3"}) and [g["id"] for g in qt.pop(5)] == ["t1", "t3"]
    q3 = DeferredQueue(tmp_path / "d2.jsonl", max_bytes=120)
    pushed = sum(q3.push({"id": f"x{i}", "pad": "y" * 50}) for i in range(10))
    assert 1 <= pushed < 10 and q3.dropped == 10 - pushed                # the spill file is bounded and refusals are counted


def test_storm_mode_defers_model_bound_alerts_and_keeps_fast_paths(monkeypatch, tmp_path):
    from aegis.service import StormControl, CycleStats, run_cycle, build_pipeline
    from aegis.ops.deferred import DeferredQueue
    monkeypatch.setenv("LLM_BACKEND", "mock"); monkeypatch.setenv("AEGIS_INGEST_HTTP", "0"); monkeypatch.setenv("AEGIS_SOURCES", "sample")
    p = build_pipeline(tmp_path / "audit.jsonl", fresh=True)
    storm = StormControl(DeferredQueue(tmp_path / "deferred.jsonl"), p.stream, 60.0)
    big = CycleStats(); big.alerts = 10_000
    assert storm.update(big) is True                                      # a huge cycle switches it on
    netops = parse_syslog_line("<189>DIST-01: %LINK-3-UPDOWN: Interface Ethernet1/49, changed state to down", ts=T)
    fast = {"id": "nf-1", "alert_type": "network_fault", "source": "Network Assurance", "netops": {"fault": "link_down", "device": "DIST-01", "iface": "Ethernet1/49", "downstream": [], "root_cause": "x"}}
    slow = {"id": "waf-1", "source": "Imperva WAF", "src_ip": "203.0.113.5", "path": "/login", "severity": "high"}
    assert p.orch.is_fast_path(fast) and not p.orch.is_fast_path(slow)
    st = run_cycle(p, alerts=iter([fast, slow, dict(slow, id="waf-2")]), sweep=False, hitl=False, storm=storm)
    assert st.deferred == 2 and st.alerts == 3 and storm.queue.pending() == 2
    small = CycleStats(); small.alerts = 3
    assert storm.update(small) is False                                   # storm over
    pend = storm.redeliver()
    assert [a["id"] for a in pend] == ["waf-1", "waf-2"] and all(a["deferred_at"] for a in pend)
    st2 = run_cycle(p, alerts=iter(pend), sweep=False, hitl=False, storm=storm)
    assert st2.alerts == 2 and st2.deferred == 0 and storm.queue.pending() == 2   # re-fed alerts are never re-deferred…
    storm.queue.ack()
    assert storm.queue.pending() == 0                                              # …and the batch is committed after processing
    p.close()


def test_sdnotify_is_a_noop_without_systemd_and_speaks_the_protocol_with_it(tmp_path, monkeypatch):
    import socket
    from aegis.ops import sdnotify
    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)
    assert not sdnotify.enabled() and sdnotify.ready() is False and sdnotify.watchdog() is False
    if not hasattr(socket, "AF_UNIX"):
        pytest.skip("sd_notify speaks over a Unix datagram socket; systemd does not run on Windows")
    sock_path = str(tmp_path / "notify.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); srv.bind(sock_path); srv.settimeout(2)
    monkeypatch.setenv("NOTIFY_SOCKET", sock_path); monkeypatch.setenv("WATCHDOG_USEC", "180000000")
    sdnotify._sock = None; sdnotify._last = 0.0
    assert sdnotify.ready("up") and srv.recv(200) == b"READY=1\nSTATUS=up"
    assert sdnotify.watchdog() and srv.recv(200) == b"WATCHDOG=1"
    assert sdnotify.watchdog() is False                                   # rate-limited
    assert sdnotify.watchdog_interval_s() == 90.0
    assert sdnotify.stopping() and srv.recv(200) == b"STOPPING=1"
    srv.close(); sdnotify._sock = None


def test_status_command_reports_chain_and_backlog(tmp_path, monkeypatch, capsys):
    from aegis.service import status_main
    from aegis.ops.deferred import DeferredQueue
    monkeypatch.setenv("AEGIS_INGEST_BIND", "127.0.0.1:1")                 # nothing listening
    log = AuditLog(tmp_path / "audit.jsonl"); log.append(_chain(0))
    DeferredQueue(tmp_path / "deferred.jsonl").push({"id": "z"})
    assert status_main(str(tmp_path / "audit.jsonl")) == 1                # receiver unreachable → non-zero, but still reports
    out = capsys.readouterr().out
    assert "unreachable" in out and "intact" in out and "1 alert(s) waiting" in out


# ------------------------------------------------------------ review round 2 --

def test_source_raising_mid_cycle_does_not_kill_the_cycle(tmp_path, monkeypatch):
    from aegis.service import build_pipeline, run_cycle
    monkeypatch.setenv("LLM_BACKEND", "mock"); monkeypatch.setenv("AEGIS_INGEST_HTTP", "0"); monkeypatch.setenv("AEGIS_SOURCES", "sample")
    p = build_pipeline(tmp_path / "audit.jsonl", fresh=True)
    def feed():
        yield {"id": "ok-1", "source": "Imperva WAF", "src_ip": "203.0.113.5", "path": "/login", "severity": "high"}
        raise RuntimeError("Sentinel query failed: HTTP 503")
    st = run_cycle(p, alerts=feed(), sweep=False, hitl=False)
    assert st.alerts == 1 and st.errors == 1                                   # one processed, the failure counted, no exception
    p.close()


def test_audit_write_failure_parks_the_alert_for_redelivery(tmp_path, monkeypatch):
    from aegis.service import build_pipeline, run_cycle, StormControl
    from aegis.ops.deferred import DeferredQueue
    from aegis.agents.shared.audit import AuditWriteError
    monkeypatch.setenv("LLM_BACKEND", "mock"); monkeypatch.setenv("AEGIS_INGEST_HTTP", "0"); monkeypatch.setenv("AEGIS_SOURCES", "sample")
    p = build_pipeline(tmp_path / "audit.jsonl", fresh=True)
    storm = StormControl(DeferredQueue(tmp_path / "deferred.jsonl"), p.stream, 60.0)
    def boom(*a, **k): raise AuditWriteError("audit log not writable: No space left on device", 28)
    monkeypatch.setattr(p.orch, "handle", boom)
    alert = {"id": "waf-9", "source": "Imperva WAF", "src_ip": "203.0.113.5", "path": "/login", "severity": "high"}
    st = run_cycle(p, alerts=iter([alert]), sweep=False, hitl=False, storm=storm)
    assert st.audit_failures == 1 and st.deferred == 1 and storm.queue.pending() == 1
    parked = storm.queue.pop(5)
    assert parked[0]["id"] == "waf-9" and parked[0]["audit_deferred"] is True   # re-fed once the log is writable
    p.close()


def test_torn_tail_repair_keeps_intact_rows_after_a_bad_middle_line(tmp_path):
    from aegis.agents.shared.audit import AuditLog
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    from aegis.agents.shared.evidence_chain import EvidenceChain
    for i in range(4):
        log.append(EvidenceChain(alert_id=f"A{i}", investigated_by="t", verdict="benign", confidence=0.5))
    rows = path.read_text().splitlines()
    rows[1] = rows[1][:20]                                                     # corrupt a MIDDLE row (not a torn write)
    path.write_text("\n".join(rows) + "\n")
    log2 = AuditLog(path)                                                      # must not discard rows 2-3
    assert len(path.read_text().splitlines()) == 4
    assert log2.verify_report(all_files=False)["broken_at"] is not None       # but verify reports it
    # a genuinely torn TAIL is repaired
    path.write_text(path.read_text() + '{"alert_id": "A9", "half')
    AuditLog(path)
    assert len(path.read_text().splitlines()) == 4 and list(tmp_path.glob("audit.jsonl.torn-*"))
    # read-only construction never touches the file
    path.write_text(path.read_text() + '{"alert_id": "A10", "half')
    AuditLog(path, repair=False)
    assert path.read_text().endswith('"half')


def test_contrib_cursor_survives_audit_rotation(tmp_path, monkeypatch):
    from aegis.agents.shared.audit import AuditLog
    from aegis.agents.shared.evidence_chain import EvidenceChain
    from aegis.dataset import contrib
    monkeypatch.setenv("AEGIS_DATASET_SALT", "s" * 16)
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, max_bytes=1500)                                       # rotates every few rows
    cur = tmp_path / ".contrib.cursor"
    def chains(n, start):
        for i in range(start, start + n):
            log.append(EvidenceChain(alert_id=f"R{i}", investigated_by="t", verdict="benign", confidence=0.5))
    chains(3, 0)
    b1, c1 = contrib.build_bundle(path, installation_id="inst-1", cursor=contrib.read_cursor_state(cur))
    contrib.write_cursor(cur, c1)
    chains(12, 3)                                                              # several rotations happen here
    assert len(log.rotated_files()) >= 1
    b2, c2 = contrib.build_bundle(path, installation_id="inst-1", cursor=contrib.read_cursor_state(cur))
    assert b1["counts"]["records"] == 3 and b2["counts"]["records"] == 12       # nothing lost across the rotation
    contrib.write_cursor(cur, c2)
    b3, _ = contrib.build_bundle(path, installation_id="inst-1", cursor=contrib.read_cursor_state(cur))
    assert b3["counts"]["records"] == 0                                        # and nothing re-sent
