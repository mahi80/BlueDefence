"""Community contribution pipeline: what leaves a bank, and what must never (review round 1 regressions)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.dataset import contrib, privacy_gate
from aegis.dataset.scrub import Scrubber
from aegis.dataset.schema import _cap_raw


def _chain(aid: str, **alert) -> dict:
    return {"alert_id": aid, "integrity_hash": f"{abs(hash(aid)) % (1 << 64):064x}", "verdict": "suspicious", "confidence": 0.8,
            "rationale": "x", "evidence": [{"source": "waf", "signal": "s", "raw_data": alert}], "recommended_actions": [
                {"action_type": "block_ip", "target": alert.get("src_ip", "10.0.0.1"), "requires_approval": True}],
            "metadata": {"alert": {"id": aid, "alert_type": "waf", **alert}}}


def _audit(tmp_path: Path, chains: list[dict]) -> Path:
    p = tmp_path / "audit.jsonl"
    p.write_text("".join(json.dumps(c) + "\n" for c in chains))
    return p


def test_gate_catches_bare_numbers_keys_and_v6_but_passes_telemetry_ids():
    """F1 / F15 / F6: digit-only identities and dict keys are checked; SIDs, UUIDs, hashes and tokens are not findings."""
    leaks = [{"to_acct": 50100234567890}, {"x": "432156789012"}, {"x": "4111111111111111"}, {"x": "9876543210"},
             {"rajesh.verma@bank.in": 1}, {"x": "2401:4900:1f3a:1::12"}, {"x": "00:1A:2B:3C:4D:5E"},
             {"x": "ftp://rverma:Passw0rd!@10.0.0.5/"}, {"x": "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
             {"x": "-----BEGIN RSA PRIVATE KEY-----"}, {"id": "50100234567890"}]
    for obj in leaks:
        assert not privacy_gate.gate(obj)[0], obj
    fine = [{"x": "S-1-5-21-3623811015-3361044348-30300820-1013"}, {"event_id": "123e4567-e89b-12d3-a456-426614174000"},
            {"x": "email-0011223344aa"}, {"x": "a" * 64}, {"x": "12:30:45"}, {"ts": 1700000000000}, {"ts": 1700000000000000000},
            {"x": "Ethernet1/49"}, {"x": "443:8443"}, {"x": "10.1.2.3"}, {"x": "fe80::1"}, {"x": "CHG-1000123"}, {"x": 0.75}]
    for obj in fine:
        assert privacy_gate.gate(obj)[0], obj
    clean, bad = privacy_gate.gate_records([{"a": "ok"}, {"a": "me@x.com"}, {"a": 1}])
    assert clean == [0, 2] and list(bad) == [1]


def test_scrubber_does_not_leak_username_prefixes_and_knows_windows_identity_keys():
    """F2 / F6."""
    sc = Scrubber(salt="s")
    out = sc.scrub({"user": "rverma_admin", "TargetUserName": "priya.sharma", "SubjectUserSid": "S-1-5-21-1-2-3-1001"})
    assert "rverma" not in json.dumps(out) and "priya" not in json.dumps(out)
    assert sc.scrub({"user": "u_42891"})["user"].startswith("u_")               # numeric suffix ids keep their prefix
    assert sc.scrub({"user": "rverma_admin"})["user"] != sc.scrub({"user": "jsmith_admin"})["user"]


def test_raw_evidence_cap_never_splits_an_identity():
    """F9: the cap runs before the scrubber; a token cut in half would hide from both."""
    raw = {"a": "x" * 300, "b": "y " * 250 + "rajesh.verma@bank.in tail", "list": list(range(100))}
    capped = _cap_raw(raw)
    text = json.dumps(capped)
    assert "rajesh.verma@bank.in" in text or "rajesh" not in text          # whole or absent, never "rajesh.ve"
    assert len(capped["list"]) == 20 and capped["a"].endswith("…")


def test_unsalted_bundle_is_not_sent(tmp_path, monkeypatch):
    """F3: the installation id travels with the bundle, so it can never be the redaction key."""
    monkeypatch.delenv("AEGIS_DATASET_SALT", raising=False)
    audit = _audit(tmp_path, [_chain("a1", src_ip="203.0.113.9", user="x@y.com")])
    res = contrib.contribute(audit_path=audit, installation_id="bd-x", out=tmp_path / "b.json.gz", cursor_path=tmp_path / "c")
    assert not res["sent"] and "unsalted" in res["reason"] and not (tmp_path / "b.json.gz").exists()
    monkeypatch.setenv("AEGIS_DATASET_SALT", "k" * 32)
    res = contrib.contribute(audit_path=audit, installation_id="bd-x", out=tmp_path / "b.json.gz", cursor_path=tmp_path / "c")
    assert res["records"] == 1 and (tmp_path / "b.json.gz").exists()
    bundle = next(iter(contrib.iter_bundles(tmp_path)))[1]
    assert bundle["salted"] is True and "203.0.113.9" not in json.dumps(bundle) and "x@y.com" not in json.dumps(bundle)


def test_gate_quarantines_one_record_and_the_cursor_moves_on(tmp_path, monkeypatch):
    """F5: a leaky record is held back and noted; the others ship; the next run does not re-send the same bytes."""
    monkeypatch.setenv("AEGIS_DATASET_SALT", "k" * 32)
    # a MAC address: the scrubber does not tokenise it, so the gate is what stops it
    chains = [_chain("ok1", src_ip="10.0.0.1"), _chain("leak", src_ip="10.0.0.2", note="mac 00:1A:2B:3C:4D:5E"), _chain("ok2", src_ip="10.0.0.3")]
    audit = _audit(tmp_path, chains)
    res = contrib.contribute(audit_path=audit, installation_id="bd-x", out=tmp_path / "b.json.gz", cursor_path=tmp_path / "c")
    assert res["records"] == 2 and res["quarantined"] == 1
    q = (tmp_path / "c").with_suffix(".quarantine.jsonl").read_text()
    assert "mac" in q and "00:1A" not in q                                           # kinds and paths only, never the value
    assert contrib.read_cursor(tmp_path / "c") == audit.stat().st_size
    res = contrib.contribute(audit_path=audit, installation_id="bd-x", out=tmp_path / "b2.json.gz", cursor_path=tmp_path / "c")
    assert res["reason"] == "nothing new"
    # F8: the audit log is rotated (smaller than the cursor) → read from the start instead of "nothing new" forever
    _audit(tmp_path, [_chain("after-rotate", src_ip="10.0.0.4")])
    res = contrib.contribute(audit_path=audit, installation_id="bd-x", out=tmp_path / "b3.json.gz", cursor_path=tmp_path / "c")
    assert res["records"] == 1


def test_decisions_join_uses_the_action_type_not_the_display_string(tmp_path):
    """F7: the HITL card stores 'block_ip -> 203.0.113.45'; the join must see 'block_ip'."""
    hitl = tmp_path / "hitl"; hitl.mkdir()
    (hitl / "cards.jsonl").write_text(json.dumps({"id": "ap1", "action": "block_ip -> 203.0.113.45",
                                                  "args": {"alert_id": "al-1", "target": "203.0.113.45"}}) + "\n")
    (hitl / "decisions.jsonl").write_text(json.dumps({"approval_id": "ap1", "status": "rejected", "reason": "false positive", "ts": 1}) + "\n")
    d = contrib._decisions(hitl)
    assert d["al-1"][0].action_type == "block_ip" and d["al-1"][0].decision == "rejected"


def test_push_uses_a_binary_content_type_and_caps_size(monkeypatch):
    """rev2-F7: the HTTP API only base64-encodes binary media types."""
    seen = {}

    class R:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return b'{"ok": true}'

    def fake_open(req, timeout=0):
        seen["ct"] = req.get_header("Content-type"); seen["ce"] = req.get_header("Content-encoding"); return R()
    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", fake_open)
    assert contrib.push_bundle("https://s", {"schema": "aegis-contrib/1", "records": []}, "tok") == {"ok": True}
    assert seen["ct"] == "application/gzip" and seen["ce"] == "gzip"
    monkeypatch.setattr(contrib, "MAX_PUSH_BYTES", 10)
    with pytest.raises(RuntimeError, match="over the"):
        contrib.push_bundle("https://s", {"schema": "aegis-contrib/1", "records": [{"x": "y" * 100}]}, "tok")
