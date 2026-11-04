"""Round-8 core review regressions: R8-1 edge decodes, R8-2/R8-11/R8-12 licence & edition, R8-3/R8-4/R8-7 audit
retention keys, R8-5 console fallback, R8-6 reindex exit code, R8-8 backup modes, R8-9/R8-10 healing chart,
R8-13 agent chart."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import time
from pathlib import Path

import pytest

from aegis import license as L

ROOT = Path(__file__).resolve().parents[2]
GENESIS = "0" * 64


def _chain(rows: list[dict], prev: str = GENESIS) -> tuple[list[dict], str]:
    out = []
    for body in rows:
        h = hashlib.sha256((prev + json.dumps(body, sort_keys=True, separators=(",", ":"))).encode()).hexdigest()
        out.append({**body, "integrity_hash": h})
        prev = h
    return out, prev


def _write(p: Path, rows: list[dict]) -> None:
    p.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


def _rotated(tmp: Path):
    audit = tmp / "audit.jsonl"
    s1, t1 = _chain([{"alert_id": f"s1-{i}", "verdict": "malicious"} for i in range(3)])
    s2, t2 = _chain([{"alert_id": f"s2-{i}", "verdict": "benign"} for i in range(3)], t1)
    lv, _ = _chain([{"alert_id": f"l-{i}", "verdict": "benign"} for i in range(2)], t2)
    _write(tmp / "audit.jsonl.1000", s1)
    _write(tmp / "audit.jsonl.2000", s2)
    _write(audit, lv)
    return audit, s1, t1


@pytest.fixture
def _nokeys(monkeypatch):
    for k in ("AEGIS_AUDIT_KEY", "AEGIS_AUDIT_KEY_PREVIOUS", "AEGIS_DECISION_KEY", "AEGIS_CONSOLE_TOKEN", "AEGIS_AUDIT_ANCHOR"):
        monkeypatch.delenv(k, raising=False)
    return monkeypatch


# ---------------------------------------------------------------- R8-1 ---
def test_r8_1_edge_emits_one_decision_per_event(tmp_path):
    go = shutil.which("go")
    if not go:
        pytest.skip("go toolchain not installed (aegis/edge/tier0_test.go covers this in Go)")
    edge = ROOT / "aegis" / "edge"
    binary = tmp_path / "tier0"
    env = {**os.environ, "GOCACHE": str(tmp_path / "gocache"), "GOFLAGS": "-mod=mod"}
    subprocess.run([go, "build", "-o", str(binary), "."], cwd=edge, check=True, env=env, timeout=300)
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"feature_map": {"ip_known_bad": 0, "rate": 1}, "weights": [[-1, 0.5, 3], [0, 0.1, 0.2]],
                                  "bias": [0, 0, 0], "block_gate": 0.9}))
    lines = ['{"id":"ok","features":{"ip_known_bad":1}}', '{"id":"overflow","features":{"rate":1e400}}',
             '{"id":"string","features":{"rate":"x"}}', '{"id":"trunc","features":', "garbage"]
    out = subprocess.run([str(binary), "-policy", str(policy)], input="\n".join(lines) + "\n", capture_output=True,
                         text=True, timeout=60, check=True).stdout.strip().splitlines()
    decisions = [json.loads(x) for x in out]
    assert [d["id"] for d in decisions] == ["ok", "overflow", "string", "trunc", ""]
    for d in decisions[1:]:
        assert d["action"] == "escalate" and d["hitl_required"] is True


def test_r8_1_edge_source_never_skips():
    src = (ROOT / "aegis" / "edge" / "tier0.go").read_text()
    assert "skip bad event" not in src and "failClosed(id)" in src


# ---------------------------------------------------------------- R8-2 ---
@pytest.mark.parametrize("extra,check", [
    ({"AEGIS_EDITION": "soc", "AEGIS_HITL_TRANSPORT": "dashboard"}, lambda e: e["AEGIS_HITL_TRANSPORT"] == "file"),
    ({"AEGIS_EDITION": "full", "AEGIS_SOURCES": "stream,acp,waf"}, lambda e: e["AEGIS_SOURCES"] == "stream,waf"),
])
def test_r8_2_evaluation_mode_neutralises_dashboard_transport_and_acp_source(extra, check):
    from aegis.edition import apply_edition
    env = {"AEGIS_LICENSE_ENFORCE": "1", "AEGIS_LICENSE": "/nonexistent.jwt", "AEGIS_INSTALL_ID": "bd-x",
           "ACP_DASHBOARD_URL": "https://dash", "ACP_GOVERN": "1", **extra}
    L.apply(L.check(env, keys={}), env)
    assert apply_edition(env).name == "external"          # used to raise EditionError → crash loop
    assert check(env)


# --------------------------------------------------------------- R8-11 ---
def test_r8_11_valid_licence_after_evaluation_restores_the_configured_edition():
    from aegis.edition import apply_edition, validate
    env = {"AEGIS_LICENSE_ENFORCE": "1", "AEGIS_LICENSE": "/nonexistent.jwt", "AEGIS_INSTALL_ID": "i", "AEGIS_EDITION": "soc",
           "ACP_DASHBOARD_URL": "https://dash", "AEGIS_HITL_TRANSPORT": "dashboard"}
    L.apply(L.check(env, keys={}), env)
    apply_edition(env)
    assert env["AEGIS_EDITION"] == "external"
    lic = L.License(customer="b", installation_id="i", edition="soc", tier="standard", issued=0, expires=10**10,
                    features=["live_enforcement"])
    L.apply(L.LicenseState(status="valid", license=lic, enforce=True, effective_edition="soc",
                           effective_features=set(lic.features)), env)
    assert env["AEGIS_EDITION"] == "soc" and env["ACP_DASHBOARD_URL"] == "https://dash"
    assert env["AEGIS_HITL_TRANSPORT"] == "dashboard"
    assert validate(env) == []


# --------------------------------------------------------------- R8-12 ---
def test_r8_12_install_always_enforces_the_licence():
    sh = (ROOT / "install.sh").read_text()
    enforce = sh.index('\n  echo "AEGIS_LICENSE_ENFORCE=1"\n')
    lic_if = sh.index('\n  if [[ -f "$LIC_FILE" ]]; then\n    echo "AEGIS_LICENSE=$LIC_FILE"')
    assert enforce < lic_if                     # written unconditionally, not only when a licence file exists
    assert sh.count('echo "AEGIS_LICENSE_ENFORCE=1"') == 1


def test_r8_12_operator_issuer_is_recorded_and_reported(tmp_path, monkeypatch):
    _pub, priv = L.write_keypair(tmp_path, "self-1", bits=1024)
    k = json.loads(priv.read_text())
    lic = L.License(customer="anyone", installation_id="", edition="full", tier="enterprise", issued=time.time(),
                    expires=time.time() + 86400, features=["swarm"])
    (tmp_path / "license.jwt").write_text(L.issue(lic, n=int(k["n"], 16), d=int(k["d"], 16), kid="self-1"))
    monkeypatch.setenv("AEGIS_LICENSE_PUBKEYS", str(tmp_path))
    st = L.check({"AEGIS_LICENSE": str(tmp_path / "license.jwt"), "AEGIS_LICENSE_ENFORCE": "1"})
    assert st.status == "valid"                               # the operator option is kept …
    assert st.issuer and st.to_dict()["issuer_overridden"] is True     # … but never silent
    assert "NON-DEFAULT ISSUER" in st.describe()
    assert L.heartbeat_payload(installation_id="x", audit_path=None, env=dict(os.environ))["issuer_overridden"] is True
    monkeypatch.delenv("AEGIS_LICENSE_PUBKEYS")
    assert L.check({"AEGIS_LICENSE": "/nonexistent"}).to_dict()["issuer_overridden"] is False


# ------------------------------------------------------ R8-3 / R8-4 / R8-7 ---
def test_r8_3_retire_refuses_without_a_key_and_ignores_the_console_token(_nokeys, tmp_path):
    from aegis.agents.shared.audit import AuditLog
    audit, _, _ = _rotated(tmp_path)
    res = AuditLog(audit, repair=False).retire_segments(1)
    assert not res["ok"] and (tmp_path / "audit.jsonl.1000").exists()
    _nokeys.setenv("AEGIS_CONSOLE_TOKEN", "console")                          # not a retention key any more
    assert not AuditLog(audit, repair=False).retire_segments(1)["ok"]
    assert (tmp_path / "audit.jsonl.1000").exists()


def test_r8_3_key_rotation_via_previous_keys_and_resign(_nokeys, tmp_path):
    from aegis.agents.shared.audit import AuditLog
    from aegis.audit.__main__ import main
    audit, _, _ = _rotated(tmp_path)
    _nokeys.setenv("AEGIS_AUDIT_KEY", "old-key")
    assert AuditLog(audit, repair=False).retire_segments(1)["signed"]
    _nokeys.setenv("AEGIS_AUDIT_KEY", "new-key")
    assert not AuditLog(audit, repair=False).verify_report(all_files=True)["ok"]          # old key not listed
    _nokeys.setenv("AEGIS_AUDIT_KEY_PREVIOUS", "old-key")
    assert AuditLog(audit, repair=False).verify_report(all_files=True)["ok"]
    assert main(["resign", "--audit", str(audit)]) == 0
    _nokeys.delenv("AEGIS_AUDIT_KEY_PREVIOUS")
    assert AuditLog(audit, repair=False).verify_report(all_files=True)["ok"]              # now under the new key


def test_r8_3_pre_round8_console_signed_checkpoint_is_accepted_when_listed(_nokeys, tmp_path):
    import hmac

    from aegis.agents.shared.audit import AuditLog
    audit, _, _ = _rotated(tmp_path)
    _nokeys.setenv("AEGIS_AUDIT_KEY", "k")
    assert AuditLog(audit, repair=False).retire_segments(1)["ok"]
    legacy = hmac.new(b"console-tok", b"aegis-decision-signing-v1", hashlib.sha256).digest()
    log = AuditLog(audit, repair=False)
    cp = json.loads(log.retention_path().read_text())
    cp.pop("kid")
    cp["sig"] = AuditLog._retention_sig(cp, legacy)
    log.retention_path().write_text(json.dumps(cp))
    assert not AuditLog(audit, repair=False).verify_report(all_files=True)["ok"]
    _nokeys.setenv("AEGIS_AUDIT_KEY_PREVIOUS", "console:console-tok")
    assert AuditLog(audit, repair=False).verify_report(all_files=True)["ok"]


def test_r8_4_forged_checkpoint_without_a_key_is_unverifiable_not_green(_nokeys, tmp_path):
    from aegis.agents.shared.audit import AuditLog
    from aegis.audit.__main__ import main
    _nokeys.setenv("AEGIS_AUDIT_ANCHOR", str(tmp_path / "anchors.jsonl"))
    audit, s1, t1 = _rotated(tmp_path)
    (tmp_path / "anchors.jsonl").write_text(json.dumps({"hash": s1[2]["integrity_hash"], "log": str(audit.resolve())}) + "\n")
    (tmp_path / "audit.jsonl.1000").unlink()
    (tmp_path / "audit.jsonl.retention").write_text(json.dumps(
        {"seed": t1, "dropped": [], "anchors_retired": [s1[2]["integrity_hash"]], "entries_retired": 0}))
    rep = AuditLog(audit, repair=False).verify_report(all_files=True)
    assert not rep["ok"] and rep["unverifiable"] and "no key" in rep["broken_at"][1]
    assert main(["verify", "--audit", str(audit), "--all"]) == 3
    _nokeys.setenv("AEGIS_AUDIT_KEY", "k")                    # with a key: an unsigned checkpoint is a forgery
    rep = AuditLog(audit, repair=False).verify_report(all_files=True)
    assert not rep["ok"] and not rep["unverifiable"]


def test_r8_4_unsigned_legacy_checkpoint_can_be_vouched_once(_nokeys, tmp_path):
    from aegis.agents.shared.audit import AuditLog
    audit, _, t1 = _rotated(tmp_path)
    (tmp_path / "audit.jsonl.1000").unlink()
    (tmp_path / "audit.jsonl.retention").write_text(json.dumps(
        {"seed": t1, "dropped": ["audit.jsonl.1000"], "anchors_retired": [], "entries_retired": 3}))
    _nokeys.setenv("AEGIS_AUDIT_KEY", "k")
    assert not AuditLog(audit, repair=False).resign_retention()["ok"]
    res = AuditLog(audit, repair=False).resign_retention(trust_unverified=True)
    assert res["ok"] and res["vouched"]
    assert "vouched_at" in json.loads((tmp_path / "audit.jsonl.retention").read_text())
    assert AuditLog(audit, repair=False).verify_report(all_files=True)["ok"]


def test_r8_7_tail_after_retiring_everything_chains_from_the_seed(_nokeys, tmp_path):
    from aegis.agents.shared.audit import AuditLog
    from aegis.agents.shared.evidence_chain import EvidenceChain
    _nokeys.setenv("AEGIS_AUDIT_KEY", "k")
    audit = tmp_path / "audit.jsonl"
    s1, t1 = _chain([{"alert_id": f"s1-{i}"} for i in range(3)])
    _write(tmp_path / "audit.jsonl.1000", s1)
    assert AuditLog(audit, repair=False).retire_segments(1)["ok"]
    log = AuditLog(audit)
    assert log.tail_hash == t1
    log.append(EvidenceChain(alert_id="new-1", investigated_by="t", verdict="benign", confidence=0.5))
    assert AuditLog(audit, repair=False).verify_report(all_files=True)["ok"]


# ---------------------------------------------------------------- R8-5 ---
def _forged_log(tmp_path):
    rows, _ = _chain([{"alert_id": f"a{i}", "verdict": "benign", "confidence": 0.5} for i in range(3)])
    forged = {"alert_id": "FORGED-1", "verdict": "benign", "confidence": 0.99, "integrity_hash": "f" * 64}
    audit = tmp_path / "audit.jsonl"
    _write(audit, rows + [forged])
    return audit, rows


def test_r8_5_console_never_serves_an_unindexed_forged_row_with_a_healthy_index(_nokeys, tmp_path):
    from aegis.ingest.console_api import ConsoleAPI
    from aegis.store import IndexStore
    audit, _rows = _forged_log(tmp_path)
    st = IndexStore(f"sqlite:///{tmp_path / 'i.sqlite'}")
    st.reindex(audit)
    st.stale = False                         # the service's own store: not the CLI's, its flag stayed healthy
    api = ConsoleAPI(audit, None, index=st)
    assert api.chain("FORGED-1") is None
    assert api.chain("a1")["verified"] is True


def test_r8_5_file_fallback_marks_rows_verified_or_not(_nokeys, tmp_path):
    from aegis.ingest.console_api import ConsoleAPI
    audit, rows = _forged_log(tmp_path)
    api = ConsoleAPI(audit, None, index=None)
    bad = api.chain("FORGED-1")
    assert bad is not None and bad["verified"] is False and bad["integrity"].startswith("unverified")
    for r in rows:
        assert api.chain(r["alert_id"])["verified"] is True


# ---------------------------------------------------------------- R8-6 ---
def test_r8_6_reindex_cli_fails_on_a_broken_chain(_nokeys, tmp_path, capsys):
    pytest.importorskip("sqlalchemy")
    from aegis.store.__main__ import main
    audit, _ = _forged_log(tmp_path)
    assert main(["reindex", "--audit", str(audit), "--url", f"sqlite:///{tmp_path / 'j.sqlite'}"]) == 1
    good = tmp_path / "good"
    good.mkdir()
    rows, _ = _chain([{"alert_id": "a", "verdict": "benign"}])
    _write(good / "audit.jsonl", rows)
    assert main(["reindex", "--audit", str(good / "audit.jsonl"), "--url", f"sqlite:///{tmp_path / 'k.sqlite'}"]) == 0


# ---------------------------------------------------------------- R8-8 ---
def test_r8_8_backup_is_private(tmp_path):
    if not (shutil.which("bash") and shutil.which("tar") and shutil.which("sha256sum")):
        pytest.skip("needs bash, tar, sha256sum")
    sh = (ROOT / "install.sh").read_text()
    script = re.search(r"cat > /usr/local/bin/aegis-backup <<'EOS'\n(.*?)\nEOS\n", sh, re.DOTALL).group(1)
    (tmp_path / "aegis-backup").write_text(script)
    root = tmp_path / "root"
    (root / "etc" / "aegis").mkdir(parents=True)
    (root / "var" / "lib" / "aegis").mkdir(parents=True)
    (root / "etc" / "aegis" / "aegis.env").write_text("AEGIS_CONSOLE_TOKEN=secret\n")
    (root / "var" / "lib" / "aegis" / "audit.jsonl").write_text("{}\n")
    dest = tmp_path / "backups"
    env = {**os.environ, "AEGIS_BACKUP_ROOT": str(root)}
    subprocess.run(["bash", str(tmp_path / "aegis-backup"), str(dest)], check=True, env=env, capture_output=True, timeout=60)
    assert stat.S_IMODE(dest.stat().st_mode) == 0o700
    files = list(dest.iterdir())
    assert len(files) == 2
    for f in files:
        assert stat.S_IMODE(f.stat().st_mode) == 0o600, f


# ------------------------------------------------------- R8-9 / R8-10 ---
def test_r8_9_10_healing_chart_bounds_the_forensic_job():
    t = ROOT / "aegis" / "healing" / "k8s" / "templates"
    job = (t / "forensic-snapshot-job.yaml").read_text()
    # nothing forensic runs at install: the Job only exists inside the ConfigMap template
    top_level_kinds = re.findall(r"^kind: (\w+)", job, re.MULTILINE)
    assert "Job" not in top_level_kinds and "PersistentVolumeClaim" not in top_level_kinds
    assert "kind: ConfigMap" in job and "aegis-forensic-job-template" in job
    assert "ephemeral:" in job and "aegis-forensic-pvc" not in job
    assert "nodeName:" not in job and "podAffinity:" in job
    assert re.search(r"kind: NetworkPolicy[\s\S]*aegis.bank/role: forensic-snapshot[\s\S]*- Egress", job)
    pol = (t / "forensic-admission-policy.yaml").read_text()
    for needle in ("nodeName", "nodeSelector", "tolerations", "secretKeyRef", "c.command ==", "forensics.command",
                   "has(v.emptyDir)", "aegis-healing-pod-patch", "object.spec == oldObject.spec"):
        assert needle in pol, needle
    rbac = (t / "controller-rbac.yaml").read_text()
    assert "aegis-healing-pod-patch" in rbac and 'resourceNames: ["aegis-forensic-job-template"]' in rbac
    assert "aegis.forensicLabels" in (t / "_helpers.tpl").read_text()


# --------------------------------------------------------------- R8-13 ---
def test_r8_13_agent_chart_licence_and_identity():
    t = ROOT / "aegis" / "k8s" / "templates"
    ss = (t / "statefulset.yaml").read_text()
    assert '- name: AEGIS_LICENSE\n          value: "{{ .Values.state.mountPath }}/license/license.jwt"' in ss
    assert "- name: AEGIS_INSTALL_ID" in ss and "installation.idSecret" in ss and "required" in ss
    assert "- name: AEGIS_AUDIT_KEY" in ss and "audit.keySecret" in ss
    assert '"aegis.license", "seed"' in ss
    np = (t / "networkpolicy.yaml").read_text()
    assert ".Values.license.serverCIDRs" in np and ".Values.license.serverPort" in np
    yaml = pytest.importorskip("yaml")
    values = yaml.safe_load((ROOT / "aegis" / "k8s" / "values.yaml").read_text())
    assert values["license"]["enforce"] == "1" and "installation" in values


def test_r8_13_seed_copies_once_and_never_over_a_renewal(tmp_path):
    d = tmp_path / "k"
    _pub, priv = L.write_keypair(d, "kid-1", bits=1024)
    k = json.loads(priv.read_text())
    keys = L.load_public_keys(d)

    def tok(cust):
        lic = L.License(customer=cust, installation_id="inst", edition="soc", tier="standard", issued=time.time(),
                        expires=time.time() + 86400, features=[])
        return L.issue(lic, n=int(k["n"], 16), d=int(k["d"], 16), kid="kid-1")
    env = {"AEGIS_INSTALL_ID": "inst"}
    src, dest = tmp_path / "secret" / "license.jwt", tmp_path / "pvc" / "license" / "license.jwt"
    src.parent.mkdir()
    src.write_text(tok("seed-1"))
    assert L.seed_token(src, dest, env=env, keys=keys).startswith("seeded")
    renewed = tok("renewed")
    dest.write_text(renewed + "\n")                            # the service renewed in place
    assert L.seed_token(src, dest, env=env, keys=keys).startswith("kept")
    assert dest.read_text().strip() == renewed
    src.write_text(tok("upgrade"))                             # operator replaced the Secret
    assert L.seed_token(src, dest, env=env, keys=keys).startswith("seeded")
    src.write_text("not.a.token")
    before = dest.read_text()
    assert L.seed_token(src, dest, env=env, keys=keys).startswith("not seeded")
    assert dest.read_text() == before


def test_r8_install_generates_an_audit_key():
    sh = (ROOT / "install.sh").read_text()
    assert 'echo "AEGIS_AUDIT_KEY=$AUDIT_KEY"' in sh and "grep -s '^AEGIS_AUDIT_KEY='" in sh
