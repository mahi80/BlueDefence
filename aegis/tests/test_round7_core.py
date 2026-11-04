"""Round-7 core review regressions: R-2 licence path, R-3 chart shape, R-4 evaluation mode on a
dashboard host, R-5 forensic Job identity, R-7 reindex honesty, R-10 renewal restores, R-11 no
bootstrap key, R-12 audit retention."""
from __future__ import annotations

import hashlib
import json
import types
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


# ---------------------------------------------------------------- R-2 ---
def test_r2_install_keeps_licence_under_the_writable_state_dir():
    sh = (ROOT / "install.sh").read_text()
    assert 'LIC_FILE="$VAR/license.jwt"' in sh            # ProtectSystem=strict: only $VAR is writable
    assert "AEGIS_LICENSE=$LIC_FILE" in sh
    assert "/var/lib/aegis/license.jwt" in (ROOT / "README.md").read_text()


def test_r2_renewal_failure_is_a_metric():
    src = (ROOT / "aegis" / "service.py").read_text()
    assert "aegis_license_renewal_failures_total" in src
    assert "AEGIS_LICENSE_RENEW_ALERT_DAYS" in src


# ---------------------------------------------------------------- R-4 ---
def test_r4_evaluation_mode_runs_on_a_dashboard_integrated_host():
    from aegis.edition import apply_edition
    env = {"AEGIS_LICENSE_ENFORCE": "1", "AEGIS_LICENSE": "/nonexistent.jwt",
           "ACP_DASHBOARD_URL": "https://dash.bank.internal", "ACP_GOVERN": "1", "AEGIS_INSTALL_ID": "bd-x"}
    st = L.apply(L.check(env, keys={}), env)
    assert st.runs
    apply_edition(env)                                      # used to raise: external edition forbids the dashboard
    assert "ACP_DASHBOARD_URL" not in env
    assert env.get("ACP_GOVERN") != "1"


# --------------------------------------------------------------- R-10 ---
def test_r10_renewal_after_degrade_restores_live_settings():
    env = {"AEGIS_LICENSE_ENFORCE": "1", "AEGIS_EDITION": "soc", "AEGIS_ENFORCEMENT_MODE": "live",
           "AEGIS_SWARM": "1", "AEGIS_INSTALL_ID": "i"}
    lic = L.License(customer="b", installation_id="i", edition="soc", tier="standard", issued=0, expires=10**10,
                    features=["swarm", "live_enforcement", "auto_block_live"])
    valid = L.LicenseState(status="valid", license=lic, enforce=True, effective_edition="soc",
                           effective_features=set(lic.features))
    L.degrade(env)                                          # licence expired while running
    assert env["AEGIS_ENFORCEMENT_MODE"] != "live"
    L.apply(valid, env)                                     # renewed
    assert env["AEGIS_ENFORCEMENT_MODE"] == "live"
    assert env["AEGIS_SWARM"] == "1"
    assert "AEGIS_AUTO_BLOCK" not in env                    # was unset before the degrade → unset again


# ---------------------------------------------------------------- R-7 ---
def test_r7_reindex_stays_stale_on_errors_and_refuses_a_broken_chain(tmp_path):
    from sqlalchemy.exc import OperationalError

    from aegis.store import IndexStore
    rows, _ = _chain([{"alert_id": f"a{i}", "verdict": "benign", "confidence": 0.5} for i in range(3)])
    rows.append({"alert_id": "FORGED", "verdict": "malicious", "confidence": 0.99, "integrity_hash": "f" * 64})
    audit = tmp_path / "audit.jsonl"
    _write(audit, rows)
    st = IndexStore(f"sqlite:///{tmp_path / 'i.sqlite'}")
    orig = st._index.__func__
    n = {"c": 0}

    def flaky(self, chain, **kw):
        n["c"] += 1
        if n["c"] == 2:
            self._fail("index_chain", OperationalError("x", {}, Exception("db down")))
            return "error"
        return orig(self, chain, **kw)
    st._index = types.MethodType(flaky, st)
    res = st.reindex(audit)
    assert res["errors"] == 1
    assert res["broken_at"] and "audit.jsonl" in res["broken_at"]
    assert res["stale"] is True and st.stale is True
    assert st.get("FORGED") is None


def test_r7_clean_reindex_clears_stale(tmp_path):
    from aegis.store import IndexStore
    rows, _ = _chain([{"alert_id": f"a{i}", "verdict": "benign", "confidence": 0.5} for i in range(3)])
    audit = tmp_path / "audit.jsonl"
    _write(audit, rows)
    st = IndexStore(f"sqlite:///{tmp_path / 'i.sqlite'}")
    res = st.reindex(audit)
    assert res["errors"] == 0 and res["broken_at"] is None and st.stale is False


# --------------------------------------------------------------- R-11 ---
def test_r11_no_bootstrap_key_ships():
    keys = L.load_public_keys()
    assert keys and not any("bootstrap" in k for k in keys)
    assert not list((ROOT / "aegis" / "keys").glob("*bootstrap*"))


# --------------------------------------------------------------- R-12 ---
def _rotated_log(tmp_path: Path, anchor_hashes_from_first: bool = False):
    audit = tmp_path / "audit.jsonl"
    seg1, tail1 = _chain([{"alert_id": f"s1-{i}"} for i in range(3)])
    seg2, tail2 = _chain([{"alert_id": f"s2-{i}"} for i in range(3)], tail1)
    live, _ = _chain([{"alert_id": f"l-{i}"} for i in range(2)], tail2)
    _write(tmp_path / "audit.jsonl.1000", seg1)
    _write(tmp_path / "audit.jsonl.2000", seg2)
    _write(audit, live)
    return audit, seg1, tail1


@pytest.fixture
def _audit_env(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_DECISION_KEY", "k" * 64)
    monkeypatch.setenv("AEGIS_AUDIT_ANCHOR", str(tmp_path / "anchors.jsonl"))
    return tmp_path


def test_r12_retire_keeps_verify_all_green_and_retires_anchors(_audit_env):
    from aegis.agents.shared.audit import AuditLog
    tmp = _audit_env
    audit, seg1, tail1 = _rotated_log(tmp)
    (tmp / "anchors.jsonl").write_text(json.dumps({"hash": seg1[1]["integrity_hash"], "log": str(audit.resolve())}) + "\n")
    log = AuditLog(audit, repair=False)
    assert log.verify_report(all_files=True)["ok"]
    res = log.retire_segments(1)
    assert res["ok"] and res["seed"] == tail1 and res["signed"]
    assert not (tmp / "audit.jsonl.1000").exists()
    rep = AuditLog(audit, repair=False).verify_report(all_files=True)
    assert rep["ok"], rep                                    # the anchor on a retired row no longer reads as truncation
    cp, problem = AuditLog(audit, repair=False).retention()
    assert not problem and seg1[1]["integrity_hash"] in cp["anchors_retired"] and cp["entries_retired"] == 3


def test_r12_deleting_a_segment_without_retire_is_still_caught(_audit_env):
    from aegis.agents.shared.audit import AuditLog
    audit, _, _ = _rotated_log(_audit_env)
    (_audit_env / "audit.jsonl.1000").unlink()
    assert not AuditLog(audit, repair=False).verify_report(all_files=True)["ok"]


def test_r12_tampered_retention_checkpoint_breaks_verification(_audit_env):
    from aegis.agents.shared.audit import AuditLog
    audit, _, _ = _rotated_log(_audit_env)
    assert AuditLog(audit, repair=False).retire_segments(1)["ok"]
    rp = AuditLog(audit, repair=False).retention_path()
    cp = json.loads(rp.read_text())
    cp["seed"] = "a" * 64
    rp.write_text(json.dumps(cp))
    rep = AuditLog(audit, repair=False).verify_report(all_files=True)
    assert not rep["ok"] and rep["broken_at"][0] == "<retention>"


def test_r12_retire_refuses_a_broken_segment(_audit_env):
    from aegis.agents.shared.audit import AuditLog
    audit, seg1, _ = _rotated_log(_audit_env)
    seg1[1]["alert_id"] = "edited"
    _write(_audit_env / "audit.jsonl.1000", seg1)
    res = AuditLog(audit, repair=False).retire_segments(1)
    assert not res["ok"] and (_audit_env / "audit.jsonl.1000").exists()


def test_r12_retire_cli(_audit_env, capsys):
    from aegis.audit.__main__ import main
    audit, _, _ = _rotated_log(_audit_env)
    assert main(["retire", "--audit", str(audit), "--segments", "2"]) == 0
    assert json.loads(capsys.readouterr().out.strip().splitlines()[-1])["ok"]
    assert main(["verify", "--audit", str(audit), "--all"]) == 0


# ------------------------------------------------------------ R-3 / R-5 ---
def test_r3_agent_chart_is_a_single_replica_service():
    t = ROOT / "aegis" / "k8s" / "templates"
    assert not (t / "hpa.yaml").exists() and not (t / "deployment.yaml").exists()
    ss = (t / "statefulset.yaml").read_text()
    assert "kind: StatefulSet" in ss and "replicas: 1\n" in ss
    assert '"aegis.service", "--audit"' in ss and "aegis.main" not in ss.split("command:")[1].splitlines()[0]
    for var in ("AEGIS_AUDIT_PATH", "AEGIS_CHECKPOINT", "AEGIS_HITL_DIR", "ACP_HOME", "AEGIS_INGEST_HTTP", "AEGIS_INGEST_BIND"):
        assert f"name: {var}" in ss
    assert "/readyz" not in ss and "path: /healthz, port: receiver" in ss
    yaml = pytest.importorskip("yaml")
    values = yaml.safe_load((ROOT / "aegis" / "k8s" / "values.yaml").read_text())
    assert "hpa" not in values and "replicas" not in values
    assert values["securityContext"]["readOnlyRootFilesystem"] is True


def test_r5_forensic_job_has_its_own_tokenless_identity():
    t = ROOT / "aegis" / "healing" / "k8s" / "templates"
    job = (t / "forensic-snapshot-job.yaml").read_text()
    assert "docker.sock" not in job.split("apiVersion", 1)[1]     # (the header comment may say why it is gone)
    assert "serviceAccountName: {{ .Values.forensics.serviceAccount }}" in job
    assert "automountServiceAccountToken: false" in job and "automountServiceAccountToken: true" not in job
    pol = (t / "forensic-admission-policy.yaml").read_text()
    assert "kind: ValidatingAdmissionPolicy" in pol and "hostPath" in pol
    rbac = (t / "controller-rbac.yaml").read_text()
    assert "forensic-admission-policy.yaml" in rbac
