"""Kubernetes posture: workloads, RBAC and network isolation from a kubectl export (or live kubectl)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from aegis.posture import k8s_posture as k8s
from aegis.posture import sources, summarize
from aegis.posture.__main__ import main as cli

SAMPLES = Path(__file__).resolve().parents[1] / "posture" / "samples"


@pytest.fixture
def export():
    return sources.load_json(SAMPLES / "k8s_cluster_export.json")


def where(findings, fid):
    return sorted(f.affected_component for f in findings if f.id == fid)


def dep(spec, name="app", ns="apps"):
    return {"kind": "Deployment", "metadata": {"name": name, "namespace": ns}, "spec": {"template": {"spec": spec}}}


HARDENED = {"name": "c", "image": "r/app@sha256:1", "resources": {"limits": {"cpu": "1", "memory": "1Gi"}},
            "securityContext": {"allowPrivilegeEscalation": False, "runAsNonRoot": True, "readOnlyRootFilesystem": True}}


def ids_for(spec):
    return {f.id for f in k8s.scan([dep(spec)]) if f.resource.startswith("Deployment/")}


def test_sample_cluster_summary(export):
    f = k8s.scan(export)
    assert summarize(f) == {"critical": 4, "high": 6, "medium": 9, "low": 12, "info": 0}
    assert all(x.scanner == "k8s_posture" for x in f)


def test_clean_controlled_and_system_workloads_are_not_flagged(export):
    refs = {f.affected_component for f in k8s.scan(export)}
    assert not any("payments-api" in r for r in refs)          # hardened workload + its namespace policy
    assert not any("kube-proxy" in r for r in refs)            # kube-system skipped by default
    assert "Namespace/payments" not in refs                    # has NetworkPolicy and PSA enforce label


def test_include_system_scans_kube_system(export):
    f = k8s.scan(export, include_system=True)
    assert "DaemonSet/kube-system/kube-proxy" in where(f, "K8S-PRIVILEGED")


def test_breakout_paths(export):
    f = k8s.scan(export)
    assert where(f, "K8S-PRIVILEGED") == ["DaemonSet/batch/node-agent"]
    assert where(f, "K8S-HOSTPATH-SENSITIVE") == ["DaemonSet/batch/node-agent"]
    assert where(f, "K8S-HOST-NAMESPACE") == ["DaemonSet/batch/node-agent"]


def test_cluster_admin_service_account_mounted_in_a_workload_is_critical(export):
    f = k8s.scan(export)
    assert where(f, "K8S-WORKLOAD-CLUSTER-ADMIN-SA") == ["Deployment/batch/report-gen"]
    assert where(f, "K8S-RBAC-CLUSTER-ADMIN") == ["ClusterRoleBinding/ci-admin"]   # system:masters binding is not flagged


def test_token_not_mounted_downgrades_cluster_admin_sa(export):
    for o in export["items"]:
        if o["metadata"]["name"] == "report-gen":
            o["spec"]["template"]["spec"]["automountServiceAccountToken"] = False
    assert not where(k8s.scan(export), "K8S-WORKLOAD-CLUSTER-ADMIN-SA")


def test_rbac_rules_only_for_bound_custom_roles(export):
    f = k8s.scan(export)
    assert where(f, "K8S-RBAC-WILDCARD") == ["ClusterRole/ops-everything"]      # unused-wild is unbound → inert
    assert where(f, "K8S-RBAC-READ-SECRETS") == ["Role/payments/support-debug"]
    assert where(f, "K8S-RBAC-POD-EXEC") == ["Role/payments/support-debug"]
    assert where(f, "K8S-RBAC-ANONYMOUS") == ["ClusterRoleBinding/oops-public-view"]


def test_escalate_bind_impersonate():
    items = [{"kind": "ClusterRole", "metadata": {"name": "r"}, "rules": [{"resources": ["clusterroles"], "verbs": ["bind", "escalate"]}]},
             {"kind": "ClusterRoleBinding", "metadata": {"name": "b"}, "roleRef": {"kind": "ClusterRole", "name": "r"}, "subjects": [{"kind": "User", "name": "u"}]}]
    (f,) = k8s.scan(items)
    assert f.id == "K8S-RBAC-ESCALATE" and "bind, escalate" in f.evidence


def test_hardened_container_is_clean():
    assert ids_for({"serviceAccountName": "app", "containers": [HARDENED]}) == set()


@pytest.mark.parametrize("patch,expect", [
    ({"securityContext": {**HARDENED["securityContext"], "privileged": True}}, "K8S-PRIVILEGED"),
    ({"securityContext": {**HARDENED["securityContext"], "capabilities": {"add": ["NET_ADMIN"]}}}, "K8S-DANGEROUS-CAPABILITY"),
    ({"securityContext": {**HARDENED["securityContext"], "runAsNonRoot": None, "runAsUser": 0}}, "K8S-RUNS-AS-ROOT"),
    ({"securityContext": {**HARDENED["securityContext"], "allowPrivilegeEscalation": True}}, "K8S-PRIV-ESCALATION-ALLOWED"),
    ({"securityContext": {**HARDENED["securityContext"], "readOnlyRootFilesystem": False}}, "K8S-WRITABLE-ROOTFS"),
    ({"image": "nginx"}, "K8S-IMAGE-LATEST"),
    ({"image": "nginx:latest"}, "K8S-IMAGE-LATEST"),
    ({"resources": {"limits": {"cpu": "1"}}}, "K8S-NO-LIMITS"),
    ({"ports": [{"containerPort": 80, "hostPort": 80}]}, "K8S-HOST-PORT"),
    ({"env": [{"name": "API_KEY", "value": "abc"}]}, "K8S-SECRET-IN-ENV"),
])
def test_single_container_misconfig(patch, expect):
    assert expect in ids_for({"serviceAccountName": "app", "containers": [{**HARDENED, **patch}]})


def test_secret_env_via_secret_ref_is_fine():
    c = {**HARDENED, "env": [{"name": "DB_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "db", "key": "pw"}}}]}
    assert ids_for({"serviceAccountName": "app", "containers": [c]}) == set()


def test_registry_port_is_not_a_tag():
    c = {**HARDENED, "image": "registry.bank:5000/app:2.1"}
    assert "K8S-IMAGE-LATEST" not in ids_for({"serviceAccountName": "app", "containers": [c]})


def test_pod_level_run_as_non_root_covers_containers():
    c = {**HARDENED, "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True}}
    spec = {"serviceAccountName": "app", "securityContext": {"runAsNonRoot": True}, "containers": [c]}
    assert ids_for(spec) == set()


def test_init_containers_and_cronjobs_are_scanned():
    bad = {**HARDENED, "securityContext": {"privileged": True}}
    cj = {"kind": "CronJob", "metadata": {"name": "nightly", "namespace": "apps"},
          "spec": {"jobTemplate": {"spec": {"template": {"spec": {"serviceAccountName": "x", "initContainers": [bad], "containers": [HARDENED]}}}}}}
    assert "CronJob/apps/nightly" in where(k8s.scan([cj]), "K8S-PRIVILEGED")


def test_non_sensitive_hostpath_is_high_not_critical():
    f = k8s.scan([dep({"serviceAccountName": "a", "volumes": [{"name": "l", "hostPath": {"path": "/var/log/app"}}], "containers": [HARDENED]})])
    assert [(x.id, x.severity) for x in f if "HOSTPATH" in x.id] == [("K8S-HOSTPATH", "high")]


def test_secrets_in_export_are_ignored_and_reported(export):
    export["items"].append({"kind": "Secret", "metadata": {"name": "db", "namespace": "payments"}, "data": {"pw": "c2VjcmV0"}})
    before = summarize(k8s.scan(export))
    assert before == {"critical": 4, "high": 6, "medium": 9, "low": 12, "info": 0}
    assert any("Secret objects" in n for n in k8s.notes(export))


def test_notes_flag_missing_kinds():
    n = k8s.notes([dep({"containers": [HARDENED]})])
    assert any("Namespace" in x and "NetworkPolicy" in x for x in n)


# ---- live collection + CLI -----------------------------------------------------------------------

def test_live_needs_flag(monkeypatch):
    monkeypatch.delenv("AEGIS_POSTURE_LIVE", raising=False)
    with pytest.raises(sources.PostureSourceError, match="AEGIS_POSTURE_LIVE"):
        sources.collect_k8s()


def test_live_runs_read_only_kubectl_without_secrets(monkeypatch, export):
    monkeypatch.setenv("AEGIS_POSTURE_LIVE", "1")
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/kubectl")
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, json.dumps(export), "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    out = sources.collect_k8s("prod-ap-south-1")
    assert out == export
    cmd = seen["cmd"]
    assert cmd[1] == "get" and "secrets" not in cmd[2].split(",") and cmd[-2:] == ["--context", "prod-ap-south-1"]


def test_live_kubectl_errors_surface(monkeypatch):
    monkeypatch.setenv("AEGIS_POSTURE_LIVE", "1")
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/kubectl")
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, "", "Forbidden: cannot list rolebindings"))
    with pytest.raises(sources.PostureSourceError, match="Forbidden"):
        sources.collect_k8s()


def test_live_without_kubectl(monkeypatch):
    monkeypatch.setenv("AEGIS_POSTURE_LIVE", "1")
    monkeypatch.setattr("shutil.which", lambda _: None)
    with pytest.raises(sources.PostureSourceError, match="kubectl on PATH"):
        sources.collect_k8s()


def test_cli(capsys):
    args = ["k8s", "--export", str(SAMPLES / "k8s_cluster_export.json"), "--json"]
    assert cli(args + ["--fail-on", "critical"]) == 1
    rep = json.loads(capsys.readouterr().out)
    assert rep["scan"] == "k8s" and rep["summary"]["critical"] == 4 and rep["notes"]
    assert cli(["k8s"]) == 2
    assert "kubectl get" in capsys.readouterr().err
