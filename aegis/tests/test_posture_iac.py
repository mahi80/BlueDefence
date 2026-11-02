"""Policy-as-code gate: Terraform plans and Kubernetes manifests, judged by the same rules as runtime."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from aegis.posture import iac_policy as iac
from aegis.posture import sources, summarize
from aegis.posture.__main__ import main as cli

S = Path(__file__).resolve().parents[1] / "posture" / "samples" / "iac"
TODAY = date(2026, 11, 2)


@pytest.fixture
def plan():
    return sources.load_json(S / "plan.json")


def rc(addr, typ, after, actions=("create",)):
    return {"resource_changes": [{"address": addr, "type": typ, "change": {"actions": list(actions), "after": after}}]}


def ids(findings):
    return sorted((f.id, f.resource) for f in findings)


def test_sample_plan(plan):
    f = iac.scan_plan(plan)
    assert summarize(f) == {"critical": 4, "high": 6, "medium": 1, "low": 0, "info": 0}
    assert all(x.scanner == "iac_policy" and x.resource.startswith("aws_") for x in f)


def test_same_rule_ids_as_runtime(plan):
    got = {x.id for x in iac.scan_plan(plan)}
    assert {"CSPM-SG-DB-PORT-OPEN", "CSPM-RDS-PUBLIC", "CSPM-EC2-IMDSV1", "IAM-POLICY-FULL-ADMIN", "IAM-ROLE-TRUST-ANYONE"} <= got


def test_deleted_and_safe_resources_pass(plan):
    addrs = {x.resource for x in iac.scan_plan(plan)}
    assert "aws_db_instance.old_reports" not in addrs           # being deleted
    assert "aws_vpc_security_group_ingress_rule.web_https" not in addrs
    assert "aws_launch_template.batch" not in addrs             # IMDSv2 required
    assert "aws_kms_key.cards" not in addrs                     # rotation on


def test_changed_only_skips_no_op():
    p = rc("aws_kms_key.k", "aws_kms_key", {"enable_key_rotation": False}, actions=("no-op",))
    assert iac.scan_plan(p) and not iac.scan_plan(p, changed_only=True)


@pytest.mark.parametrize("typ,after,expect", [
    ("aws_security_group", {"ingress": [{"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}]}, "CSPM-SG-ALL-PORTS-OPEN"),
    ("aws_security_group", {"ingress": [{"protocol": "tcp", "from_port": 3389, "to_port": 3389, "ipv6_cidr_blocks": ["::/0"]}]}, "CSPM-SG-ADMIN-PORT-OPEN"),
    ("aws_security_group_rule", {"type": "ingress", "protocol": "tcp", "from_port": 6379, "to_port": 6379, "cidr_blocks": ["0.0.0.0/0"]}, "CSPM-SG-DB-PORT-OPEN"),
    ("aws_ebs_volume", {"encrypted": False}, "CSPM-EBS-UNENCRYPTED"),
    ("aws_ebs_encryption_by_default", {"enabled": False}, "CSPM-EBS-DEFAULT-ENCRYPTION-OFF"),
    ("aws_cloudtrail", {"enable_log_file_validation": False}, "CSPM-CLOUDTRAIL-NO-VALIDATION"),
    ("aws_s3_bucket_acl", {"acl": "public-read"}, "CSPM-S3-PUBLIC-BUCKET"),
    ("aws_s3_account_public_access_block", {"block_public_acls": False}, "CSPM-S3-ACCOUNT-BPA-OFF"),
    ("aws_iam_role_policy", {"policy": json.dumps({"Statement": [{"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": "*"}]})}, "IAM-POLICY-PRIVESC"),
    ("aws_iam_group_policy_attachment", {"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}, "IAM-USER-ADMIN"),
    ("aws_eks_cluster", {"vpc_config": [{"endpoint_public_access": True}]}, "IAC-EKS-PUBLIC-API"),
    ("aws_instance", {}, "CSPM-EC2-IMDSV1"),  # IMDSv2 not required explicitly
])
def test_terraform_rules(typ, after, expect):
    assert [x.id for x in iac.scan_plan(rc(f"{typ}.x", typ, after))] == [expect]


@pytest.mark.parametrize("typ,after", [
    ("aws_security_group_rule", {"type": "egress", "protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}),
    ("aws_security_group", {"ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": ["10.0.0.0/8"]}]}),
    ("aws_s3_bucket_policy", {"policy": json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                                                                   "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-1"}}}]})}),
    ("aws_eks_cluster", {"vpc_config": [{"endpoint_public_access": True, "public_access_cidrs": ["203.0.113.0/24"]}]}),
    ("aws_kms_key", {"enable_key_rotation": False, "customer_master_key_spec": "RSA_2048"}),
    ("aws_iam_role", {"assume_role_policy": json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}}]})}),
    ("aws_db_instance", {"publicly_accessible": False, "storage_encrypted": True, "backup_retention_period": 7, "deletion_protection": True}),
    ("aws_instance", {"metadata_options": [{"http_tokens": "required"}]}),
])
def test_terraform_safe_configs(typ, after):
    assert iac.scan_plan(rc(f"{typ}.x", typ, after)) == []


def test_conditioned_wildcard_trust_is_high():
    doc = {"Statement": [{"Effect": "Allow", "Principal": "*", "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-1"}}}]}
    (f,) = iac.scan_plan(rc("aws_iam_role.r", "aws_iam_role", {"assume_role_policy": json.dumps(doc)}))
    assert f.severity == "high"


def test_manifests_reuse_k8s_rules_without_cluster_dependent_checks():
    docs = iac.load_manifests([S / "k8s"])
    assert {d["kind"] for d in docs} == {"Deployment", "DaemonSet"}
    f = iac.scan_manifests(docs)
    assert {x.resource for x in f} == {"DaemonSet/logging/log-shipper"}           # payments-api is clean
    assert {"K8S-PRIVILEGED", "K8S-HOSTPATH-SENSITIVE", "K8S-SECRET-IN-ENV"} <= {x.id for x in f}
    assert not {x.id for x in f} & {"K8S-NO-NETWORKPOLICY", "K8S-NO-POD-SECURITY-ADMISSION"}


def test_manifest_list_and_bad_yaml(tmp_path):
    (tmp_path / "list.json").write_text(json.dumps({"kind": "List", "items": [{"kind": "Pod", "metadata": {"name": "p"}, "spec": {"containers": []}}]}))
    assert [d["kind"] for d in iac.load_manifests([tmp_path])] == ["Pod"]
    (tmp_path / "bad.yaml").write_text("kind: [unclosed")
    with pytest.raises(sources.PostureSourceError, match="cannot parse"):
        iac.load_manifests([tmp_path])


# ---- waivers --------------------------------------------------------------------------------------

def test_waivers_apply_expire_and_report(plan):
    f = iac.scan_plan(plan)
    kept, waived, notes = iac.apply_waivers(f, iac.load_waivers(S / "waivers.yaml"), today=TODAY)
    assert [(x.id, w.approved_by) for x, w in waived] == [("CSPM-SG-ADMIN-PORT-OPEN", "ciso")]
    assert len(kept) == len(f) - 1
    assert any("expired 2026-06-30" in n for n in notes)
    assert "CSPM-KMS-NO-ROTATION" in {x.id for x in kept}                     # expired waiver suppresses nothing


def test_waiver_globs_and_unused_waivers(plan, tmp_path):
    w = tmp_path / "w.yaml"
    w.write_text("waivers:\n"
                 "  - {id: 'CSPM-RDS-*', resource: 'aws_db_instance.ledger', reason: r, approved_by: ciso, expires: 2027-01-01}\n"
                 "  - {id: 'IAM-*', resource: 'aws_iam_role.nothing', reason: r, approved_by: ciso, expires: 2027-01-01}\n")
    _, waived, notes = iac.apply_waivers(iac.scan_plan(plan), iac.load_waivers(w), today=TODAY)
    assert sorted(x.id for x, _ in waived) == ["CSPM-RDS-PUBLIC", "CSPM-RDS-UNENCRYPTED"]
    assert any("matched nothing" in n and "aws_iam_role.nothing" in n for n in notes)


@pytest.mark.parametrize("entry,missing", [
    ("{id: X, resource: r, approved_by: ciso, expires: 2027-01-01}", "reason"),
    ("{id: X, resource: r, reason: because, expires: 2027-01-01}", "approved_by"),
    ("{id: X, resource: r, reason: because, approved_by: ciso}", "expires"),
])
def test_waiver_must_have_reason_approver_and_expiry(tmp_path, entry, missing):
    w = tmp_path / "w.yaml"
    w.write_text(f"waivers:\n  - {entry}\n")
    with pytest.raises(sources.PostureSourceError, match=missing):
        iac.load_waivers(w)


# ---- CLI as a CI gate -----------------------------------------------------------------------------

def test_cli_gate(capsys, monkeypatch):
    monkeypatch.setattr(iac, "_today", lambda: TODAY)  # sample waivers expire; keep the test independent of the clock
    base = ["iac", "--plan", str(S / "plan.json"), "--k8s", str(S / "k8s"), "--waivers", str(S / "waivers.yaml"), "--json"]
    assert cli(base + ["--fail-on", "high"]) == 1
    rep = json.loads(capsys.readouterr().out)
    assert rep["scan"] == "iac" and len(rep["waived"]) == 1 and rep["waived"][0]["waiver"]["approved_by"] == "ciso"
    assert rep["findings"][0]["severity"] == "critical"
    assert cli(base) == 0                                                    # report-only without --fail-on


def test_cli_rejects_non_plan_and_missing_input(tmp_path, capsys):
    p = tmp_path / "state.json"
    p.write_text(json.dumps({"values": {}}))
    assert cli(["iac", "--plan", str(p)]) == 2
    assert "not a Terraform plan" in capsys.readouterr().err
    assert cli(["iac"]) == 2


def test_clean_plan_passes_the_gate(tmp_path):
    p = tmp_path / "plan.json"
    p.write_text(json.dumps(rc("aws_instance.ok", "aws_instance", {"metadata_options": [{"http_tokens": "required"}]})))
    assert cli(["iac", "--plan", str(p), "--fail-on", "low"]) == 0
