"""IAM posture review: the standing risks in an account, from an offline export."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aegis.posture import iam_review, sources, summarize
from aegis.posture.__main__ import main as cli

SAMPLES = Path(__file__).resolve().parents[1] / "posture" / "samples"
NOW = datetime(2026, 11, 2, tzinfo=UTC)
A = "111111111111"


@pytest.fixture
def details():
    return sources.load_json(SAMPLES / "aws_iam_auth_details.json")


@pytest.fixture
def report():
    return sources.load_credential_report(SAMPLES / "aws_credential_report.csv")


def ids(findings, component=None):
    return {f.id for f in findings if component is None or f.affected_component.startswith(component)}


def test_sample_account_finds_every_planted_issue(details, report):
    f = iam_review.review(details, report, now=NOW)
    assert ids(f) == {
        "IAM-ROLE-TRUST-ANYONE", "IAM-ROOT-ACCESS-KEY", "IAM-ROOT-NO-MFA", "IAM-POLICY-PRIVESC",
        "IAM-ROLE-CROSS-ACCOUNT", "IAM-ROLE-INLINE-ADMIN", "IAM-USER-ADMIN", "IAM-USER-NO-MFA",
        "IAM-KEY-NOT-ROTATED", "IAM-USER-INACTIVE-PASSWORD", "IAM-USER-DIRECT-POLICY", "IAM-USER-TWO-KEYS",
    }
    assert summarize(f) == {"critical": 3, "high": 5, "medium": 2, "low": 2, "info": 0}


def test_most_severe_first_and_risk_scored(details, report):
    f = iam_review.review(details, report, now=NOW)
    assert [x.severity for x in f[:3]] == ["critical"] * 3
    assert all(x.risk_score is not None and x.scanner == "iam_review" for x in f)
    assert f[0].risk_score > f[-1].risk_score


def test_service_roles_and_clean_users_are_not_flagged(details, report):
    f = iam_review.review(details, report, now=NOW)
    assert not ids(f, "lambda-exec")
    # analyst: MFA on, read-only via group — only the stale console password
    assert ids(f, "analyst") == {"IAM-USER-INACTIVE-PASSWORD"}


def test_admin_via_group_is_caught(details):
    f = iam_review.review(details, None, now=NOW)
    admin = [x for x in f if x.id == "IAM-USER-ADMIN"]
    assert [x.affected_component for x in admin] == ["ops-admin"]


def test_trusted_account_suppresses_cross_account_finding(details):
    f = iam_review.review(details, None, now=NOW, trusted_accounts=["999999999999"])
    assert "IAM-ROLE-CROSS-ACCOUNT" not in ids(f)


def test_external_id_condition_downgrades_cross_account(details):
    role = next(r for r in details["RoleDetailList"] if r["RoleName"] == "vendor-audit")
    role["AssumeRolePolicyDocument"]["Statement"][0]["Condition"] = {"StringEquals": {"sts:ExternalId": "x"}}
    f = [x for x in iam_review.review(details, None, now=NOW) if x.id == "IAM-ROLE-CROSS-ACCOUNT"]
    assert f and f[0].severity == "medium"


def test_conditioned_wildcard_trust_is_high_not_critical():
    d = {"RoleDetailList": [{"RoleName": "r", "Arn": f"arn:aws:iam::{A}:role/r", "Path": "/",
         "AssumeRolePolicyDocument": {"Statement": [{"Effect": "Allow", "Principal": "*",
                                                      "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-1"}}}]}}]}
    (f,) = iam_review.review(d, None, now=NOW)
    assert (f.id, f.severity) == ("IAM-ROLE-TRUST-ANYONE", "high")


def test_same_account_trust_is_not_cross_account():
    d = {"RoleDetailList": [{"RoleName": "r", "Arn": f"arn:aws:iam::{A}:role/r", "Path": "/",
         "AssumeRolePolicyDocument": {"Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{A}:root"}}]}}]}
    assert iam_review.review(d, None, now=NOW) == []


def test_url_encoded_policy_documents_are_decoded():
    from urllib.parse import quote
    doc = quote(json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))
    d = {"Policies": [{"PolicyName": "p", "Arn": f"arn:aws:iam::{A}:policy/p", "AttachmentCount": 2,
                       "PolicyVersionList": [{"IsDefaultVersion": True, "Document": doc}]}]}
    assert ids(iam_review.review(d, None, now=NOW)) == {"IAM-POLICY-FULL-ADMIN"}


def test_unattached_and_aws_managed_policies_are_skipped():
    full = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    d = {"Policies": [
        {"PolicyName": "unused", "Arn": f"arn:aws:iam::{A}:policy/unused", "AttachmentCount": 0,
         "PolicyVersionList": [{"IsDefaultVersion": True, "Document": full}]},
        {"PolicyName": "AdministratorAccess", "Arn": iam_review.ADMIN_POLICY_ARN, "AttachmentCount": 5,
         "PolicyVersionList": [{"IsDefaultVersion": True, "Document": full}]}]}
    assert iam_review.review(d, None, now=NOW) == []


def test_deny_statements_do_not_count_as_admin():
    d = {"Policies": [{"PolicyName": "p", "Arn": f"arn:aws:iam::{A}:policy/p", "AttachmentCount": 1,
                       "PolicyVersionList": [{"IsDefaultVersion": True,
                                              "Document": {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}}]}]}
    assert iam_review.review(d, None, now=NOW) == []


def test_never_used_old_key_is_unused(report):
    row = {"user": "bot", "arn": "x", "password_enabled": "false", "mfa_active": "false",
           "access_key_1_active": "true", "access_key_1_last_rotated": "2026-08-01T00:00:00+00:00",
           "access_key_1_last_used_date": "N/A", "access_key_2_active": "false"}
    f = iam_review.review({}, [row], now=NOW)
    (unused,) = [x for x in f if x.id == "IAM-KEY-UNUSED"]
    assert "never used" in unused.evidence


def test_credential_report_formats(report):
    csv_text = (SAMPLES / "aws_credential_report.csv").read_text()
    b64 = base64.b64encode(csv_text.encode()).decode()
    envelope = json.dumps({"Content": b64, "ReportFormat": "text/csv"})
    for raw in (csv_text, b64, envelope, csv_text.encode()):
        assert sources.parse_credential_report(raw) == report


def test_without_credential_report_the_gap_is_reported(details):
    assert iam_review.coverage_note(None)
    assert not ids(iam_review.review(details, None, now=NOW)) & {"IAM-ROOT-NO-MFA", "IAM-USER-NO-MFA"}


def test_live_mode_refuses_unless_enabled(monkeypatch):
    monkeypatch.delenv("AEGIS_POSTURE_LIVE", raising=False)
    with pytest.raises(sources.PostureSourceError, match="AEGIS_POSTURE_LIVE"):
        sources.live_aws_iam()


def test_live_mode_explains_missing_sdk(monkeypatch):
    import builtins
    monkeypatch.setenv("AEGIS_POSTURE_LIVE", "1")
    real = builtins.__import__
    monkeypatch.setattr(builtins, "__import__", lambda n, *a, **k: (_ for _ in ()).throw(ImportError()) if n == "boto3" else real(n, *a, **k))
    with pytest.raises(sources.PostureSourceError, match="boto3"):
        sources.live_aws_iam()


def test_live_mode_collects_with_read_only_calls(monkeypatch, details):
    calls = []

    class FakeIAM:
        def get_paginator(self, name):
            calls.append(name)
            return type("P", (), {"paginate": lambda self: iter([details])})()

        def generate_credential_report(self):
            calls.append("generate_credential_report")
            return {"State": "COMPLETE"}

        def get_credential_report(self):
            calls.append("get_credential_report")
            return {"Content": (SAMPLES / "aws_credential_report.csv").read_bytes()}

    monkeypatch.setattr(sources, "_boto3_client", lambda service: FakeIAM())
    d, rep = sources.live_aws_iam()
    assert calls == ["get_account_authorization_details", "generate_credential_report", "get_credential_report"]
    assert len(d["UserDetailList"]) == 3 and len(rep) == 4


def test_cli_json_and_fail_on(capsys):
    args = ["iam", "--auth-details", str(SAMPLES / "aws_iam_auth_details.json"), "--json"]
    assert cli(args) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["summary"]["critical"] == 1  # only the Principal "*" trust; root checks need the report
    assert out["note"] and out["findings"][0]["severity"] in ("critical", "high")
    assert cli(args + ["--fail-on", "high"]) == 1
    assert cli(args + ["--fail-on", "critical"]) == 1  # Principal "*" trust is critical without any report


def test_cli_missing_input_is_a_usage_error(capsys):
    assert cli(["iam"]) == 2
    assert "--auth-details" in capsys.readouterr().err
