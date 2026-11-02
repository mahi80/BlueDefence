"""CSPM: standing AWS misconfigurations from a bundle (offline export or live read-only collection)."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from aegis.posture import cspm, sources, summarize
from aegis.posture.__main__ import main as cli

SAMPLES = Path(__file__).resolve().parents[1] / "posture" / "samples"


@pytest.fixture
def bundle():
    return sources.load_json(SAMPLES / "aws_cspm_bundle.json")


def by(findings, fid):
    return [f.affected_component for f in findings if f.id == fid]


def test_sample_bundle_summary(bundle):
    f = cspm.scan(bundle)
    assert summarize(f) == {"critical": 6, "high": 4, "medium": 9, "low": 6, "info": 0}
    assert all(x.scanner == "cspm" and x.risk_score for x in f)
    assert cspm.coverage_gaps(bundle) == []


def test_public_buckets_respect_block_public_access(bundle):
    f = cspm.scan(bundle)
    # policy-public, ACL-public, and one policy-public bucket shielded by its own BPA
    assert sorted(by(f, "CSPM-S3-PUBLIC-BUCKET")) == ["wb-kyc-scans", "wb-marketing-site"]
    # turning on account-level BPA shields every bucket
    bundle["account_public_access_block"] = {k: True for k in cspm._BPA}
    f = cspm.scan(bundle)
    assert not by(f, "CSPM-S3-PUBLIC-BUCKET") and not by(f, "CSPM-S3-ACCOUNT-BPA-OFF")


def test_security_group_rules(bundle):
    f = cspm.scan(bundle)
    assert by(f, "CSPM-SG-DB-PORT-OPEN") == ["core-db (sg-0db)"]
    assert by(f, "CSPM-SG-ADMIN-PORT-OPEN") == ["jumpbox (sg-0jump)"]
    assert by(f, "CSPM-SG-ALL-PORTS-OPEN") == ["legacy-any (sg-0legacy)"]
    assert not [x for x in f if "sg-0web" in x.affected_component]  # 443 public + 8080 internal is fine


@pytest.mark.parametrize("perm,expect", [
    ({"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}, "CSPM-SG-ALL-PORTS-OPEN"),
    ({"IpProtocol": "tcp", "FromPort": 3300, "ToPort": 3310, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}, "CSPM-SG-DB-PORT-OPEN"),  # 3306 inside a range
    ({"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}, "CSPM-SG-ADMIN-PORT-OPEN"),
    ({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "203.0.113.0/24"}]}, None),
])
def test_port_ranges_and_sources(perm, expect):
    f = cspm.scan({"security_groups": [{"GroupId": "sg-x", "GroupName": "x", "IpPermissions": [perm]}]})
    assert [x.id for x in f] == ([expect] if expect else [])


def test_ipv6_admin_port_maps_to_ipv6_control():
    perm = {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}
    (f,) = cspm.scan({"security_groups": [{"GroupId": "sg-x", "GroupName": "x", "IpPermissions": [perm]}]})
    assert f.control.endswith("5.3")


def test_imdsv1_is_worse_on_public_instances(bundle):
    f = {x.affected_component: x.severity for x in cspm.scan(bundle) if x.id == "CSPM-EC2-IMDSV1"}
    assert f == {"netbanking-web-1 (i-0weba)": "high", "i-0batch": "medium"}  # terminated one skipped


def test_rds_checks(bundle):
    f = cspm.scan(bundle)
    for fid in ("CSPM-RDS-PUBLIC", "CSPM-RDS-UNENCRYPTED", "CSPM-RDS-NO-BACKUPS", "CSPM-RDS-NO-DELETION-PROTECTION"):
        assert by(f, fid) == ["core-ledger"]


def test_multi_region_trail_clears_the_critical(bundle):
    bundle["trails"].append({"Name": "org", "TrailARN": "arn:org", "IsMultiRegionTrail": True, "IsLogging": True,
                             "LogFileValidationEnabled": True, "KmsKeyId": "arn:kms"})
    assert not by(cspm.scan(bundle), "CSPM-CLOUDTRAIL-NO-MULTIREGION")


def test_stopped_multi_region_trail_is_flagged_twice():
    b = {"trails": [{"Name": "org", "TrailARN": "arn:org", "IsMultiRegionTrail": True, "IsLogging": False}]}
    assert {x.id for x in cspm.scan(b)} == {"CSPM-CLOUDTRAIL-NO-MULTIREGION", "CSPM-CLOUDTRAIL-STOPPED"}


def test_only_customer_symmetric_keys_need_rotation(bundle):
    assert by(cspm.scan(bundle), "CSPM-KMS-NO-ROTATION") == ["k-cust"]


def test_missing_sections_are_gaps_not_clean():
    f = cspm.scan({"account_id": "1"})
    assert f == []
    assert set(cspm.coverage_gaps({"account_id": "1"})) == set(cspm.BUNDLE_KEYS)


def test_empty_sections_are_findings_when_absence_is_the_problem():
    f = {x.id for x in cspm.scan({"trails": [], "guardduty_detectors": [], "config_recorders": [], "password_policy": None})}
    assert f == {"CSPM-CLOUDTRAIL-NO-MULTIREGION", "CSPM-GUARDDUTY-OFF", "CSPM-CONFIG-OFF", "CSPM-NO-PASSWORD-POLICY"}


def test_clean_account_has_no_findings():
    on = {k: True for k in cspm._BPA}
    clean = {
        "account_public_access_block": on,
        "buckets": [{"Name": "b", "PublicAccessBlock": on, "PolicyStatus": {"IsPublic": False}, "Acl": {"Grants": []},
                     "Encryption": {"Rules": [{}]}, "Versioning": {"Status": "Enabled"}, "Logging": {"TargetBucket": "l"}}],
        "security_groups": [{"GroupId": "sg-d", "GroupName": "default", "IpPermissions": [], "IpPermissionsEgress": []}],
        "instances": [{"InstanceId": "i", "MetadataOptions": {"HttpTokens": "required"}}],
        "volumes": [{"VolumeId": "v", "Encrypted": True}], "ebs_encryption_by_default": True,
        "db_instances": [{"DBInstanceIdentifier": "d", "PubliclyAccessible": False, "StorageEncrypted": True,
                          "BackupRetentionPeriod": 7, "DeletionProtection": True}],
        "trails": [{"Name": "t", "IsMultiRegionTrail": True, "IsLogging": True, "LogFileValidationEnabled": True, "KmsKeyId": "k"}],
        "kms_keys": [{"KeyId": "k", "KeyManager": "CUSTOMER", "KeyState": "Enabled", "KeyRotationEnabled": True}],
        "vpcs": [{"VpcId": "v", "FlowLogs": ["v"]}], "guardduty_detectors": [{"Status": "ENABLED"}],
        "config_recorders": [{"name": "d", "recording": True}],
        "password_policy": {"MinimumPasswordLength": 14, "PasswordReusePrevention": 24},
    }
    assert cspm.scan(clean) == []
    assert cspm.coverage_gaps(clean) == []


# ---- live / export collection ------------------------------------------------------------------

class _Err(Exception):
    def __init__(self, code):
        self.response = {"Error": {"Code": code}}


class _Pager:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **_):
        return iter(self.pages)


class FakeAWS:
    """Minimal stand-in for the boto3 clients collect_aws_cspm uses; records every call made."""

    def __init__(self, svc, region, calls):
        self.svc, self.calls = svc, calls
        self.meta = type("M", (), {"region_name": region})()

    def __getattr__(self, op):
        if op.startswith("_"):
            raise AttributeError(op)

        def call(*a, **kw):
            self.calls.append(f"{self.svc}.{op}")
            return getattr(self, f"_{self.svc}_{op}", lambda **_: {})(**kw)
        return call

    def get_paginator(self, op):
        self.calls.append(f"{self.svc}.paginate:{op}")
        data = {
            "describe_security_groups": [{"SecurityGroups": [{"GroupId": "sg-1", "GroupName": "db", "IpPermissions": [
                {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]}],
            "describe_instances": [{"Reservations": [{"Instances": [{"InstanceId": "i-1", "MetadataOptions": {"HttpTokens": "optional"}}]}]}],
            "describe_vpcs": [{"Vpcs": [{"VpcId": "vpc-1"}]}],
            "list_keys": [{"Keys": [{"KeyId": "k1"}]}],
        }
        return _Pager(data.get(op, [{}]))

    def _sts_get_caller_identity(self):
        return {"Account": "123456789012"}

    def _s3control_get_public_access_block(self, **_):
        raise _Err("NoSuchPublicAccessBlockConfiguration")

    def _s3_list_buckets(self):
        return {"Buckets": [{"Name": "open"}]}

    def _s3_get_public_access_block(self, **_):
        raise _Err("NoSuchPublicAccessBlockConfiguration")

    def _s3_get_bucket_policy_status(self, **_):
        return {"PolicyStatus": {"IsPublic": True}}

    def _s3_get_bucket_encryption(self, **_):
        raise _Err("ServerSideEncryptionConfigurationNotFoundError")

    def _ec2_get_ebs_encryption_by_default(self):
        return {"EbsEncryptionByDefault": False}

    def _cloudtrail_describe_trails(self, **kw):
        assert kw.get("includeShadowTrails") is True
        return {"trailList": [{"Name": "org", "TrailARN": "arn:t", "HomeRegion": "us-east-1", "IsMultiRegionTrail": True,
                               "LogFileValidationEnabled": True}]}

    def _cloudtrail_get_trail_status(self, **_):
        return {"IsLogging": True}

    def _kms_describe_key(self, **_):
        return {"KeyMetadata": {"KeyId": "k1", "KeyManager": "CUSTOMER", "KeyState": "Enabled", "KeySpec": "SYMMETRIC_DEFAULT"}}

    def _kms_get_key_rotation_status(self, **_):
        return {"KeyRotationEnabled": False}

    def _guardduty_list_detectors(self):
        return {"DetectorIds": []}

    def _iam_get_account_password_policy(self):
        raise _Err("NoSuchEntity")


@pytest.fixture
def fake_aws(monkeypatch):
    calls: list[str] = []
    regions: list[str] = []

    def client(svc, *, require_flag=True, **kw):
        if require_flag and not sources.live_enabled():
            raise sources.PostureSourceError("live posture collection is off")
        regions.append(kw.get("region_name", "ap-south-1"))
        return FakeAWS(svc, kw.get("region_name", "ap-south-1"), calls)

    monkeypatch.setattr(sources, "_boto3_client", client)
    return calls, regions


def test_live_collection_needs_the_flag(monkeypatch, fake_aws):
    monkeypatch.delenv("AEGIS_POSTURE_LIVE", raising=False)
    with pytest.raises(sources.PostureSourceError):
        sources.collect_aws_cspm()


def test_collected_bundle_scans_and_uses_only_read_calls(monkeypatch, fake_aws):
    calls, regions = fake_aws
    monkeypatch.setenv("AEGIS_POSTURE_LIVE", "1")
    b = sources.collect_aws_cspm()
    assert cspm.coverage_gaps(b) == []
    ids = {f.id for f in cspm.scan(b)}
    assert {"CSPM-S3-PUBLIC-BUCKET", "CSPM-SG-DB-PORT-OPEN", "CSPM-EC2-IMDSV1", "CSPM-KMS-NO-ROTATION",
            "CSPM-GUARDDUTY-OFF", "CSPM-NO-PASSWORD-POLICY", "CSPM-EBS-DEFAULT-ENCRYPTION-OFF"} <= ids
    assert "CSPM-CLOUDTRAIL-NO-MULTIREGION" not in ids  # shadow trail from us-east-1 counted
    assert "us-east-1" in regions                       # its status read from its home region
    ops = {c.split(".", 1)[1].split(":")[-1] for c in calls}
    assert all(op.startswith(("get_", "list_", "describe_")) for op in ops), ops


def test_scp_deny_drops_one_section_not_the_scan(monkeypatch, fake_aws):
    """Seen on a real AWS Organizations account: an SCP explicitly denies guardduty:ListDetectors.
    The rest of the account must still be scanned, and GuardDuty reported as not checked, not clean."""
    monkeypatch.setenv("AEGIS_POSTURE_LIVE", "1")
    deny = _Err("AccessDeniedException")
    deny.response["Error"]["Message"] = "... with an explicit deny in a service control policy"
    monkeypatch.setattr(FakeAWS, "_guardduty_list_detectors", lambda self: (_ for _ in ()).throw(deny))
    b = sources.collect_aws_cspm()
    assert "guardduty_detectors" not in b and "service control policy" in b["collection_errors"]["guardduty_detectors"]
    ids = {f.id for f in cspm.scan(b)}
    assert "CSPM-GUARDDUTY-OFF" not in ids                       # unknown is not "off"
    assert {"CSPM-S3-PUBLIC-BUCKET", "CSPM-SG-DB-PORT-OPEN"} <= ids  # everything else still scanned
    (gap,) = cspm.coverage_gaps(b)
    assert gap.startswith("guardduty_detectors (access denied") and "AccessDeniedException" in gap


def test_denied_bucket_call_drops_the_s3_section(monkeypatch, fake_aws):
    monkeypatch.setenv("AEGIS_POSTURE_LIVE", "1")
    monkeypatch.setattr(FakeAWS, "_s3_get_bucket_policy_status", lambda self, **_: (_ for _ in ()).throw(_Err("AccessDenied")))
    b = sources.collect_aws_cspm()
    assert "buckets" not in b and "buckets" in b["collection_errors"]
    assert "CSPM-S3-PUBLIC-BUCKET" not in {f.id for f in cspm.scan(b)}


def test_non_aws_errors_still_stop_the_collection(monkeypatch, fake_aws):
    monkeypatch.setenv("AEGIS_POSTURE_LIVE", "1")
    monkeypatch.setattr(FakeAWS, "_kms_describe_key", lambda self, **_: (_ for _ in ()).throw(KeyError("bug")))
    with pytest.raises(KeyError):
        sources.collect_aws_cspm()


def test_cli_reports_why_a_section_was_skipped(tmp_path, capsys):
    p = tmp_path / "b.json"
    p.write_text(json.dumps({"account_id": "1", "collection_errors": {"guardduty_detectors": "AccessDeniedException: SCP"}}))
    assert cli(["cspm", "--bundle", str(p)]) == 0
    assert "guardduty_detectors (access denied or failed: AccessDeniedException: SCP)" in capsys.readouterr().out


def test_export_runs_without_the_flag_and_cli_scans_it(monkeypatch, fake_aws, tmp_path, capsys):
    monkeypatch.delenv("AEGIS_POSTURE_LIVE", raising=False)
    out = tmp_path / "bundle.json"
    assert cli(["export-aws", "--out", str(out)]) == 0
    assert "account 123456789012" in capsys.readouterr().out
    assert cli(["cspm", "--bundle", str(out), "--json", "--fail-on", "critical"]) == 1
    rep = json.loads(capsys.readouterr().out)
    assert rep["scan"] == "cspm" and rep["summary"]["critical"] >= 2 and rep["notes"] == []


def test_cli_reports_gaps_and_bad_input(tmp_path, capsys):
    p = tmp_path / "b.json"
    p.write_text(json.dumps({"account_id": "1", "buckets": []}))
    assert cli(["cspm", "--bundle", str(p)]) == 0
    assert "not in bundle, not checked" in capsys.readouterr().out
    p.write_text("[]")
    assert cli(["cspm", "--bundle", str(p)]) == 2
    assert cli(["cspm"]) == 2


def test_sample_bundle_is_not_mutated_by_scan(bundle):
    before = copy.deepcopy(bundle)
    cspm.scan(bundle)
    assert bundle == before
