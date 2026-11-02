"""CSPM — standing cloud misconfigurations in an AWS account (one region + the global services).

The runtime ``cloud_controlplane`` agent flags the *change* that opens a bucket or a security group.
This flags the bucket that has been public since 2019 and the database port that was opened before
AEGIS was installed.

Input is one JSON bundle (see ``BUNDLE_KEYS``), produced either by the bank with
``python -m aegis.posture export-aws`` under its own read-only credentials, or collected live by AEGIS
when ``AEGIS_POSTURE_LIVE=1``. Every key is optional: a missing section is skipped and reported in
``coverage_gaps``, never treated as "clean".
"""

from __future__ import annotations

from typing import Any

from .base import PostureFinding, sort_findings

CIS = "CIS AWS Foundations v2.0"

BUNDLE_KEYS = (
    "account_public_access_block",  # s3control get-public-access-block -> PublicAccessBlockConfiguration
    "buckets",                      # [{Name, PublicAccessBlock, PolicyStatus, Acl, Encryption, Versioning, Logging}]
    "security_groups",              # ec2 describe-security-groups -> SecurityGroups
    "instances",                    # ec2 describe-instances -> flattened Instances
    "volumes",                      # ec2 describe-volumes -> Volumes
    "ebs_encryption_by_default",    # ec2 get-ebs-encryption-by-default -> bool
    "db_instances",                 # rds describe-db-instances -> DBInstances
    "trails",                       # cloudtrail describe-trails + get-trail-status, merged per trail
    "kms_keys",                     # [{KeyId, KeyManager, KeyState, KeyRotationEnabled}]
    "vpcs",                         # [{VpcId, IsDefault, FlowLogs: [..]}]
    "guardduty_detectors",          # [{DetectorId, Status}]
    "config_recorders",             # [{name, recording}]
    "password_policy",              # iam get-account-password-policy -> PasswordPolicy (null = none set)
)

ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
DATA_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 1521: "Oracle", 27017: "MongoDB",
              6379: "Redis", 9200: "Elasticsearch", 5601: "Kibana", 11211: "Memcached", 2375: "Docker API"}
PUBLIC_GRANTEES = ("http://acs.amazonaws.com/groups/global/AllUsers",
                   "http://acs.amazonaws.com/groups/global/AuthenticatedUsers")
_BPA = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def _f(**kw: Any) -> PostureFinding:
    kw.setdefault("confidence", 0.95)
    kw.setdefault("category", "misconfig")
    return PostureFinding(scanner="cspm", **kw)


def _bpa_on(cfg: dict | None) -> bool:
    return bool(cfg) and all(cfg.get(k) for k in _BPA)


def _open_ranges(perm: dict) -> list[str]:
    v4 = [r.get("CidrIp") for r in perm.get("IpRanges", []) if r.get("CidrIp") == "0.0.0.0/0"]
    v6 = [r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") == "::/0"]
    return v4 + v6


# protocols whose rules carry port numbers; ICMP / ICMPv6 / GRE / ESP rules open no TCP or UDP port
_PORT_PROTOCOLS = {"-1", "tcp", "udp", "6", "17", "all"}


def carries_ports(perm: dict) -> bool:
    """True when the rule can open a TCP/UDP port. An ICMP rule's FromPort/ToPort are the ICMP type and
    code (-1 = all types), not ports — reading them as "all ports" turned an open ping into a critical
    any-any finding and made every TCP port on the host look internet-facing."""
    return str(perm.get("IpProtocol", "-1")).lower() in _PORT_PROTOCOLS


def _ports(perm: dict) -> tuple[int, int] | None:
    """(from, to) for a port-bearing rule; None means every port. Call ``carries_ports`` first."""
    if str(perm.get("IpProtocol")).lower() in ("-1", "all"):
        return None
    lo, hi = perm.get("FromPort"), perm.get("ToPort")
    if lo is None or hi is None or (lo, hi) in ((-1, -1), (0, 65535)):
        return None
    return int(lo), int(hi)


def _name(tags: list | None, default: str) -> str:
    for t in tags or []:
        if t.get("Key") == "Name" and t.get("Value"):
            return f"{t['Value']} ({default})"
    return default


def scan(bundle: dict) -> list[PostureFinding]:
    out: list[PostureFinding] = []
    acct = bundle.get("account_id", "?")

    # ---- S3 -------------------------------------------------------------------------------------
    acct_bpa = bundle.get("account_public_access_block")
    if "account_public_access_block" in bundle and not _bpa_on(acct_bpa):
        out.append(_f(id="CSPM-S3-ACCOUNT-BPA-OFF", severity="high", resource=f"arn:aws:s3:::*@{acct}",
                      affected_component=f"account {acct}", control=f"{CIS} — S3 Block Public Access",
                      evidence="account-level S3 Block Public Access is not fully enabled",
                      recommended_remediation="Turn on all four account-level Block Public Access settings; exempt specific buckets only by exception"))
    for b in bundle.get("buckets", []):
        name = b.get("Name", "?")
        arn = f"arn:aws:s3:::{name}"
        public_policy = bool((b.get("PolicyStatus") or {}).get("IsPublic"))
        public_acl = [g for g in (b.get("Acl") or {}).get("Grants", [])
                      if (g.get("Grantee") or {}).get("URI") in PUBLIC_GRANTEES]
        shielded = _bpa_on(acct_bpa) or _bpa_on(b.get("PublicAccessBlock"))
        if (public_policy or public_acl) and not shielded:
            how = " and ".join(x for x in ("bucket policy" if public_policy else "", "ACL grant to everyone" if public_acl else "") if x)
            out.append(_f(id="CSPM-S3-PUBLIC-BUCKET", severity="critical", resource=arn, affected_component=name,
                          control=f"{CIS} — S3 Block Public Access",
                          evidence=f"bucket is publicly readable via {how}, and Block Public Access does not stop it",
                          recommended_remediation="Enable Block Public Access on the bucket; serve public content through CloudFront with origin access control"))
        if "Encryption" in b and not b.get("Encryption"):
            out.append(_f(id="CSPM-S3-NO-DEFAULT-ENCRYPTION", severity="low", resource=arn, affected_component=name,
                          evidence="no default encryption configuration on the bucket",
                          recommended_remediation="Set default encryption to SSE-KMS with a customer-managed key for regulated data"))
        if "Versioning" in b and (b.get("Versioning") or {}).get("Status") != "Enabled":
            out.append(_f(id="CSPM-S3-NO-VERSIONING", severity="low", resource=arn, affected_component=name,
                          evidence="versioning is off: a ransomware overwrite or delete is unrecoverable",
                          recommended_remediation="Enable versioning (and MFA delete / Object Lock for backups)"))
        if "Logging" in b and not b.get("Logging"):
            out.append(_f(id="CSPM-S3-NO-ACCESS-LOGGING", severity="low", resource=arn, affected_component=name,
                          evidence="server access logging is off",
                          recommended_remediation="Enable server access logging or CloudTrail S3 data events for this bucket"))

    # ---- network --------------------------------------------------------------------------------
    for sg in bundle.get("security_groups", []):
        gid = sg.get("GroupId", "?")
        label = f"{sg.get('GroupName', gid)} ({gid})"
        arn = f"arn:aws:ec2:{bundle.get('region', '*')}:{acct}:security-group/{gid}"
        if sg.get("GroupName") == "default":
            n_in, n_out = len(sg.get("IpPermissions", [])), len(sg.get("IpPermissionsEgress", []))
            if n_in or n_out:
                out.append(_f(id="CSPM-SG-DEFAULT-NOT-EMPTY", severity="medium", resource=arn, affected_component=label,
                              control=f"{CIS} 5.4",
                              evidence=f"the VPC default security group has {n_in} inbound / {n_out} outbound rule(s)",
                              recommended_remediation="Remove all rules from default security groups; use purpose-built groups"))
        for perm in sg.get("IpPermissions", []):
            srcs = _open_ranges(perm)
            if not srcs or not carries_ports(perm):
                continue
            pr = _ports(perm)
            src = ", ".join(srcs)
            if pr is None:
                out.append(_f(id="CSPM-SG-ALL-PORTS-OPEN", severity="critical", resource=arn, affected_component=label,
                              control=f"{CIS} 5.2", evidence=f"all ports open to {src}",
                              recommended_remediation="Remove the any-any rule; allow only the ports the workload serves, from known sources"))
                continue
            lo, hi = pr
            data = [f"{n} {p}" for p, n in DATA_PORTS.items() if lo <= p <= hi]
            admin = [f"{n} {p}" for p, n in ADMIN_PORTS.items() if lo <= p <= hi]
            if data:
                out.append(_f(id="CSPM-SG-DB-PORT-OPEN", severity="critical", resource=arn, affected_component=label,
                              evidence=f"data-store port(s) open to {src}: {', '.join(data)}",
                              recommended_remediation="Databases must never face the internet: restrict to the application tier's security group"))
            if admin:
                out.append(_f(id="CSPM-SG-ADMIN-PORT-OPEN", severity="high", resource=arn, affected_component=label,
                              control=f"{CIS} 5.2" if any(":" not in s for s in srcs) else f"{CIS} 5.3",
                              evidence=f"remote-admin port(s) open to {src}: {', '.join(admin)}",
                              recommended_remediation="Close SSH/RDP to the internet; use SSM Session Manager or a bastion behind VPN"))

    for v in bundle.get("vpcs", []):
        if "FlowLogs" in v and not v.get("FlowLogs"):
            vid = v.get("VpcId", "?")
            out.append(_f(id="CSPM-VPC-NO-FLOW-LOGS", severity="medium", resource=vid, affected_component=vid,
                          control=f"{CIS} — VPC flow logging",
                          evidence="VPC has no flow logs: network forensics after an incident is impossible",
                          recommended_remediation="Enable VPC flow logs (at least REJECT) to CloudWatch Logs or S3"))

    # ---- compute & storage ----------------------------------------------------------------------
    for i in bundle.get("instances", []):
        if (i.get("State") or {}).get("Name") == "terminated":
            continue
        iid = i.get("InstanceId", "?")
        if (i.get("MetadataOptions") or {}).get("HttpTokens") == "optional":
            public = bool(i.get("PublicIpAddress"))
            out.append(_f(id="CSPM-EC2-IMDSV1", severity="high" if public else "medium", resource=iid,
                          affected_component=_name(i.get("Tags"), iid), control=f"{CIS} 5.6",
                          evidence="instance metadata allows IMDSv1" + (" on an internet-facing instance (SSRF → role credentials)" if public else ""),
                          recommended_remediation="Require IMDSv2 (HttpTokens=required); set the account default for new instances"))
    if bundle.get("ebs_encryption_by_default") is False:
        out.append(_f(id="CSPM-EBS-DEFAULT-ENCRYPTION-OFF", severity="medium", resource=f"ebs-default@{acct}",
                      affected_component=f"account {acct} / {bundle.get('region', '?')}", control=f"{CIS} 2.2.1",
                      evidence="EBS encryption by default is off in this region",
                      recommended_remediation="Enable EBS encryption by default (aws ec2 enable-ebs-encryption-by-default)"))
    for vol in bundle.get("volumes", []):
        if vol.get("Encrypted") is False:
            vid = vol.get("VolumeId", "?")
            out.append(_f(id="CSPM-EBS-UNENCRYPTED", severity="medium", resource=vid, affected_component=_name(vol.get("Tags"), vid),
                          evidence="EBS volume is not encrypted",
                          recommended_remediation="Snapshot, copy the snapshot with encryption, and replace the volume"))

    # ---- databases ------------------------------------------------------------------------------
    for db in bundle.get("db_instances", []):
        did = db.get("DBInstanceIdentifier", "?")
        arn = db.get("DBInstanceArn", did)
        if db.get("PubliclyAccessible"):
            out.append(_f(id="CSPM-RDS-PUBLIC", severity="critical", resource=arn, affected_component=did, control=f"{CIS} 2.3.3",
                          evidence=f"{db.get('Engine', 'RDS')} instance is publicly accessible",
                          recommended_remediation="Set PubliclyAccessible=false and place the instance in private subnets"))
        if db.get("StorageEncrypted") is False:
            out.append(_f(id="CSPM-RDS-UNENCRYPTED", severity="high", resource=arn, affected_component=did, control=f"{CIS} 2.3.1",
                          evidence="database storage is not encrypted at rest",
                          recommended_remediation="Restore from an encrypted snapshot copy; encryption cannot be enabled in place"))
        if db.get("BackupRetentionPeriod") == 0:
            out.append(_f(id="CSPM-RDS-NO-BACKUPS", severity="medium", resource=arn, affected_component=did,
                          evidence="automated backups are disabled (retention 0 days)",
                          recommended_remediation="Set backup retention to at least 7 days (RBI BCP expects tested restores)"))
        if db.get("DeletionProtection") is False:
            out.append(_f(id="CSPM-RDS-NO-DELETION-PROTECTION", severity="low", resource=arn, affected_component=did,
                          evidence="deletion protection is off",
                          recommended_remediation="Enable deletion protection on production databases"))

    # ---- logging & detection --------------------------------------------------------------------
    if "trails" in bundle:
        trails = bundle.get("trails") or []
        live_multi = [t for t in trails if t.get("IsMultiRegionTrail") and t.get("IsLogging")]
        if not live_multi:
            out.append(_f(id="CSPM-CLOUDTRAIL-NO-MULTIREGION", severity="critical", resource=f"cloudtrail@{acct}",
                          affected_component=f"account {acct}", control=f"{CIS} 3.1",
                          evidence="no multi-region CloudTrail trail is logging: control-plane activity is unrecorded",
                          recommended_remediation="Create a multi-region trail (ideally an organization trail) delivering to a locked-down log bucket"))
        for t in trails:
            tn = t.get("Name", "?")
            tarn = t.get("TrailARN", tn)
            if t.get("IsLogging") is False:
                out.append(_f(id="CSPM-CLOUDTRAIL-STOPPED", severity="high", resource=tarn, affected_component=tn,
                              evidence="trail exists but logging is stopped",
                              recommended_remediation="Restart logging and find out who stopped it (StopLogging in CloudTrail)"))
            if t.get("LogFileValidationEnabled") is False:
                out.append(_f(id="CSPM-CLOUDTRAIL-NO-VALIDATION", severity="medium", resource=tarn, affected_component=tn,
                              control=f"{CIS} 3.2", evidence="log file integrity validation is off: tampering would go unnoticed",
                              recommended_remediation="Enable log file validation on the trail"))
            if "KmsKeyId" in t and not t.get("KmsKeyId"):
                out.append(_f(id="CSPM-CLOUDTRAIL-NO-KMS", severity="low", resource=tarn, affected_component=tn,
                              evidence="trail logs are not encrypted with a customer-managed KMS key",
                              recommended_remediation="Encrypt trail delivery with a customer-managed KMS key"))
    for k in bundle.get("kms_keys", []):
        if k.get("KeyManager") == "CUSTOMER" and k.get("KeyState", "Enabled") == "Enabled" and k.get("KeyRotationEnabled") is False \
                and k.get("KeySpec", "SYMMETRIC_DEFAULT") == "SYMMETRIC_DEFAULT":
            kid = k.get("KeyId", "?")
            out.append(_f(id="CSPM-KMS-NO-ROTATION", severity="medium", resource=k.get("Arn", kid), affected_component=kid,
                          control=f"{CIS} — KMS key rotation", evidence="customer-managed symmetric key has automatic rotation off",
                          recommended_remediation="Enable automatic key rotation"))
    if "guardduty_detectors" in bundle and not any(d.get("Status") == "ENABLED" for d in bundle.get("guardduty_detectors") or []):
        out.append(_f(id="CSPM-GUARDDUTY-OFF", severity="medium", resource=f"guardduty@{acct}",
                      affected_component=f"account {acct} / {bundle.get('region', '?')}",
                      evidence="GuardDuty is not enabled in this region",
                      recommended_remediation="Enable GuardDuty in every region and forward findings to AEGIS"))
    if "config_recorders" in bundle and not any(r.get("recording") for r in bundle.get("config_recorders") or []):
        out.append(_f(id="CSPM-CONFIG-OFF", severity="medium", resource=f"config@{acct}",
                      affected_component=f"account {acct} / {bundle.get('region', '?')}", control=f"{CIS} — AWS Config",
                      evidence="AWS Config is not recording: no configuration history for audits or forensics",
                      recommended_remediation="Enable an AWS Config recorder for all resources in every region"))

    # ---- account password policy ----------------------------------------------------------------
    if "password_policy" in bundle:
        pp = bundle.get("password_policy")
        if not pp:
            out.append(_f(id="CSPM-NO-PASSWORD-POLICY", severity="medium", resource=f"iam-password-policy@{acct}",
                          affected_component=f"account {acct}", control=f"{CIS} 1.8",
                          evidence="no IAM account password policy is set (AWS defaults apply)",
                          recommended_remediation="Set a password policy: minimum length 14, reuse prevention 24"))
        else:
            if (pp.get("MinimumPasswordLength") or 0) < 14:
                out.append(_f(id="CSPM-PASSWORD-SHORT", severity="low", resource=f"iam-password-policy@{acct}",
                              affected_component=f"account {acct}", control=f"{CIS} 1.8",
                              evidence=f"minimum password length is {pp.get('MinimumPasswordLength')}",
                              recommended_remediation="Require at least 14 characters"))
            if (pp.get("PasswordReusePrevention") or 0) < 24:
                out.append(_f(id="CSPM-PASSWORD-REUSE", severity="low", resource=f"iam-password-policy@{acct}",
                              affected_component=f"account {acct}", control=f"{CIS} 1.9",
                              evidence=f"password reuse prevention remembers {pp.get('PasswordReusePrevention') or 0} passwords",
                              recommended_remediation="Prevent reuse of the last 24 passwords"))

    return sort_findings(out)


_SECTION_OF = (("CSPM-SG-", "security_groups"), ("CSPM-EC2-", "instances"), ("CSPM-EBS-DEFAULT", "ebs_encryption_by_default"),
               ("CSPM-EBS-", "volumes"), ("CSPM-S3-ACCOUNT", "account_public_access_block"), ("CSPM-S3-", "buckets"),
               ("CSPM-RDS-", "db_instances"), ("CSPM-CLOUDTRAIL-", "trails"), ("CSPM-GUARDDUTY-", "guardduty_detectors"),
               ("CSPM-CONFIG-", "config_recorders"), ("CSPM-KMS-", "kms_keys"), ("CSPM-PASSWORD-", "password_policy"),
               ("CSPM-NO-PASSWORD", "password_policy"), ("CSPM-VPC-", "vpcs"))


def section_of(finding_id: str) -> str | None:
    """The bundle section a finding comes from — so a section that was not collected this run carries its
    findings forward instead of resolving them."""
    return next((sec for pre, sec in _SECTION_OF if str(finding_id).startswith(pre)), None)


def unchecked_sections(bundle: dict) -> list[str]:
    return [k for k in BUNDLE_KEYS if k not in bundle]


def coverage_gaps(bundle: dict) -> list[str]:
    """Bundle sections that were not supplied (or that the collector was refused), so the report never
    implies 'clean' for them. A refused section names the reason, e.g. an SCP explicit deny."""
    errs = bundle.get("collection_errors") or {}
    return [f"{k} (access denied or failed: {errs[k]})" if k in errs else k for k in BUNDLE_KEYS if k not in bundle]
