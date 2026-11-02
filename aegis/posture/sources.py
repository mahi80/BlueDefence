"""Where posture scanners get their snapshot: an offline export file, or live read-only APIs.

Offline is the default and the recommended pilot mode — the bank runs its own export command and
hands AEGIS a file, so AEGIS never holds cloud credentials. Live mode is opt-in
(``AEGIS_POSTURE_LIVE=1``) and only ever calls read-only List/Get/Describe APIs.
"""

from __future__ import annotations

import base64
import csv
import io
import json
import os
import time
from pathlib import Path
from typing import Any


class PostureSourceError(RuntimeError):
    pass


def live_enabled() -> bool:
    return os.environ.get("AEGIS_POSTURE_LIVE", "").strip() == "1"


def load_json(path: str | Path) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise PostureSourceError(f"export not found: {path}") from e
    except json.JSONDecodeError as e:
        raise PostureSourceError(f"{path} is not valid JSON: {e}") from e


def parse_credential_report(raw: str | bytes) -> list[dict[str, str]]:
    """The IAM credential report is a CSV; ``aws iam get-credential-report`` returns it base64'd in
    a JSON envelope. Accept the CSV text, the base64 blob, or the whole JSON envelope."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    text = raw.strip()
    if text.startswith("{"):
        text = json.loads(text).get("Content", "")
    if not text.startswith("user,"):
        try:
            text = base64.b64decode(text).decode("utf-8")
        except Exception as e:
            raise PostureSourceError("credential report is neither CSV nor base64 CSV") from e
    return list(csv.DictReader(io.StringIO(text)))


def load_credential_report(path: str | Path) -> list[dict[str, str]]:
    try:
        return parse_credential_report(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise PostureSourceError(f"credential report not found: {path}") from e


# ---- live (opt-in) --------------------------------------------------------------------------------

def _boto3_client(service: str, *, require_flag: bool = True, **kw: Any) -> Any:
    if require_flag and not live_enabled():
        raise PostureSourceError("live posture collection is off; set AEGIS_POSTURE_LIVE=1 or pass an export file")
    try:
        import boto3
    except ImportError as e:
        raise PostureSourceError("live AWS collection needs boto3: pip install 'bluedefence[posture-aws]'") from e
    return boto3.client(service, **kw)


def live_aws_iam(wait_s: float = 30.0) -> tuple[dict, list[dict[str, str]]]:
    """Collect the same two inputs as the offline export, via read-only IAM calls.

    Needs only ``iam:GetAccountAuthorizationDetails``, ``iam:GenerateCredentialReport`` and
    ``iam:GetCredentialReport`` (the AWS-managed ``SecurityAudit`` policy covers all three).
    """
    iam = _boto3_client("iam")
    details: dict[str, list] = {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []}
    for page in iam.get_paginator("get_account_authorization_details").paginate():
        for k, acc in details.items():
            acc.extend(page.get(k, []))

    deadline = time.monotonic() + wait_s
    while iam.generate_credential_report().get("State") != "COMPLETE":
        if time.monotonic() > deadline:
            raise PostureSourceError("credential report not ready in time; retry or use an export")
        time.sleep(2)
    content = iam.get_credential_report()["Content"]
    return details, parse_credential_report(content)


def _safe(fn: Any, *a: Any, missing: tuple[str, ...] = (), default: Any = None, **kw: Any) -> Any:
    """Call a read-only AWS API; return ``default`` when the resource simply has no such config
    (e.g. NoSuchBucketPolicy). Any other error propagates so a permissions gap is not read as clean."""
    try:
        return fn(*a, **kw)
    except Exception as e:  # botocore ClientError; botocore is only importable in live mode
        code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
        if code in missing:
            return default
        raise


def collect_aws_cspm(region: str | None = None, *, require_flag: bool = True) -> dict:
    """Build the ``cspm.scan`` bundle for one region (plus S3 / IAM, which are global) with
    read-only Describe/Get/List calls. The AWS-managed ``SecurityAudit`` policy is sufficient.

    ``require_flag=False`` is used by ``export-aws``: the bank runs the export itself and hands AEGIS
    the file, so AEGIS's own live-mode switch does not apply.
    """
    c = lambda svc: _boto3_client(svc, require_flag=require_flag, **({"region_name": region} if region else {}))
    sts, s3, s3c, ec2, rds, ct, kms, gd, cfg, iam, elb, waf = (c(s) for s in
        ("sts", "s3", "s3control", "ec2", "rds", "cloudtrail", "kms", "guardduty", "config", "iam", "elbv2", "wafv2"))
    acct = sts.get_caller_identity()["Account"]  # must succeed: no identity, no scan
    region = ec2.meta.region_name
    b: dict[str, Any] = {"account_id": acct, "region": region}
    errors: dict[str, str] = {}
    page = lambda cl, op, key, **kw: [x for p in cl.get_paginator(op).paginate(**kw) for x in p.get(key, [])]

    def section(key: str, fn: Any) -> None:
        """Collect one bundle section. An AWS API refusal (an SCP explicit deny, a missing permission)
        drops only that section and records why, so the report says "not checked: access denied"
        instead of the whole scan failing. Anything that is not an AWS API error still propagates."""
        try:
            b[key] = fn()
        except Exception as e:
            err = getattr(e, "response", None)
            if not isinstance(err, dict) or "Error" not in err:
                raise
            errors[key] = f"{err['Error'].get('Code', 'Error')}: {str(err['Error'].get('Message', ''))[:200]}"

    def buckets() -> list:
        out = []
        nf = ("NoSuchPublicAccessBlockConfiguration", "NoSuchBucketPolicy", "ServerSideEncryptionConfigurationNotFoundError")
        for bk in s3.list_buckets().get("Buckets", []):
            n = bk["Name"]
            out.append({
                "Name": n,
                "PublicAccessBlock": (_safe(s3.get_public_access_block, Bucket=n, missing=nf, default={}) or {}).get("PublicAccessBlockConfiguration"),
                "PolicyStatus": (_safe(s3.get_bucket_policy_status, Bucket=n, missing=nf, default={}) or {}).get("PolicyStatus"),
                "Acl": {"Grants": s3.get_bucket_acl(Bucket=n).get("Grants", [])},
                "Encryption": (_safe(s3.get_bucket_encryption, Bucket=n, missing=nf, default={}) or {}).get("ServerSideEncryptionConfiguration"),
                "Versioning": {"Status": s3.get_bucket_versioning(Bucket=n).get("Status")},
                "Logging": s3.get_bucket_logging(Bucket=n).get("LoggingEnabled"),
            })
        return out

    def vpcs() -> list:
        flows = {f.get("ResourceId") for f in page(ec2, "describe_flow_logs", "FlowLogs")}
        return [{"VpcId": v["VpcId"], "IsDefault": v.get("IsDefault"), "FlowLogs": [v["VpcId"]] if v["VpcId"] in flows else []}
                for v in page(ec2, "describe_vpcs", "Vpcs")]

    def trails() -> list:
        # Include shadow trails: a multi-region trail homed in another region still covers this one.
        # Its status has to be read from its home region.
        out, home_clients = [], {region: ct}
        for t in ct.describe_trails(includeShadowTrails=True).get("trailList", []):
            home = t.get("HomeRegion") or region
            if home not in home_clients:
                home_clients[home] = _boto3_client("cloudtrail", require_flag=require_flag, region_name=home)
            st = home_clients[home].get_trail_status(Name=t["TrailARN"])
            out.append({**t, "IsLogging": st.get("IsLogging"), "KmsKeyId": t.get("KmsKeyId")})
        return out

    def kms_keys() -> list:
        out = []
        for k in page(kms, "list_keys", "Keys"):
            meta = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
            if meta.get("KeyManager") == "CUSTOMER" and meta.get("KeyState") == "Enabled":
                rot = _safe(kms.get_key_rotation_status, KeyId=k["KeyId"], missing=("UnsupportedOperationException",), default={})
                meta["KeyRotationEnabled"] = (rot or {}).get("KeyRotationEnabled")
            out.append({x: meta.get(x) for x in ("KeyId", "Arn", "KeyManager", "KeyState", "KeySpec", "KeyRotationEnabled")})
        return out

    def recorders() -> list:
        st = {s["name"]: s.get("recording") for s in cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])}
        return [{"name": n, "recording": r} for n, r in st.items()]

    section("account_public_access_block", lambda: _safe(s3c.get_public_access_block, AccountId=acct,
            missing=("NoSuchPublicAccessBlockConfiguration",), default={}).get("PublicAccessBlockConfiguration"))
    section("buckets", buckets)
    section("security_groups", lambda: page(ec2, "describe_security_groups", "SecurityGroups"))
    section("instances", lambda: [i for r in page(ec2, "describe_instances", "Reservations") for i in r.get("Instances", [])])
    section("volumes", lambda: page(ec2, "describe_volumes", "Volumes"))
    section("ebs_encryption_by_default", lambda: ec2.get_ebs_encryption_by_default().get("EbsEncryptionByDefault"))
    section("vpcs", vpcs)
    section("db_instances", lambda: page(rds, "describe_db_instances", "DBInstances"))
    section("trails", trails)
    section("kms_keys", kms_keys)
    section("guardduty_detectors", lambda: [{"DetectorId": d, "Status": gd.get_detector(DetectorId=d).get("Status")}
                                            for d in gd.list_detectors().get("DetectorIds", [])])
    section("config_recorders", recorders)
    def load_balancers() -> list:
        """ALB / NLB with listeners, targets and any AWS WAF web ACL — the exposure engine's internet paths."""
        out = []
        for lb in page(elb, "describe_load_balancers", "LoadBalancers"):
            arn = lb["LoadBalancerArn"]
            listeners = [{"Port": x.get("Port"), "Protocol": x.get("Protocol")}
                         for x in page(elb, "describe_listeners", "Listeners", LoadBalancerArn=arn)]
            targets = []
            for tg in page(elb, "describe_target_groups", "TargetGroups", LoadBalancerArn=arn):
                for th in elb.describe_target_health(TargetGroupArn=tg["TargetGroupArn"]).get("TargetHealthDescriptions", []):
                    t = th.get("Target") or {}
                    targets.append({"Id": t.get("Id"), "Port": t.get("Port") or tg.get("Port")})
            acl = None
            if lb.get("Type") == "application":
                try:
                    acl = ((waf.get_web_acl_for_resource(ResourceArn=arn) or {}).get("WebACL") or {}).get("Name")
                except Exception as e:  # noqa: BLE001 - unknown WAF state reads as "no WAF": more findings, never fewer
                    errors.setdefault("load_balancer_waf", str(getattr(e, "response", {}).get("Error", {}).get("Code", e))[:200])
            out.append({"LoadBalancerName": lb.get("LoadBalancerName"), "LoadBalancerArn": arn, "Scheme": lb.get("Scheme"),
                        "Type": lb.get("Type"), "SecurityGroups": lb.get("SecurityGroups") or [],
                        "listeners": listeners, "targets": targets, "web_acl": acl})
        return out

    section("load_balancers", load_balancers)
    section("password_policy", lambda: (_safe(iam.get_account_password_policy, missing=("NoSuchEntity",), default={}) or {}).get("PasswordPolicy"))
    if errors:
        b["collection_errors"] = errors
    return b


def collect_k8s(context: str | None = None, *, kubectl: str = "kubectl", timeout_s: float = 120.0) -> dict:
    """Read the cluster with the same read-only ``kubectl get`` the bank would run for an offline
    export. Secrets are never requested. Uses the caller's kubeconfig; a read-only ClusterRole
    (get/list on the kinds in ``k8s_posture.EXPORT_KINDS``) is sufficient."""
    import shutil
    import subprocess

    from .k8s_posture import EXPORT_KINDS

    if not live_enabled():
        raise PostureSourceError("live posture collection is off; set AEGIS_POSTURE_LIVE=1 or pass --export FILE")
    if shutil.which(kubectl) is None:
        raise PostureSourceError(f"live Kubernetes collection needs {kubectl} on PATH")
    cmd = [kubectl, "get", ",".join(EXPORT_KINDS), "--all-namespaces", "-o", "json"]
    if context:
        cmd += ["--context", context]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s, check=False)
    except subprocess.TimeoutExpired as e:
        raise PostureSourceError(f"kubectl timed out after {timeout_s:.0f}s") from e
    if r.returncode != 0:
        raise PostureSourceError(f"kubectl failed: {r.stderr.strip()[:300]}")
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError as e:
        raise PostureSourceError("kubectl did not return JSON") from e


def _az_runner(az: str, subscription: str | None, timeout_s: float) -> Any:
    import shutil
    import subprocess

    if shutil.which(az) is None:
        raise PostureSourceError(f"Azure collection needs the {az} CLI on PATH (and `az login` as a Reader + Security Reader)")

    def run(*args: str) -> Any:
        cmd = [az, *args, "--only-show-errors", "-o", "json"]
        if subscription:
            cmd += ["--subscription", subscription]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s, check=False)
        except subprocess.TimeoutExpired as e:
            raise PostureSourceError(f"az {' '.join(args[:3])} timed out") from e
        if r.returncode != 0:
            raise PostureSourceError(f"az {' '.join(args[:3])} failed: {r.stderr.strip()[:300]}")
        try:
            out = json.loads(r.stdout or "null")
        except json.JSONDecodeError as e:
            raise PostureSourceError(f"az {' '.join(args[:3])} did not return JSON") from e
        return out.get("value", out) if isinstance(out, dict) and "value" in out else out

    return run


def collect_azure(subscription: str | None = None, *, require_flag: bool = True, az: str = "az",
                  timeout_s: float = 120.0) -> dict:
    """Build the ``azure_cspm.scan`` bundle for one subscription with read-only ``az`` calls
    (list / show only). ``require_flag=False`` is used by ``export-azure``, which the bank runs itself."""
    if require_flag and not live_enabled():
        raise PostureSourceError("live posture collection is off; set AEGIS_POSTURE_LIVE=1 or pass --bundle FILE")
    run = _az_runner(az, subscription, timeout_s)

    acct = run("account", "show")  # must succeed: no subscription, no scan
    b: dict[str, Any] = {"subscription": {"id": acct.get("id"), "name": acct.get("name"), "tenant": acct.get("tenantId")}}
    errors: dict[str, str] = {}

    def section(key: str, fn: Any) -> None:
        """One bundle section. An az refusal (missing role, Azure Policy deny, provider not registered)
        drops only that section and records why; the report shows it as not checked, never clean."""
        try:
            b[key] = fn()
        except PostureSourceError as e:
            errors[key] = str(e)[:300]

    def sql() -> list:
        servers = run("sql", "server", "list")
        for s in servers:
            rg, nm = s.get("resourceGroup"), s.get("name")
            s["firewall_rules"] = run("sql", "server", "firewall-rule", "list", "--resource-group", rg, "--server", nm)
            s["audit_state"] = (run("sql", "server", "audit-policy", "show", "--resource-group", rg, "--name", nm) or {}).get("state")
        return servers

    def flexible(svc: str) -> list:
        servers = run(svc, "flexible-server", "list")
        for s in servers:
            s["firewall_rules"] = run(svc, "flexible-server", "firewall-rule", "list",
                                      "--resource-group", s.get("resourceGroup"), "--name", s.get("name"))
        return servers

    section("storage_accounts", lambda: run("storage", "account", "list"))
    section("network_security_groups", lambda: run("network", "nsg", "list"))
    section("sql_servers", sql)
    section("postgres_servers", lambda: flexible("postgres"))
    section("mysql_servers", lambda: flexible("mysql"))
    section("key_vaults", lambda: [run("keyvault", "show", "--name", v.get("name"), "--resource-group", v.get("resourceGroup"))
                                   for v in run("keyvault", "list")])
    section("aks_clusters", lambda: run("aks", "list"))
    section("defender_plans", lambda: run("security", "pricing", "list"))
    section("activity_log_diagnostics", lambda: run("monitor", "diagnostic-settings", "subscription", "list"))
    section("role_assignments", lambda: run("role", "assignment", "list", "--all"))
    section("custom_roles", lambda: run("role", "definition", "list", "--custom-role-only", "true"))
    # reachability inputs for the exposure engine (not CSPM checks themselves)
    section("virtual_machines", lambda: run("vm", "list", "--show-details"))
    section("network_interfaces", lambda: run("network", "nic", "list"))
    section("virtual_networks", lambda: run("network", "vnet", "list"))
    section("load_balancers", lambda: run("network", "lb", "list"))
    if errors:
        b["collection_errors"] = errors
    return b
