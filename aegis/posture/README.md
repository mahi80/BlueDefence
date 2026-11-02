# Posture scanning

Runtime agents judge events as they happen. Posture scanners judge a **snapshot**: every identity,
bucket, cluster and template as it stands, so a misconfiguration that predates AEGIS is still found.

| Scanner | Status | Input (offline) | Live mode |
|---|---|---|---|
| IAM review | ✅ | `aws iam get-account-authorization-details` + `aws iam get-credential-report` | boto3, `SecurityAudit` policy |
| CSPM (AWS) | ✅ | `python -m aegis.posture export-aws --out bundle.json` (run by the bank) | boto3, `SecurityAudit` policy |
| CSPM (Azure) | ✅ | `python -m aegis.posture export-azure --out azure.json` (run by the bank, `az login`) | read-only `az` (Reader + Security Reader) |
| Kubernetes posture | ✅ | `kubectl get <kinds> -A -o json` (no secrets) | read-only `kubectl get` |
| Policy-as-code (IaC) | ✅ | `terraform show -json plan.out` + Kubernetes YAML | — (pre-deploy gate) |

**Offline is the default and the recommended pilot mode.** The bank runs the export with its own
credentials and hands AEGIS the files, so AEGIS never holds cloud credentials. **Live mode** is opt-in:
`AEGIS_POSTURE_LIVE=1`, `pip install 'bluedefence[posture-aws]'`, and only read-only API calls.

Findings are `PostureFinding` — a `vuln_discovery.Finding` plus the benchmark `control` it maps to —
so they share the patch / HITL queue with every other vulnerability finding.

## IAM review

```bash
aws iam get-account-authorization-details > auth.json
aws iam generate-credential-report && aws iam get-credential-report > report.json
python -m aegis.posture iam --auth-details auth.json --credential-report report.json \
    --trusted-account 222222222222 --fail-on critical
```

| Check | Severity | CIS AWS v2.0 |
|---|---|---|
| Root account has an active access key | critical | 1.4 |
| Root account has no MFA | critical | 1.5 |
| Role trust allows `Principal "*"` (no Condition) | critical (high with Condition) | — |
| Console user without MFA | high | 1.10 |
| User holds full admin (direct, group or inline) | high | — |
| Customer policy / role inline policy allows `*` on `*` | high | 1.16 |
| Policy allows a privilege-escalation action (`iam:PassRole`, `iam:CreatePolicyVersion`, …) on `*` | high | — |
| Role assumable from an unlisted external account without `sts:ExternalId` | high (medium with it) | — |
| Access key older than 90 days | medium | 1.14 |
| Access key or console password unused for 45+ days | medium | 1.12 |
| Policies attached directly to a user | low | 1.15 |
| User has two active access keys | low | 1.13 |

Without the credential report the MFA, root, key-age and inactivity checks are skipped, and the
output says so. Try it on the bundled sample: `python -m aegis.posture iam --auth-details
aegis/posture/samples/aws_iam_auth_details.json --credential-report aegis/posture/samples/aws_credential_report.csv`.

## CSPM

```bash
# at the bank, with its own read-only credentials (SecurityAudit), one region at a time:
python -m aegis.posture export-aws --region ap-south-1 --out bundle-aps1.json
# in AEGIS:
python -m aegis.posture cspm --bundle bundle-aps1.json --fail-on critical
```

`export-aws` is the same collector as live mode, so an export and a live scan see identical data.
It only calls `Get*` / `List*` / `Describe*`; a permissions error stops the export instead of
quietly reading as "clean". Any bundle section that is missing is listed under `notes` as not
checked. Multi-region trails homed in another region are counted (their status is read there).

| Area | Check | Severity | CIS AWS v2.0 |
|---|---|---|---|
| S3 | Bucket public via policy or ACL, not stopped by Block Public Access | critical | S3 BPA |
| S3 | Account-level Block Public Access not fully on | high | S3 BPA |
| S3 | No default encryption / versioning off / access logging off | low | — |
| Network | Security group open to the internet on all ports | critical | 5.2 |
| Network | Data-store port (MySQL, Postgres, SQL Server, Oracle, Mongo, Redis, Elasticsearch, …) open to the internet | critical | — |
| Network | SSH / RDP open to the internet | high | 5.2 / 5.3 |
| Network | Default security group has rules | medium | 5.4 |
| Network | VPC without flow logs | medium | — |
| Compute | IMDSv1 allowed (high on a public instance: SSRF → role credentials) | high / medium | 5.6 |
| Storage | EBS encryption-by-default off; unencrypted volume | medium | 2.2.1 |
| Databases | RDS publicly accessible | critical | 2.3.3 |
| Databases | RDS storage unencrypted | high | 2.3.1 |
| Databases | Automated backups off / deletion protection off | medium / low | — |
| Logging | No logging multi-region CloudTrail | critical | 3.1 |
| Logging | Trail stopped / log validation off / no CMK | high / medium / low | — / 3.2 / — |
| Logging | GuardDuty off, AWS Config not recording | medium | — |
| Keys | Customer-managed symmetric KMS key without rotation | medium | — |
| Identity | No password policy / length < 14 / reuse < 24 | medium / low / low | 1.8 / 1.9 |

## Azure posture

```bash
# at the bank, signed in with `az login` as Reader + Security Reader on the subscription:
python -m aegis.posture export-azure --subscription bank-prod-centralindia --out azure.json
# in AEGIS:
python -m aegis.posture azure --bundle azure.json --fail-on critical
# or live (AEGIS_POSTURE_LIVE=1, az on PATH and signed in):
python -m aegis.posture azure --live --subscription bank-prod-centralindia
```

The collector only runs `az … list` / `az … show`; a permission error stops the export instead of
reading as clean. **Entra ID (MFA, guests, conditional access) needs Microsoft Graph and is not
collected** — every report lists it as not checked. In `posture.yaml` use `type: azure` with `bundle:` or
`live: true` + `subscription:`. `azurerm_*` Terraform resources go through the same rules in the
policy-as-code gate (storage accounts, NSGs and rules, SQL / PostgreSQL / MySQL firewall rules, Key Vault,
AKS, custom role definitions, user role assignments, Defender pricing).

| Area | Check | Severity |
|---|---|---|
| Network | NSG inbound from Internet/`*`: all ports / data-store port / RDP-SSH | critical / critical / high |
| Databases | SQL / PostgreSQL / MySQL public with a firewall rule covering the internet | critical |
| Databases | 'Allow Azure services' rule; TLS < 1.2; SQL auditing off | medium |
| Storage | anonymous blob access; HTTPS-only off | high |
| Storage | TLS < 1.2; firewall default Allow; shared-key auth allowed | medium / medium / low |
| Key Vault | no purge protection; reachable from any network; legacy access policies | medium / medium / low |
| AKS | RBAC off; public API with no authorized ranges; local accounts; no network policy | critical / high / medium / medium |
| Identity | user with standing Owner / Contributor / UAA on the subscription (use PIM); custom role with `*` at subscription scope | high |
| Logging | subscription Activity Log not exported | high |
| Detection | Defender for Cloud plans on Free | medium |

## Kubernetes posture

```bash
# at the bank (read-only ClusterRole with get/list on these kinds is enough; secrets are NOT exported):
kubectl get namespaces,pods,deployments,daemonsets,statefulsets,replicasets,jobs,cronjobs,serviceaccounts,roles,clusterroles,rolebindings,clusterrolebindings,networkpolicies -A -o json > cluster.json
# in AEGIS:
python -m aegis.posture k8s --export cluster.json --fail-on critical
# or live (AEGIS_POSTURE_LIVE=1, kubectl on PATH):
python -m aegis.posture k8s --live --context prod-ap-south-1
```

Workloads are judged once, at their controller (a Deployment, not each of its pods). `kube-system`
is skipped by default (CNI / kube-proxy are privileged by design) — `--include-system` scans it.
Secret objects are never requested; if an export contains them they are ignored and the report says so.

| Area | Check | Severity | CIS K8s v1.9 / PSS |
|---|---|---|---|
| Workload | Privileged container | critical | 5.2.1 / baseline |
| Workload | hostPath to `/`, `/etc`, `/proc`, the container runtime socket, kubelet dir … | critical | baseline |
| Workload | Mounts the token of a service account bound to cluster-admin | critical | 5.1.1 |
| Workload | hostNetwork / hostPID / hostIPC; other hostPath; dangerous capabilities (SYS_ADMIN, NET_ADMIN, ALL …) | high | 5.2.2–5.2.4, 5.2.8–9 |
| Workload | Explicit UID 0; plaintext secret-like env var in the manifest | high | 5.2.7; 5.4.1 |
| Workload | allowPrivilegeEscalation not false; root not prevented; hostPort | medium | 5.2.6; 5.2.7; baseline |
| Workload | Writable root FS; no CPU/memory limits; unpinned / `latest` image; default SA token mounted | low | 5.1.5–6 |
| RBAC | Any role granted to `system:anonymous` / `system:unauthenticated` / `system:authenticated` | critical | 5.1.1 |
| RBAC | cluster-admin bound to anything other than `system:masters` | high | 5.1.1 |
| RBAC | Bound custom role with `*`/`*`, or `escalate` / `bind` / `impersonate` | high | 5.1.3, 5.1.8 |
| RBAC | Bound custom role can read Secrets / exec into pods | medium | 5.1.2 |
| Network | Namespace with workloads and no NetworkPolicy | medium | 5.3.2 |
| Namespace | No Pod Security Admission enforce label; workloads in `default` | low | PSS; 5.7.4 |

## Policy-as-code (pre-deploy gate)

The same rules, run before deploy: **one rule, one ID, whether it fires in a pull request or on the
live account.** Terraform resources are translated into the shapes the CSPM and IAM scanners judge;
Kubernetes manifests go through the K8s workload and RBAC checks. Findings carry the Terraform address
or `Kind/namespace/name`.

```bash
terraform show -json plan.out > plan.json
python -m aegis.posture iac --plan plan.json --changed-only --k8s k8s/ --waivers security/waivers.yaml --fail-on high
```

Covered Terraform types: `aws_security_group`, `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`,
`aws_db_instance`, `aws_instance`, `aws_launch_template`, `aws_ebs_volume`, `aws_ebs_encryption_by_default`,
`aws_kms_key`, `aws_cloudtrail`, `aws_s3_bucket(_acl|_policy|_public_access_block)`, `aws_s3_account_public_access_block`,
`aws_iam_policy`, `aws_iam_(role|user|group)_policy`, `aws_iam_(user|group)_policy_attachment`, `aws_iam_role`, `aws_eks_cluster`.
Deleted resources are skipped; `--changed-only` also skips no-ops. Namespace-level K8s checks (NetworkPolicy, PSA)
depend on the cluster, so they stay in the live `k8s` scan.

**Waivers are the exception register.** Each needs `id` and `resource` (globs allowed), `reason`,
`approved_by` and `expires`; a waiver missing any of them is rejected (exit 2). Expired waivers suppress
nothing and are reported; waivers that match nothing are reported for clean-up; every applied waiver is
listed with its reason and approver.

```yaml
waivers:
  - id: CSPM-SG-ADMIN-PORT-OPEN
    resource: aws_security_group_rule.bastion_ssh
    reason: "Break-glass bastion behind Zscaler during VPN migration — CR-2291"
    approved_by: ciso
    expires: 2026-12-31
```

A ready-to-copy GitHub Actions workflow is in `deploy/ci/bluedefence-iac-gate.yml` (OIDC read-only plan
role, gate on `high`, report in the job summary).

## The VAPT loop (`run`) and the console Posture tab

`posture.yaml` lists every scan, the waiver register, the remediation SLA per severity and where results
are stored (sample: `samples/posture.yaml`). Paths are relative to the config file.

```bash
python -m aegis.posture run --config /etc/aegis/posture.yaml              # one run (cron / systemd timer)
python -m aegis.posture run --config /etc/aegis/posture.yaml --loop       # or keep running every interval_minutes
python -m aegis.posture run --config posture.yaml --fail-on-overdue       # exit 1 if anything is past SLA
```

Each run:

- executes every scan (export or `live: true`); **one failing scan never stops the others**;
- applies the single waiver register to all findings — if the register cannot be read, **nothing is
  waived** and the run says so (fail safe: more findings, never fewer);
- fingerprints every finding → **new**, **still open** (first-seen date, age), **resolved**. A fixed
  problem that comes back is new again, with a fresh SLA. A waived finding keeps its true first-seen
  date, so when the waiver lapses the SLA clock has not reset;
- a scan that **fails** carries its previous findings forward marked **stale** — never "resolved";
- checks every open finding against `sla_days` (default critical 7, high 30, medium 90, low 180);
- writes `runs/<run_id>.json`, a VAPT-style `runs/<run_id>.md` (summary, scope, past-SLA, new, every open
  finding with evidence / fix / control, resolved, accepted risk), `state.json`, and `latest.json`.

The SOC console's **Posture** tab reads `latest.json` from `AEGIS_POSTURE_DIR` (same SOC host; no new
backend endpoint, no cloud credentials near the console): past-SLA criticals first, filters by scan /
severity / past SLA / new, finding detail with the fix and control, accepted risk, resolved since last
run. Without `AEGIS_POSTURE_DIR` a live console says posture is not connected; with no backend at all it
shows the sample run. Timestamps render in `NEXT_PUBLIC_AEGIS_TZ` (default `Asia/Kolkata`).

Systemd units for a daily run are in `deploy/posture/`.

Exit codes: `0` ok, `1` a finding at or above `--fail-on`, `2` bad or missing input.
