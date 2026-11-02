# Posture scanning

Runtime agents judge events as they happen. Posture scanners judge a **snapshot**: every identity,
bucket, cluster and template as it stands, so a misconfiguration that predates AEGIS is still found.

| Scanner | Status | Input (offline) | Live mode |
|---|---|---|---|
| IAM review | ✅ | `aws iam get-account-authorization-details` + `aws iam get-credential-report` | boto3, `SecurityAudit` policy |
| CSPM | planned | — | — |
| Kubernetes posture | planned | — | — |
| Policy-as-code (IaC) | planned | — | — |

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

Exit codes: `0` ok, `1` a finding at or above `--fail-on`, `2` bad or missing input.
