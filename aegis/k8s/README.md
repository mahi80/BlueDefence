# AEGIS — Agent layer Helm chart

Ships the agent layer (orchestrator + specialists + meta-agent + RL
generator) as a Kubernetes Deployment with IRSA, NetworkPolicy egress
allowlist, HPA, and Prometheus scrape annotations.

Pairs with the other two charts in this repo:

  - `aegis/healing/k8s/`       — Self-Healing controller + Argo
                                  Rollouts canary + forensic Job
  - `aegis/observability/k8s/` — OTel collector + alerts (this chart's
                                  pods are scraped by it)
  - `aegis/k8s/` (this chart) — the agent workload itself

## Layout

```
aegis/k8s/
  Chart.yaml
  values.yaml          replicas, resources, IRSA role ARN, LLM backend,
                       voter backend (multi-provider diversity), egress
                       allowlist, securityContext
  templates/
    _helpers.tpl
    serviceaccount.yaml   IRSA-annotated ServiceAccount
    deployment.yaml       Deployment + PVC for audit buffer + Service
    networkpolicy.yaml    Egress allowlist + ingress restricted to OTel
    hpa.yaml              HPA on CPU + custom alerts_queued metric
```

## Prerequisites

1. EKS cluster from `aegis/deploy/aws` (or equivalent) with the
   IAM role ARN for IRSA.
2. Argo Rollouts CRDs installed (only required if you also apply the
   `aegis/healing/k8s/` chart; this chart uses plain Deployment).
3. external-secrets-operator installed (referenced for the runtime
   credentials secret; the actual `ExternalSecret` resource is
   tenant-specific and lives in the bank's own configuration repo,
   pointing at the Secrets Manager path the Terraform module created).
4. The OTel collector chart applied so Prometheus scrape works.

## Install

```bash
# Set the IRSA role ARN from the Terraform output
ROLE_ARN=$(terraform output -raw aegis_irsa_role_arn)

helm install aegis-agent aegis/k8s \
    --namespace bank-prod \
    --set serviceAccount.roleArn="$ROLE_ARN" \
    --set llm.backend=bedrock \
    --set llm.voter_backend=gemma
```

## What the chart does

- Deploys 3 replicas of the agent layer (HPA scales 3-20 based on CPU
  + custom `aegis_alerts_queued` metric).
- Mounts a PVC at `/var/aegis/audit` so the local hash-chain survives
  pod restart while waiting for flush to the S3 Object Lock bucket.
- IRSA binds the pod's ServiceAccount to an IAM role with
  bedrock:Invoke + secretsmanager:GetSecretValue + audit-bucket
  s3:PutObject. No long-lived static credentials in the pod.
- NetworkPolicy denies all egress except: DNS, OTel collector, Bedrock
  VPC endpoint, Splunk REST, ServiceNow REST. Compromised agent pod
  cannot exfiltrate to attacker C2.
- Prometheus scrape annotations + `/metrics` port enable the OTel
  collector to pick up the per-agent counters automatically.

## Production extensions left for the bank's platform team

- ExternalSecret resource pointing to the Secrets Manager path
- Image pull secrets / OCI registry creds (Cosign signature verify
  via admission controller)
- PodDisruptionBudget tuning to bank's SLO posture
- Affinity / topologySpreadConstraints across AZs
- VolumeSnapshot policies for the audit buffer PVC

## Validate locally

```bash
helm lint aegis/k8s
helm template aegis-agent aegis/k8s --set serviceAccount.roleArn=arn:aws:iam::000000000000:role/test > /tmp/rendered.yaml
kubectl apply --dry-run=server -f /tmp/rendered.yaml
```
