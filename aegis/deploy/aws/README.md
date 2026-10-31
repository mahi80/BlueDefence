# AEGIS — AWS deployment

Walking-skeleton Terraform that lays down the four production-shaped
seams the project plan requires:

| Concern | Resource |
|---|---|
| Compute / orchestration | EKS cluster + managed node group + OIDC provider for IRSA |
| Audit log (tamper-evident at storage layer) | S3 bucket with Object Lock COMPLIANCE mode (7-year default), versioning, KMS-encrypted |
| Secrets (no static env vars at runtime) | Secrets Manager with KMS encryption + cross-region DR replica + (commented) rotation hook |
| LLM access (data residency: no PII over public internet) | Bedrock VPC endpoint (runtime + control plane) with IRSA-tag-scoped invoke policy |

This is NOT turnkey production. It's the canonical IaC scaffold a
bank's platform team would extend with the bank's own VPC topology,
organization-wide IAM baselines, KMS key policies, NetworkPolicy
implementation (Cilium / Calico), service-mesh (Istio / Linkerd),
load-balancer-controller, and CI deployment pipeline.

## Layout

```
aegis/deploy/aws/
  main.tf                    Top-level wiring + variables + outputs + KMS key
  modules/
    eks/                     EKS cluster + node group + OIDC provider
    audit-storage/           S3 + Object Lock COMPLIANCE + KMS + bucket policy
    secrets/                 Secrets Manager + cross-region DR + rotation hook
    bedrock-endpoint/        Bedrock VPC endpoint + security group + invoke policy
```

## What the scaffold gives you

After `terraform apply`:

- An EKS cluster `aegis-<tenant_id>` with a managed node group of 3
  m6i.xlarge nodes (private endpoint, no public access)
- An OIDC provider configured for IRSA so the agentic workload can
  assume IAM roles via service accounts
- An S3 bucket `aegis-audit-<tenant_id>-<region>` with
  Object Lock COMPLIANCE mode + 7-year retention. Even root cannot
  shorten retention (per Object Lock COMPLIANCE semantics)
- A Secrets Manager secret `aegis/<tenant_id>/credentials` with
  cross-region DR replica and KMS encryption. Empty initial value;
  operators populate via console or CI with proper change-control
- A Bedrock VPC endpoint (runtime + control plane) so the agent
  layer can call Claude via Bedrock without leaving the bank's VPC.
  Endpoint policy gates invocations to IAM principals tagged
  `Project=AEGIS`

## What it does NOT do

These are the natural follow-ups for a bank's platform team:

- **VPC / subnet creation** — assumes the bank's standard VPC
  exists (`vpc_id` + `private_subnet_ids` are inputs, not outputs)
- **NetworkPolicy enforcement** — Cilium or Calico install is
  cluster-bootstrap, not in this chart
- **Karpenter / cluster-autoscaler** — node group is fixed-size for
  the demo
- **AWS Load Balancer Controller** — for ingress / external-DNS
  integration
- **EBS CSI driver** — for stateful workloads (audit log writes
  directly to S3, but other components may need PVCs)
- **The actual application Helm install** — `aegis/healing/k8s/`
  and `aegis/observability/k8s/` charts go on top, applied by the
  bank's CD pipeline (Argo CD / Flux / similar)
- **Monitoring** — Tempo + Mimir + Grafana installation in the
  observability namespace (referenced by the OTel chart's exporter
  endpoints)
- **Backup / DR runbooks** — operational procedures for the audit
  log + secrets + cluster state, not IaC

## Quick start

```bash
cd aegis/deploy/aws
terraform init
terraform plan -var "vpc_id=vpc-xxxxxxxx" -var "private_subnet_ids=[\"subnet-aaa\",\"subnet-bbb\",\"subnet-ccc\"]"
terraform apply
```

Outputs:

```
Outputs:
  cluster_name        = "aegis-default"
  audit_bucket        = "aegis-audit-default-ap-south-1"
  secrets_path        = "aegis/default/credentials"
  bedrock_endpoint_id = "vpce-xxxxxxxxxxxxxxxxx"
```

Then deploy the Helm charts:

```bash
aws eks update-kubeconfig --name $(terraform output -raw cluster_name)
helm install aegis-healing aegis/healing/k8s
helm install aegis-obs    aegis/observability/k8s
```

## Cost note

The walking-skeleton config (3 m6i.xlarge nodes + S3 + Secrets +
Bedrock endpoint) costs roughly $300-500/month per tenant in
ap-south-1 at idle. Add Bedrock invocation cost on top per the
token-budget tracker in `agents/shared/llm_client.py`.
