# AEGIS — Agent layer Helm chart

Ships the agent layer (orchestrator + specialists + meta-agent + RL
generator) as a single-replica Kubernetes StatefulSet running `python -m aegis.service`,
with IRSA, a NetworkPolicy egress allowlist and Prometheus scrape annotations.

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
  values.yaml          receiver port, state PVC, resources, IRSA role ARN, LLM backend,
                       voter backend (multi-provider diversity), egress
                       allowlist, securityContext
  templates/
    _helpers.tpl
    serviceaccount.yaml   IRSA-annotated ServiceAccount
    statefulset.yaml      StatefulSet (replicas 1) + state PVC template + Service
    networkpolicy.yaml    Egress allowlist + ingress to the receiver (OTel + receiver.ingressFrom)
```

## Prerequisites

1. EKS cluster from `aegis/deploy/aws` (or equivalent) with the
   IAM role ARN for IRSA.
2. Argo Rollouts CRDs installed (only required if you also apply the
   `aegis/healing/k8s/` chart; this chart uses a plain StatefulSet).
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
    --set installation.id="$(python -m aegis.license install-id)" \
    --set license.existingSecret=aegis-license \
    --set license.server=https://licence.example \
    --set 'license.serverCIDRs={203.0.113.10/32}' \
    --set llm.backend=bedrock \
    --set llm.voter_backend=gemma
```

Required before install: `installation.id` (or `installation.idSecret`) — the chart refuses to
render without it — and `AEGIS_AUDIT_KEY` in the `aegis-runtime-credentials` secret (or
`audit.keySecret`); the pod does not start without it.

## What the chart does

- Runs exactly **one** pod of `python -m aegis.service --audit /var/aegis/audit/audit.jsonl`.
  There is deliberately no HPA and no replica knob: the service owns one append-only
  audit hash chain, one alert checkpoint and one HITL queue, so a second pod would fork
  the chain and poll every source twice (duplicate verdicts and actions). Scale with
  `resources`. A StatefulSet (not a Deployment) guarantees the old pod is gone before the
  new one attaches the volume.
- One PVC (`volumeClaimTemplates`, `state.size`) at `/var/aegis` holds every writable
  path — `AEGIS_AUDIT_PATH`, `AEGIS_CHECKPOINT`, `AEGIS_HITL_DIR`, `ACP_HOME`,
  `AEGIS_TI_CACHE`, `HOME` — so the root filesystem stays read-only and the chain,
  checkpoint and queue survive restarts. Ship the chain to the S3 Object Lock bucket;
  the PVC is the working copy.
- Starts the push receiver on `0.0.0.0:8787` (`AEGIS_INGEST_HTTP=1`): `/healthz` is the
  readiness probe (503 when degraded takes the pod out of the Service without a restart
  loop; liveness is a TCP check), `/metrics` is the scrape target (set
  `AEGIS_METRICS_TOKEN`), `/ingest/*` takes pushed events. The receiver refuses to bind
  a non-loopback address without `AEGIS_INGEST_TOKEN`, so that key must be in the
  `aegis-runtime-credentials` secret.
- IRSA binds the pod's ServiceAccount to an IAM role with
  bedrock:Invoke + secretsmanager:GetSecretValue + audit-bucket
  s3:PutObject. No long-lived static credentials in the pod.
- NetworkPolicy denies all egress except: DNS, OTel collector, Bedrock
  VPC endpoint, Splunk REST, ServiceNow REST. Compromised agent pod
  cannot exfiltrate to attacker C2.
- Prometheus scrape annotations point at `/metrics` on the receiver port (8787); the
  scrape job needs the metrics bearer token.
- Licence (review round 8 R8-13): `AEGIS_LICENSE` points at `/var/aegis/license/license.jwt` on
  the PVC, because the service renews the token in place and the root filesystem is read-only.
  `license.existingSecret` (key `license.jwt`) seeds it through the `license-seed` init container
  (`python -m aegis.license seed`): copied when the PVC has no token or the Secret changed, never
  over a renewal, and only if it verifies for this installation. `AEGIS_LICENSE_ENFORCE=1` by
  default (`license.enforce`). `AEGIS_INSTALL_ID` is pinned from `installation.id` /
  `installation.idSecret` — a pod's machine identity is not stable, and the licence is bound to
  it. NetworkPolicy has no FQDN rules, so `license.serverCIDRs` (+ `serverPort`) opens egress to
  the licence service (or your egress proxy); empty = heartbeat/renewal cannot leave the pod.
- Audit retention key: `AEGIS_AUDIT_KEY` (from `audit.keySecret`) signs the retention checkpoint
  written by `python -m aegis.audit retire`; retire refuses and verify reports "unverifiable"
  without it. Rotate with `AEGIS_AUDIT_KEY_PREVIOUS` + `python -m aegis.audit resign`.

## Production extensions left for the bank's platform team

- ExternalSecret resource pointing to the Secrets Manager path
- Image pull secrets / OCI registry creds (Cosign signature verify
  via admission controller)
- A PodDisruptionBudget (a single pod means node drains cause a short outage; pushes
  should be retried by the sender)
- VolumeSnapshot policies for the state PVC

## Validate locally

```bash
helm lint aegis/k8s
helm template aegis-agent aegis/k8s --set serviceAccount.roleArn=arn:aws:iam::000000000000:role/test \
    --set installation.id=bd-test > /tmp/rendered.yaml
kubectl apply --dry-run=server -f /tmp/rendered.yaml
```
