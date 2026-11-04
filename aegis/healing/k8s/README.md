# AEGIS Self-Healing — K8s manifests (Helm chart)

Operationalizes the snapshot → sever → respawn → re-onboard pipeline
defined in [aegis/healing/pipeline.py](../pipeline.py) on a real
Kubernetes cluster.

## What's here

```
aegis/healing/k8s/
  Chart.yaml           Helm chart metadata
  values.yaml          Per-environment knobs
  templates/
    _helpers.tpl
    rollout.yaml                  Argo Rollouts canary respawn + analysis
    networkpolicy.yaml            Egress allowlist + quarantine deny-all
    forensic-snapshot-job.yaml    ConfigMap holding the pre-respawn LiME + criu Job template (the controller
                                  instantiates it; nothing runs at install), its token-less ServiceAccount,
                                  and a deny-all NetworkPolicy for forensic pods
    forensic-admission-policy.yaml  ValidatingAdmissionPolicies bounding the Jobs the controller may create
                                    and the pod patches it may make
    controller-rbac.yaml          Least-privilege ServiceAccount + Role
    controller-deployment.yaml    Healing controller (HA, leader-elected)
```

## How the pipeline maps to manifests

| Pipeline stage (Python) | K8s artifact |
|---|---|
| `snapshot()` | Labels the target pod `aegis.bank/forensic-target=<artifact>`, reads the Job template from the `aegis-forensic-job-template` ConfigMap, substitutes `${TARGET_POD}` / `${ARTIFACT_ID}` and creates the `Job`; a required podAffinity to the labelled pod puts it on the target's node. LiME captures memory, criu captures process state, tcpdump replays from NetFlow. Output goes to a per-snapshot ephemeral claim in the WORM storage class. |
| `sever()` | Patches the suspect pod with label `aegis.bank/quarantined=true`. The `*-quarantine` NetworkPolicy denies all ingress/egress for any pod with this label. The pod is left running for forensics; quarantine is the active control. |
| `respawn()` | Patches the Argo `Rollout` to bump replicas + abort the suspect; new pods come up from the immutable image with a fresh workload identity (the `aegis.bank/respawn-generation` annotation forces a rolling restart). |
| `reonboard()` | Argo Rollouts canary steps gradually shift traffic to the new replicas; the AnalysisTemplate gates promotion on success-rate >= `successThreshold`. |

## Validate locally (no real cluster needed)

```bash
# Lint
helm lint aegis/healing/k8s

# Render to a single YAML for review
helm template aegis-healing aegis/healing/k8s > /tmp/rendered.yaml

# Dry-run against a kind cluster (if you have one)
kind create cluster --name aegis-test
kubectl apply --dry-run=server -f /tmp/rendered.yaml
```

## Production deployment notes

- **Argo Rollouts must be installed** in the cluster before this chart
  applies. Install: `kubectl create namespace argo-rollouts && kubectl
  apply -n argo-rollouts -f https://github.com/argoproj/argo-rollouts/releases/latest/download/install.yaml`.
- **WORM storage class** (`worm-immutable` in values.yaml) needs to be
  provisioned by the cluster admin — typically a CSI driver mapping to
  S3 Object Lock, Azure Blob immutability, or GCS Bucket Lock. It **must use
  `reclaimPolicy: Retain`**: every snapshot gets its own generic ephemeral
  claim (no shared ReadWriteOnce claim pinning snapshots to one node), and that
  claim is deleted with the Job's pod — Retain is what keeps the evidence volume.
- **Nothing forensic runs at install.** The Job is shipped as a ConfigMap
  template (`aegis-forensic-job-template`); the controller may `get` only that
  ConfigMap.
- **Image registry** (`registry.bank.internal/...`) must be the bank's
  internal mirror with image signing (cosign) enabled. Production
  AdmissionController should reject unsigned images.
- **Secrets** consumed by the healing image (audit log bucket creds)
  must come from Vault / HSM via short-lived JIT injection, NOT
  long-lived K8s Secrets — see the `Securing the agentic stack` section
  of the project plan.
- **Observability**: the controller exposes Prometheus metrics on
  `:9090`. Wire to Grafana for healing-event timelines, MTTR, and
  forensic-artifact catalog views.

## Failure modes the chart is designed to bound

| Failure | Containment |
|---|---|
| Healing controller is compromised | RBAC denies cluster-admin; can only label pods + create Jobs + patch Rollouts in the target namespace. "Create Jobs" alone would let it start any pod, so `forensic-admission-policy.yaml` (ValidatingAdmissionPolicy, Kubernetes ≥ 1.30; `forensics.admissionPolicy`) denies any Job it creates unless it is one container of the forensic image running the pinned `forensics.command`/`args`, as the token-less `aegis-forensic-snapshot` ServiceAccount, labelled `aegis.bank/role=forensic-snapshot`, with only emptyDir / WORM ephemeral volumes (no hostPath, Secret, projected, ConfigMap or existing PVC), no Secret/ConfigMap env, no nodeName/nodeSelector/tolerations/custom scheduler (placement only via the podAffinity to the labelled target pod), no hostNetwork/hostIPC, privileged mode or extra capabilities. `patch pods` is needed for the quarantine and forensic-target labels; a second policy (`aegis-healing-pod-patch`) rejects any pod update by the controller that changes the spec, annotations or any other label. NetworkPolicy denies egress except to API server + DNS. |
| Forensic Job is compromised | It runs as its own ServiceAccount with no API token mounted and no container-runtime socket (process state is read via hostPID + SYS_PTRACE), so it cannot call the API or take over the node's runtime. `aegis-forensic-deny-all` gives forensic pods no ingress and no egress — the memory image cannot leave over the network. |
| Forensic snapshot Job is compromised | Capabilities limited to SYS_PTRACE + SYS_ADMIN (needs them for memory dump); no privileged: true. Output goes to WORM PVC the Job cannot delete. |
| Respawn pulls a tampered image | Cluster's image admission controller rejects unsigned/unverified images. The chart references `IfNotPresent` pull policy — production MUST set `Always` once registry signing is enforced. |
| Rollout regresses | AnalysisTemplate failureLimit aborts on 2 consecutive metric failures; `setWeight` steps with pauses give time to detect. |

## What's intentionally out of scope here

- Multi-region failover during heal (handled at the service mesh / DNS layer)
- Stateful workloads (DBs, message brokers) — those use replica failover, not respawn
- Compliance approval workflow for high-impact heals (Slack-bot or ServiceNow integration; lives in the Response Agent)
