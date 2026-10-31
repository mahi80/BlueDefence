# AEGIS observability — K8s manifests (Helm chart)

Production deployment of the OpenTelemetry collector that ingests
spans + metrics from AEGIS workloads and forwards them to the bank's
internal observability stack (Tempo for traces, Mimir for metrics).
Composes with `aegis/healing/k8s/` so a single `helm install` per
chart wires up both self-healing and observability.

## What's here

```
aegis/observability/k8s/
  Chart.yaml
  values.yaml          Collector image, exporter endpoints, sampling rate
  templates/
    _helpers.tpl
    configmap.yaml     OTel collector pipeline config (receivers/processors/exporters)
    daemonset.yaml     Collector DaemonSet + ServiceAccount + ClusterRole +
                       Service + NetworkPolicy egress allowlist
    alerts.yaml        PrometheusRule with 5 AEGIS-specific alerts
```

## What the collector does

1. **OTLP receivers** (gRPC :4317, HTTP :4318) — AEGIS Python agents
   push spans + metrics through `aegis/agents/shared/observability.py`,
   which uses the OTel SDK if installed (otherwise the calls are
   internal-record-only).
2. **Prometheus scrape** — auto-discovers AEGIS pods via
   `app.kubernetes.io/managed-by` labels and scrapes their
   `/metrics` endpoints.
3. **Defense-in-depth PII redaction** (`attributes/aegis-redact`
   processor) — drops any attribute that looks PII-shaped even after
   the AEGIS PII tokenizer at the application layer. The tokenizer is
   the primary control; this is belt-and-braces.
4. **Probabilistic sampling** at the collector (rate from
   `values.yaml`). AEGIS itself doesn't sample — sampling is a
   collector-level decision.
5. **Forwards** traces to Tempo, metrics to Mimir. NetworkPolicy
   blocks egress to anything outside the observability namespace —
   compromised collector cannot exfiltrate to external SaaS (the
   `external_export_blocked` invariant in values.yaml).

## Alerts shipped

The chart's `alerts.yaml` provisions a `PrometheusRule` with 5
AEGIS-specific alerts:

| Alert | Condition | Severity |
|---|---|---|
| `AEGISAuditChainBroken` | `aegis_audit_integrity == 0` for 1m | critical |
| `AEGISHITLBacklogStuck` | HITL actions queued but no high-impact actions executed in 1h | warning |
| `AEGISFalsePositiveSpike` | `malicious` verdict rate > 50% for 10m | warning |
| `AEGISTokenBudgetSpike` | LLM cost rate > $10/hr for 15m | warning |
| `AEGISSpecialistMissing` | orchestrator or response agent not seen in metrics for 5m | critical |

These cover the failure modes explicitly called out in the project
plan: tamper-evident audit failure, agent compromise (no activity),
campaign-driven cost spike, FP-rate-driven analyst trust loss, HITL
gating breakdown.

## Validate locally (no real cluster needed)

```bash
helm lint aegis/observability/k8s
helm template aegis-obs aegis/observability/k8s > /tmp/rendered.yaml
kubectl apply --dry-run=server -f /tmp/rendered.yaml   # if you have a cluster
```

## Production deployment notes

- **Tempo + Mimir must already be installed** in the bank's
  observability namespace before this chart applies. Endpoints in
  `values.yaml` (`tempo_endpoint`, `mimir_endpoint`) point to those
  services.
- **Sampling** defaults to 1.0 (100%) for the demo. In steady-state
  prod, drop to ~0.1 for ambient traffic; keep 1.0 for spans tagged
  with high-impact action types (configure tail-sampling at the
  collector for that nuance).
- **No external SaaS export** — the chart explicitly blocks egress
  outside the bank's observability namespace. If the bank uses a
  SaaS observability vendor (Honeycomb, Datadog, New Relic), egress
  must go through a vetted forward proxy in the egress allowlist.
- **Defense in depth** — the `attributes/aegis-redact` processor is
  belt-and-braces. The application-layer PII tokenizer
  (`agents/shared/pii_tokenizer.py`) is the primary control.

## What's intentionally NOT here

- Tempo + Mimir + Grafana installation (these are infra concerns,
  not the AEGIS application's responsibility)
- Tail-sampling configuration tuned for the bank's actual traffic
  profile (workload-specific)
- AlertManager routing to PagerDuty / Slack channels (bank's existing
  routing config)
- Long-term span / metric retention policy (cluster-level concern)

These are the natural ops integration points.
