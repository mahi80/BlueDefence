# Tier-0 inline filter (Go)

Purpose: per-request allow/block/escalate decisions at bank scale
(millions of req/s). Python's GIL and per-call cost rule it out for
this hot path; Go gives microsecond decisions, low memory, single-binary
deployment, and a smaller supply-chain surface than a Python container.

## What's here

`tier0.go` reads JSON-lines events from stdin and applies a policy
loaded from `--policy <path>`, emitting JSON-lines decisions on stdout.

The policy file is a linear classifier as a stand-in for a real PPO
model. To export from a trained PPO checkpoint, run:

```bash
python -m aegis.rl.export_policy --checkpoint runs/ppo_baseline.zip --out aegis/rl/policy.json
```

## Build & run

```bash
cd aegis/edge
go build -o tier0 .
echo '{"id":"e1","features":{"primitive_count":2.0,"ip_known_bad":1.0}}' | ./tier0 -policy ../rl/policy.json
```

## Enforcing AEGIS decisions at the edge

The SOC service exposes its active enforcement set at `GET /ingest/blocklist`
(bearer `AEGIS_INGEST_TOKEN`): IPs / CIDRs and client fingerprints (JA4 / JA3,
optionally with an exact user agent), each with its expiry. An inline filter —
this tier-0 binary, Envoy `ext_authz`, a Cloudflare Worker — polls it every few
seconds and short-circuits those clients without calling any vendor API. The Go
binary does not implement that poll yet; it is the first production seam below.

## Production seams to wire later

| Seam | Stand-in | Production |
|---|---|---|
| Blocklist | none | poll `GET /ingest/blocklist` on the SOC service; deny listed IPs / fingerprints inline |
| Input | stdin JSONL | Kafka consumer (segmentio/kafka-go or sarama) |
| Output | stdout JSONL | Kafka produce + Envoy ext_authz response |
| Policy | linear classifier JSON | ONNX (preferred) or torchserve for trained PPO |
| Observability | none | OpenTelemetry traces + Prometheus metrics |
| HITL on block | flag in output | Slack approval webhook + ticket creation |

### Upgrading the policy: linear JSON -> ONNX

The current `Policy` struct in `tier0.go` parses linear weights from
JSON. For non-linear policies (real PPO output), swap to ONNX:

1. Export the trained model:
   ```bash
   # sklearn baseline (no torch needed):
   python -m aegis.rl.onnx_export --from sklearn --out aegis/rl/policy.onnx
   # PPO checkpoint (needs torch + sb3):
   python -m aegis.rl.onnx_export --from ppo --checkpoint runs/ppo_baseline.zip --out aegis/rl/policy.onnx
   ```
2. Replace the `Policy.decide()` body in tier0.go with an ONNX runtime
   inference call. Recommended Go bindings:
   - `github.com/yalue/onnxruntime_go` — cgo binding to Microsoft's
     ONNX Runtime. Best perf, handles all opsets, used in production.
   - `github.com/owulveryck/onnx-go` — pure-Go, lighter, narrower opset
     coverage. Fine for small linear models, weaker for full nets.
3. Verify the model loads and inference matches the Python verdict on
   a held-out batch before promoting.

## Why Go (not Python or Rust)

- Concurrency model fits the I/O pattern (Kafka fan-in/fan-out).
- Static binary -> smaller supply-chain surface than a Python container
  with pip dependencies (LiteLLM-class risk reduction).
- Faster startup than Python -> matters for self-healing respawns.
- Rust is also viable; Go chosen here for ecosystem maturity in the
  service-mesh / Kafka tooling banks already use.
