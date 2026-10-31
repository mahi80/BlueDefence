# AEGIS sandbox — proof plan

**Purpose:** a self-contained Azure twin of "one slice of a bank's stack" where every
claim in the CISO assessment (`AEGIS vs Traditional Endpoint Security`) can be *shown*,
with no bank tenant and nothing production touched. This is what you hand the CTO when
asking for the real sandbox: "here is the same thing running on our own subscription,
here are the receipts."

Terraform + runbook: [`deploy/sandbox/azure/`](../../deploy/sandbox/azure/README.md).
Learning track (no detection model; triage first-pass + DPO): roadmap Phase 3.

## The stack it stands up

```
          Front Door + WAF ──┐
 Juice Shop (target VM) ─────┤  diagnostics          ┌─ Logic App playbooks (the "hands", shadow)
 Defender for Servers ───────┤ ─────────► Sentinel ──┤   (AEGIS_SOAR_VENDOR=sentinel)
 vendor CEF (Zscaler/CRWD/   │  SecurityAlert        └─ F5 BIG-IP VE (optional, AEGIS_WAF_VENDOR=f5)
   Imperva/F5) via AMA ──────┤                 │
 Sophos (content-hub) ───────┘                 ▼
                                      AEGIS SOC service (aegis.service)
                                      orchestrator + 10 specialists + swarm,
                                      ACP-governed (SOC-AGENTQ-01), HITL → dashboard
```

One alert path (`aegis.ingest.SentinelConsumer`) because every vendor has a Sentinel
content-hub connector; per-vendor code is only ever for *enforcement*, and enforcement
stays HITL/shadow.

## Assessment claim → sandbox scenario → evidence

| # | Assessment strength | Scenario in the sandbox | Evidence it produces |
|---|---|---|---|
| S1 | **Multi-agent autonomous investigations** (perimeter) | `scenario.sh <fd> scan` — nuclei/ZAP at the Front Door; WAF → Sentinel → AEGIS | perimeter specialist chain in the dashboard, verdict + evidence, < 60 s |
| S2 | **Intent-based security** (not just events) | same traffic, but the swarm fans out (ioc_enrich, blast_radius, log_hunt) | `metadata.swarm` on the chain: corroborating evidence, re-vote, campaign view |
| S3 | **Cross-domain / identity + endpoint** | Defender for Servers alert on the target VM (Atomic Red Team T1059 on Linux) → Sentinel | edr/auth specialist chain; entity graph folded into host/account keys |
| S4 | **Transaction / fraud investigation** | replay a synthetic RTGS-structuring alert through the service (eval fixture) | transaction specialist chain — the BFSI use case, no bank data |
| S5 | **AI-vs-AI defence** | the injection corpus (`python -m aegis.eval.run`) + a prompt-injected alert field | 9/9 injection containment; injected text never becomes an action |
| S6 | **Governance + HITL + immutable audit** | an `isolate` recommendation on a protected target | dashboard approval card (decider, role, rationale); two-person rule; hash-chained audit |
| S7 | **Autonomous Tier-1/2 analyst, controlled response** | shadow window: WAF `throttle`/`challenge` via playbook, `block`/`isolate` HITL | receipts ("would have done") vs analyst decisions → `aegis.shadow report` |
| S8 | **Tiered latency** (honest version) | measure: deterministic honeytoken/triage fast path vs LLM investigation | p50 from `aegis.eval.swarm_timing`; the RL hot path is **not** claimed (roadmap 3.4 = DPO) |
| S9 | **Compliance-aware evidence** | a high-confidence malicious chain → CERT-In draft + FS-ISAC STIX bundle | generated artefacts; dataset export with provenance to the bank-side bucket |
| S10 | **Vendor enforcement reach** | Logic App playbook per action type; F5 VE live `block` if `enable_f5=true` | playbook run ids in the receipt chain; F5WafConnector live smoke |

S4/S5/S9 run from eval fixtures and need no live feed, so they work on day 0. S1–S3, S6–S8,
S10 come online as each vendor feed/trial is wired (runbook "Vendor feeds").

## What the sandbox deliberately does NOT prove

State these to the CTO so the ask for the *real* sandbox is grounded:

- **Detection quality** — Juice Shop + nuclei is not a bank's alert mix; the fine-tune
  (3.3) needs real analyst-labelled alerts, which only a real tenant produces.
- **The flip-live decision** — shadow agreement numbers here are against *our* judgement,
  not a SOC team's. The 2-week shadow window (1.5 thresholds) only counts on real traffic.
- **Imperva / Zscaler / CrowdStrike / Sophos as live enforcement** — these have no
  self-serve trial for the enforcement APIs; the sandbox proves the *ingest* path (via
  Sentinel) and the connector *shape* (mock-tested), not a live block on those platforms.
  F5 is the exception (BIG-IP VE BYOL trial), which is why it is the one wired live.
- **Scale** — one B4ms, one target. Throughput/HA is the k8s chart (`aegis/k8s`), not this.

## Cost / teardown

~USD 300–500/month with the evening auto-shutdown (Front Door Standard ~$35 + VMs when on +
Sentinel after the 31-day free tier). `terraform destroy` removes everything; the RG is
dedicated (`rg-aegis-sandbox`) so nothing else is at risk. Defender for Servers is OFF by
default (it is subscription-wide) — turn it on only with `enable_defender_for_servers=true`
on a subscription you don't mind billing.
