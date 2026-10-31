# AEGIS Smart Brain roadmap (v6 → v10)

Status as of 24 Oct 2026. Living doc: https://claude.ai/artifact/BTprv2hX55yXUH2rGJ8qVi

## Goal

An always-on security brain that watches every endpoint continuously, judges activity in
context rather than one alert at a time, and runs on a handful of GPUs or CPU-hosted GGUF models.

- **Continuous watch:** every user, host, IP and session is reviewed on a schedule, alert or not.
- **Accuracy over size:** small quantised models do most of the work; the fine-tuned Qwen3-8B
  takes the hard judgement calls; a larger model or an analyst sees only the hardest cases.
- **Human in control:** block, isolate, lock account and revoke sessions always need approval.
- **Gets smarter:** analyst corrections feed retraining every month.

## Where we are

| Item | State | Detail |
|---|---|---|
| v6 triage adapter (Qwen3-8B, QLoRA) | Training | Session/cookie domain (#187): forged cookie claims (T1606.001), session fixation (T1539). Synth run first, then `MODE=public`. |
| v6 data | Verified | 1,500 synthetic rows, 12 domains, 125 session rows, 201 injection rows |
| sec-eval test set | Built | 300 ATT&CK-mapping + 100 Sigma-writing cases, 0 overlap with training |
| v7 training data | Built | 4,604 SFT rows (ATT&CK mapping + Sigma) from the SigmaHQ training split; rows naming a real CVE id removed |
| RAG corpus | Built | 706 ATT&CK techniques, 1,756 CISA KEV entries, 122,336 CVEs (2025–2026) |
| Hardware | Laptop | RTX 4080 Laptop 12 GB; GPU cluster planned |

## Target architecture: a tiered funnel

Each tier escalates only what it cannot settle, so the 8B brain spends compute on a tiny
share of activity.

```
All telemetry, 24x7 (endpoints, network, cloud, identity, app logs)
  │ every event
  ▼
Tier 1   Stream layer — normalise, Sigma rules, baselines, anomaly scores   (CPU, 100% of events)
  │ signals only
  ▼
Tier 1.5 Small distilled classifier — passes on only uncertain signals       (CPU)
  │ uncertain signals, grouped by entity
  ▼
Tier 2   Entity timelines + risk score; Qwen3-1.7B GGUF triager              (CPU servers)
  │ risky stories
  ▼
Tier 3   Qwen3-8B brain + specialist LoRAs, RAG, tools; hunts by querying logs (few GPUs)
  │ low confidence only                                    ▲
  ▼                                                        │ analyst corrections → monthly DPO
Escalation — 32B model or analyst; human approval for containment ──┘
```

## Roadmap

| Phase | Scope | Gate |
|---|---|---|
| **v6** (training now) | Session/cookie domain in the triage adapter. Synth run, then `MODE=public`. | ≤ 5 historical misses, 0 injection leaks |
| **v7** Detection-engineering skills | ATT&CK mapping + Sigma drafting, ~1,500 rows sampled from sec-eval. Exclude every sec-eval test `source` from `build-public`. 2 epochs. Merged into triage or a separate LoRA (open). | Triage gate holds; `attack_map` F1 ≥ v6 + 0.15; Sigma parses ≥ 98%; ≤ 3% general regression |
| **v8** Efficient cascade | `confidence` field + escalation threshold; verdict cache; GBNF-constrained JSON; distil v7 into a Qwen3-1.7B triager and a small CPU classifier. | No silent misses; 1.7B close to 8B on routine cases (target set after v7) |
| **v9** Always-on entity timelines | Stream normaliser, Sigma engine, entity store with risk scores. Synthetic timelines incl. normal days. Train on timelines + tool calls (query logs, entity history, CVE lookup). | New timeline gate: multi-stage chains caught, few false alarms on normal days |
| **v10** Verified detections + learning loop | Labelled attack/benign log slices; Sigma behavioural scoring; GRPO with `reward_sigma`; analyst corrections as DPO; imatrix-calibrated GGUF per tier. | `fires_on_pos` ≥ 0.70, `quiet_on_neg` ≥ 0.90 |

v8 comes before the always-on timelines because v9 only fits on a few GPUs once the cheap tiers
filter most of the work. Every quant level (Q4/Q5) must pass the same gates before shipping.

## Efficiency levers

| Lever | What it does | Phase |
|---|---|---|
| Confidence routing | Each tier answers when confident, escalates when not | v8 |
| Verdict cache | Hash normalised repeat patterns, reuse the verdict | v8 |
| Distillation | Large teacher → 8B → 1.7B triager → small classifier | v8 |
| Constrained output | GBNF grammar in llama.cpp: short JSON that always parses | v8 |
| Entity timelines | Compact per-entity stories, fixed system prompt for prefix caching | v9 |
| Tools and RAG | CVE/KEV/ATT&CK looked up, not memorised; query raw logs when unsure | v9 |
| Specialist LoRAs | Adapters per domain swapped at runtime | v9 |
| Verified rewards | GRPO rewards rules that fire on attack logs and stay quiet on benign | v10 |
| Calibrated quantisation | Q4_K_M/Q5_K_M with a security-data importance matrix, each quant scored | v10 |
| Active learning | Analyst corrections → DPO; uncertain cases labelled first | v10 |

## Open decisions and risks

- [ ] v7: merge into the triage adapter, or a separate LoRA?
- [ ] v8 distillation teacher: local 32B or hosted API? Bank data cannot leave the client boundary.
- [ ] Cluster sizing for the first client, after v8 throughput tests
- [ ] Pilot client for analyst-labelled data — all training rows so far are synthetic or public
- [ ] Sigma rules are DRL 1.1: attribution needed in commercial outputs
- [ ] Public Hugging Face repo: confirm no client-specific content ships in the adapter
- [ ] Lab log slices (attack + benign) needed before v10 behavioural scoring
