# BlueDefence

Autonomous SOC — **AEGIS** (Agent Q), an ACP-governed detection, investigation and
response brain, with its analyst console. Carved out of the ACP monorepo
(`mahi80/rbi`) so the SOC product ships on its own cadence.

Detection is **deterministic** (scorers, fast-paths, policy-as-code); the LLMs
**triage and judge**; a multi-model vote guards the irreversible calls; and every
containment action is auditable and, by default, held for a human.

## Architecture

```mermaid
flowchart LR
  subgraph IN[Ingest]
    SIEM[Sentinel / Splunk]
    WAF[WAF: Imperva / F5 / Cloudflare]
    GOVE[ACP governance events]
  end
  IN --> ORCH[Orchestrator]
  ORCH --> DET["Deterministic detection<br/>scorers · fast-paths · policy-as-code"]
  ORCH --> TRI["LLM triage<br/>fine-tuned model"]
  TRI --> VOTE["Independent / ensemble vote<br/>guards irreversible calls"]
  ORCH --> SW["Swarm fan-out<br/>blast radius · min-cut plan · attacker twin"]
  DET --> CH[(Evidence chain)]
  VOTE --> CH
  SW --> CH
  CH --> HITL[HITL approval card]
  HITL --> RESP["Response connectors<br/>WAF / SOAR · shadow by default"]
  CH -. HTTP .-> DASH[(ACP dashboard<br/>/api/soc · /api/approvals)]
  DASH --> CON[soc-console]
  SDK["acp-sdk (pinned package)"] -. governs .-> ORCH
```

A detection flows **ingest → orchestrator**, where the deterministic layer reaches a verdict
where it can and the LLM triages the rest; an independent (or multi-model ensemble) vote guards
the irreversible calls; a swarm of short-lived workers walks the blast radius and plans the
**minimum cut**. It all lands in a hash-linked **evidence chain** → a **HITL** approval card →
**response connectors** (shadow until receipts prove an action safe; containment always waits for
a human). The dashboard and console are HTTP consumers; `acp-sdk` governs the brain as an optional,
pinned package. Full detail: [`aegis/README.md`](aegis/README.md).

## Layout

| Path | What it is |
|---|---|
| `aegis/` | The SOC brain: orchestrator → specialists → swarm fan-out → evidence chains → min-cut containment → HITL. Ingest (Sentinel/Splunk/WAF), response connectors (shadow by default), eval gates, dataset capture, meta-agent. See `aegis/README.md`. |
| `soc-console/` | The analyst console (Next.js) — decision-first HITL queue, evidence-backed Agent Q, attack-path map. Talks to the dashboard over HTTP. |
| `scripts/` | `soc_demo.py` (presenter-paced offline scenario the console renders) and `soc_live.py` (drives the real pipeline). |
| `docs/plans/` | AEGIS roadmaps. |

## The two seams (why this split is clean)

1. **Governance → `acp-sdk`, a pinned package.** Only `aegis/governance.py` touches it,
   imported lazily — AEGIS runs without it (governance degrades to a no-op). Pinned to
   `mahi80/rbi@b2e9d97` (acp-sdk 0.8.3) in `requirements-governance.txt` / `pyproject.toml`.
2. **Persistence/HITL → the ACP dashboard, over HTTP.** No dashboard code is imported;
   AEGIS posts to `ACP_DASHBOARD_URL` (`/api/soc/*`, `/api/approvals`). That API is the
   frozen contract between the two repos.

## Install

Prerequisites: **Python ≥ 3.11**; **Node 22** for the console; (optional) read access to the
private `mahi80/rbi` for the governance SDK.

```bash
# The SOC brain (base deps). AEGIS runs without governance — the acp-sdk import is optional.
pip install -e .                      # from pyproject; or: pip install -r aegis/requirements.txt

# Optional: the governance runtime (SOC-AGENTQ-01 under ACPGuard). Needs access to the private SDK.
pip install -e ".[governance]"        # pinned to mahi80/rbi@b2e9d97 (acp-sdk 0.8.3)
#   private install needs a token — either `gh auth setup-git`, or:
#   pip install "acp-sdk @ git+https://x-access-token:$GH_READ_TOKEN@github.com/mahi80/rbi.git@b2e9d97#subdirectory=acp-sdk"

# The console
cd soc-console && npm install
```

## Run

```bash
# Tests + the end-to-end eval gate
python -m pytest aegis/tests -q
python -m aegis.eval.fault_injection          # whole pipeline over synthetic campaigns

# One real service cycle over the built-in sample alerts (external edition, shadow enforcement)
python -m aegis.service

# The console against the presenter-paced demo scenario
python scripts/soc_demo.py --port 8799
cd soc-console && AEGIS_API_ORIGIN=http://localhost:8799 \
  AEGIS_AUTH_MODE=demo AEGIS_CONSOLE_SECRET=demo AEGIS_DEMO_USER=soc AEGIS_DEMO_PASSWORD=demo \
  npm run dev
```

Point AEGIS at a live dashboard with `ACP_DASHBOARD_URL` + `ACP_API_KEY` (persistence + HITL);
see the flags below and [`aegis/README.md`](aegis/README.md) for the full configuration reference.

## Key env flags

| Flag | Default | Effect |
|---|---|---|
| `ACP_DASHBOARD_URL`, `ACP_API_KEY` | — | Persistence + HITL transport to the dashboard. |
| `AEGIS_EDITION` | `external` | `external` \| `soc` \| `full`. |
| `AEGIS_ENFORCEMENT_MODE` | `shadow` | `shadow` logs what it would enforce; `live` calls vendor connectors. |
| `AEGIS_SWARM` | `1` | Swarm fan-out on triage. |
| `AEGIS_AUTO_BLOCK` | `shadow` | Detection-time auto-block of narrow, external, reversible targets (TTL, voter-gated). |
| `AEGIS_ENSEMBLE_VOTE` | `off` | Multi-model majority vote on the irreversible judgment. With it on, `build_pipeline` loads the extra voters named in `AEGIS_VOTER_MODELS` (comma-separated `model` or `backend:model`, e.g. `vllm:llama-3-8b, vllm:mistral-7b`) so the panel is ≥2; pick different families. Off, or with none set, it's the single-voter path. |
| `AEGIS_HITL_TIMEOUT` | `off` | Timeout fallback: a reversible action with a majority-concur vote auto-executes past its window; irreversible actions and split votes hold for a human. `shadow` \| `live`; `AEGIS_HITL_TIMEOUT_SEC` (120). |
| `AEGIS_OUTFLOW_BREAKER` | `shadow` | Outflow circuit breaker: during a drain burst (N high-value transfers to new beneficiaries from one sender), hold that sender's further payments without waiting for a human. `off` \| `shadow` \| `live`; TTL `AEGIS_OUTFLOW_BREAKER_TTL` (3600 s). Every other hold still waits. |
| `AEGIS_HIGH_VALUE_INR`, `AEGIS_OUTFLOW_BURST_N`, `AEGIS_OUTFLOW_WINDOW_S` | ₹1 cr, 3, 1800 s | Outflow guard: a high-value transfer to a beneficiary not known to be existing is held for a human; a burst is a drain. |
| `AEGIS_TREASURY_ACCOUNTS` | — | Treasury / nostro / settlement senders (plus ids containing TREASURY, NOSTRO, VOSTRO, SETTLEMENT, and `svc_` users). |
| `AEGIS_PRIVILEGED_USERS`, `AEGIS_PRIVILEGED_HOSTS` | — | Engineers with production reach (DevOps / SRE / DevSecOps / platform) and their machines — export from the IdP groups and asset inventory. A compromise there is a crown-jewel incident: isolate, revoke, rotate. Role tags on alerts work too. |
| `AEGIS_CROWN_JEWELS` | payment, signer, hsm, swift, treasury, vault, kms, core-banking | Systems where interactive access or a control change (signing policy, allowlist, limits) outside a ticketed window is malicious. |

WAF/SOAR vendors: `AEGIS_WAF_VENDOR`, `AEGIS_SOAR_VENDOR` (+ creds) — see `aegis/README.md`.

## Learning loop (DPO from the approvals queue)

Every analyst decision at the HITL card is supervision. `aegis.dataset export --dpo` turns the
ones that **overruled the model** into preference pairs in `dpo/preferences.jsonl`:

- `human_corrected` (analyst rejected the action *and* gave the verdict it should have been) →
  **chosen** = the analyst's verdict, **rejected** = the model's.
- `human_disputed` (analyst rejected an auto-run action, no verdict) → **chosen** = the same
  verdict with that action held for a human, **rejected** = the model's auto-run.

Confirmations and agreements produce no pair — there is nothing to prefer. DPO then nudges the
judge toward the analyst's call and away from the one it overruled, so detection sharpens with
each decision and needs fewer of them over time. Same held-out eval gate as SFT.

```bash
aegis.dataset export --dashboard --dpo --out datasets/triage-v1   # pulls chains + decisions
python -m aegis.finetune.dpo --data datasets/triage-v1 --dry-run   # validate pairs + plan (no GPU)
```

Analyst-only by construction, and `load_dpo` refuses non-analyst pairs unless `--allow-synthetic`,
so no one preference-tunes a bank model on scaffold data by accident.

## Pilot at a bank (sandbox) — what to ask for

The one ask that decides the pilot: **a read-only mirror of real production logs into the sandbox**.
A non-prod environment has almost no attack traffic, so AEGIS would have nothing to catch and the
pilot would prove nothing. Everything below supports that.

**Must-haves** — the pilot fails without these:

| # | Ask | Detail | Why |
|---|---|---|---|
| 1 | Two VMs in an isolated sandbox | SOC host: 4 vCPU, 16 GB, 50 GB SSD. GPU host: 1× 24 GB (L4 / A10). Ubuntu 22.04 or RHEL 9, container runtime | Runs the brain and the local model; data never leaves the bank |
| 2 | Read-only log mirror, live, at least one feed | WAF/CDN log export, or SIEM read-only API (Sentinel / Splunk) | Something real to detect on |
| 3 | Historical replay | 60–90 days of logs, pseudonymised if needed | Baselines, and a back-test: would AEGIS have caught your past incidents? |
| 4 | Past incidents with outcomes | 200–500 alerts the SOC already decided (true / false positive, action taken) | Measures accuracy on the bank's data, not ours |
| 5 | Analyst time | 1–2 SOC analysts, ~3–4 h/week, to decide approval cards | The shadow report is scored against their decisions |
| 6 | Approvals channel | ServiceNow dev instance, or accept the file queue | Where the cards land |
| 7 | Sponsor and signed success criteria | CISO or Head of SOC; criteria agreed before day 1 | Avoids "interesting, but…" at the end |

**Should-haves** — each unlocks a class of detection:

| Ask | Unlocks |
|---|---|
| Network sensor tap, or Zeek / Suricata logs | C2 beacons, slow exfiltration, shadow AI |
| EDR alerts (CrowdStrike / Defender) | Endpoint compromise |
| Privileged engineers and their machines (IdP groups, asset inventory) → `AEGIS_PRIVILEGED_USERS` / `_HOSTS` | Attacks on DevOps / DevSecOps engineers — the entry point of the Oct 2026 Binance drain |
| Crown-jewel list (payment signer, HSM, SWIFT, treasury, vault) → `AEGIS_CROWN_JEWELS` | Crown-jewel access and control-change detection |
| Kubernetes / cloud audit logs; HSM / payment-signer audit logs | Privileged access and signer tampering |
| Core-banking transaction stream (or a replay) and the treasury / nostro account list → `AEGIS_TREASURY_ACCOUNTS` | Drain and outflow detection |
| Change-ticket / CMDB feed | Tells ticketed changes from attacks — fewer false positives |
| Web proxy logs (Zscaler, Squid) | Shadow AI and pulls of uncensored / abliterated models |
| Sandbox tenants for the WAF / SOAR | One connector smoke test, still in shadow |

**Approvals to start early** — these take the longest at a bank:

| Approval | Who signs |
|---|---|
| Data handling: data stays on-prem, PII tokenised, nothing leaves the bank | Legal / DPO |
| Security review of AEGIS itself | InfoSec |
| Model-risk sign-off for a local LLM (RBI FREE-AI) | Model risk / CRO office |
| Network change: one inbound ingest port, internal only | Network / CAB |

**What the bank gets in return:**

- **Shadow only** — AEGIS takes no action on any bank system during the pilot; it records what it *would* do.
- **No data egress** — the models run on the bank's GPU, no internet calls (air-gap supported).
- **Read-only credentials** everywhere.
- **6–8 weeks** — install (1), wire feeds (2), shadow window (2–3), review (1).
- **Success criteria to propose** — catch ≥ X% of the bank's past confirmed incidents in replay; false
  positives ≤ Y/day on live traffic; a verdict in under a minute; a shadow report showing which
  actions would have been safe to automate.

Lead with must-haves 2–4: a bank that says yes to real logs and past incidents will make the rest routine.

## CI

- `.github/workflows/aegis-ci.yml` — eval gates (historical + injection, investigation
  quality, fault injection, property tests) and `pytest aegis/tests`. The governed job runs
  the unit tests always; it installs `acp-sdk` and runs the governance eval **only when the
  repo secret `GH_READ_TOKEN` is set** (a read-scoped PAT for `mahi80/rbi`). Without the
  secret it stays green — governance-only tests self-skip — and the full governed gate turns
  on automatically the day a token is added. No token is required to keep CI green.
- `.github/workflows/soc-console-ci.yml` — `npm ci` + typecheck + build.

## Provenance

Clean import from `mahi80/rbi` (the ACP monorepo) at `b2e9d97`. The dashboard, the
license server and `acp-sdk` itself stay in `rbi`; BlueDefence consumes the SDK as a
pinned package and the dashboard over HTTP.
