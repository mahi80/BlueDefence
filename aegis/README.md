# AEGIS — Agent Q, the autonomous SOC

AEGIS is the security-operations agent behind ACP. It reads the alerts a bank's existing
stack already produces (SIEM, WAF, EDR, identity, core banking), triages them with a
fine-tuned model, investigates with a swarm of short-lived workers, plans the *smallest*
containment that protects the crown jewels, and puts that plan on an approval card for a
human. Everything it decides is evidence, every action goes through a connector that can
run in shadow mode, and every step is written to a hash-chained audit log.

It ships in three **editions** from one codebase: the SOC on its own (`external`), the SOC
with the ACP console (`soc`), or the SOC joined to ACP's governance of the bank's own AI
agents (`full`).

```
  bank telemetry                         AEGIS                                      people / vendors
  ─────────────                          ─────                                      ────────────────
  Sentinel · Splunk ─┐  poll
  WAF (5 vendors) ───┤  push ─► ingest ─► campaign context ─► triage ─┬─► fast paths: honeytoken / canary,
  Okta · EDR · CBS ──┤  (Logpush,  (dedupe,   (this IP / session /     │    control-plane fact (Q37, pause),
  ACP governance ────┘   Firehose,  checkpoint) fingerprint, 30 min)   │    adaptive attacker (retry-after-stop)
                         Event Hub)
     events (full)                                                 ▼
                                               specialist (perimeter · auth · edr · api_abuse · transaction ·
                                               cloud · dlp · email · mobile · wireless) ─► voter (2nd model)
                                                                   │
                                                 verdict ◄─────────┘   benign → close
                                                    │ suspicious / malicious / uncertain
                                                    ▼
                                        swarm enrichers (≤ 60 s, inline)     ──►  HITL card (dashboard ·
                                        intel · decoy · blast · log hunt ·          ServiceNow · file queue)
                                        patch · analyst brief; never lowers         │ approve
                                                    │                               ▼
                                                    ▼                         response agent ─► WAF / SOAR
                                        async investigation tier                (auto-safe now;   connectors
                                        walkers → blast graph → min-cut plan     containment       (shadow →
                                        → attacker twin → card updated in place  after approval)    live)
                                                    │                               │
                                                    └──── containment loop: re-walk after each step ◄┘

  audit.jsonl (hash-chained, authoritative) · receipts.jsonl · dataset capture → retrain → human-approved promotion
```

## Contents

1. [Run it in five minutes](#run-it-in-five-minutes)
2. [Editions](#editions)
3. [How a verdict is reached](#how-a-verdict-is-reached)
4. [Against AI-agent attackers](#against-ai-agent-attackers) — fingerprints, retry-after-stop, auto-block
5. [What leaves over TLS](#what-leaves-over-tls) — beacons, exfiltration, known-bad servers, shadow AI
6. [What the network itself says](#what-the-network-itself-says) — root cause, alarm suppression, flaps, bad pushes, the Kafka bridge
7. [What happens after the verdict](#what-happens-after-the-verdict)
8. [The model: data, fine-tune, gate, retrain](#the-model-data-fine-tune-gate-retrain)
9. [Threat intelligence](#threat-intelligence)
10. [Connecting a bank](#connecting-a-bank) — sources, approvals, connectors, topology
11. [ACP integration (full edition)](#acp-integration-full-edition)
12. [Failure handling and logging](#failure-handling-and-logging)
13. [Evaluation and CI gates](#evaluation-and-ci-gates)
14. [Configuration reference](#configuration-reference)
15. [Code map](#code-map)
16. [Honest limits](#honest-limits)

---

## Run it in five minutes

> Installing on a real host? One command does the whole thing — user, venv, config, licence, systemd:
> `curl -fsSL https://raw.githubusercontent.com/mahi80/BlueDefence/main/install.sh | sudo bash`
> (see the root README § *Install on a bank host*). The steps below are the developer path.

Everything below runs offline on a laptop: mock LLM, mock telemetry tenant, mock WAF / SOAR
tenants, file-based approvals. No dashboard, no API keys.

```bash
pip install -r aegis/requirements.txt

# one cycle of the real service over the built-in sample alerts, external edition
AEGIS_EDITION=external LLM_BACKEND=mock AEGIS_SWARM=1 AEGIS_INVESTIGATE=1 AEGIS_TWIN=1 \
AEGIS_WAF_VENDOR=mock AEGIS_SOAR_VENDOR=mock AEGIS_HITL_DIR=/tmp/aegis-hitl \
python -m aegis.service --once

cat /tmp/aegis-hitl/cards.jsonl            # the approval cards (and the investigation rows)
AEGIS_HITL_DIR=/tmp/aegis-hitl python -m aegis.hitl decide <id from a card> approve --by me
# next cycle executes it through the (mock) WAF connector in shadow mode → receipt
```

Prove it behaves:

```bash
python -m aegis.eval.run                       # 37 historical verdicts + 9 prompt-injection cases
python -m aegis.eval.investigation_quality     # walkers / planner / loop / twin on 6 scripted worlds
python -m aegis.eval.fault_injection           # the whole pipeline with each dependency failing in turn
python -m aegis.eval.purple_team               # adaptive AI-agent attackers vs AEGIS: detect, contain, collateral
pytest aegis/tests -q                          # ~270 tests
```

### A sandbox that mirrors a bank onboarding

Each onboarding step has an in-process stand-in, so the full path can be rehearsed before a
bank gives you anything:

| Onboarding step | Real | Sandbox stand-in |
|---|---|---|
| Alert feed | `AEGIS_SOURCES=sentinel,waf,splunk` | `AEGIS_SOURCES=sample`, or `WAF_EVENT_FILE=aegis/ingest/fixtures/waf_events.log` (or `cloud_waf_events.jsonl`) with `waf`, or the real-shape Log Analytics fixture in `aegis/ingest/fixtures/` |
| Network sensor | Zeek / Suricata on the egress tap, or the proxy's logs | `AEGIS_SOURCES=ndr NDR_EVENT_FILE=aegis/ingest/fixtures/ndr/zeek_tls.sample.jsonl` (or `suricata_eve.sample.jsonl`), with `AEGIS_TLS_IOC_FILE` and `AEGIS_AI_REGISTER` from the same folder |
| Network operations | device syslog, SNMP traps, NetFlow, telemetry, RANCID/Oxidized configs, LLDP — usually already on Kafka → the [Kafka bridge](../kafka-bridge/README.md) | `AEGIS_SOURCES=netops NETOPS_EVENT_FILE=aegis/ingest/fixtures/netops/campus.sample.log` |
| Topology for the blast radius | a `TelemetrySource` adapter over Okta / EDR / NetFlow / CBS | `MockTenant` (deterministic world; `AEGIS_MOCK_SPREAD` sets how compromised it looks) |
| Approvals | ServiceNow / dashboard | `AEGIS_HITL_TRANSPORT=file` (decide in the console, or `python -m aegis.hitl decide`) |
| WAF / SOAR | Imperva · F5 · Cloudflare · AWS WAF · Azure WAF · XSOAR · Sentinel playbooks | `AEGIS_WAF_VENDOR=mock` (Imperva), `mock-cloudflare`, `mock-aws`, `mock-azure`; `AEGIS_SOAR_VENDOR=mock` — the *real* connector classes against stateful fakes with 429 / 5xx / dropped connections, lock-token and etag races, bad signatures |
| Shadow window | two weeks of real receipts | `python -m aegis.shadow report --receipts aegis/_receipts.jsonl --audit aegis/_audit_log.jsonl` |
| Model | the fine-tuned adapter | `LLM_BACKEND=mock` (deterministic) or `LLM_BACKEND=local AEGIS_MODEL=<adapter>` |
| ACP console | `ACP_DASHBOARD_URL` | run the dashboard locally (see the repo-root README, WSL notes) with `AEGIS_EDITION=soc` |

The cloud version of the same rehearsal — Sentinel, Front Door WAF over a deliberately
vulnerable target, Logic App playbooks — is `deploy/sandbox/azure/` (Terraform; proof plan in
`docs/plans/aegis-sandbox-proof-plan.md`).

---

## Editions

`AEGIS_EDITION` separates the standalone SOC from the ACP integration. **BlueDefence is standalone
by default (`external`)**: its own Next.js console (`soc-console/`) talks to this host's API — chains
from the local audit log, approvals through the local queue — with no ACP dashboard and no `acp-sdk`.
A host that sets `ACP_DASHBOARD_URL` without naming an edition keeps `full`, so integrated installs are
unchanged. The default is chosen from `ACP_DASHBOARD_URL` alone: a host with `ACP_GOVERN=1` or the
`acp` source in `AEGIS_SOURCES` but no dashboard URL now defaults to `external` and refuses to start
with an `EditionError` (set `AEGIS_EDITION` and `ACP_DASHBOARD_URL` explicitly).

| | `external` (default) | `soc` | `full` |
|---|---|---|---|
| Alert feeds, triage model, swarm, blast radius, plan, twin | ✅ | ✅ | ✅ |
| WAF / SOAR connectors, shadow mode, receipts | ✅ | ✅ | ✅ |
| Local hash-chained audit | ✅ authoritative | ✅ | ✅ |
| Approvals | **BlueDefence console** (local queue), ServiceNow, or file (+ Slack notify) | dashboard, ServiceNow or file | dashboard, ServiceNow or file |
| Console: incidents, approvals, posture, exposures, model loop | ✅ BlueDefence console → this host | ✅ | ✅ |
| Model promotion (`retrain propose` / `sync`) | local queue, decided in the console | ACP dashboard (`--dashboard`) | ACP dashboard (`--dashboard`) |
| ACP dashboard: shadow report upload, receipts/chains shipped, rule feed | — | ✅ | ✅ |
| SOC brain governed under ACPGuard | — | — | ✅ |
| ACP SDK in the customer's own agents, Q37, Q rogue detectors | — | — | ✅ |
| Q ↔ AEGIS bridge | — | — | ✅ |

**Standalone in three settings:** on the host, `AEGIS_CONSOLE_TOKEN=<secret>` (the push receiver then
serves `/api/soc/*` + `/api/approvals` + `/api/soc/proposals` from its own files); in the console,
`AEGIS_API_ORIGIN=http://<host>:8787` and `AEGIS_API_KEY=<same secret>`. Analysts sign in to the
console; only deciding roles see Approve / Reject, and the decision lands in `decisions.jsonl` where the
service executes it on its next cycle.

`aegis/edition.py::apply_edition()` runs first in `build_pipeline`: it fills the edition's
defaults and **refuses** contradictory configuration with the variable named
(`external` + `ACP_DASHBOARD_URL`, `ACP_GOVERN=1`, the `acp` source or dashboard approvals;
`soc` + `ACP_GOVERN=1`). A console edition with no dashboard URL is allowed but logged as
degraded. The service banner starts with the edition, e.g. `[external] … ungoverned brain — HITL file`.

---

## How a verdict is reached

1. **Ingest** — `aegis/ingest/` normalises each source to one alert shape, dedupes through a
   shared checkpoint and survives restarts and throttling.
2. **Campaign context** (`walkers/campaign.py`, `AEGIS_CAMPAIGN_CONTEXT=1`, on even when the
   swarm is off) — before triage, what the same source IP / session / user / **client
   fingerprint** did in the window is folded into the alert: distinct endpoints, requests per
   minute, WAF signature diversity, cross-owner reads, time span, IP and user-agent rotation,
   and retry-after-stop. This is what turns five boring requests into one recognisable
   AI-agent chain.
3. **Fast paths** — no model involved:
   - **Honeytokens and stack canaries** (`agents/deception/`): a decoy source map, decoy bundle
     key, dummy admin/export route, legacy admin path. Nothing legitimate touches them, so a
     touch is `malicious` at 0.97.
   - **Control-plane facts** (`orchestrator/control_plane.py`, full edition): a Q37 block, an
     `infra_attack` pause or a CRITICAL rogue verdict on a governed agent is enforcement that
     already happened, so the chain is built from the control evidence.
   - **Adaptive attacker** (`orchestrator/adaptive.py`): a client stopped by the WAF that comes
     back within seconds from new IPs with changed requests — see the next section.
   - **Credential stuffing** (`orchestrator/auth_abuse.py`): one client submitting an auth form
     at machine rate.
   - **BOLA / object walking** (`orchestrator/bola.py`): an alert from the API-gateway detector.
   - **Spoofed browser** (`orchestrator/spoofed_client.py`): a browser user agent on a TLS
     handshake no browser makes, stopped by the WAF or submitting an auth form.
   - **Egress** (`orchestrator/egress.py`): a beacon, exfiltration, known-bad TLS server or
     shadow-AI finding from the network sensor — see "What leaves over TLS".
4. **Triage** — the fine-tuned model (or a frontier model) routes to a specialist or closes.
5. **Specialist** — one of ten domain agents runs its deterministic tools (decode layers, IP
   reputation, impossible travel, MFA fatigue, BOLA / enumeration, process trees, mule
   fan-in, cloud key creation, DLP, phishing, TLS identity…) and the model reasons over the
   tool output, which is always wrapped as untrusted data.
6. **The corroboration rule** the model is trained on: two independent strong signals, or one
   strong plus two weak → `malicious`; one strong or two weak → `suspicious`; else `benign`.
   Contexts (pen-test window, synthetic monitor, deploy, dev VPN, inspection proxy…)
   neutralise only the signal classes they explain.
7. **Voter** — a second model reviews the verdict; dissent caps confidence and forces a human.

Confidence is **policy-calibrated** (the rule above plus the voter cap), not yet
statistically calibrated against analyst outcomes; the retrain loop is where that measurement
will come from.

---

## Against AI-agent attackers

An attacking agent is fast (recon to exploit in minutes), rotates (a new IP every few
requests from a proxy pool) and adapts (mutates and retries the moment it is stopped). Three
mechanisms answer those three traits.

**Follow the client, not the IP** (`agents/shared/fingerprint.py`). The TLS fingerprint (JA4 /
JA3, from Cloudflare and AWS WAF logs) survives IP rotation. Campaign context is keyed on it,
so twenty requests from twenty IPs are one client. Where no TLS fingerprint is logged, a
header-order hash correlates but is never enforced.

**Does the handshake match the browser it claims?** (`agents/shared/tls_client.py`). The
client picks its user agent string, but the TLS ClientHello comes from its real network stack.
An agent on python-httpx, aiohttp, Go or Node that copies a Chrome user agent still shakes
hands like a library. Campaign context judges every request that carries a JA4 and claims a
browser *before* the request teaches the model anything. It attaches `tls_client`: the claimed
browser, the observed stack, whether they are consistent, the strength, and the reasons.

| Evidence | What it says |
|---|---|
| reference (`AEGIS_JA4_DB`) | the operator's JSONL of known JA4s, labelled `browser` (with family), `library` or `middlebox`. None is bundled; `ingest/fixtures/ja4_reference.sample.jsonl` shows the shape with invented values |
| learned: library | honest automation (`partner-sync/…`, `python-httpx/…`) presents this JA4 from ≥ 2 IPs (`AEGIS_TLS_LIBRARY_IPS`) |
| learned: shared | ≥ 3 different browser user agents present it on benign requests (`AEGIS_TLS_SHARED_UAS`). That is a browser population, or a TLS-inspecting middlebox re-originating every employee's handshake, so it is never a mismatch |
| structural | strong: no ALPN, http/1.1 offered before h2, no TLS 1.3 from a version that has it, < 6 extensions. Half weight: 30+ cipher suites, no SNI, < 10 extensions |

Only requests the edge let through untouched teach the model; hostile traffic never does. A
*strong* mismatch is a lie about the client, and it changes three things:
- **Spoofed-browser fast path** (`orchestrator/spoofed_client.py`). The lie plus intent (the
  bank's WAF stopped the request, or it is an auth-form submission) gives `suspicious` 0.80 /
  0.75 and **`challenge fp:ja4:<v>;ua:<exact UA>`**. No real browser presents that pair, a
  script cannot pass the challenge, and anyone behind an unlearned middlebox who matched it
  would pass. It is never a block. If the client keeps coming back after the challenge, the
  adaptive path calls it `malicious`. AEGIS's own rules showing up in the WAF log (`aegis …`)
  don't count as the WAF stopping it.
- **Client actions** for every fast path: a `Mozilla/` user agent the handshake contradicts is
  followed with that composite challenge, not by IP only.
- **Credential stuffing** counts the spoofer by fingerprint + user agent across its pool. A
  *consistent* browser user agent is counted per IP + user agent instead, because fingerprint +
  user agent on a real browser is every customer on that build, not one client.

**Retry-after-stop** (`walkers/campaign.py` → `orchestrator/adaptive.py`). For every request
the WAF stopped, attempts that follow within 120 s count as retries — a rotation if from a
new IP, a mutation if the request changed. Only attack-shaped requests count (stopped or
flagged), so customers behind a shared NAT or browser fingerprint never form a campaign.
≥ 3 retries, median ≤ 30 s, ≥ 2 rotations or mutations → `malicious` without the LLM, with
actions on the client:

| What the client looks like | Action |
|---|---|
| any | `block` the current IP (short TTL) + `escalate` to an analyst |
| TLS fingerprint, one non-browser user agent | `block fp:ja4:<v>;ua:<exact UA>` — stops the whole proxy pool |
| TLS fingerprint, rotating user agents | `challenge fp:ja4:<v>` — a bare JA4 is shared by real browsers; they pass a challenge |
| a `Mozilla/` user agent the TLS handshake contradicts | `challenge fp:ja4:<v>;ua:<exact UA>` — only clients telling the same lie match |
| a `Mozilla/` user agent with a consistent handshake | no fingerprint action — it could be customers; IP only |
| the exact client (fingerprint + UA) seen on ≥ 2 benign clients; for a bare-fingerprint challenge, the fingerprint seen on ≥ 2 benign clients in the window or in the estate's longer memory (a partner's hourly sync) | no fingerprint action |
| fingerprint in `AEGIS_FP_ALLOW` | no fingerprint action |

Fingerprint rules are enforced on Cloudflare (custom rule in `http_request_firewall_custom`)
and AWS WAF (rule in the AEGIS rule group, `AEGIS_AWS_WAF_RULE_GROUP`); Imperva, F5 and Azure
refuse them (`unsupported`), so the action parks for a human while the IP block still runs.

**Tiered autonomy** (`agents/response/autonomy.py`, `AEGIS_AUTO_BLOCK=off|shadow|live`,
default `shadow`). Minutes of approval latency is the whole fight against an agent, so a
**short, self-expiring** block on a narrow external target may run without a human — when the
verdict is `malicious` ≥ 0.90, the voter did not dissent, the target is a public IP, a CIDR no
wider than /24, or a fingerprint paired with a non-browser user agent, it is not protected or
allow-listed, and fewer than 50 auto-blocks ran in the last hour. TTL 15 min, renewed while
the attack continues, rolled back by the connector. In `shadow` an eligible block is recorded
as an `auto-shadow` receipt and still goes to a human — the shadow report scores auto-block
against their decisions before anyone turns it `live`. This is separate from
`AEGIS_ENFORCEMENT_MODE`, so flipping challenge / throttle live never makes blocks autonomous.
Containment (isolate, revoke, lock, rotate) is always a human.

**How long an approved action lasts.** Automated actions keep the connector TTL (1 h, renewed while
the attack continues). An action a person approved does not lapse on that clock: containment
(isolate, block_egress, lock, revoke, rotate…) stays in force until a person releases it at the
vendor (`AEGIS_APPROVED_TTL_SEC`, default `0` = until released), and an approved block / throttle /
challenge on an IP lasts a day (`AEGIS_APPROVED_BLOCK_TTL_SEC`, default `86400`) so WAF rule sets do
not grow forever. A later automated re-apply of the same action only ever extends it. The
HITL-timeout path is not a person and keeps the connector TTL.
Re-approving after a release at the vendor applies it again: for EDR contain, SOAR playbooks and the
SWG category a human re-approval of a permanent action calls the vendor, not a no-op renewal.

**HITL timeout** (`agents/response/hitl_timeout.py`, `AEGIS_HITL_TIMEOUT=off|shadow|live`,
default `off`; window `AEGIS_HITL_TIMEOUT_SEC`, default 120 s; floor `AEGIS_HITL_TIMEOUT_MIN_CONF`, default 0.6). When an approval waits past its window with no
decision, a *reversible* action (block, block_egress, throttle, challenge) runs on timeout only if
the reviewer vote explicitly concurred (`vote_concur` is `True`; a chain with no vote — triage
`respond`, deterministic detectors — is held) and confidence ≥ the floor. Everything else is held
for a human. A transport that cannot be read (ServiceNow non-200, a dashboard error) never falls through
to the timeout path. The same contract gate and width rules as any unattended action apply (below).

**What may run with no human** (`agents/response/contracts.py`, `agents/response/grounding.py`). Every
action type has a contract — its impact (read-only, low, moderate, high, severe, irreversible), how it is
undone, and whether a human decides by policy; the test suite fails if an action type has none, and the
auto-safe and always-HITL sets are derived from the contracts. An action that would run unattended
(auto-safe, tiered auto-block, outflow breaker, HITL timeout) must clear all of:

| Check | Rule |
|---|---|
| Autonomy tier | `AEGIS_AUTONOMY_TIER` L0–L4 caps the impact: L0/L1 read-only, L2 low, L3 moderate, L4 high (default L4 = each switch decides). Severe and irreversible actions never run unattended. |
| Confidence | the chain's confidence reaches the floor for the impact: low 0.70, moderate 0.85, high 0.95 (`AEGIS_AUTONOMY_FLOOR_LOW` / `_MODERATE` / `_HIGH`). |
| Protected target | a target on `AEGIS_PROTECTED_TARGETS` raises the impact one rank. |
| Grounded | the target is one of the alert's entities (or the chain's tool evidence), or a narrow network around one. |
| Narrow | at most a /24 (IPv4) or /48 (IPv6), never internal or reserved space; a destination with two labels that is not a shared suffix; never a principal on `AEGIS_UNATTENDED_DENY_PRINCIPALS` (admin, root, krbtgt, svc_* …). |
| No injection | nothing runs unattended on a chain with prompt-injection evidence. |

Each check can only make the answer stricter. The design of the contracts and the confidence × impact ×
tier gate follows [AiSOC](https://github.com/beenuar/AiSOC) (MIT).

**Read back at the vendor.** After an action is applied live (unattended or approved), the connector reads
it back where the vendor allows it — Imperva rule, AWS WAF IP set, CrowdStrike containment status, Zscaler
category. A vendor that does not show it turns "executed" into a human's problem (an approved action is
retried); the receipt records `verified`. Every `AEGIS_VERIFY_EVERY_S` (default 300 s, 0 = off) the service
re-reads active enforcement: an action released or removed outside AEGIS is marked `drifted` and logged,
instead of being reported as still in force, and the next approval applies it afresh. A rule is judged only after
`AEGIS_VERIFY_GRACE_S` and called drifted only after two misses in a row; a drifted WAF rule is deleted at the vendor
so a misread never orphans one (contain / category connectors are left alone). The read-backs run on their own
thread. In live mode an action no vendor connector handles is `unsupported` (a human does it), never "applied" by
the logging fallback. Connectors that cannot
read back (Cloudflare, Azure, F5, SOAR playbooks) report "not verifiable" on the receipt.

**Quarantine a rogue AI agent** (`connectors/openshell.py`). An AI agent that runs inside an
[NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) sandbox is quarantined without touching its host:
`isolate agent:<sandbox>` reads the sandbox's policy, saves it (0600), and replaces it with the same policy
minus every `network_policies` rule (`openshell policy set … --wait`). OpenShell is default-deny and injects
credentials only into requests the policy admits, so the agent can reach nothing and use no key. Filesystem and
Landlock settings are kept as they were. Undo restores the saved policy; the read-back confirms the network
policy is empty. `isolate` is SEVERE, so a person always approves it. Turn it on with
`AEGIS_AGENT_SANDBOX=openshell` (`mock` for a lab); the connector sits first in the registry and claims only
`agent:` / `sandbox:` targets, so a host isolate still goes to the EDR. OpenShell is alpha; the connector uses
only its documented CLI.

**Sandbox AEGIS itself with OpenShell** (`ops/openshell_policy.py`). The specialists read attacker-written text, so
a prompt injection that gets past the injection defences must still find nowhere to send data.
`python -m aegis.ops.openshell_policy --out aegis-sandbox.yaml` writes an OpenShell policy for this deployment. Only
the hosts its configuration actually talks to are allowed: the model API, each vendor connector, ServiceNow, intel
feeds, Kafka and the ACP dashboard. Everything else is denied. Then run
`openshell sandbox create --name aegis --policy aegis-sandbox.yaml -- python -m aegis.service`.
* **No secrets in the file.** Only host names and ports are read from the environment, never a token, so the file is
  safe to review and commit.
* **Fail closed.** An integration this module does not recognise stays blocked until you add it with
  `--extra host:port`.
* **Red-team range.** `deploy/openshell/attack-range-policy.yaml` does the same for an attack agent: it can reach
  the range and its model, and nothing else.

**Never-block guardrail** (`agents/shared/netguard.py`). No connectivity-severing action
(`block`, `isolate`, `throttle`, `quarantine`, `block_egress`) reaches a connector when the target
is loopback, link-local, unspecified or multicast / reserved space, or an operator-listed address
(`AEGIS_NEVER_BLOCK` CIDRs, `AEGIS_NEVER_BLOCK_HOSTS`) — auto, auto-approved and human-approved
alike, at the single `ConnectorRegistry.apply()` choke point and at `ResponseAgent.approve()`. So
an approval cannot blind the SOC by blocking its own ingest, the shim's alert sink, or — in a
loopback lab where every source IP is `127.0.0.1` — every agent at once. Deliberately narrower
than the auto-block guard above: RFC1918 stays blockable, so a compromised *internal* host can
still be isolated.

**Measured, not claimed** — `python -m aegis.eval.purple_team` (`eval/purple_team/`) runs
scripted adaptive attackers through the real pipeline with the mock Cloudflare tenant in live
enforcement. Each run starts with five minutes of ordinary traffic and keeps customers
interleaved with the attacker. The crowd includes a partner's integration on the same Python
TLS stack as the agents, last synced 45 minutes earlier, and a corporate customer's staff
behind a TLS-inspecting proxy, each with logins and a WAF false positive. The benchmark prints,
per campaign: the step and simulated second
of the first `malicious` verdict, when the client was contained (its next request denied by
AEGIS and no later success), requests that reached the application (and how many after
detection), sensitive endpoints reached, collateral on customers, and pipeline cost per event.
It compares `auto-block` with `human@300s` (a simulated analyst approving every block five
minutes later). The gated rows fail CI:

| campaign | auto-block | human @ 300 s |
|---|---|---|
| rotating SQLi agent (8-IP pool, one UA) | detected step 5, contained step 6, **0 sensitive reached** | detected step 5, never contained, 3 sensitive reached |
| UA-rotating scanner | contained step 9 via its retry-pool IPs — the partner's integration shares its TLS stack, so the bare-fingerprint challenge is held back | never contained — the IP blocks wait for a human |
| browser-driven agent (shares the customers' JA4) | contained step 9 via its retry-pool IPs, 0 sensitive | never contained |
| honeytoken touch | contained on the next request | never contained |
| credential stuffing (3-IP pool, one client) | detected at attempt 8, contained at 9 — challenge + throttle, no block | same (challenge is auto-safe) |
| BOLA: a customer token walking account ids (API-gateway logs + ownership) | confirmed at request 3 (2 foreign accounts read), contained at 6 | detected at 3, never contained — the token revoke waits for a human |
| Chrome user agent on a scripting TLS stack (http/1.1 first) | challenged on the exact pair at step 2, contained step 3; *step 11 without the TLS check* | same — the challenge is auto-safe |
| Chrome user agent on an HTTP/2 library (browser-shaped handshake) | contained step 3 — the estate learned the stack from the partner's honest user agent | same |
| slow credential stuffing (3/min, under the burst rate) behind a Chrome user agent | challenged on attempt 1, contained at 2; *without the TLS check: never detected, 12 logins through* | same |
| low-and-slow: one client mutating against one endpoint, paced under every burst / retry signal | detected step 3, contained step 4 — caught by accumulation (attack-shaped WAF stops per source IP on one endpoint), not cadence | same |
| customers, partner and proxy staff only | nothing enforced, nothing malicious | — |

Reported but not gated: **ownership-confirmed BOLA still needs the API gateway** — proving a
caller read an object it does not own needs the principal *and* an ownership source, which only
the gateway path carries. The edge now closes part of the gap: the shim derives a hashed
`principal` from the session cookie / bearer (`scripts/aegis_edge.py`, salt
`AEGIS_PRINCIPAL_SALT`), and the perimeter's `id_enumeration` scorer flags one caller walking many
distinct object-ids on one endpoint (`AEGIS_IDENUM_HIGH` / `_MED` / `_WINDOW_SEC`) — the
*behavioural* tell, without ownership. (Low-and-slow — one request every 2.5 min — is now caught
by accumulation rather than cadence; see the row above.)

**BOLA / object walking** (`agents/api_abuse/object_walk.py`, `orchestrator/bola.py`) needs
what only an API gateway logs: the authenticated principal next to the object id. Gateway
records (Azure APIM, AWS API Gateway, Kong, generic JSON — `ingest/apigw.py`) feed a bounded,
in-memory detector per principal and endpoint template; raw events never reach the model,
only the alerts it emits:

| level | when (in `AEGIS_BOLA_WINDOW_S`, 300 s) | verdict | response |
|---|---|---|---|
| confirmed | ≥ 2 objects owned by other customers answered 2xx | malicious 0.95 | block every IP of the walk + safe fingerprint action; **revoke the principal's sessions** and escalate as a possible personal-data breach (human) |
| attempted | ≥ 5 foreign objects requested, authorisation refused | malicious 0.90 | same containment; no exposure |
| behavioural | ≥ 10 distinct objects not known to be the principal's, sequential / not-found / machine cadence | suspicious 0.70 | throttle + challenge, escalate |

Ownership comes from the bank (`AEGIS_OWNERSHIP_FILE` CSV/JSONL export, or `AEGIS_OWNERSHIP_URL`
lookup, cached, failures = unknown); the owner ids must be in the namespace the gateway logs as
principal. Without it only *behavioural* fires. Objects the principal owns never count (a
corporate customer reading its forty accounts is quiet), joint accounts list several owners,
and `AEGIS_BOLA_EXEMPT_PRINCIPALS` covers the CRM and service principals that read other
customers' objects by design. Alerts carry counts and object ids masked to the last four
characters — never the victims' identifiers. The token is the real containment; IP blocks buy
time until a human revokes it.

**Credential stuffing** (`orchestrator/auth_abuse.py`) has its own fast path: auth-form writes
(POST/PUT/PATCH to login / token / OTP / password endpoints) from **one client** — same TLS
fingerprint *and* user agent, or same IP *and* user agent, so a branch NAT never adds up — at
≥ `AEGIS_AUTH_BURST_MIN` (8) in 60 s → `malicious`, `throttle` the IP, `challenge` the client
(fingerprint + UA when it is not a browser or the handshake contradicts the browser it claims,
else the IP), `escalate` to review which accounts were tried. A consistent browser user agent
is counted per IP + UA, never per fingerprint + UA (that would be every customer on the build). No block: a customer on a bad link pays a challenge, not access. Numbers above are with `LLM_BACKEND=mock`; run with a
real backend to measure the model, and with `--approval-latency` for the bank's real SOC cadence.

Sandbox: `WAF_EVENT_FILE=aegis/ingest/fixtures/agentic_rotation.jsonl` holds a rotating agent,
a patient human and a crowd of customers on a shared browser build; run it with
`AEGIS_WAF_VENDOR=mock-cloudflare AEGIS_ENFORCEMENT_MODE=live AEGIS_AUTO_BLOCK=live` and only
the agent's IPs and fingerprint are blocked (`tests/test_adaptive_attacker.py`).

Sandbox for the TLS check: `WAF_EVENT_FILE=aegis/ingest/fixtures/tls_spoofing.jsonl` is sample
data (invented JA4s, documentation IPs). It holds:
- a partner's sync 45 minutes earlier;
- customers and a corporate proxy's staff, with logins and a WAF false positive each;
- an agent with a Chrome user agent on a scripting TLS stack.

Run it with `AEGIS_SOURCES=waf AEGIS_WAF_VENDOR=mock-cloudflare AEGIS_ENFORCEMENT_MODE=live
python -m aegis.service --once`. The only rule written is one managed challenge on the agent's
JA4 + user agent (`tests/test_tls_client.py`). Add
`AEGIS_JA4_DB=aegis/ingest/fixtures/ja4_reference.sample.jsonl` to see reference labels at work.

## What leaves over TLS

The WAF sees attackers coming in. A network sensor on the egress path sees what goes out: an
implant calling home, a slow drip of data to a host nobody else uses, a desktop pasting into a
public chatbot. The payloads are encrypted, so AEGIS works from metadata: when, how often, how
much, to whom, and with which certificate and client TLS stack.

**What it reads** (`ingest/ndr.py`):
- Zeek JSON logs: `ssl` (SNI, JA4 / JA3 / JA3S, certificate chain, validation), `conn` (bytes
  each way) and `x509` (subject, issuer, validity, SANs), joined by connection uid and
  certificate fingerprint.
- Suricata EVE `tls` + `flow` events, joined by `flow_id`.
- Any proxy, firewall or Zscaler feed shaped to `src_ip`, `dst_ip`, `sni` / `host`,
  `bytes_out` and `bytes_in`.

It reads a file (`AEGIS_SOURCES=ndr`, `NDR_EVENT_FILE`), a push (`POST /ingest/ndr?sensor=zeek`)
or an Event Hub (`AEGIS_EVENTHUB_SOURCE=ndr`). Raw events never reach the model; a bounded
detector (`agents/ndr/egress.py`) emits findings, and only those reach the orchestrator.

**What it finds**, per (internal host, destination). The destination is the SNI, or the server
IP when there is none:

| Finding | When | Alone it is |
|---|---|---|
| beacon | ≥ 8 handshakes over ≥ 10 min, median interval 5 s – 6 h, jitter (MAD / median) ≤ 0.2 (stricter while the sample is small), to a **rare** destination | suspicious 0.70 (0.60 when the client is a browser: a polling tab) |
| exfiltration | ≥ 50 MB sent within 6 h and ≥ 5 × what came back, to a rare destination | suspicious 0.70 |
| known-bad TLS | the server's certificate (SHA1 / SHA256) or name is on the TLS IOC list (`AEGIS_TLS_IOC_FILE`: JSONL, or abuse.ch SSLBL CSV exports), or a feed domain / IP in the threat-intel store; a client JA3 / JA4 or server JA3S match is one strong signal | malicious ≥ 0.90 for a certificate or name |
| shadow AI | an AI service (OpenAI, Anthropic, Gemini, Vertex, Azure OpenAI, Bedrock, Mistral, Cohere, Groq, DeepSeek, Perplexity, Hugging Face… — public hostnames, extendable) that the host is not registered for in `AEGIS_AI_REGISTER`; a second finding on ≥ 10 MB uploaded within an hour | suspicious 0.55 / 0.70 |

**Rare** means at most `AEGIS_NDR_RARE_MAX_SRCS` (3) internal hosts talk to the destination.
OS updates, EDR telemetry and chat presence all beacon, from every host, and prevalence is what
keeps them quiet. Certificate oddities never alert on their own, they corroborate:
- strong: a tool's default subject (OpenSSL's "Internet Widgits Pty Ltd" and similar);
- medium: a self-signed certificate;
- weak: issued days ago, a name mismatch, an untrusted chain, or no SNI.

The verdict follows the corroboration rule the model is trained on. Two strong signals (a beacon
to a server with a tool-default certificate) give `malicious` 0.90, and one strong plus two
weaker give 0.85. `malicious` proposes `isolate` the host, `block_egress` the destination and
`escalate`, all human-approved: egress control is the proxy or firewall team's change, and the
WAF connectors act on the internet edge. `suspicious` gets `monitor` (auto) and `escalate`.

**Shadow AI → the AI inventory** (RBI FREE-AI Rec 23). `AEGIS_AI_REGISTER` lists the bank's AI
systems as `host,system,endpoints` (CSV) or JSONL. An empty host approves an endpoint for
everyone, which is how the enterprise tenant is listed. Every sighting lands in a register of
discovered usage (`AEGIS_SHADOW_AI_REGISTER`, JSON), marked registered / approved / unapproved /
unregistered: the coverage evidence a CISO hands the regulator. With the dashboard connected the
changed rows are shipped to `/api/soc/ai-usage` (alembic 053), and `/ai-registry` shows **AI
services seen in use** under the onboarded register, the gaps first.

**Measured** — `python -m aegis.eval.egress_bench` (CI gate) runs a simulated office through the
real pipeline: 42 hosts and three hours of Zeek-shaped TLS metadata. Every host beacons to its
OS vendor, EDR and chat service. Uploads go to the corporate share, and the registered AI
system calls its tenant. The threats run against that background:

| scenario | found | judged |
|---|---|---|
| implant: 60 s ±6 %, TLS 1.2, self-signed, tool-default subject, 2 days old | 13.9 min | malicious 0.90 |
| implant over TLS 1.3 (no certificate visible): 300 s ±10 % | 37.6 min | suspicious 0.70 |
| slow exfiltration, ~1 MB/min to a rare storage host | 76.7 min | suspicious 0.75 |
| a server whose certificate is on the IOC list | first connection | malicious 0.95 |
| unregistered desktop calling a public AI API, ~15 MB an hour | 0.7 min after it starts; upload at 0.70 | suspicious 0.70 |
| registered AI system calling a provider outside its approval | first connection | suspicious 0.55 |
| benign: every host's vendor beacons, file-share uploads, registered / approved AI use | — | nothing |
| benign: a trader's browser tab polling a niche site every 30 s | yes | suspicious 0.60 — the honest false-positive class |

Every gated scenario was found in all of 12 random worlds, with no `malicious` verdict and no
containment proposal on a benign host. Reported but not gated:
- C2 behind a name every host already uses is hidden by prevalence;
- a single long-held connection makes no new handshakes;
- a beacon with ±60 % jitter is caught in 5 of 12 worlds, late.

Sample data (`ingest/fixtures/ndr/`, invented values, a 30-minute slice of the same world): the
same connections as Zeek (`zeek_tls.sample.jsonl`) and Suricata (`suricata_eve.sample.jsonl`),
the TLS IOC list in both formats (`tls_ioc.sample.jsonl`, `sslbl.sample.csv`), and the AI
register (`ai_register.sample.csv`). Run `AEGIS_SOURCES=ndr
NDR_EVENT_FILE=aegis/ingest/fixtures/ndr/zeek_tls.sample.jsonl
AEGIS_TLS_IOC_FILE=aegis/ingest/fixtures/ndr/sslbl.sample.csv
AEGIS_AI_REGISTER=aegis/ingest/fixtures/ndr/ai_register.sample.csv
AEGIS_SHADOW_AI_REGISTER=shadow_ai.json python -m aegis.service --once` and eight findings come
out, two of them malicious, along with the register (`tests/test_ndr.py`). Regenerate the files
with `--write-fixtures DIR`.

---

## What the network itself says

Security and network operations read the same wires. A fibre cut, a flapping uplink, a config
push that broke BGP, a WAN link at 95 % — the NOC sees those as hundreds of vendor alarms; the SOC
needs to know whether the outage is an accident or the first move of an attack (an unticketed
change on a distribution switch at 02:00 looks the same from the syslog either way). AEGIS
carries one **network-assurance** detector (`agents/netops/assurance.py`, deterministic, no model)
for both audiences.

**What it reads** (`ingest/netops.py`): Cisco IOS / IOS-XE / NX-OS system messages
(`%LINK-3-UPDOWN`, `%ETHPORT-5-IF_DOWN_*`, `%OSPF-5-ADJCHG`, `%BGP-5-ADJCHANGE`, `%SYS-5-CONFIG_I`,
hardware and environment facilities) as raw relay lines or JSON-wrapped; SNMP traps (`linkDown`,
`bgpBackwardTransition`, FRU and sensor traps); NetFlow / IPFIX / sFlow records; streaming telemetry
(gNMI / MDT or SNMP-polled interface counters); configuration snapshots from RANCID / Oxidized / NSO
(hash + change ticket + user); and LLDP / CDP neighbour tables for topology. Interface names are
canonicalised (`Gi1/0/49` ≡ `GigabitEthernet1/0/49`, `Eth1/49` ≡ `Ethernet1/49`) so both ends of a
link match.

**What it does.** From LLDP it keeps the graph; for every link-down it asks *who loses their path
to a core if this link goes* (a reachability diff, so a dual-homed switch losing one uplink has
nothing downstream and is **medium / redundant**, a single-homed one is **critical** with its
users counted). Everything that then arrives from inside that blast radius — the far end's view,
the access switches' uplinks, their OSPF dead timers, their silence — is folded into the one
incident as symptoms, for as long as the link stays down and a grace window after it comes back.
Edge ports (anything the topology does not know) never alert on a single transition — users
unplug things all day — but five transitions in five minutes on *any* interface is a **flap**, once
per episode. Telemetry gives **interface errors** (CRC rate), **congestion** (utilisation over N
samples) and **device unreachable** (silence). A configuration whose hash differs from the golden is
**drift**; drift **with a change ticket** is benign; drift **without one, followed inside ten
minutes by that device losing an adjacency or a link**, is a **bad config push** — `malicious`,
with `config_rollback` to golden and `revoke_sessions` for whoever pushed it, both held for a human.

| Fault | Verdict | Proposed (all HITL except monitor) |
|---|---|---|
| `link_down` with downstream | suspicious 0.90, critical | escalate, monitor the far end |
| `link_down` redundant | suspicious 0.75, medium | escalate, monitor |
| `link_flap` | suspicious 0.80 | `interface_shutdown` of the flapping port, escalate |
| `adjacency_loss` | suspicious 0.80 | escalate, monitor |
| `bad_config_push` | **malicious 0.88**, critical | `config_rollback`, `revoke_sessions` (pusher), escalate |
| `config_drift` (ticketed / unticketed) | benign 0.70 / malicious 0.80 | monitor / `config_rollback`, escalate |
| `interface_errors`, `congestion` | suspicious 0.70 | escalate, monitor |
| `device_unreachable` | suspicious 0.75 | escalate |

**Measured** — `python -m aegis.eval.network_fault_bench` (CI gate) runs a simulated 48-device
campus/WAN (two cores, four distribution switches of which one is single-homed, forty access
switches with users, two WAN edges) for three hours with per-minute telemetry, LLDP and 400
edge-port plug/unplug events, and injects eight faults. Every one is caught at its root device and
port; the single-homed fibre cut turns **53 vendor alarms into one alert** (10 downstream switches,
~1,000 users, 53 symptoms folded in); the dual-homed cut is medium with nothing stranded; the
flapping port is one alert with a port-shut proposal, not eight; the unticketed push is malicious
with a rollback, the ticketed one never is; and across the healthy devices and the plug/unplug
churn there are **zero alerts and zero remediations proposed**.

**Feeding it.** A file (`AEGIS_SOURCES=netops NETOPS_EVENT_FILE=…`, raw syslog and JSON lines may
be mixed; `ingest/fixtures/netops/campus.sample.log` is a small worked example), a push
(`POST /ingest/netops?feed=syslog|snmp|netflow|telemetry|config|lldp`, NDJSON or raw lines, gzip
accepted), or the stream receiver's content sniff (a line with `%FACILITY-SEV-MNEMONIC:` or an
LLDP row is routed here whatever the source said). Most banks already land all of this on
**Kafka**, which is what the **Java Kafka bridge** ([`kafka-bridge/`](../kafka-bridge/README.md),
Kafka Streams) is for: it consumes `aegis.syslog` / `aegis.netflow` / `aegis.telemetry` /
`aegis.alerts`, dedupes re-deliveries, folds a bouncing port's transitions, batches to
`/ingest/netops` with backpressure (an AEGIS 503 stops consumption instead of dropping), and
produces every finalised evidence chain from `GET /ingest/verdicts?after=<seq>` to
`aegis.verdicts`, keyed by alert id with the hash-chain position in the headers, so SOAR, the
SIEM and the CMDB read AEGIS decisions as a stream.

---

## What happens after the verdict

**Inline swarm** (`orchestrator/swarm.py`, on by default — `AEGIS_SWARM=0` turns it off, ≤ 60 s) — on a suspicious /
malicious / uncertain verdict, short-lived parallel workers each do one job: IOC extract,
intel enrichment, deception check, one-hop blast radius, log-hunt queries for the analyst,
patch proposal, analyst brief. Their evidence is merged, the voter re-scores, and the swarm
**never lowers a verdict**.

**Async investigation tier** (`orchestrator/walkers/`, `AEGIS_INVESTIGATE=1`) — runs after the
card is filed and updates it in place:

| Step | Module | Output |
|---|---|---|
| Walk | `walk.py` | six walkers (identity, endpoint, network, cloud, data, transaction) expand from the alert's entities hop by hop through a `TelemetrySource` |
| Blast graph | `graph.py` | reached nodes scored by sensitivity ÷ distance; critical ≥ 0.85 (core banking DB, SWIFT gateway, domain controller, KMS, PII tables…); exact single-edge choke points |
| Plan | `mitigation.py` | minimum cut over *actions* (revoking one session beats locking nine accounts), ranked by protected sensitivity ÷ business disruption, rollback text per step, auto-safe steps (throttle, challenge) first, containment under HITL |
| Twin | `twin.py`, `AEGIS_TWIN=1` | persona attackers play abstract moves over the graph for N rounds: exposure (share of futures reaching a crown jewel) vs. with the plan → **plan effectiveness**; re-ranks the plan |
| Loop | `loop.py` | after each approved step executes, re-walk; did the critical set shrink, did the attacker move? |

The HITL card shows all of it — blast graph by hop, plan table, twin bars, containment
timeline (`acp-dashboard/frontend/src/components/InvestigationPanel.tsx`, or the ServiceNow
work notes). The verdict is asserted unchanged everywhere in this tier.

**Response** (`agents/response/`) — every action goes through a connector with idempotency,
TTL and rollback; shadow mode (`AEGIS_ENFORCEMENT_MODE=shadow`, default) records what *would*
have happened as a receipt. Auto-safe actions run immediately; `block` / `isolate` / `lock` /
`revoke` / `rotate` wait for a human (except a narrow, short-TTL block under tiered autonomy,
above), and on `AEGIS_PROTECTED_TARGETS` need two: the first approval leaves the card
`awaiting_second` (kept across restarts), the same person cannot give the second, and a different
approver runs it. That works end to end in the standalone console; the ACP dashboard and ServiceNow
must also accept a second approval on an approved item. `AEGIS_PROTECTED_TARGETS` matches a CIDR only
when the target is a bare IP; a `/32` spelling, a `host:` prefix or an EDR device id is not matched
yet (review W4). A rolling cap of `AEGIS_HIGH_IMPACT_MAX` (default 10) high-impact actions per
`AEGIS_HIGH_IMPACT_WINDOW_SEC` (default 60) bounds a compromised agent. An approval that cannot run
yet (over the cap, a vendor error) stays pending and is retried; only after that does it settle
`failed`, shown in the console as "Approved — NOT executed". `python -m aegis.shadow report` compares receipts with what
analysts decided and says which actions are ready to flip live. With `--dashboard` it reads the
decisions from ACP; standalone (`--receipts` / `--audit`) it has no source of analyst decisions
yet, so every group stays `unreviewed` (review C8).

---

## The model: data, fine-tune, gate, retrain

| Stage | Command | Notes |
|---|---|---|
| Realistic training data | `python -m aegis.dataset build-public --out runs/public --n 50000` | SigmaHQ rules + OTRF datasets + product-native envelopes for the whole CISO stack (CrowdStrike, Sophos, Defender/Sentinel/MDI/MDCA/MDO, Zscaler, Imperva/F5, XSOAR) + corroboration, agentic-attacker, TLS-identity and endpoint rows + injection. Labels encode **policy**, never real CVE ids or payloads; eval fingerprints are excluded |
| Analyst-labelled data | `python -m aegis.dataset export --out runs/export --dashboard` | chains joined with approve / reject decisions and rationale |
| Fine-tune | `bash aegis/finetune/run_local.sh` | QLoRA on Qwen3-8B (RTX 4080 12 GB, ~10 s/step); `RESUME=1` continues a died run |
| Gate | `python -m aegis.finetune.gate --adapter <dir>` | 37 historical (≤ 5 misses) + 9 injection (0 leaks), plus agentic and endpoint corpora tracked; writes `gate.json` with the raw output of every miss |
| Use it | `LLM_BACKEND=local AEGIS_LOCAL_4BIT=1 AEGIS_MODEL=<adapter>` | base model + LoRA loaded on the SOC host |
| Retrain loop | `python -m aegis.finetune.retrain run` · `shadow` · `propose` · `sync` | weekly: new analyst rows → train → gate → shadow on decisions *newer than the export* → a `model_promotion` proposal a human accepts → `current.json`, read via `AEGIS_MODEL_POINTER`. A model never promotes itself |

First gate pass: `triage-qwen3-8b-public-v3` — 33/37 historical, 9/9 injection, against the
frontier baseline's 32/37.

---

## Threat intelligence

- **IOC store** (`agents/threat_intel/`) — STIX 2.1, MISP, Recorded Future, Tenable, peer sync,
  mock seed; distributed into the perimeter and EDR matchers. Every indicator passes a gate
  (`validate.py`): unknown kinds and malformed values are refused, and so is the bank's own space
  (RFC 1918, CGNAT, loopback / reserved, `AEGIS_INTERNAL_NETS`, `AEGIS_NEVER_BLOCK*`,
  `AEGIS_INTERNAL_DOMAINS`). Values are normalised and confidence clamped to 0–1. Expired
  indicators are taken back out of the matchers on the next sync (seed entries are never touched).
  Indicators the LLM extracts from an advisory are untrusted: confidence ≤
  `AEGIS_TI_LLM_MAX_CONFIDENCE` (0.6), expiry `AEGIS_TI_LLM_TTL_SEC` (3 days), tagged
  `llm-extracted`, kept as lookup evidence, and pushed into the matchers only with
  `AEGIS_TI_MERGE_LLM_IOCS=1`. An LLM copy of an indicator a feed already supplied is ignored, so
  it cannot de-list the feed entry.
- **CISA KEV + NVD 2.0 + EPSS** (`cve_feeds.py`, `AEGIS_CVE_INTEL=1`) — cached, incremental,
  rate-limited (`NVD_API_KEY` raises the limit); KEV entries become CVE IOCs tagged with vendor,
  product, due date and ransomware use; NVD CPE ranges give `vuln_discovery.dependency_scan`
  live matches with real CVSS / KEV / EPSS. A feed outage keeps the last good cache.
- **Client-exposure scan** (`vuln_discovery/client_exposure.py`) — 14 per-stack checks for what
  an attacker's AI agent harvests first: source maps in production, secrets in bundles, debug /
  profiler / `.env` routes, `DEBUG` flags, browsable API, GraphQL introspection, mobile
  pinning, CSP / SRI, exposed admin.

---

## Connecting a bank

The onboarding order, with what the bank provides at each step. For an on-prem / air-gapped
install (editions, hardware and GPU sizing, offline bootstrap, firewall matrix), see
[`docs/deploy/onprem-bank.md`](../docs/deploy/onprem-bank.md). The exact per-feed wiring commands
(Zeek → `/ingest/ndr`, Cloudflare Logpush → `/ingest/waf`, …) are in the
[feed-wiring runbook](../docs/runbooks/wiring-feeds.md). An app with no WAF of its own can be fronted
by the **edge shim** (`scripts/aegis_edge.py`), which inspects, forwards to `/ingest/alerts`, and
enforces the blocklist; the investigation layer reasons over the bank's own topology when an estate
export is supplied (`AEGIS_TENANT=inventory`, `AEGIS_TENANT_FILE` — see `InventorySource`).

**1. Alert sources** — `AEGIS_SOURCES`:

| Source | Consumer | Config |
|---|---|---|
| `sentinel` | Log Analytics query over `SecurityAlert`, entity graph folded into user / host / IP / url / process / hash | `SENTINEL_WORKSPACE_ID`, `_TENANT_ID`, `_CLIENT_ID`, `_CLIENT_SECRET`, optional `SENTINEL_KQL`, `SENTINEL_TIMESPAN` |
| `splunk` | REST export search | `SPLUNK_URL`, `SPLUNK_TOKEN`, `AEGIS_SPLUNK_SEARCH` |
| `waf` | Imperva / F5 ASM (CEF, F5 key=value, JSON lines); Cloudflare Logpush `firewall_events` and GraphQL `firewallEventsAdaptive`; AWS WAFv2 logs (S3 / Firehose / CloudWatch); Azure Front Door and App Gateway WAF diagnostics, nested or flattened `AzureDiagnostics`, Event Hub `{"records": […]}`; plain or `.gz` | `WAF_EVENT_FILE` |
| `acp` | ACP governance events (full edition) | `ACP_DASHBOARD_URL`, `ACP_API_KEY` |
| **push** (`stream`, added automatically) | **vendors push to AEGIS**: `POST /ingest/cloudflare` (Logpush HTTP destination, gzip NDJSON), `POST /ingest/firehose` (Kinesis Firehose HTTP endpoint: base64 records, `requestId` echoed), `POST /ingest/waf` (any forwarder: NDJSON / CEF / F5, plain or gzip), `POST /ingest/alerts` (normalised AEGIS alerts) | `AEGIS_INGEST_HTTP=1`, `AEGIS_INGEST_BIND` (default `0.0.0.0:8787`), **`AEGIS_INGEST_TOKEN`** (required off loopback; sent as `Authorization: Bearer`, `X-Amz-Firehose-Access-Key` or `X-AEGIS-Token`), `AEGIS_INGEST_MAX_MB`, `AEGIS_STREAM_CAPACITY` |
| `apigw` | API-gateway access logs (Azure APIM, AWS API Gateway, Kong, generic JSON) → object-walk (BOLA) detector; only its alerts are yielded. Push: `POST /ingest/apigw?gateway=apim` | `APIGW_EVENT_FILE`, `AEGIS_OWNERSHIP_FILE` or `AEGIS_OWNERSHIP_URL` (+ `_TOKEN`), `AEGIS_APIGW_PRINCIPAL_FIELD`, `AEGIS_BOLA_*` |
| `eventhub` | Azure WAF diagnostics streamed through an Event Hub (`azure-eventhub`, optional dependency); per-partition checkpoint in a local file | `AEGIS_EVENTHUB_CONN` (with `EntityPath=` or `AEGIS_EVENTHUB_NAME`), `AEGIS_EVENTHUB_GROUP`, `AEGIS_EVENTHUB_START=latest\|earliest`, `AEGIS_EVENTHUB_CHECKPOINT` |
| `sample` | built-in alerts | — |

**Push versus poll.** A polled source is read once per `AEGIS_POLL_SECONDS`; a pushed event
wakes the service loop and gets its verdict in milliseconds (`stream pass … handle_ms=`), with
the poll interval untouched. The push queue is bounded: when full the receiver answers **503**
and the vendor retries (Firehose then backs the batch up to S3) — nothing is silently dropped,
and re-delivered batches dedupe on the vendor event id. Put the bank's load balancer or reverse
proxy in front of the port for TLS. `GET /healthz` shows queue depth and counters. Every pushed
alert carries `received_at` and `ingest_lag_ms` (vendor timestamp → AEGIS receipt).

**Edge enforcement hook.** `GET /ingest/blocklist` (same token) serves the active enforcement
set — IPs, CIDRs and client fingerprints with expiry — so an inline enforcer the bank already
runs (Envoy `ext_authz`, a Cloudflare Worker, the Go tier-0 filter in `aegis/edge/`) can apply
AEGIS's decisions at the edge in microseconds without any vendor API. Shadow (dry-run)
receipts are never served.

Detection is bounded by what the bank logs: without WAF / CDN logs there is no agentic-chain
detection on the web tier.

**2. Approvals** — `AEGIS_HITL_TRANSPORT`:

| Transport | How a human decides |
|---|---|
| `dashboard` | Approve / Reject (with rationale) on the ACP Approvals page |
| `servicenow` | one incident per approval (Table API); set `u_aegis_decision` or resolve with an *Approved* close code; the investigation lands in work notes. `AEGIS_SERVICENOW_URL`, user/pass or `_TOKEN`, `_TABLE`, `_ASSIGNMENT_GROUP` |
| `file` | the console (or `python -m aegis.hitl decide <id> approve --by <name>`) writes a **signed** row to `decisions.jsonl`; only signed rows execute, and no row may claim an `aegis:` approver. The key is `AEGIS_DECISION_KEY`, or derived from `AEGIS_CONSOLE_TOKEN` (so every `install.sh` host signs); with neither, rows are accepted unsigned with a warning (lab only). Optional `AEGIS_SLACK_WEBHOOK` notify. `AEGIS_HITL_DIR` |

Pending approvals survive a restart on every transport: each filed card and each settlement is
journalled (`AEGIS_HITL_STATE`, default `<AEGIS_HITL_DIR or ./.aegis-hitl>/pending.jsonl`, `off`
to disable) and replayed on start, so a decision taken while AEGIS was down is executed on the
next cycle. A journal that cannot be written is logged at WARNING and never blocks filing.
| `stdout` | printed card |

**3. Response connectors** — shadow first, always:

```
AEGIS_WAF_VENDOR=imperva   AEGIS_WAF_SITE_ID  AEGIS_WAF_API_ID  AEGIS_WAF_API_KEY  [AEGIS_WAF_RATE_LIMIT]
AEGIS_WAF_VENDOR=f5        AEGIS_WAF_URL  AEGIS_WAF_POLICY_ID  AEGIS_WAF_USER/PASS or AEGIS_WAF_TOKEN
AEGIS_WAF_VENDOR=cloudflare AEGIS_CF_API_TOKEN  AEGIS_CF_ZONE_ID (or AEGIS_CF_ACCOUNT_ID for account-wide rules)
                           [AEGIS_WAF_RATE_LIMIT  AEGIS_CF_RATE_PERIOD  AEGIS_CF_MITIGATION_TIMEOUT]
AEGIS_WAF_VENDOR=aws       AEGIS_AWS_REGION  AEGIS_AWS_WAF_IPSETS="block=<name>/<id>,challenge=<name>/<id>,throttle=<name>/<id>"
                           [AEGIS_AWS_WAF_RULE_GROUP=<name>/<id>  — AEGIS-owned rule group for fingerprint rules]
                           [AEGIS_AWS_WAF_SCOPE=REGIONAL|CLOUDFRONT]  keys: AEGIS_AWS_ACCESS_KEY_ID/_SECRET_ACCESS_KEY, AWS_* or instance role
AEGIS_WAF_VENDOR=azure     AEGIS_AZURE_SUBSCRIPTION_ID  AEGIS_AZURE_RESOURCE_GROUP  AEGIS_AZURE_WAF_POLICY
                           [AEGIS_AZURE_WAF_FLAVOR=frontdoor|appgw  AEGIS_AZURE_WAF_PRIORITY=10  AEGIS_AZURE_WAF_ACTIONS]
                           auth: AEGIS_AZURE_TENANT_ID/_CLIENT_ID/_CLIENT_SECRET, AEGIS_AZURE_TOKEN, or managed identity (azure-identity)
AEGIS_SOAR_VENDOR=xsoar    AEGIS_SOAR_URL  AEGIS_SOAR_API_KEY  AEGIS_SOAR_PLAYBOOKS="isolate=Isolate-Host,isolate.undo=Release-Host"
AEGIS_SOAR_VENDOR=sentinel AEGIS_SOAR_PLAYBOOKS="revoke_sessions=<Logic App trigger URL>"
AEGIS_EDR_VENDOR=crowdstrike AEGIS_EDR_CLIENT_ID  AEGIS_EDR_CLIENT_SECRET  [AEGIS_EDR_URL]
AEGIS_EDR_VENDOR=defender  AEGIS_EDR_TENANT_ID  AEGIS_EDR_CLIENT_ID  AEGIS_EDR_CLIENT_SECRET (or managed identity)
AEGIS_EDR_VENDOR=sentinelone AEGIS_EDR_URL  AEGIS_EDR_TOKEN
AEGIS_EDR_VENDOR=trend     AEGIS_EDR_URL (regional API, e.g. https://api.in.xdr.trendmicro.com)  AEGIS_EDR_TOKEN
AEGIS_FW_VENDOR=panos      AEGIS_FW_URL  AEGIS_FW_TOKEN (API key)  [AEGIS_FW_TAG_SRC=aegis-block-src  AEGIS_FW_TAG_DST=aegis-block-dst]
AEGIS_FW_VENDOR=fortigate  AEGIS_FW_URL  AEGIS_FW_TOKEN (REST admin token)  [AEGIS_FW_VDOM]
AEGIS_IDP_VENDOR=entra     AEGIS_IDP_TENANT_ID  AEGIS_IDP_CLIENT_ID  AEGIS_IDP_CLIENT_SECRET  [AEGIS_IDP_PROTECTED=breakglass@bank.in,…]
AEGIS_IDP_VENDOR=ad        AEGIS_AD_URL (ldaps://)  AEGIS_AD_BASE_DN  AEGIS_AD_BIND_DN  AEGIS_AD_BIND_PASSWORD  [AEGIS_AD_CA]   (pip install 'aegis[ad]')
AEGIS_PAM_VENDOR=cyberark  AEGIS_PAM_URL  AEGIS_PAM_USERNAME  AEGIS_PAM_PASSWORD
AEGIS_PAYHOLD_VENDOR=api   AEGIS_PAYHOLD_URL (https)  AEGIS_PAYHOLD_TOKEN  AEGIS_PAYHOLD_SIGNING_KEY   (the bank's adapter: deploy/payment-hold/openapi.yaml)
AEGIS_BLOCK_FEED=1         firewalls pull GET /ingest/blocklist?format=txt[&kind=dst] (read token; bearer or basic auth)
AEGIS_ENFORCEMENT_MODE=shadow   AEGIS_PROTECTED_TARGETS="cbs-db,swift-gw,dc-*"
```

The bank stack (each has a `mock…` vendor for a lab; a private CA → `SSL_CERT_FILE`):

| Control point | Vendor | Actions | What AEGIS changes | Undo / read-back | Least privilege |
|---|---|---|---|---|---|
| Firewall | Palo Alto PAN-OS | block (source), block_egress (destination), one IP | registers the IP with a timed tag (TTL) in two Dynamic Address Groups the bank wires to deny rules once; never edits rules or commits | unregister / `show object registered-ip` | API role: User-ID + operational show only |
| Firewall | Fortinet FortiGate | block (source), one IP — the banned list drops traffic *from* an address, so not egress | banned-IP quarantine list with an expiry (TTL); an IP that is already banned is left as it is (never shortened) | clear (not a pre-existing ban) / list banned | REST admin profile limited to user-quarantine |
| EDR | Defender for Endpoint | isolate (Full) | device isolation (resolves host name → one device, or the device id); a device already isolated is recorded as pre-existing | unisolate (not a pre-existing isolation) / newest machine action | `Machine.Isolate`, `Machine.Read.All` |
| EDR | SentinelOne | isolate | agent network disconnect; an agent already disconnected is recorded as pre-existing | connect (not a pre-existing one) / `networkStatus` | API user with disconnect / connect |
| Identity | Entra ID | revoke_sessions, force_logout (one-shot); lock_account | revoke all refresh tokens; disable the account + revoke | re-enables only an account AEGIS disabled / `accountEnabled` | `User.Read.All`, `User.RevokeSessions.All`, `User.EnableDisableAccount.All` |
| Firewall | Check Point / any NGFW, by pull | block, block_egress (IP / CIDR) | nothing on the firewall: live blocks are listed at `/ingest/blocklist?format=txt` (`&kind=dst` for egress); a Network Feed object (R81.20+), PAN-OS EDL or FortiGate threat feed fetches it and one deny rule uses it | drops off the next fetch / not verifiable (AEGIS cannot see the last fetch) | the feed's read token only (basic-auth password) |
| EDR | Trend Vision One | isolate | endpoint isolation (resolves endpoint name → one agent GUID) | restore / a failed isolation task only (otherwise not verifiable) | API key with Response permissions |
| Identity | Active Directory (on-prem) | lock_account | sets `userAccountControl` ACCOUNTDISABLE over LDAPS with the DC certificate verified (`AEGIS_AD_CA` for a private CA); built-in Administrator / Guest / krbtgt refused, by name or RID even when renamed | re-enables only an account AEGIS disabled / the bit | delegated write of `userAccountControl` on the user OUs |
| Money | **AEGIS Payment Hold API** (the bank's adapter on its payment hub / switch / fraud engine) | hold: `outbound:<account>` (every outbound payment) or one transfer (`txn:<UTR / RRN / UETR>`) | a TTL'd hold that parks payments; never debits, credits or reverses. Each request is HMAC-signed over its method, path, timestamp, a one-time nonce and its body; the adapter refuses a stale timestamp or a reused nonce. A bare reference is refused (say `outbound:` or `txn:`). A transfer that already settled is reported as too late (escalate for recall), never as applied | release / the hold's state | a token and signing key for that one API, reachable only from the AEGIS host |
| PAM | CyberArk PVWA | rotate_credential (permanent, two-person) | immediate CPM password change of exactly one vaulted account (`account:<user>[@<address>]`) | cannot be undone / last-modified time | vault user allowed to initiate CPM changes only |

AD has no session revoke: Kerberos tickets that were already issued stay valid until they expire (10 h by default).
When that matters, pair an AD lock with `rotate_credential` or an EDR isolate. Check Point is served by the feed and
not by a Management API connector, because a direct write would need a publish and a policy install, which is a
change-window operation.

Principals on `AEGIS_IDP_PROTECTED` (break-glass accounts) are never locked, revoked or rotated by AEGIS. The list is
checked against every name the resolved account goes by (object id, UPN, sAMAccountName, mail nickname, vault user
name), not only the target as written. One-shot actions (revoke sessions, rotate a password, kill a process) run at
the vendor every time they are approved; they never leave an "active" receipt behind that a later apply would treat as
already done.

Routing precedence: OpenShell, WAF, payment hold, SOAR, EDR, SWG, firewall, identity, PAM, then the pull feed. A WAF
therefore takes IP `block` and a SWG (Zscaler) takes `block_egress` before the firewall connector;
`AEGIS_PREFER_FIREWALL=1` puts PAN-OS / FortiGate right after OpenShell instead. Direction prefixes are honoured: a
`src:` target is only blocked inbound, a `dst:` one only outbound. Whether an
action may run unattended is decided by its action contract and the autonomy tier, the same as for every other
connector. `isolate` is SEVERE. `rotate_credential` is IRREVERSIBLE and needs two people. Everything runs in shadow
until `AEGIS_ENFORCEMENT_MODE=live`.

How each WAF is bound:

| WAF | Reads (ingest) | Acts (connector) | What AEGIS owns on the vendor side | Least privilege |
|---|---|---|---|---|
| Imperva | CEF / JSON export | block, challenge, throttle | one site rule per (action, IP) | API id with site rule edit |
| F5 BIG-IP AWAF | CEF / key=value / JSON | block | one ASM IP-address exception per IP | ASM policy editor |
| Cloudflare | Logpush / GraphQL (incl. JA4 / JA3) | block, managed challenge (IP Access Rules); throttle (rule in the zone's `http_ratelimit` ruleset); fingerprint block / challenge (custom rule; needs Bot Management for `cf.bot_management.ja4`) | individual rules, noted `aegis …`; a rule that already existed is never deleted | token: Firewall Services Edit (+ Zone WAF Edit for throttle and fingerprint rules) |
| AWS WAF | WAFv2 logs (incl. JA4 / JA3, header order) | whatever rule the bank points at each IP set (block / CAPTCHA / challenge / rate-based); fingerprint block / challenge in an AEGIS rule group | **membership only** of the IP sets in `AEGIS_AWS_WAF_IPSETS`, plus the rules of one AEGIS rule group the bank references once from its WebACL — the WebACL stays the bank's | `wafv2:GetIPSet` + `wafv2:UpdateIPSet` on those sets (+ `GetRuleGroup` / `UpdateRuleGroup` on the AEGIS rule group) |
| Azure Front Door / App Gateway WAF | diagnostic logs | block, JSChallenge, rate limit | three custom rules (`aegisblock`, `aegischallenge`, `aegisthrottle`) — created on first use, removed when empty; the bank's rules are carried through every PUT untouched | custom role with read/write on that one policy |

Concurrency is handled the vendor's way (AWS `LockToken`, Azure `etag`/`If-Match`, both re-read
and retry), so AEGIS and an analyst editing the same list do not overwrite each other. The AWS
signer is checked against AWS's published SigV4 example and botocore. API field names follow
the public docs; the first real-tenant run may need a field renamed.

After two weeks, `python -m aegis.shadow report` lists what is ready to go live, lowest blast
radius first.

**4. Topology** — the walkers need a `TelemetrySource` over the bank's own systems (sessions
for a user, lateral logons from a host, flows from an IP, roles for a principal, tables
queried, beneficiaries of an account). The contract is `walkers/sources.py`; today only
`MockTenant` implements it, so writing the bank's adapter is the main onboarding build.
Crown-jewel sensitivities are in `walkers/graph.py::SENSITIVITY`.

**5. Decoys** — plant `canaries_for(stack)` output on the web tier (`AEGIS_STACKS=react,django,…`).

**6. Model** — `LLM_BACKEND=local AEGIS_MODEL=<adapter>` for no data egress; optional frontier
voter via `ANTHROPIC_API_KEY`. PII tokenization (`AEGIS_PII_TOKENIZATION=1`, default) runs
before any model call.

**7. Smoke** — `python -m aegis.service --once` on the bank's environment, then
`python -m aegis.eval.fault_injection` on the same host.

---

### OCSF and declarative connectors

* **OCSF in:** `POST /ingest/ocsf?product=<name>` takes OCSF events of any class (NDJSON, or JSON arrays per line) —
  AWS Security Lake subscribers, CrowdStrike, Okta, Cribl, Vector / Fluent Bit OCSF outputs — and maps them onto the
  alert fields the specialists read (`aegis/ingest/ocsf.py`). **OCSF out:** `GET /ingest/verdicts?format=ocsf`
  serves every verdict as an OCSF Detection Finding (class 2004) for a SIEM or data lake.
* **Sigma over OCSF:** set `AEGIS_SIGMA_RULES` to a SigmaHQ checkout, or the bank's own rules directory, and every
  OCSF event is run against those rules (`aegis/detect/sigma.py`). This covers `/ingest/ocsf`, Kafka `ocsf` topics and
  OCSF connectors. A hit is attached to the alert (`sigma`: rule id, title, level, ATT&CK techniques) and raises its
  severity to the rule's level. It decides nothing by itself; the swarm still investigates.
  * **Supported:** maps, lists, keywords (including key-less `'|all'` blocks), `null` and empty values; the modifiers
    `contains`, `startswith`, `endswith`, `all`, `re`, `cidr`, `exists`, `windash` (mixed `-` `/` and Unicode
    dashes at flag positions), `cased` and `lt` / `gt`; and conditions with `and` / `or` / `not`, `1 of` / `all of`.
  * **Skipped and counted, never half-run:** aggregations, `near`, the `base64*` / `utf16*` / `fieldref` modifiers, and
    any modifier the engine does not know (a time modifier, a typo).
  * **Field mapping:** the logsource picks the OCSF class (and, for process / file categories, the `activity_id`: a
    `process_creation` rule does not fire on a Terminate event). Sigma fields map to OCSF attributes
    (`CommandLine` → `process.cmd_line` …); outside Process Activity the process that acted is `actor.process`, so
    `Image` / `CommandLine` there resolve to it. `Hashes` reads OCSF hash objects as `SHA256=…`, and
    `c-uri-extension` is the URL path's extension.
  * **Linear matching.** Wildcard values are matched by literal pieces (`str.find`), never by a backtracking regex, so
    an attacker-written command line cannot stall ingest. Values are matched whole up to 32 KB. A rule's own `|re`
    stays a regular expression (trusted like the bank's SIEM trusts it), applied to the first 32 KB.
  * **Logsources covered:** Windows channels → Event Log Activity (1008); PowerShell script and module logging →
    Script Activity (1009); Linux auditd; AV detections → Detection Finding (2004); Kubernetes, Bitbucket and GitHub
    audit → API Activity (6003); plus the process, file, network, DNS, web, cloud and identity categories.
  * **Against SigmaHQ (Nov 2026):** 3,109 rules load. 52 are skipped: 25 below the level floor, 15 with a logsource
    that has no OCSF class, and 12 that use an unsupported modifier. On one core, a process event takes about 10 ms
    against the 1,724 process rules; an event-log or script event takes about 1–1.5 ms; a 32 KB adversarial command
    line about 0.4 s across every process rule.
  * `AEGIS_SIGMA_MIN_LEVEL` (default `low`) sets the lowest rule level loaded.
  * `python -m aegis.detect --rules <dir> events.ndjson` shows what loads and what fires.
* **Kafka at scale:** `AEGIS_SOURCES=kafka` joins a consumer group (`aegis/ingest/kafka.py`, extra `aegis[kafka]`).
  `AEGIS_KAFKA_TOPICS=sec.ocsf=ocsf,sec.edr=edr,waf.cf=cloudflare` maps each topic to an AEGIS source; offsets are
  committed only after the batch is queued, and a full queue holds the batch (the consumer stops fetching) instead of
  skipping it. SASL_SSL / SSL only (`AEGIS_KAFKA_BOOTSTRAP`, `_GROUP`, `_START`, `_SECURITY_PROTOCOL`,
  `_SASL_MECHANISM`, `_USERNAME`, `_PASSWORD`, `_CA`, `_CERT`, `_KEY`; PLAINTEXT needs `AEGIS_KAFKA_ALLOW_PLAINTEXT=1`).
  Run it with `AEGIS_STREAM_JOURNAL` set, so a committed batch is on disk before it is investigated. Several AEGIS
  readers in one group share the partitions.
* **Shippers:** `deploy/shippers/vector.toml` and `deploy/shippers/fluent-bit.yaml` send a bank's existing logs to
  `/ingest/ocsf` / `/ingest/edr` (gzip, disk buffer, retry on 503) or onto Kafka; tokens come from the environment.
* **Declarative pull connectors:** a connector is a YAML spec plus a recorded sample in `aegis/ingest/connectors/`.
  Enable with `AEGIS_SOURCES=kit:<name>`; credentials only from the environment (`{env:NAME}`); specs must be
  `read_only: true` (GET, or POST to a declared search endpoint), https only, bounded pages, next-links never followed
  to another host. `python -m aegis.ingest.kit list` shows the catalogue and each spec's verification level;
  `… kit test <name>` replays the sample with no network.

| Spec | Source | Verified |
|---|---|---|
| `okta` | Okta System Log | recorded sample |
| `msdefender` | Microsoft Defender XDR (Graph `alerts_v2`, OAuth client credentials) | recorded sample |
| `sentinelone` | SentinelOne threats | recorded sample |
| `qradar` | IBM QRadar offenses | recorded sample |
| `elastic` | Elastic Security detection alerts | recorded sample |

"Recorded sample" = the response shape from the vendor's API documentation, replayed in CI; a spec becomes
`live-tenant` only after a pull against a real tenant.

### MCP gateway (ask AEGIS from an AI assistant)

`python -m aegis.mcp` is a stdio MCP server, so an analyst's MCP client (Claude, an IDE assistant, an internal
copilot) can ask AEGIS what it found. Tools: `aegis_recent_verdicts` (optionally by verdict),
`aegis_get_evidence_chain` (by chain hash or alert id), `aegis_list_approvals` (pending by default),
`aegis_list_proposals`.

* **Backends.** By default it reads this host's audit file (`AEGIS_AUDIT_PATH`) and HITL directory (`AEGIS_HITL_DIR`).
  For a remote AEGIS, set `AEGIS_MCP_URL=https://…` (redirects are never followed — the token goes only to that
  address — and a loopback URL never goes through a proxy) and `AEGIS_MCP_TOKEN` (the read token); https only, http only to
  loopback.
* **Untrusted output.** Every result is redacted and wrapped as untrusted data, with prompt-injection and obfuscation
  flags. Evidence carries attacker-written text, and the client's model must read it as evidence, not instructions.
* **Never approves.** Approving a containment is a person's decision, made where they sign in. With
  `AEGIS_MCP_ALLOW_REJECT=1` and `AEGIS_MCP_USER=<name>`, a fifth tool, `aegis_reject_action`, can reject one pending
  action, which is the safe direction. A reason is required, the decision is signed like a console decision, and it
  is recorded as `mcp:<name>`. Remote rejects also need `AEGIS_MCP_CONSOLE_TOKEN`.

```json
{"mcpServers": {"bluedefence": {"command": "python", "args": ["-m", "aegis.mcp"],
  "env": {"AEGIS_MCP_URL": "https://aegis.bank.internal", "AEGIS_MCP_TOKEN": "<read token>"}}}}
```

## ACP integration (full edition)

- **The SOC brain is a governed agent** (`governance.py`, `SOC-AGENTQ-01`): every specialist,
  swarm worker, walker and the twin is a governed tool call — per-alert budget, Q30 allowlist,
  Q33 rate limit (`ACP_RATE_LIMIT`), and the dashboard pause-gate as a kill switch.
- **Q ↔ AEGIS bridge** — Q watches the bank's own AI agents; AEGIS watches the outside. With
  `AEGIS_SOURCES=…,acp`, a governed LangGraph agent that Q37 blocked or the pause-gate stopped
  becomes a SOC incident with a blast radius, a plan and a card, and is correlated with
  external traffic from its host. In the other direction, `threat_intel/publish.py` sends KEV /
  NVD advisories with `affects_frameworks` (from CPE) to the dashboard, so its hourly
  threat-impact scan matches live intel against each agent's framework.
- **Scope**: Q37 and the threat-impact scan cover agents running the ACP SDK. An *external*
  attacker's agent is detected by AEGIS alone — behavioural chains, canaries, the exposure scan.
- **Self-evolving rules** (`evolve/`): accepted meta-agent proposals arrive as a versioned rule
  feed and are applied in-process against an allowlist of patchable detection primitives —
  revertible, ReDoS-guarded; a feed outage keeps the last good rules.

---

## Failure handling and logging

No dependency failure may drop an alert silently or let a broken model close one.
`python -m aegis.eval.fault_injection` (a CI gate) runs the whole pipeline over the 67 eval
alerts with each dependency failing in turn and checks: **survives** (every alert gets a
sealed chain), **safe** (nothing auto-closed or auto-executed by a broken brain), **loud** (the
fault is logged at WARNING or above).

| Fault | What the SOC does | Log line |
|---|---|---|
| Primary LLM down | degraded chain: `uncertain`, confidence 0, escalate under HITL; deterministic paths still decide; nothing executes | `ERROR [orchestrator] alert X could not be investigated … escalating as uncertain` |
| LLM returns garbage | triage → perimeter; specialist → escalate | `WARNING [<specialist>] LLM verdict unparsable` |
| Voter down | counted as dissent → HITL | `WARNING [voter] no usable vote` |
| Dashboard down / refusing | stdout card; local audit stays authoritative; last good rules kept | `WARNING [hitl] … unreachable`, `[persist] … failed` (then one summary line per minute) |
| ServiceNow down | stdout card; pending approvals kept | `WARNING [hitl:servicenow] could not file approval` |
| Audit log unwritable | **fails closed** — no audit row, no action | `ERROR [service] alert X failed` — page on this |
| Telemetry source down | walk reports the error; verdict unchanged | `WARNING [walker.<name>] query failed` |
| Governance pause / block | workers, walkers, twin skipped; first-pass verdict stands | `WARNING [swarm.<w>] skipped by governance` |
| Vendor connector down | `failed` receipt parked for a human | `ERROR [connector:<vendor>] …` |
| KEV / NVD / EPSS down | last good cache | `WARNING KEV fetch failed` |
| Anthropic client cannot be built | falls back to the mock brain — treat as a page | `ERROR AnthropicClient unavailable … MOCK client` |

Conventions (ruff `S110/S112/BLE001/TRY400` clean on runtime paths): one `aegis.*` logger per
module; no silent `except: pass` — every catch logs or records the error on the object it
belongs to; a mock fallback is always an ERROR; an outage that fails every call logs the first
failure and then one summary per minute.

---

## Evaluation and CI gates

| Gate | What | Pass |
|---|---|---|
| `aegis.eval.run` | 37 historical alerts (verdict agreement) + 9 prompt-injection cases (no `allow`) | 37/37, 9/9 (mock); live frontier baseline 32/37 + 9/9 |
| `aegis.finetune.gate` | fine-tuned adapter on the same held-out set + agentic (13) and endpoint (8) chains tracked | ≤ 5 misses, 0 leaks |
| `aegis.eval.ai_red_team.run` | LLM-driven attacker with one adaptation step | 0 leaks, 0 evasion |
| `aegis.eval.investigation_quality` | 6 scripted worlds with known ground truth: radius completeness and precision, plan coverage and minimality, HITL policy, loop shrink, twin effectiveness | 6/6 |
| `aegis.eval.fault_injection` | 18 scenarios incl. the external edition with no dashboard and the push receiver | 18/18 |
| `aegis.eval.purple_team` | adaptive AI-agent attackers + customers, partner, proxy staff vs the real pipeline (mock Cloudflare, live enforcement) | gated campaigns detected and contained, zero collateral |
| `aegis.eval.egress_bench` | a simulated office's TLS metadata: implants, exfiltration, known-bad certificate, shadow AI among every-host vendor beacons | 6/6 found as expected, no `malicious` or containment on benign hosts |
| `aegis.eval.network_fault_bench` | a 48-device campus/WAN under eight injected faults among per-minute telemetry and edge-port churn | 8/8 at the right root cause, 53 alarms → 1 alert on the fibre cut, zero alerts on healthy devices, zero wrong remediations |
| `aegis.eval.swarm_timing` | live latency and cost per mode | verdict < 60 s |
| `pytest aegis/tests` | unit + integration | all green |
| Governed job | historical + injection evals under ACPGuard | no verdict drift, no blocks |

All run in `.github/workflows/aegis-ci.yml`. Live results: `aegis/eval/results/`.

---

## Configuration reference

| Area | Variables |
|---|---|
| Edition | `AEGIS_EDITION` (`external` · `soc` · `full`) |
| Model | `LLM_BACKEND` (`mock` · `local` · `anthropic` · `auto`), `AEGIS_MODEL`, `AEGIS_LOCAL_4BIT`, `AEGIS_MODEL_POINTER` (an adapter must carry its recorded digest; `AEGIS_ALLOW_UNVERIFIED_MODEL=1` overrides in a lab), `ANTHROPIC_API_KEY`, `AEGIS_VOTER_BACKEND`, `AEGIS_PII_TOKENIZATION` |
| Sources | `AEGIS_SOURCES`, `AEGIS_CHECKPOINT`, `AEGIS_POLL_SECONDS`, `AEGIS_MAX_ALERTS_PER_CYCLE`, Sentinel / Splunk / WAF / ACP variables above, `AEGIS_CHECKPOINT_FLUSH_S` (1 s: how often the ingest checkpoint is written; a crash re-delivers at most that much), `AEGIS_INGEST_POISON_MAX` (3: an alert that ended the process this many times is skipped), `AEGIS_HTTP_MAX_RETRY_AFTER` (30 s cap on a vendor's Retry-After) |
| Index | `AEGIS_INDEX_URL` (derived, rebuildable SQL index of the audit chain for the console and reports — `duckdb:///…` default, `sqlite:///…`, `postgresql+psycopg2://…`, `mssql+pyodbc://…`; one SQLAlchemy ORM, pick by URL), `AEGIS_INDEX=0` to disable; `python -m aegis.store reindex | stats` |
| Push / stream | `AEGIS_INGEST_HTTP`, `AEGIS_INGEST_BIND`, `AEGIS_INGEST_TOKEN`, `AEGIS_INGEST_READ_TOKEN` (optional separate token for `GET /ingest/verdicts|blocklist|license` and the console reads), `AEGIS_CONSOLE_TOKEN` (the analyst console's key: reads `/api/soc/*` + `/api/approvals` and may POST decisions — see `aegis/ingest/console_api.py`), `AEGIS_INGEST_MAX_MB`, `AEGIS_INGEST_MAX_INFLATE_MB` (cap on what a gzip body may expand to, default 64), `AEGIS_STREAM_CAPACITY`, `AEGIS_EVENTHUB_CONN`, `AEGIS_EVENTHUB_NAME`, `AEGIS_EVENTHUB_GROUP`, `AEGIS_EVENTHUB_START`, `AEGIS_EVENTHUB_CHECKPOINT`, `AEGIS_KAFKA_*`, `AEGIS_SIGMA_RULES`, `AEGIS_SIGMA_MIN_LEVEL` (see § OCSF and declarative connectors), `AEGIS_MCP_URL`, `AEGIS_MCP_TOKEN`, `AEGIS_MCP_CONSOLE_TOKEN`, `AEGIS_MCP_ALLOW_REJECT`, `AEGIS_MCP_USER` (see § MCP gateway), `AEGIS_STREAM_JOURNAL` (write-ahead file for pushed records: a batch is on disk before the vendor gets its 200, and what was not handled is queued again after a restart; off by default), `AEGIS_STREAM_JOURNAL_FSYNC` (`1`: fsync each batch); `POST /ingest/edr` takes Sysmon events and osquery result logs |
| Investigation | `AEGIS_CAMPAIGN_CONTEXT`, `AEGIS_CAMPAIGN_WINDOW_MIN`, `AEGIS_SWARM`, `AEGIS_SWARM_MAX_WORKERS`, `AEGIS_SWARM_MAX_SECONDS`, `AEGIS_INVESTIGATE`, `AEGIS_INVESTIGATE_MAX_SECONDS`, `AEGIS_INVESTIGATE_WORKERS`, `AEGIS_TWIN`, `AEGIS_TWIN_PERSONAS`, `AEGIS_TWIN_ROUNDS`, `AEGIS_MOCK_SPREAD`, `AEGIS_INVESTIGATE_MAX_QUEUED` (200), `AEGIS_SWARM_MAX_ABANDONED` (4 x workers: stuck threads before the swarm stops replacing its pool) |
| Approvals | `AEGIS_HITL_TRANSPORT`, `AEGIS_HITL_DIR`, `AEGIS_HITL_STATE`, `AEGIS_HITL_TIMEOUT`, `AEGIS_HITL_TIMEOUT_SEC`, `AEGIS_HITL_TIMEOUT_MIN_CONF`, `AEGIS_SLACK_WEBHOOK`, `AEGIS_SERVICENOW_*`, `AEGIS_SNOW_APPROVE_CODES` (`approved`: the ServiceNow close codes that count as an approval), `AEGIS_SERVICENOW_SELF` (AEGIS's own ServiceNow account(s), never counted as an approver; the basic-auth user is included), `AEGIS_HITL_MAX_AGE_S` (604800 = 7 days; `off` = never: an undecided approval older than this settles `expired`, never executed), `AEGIS_HITL_SYNC_BUDGET_S` (30: seconds spent polling approvals per cycle; the rest wait for the next cycle, least-recently polled first) |
| Response | `AEGIS_ENFORCEMENT_MODE`, `AEGIS_AUTONOMY_TIER`, `AEGIS_AUTONOMY_FLOOR_LOW` / `_MODERATE` / `_HIGH`, `AEGIS_UNATTENDED_DENY_PRINCIPALS`, `AEGIS_VERIFY_EVERY_S`, `AEGIS_VERIFY_GRACE_S` (60 s before a new rule is judged), `AEGIS_VERIFY_RETRY_S` (2 s second look after a missed read-back), `AEGIS_PROTECTED_TARGETS`, `AEGIS_NEVER_BLOCK`, `AEGIS_NEVER_BLOCK_HOSTS`, `AEGIS_HIGH_IMPACT_MAX`, `AEGIS_HIGH_IMPACT_WINDOW_SEC`, `AEGIS_APPROVED_TTL_SEC`, `AEGIS_APPROVED_BLOCK_TTL_SEC`, `AEGIS_OUTFLOW_BREAKER` (its own `AEGIS_OUTFLOW_BREAKER_MIN_CONF` floor applies to `hold`, not the autonomy tier), `AEGIS_WAF_*`, `AEGIS_SOAR_*`, `AEGIS_AGENT_SANDBOX` (`openshell` · `mock`), `AEGIS_OPENSHELL_BIN`, `AEGIS_RECEIPTS`, `AEGIS_RECEIPTS_PATH`, `AEGIS_OUTFLOW_SPLIT_FLOOR_INR` (1/20 of `AEGIS_HIGH_VALUE_INR`: smaller transfers enter the outflow ledger and add up), `AEGIS_DB_APP_HOSTS` (IPs / CIDRs whose DB `application_name` is trusted) |
| Agentic attackers | `AEGIS_AUTO_BLOCK` (`off` · `shadow` · `live`), `AEGIS_AUTO_BLOCK_MIN_CONF`, `AEGIS_AUTO_BLOCK_TTL`, `AEGIS_AUTO_BLOCK_MAX_PER_HOUR`, `AEGIS_FP_ALLOW`, `AEGIS_ADAPTIVE_MIN_RETRIES`, `AEGIS_ADAPTIVE_MAX_RETRY_S`, `AEGIS_AUTH_BURST_MIN`, `AEGIS_AWS_WAF_RULE_GROUP`, `AEGIS_JA4_DB`, `AEGIS_TLS_SHARED_UAS`, `AEGIS_TLS_LIBRARY_IPS` |
| Network sensor (NDR) | `NDR_EVENT_FILE`, `AEGIS_INTERNAL_NETS`, `AEGIS_TLS_IOC_FILE`, `AEGIS_AI_REGISTER`, `AEGIS_SHADOW_AI_REGISTER`, `AEGIS_AI_PROVIDERS_EXTRA`, `AEGIS_NDR_RARE_MAX_SRCS`, `AEGIS_NDR_BEACON_MIN_CONN`, `AEGIS_NDR_BEACON_MIN_SPAN_S`, `AEGIS_NDR_BEACON_MAX_JITTER`, `AEGIS_NDR_EXFIL_MIN_MB`, `AEGIS_NDR_EXFIL_WINDOW_S`, `AEGIS_NDR_EXFIL_RATIO`, `AEGIS_NDR_AI_UPLOAD_MB`, `AEGIS_NDR_ALLOW_DOMAINS`, `AEGIS_NDR_ALLOW_HOSTS`, `AEGIS_NDR_ALLOWED_SNI_EXFIL_FACTOR` (4: the per-destination-IP upload total still alarms behind an allow-listed SNI, at this multiple of `AEGIS_NDR_EXFIL_MIN_MB`) |
| Email | `AEGIS_MAIL_AUTHSERV_ID` (comma list: only `Authentication-Results` written by these authserv-ids count; unset = the top-most one) |
| Licence | `AEGIS_LICENSE`, `AEGIS_LICENSE_ENFORCE`, `AEGIS_INSTALL_ID`, `AEGIS_INSTALL_SALT`, `AEGIS_LICENSE_PUBKEYS` (operator-run issuer: logged loudly at startup, recorded as `issuer` in the licence status and `issuer_overridden` in the heartbeat), `AEGIS_LICENSE_OVERLIMIT_DAYS` — see the root README § Licensing |
| Network assurance | `NETOPS_EVENT_FILE`, `AEGIS_NETOPS_MAX_DEVICES`, `AEGIS_NET_FLAP_N`, `AEGIS_NET_FLAP_WINDOW_S`, `AEGIS_NET_CORR_WINDOW_S`, `AEGIS_NET_ERR_PER_MIN`, `AEGIS_NET_UTIL_PCT`, `AEGIS_NET_UTIL_SAMPLES`, `AEGIS_NET_SILENT_S`, `AEGIS_NET_BAD_PUSH_S`, `AEGIS_NET_GOLDEN`, `AEGIS_NET_GOLDEN_FIRST_SEEN`, `AEGIS_NET_INVENTORY` |
| BOLA | `AEGIS_OWNERSHIP_FILE`, `AEGIS_OWNERSHIP_URL`, `AEGIS_OWNERSHIP_TOKEN`, `AEGIS_BOLA_WINDOW_S`, `AEGIS_BOLA_CROSS_MIN`, `AEGIS_BOLA_ATTEMPT_MIN`, `AEGIS_BOLA_DISTINCT_MIN`, `AEGIS_BOLA_EXEMPT_PRINCIPALS`, `AEGIS_APIGW_PRINCIPAL_FIELD`, `APIGW_EVENT_FILE`, `AEGIS_EVENTHUB_SOURCE` |
| Intel | `AEGIS_CVE_INTEL`, `NVD_API_KEY`, `AEGIS_TI_CACHE`, `AEGIS_INTEL_MOCK`, `AEGIS_STACKS`, `AEGIS_INTERNAL_DOMAINS`, `AEGIS_TI_LLM_MAX_CONFIDENCE`, `AEGIS_TI_LLM_TTL_SEC`, `AEGIS_TI_MERGE_LLM_IOCS` |
| Edge shim | `AEGIS_EDGE_TRUST_DEMO_SRC`, `AEGIS_EDGE_MAX_PUSHED`, `AEGIS_EDGE_MAX_CLIENTS`, `AEGIS_EDGE_CONTROL_TOKEN` (separate token for `/control/enforce`), `AEGIS_EDGE_MIN_PREFIX_V4` / `_V6` (16 / 48: widest block the edge enforces) |
| ACP | `ACP_DASHBOARD_URL`, `ACP_API_KEY`, `ACP_GOVERN`, `ACP_AGENT_CODE`, `ACP_BU`, `ACP_RATE_LIMIT`, `AEGIS_PERSIST`, `AEGIS_RULE_FEED`, `AEGIS_ACP_MIN_SEVERITY`, `AEGIS_ACP_KINDS` |
| Data | `AEGIS_DATASET_CAPTURE`, `AEGIS_DATASET_SALT`, `AEGIS_AUDIT_PATH`, `AEGIS_LOG_LEVEL`, `AEGIS_AUDIT_ANCHOR` (append-only file on another volume; tail hashes written every `AEGIS_AUDIT_ANCHOR_EVERY` rows, default 100, so `python -m aegis.audit verify --all` sees a cut-off tail), `AEGIS_AUDIT_KEY` (signs retention checkpoints from `python -m aegis.audit retire`, which refuses without it; falls back to `AEGIS_DECISION_KEY`, never the console token; `verify` with a checkpoint and no key exits 3 "unverifiable"), `AEGIS_AUDIT_KEY_PREVIOUS` (comma list of earlier keys still accepted — `console:<token>` for a pre-round-8 checkpoint; re-sign with `python -m aegis.audit resign`), `AEGIS_AUDIT_REFEED_MAX` (3), `AEGIS_DEAD_LETTER` (where alerts that cannot be sealed for a non-disk reason are set aside), `AEGIS_PERSIST_FLUSH_S` (2), `AEGIS_CONTRIB_MAX_PER_INSTALL` (1000 records per contributing installation) |

---

## Code map

| Path | What |
|---|---|
| `service.py` | the long-running SOC process (`build_pipeline`, `run_cycle`, `--once`) |
| `edition.py` | editions, defaults, contradiction checks |
| `license.py` | per-installation licence: stdlib RSA verify, issue/keygen/verify/report CLI, evaluation mode, feature gates, 24 h meter; public keys in `keys/` |
| `ingest/` | Sentinel, WAF, API-gateway, network-sensor (`ndr.py`), network-operations (`netops.py`: syslog / traps / flows / telemetry / configs / LLDP), ACP consumers; push receiver (`http_push.py`, incl. the `/ingest/verdicts` feed), stream queue (`stream.py`), Event Hub reader (`eventhub.py`), Kafka reader (`kafka.py`), OCSF (`ocsf.py`), declarative connectors (`kit.py`); checkpoint |
| `detect/` | Sigma rules executed over OCSF events (`sigma.py`): first-pass detector that enriches alerts |
| `mcp/` | MCP gateway: analysts' MCP clients query verdicts, evidence chains and the approval queue (read-only; reject only when enabled) |
| `agents/orchestrator/` | triage, specialist dispatch, voter, fast paths (control-plane, adaptive attacker, credential stuffing, BOLA, spoofed browser, egress), swarm |
| `agents/netops/` | network assurance: topology (LLDP) → reachability-diff blast radius, root cause vs symptom, flaps, telemetry thresholds, config drift and bad pushes |
| `agents/ndr/` | egress detector (beacons, exfiltration, certificate oddities), TLS IOC list (`tls_intel.py`), AI-service catalogue + register + discovered usage (`ai_usage.py`) |
| `agents/orchestrator/walkers/` | campaign context, walkers, blast graph, mitigation planner, twin, containment loop, async investigator |
| `agents/<domain>/` | perimeter, auth, edr, api_abuse (incl. `object_walk.py` BOLA detector, `ownership.py`), transaction, cloud_controlplane, dlp, email, mobile, wireless |
| `agents/deception/` | honeytokens, per-stack canaries |
| `agents/threat_intel/` | IOC store and feeds, KEV / NVD / EPSS, publisher to the dashboard |
| `agents/vuln_discovery/` | dependency, config, code, supply-chain, client-exposure scans |
| `agents/response/` | response agent, tiered autonomy (`autonomy.py`), connectors (Imperva / F5 in `waf.py`, Cloudflare / AWS / Azure in `cloud_waf.py`, SigV4 + Azure AD in `cloud_auth.py`, SOAR, mock tenants), receipts |
| `agents/shared/` | evidence chain, client fingerprints, TLS / user-agent consistency (`tls_client.py`), action-target resolution, audit log, LLM clients, PII tokenizer, injection defense, observability |
| `hitl/` | approval transports (dashboard, ServiceNow, file) and the investigation card |
| `governance.py` | the SOC brain under ACPGuard |
| `persist/`, `evolve/`, `shadow/` | dashboard sink, rule feed, shadow report |
| `dataset/`, `finetune/` | training data, QLoRA trainer, gate, retrain loop |
| `meta_agent/` | proposals from eval failures |
| `eval/` | every gate listed above, the purple-team benchmark (`purple_team/`), the egress benchmark (`egress_bench.py`), plus the corpora |
| `intel/`, `compliance/` | CERT-In draft, FS-ISAC STIX bundle, regulator report |
| `healing/`, `mtd/`, `rl/`, `edge/` | self-healing pipeline, moving-target defense, RL research stack, Go data-plane skeleton |

Roadmap and decision log: `docs/plans/aegis-production-roadmap.md`.

---

## Honest limits

**Known issues from the 2026-11-03 review** (full report in the project's review doc; fixes in
progress):

- **Blast-radius numbers:** the critical count is capped at 10, a walk whose queries all fail
  reads as a clean radius, and plan steps are not filed as approvals (B1, B3, B5).
- **Chunked pushes to `/ingest/*` are not read** (C1): configure relays (Fluent Bit, Vector) to
  send `Content-Length`.
- **Do not point the posture runner and the SOC service at the same `AEGIS_HITL_DIR`** (C2): they
  share one journal and settle each other's cards.
- **The governance tests do not run in CI** until the repo has the `GH_READ_TOKEN` secret (T1).

- **Blast radius runs on a mock tenant** until a bank's `TelemetrySource` adapter exists.
- **WAF / SOAR connectors** are built to the public API shapes and tested against mock tenants;
  each still needs one live smoke on a real tenant.
- **Confidence is not yet calibrated** against analyst outcomes; that needs a few hundred
  decided alerts from a live deployment.
- **Detection quality is measured on held-out sets**, not yet on a live tenant; the two-week
  shadow window is the step that turns "built" into "measured".
- **What the bank doesn't log, AEGIS can't see.**
- **Retry-after-stop needs the WAF's stop events in the feed**, and fingerprint following needs
  JA4 / JA3 in the logs (Cloudflare Bot Management, AWS WAF). Pushed sources (Logpush, Firehose,
  Event Hub) reach a verdict in milliseconds; polled sources (Sentinel, Splunk) still wait for
  the poll interval, and vendor-side batching adds its own delay (Logpush ships every few
  seconds, Firehose buffers 60 s by default — set its buffer interval to the minimum).
- **Low-and-slow campaigns are undetected** (the purple-team report shows it): one request every
  few minutes is below every cadence signal by design.
- **Ownership-confirmed BOLA needs API-gateway logs with the principal, and an ownership source**
  from the bank. The WAF / edge path is no longer blind — the shim derives a hashed principal and
  the perimeter's `id_enumeration` flags object-id walking (the *behavioural* tell) — but
  *confirming* a caller read an object it does not own still needs the gateway + ownership, and
  without ownership it only reaches *suspicious*. Containing an authenticated walker is a token
  revoke (human); IP blocks lag one rotation.
- **Benign-sharing of a fingerprint is judged from what reaches AEGIS** (security events, not
  all traffic); `AEGIS_FP_ALLOW` and the shadow window are the safety net until then. The TLS
  model learns from the same feed, so send Cloudflare's `http_requests` dataset (or a sample of
  it), not only `firewall_events`.
- **The TLS check sees only what JA4 shows.**
  - A client that drives a real browser, or imitates a browser's ClientHello
    (curl-impersonate, curl_cffi, uTLS), is consistent by construction.
  - An HTTP/2-capable library is caught only by the reference file, or once its honest user
    agent has been learned.
  - Until three browsers have come through a new TLS-inspecting proxy, its users can be
    challenged (they pass). Label the proxy in `AEGIS_JA4_DB` to skip that.
  - Quiet requests can teach the model that a lie is normal. That costs detection, never
    collateral.
  - Only the JA4 client fingerprint (BSD-3) is used; JA4S/H/X are FoxIO-licensed and are not.
- **Egress detection sees metadata from where the sensor sits.**
  - TLS 1.3 hides the server certificate from a passive sensor, and ECH hides the SNI (the
    destination becomes an IP).
  - A TLS-inspecting proxy in front of the sensor hides everything behind it; feed the proxy's
    own logs instead.
  - An implant that holds one connection open makes no new handshakes.
  - C2 behind a name every host uses is hidden by prevalence.
  - Exfiltration to a sanctioned SaaS that many hosts use is a DLP / CASB question.
  - Very jittery beacons are caught only sometimes.
  - Zeek's x509 log carries SHA-256, so list a certificate by SHA-256 or add SHA-1 from
    `files.log`.
- RL (`rl/`) and MTD are research components, not on the verdict path.
