# Wiring real feeds into AEGIS

**Purpose.** Point each real telemetry source at a running AEGIS SOC so the brain watches a live
estate instead of fixtures. This is the "real senses" step. Follow it the day **v60.28** is
deployed; until then it is the target state. One piece — the **estate map** (§6) — needs no deploy
and can be done today.

**The shape never changes:** a producer emits logs → AEGIS **parses** them (the consumers in
`aegis/ingest/` already speak every format below) → the brain triages → the connectors enforce.
What you are wiring is only the *transport* from the producer to one `/ingest/*` endpoint (push)
or a file / Event Hub the service polls. Always start in **shadow** (`AEGIS_ENFORCEMENT_MODE=shadow`).

---

## 0. Prerequisites (once)

1. **Deploy v60.28** and run the SOC service on the SOC host:
   ```bash
   # env in /root/acp-aegis.env (or the systemd unit)
   AEGIS_EDITION=soc            # or full
   ACP_DASHBOARD_URL=https://dashboard.acpgovernance.com
   ACP_API_KEY=...              # SOC agent key
   AEGIS_GOVERN=1 AEGIS_SWARM=1
   AEGIS_DATASET_SALT=<secret>  # capture on by default — this is what starts real learning
   AEGIS_ENFORCEMENT_MODE=shadow
   python -m aegis.service      # poll loop; --once for a smoke cycle
   ```
2. **Turn the HTTP ingest receiver on** (so producers can push):
   ```bash
   AEGIS_INGEST_HTTP=1
   AEGIS_INGEST_BIND=0.0.0.0:8787
   AEGIS_INGEST_TOKEN=<shared-bearer>   # REQUIRED off loopback; every producer sends it
   ```
3. **Health check:** `curl -s http://SOC:8787/healthz` → `{"ok": true, ...}`.

Every push below carries `Authorization: Bearer $AEGIS_INGEST_TOKEN` and `Content-Type:
application/x-ndjson` (one JSON object per line). Endpoints: `/ingest/cloudflare`,
`/ingest/firehose`, `/ingest/waf`, `/ingest/apigw`, `/ingest/ndr`, `/ingest/alerts`, and
`GET /ingest/blocklist` (for edge enforcers, incl. the edge shim).

**Verify any feed the same way:** send one real (or sample) line, then confirm a verdict landed —
`GET /api/soc/events` on the dashboard, or the incidents table in Postgres. Sample lines for every
format live in `aegis/ingest/fixtures/`.

---

## 1. Network sensor — NDR (the silent-RAT / beacon eyes)

**You provide:** a Zeek or Suricata box on a SPAN/TAP port (or cloud packet-mirror).

- Zeek: emit JSON (`redef LogAscii::use_json = T;`) for `ssl`, `conn`, `x509`. Suricata: EVE JSON
  (`tls`, `flow`) is already the right shape.
- Ship with any HTTP forwarder (Vector / Fluent Bit / Filebeat HTTP output) to `/ingest/ndr`:
  ```bash
  curl -sS -H "Authorization: Bearer $TOK" -H "Content-Type: application/x-ndjson" \
       --data-binary @zeek_ssl.ndjson  http://SOC:8787/ingest/ndr
  ```
  Alternatives: write the JSON to a file and set `NDR_EVENT_FILE=/var/log/zeek/ssl.ndjson` (the
  poller tails it), or Azure Event Hub with `AEGIS_EVENTHUB_SOURCE=ndr`.
- **Intel/registers** the detector reads (samples in `aegis/ingest/fixtures/ndr/`):
  `AEGIS_TLS_IOC_FILE=<jsonl | SSLBL csv>` (e.g. `tls_ioc.sample.jsonl` / `sslbl.sample.csv`),
  `AEGIS_AI_REGISTER=<approved AI SNIs>` (`ai_register.sample.csv`),
  `AEGIS_SHADOW_AI_REGISTER=<discovered>` (RBI Rec 23). Thresholds tune via `AEGIS_NDR_*`.
- **Verify:** `curl ... --data-binary @aegis/ingest/fixtures/ndr/zeek_tls.sample.jsonl .../ingest/ndr`
  (or `suricata_eve.sample.jsonl`) → a beacon/exfil/known-bad-TLS verdict in the console.
- **Limit:** metadata only — TLS 1.3 hides certs, ECH hides SNI, a dormant implant with no
  callback is invisible, jittery beacons are caught only sometimes. **Sensor placement is the
  whole game** — tap where egress actually concentrates.

## 2. WAF / edge (web-attack eyes)

**You provide:** the bank's real WAF log export + (for enforcement) a tenant key.

- **Cloudflare:** create a **Logpush** job with an **HTTP destination** = `https://SOC:8787/ingest/cloudflare`
  (add the `Authorization` header in the job config). Set `AEGIS_WAF_VENDOR=cloudflare` (+ `AEGIS_CF_*`).
- **AWS WAF:** logging → **Kinesis Data Firehose** → "HTTP endpoint" delivery to `/ingest/firehose`.
  `AEGIS_WAF_VENDOR=aws` (+ `AEGIS_AWS_*`, SigV4).
- **Azure WAF (Front Door / App Gateway):** diagnostic settings → Event Hub → `AEGIS_EVENTHUB_SOURCE`
  reader. `AEGIS_WAF_VENDOR=azure` (+ `AEGIS_AZURE_*`).
- **Imperva / F5:** forward their syslog/CEF to `/ingest/waf`.
- **No WAF on an app?** Front it with the **edge shim** (`scripts/aegis_edge.py`) — it inspects and
  forwards to `/ingest/alerts` and polls `/ingest/blocklist`. See its `--help`.
- **Verify:** `curl ... --data-binary @aegis/ingest/fixtures/cloud_waf_events.jsonl .../ingest/waf`
  (or `waf_events.log`) → a web-attack verdict in the console.

## 3. API gateway (BOLA / authz eyes)

**You provide:** gateway access logs **with the principal field**, and an ownership source.

- APIM (log `userId` via policy), AWS API Gateway access logs, or Kong http-log → `/ingest/apigw`
  (push), or `APIGW_EVENT_FILE=<path>`, or Event Hub `AEGIS_EVENTHUB_SOURCE=apigw`.
- **Ownership map** (who owns which object) so a foreign-object read is detectable:
  `AEGIS_OWNERSHIP_FILE=<csv|jsonl>` or `AEGIS_OWNERSHIP_URL` (+ `_TOKEN`); set
  `AEGIS_APIGW_PRINCIPAL_FIELD` if the field isn't the default.
- **Limit:** without the principal + ownership, the same walk through WAF logs stays undetected —
  that is the case for gateway logs. Gateway-side token revoke is still a human step.

## 4. Endpoint / EDR (host eyes, for the replicating threat)

**You provide:** EDR detections + device inventory.

- **Detections:** stream them in via the SIEM consumers that already exist (Sentinel KQL / Splunk ES),
  or normalize to AEGIS alerts and push to `/ingest/alerts`.
- **Enforcement:** `AEGIS_EDR_VENDOR=crowdstrike` + `AEGIS_EDR_CLIENT_ID`/`AEGIS_EDR_CLIENT_SECRET`
  (CrowdStrike contain-host / kill-process — both **HITL**).
- **Inventory** feeds the estate graph (§6), which is where the blast-radius walk gets real.

## 5. Internal agents — ACP governance (already real)

Set `AEGIS_SOURCES=acp` (+ `AEGIS_ACP_MIN_SEVERITY`, `AEGIS_ACP_KINDS`). The Q↔AEGIS bridge reads
live rogue / Q37 / pause events from the dashboard — this one needs no new sensor, only the
dashboard URL + key already in §0. (Q37 + threat-impact cover **SDK-governed internal** agents;
external attackers are the behavioural feeds above.)

## 6. The estate map — do this today (no deploy)

The investigation layer (blast-radius walk, min-cut, containment loop) needs a map of what reaches
what. Export it from CMDB + EDR + IAM + CBS into the shape in
`aegis/ingest/fixtures/estate.sample.json`, then:
```bash
AEGIS_TENANT=inventory
AEGIS_TENANT_FILE=/etc/aegis/estate.json
```
`InventorySource` serves it to the walkers unchanged. This is the one real sense that works with no
live feed and no deploy — the brain can plan over your real topology now.

---

## Enforcement: shadow → live (never flip blind)

1. All connectors `dry_run` under `AEGIS_ENFORCEMENT_MODE=shadow` + `AEGIS_AUTO_BLOCK=shadow`.
2. Run the **1.5 shadow window (~2 weeks):** `python -m aegis.shadow report --dashboard` joins
   "would-block" receipts ⋈ chains ⋈ what the analyst actually did → per `(connector, action)`
   agree/disagree, and a `ready|not_yet` verdict.
3. Flip live **per action, lowest blast-radius first:** `throttle`/`challenge` → WAF rule → `block`
   → `isolate`/`kill` (the last stay HITL regardless). Containment is always human-approved.

## Order of operations

1. §0 deploy + receiver → `/healthz` green.
2. §6 estate map (today) — makes the *planning* real.
3. §5 ACP — free, already-live internal eyes.
4. One external feed end-to-end in shadow — usually §2 WAF (Cloudflare/AWS) or §1 NDR.
5. Add the rest; start the §-enforcement shadow window on the first vendor connector.
6. After ~weeks of real analyst decisions accrue, retrain triage on real data (roadmap 3.3 → DPO).

## Status

| Piece | State |
|---|---|
| Parsers for every format above | ✅ in `aegis/ingest/` (tested on fixtures) |
| Receiver + poller + Event Hub reader | ✅ ship in v60.28 |
| Estate map (`InventorySource`) | ✅ wire today from one export (§6) |
| ACP internal-agent feed | ✅ live with the dashboard key |
| NDR / WAF / API-gw / EDR live feeds | ⏳ your sensor + log-export config + keys |
| Deploy that runs the receiver | ⏳ v60.28 (registry/VM login) |
| Real learning (3.3 / DPO) | ⏳ accrues after deploy + capture on |

**Not doable from this session:** standing up a Zeek box, enabling Cloudflare Logpush, minting
tenant keys, or the v60.28 deploy — all live in your environment. This runbook is the exact steps
for when you do.
