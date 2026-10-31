# AEGIS Kafka bridge

Most banks already land device syslog, NetFlow/IPFIX, streaming telemetry and SIEM alerts on Kafka.
This bridge (Java 21, Kafka Streams) is how AEGIS joins that estate without anyone changing a
collector: it consumes the topics, dedupes and pre-aggregates, and pushes to the AEGIS push receiver
over HTTPS; it polls AEGIS for finalised verdicts and produces them to a topic so SOAR, the SIEM,
the CMDB or ticketing read AEGIS decisions like any other stream.

```
 aegis.syslog     ─┐                                       ┌─► POST /ingest/netops?feed=syslog
 aegis.netflow    ─┤  key by device → dedupe → flap fold   ├─► POST /ingest/netops?feed=netflow
 aegis.telemetry  ─┤  (Kafka Streams, bounded buffer)      ├─► POST /ingest/netops?feed=telemetry
 aegis.alerts     ─┘                                       └─► POST /ingest/alerts
 aegis.verdicts   ◄── poll GET /ingest/verdicts?after=<seq> ◄── AEGIS audit log (hash-chained)
```

## What it does, and why

| Stage | Behaviour | Why |
|---|---|---|
| Key by device | Syslog records with no Kafka key are keyed by the relay host field | Every line from one device lands on one partition, so dedupe and flap state are local |
| Dedupe | A (key, body) seen inside `BRIDGE_DEDUPE_TTL_S` (120 s) is dropped | Relays and collectors re-deliver on reconnect; a duplicate link-down looks like a flap |
| Flap fold | Per interface, the first `BRIDGE_FLAP_FORWARD_N` (8) up/down transitions per `BRIDGE_FLAP_WINDOW_S` (300 s) window are forwarded, the rest counted and folded into one `%AEGIS-5-FLAP_SUPPRESSED` line at the window end | AEGIS needs five transitions to call a flap; a port bouncing 40×/min must not cost 2,400 records |
| Batch + POST | NDJSON batches of `BRIDGE_BATCH_LINES` (500) or every `BRIDGE_LINGER_MS` (1 s), `Authorization: Bearer $AEGIS_INGEST_TOKEN` | One HTTP call per batch, not per line |
| Backpressure | AEGIS 503/429 → the same batch is retried with backoff (250 ms → 30 s); the buffer is bounded (`BRIDGE_MAX_BUFFERED_LINES`, 20,000) and a full buffer blocks the Streams thread, which stops consuming | Nothing is dropped silently; the lag shows on the consumer group, where it is already monitored |
| Verdict egress | `GET /ingest/verdicts?after=<seq>` every `BRIDGE_VERDICT_POLL_MS` (2 s); each evidence chain is produced to `AEGIS_TOPIC_VERDICTS` keyed by alert id, with `aegis-seq` and `aegis-prev-hash` headers; the cursor advances only after the broker acked and is persisted to `BRIDGE_CURSOR_FILE` | At-least-once with an exact resume point; consumers dedupe on `seq` and can re-verify the hash chain |

A 4xx other than 429 (wrong token, body too large) drops the batch and logs it: retrying would never succeed.

## Run

```bash
docker build -t aegis-kafka-bridge kafka-bridge/
docker run -d --name aegis-bridge -v aegis-bridge-state:/var/lib/aegis-bridge \
  -e KAFKA_BOOTSTRAP_SERVERS=kafka-1:9093,kafka-2:9093 \
  -e KAFKA_SECURITY_PROTOCOL=SASL_SSL -e KAFKA_SASL_MECHANISM=SCRAM-SHA-512 \
  -e KAFKA_SASL_JAAS_CONFIG='org.apache.kafka.common.security.scram.ScramLoginModule required username="aegis" password="…";' \
  -e AEGIS_URL=https://aegis.soc.bank.internal:8787 -e AEGIS_INGEST_TOKEN=… \
  aegis-kafka-bridge
```

Any `KAFKA_*` variable is passed through to the Streams and producer clients (`KAFKA_SSL_TRUSTSTORE_LOCATION`
→ `ssl.truststore.location`), so mTLS and SASL work without a config file. The bridge needs read on the
four ingress topics, write on the verdicts topic, and the usual Streams rights on its own
`<BRIDGE_APPLICATION_ID>-*` changelog topics (or pre-create them and set `BRIDGE_PERSISTENT_STORES=0`,
the default, which keeps dedupe/flap state in memory — it is a cache, losing it on restart costs nothing).

**Licence.** At start the bridge reads `GET /ingest/license`; when AEGIS enforces its licence
(`AEGIS_LICENSE_ENFORCE=1`) and `kafka_bridge` is not among the licensed features it exits with code 3 and one
clear line. AEGIS unreachable at start is not a licence failure — the bridge starts and the sink retries.

On the AEGIS side: `AEGIS_INGEST_HTTP=1`, `AEGIS_INGEST_TOKEN=<same token>`, and the receiver must run in the
service process (it is — `GET /ingest/verdicts` reads the service's audit log).

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `KAFKA_BOOTSTRAP_SERVERS` | required | broker list |
| `AEGIS_URL` | required | the AEGIS push receiver, e.g. `https://aegis:8787` |
| `AEGIS_INGEST_TOKEN` | "" | bearer token (required unless AEGIS listens on loopback) |
| `AEGIS_TOPIC_SYSLOG` / `_NETFLOW` / `_TELEMETRY` / `_ALERTS` / `_VERDICTS` | `aegis.syslog` … `aegis.verdicts` | topics |
| `BRIDGE_APPLICATION_ID` | `aegis-kafka-bridge` | Streams application id / consumer group |
| `BRIDGE_DEDUPE_TTL_S` | 120 | dedupe window |
| `BRIDGE_FLAP_WINDOW_S` / `BRIDGE_FLAP_FORWARD_N` | 300 / 8 | flap fold window and how many transitions reach AEGIS per window |
| `BRIDGE_BATCH_LINES` / `BRIDGE_LINGER_MS` | 500 / 1000 | batching |
| `BRIDGE_MAX_BUFFERED_LINES` | 20000 | bounded buffer; full = backpressure |
| `BRIDGE_VERDICT_POLL_MS` | 2000 | verdict poll interval |
| `BRIDGE_CURSOR_FILE` | `/var/lib/aegis-bridge/verdict.cursor` | resume point |
| `BRIDGE_PERSISTENT_STORES` | 0 | 1 = RocksDB-backed dedupe/flap state with changelog topics |
| `BRIDGE_STATE_DIR` | `/var/lib/aegis-bridge/streams` | Streams state dir |
| `BRIDGE_STREAM_THREADS` | 2 | Streams threads |

## Build and test

```bash
cd kafka-bridge && mvn -q test        # TopologyTestDriver + fake AEGIS; no broker needed
mvn -q package && java -jar target/aegis-kafka-bridge.jar
```

The verdicts topic carries the full evidence chain JSON (verdict, confidence, evidence, recommended
actions, HITL outcome, `integrity_hash`) — the same record the AEGIS audit log holds, so a consumer can
recompute `sha256(prev_hash + canonical_json)` and prove nothing was altered in transit.
