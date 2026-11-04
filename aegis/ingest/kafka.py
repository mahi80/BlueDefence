"""Kafka reader — consume security events from a bank's Kafka (or Confluent / MSK / Redpanda / Event Hubs Kafka
endpoint) at scale, onto the shared ``StreamQueue``.

Many banks already land their logs on Kafka (often via Vector, Fluent Bit, Logstash or Cribl). This reader joins a
consumer group, takes a batch, splits each message (one JSON object, ``{"records": [...]}``, a JSON array of OCSF
events, or NDJSON) into lines, queues them, and only then commits the offsets — so a batch the queue cannot take
yet is held (backpressure: the consumer stops fetching) and never skipped. Offsets live in the broker's consumer
group, so several AEGIS readers in one group share the partitions. Set ``AEGIS_STREAM_JOURNAL`` too: with it a
committed batch is already on disk, so a crash after the commit loses nothing.

Topics map to AEGIS sources: ``AEGIS_KAFKA_TOPICS=sec.ocsf=ocsf,waf.cf=cloudflare,edr.sysmon=edr``. A source named
``ocsf`` / ``ocsf-<product>`` goes through the OCSF mapper, ``edr`` through the host-telemetry path, anything else
through the usual stream detection (WAF / NDR / API gateway / netops). A topic with no ``=`` uses
``AEGIS_KAFKA_SOURCE`` (default ``kafka``).

Env: ``AEGIS_KAFKA_BOOTSTRAP`` (``host:9093,…``), ``AEGIS_KAFKA_TOPICS``, ``AEGIS_KAFKA_GROUP`` (``aegis``),
``AEGIS_KAFKA_START`` (``latest`` | ``earliest``, for a group with no committed offset),
``AEGIS_KAFKA_SECURITY_PROTOCOL`` (``SASL_SSL`` default; ``SSL``; ``PLAINTEXT`` only with
``AEGIS_KAFKA_ALLOW_PLAINTEXT=1`` — the payloads are security logs), ``AEGIS_KAFKA_SASL_MECHANISM``
(``SCRAM-SHA-512`` default · ``SCRAM-SHA-256`` · ``PLAIN``), ``AEGIS_KAFKA_USERNAME``, ``AEGIS_KAFKA_PASSWORD``,
``AEGIS_KAFKA_CA`` (CA bundle path), ``AEGIS_KAFKA_CERT`` / ``AEGIS_KAFKA_KEY`` (mTLS). Credentials come only from
the environment. Uses ``confluent-kafka`` (optional extra ``aegis[kafka]``); the consumer is injectable for tests.
"""

from __future__ import annotations

import logging
import os
import re
import threading
import time
from collections.abc import Callable
from typing import Any

from .eventhub import _split_body
from .stream import StreamQueue, get_stream

logger = logging.getLogger("aegis.ingest.kafka")

_PROTOCOLS = {"SASL_SSL", "SSL", "PLAINTEXT", "SASL_PLAINTEXT"}
_MECHANISMS = {"SCRAM-SHA-512", "SCRAM-SHA-256", "PLAIN"}
_MAX_MESSAGE = 8 * 1024 * 1024


def parse_topics(spec: str, default_source: str = "kafka") -> dict[str, str]:
    """``"a=ocsf, b, c=edr"`` → ``{"a": "ocsf", "b": "kafka", "c": "edr"}``."""
    out: dict[str, str] = {}
    for tok in str(spec or "").replace(";", ",").split(","):
        tok = tok.strip()
        if not tok:
            continue
        topic, _, source = tok.partition("=")
        topic, source = topic.strip(), (source.strip() or default_source)
        if topic:
            out[topic] = source
    return out


def kafka_config(env: dict[str, str] | None = None) -> dict[str, Any]:
    """librdkafka settings from the environment. Raises ValueError on an unsafe or incomplete setup."""
    e = os.environ if env is None else env
    bootstrap = e.get("AEGIS_KAFKA_BOOTSTRAP", "").strip()
    if not bootstrap:
        raise ValueError("AEGIS_KAFKA_BOOTSTRAP is not set")
    proto = e.get("AEGIS_KAFKA_SECURITY_PROTOCOL", "SASL_SSL").strip().upper()
    if proto not in _PROTOCOLS:
        raise ValueError(f"AEGIS_KAFKA_SECURITY_PROTOCOL={proto!r} (SASL_SSL | SSL | PLAINTEXT)")
    if proto in ("PLAINTEXT", "SASL_PLAINTEXT") and e.get("AEGIS_KAFKA_ALLOW_PLAINTEXT", "0") != "1":
        raise ValueError(f"{proto} sends security logs unencrypted; set AEGIS_KAFKA_ALLOW_PLAINTEXT=1 for a lab")
    start = e.get("AEGIS_KAFKA_START", "latest").strip().lower()
    cfg: dict[str, Any] = {
        "bootstrap.servers": bootstrap,
        "group.id": e.get("AEGIS_KAFKA_GROUP", "aegis").strip() or "aegis",
        "enable.auto.commit": False,                # commit only after the batch is queued
        "auto.offset.reset": "earliest" if start == "earliest" else "latest",
        "security.protocol": proto,
        "client.id": "aegis-soc",
        "max.partition.fetch.bytes": _MAX_MESSAGE,
    }
    if proto.startswith("SASL"):
        mech = e.get("AEGIS_KAFKA_SASL_MECHANISM", "SCRAM-SHA-512").strip().upper()
        if mech not in _MECHANISMS:
            raise ValueError(f"AEGIS_KAFKA_SASL_MECHANISM={mech!r} (SCRAM-SHA-512 | SCRAM-SHA-256 | PLAIN)")
        user, pw = e.get("AEGIS_KAFKA_USERNAME", ""), e.get("AEGIS_KAFKA_PASSWORD", "")
        if not user or not pw:
            raise ValueError("SASL needs AEGIS_KAFKA_USERNAME and AEGIS_KAFKA_PASSWORD")
        cfg.update({"sasl.mechanism": mech, "sasl.username": user, "sasl.password": pw})
    for var, key in (("AEGIS_KAFKA_CA", "ssl.ca.location"), ("AEGIS_KAFKA_CERT", "ssl.certificate.location"),
                     ("AEGIS_KAFKA_KEY", "ssl.key.location")):
        if e.get(var, "").strip():
            cfg[key] = e[var].strip()
    return cfg


class KafkaReader:
    def __init__(self, *, config: dict[str, Any], topics: dict[str, str], queue: StreamQueue | None = None,
                 consumer_factory: Callable[[dict], Any] | None = None, batch_size: int = 500,
                 poll_timeout_s: float = 1.0, backoff_s: float = 5.0):
        if not topics:
            raise ValueError("no Kafka topics configured (AEGIS_KAFKA_TOPICS)")
        self.config = dict(config)
        self.topics = dict(topics)
        # librdkafka subscribes to a topic name starting with "^" as a regex; m.topic() is then the concrete name,
        # so the source is found by matching (an exact dict lookup sent those records down the generic path)
        self._topic_rx = [(re.compile(t), src) for t, src in self.topics.items() if t.startswith("^")]
        self.queue = queue if queue is not None else get_stream()
        self._factory = consumer_factory
        self.batch_size = batch_size
        self.poll_timeout_s = poll_timeout_s
        self.backoff_s = backoff_s
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._consumer: Any = None
        self.batches = 0
        self.messages = 0
        self.skipped = 0

    def source_for(self, topic: str) -> str:
        if topic in self.topics:
            return self.topics[topic]
        for rx, src in self._topic_rx:
            if rx.match(topic):
                return src
        return "kafka"

    def _make_consumer(self) -> Any:
        if self._factory is not None:
            return self._factory(self.config)
        try:
            from confluent_kafka import Consumer  # type: ignore
        except ImportError:
            raise RuntimeError("confluent-kafka is not installed: pip install 'aegis[kafka]'") from None
        return Consumer(self.config)

    # -- one batch (also the unit the tests drive)
    def handle(self, msgs: list[Any]) -> bool:
        """Queue one batch, then commit it. False when stopped before it could be queued (nothing committed)."""
        by_source: dict[str, list[str]] = {}
        good: list[Any] = []
        for m in msgs:
            err = m.error() if hasattr(m, "error") else None
            if err:                                  # partition EOF is off by default; anything else is logged
                logger.warning("[ingest:kafka] %s: %s", getattr(m, "topic", lambda: "?")(), str(err)[:160])
                continue
            good.append(m)
            raw = m.value()
            if raw is None:
                continue
            if len(raw) > _MAX_MESSAGE:
                self.skipped += 1
                logger.warning("[ingest:kafka] %s: message over %d bytes skipped", m.topic(), _MAX_MESSAGE)
                continue
            try:
                body = raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else str(raw)
            except UnicodeDecodeError:
                self.skipped += 1
                logger.warning("[ingest:kafka] %s: message is not UTF-8; skipped", m.topic())
                continue
            source = self.source_for(m.topic())
            if source == "ocsf" or source.startswith("ocsf-"):
                from .stream import ocsf_lines_from_body
                lines, bad = ocsf_lines_from_body(body.encode("utf-8"))   # one event per item, arrays split, none cut
                if bad:
                    self.skipped += bad
                    logger.warning("[ingest:kafka] %s: %d record(s) are not JSON objects; skipped", m.topic(), bad)
            else:
                lines = _split_body(body)
            by_source.setdefault(source, []).extend(lines)
        for source, lines in by_source.items():
            attempt = 0
            while not self.queue.put_many(source, lines):
                # queue full: hold the batch and stop fetching (backpressure); never commit past it
                if self._stop.is_set():
                    return False
                attempt += 1
                if attempt in (60, 600) or attempt % 3000 == 0:
                    logger.error("[ingest:kafka] queue full for %d tries — holding %d %s record(s), not committing",
                                 attempt, len(lines), source)
                time.sleep(min(self.backoff_s, 0.1 * min(attempt, 20)))
        if good and self._consumer is not None:
            self._consumer.commit(asynchronous=False)
        self.batches += 1
        self.messages += len(good)
        return True

    def _run(self) -> None:
        delay = self.backoff_s
        while not self._stop.is_set():
            try:
                self._consumer = self._make_consumer()
                self._consumer.subscribe(list(self.topics))
                logger.info("[ingest:kafka] group %s on %s", self.config.get("group.id"), ", ".join(self.topics))
                delay = self.backoff_s
                while not self._stop.is_set():
                    msgs = self._consumer.consume(num_messages=self.batch_size, timeout=self.poll_timeout_s)
                    if msgs and not self.handle(msgs):
                        break
            except Exception as e:  # noqa: BLE001 — broker / auth / network: back off and reconnect, never die
                if self._stop.is_set():
                    break
                logger.warning("[ingest:kafka] consumer failed (%s: %s); reconnecting in %.0fs",
                               type(e).__name__, str(e)[:160], delay)
                self._stop.wait(delay)
                delay = min(delay * 2, 300)
            finally:
                c, self._consumer = self._consumer, None
                if c is not None:
                    try:
                        c.close()                    # leaves the group cleanly; uncommitted batches are re-read
                    except Exception:  # noqa: BLE001, S110
                        pass

    def start(self) -> KafkaReader:
        self.queue.enabled = True
        if self.queue.journal is None:
            logger.warning("[ingest:kafka] AEGIS_STREAM_JOURNAL is not set: records queued and committed but not yet "
                           "investigated are lost on a crash — set it for at-least-once")
        self._thread = threading.Thread(target=self._run, name="AegisKafkaReader", daemon=True)
        self._thread.start()
        return self

    def stop(self, join_timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(join_timeout)


def kafka_from_env(queue: StreamQueue | None = None, consumer_factory: Callable[[dict], Any] | None = None,
                   ) -> KafkaReader | None:
    topics = parse_topics(os.environ.get("AEGIS_KAFKA_TOPICS", ""),
                          os.environ.get("AEGIS_KAFKA_SOURCE", "kafka").strip() or "kafka")
    try:
        cfg = kafka_config()
    except ValueError as e:
        logger.error("[ingest:kafka] kafka requested but not configured: %s; skipped", e)
        return None
    if not topics:
        logger.error("[ingest:kafka] kafka requested but AEGIS_KAFKA_TOPICS is empty; skipped")
        return None
    if consumer_factory is None:
        try:
            import confluent_kafka  # noqa: F401
        except ImportError:
            logger.error("[ingest:kafka] confluent-kafka is not installed (pip install 'aegis[kafka]'); source skipped")
            return None
    return KafkaReader(config=cfg, topics=topics, queue=queue, consumer_factory=consumer_factory).start()


__all__ = ["KafkaReader", "kafka_config", "kafka_from_env", "parse_topics"]
