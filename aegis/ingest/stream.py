"""Streaming ingest — events pushed *to* AEGIS instead of polled for.

Polling a SIEM every minute is fine for a human attacker. An AI agent runs
recon → exploit → persist in less time than one poll interval, so the WAF
has to be able to push: Cloudflare Logpush (HTTP destination), AWS Kinesis
Firehose (HTTP endpoint delivery), Azure Event Hubs, or any forwarder that
can POST lines. Those receivers (``http_push.py``, ``eventhub.py``) all
drop raw records into the one ``StreamQueue`` here; ``StreamConsumer``
drains it through the same normalise → dedupe → checkpoint path as every
other source, and the service loop wakes on arrival instead of sleeping
until the next poll.

Backpressure is a decision, not an accident: the queue is bounded and a
full queue makes a receiver answer **503** (Logpush and Firehose both
retry with backoff, Firehose then backs the batch up to S3), so nothing is
silently dropped. Re-delivered batches dedupe on the vendor event id.

Every alert that comes through here carries ``received_at`` (epoch) and
``ingest_lag_ms`` (receipt − vendor timestamp), which is what the
time-to-detect benchmark reads.
"""

from __future__ import annotations

import collections
import json
import re
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterator, Optional

from .base import CONSUMED, AlertCheckpoint, BaseConsumer

logger = logging.getLogger("aegis.ingest.stream")

DEFAULT_CAPACITY = 50_000


@dataclass
class StreamItem:
    source: str                 # cloudflare | firehose | waf | alerts | azure-eventhub | …
    line: str                   # one raw record (JSON / CEF / F5 kv) or a normalised alert JSON
    received_at: float
    passthrough: bool = False   # already an AEGIS alert dict → no vendor normalisation


@dataclass
class StreamStats:
    received: int = 0
    rejected_full: int = 0
    drained: int = 0
    high_water: int = 0
    last_received_at: float = 0.0
    by_source: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"received": self.received, "rejected_full": self.rejected_full, "drained": self.drained,
                "high_water": self.high_water, "last_received_at": self.last_received_at, "by_source": dict(self.by_source)}


class StreamQueue:
    """Bounded, thread-safe buffer shared by every push receiver and the consumer."""

    def __init__(self, capacity: int = DEFAULT_CAPACITY):
        self.capacity = max(1, int(capacity))
        self._q: collections.deque[StreamItem] = collections.deque()
        self._cv = threading.Condition()
        self._full_logged = 0.0
        self.stats = StreamStats()
        self.enabled = False            # a receiver has been started → the registry drains this queue

    def put_many(self, source: str, lines: list[str], *, passthrough: bool = False) -> bool:
        """Enqueue a batch atomically. ``False`` (and nothing enqueued) when it would not fit —
        the caller answers 503 and the vendor retries the whole batch."""
        lines = [ln for ln in lines if ln and ln.strip()]
        if not lines:
            return True
        now = time.time()
        with self._cv:
            if len(self._q) + len(lines) > self.capacity:
                self.stats.rejected_full += len(lines)
                if now - self._full_logged >= 10:          # one line per 10 s while full, not one per rejected batch
                    self._full_logged = now
                    logger.warning("[stream] queue full (%d/%d): rejected %d %s records (%d total) — vendor will retry",
                                   len(self._q), self.capacity, len(lines), source, self.stats.rejected_full)
                return False
            for ln in lines:
                self._q.append(StreamItem(source=source, line=ln, received_at=now, passthrough=passthrough))
            self.stats.received += len(lines)
            self.stats.by_source[source] = self.stats.by_source.get(source, 0) + len(lines)
            self.stats.last_received_at = now
            self.stats.high_water = max(self.stats.high_water, len(self._q))
            self._cv.notify_all()
        return True

    def put(self, source: str, line: str, *, passthrough: bool = False) -> bool:
        return self.put_many(source, [line], passthrough=passthrough)

    def drain(self, max_items: int = 0) -> list[StreamItem]:
        """Take what is queued now, without blocking."""
        with self._cv:
            n = len(self._q) if max_items <= 0 else min(max_items, len(self._q))
            out = [self._q.popleft() for _ in range(n)]
            self.stats.drained += n
        return out

    def wait(self, timeout: float) -> bool:
        """Block until something is queued or ``timeout`` elapses. ``True`` when there is work."""
        with self._cv:
            if self._q:
                return True
            self._cv.wait(timeout=max(0.0, timeout))
            return bool(self._q)

    def __len__(self) -> int:
        with self._cv:
            return len(self._q)

    def clear(self) -> None:
        with self._cv:
            self._q.clear()


_shared: Optional[StreamQueue] = None
_shared_lock = threading.Lock()


def get_stream() -> StreamQueue:
    """The process-wide queue (capacity from ``AEGIS_STREAM_CAPACITY``)."""
    global _shared
    with _shared_lock:
        if _shared is None:
            import os
            _shared = StreamQueue(int(os.environ.get("AEGIS_STREAM_CAPACITY", str(DEFAULT_CAPACITY))))
        return _shared


def reset_stream() -> None:
    """Tests / fault injection: drop the shared queue so the next call builds a fresh one."""
    global _shared
    with _shared_lock:
        _shared = None


def _vendor_ts(alert: dict) -> Optional[float]:
    for k in ("timestamp", "ts", "observed_at", "TimeGenerated", "Datetime", "time"):
        v = alert.get(k)
        if isinstance(v, (int, float)):
            return float(v) / (1000.0 if v > 1e11 else 1.0)       # epoch ms vs s
        if isinstance(v, str) and v:
            try:
                return datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
            except ValueError:
                continue
    return None


class StreamConsumer(BaseConsumer):
    """Drains the shared queue; vendor records go through ``WafConsumer.normalize``
    (CEF / F5 / JSON incl. Cloudflare, AWS WAF, Azure WAF), passthrough items are
    taken as AEGIS alerts after a shape check."""

    name = "stream"

    def __init__(self, *, queue: Optional[StreamQueue] = None, checkpoint: Optional[AlertCheckpoint] = None,
                 max_items: int = 0):
        super().__init__(checkpoint)
        from .waf import WafConsumer
        self.queue = queue if queue is not None else get_stream()   # an empty queue is falsy
        self.max_items = max_items
        self._waf = WafConsumer(checkpoint=self.checkpoint)

    def fetch(self, **kwargs) -> Iterator[StreamItem]:
        yield from self.queue.drain(kwargs.get("max_items", self.max_items))

    def normalize(self, item: StreamItem) -> Any:
        if _is_apigw(item):
            return self._apigw(item)
        if _is_ndr(item):
            return self._ndr(item)
        if _is_netops(item):
            return self._netops(item)
        if item.passthrough:
            obj = json.loads(item.line)
            if not isinstance(obj, dict) or not obj.get("id"):
                return None
            alert = dict(obj)
            alert.setdefault("source", item.source)
        else:
            alert = self._waf.normalize(item.line)
            if alert is None:
                return None
        alert["received_at"] = item.received_at
        alert["ingest_source"] = item.source
        ts = _vendor_ts(alert)
        if ts is not None:
            alert["ingest_lag_ms"] = max(0, int((item.received_at - ts) * 1000))
        return alert


    def _apigw(self, item: StreamItem) -> Optional[dict]:
        """API-gateway events feed the stateful object-walk detector; most produce no alert."""
        from .apigw import normalize as apigw_normalize, shared_detector
        try:
            obj = json.loads(item.line)
        except json.JSONDecodeError:
            return None
        ev = apigw_normalize(obj)
        if ev is None:
            return None
        alert = shared_detector().observe(ev)
        if alert is None:
            return CONSUMED
        alert["received_at"] = item.received_at
        alert["ingest_source"] = item.source
        ts = _vendor_ts(alert)
        if ts is not None:
            alert["ingest_lag_ms"] = max(0, int((item.received_at - ts) * 1000))
        return alert


    def _ndr(self, item: StreamItem) -> Any:
        """Network sensor events feed the egress detector; most produce no alert."""
        from .ndr import normalize as ndr_normalize, shared_detector
        try:
            obj = json.loads(item.line)
        except json.JSONDecodeError:
            return None
        ev = ndr_normalize(obj)
        if ev is None:
            return CONSUMED
        alerts = shared_detector().observe(ev)
        for alert in alerts:
            alert["received_at"] = item.received_at
            alert["ingest_source"] = item.source
            ts = _vendor_ts(alert)
            if ts is not None:
                alert["ingest_lag_ms"] = max(0, int((item.received_at - ts) * 1000))
        return alerts or CONSUMED


    def _netops(self, item: StreamItem) -> Any:
        """Device syslog / traps / flows / telemetry / configs / LLDP feed the network-assurance detector;
        most records produce no alert (they build topology and counters)."""
        from .netops import normalize as netops_normalize, shared_detector
        from aegis.license import allows
        if not allows("netops"):
            return CONSUMED                                   # licence without network assurance: records are dropped, counted, not processed
        line = item.line.strip()
        record: Any = line
        if line[:1] in "{[":
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                return None
        ev = netops_normalize(record)
        if ev is None:
            return CONSUMED
        alerts = shared_detector().observe(ev)
        for alert in alerts:
            alert["received_at"] = item.received_at
            alert["ingest_source"] = item.source
            ts = _vendor_ts(alert)
            if ts is not None:
                alert["ingest_lag_ms"] = max(0, int((item.received_at - ts) * 1000))
        return alerts or CONSUMED


def _is_netops(item: StreamItem) -> bool:
    if item.passthrough:
        return False
    if item.source.startswith(("netops", "syslog", "snmp", "netflow", "telemetry")):
        return True
    head = item.line[:300]
    # a Cisco system message (%FACILITY-SEV-MNEMONIC:), an SNMP trap, or an LLDP/CDP neighbour row
    return bool(re.search(r"%[A-Z0-9_]+-[0-7]-[A-Z0-9_]+:", head)) or '"snmpTrapOID"' in head or '"trapName"' in head \
        or ('"neighbor"' in head and '"local_iface"' in head)


def _is_ndr(item: StreamItem) -> bool:
    if item.passthrough:
        return False
    if item.source.startswith("ndr"):
        return True
    head = item.line[:300]
    return '"id.orig_h"' in head or ('"event_type"' in head and ('"tls"' in head or '"flow"' in head) and '"src_ip"' in head)


def _is_apigw(item: StreamItem) -> bool:
    if item.passthrough:
        return False
    if item.source.startswith("apigw"):
        return True
    head = item.line[:400]
    return '"GatewayLogs"' in head or '"ApimSubscriptionId"' in head or '"apimSubscriptionId"' in head


MAX_INFLATE = 64 * 1024 * 1024      # decompressed bytes one body may expand to (AEGIS_INGEST_MAX_INFLATE_MB)


class InflateTooLarge(ValueError):
    pass


def gunzip_bounded(body: bytes, limit: Optional[int] = None) -> bytes:
    """gzip-decompress with a hard cap on the *output* — a 1000:1 bomb inside a 64 MB body must not become
    64 GB in process. Raises ``InflateTooLarge`` (a ``ValueError``) past the cap."""
    import os as _os
    import zlib
    if limit is None:
        try:
            limit = int(_os.environ.get("AEGIS_INGEST_MAX_INFLATE_MB", "")) * 1024 * 1024
        except ValueError:
            limit = MAX_INFLATE
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = d.decompress(body, limit + 1)
    if len(out) > limit or d.unconsumed_tail:
        raise InflateTooLarge(f"decompressed body over {limit} bytes")
    return out


def lines_from_body(body: bytes) -> list[str]:
    """Split a (possibly gzip-compressed) NDJSON / syslog body into lines (inflation bounded)."""
    if body[:2] == b"\x1f\x8b":
        body = gunzip_bounded(body)
    text = body.decode("utf-8", errors="replace")
    return [ln.rstrip("\r") for ln in text.split("\n") if ln.strip()]


__all__ = ["StreamQueue", "StreamItem", "StreamStats", "StreamConsumer", "get_stream", "reset_stream", "lines_from_body", "gunzip_bounded", "InflateTooLarge"]
