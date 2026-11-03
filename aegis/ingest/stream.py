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
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator, Optional

from .base import CONSUMED, AlertCheckpoint, BaseConsumer

logger = logging.getLogger("aegis.ingest.stream")

DEFAULT_CAPACITY = 50_000



def _as_utc(d: datetime) -> datetime:
    """A timestamp with no zone is UTC (what log shippers mean), not this host's local time — an IST host read
    every naive vendor time 5 h 30 min off, which broke windows and lag (review round 3 I3-16)."""
    from datetime import UTC
    return d if d.tzinfo is not None else d.replace(tzinfo=UTC)

@dataclass
class StreamItem:
    source: str                 # cloudflare | firehose | waf | alerts | azure-eventhub | …
    line: str                   # one raw record (JSON / CEF / F5 kv) or a normalised alert JSON
    received_at: float
    passthrough: bool = False   # already an AEGIS alert dict → no vendor normalisation
    journal_end: int = -1       # byte offset in the journal just past this record (-1: not journaled)


MAX_SOURCES = 256       # distinct feed names tracked; the rest are counted as "other"


@dataclass
class StreamStats:
    received: int = 0
    rejected_full: int = 0
    drained: int = 0
    high_water: int = 0
    last_received_at: float = 0.0
    by_source: dict[str, int] = field(default_factory=dict)
    #: records per source that parsed into an alert (or were consumed by a stateful detector) — what liveness
    #: counts. Records RECEIVED under a free-text name said nothing about whether the feed still parses: a vendor
    #: format change that made every record invalid still looked live (review round 3 I3-17).
    parsed_by_source: dict[str, int] = field(default_factory=dict)
    _touched: dict[str, float] = field(default_factory=dict)

    def bump(self, table: dict[str, int], source: str, n: int, now: float) -> None:
        """Count ``n`` under ``source``. At MAX_SOURCES names the one idle longest (over an hour) makes room; only
        if none is idle does the new name fold into "other". The cap never forgot a name, so 256 junk names
        pushed early kept every later real feed out of the per-source view (review round 3 R3-15)."""
        if source not in table and len(table) >= MAX_SOURCES:
            idle = min((k for k in table if k != "other"), key=lambda k: self._touched.get(k, 0.0), default=None)
            if idle is not None and now - self._touched.get(idle, 0.0) > 3600:
                table.pop(idle, None)
            else:
                source = "other"
        table[source] = table.get(source, 0) + n
        self._touched[source] = now

    def to_dict(self) -> dict:
        return {"received": self.received, "rejected_full": self.rejected_full, "drained": self.drained,
                "high_water": self.high_water, "last_received_at": self.last_received_at, "by_source": dict(self.by_source),
                "parsed_by_source": dict(self.parsed_by_source)}


class StreamQueue:
    """Bounded, thread-safe buffer shared by every push receiver and the consumer."""

    def __init__(self, capacity: int = DEFAULT_CAPACITY, *, journal: str | Path | None = None, fsync: bool = False):
        self.capacity = max(1, int(capacity))
        self._q: collections.deque[StreamItem] = collections.deque()
        self._cv = threading.Condition()
        self._full_logged = 0.0
        self.stats = StreamStats()
        self.enabled = False            # a receiver has been started → the registry drains this queue
        # Optional write-ahead journal (review E15, second half). A pushed batch was answered 200 while it existed
        # only in memory, so a crash or a restart lost up to the whole queue. With a journal, a batch is on disk
        # before the vendor gets its 200; what was handled is committed; on start the rest is queued again.
        self.journal = Path(journal) if journal else None
        self._fsync = fsync
        self._committed = 0
        self._last_commit_write = 0.0
        if self.journal is not None:
            self._replay()

    # ---- journal -------------------------------------------------------------------------------------------
    def _cursor(self) -> Path:
        assert self.journal is not None
        return self.journal.with_name(self.journal.name + ".cursor")

    def _replay(self) -> None:
        assert self.journal is not None
        self.journal.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._committed = int(self._cursor().read_text().strip() or 0)
        except (OSError, ValueError):
            self._committed = 0
        if not self.journal.exists():
            self._committed = 0
            return
        n = 0
        with self.journal.open("rb") as fh:
            fh.seek(self._committed)
            pos = self._committed
            for raw in fh:
                if not raw.endswith(b"\n"):
                    break                                 # a torn last write: never answered 200
                pos += len(raw)
                try:
                    r = json.loads(raw)
                    self._q.append(StreamItem(source=str(r["s"]), line=str(r["l"]), received_at=float(r["t"]),
                                              passthrough=bool(r.get("p")), journal_end=pos))
                    n += 1
                except (ValueError, KeyError, TypeError):
                    continue
        if n:
            logger.warning("[stream] re-queued %d pushed record(s) from %s that were accepted but not handled before "
                           "the last stop", n, self.journal)

    def _append_journal(self, items: list[StreamItem]) -> bool:
        assert self.journal is not None
        data = b"".join((json.dumps({"s": it.source, "l": it.line, "t": it.received_at, "p": it.passthrough},
                                    separators=(",", ":")) + "\n").encode() for it in items)
        try:
            fd = os.open(self.journal, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "ab") as fh:
                start = fh.tell()
                try:
                    fh.write(data)
                    fh.flush()
                    if self._fsync:
                        os.fsync(fh.fileno())
                except OSError:
                    fh.truncate(start)
                    raise
        except OSError as e:
            logger.error("[stream] journal %s not writable (%s) — answering 503 so the vendor keeps the batch",
                         self.journal, e.strerror or e)
            return False
        pos = start
        for it in items:
            pos += len((json.dumps({"s": it.source, "l": it.line, "t": it.received_at, "p": it.passthrough},
                                   separators=(",", ":")) + "\n").encode())
            it.journal_end = pos
        return True

    def commit(self, item: StreamItem, *, force: bool = False) -> None:
        """``item`` (and everything queued before it) has been handled."""
        if self.journal is None or item.journal_end < 0:
            return
        with self._cv:
            self._committed = max(self._committed, item.journal_end)
            now = time.monotonic()
            if not force and now - self._last_commit_write < 1.0:
                return
            self._last_commit_write = now
            self._write_cursor()

    def flush_commit(self) -> None:
        if self.journal is None:
            return
        with self._cv:
            self._write_cursor()

    def _write_cursor(self) -> None:
        assert self.journal is not None
        try:
            if not self._q and self.journal.exists() and self._committed >= self.journal.stat().st_size:
                # everything handled: start the journal over (cursor first — a crash in between replays nothing)
                self._cursor().write_text("0")
                self.journal.unlink(missing_ok=True)
                self._committed = 0
                return
            tmp = self._cursor().with_suffix(".tmp")
            tmp.write_text(str(self._committed))
            os.replace(tmp, self._cursor())
        except OSError as e:
            logger.warning("[stream] journal cursor not written (%s) — handled records may be re-queued after a restart", e)

    def requeue_front(self, items: list[StreamItem]) -> None:
        """Drained but not handled (the consumer stopped early): back to the head of the queue, in order."""
        if not items:
            return
        with self._cv:
            self._q.extendleft(reversed(items))
            self.stats.drained -= len(items)
            self._cv.notify_all()

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
            batch = [StreamItem(source=source, line=ln, received_at=now, passthrough=passthrough) for ln in lines]
            if self.journal is not None and not self._append_journal(batch):
                return False
            self._q.extend(batch)
            self.stats.received += len(lines)
            # ?source= / headers are free text: the distinct names counted are capped (idle ones expire)
            self.stats.bump(self.stats.by_source, source, len(lines), now)
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
            _shared = StreamQueue(int(os.environ.get("AEGIS_STREAM_CAPACITY", str(DEFAULT_CAPACITY))),
                                  journal=os.environ.get("AEGIS_STREAM_JOURNAL", "").strip() or None,
                                  fsync=os.environ.get("AEGIS_STREAM_JOURNAL_FSYNC", "0").strip() == "1")
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
                return _as_utc(datetime.fromisoformat(v.replace("Z", "+00:00"))).timestamp()
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
        items = self.queue.drain(kwargs.get("max_items", self.max_items))
        done = 0
        try:
            for it in items:
                yield it
                done += 1                       # resumed: the caller handled this record
                self.queue.commit(it)
        finally:
            # stopped early (max_alerts, shutdown): what was drained but not handled goes back, not into the void
            self.queue.requeue_front(items[done:])
            commit = getattr(self.queue, "flush_commit", None)
            if callable(commit):
                commit()

    def normalize(self, item: StreamItem) -> Any:
        out = self._normalize(item)
        alerts = out if isinstance(out, list) else [out]
        if out is CONSUMED or any(isinstance(a, dict) and a.get("id") for a in alerts):
            with self.queue._cv:
                self.queue.stats.bump(self.queue.stats.parsed_by_source, item.source, 1, time.time())
        return out

    def _normalize(self, item: StreamItem) -> Any:
        if item.source.startswith("edr") and not item.passthrough:
            return self._edr(item)
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


    def _edr(self, item: StreamItem) -> Any:
        """Host telemetry (Sysmon events, osquery result logs) pushed to ``/ingest/edr``."""
        from aegis.agents.edr.normalize import to_alert
        try:
            obj = json.loads(item.line)
        except json.JSONDecodeError:
            return None
        alert = to_alert(obj)
        if alert is None:
            return CONSUMED
        alert["received_at"] = item.received_at
        alert["ingest_source"] = item.source
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


# Content sniffing looks at a record's STRUCTURE (its top-level JSON keys, or a syslog line's own header),
# never at arbitrary substrings: a WAF event's Referer / URI / payload is attacker-controlled, and a
# "%SYS-5-CONFIG_I:" or '"id.orig_h"' planted there used to send the record to the netops / NDR parser,
# which dropped it — switching WAF detection off for that attacker's requests.
_WAF_SOURCES = ("waf", "cloudflare", "imperva", "f5", "akamai", "aws-waf", "awswaf", "azure-waf", "fortiweb", "edge")
# A device syslog header is a run of plain tokens (PRI, sequence number, timestamp, hostname) before the
# %FACILITY-SEVERITY-MNEMONIC: tag. Tokens may not contain / ? = & quotes or brackets, so a web/WAF log line
# whose URI carries "/%SYS-5-CONFIG_I:" is not taken for a router's syslog (any 160 characters used to match).
# RFC 5424 lines may carry STRUCTURED-DATA before the message — `[meta sequenceId="1"]` elements (or "-") —
# which the token rule refused, so those lines stopped reaching netops (review round 3 R3-13).
_SD_ELEMENT = r'\[[A-Za-z0-9_.@-]{1,32}(?:\s+[A-Za-z0-9_.@-]{1,32}="(?:[^"\\\]]|\\.){0,128}")*\]'
_SYSLOG_HEAD = re.compile(r"^(?:<\d{1,3}>)?(?:[^\s{}/?=&\"'<>\[\]]+\s+){0,12}(?:(?:" + _SD_ELEMENT + r")+\s+)?"
                          r"%[A-Z0-9_]+-[0-7]-[A-Z0-9_]+:")


def _top_keys(item: StreamItem) -> set[str] | None:
    """Top-level keys of a JSON-object line (None for a non-JSON line). Cached on the item."""
    cached = getattr(item, "_top_keys", False)
    if cached is not False:
        return cached
    keys: set[str] | None = None
    line = item.line.lstrip()
    if line.startswith("{"):
        try:
            obj = json.loads(line)
            keys = set(obj) if isinstance(obj, dict) else None
            if keys is not None:
                keys |= {f"{k}={v}" for k, v in obj.items() if k == "event_type" and isinstance(v, str)}
        except (ValueError, RecursionError):
            keys = None
    try:
        object.__setattr__(item, "_top_keys", keys)
    except (AttributeError, TypeError):
        pass
    return keys


def _named_waf(item: StreamItem) -> bool:
    return item.source.lower().startswith(_WAF_SOURCES)


def _is_netops(item: StreamItem) -> bool:
    if item.passthrough or _named_waf(item):
        return False
    if item.source.startswith(("netops", "syslog", "snmp", "netflow", "telemetry")):
        return True
    keys = _top_keys(item)
    if keys is not None:
        return bool(keys & {"snmpTrapOID", "trapName"}) or {"neighbor", "local_iface"} <= keys
    line = item.line[:400]
    # a Cisco system message in the syslog header itself — not anywhere in a CEF / LEEF extension
    return not line.lstrip().startswith(("CEF:", "LEEF:")) and "CEF:" not in line[:120] and bool(_SYSLOG_HEAD.search(line))


def _is_ndr(item: StreamItem) -> bool:
    if item.passthrough or _named_waf(item):
        return False
    if item.source.startswith("ndr"):
        return True
    keys = _top_keys(item)
    if keys is None:
        return False
    return "id.orig_h" in keys or (("event_type=tls" in keys or "event_type=flow" in keys) and "src_ip" in keys)


def _is_apigw(item: StreamItem) -> bool:
    if item.passthrough or _named_waf(item):
        return False
    if item.source.startswith("apigw"):
        return True
    keys = _top_keys(item)
    return bool(keys) and bool(keys & {"GatewayLogs", "ApimSubscriptionId", "apimSubscriptionId"})


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
    # every member of a multi-member gzip (`cat a.gz b.gz`, what log shippers append): only the first was read
    # and the rest silently dropped (review round 3 G4-5)
    out = bytearray()
    rest = body
    while rest:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out += d.decompress(rest, limit + 1 - len(out))
        if len(out) > limit or d.unconsumed_tail:
            raise InflateTooLarge(f"decompressed body over {limit} bytes")
        if not d.eof:
            raise ValueError("truncated gzip member")
        rest = d.unused_data
        if rest[:2] != b"\x1f\x8b":
            break                                         # trailing padding / garbage after the last member
    return bytes(out)


def lines_from_body(body: bytes) -> list[str]:
    """Split a (possibly gzip-compressed) NDJSON / syslog body into lines (inflation bounded)."""
    if body[:2] == b"\x1f\x8b":
        body = gunzip_bounded(body)
    text = body.decode("utf-8", errors="replace")
    return [ln.rstrip("\r") for ln in text.split("\n") if ln.strip()]


__all__ = ["StreamQueue", "StreamItem", "StreamStats", "StreamConsumer", "get_stream", "reset_stream", "lines_from_body", "gunzip_bounded", "InflateTooLarge"]
