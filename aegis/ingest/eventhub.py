"""Azure Event Hubs reader — Azure WAF (Front Door / Application Gateway) diagnostics, streamed.

Azure cannot push HTTP to us; its diagnostic settings stream to an Event Hub. This reader
(``azure-eventhub`` SDK, optional dependency) receives batches, splits each event body
(``{"records": [...]}`` or NDJSON) into lines on the shared ``StreamQueue``, and keeps its
own per-partition checkpoint in a small JSON file — no storage account needed for a single
SOC process. On restart it resumes from the last sequence number per partition
(``AEGIS_EVENTHUB_START=latest|earliest`` decides where a *fresh* checkpoint starts).

Env: ``AEGIS_EVENTHUB_CONN`` (namespace connection string **with** ``EntityPath=``, or set
``AEGIS_EVENTHUB_NAME``), ``AEGIS_EVENTHUB_GROUP`` (default ``$Default``),
``AEGIS_EVENTHUB_CHECKPOINT`` (default ``.aegis-eventhub.json``).

The SDK client is injectable (``client_factory``) so the reader is tested without Azure.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

from .stream import StreamQueue, get_stream

logger = logging.getLogger("aegis.ingest.eventhub")


class EventHubReader:
    def __init__(self, *, connection_string: str, eventhub_name: str = "", consumer_group: str = "$Default",
                 checkpoint_path: str | Path = ".aegis-eventhub.json", start: str = "latest",
                 queue: Optional[StreamQueue] = None, client_factory: Optional[Callable[..., Any]] = None,
                 source: str = "azure-eventhub", backoff_s: float = 5.0):
        self.connection_string = connection_string
        self.eventhub_name = eventhub_name
        self.consumer_group = consumer_group
        self.checkpoint_path = Path(checkpoint_path)
        self.default_start = start            # latest | earliest, for a fresh checkpoint
        self.queue = queue if queue is not None else get_stream()   # an empty queue is falsy
        self._factory = client_factory
        self.source = source
        self.backoff_s = backoff_s
        self._positions: dict[str, int] = self._load()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._client: Any = None
        self.batches = 0
        self.events = 0

    # -- checkpoint
    def _load(self) -> dict[str, int]:
        try:
            if self.checkpoint_path.exists():
                data = json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
                return {str(k): int(v) for k, v in (data.get("positions") or {}).items()}
        except Exception as e:  # noqa: BLE001 — a corrupt checkpoint means a clean start, not a crash
            logger.warning("[ingest:eventhub] checkpoint %s unreadable (%s); starting fresh", self.checkpoint_path, e)
        return {}

    def _save(self) -> None:
        try:
            self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.checkpoint_path.with_suffix(self.checkpoint_path.suffix + ".tmp")
            tmp.write_text(json.dumps({"positions": self._positions, "saved_at": time.time()}), encoding="utf-8")
            tmp.replace(self.checkpoint_path)
        except Exception as e:  # noqa: BLE001
            logger.warning("[ingest:eventhub] checkpoint write failed: %s", e)

    def starting_position(self) -> Any:
        """Per-partition sequence numbers (exclusive) where known; otherwise the configured default."""
        default = "-1" if self.default_start == "earliest" else "@latest"
        if not self._positions:
            return default
        return {pid: seq for pid, seq in self._positions.items()}

    # -- batch handling (also the unit the tests drive directly)
    def on_batch(self, partition_context: Any, events: list[Any]) -> None:
        if not events:
            return
        pid = str(getattr(partition_context, "partition_id", "?"))
        lines: list[str] = []
        last_seq: Optional[int] = None
        for ev in events:
            try:
                body = ev.body_as_str() if hasattr(ev, "body_as_str") else str(ev)
            except Exception as e:  # noqa: BLE001 — one undecodable event
                logger.warning("[ingest:eventhub] partition %s: event body unreadable: %s", pid, str(e)[:120])
                continue
            lines.extend(_split_body(body))
            seq = getattr(ev, "sequence_number", None)
            if isinstance(seq, int):
                last_seq = seq
        if not self.queue.put_many(self.source, lines):
            # queue full: do not advance the checkpoint; the SDK will not re-deliver, so retry the same batch until
            # it fits or we are stopped. Blocking here is the backpressure: the partition stops fetching. It used to
            # give up after 60 tries and return — and the NEXT batch's checkpoint moved past the dropped one
            # (code review 2026-11-03 E9). On stop we return without a checkpoint: the batch is re-read on restart.
            attempt = 0
            while not self.queue.put_many(self.source, lines):
                if self._stop.is_set():
                    return
                attempt += 1
                if attempt in (60, 600) or attempt % 3000 == 0:
                    logger.error("[ingest:eventhub] partition %s: queue full for %d tries — holding %d record(s), "
                                 "not checkpointing", pid, attempt, len(lines))
                time.sleep(min(self.backoff_s, 0.1 * min(attempt, 20)))
        self.batches += 1
        self.events += len(events)
        if last_seq is not None:
            with self._lock:
                self._positions[pid] = last_seq
                self._save()
        try:
            if hasattr(partition_context, "update_checkpoint"):
                partition_context.update_checkpoint(events[-1])
        except Exception:  # noqa: BLE001 — no checkpoint store configured is the normal case
            pass

    # -- lifecycle
    def _make_client(self) -> Any:
        if self._factory is not None:
            return self._factory(conn_str=self.connection_string, consumer_group=self.consumer_group,
                                 eventhub_name=self.eventhub_name or None)
        try:
            from azure.eventhub import EventHubConsumerClient  # type: ignore
        except ImportError:
            raise RuntimeError("azure-eventhub is not installed: pip install azure-eventhub") from None
        kw: dict[str, Any] = {"conn_str": self.connection_string, "consumer_group": self.consumer_group}
        if self.eventhub_name:
            kw["eventhub_name"] = self.eventhub_name
        return EventHubConsumerClient.from_connection_string(**kw)

    def _run(self) -> None:
        delay = self.backoff_s
        while not self._stop.is_set():
            try:
                self._client = self._make_client()
                with self._client:
                    logger.info("[ingest:eventhub] receiving (%s) from %s", self.consumer_group, self.starting_position())
                    self._client.receive_batch(on_event_batch=self.on_batch, starting_position=self.starting_position(),
                                               max_batch_size=500, max_wait_time=5)
                delay = self.backoff_s
            except Exception as e:  # noqa: BLE001 — network / auth / SDK: back off and reconnect, never die
                if self._stop.is_set():
                    break
                logger.warning("[ingest:eventhub] receive loop failed (%s: %s); reconnecting in %.0fs",
                               type(e).__name__, str(e)[:160], delay)
                self._stop.wait(delay)
                delay = min(delay * 2, 300)

    def start(self) -> "EventHubReader":
        self.queue.enabled = True
        self._thread = threading.Thread(target=self._run, name="AegisEventHubReader", daemon=True)
        self._thread.start()
        return self

    def stop(self, join_timeout: float = 5.0) -> None:
        self._stop.set()
        client = self._client
        if client is not None:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(join_timeout)


def _split_body(body: str) -> list[str]:
    body = body.strip()
    if not body:
        return []
    if body.startswith("{"):
        try:
            obj = json.loads(body)
        except ValueError:
            obj = None
        if isinstance(obj, dict) and isinstance(obj.get("records"), list):
            return [json.dumps(r) for r in obj["records"] if isinstance(r, dict)]
        if isinstance(obj, dict):
            return [body]
    return [ln for ln in body.split("\n") if ln.strip()]


def eventhub_from_env(queue: Optional[StreamQueue] = None) -> Optional[EventHubReader]:
    conn = os.environ.get("AEGIS_EVENTHUB_CONN", "").strip()
    if not conn:
        logger.warning("[ingest:eventhub] eventhub requested but AEGIS_EVENTHUB_CONN unset; skipped")
        return None
    try:
        import azure.eventhub  # noqa: F401
    except ImportError:
        logger.error("[ingest:eventhub] azure-eventhub is not installed (pip install azure-eventhub); source skipped")
        return None
    reader = EventHubReader(connection_string=conn, eventhub_name=os.environ.get("AEGIS_EVENTHUB_NAME", ""),
                            consumer_group=os.environ.get("AEGIS_EVENTHUB_GROUP", "$Default"),
                            checkpoint_path=os.environ.get("AEGIS_EVENTHUB_CHECKPOINT", ".aegis-eventhub.json"),
                            start=os.environ.get("AEGIS_EVENTHUB_START", "latest").strip().lower(), queue=queue,
                            source=os.environ.get("AEGIS_EVENTHUB_SOURCE", "azure-eventhub").strip() or "azure-eventhub")
    return reader.start()


__all__ = ["EventHubReader", "eventhub_from_env"]
