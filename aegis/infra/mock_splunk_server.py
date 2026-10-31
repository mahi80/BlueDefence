"""Local mock Splunk HTTP server.

Implements the minimal subset of Splunk's REST API that
SplunkConsumer (aegis/infra/splunk_source.py) uses, so the AEGIS demo
runs end-to-end against a Splunk-shaped source without a real cluster.

Endpoints supported:
  POST /services/auth/login              (form: username, password)
  POST /services/search/jobs/export      (form: search, output_mode, ...)
  POST /services/collector/event         (HEC ingest — used by seed_splunk.py)

Auth: accepts any username/password in the demo (returns a fake session
key) AND accepts a bearer token in `Authorization: Bearer <anything>`
or `Authorization: Splunk <session_key>`.

NOT implemented (intentionally — out of scope for the mock):
  - SPL parsing beyond a few simple filters (`index=`, `sourcetype=`,
    `host=`, free-text terms). Production swaps to real Splunk.
  - Search jobs lifecycle (sid, status polling). The export endpoint is
    streaming and self-contained, sufficient for the consumer.
  - HEC ack mode, batched POST, channel routing.

Run standalone for testing:
  python -m aegis.infra.mock_splunk_server --port 8089
"""
from __future__ import annotations

import argparse
import http.server
import json
import logging
import re
import threading
import time
import urllib.parse
from collections import deque
from typing import Iterable, Optional


_log = logging.getLogger("aegis.mock_splunk")


# ---- In-memory event store ---------------------------------------------

class EventStore:
    """Thread-safe, capped FIFO of Splunk-shaped events."""

    def __init__(self, capacity: int = 10_000):
        self._buf: deque[dict] = deque(maxlen=capacity)
        self._lock = threading.Lock()

    def append(self, event: dict) -> None:
        with self._lock:
            self._buf.append(event)

    def query(
        self,
        *,
        index: Optional[str] = None,
        sourcetype: Optional[str] = None,
        host: Optional[str] = None,
        terms: Optional[list[str]] = None,
        max_count: int = 1000,
    ) -> Iterable[dict]:
        with self._lock:
            snap = list(self._buf)
        out: list[dict] = []
        for ev in reversed(snap):  # newest first, like real Splunk default
            if index and ev.get("index") != index:
                continue
            if sourcetype and ev.get("sourcetype") != sourcetype:
                continue
            if host and ev.get("host") != host:
                continue
            if terms:
                hay = (ev.get("_raw") or "") + " " + " ".join(
                    f"{k}={v}" for k, v in ev.items() if not k.startswith("_")
                )
                hay = hay.lower()
                if not all(t.lower() in hay for t in terms):
                    continue
            out.append(ev)
            if len(out) >= max_count:
                break
        return out


# ---- SPL parsing (just the subset we need) ----------------------------

_SPL_KV_RX = re.compile(r"(\w+)=(\"[^\"]*\"|\S+)")


def parse_spl(spl: str) -> dict:
    """Parse a small subset: index=, sourcetype=, host=, free terms."""
    spl = spl.strip()
    # Drop leading "search" verb if present
    if spl.lower().startswith("search "):
        spl = spl[7:]
    # Drop pipeline tail (head, sort, etc.) — we always return everything
    spl = spl.split("|", 1)[0]
    parsed: dict = {"index": None, "sourcetype": None, "host": None, "terms": []}
    consumed: list[tuple[int, int]] = []
    for m in _SPL_KV_RX.finditer(spl):
        key = m.group(1).lower()
        val = m.group(2).strip('"')
        consumed.append((m.start(), m.end()))
        if key in parsed:
            parsed[key] = val
    # Free text terms = anything not consumed by k=v matches
    rebuilt = []
    last = 0
    for s, e in consumed:
        rebuilt.append(spl[last:s])
        last = e
    rebuilt.append(spl[last:])
    leftover = " ".join(rebuilt).split()
    parsed["terms"] = [t for t in leftover if t and t != "*"]
    return parsed


# ---- HTTP handler -----------------------------------------------------

class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "MockSplunkd/1.0"

    # http.server logs every request; quiet it for cleaner demo output
    def log_message(self, format: str, *args) -> None:  # noqa: A002
        _log.debug("%s - %s", self.address_string(), format % args)

    # ---- helpers
    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length) if length else b""

    def _form(self) -> dict:
        body = self._read_body().decode("utf-8")
        parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
        return {k: v[0] for k, v in parsed.items()}

    def _json(self) -> dict:
        body = self._read_body().decode("utf-8")
        try:
            return json.loads(body) if body else {}
        except json.JSONDecodeError:
            return {}

    def _send_json(self, status: int, payload: dict) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_text(self, status: int, body: str, content_type: str = "text/plain") -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _is_authorized(self) -> bool:
        # Accept ANY non-empty Authorization header in mock mode. The
        # real consumer's behavior (Bearer / Splunk session) is exercised
        # because the consumer sends one or the other; we just don't gate.
        return bool(self.headers.get("Authorization", "").strip())

    # ---- routes
    def do_POST(self) -> None:  # noqa: N802
        path = urllib.parse.urlparse(self.path).path

        if path == "/services/auth/login":
            form = self._form()
            user = form.get("username", "")
            # Returns fake session key. Real Splunk validates here.
            self._send_json(200, {"sessionKey": f"mock-session-{user or 'anon'}-{int(time.time())}"})
            return

        if path == "/services/search/jobs/export":
            if not self._is_authorized():
                self._send_json(401, {"messages": [{"type": "ERROR", "text": "auth required"}]})
                return
            form = self._form()
            spl = form.get("search", "")
            max_count = int(form.get("count", "1000"))
            parsed = parse_spl(spl)
            store: EventStore = self.server.event_store  # type: ignore[attr-defined]
            results = store.query(
                index=parsed["index"],
                sourcetype=parsed["sourcetype"],
                host=parsed["host"],
                terms=parsed["terms"],
                max_count=max_count,
            )
            # Stream NDJSON, one event per line, real-Splunk export shape
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson")
            self.end_headers()
            for ev in results:
                line = json.dumps({"result": ev}) + "\n"
                try:
                    self.wfile.write(line.encode("utf-8"))
                except (BrokenPipeError, ConnectionResetError):
                    return
            return

        if path == "/services/collector/event":
            # HEC ingest. Bodies are NDJSON, one event per line.
            if not self._is_authorized():
                self._send_json(401, {"text": "auth required", "code": 2})
                return
            store: EventStore = self.server.event_store  # type: ignore[attr-defined]
            body = self._read_body().decode("utf-8")
            n = 0
            for raw_line in body.splitlines():
                if not raw_line.strip():
                    continue
                try:
                    payload = json.loads(raw_line)
                except json.JSONDecodeError:
                    continue
                event_field = payload.get("event")
                event = {
                    "_time": str(payload.get("time", time.time())),
                    "_raw": json.dumps(event_field) if isinstance(event_field, (dict, list)) else str(event_field),
                    "index": payload.get("index", "main"),
                    "sourcetype": payload.get("sourcetype", "generic"),
                    "host": payload.get("host", "mock-splunk"),
                }
                # Surface common AEGIS fields at top level for easy SPL filtering
                if isinstance(event_field, dict):
                    for k in ("id", "severity", "source_ip", "user_id", "host"):
                        if k in event_field:
                            event[k] = event_field[k]
                store.append(event)
                n += 1
            self._send_json(200, {"text": "Success", "code": 0, "ackId": n})
            return

        self._send_json(404, {"messages": [{"type": "ERROR", "text": f"unknown path {path}"}]})

    def do_GET(self) -> None:  # noqa: N802
        path = urllib.parse.urlparse(self.path).path
        if path == "/services/server/info":
            self._send_json(200, {
                "entry": [{"content": {"version": "9.0.0-mock", "isFree": "0"}}],
            })
            return
        if path == "/health":
            self._send_text(200, "ok\n")
            return
        self._send_json(404, {"messages": [{"type": "ERROR", "text": f"unknown path {path}"}]})


class _Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, store: EventStore):
        super().__init__(addr, _Handler)
        self.event_store = store


# ---- public API for embedding in demos ---------------------------------

class MockSplunkd:
    def __init__(self, host: str = "127.0.0.1", port: int = 8089):
        self._store = EventStore()
        self._server = _Server((host, port), self._store)
        self._thread: Optional[threading.Thread] = None
        self.host = host
        self.port = self._server.server_address[1]

    @property
    def store(self) -> EventStore:
        return self._store

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="MockSplunkd", daemon=True
        )
        self._thread.start()
        _log.info("mock splunk: serving at %s", self.url)

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()


# ---- standalone runner -------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8089)
    args = p.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    server = MockSplunkd(args.host, args.port)
    server.start()
    print(f"Mock Splunk listening on {server.url}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nshutting down")
        server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
