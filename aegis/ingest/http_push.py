"""HTTP push receiver — vendors POST events to AEGIS (stdlib only, no new dependency).

    POST /ingest/cloudflare   Cloudflare Logpush HTTP destination: gzip NDJSON of
                              firewall_events / http_requests; Logpush's job-validation
                              probe ({"content":"test"}) is answered 200 and ignored.
    POST /ingest/firehose     AWS Kinesis Data Firehose "HTTP endpoint" delivery: JSON
                              {requestId, timestamp, records:[{data: <base64>}]}; the reply
                              must echo requestId. WAF logs arrive one JSON object per record.
    POST /ingest/waf          any forwarder: NDJSON / CEF / F5 key=value lines, plain or gzip
                              (Imperva, F5, Azure via a Logstash / Fluent Bit / syslog relay).
    POST /ingest/apigw        API-gateway access logs (Azure APIM, AWS API Gateway, Kong, generic JSON),
                              NDJSON plain or gzip — fed to the object-walk (BOLA) detector; only its
                              alerts reach the orchestrator. ``?gateway=apim`` tags the source.
    POST /ingest/ndr          network sensor logs (Zeek ssl / conn / x509 JSON, Suricata EVE tls / flow,
                              generic flow JSON), NDJSON plain or gzip — fed to the egress detector
                              (beacons, exfiltration, known-bad TLS, shadow AI). ``?sensor=zeek`` tags it.
    POST /ingest/netops       network operations: Cisco IOS / NX-OS syslog (raw lines or JSON-wrapped), SNMP
                              traps as JSON, NetFlow / IPFIX summaries, gNMI / MDT interface telemetry, config
                              snapshots / change records, LLDP / CDP neighbour rows — NDJSON or raw syslog, plain
                              or gzip — fed to the network-assurance detector (one root cause per outage, downstream
                              alarms folded in, flaps, drift, bad pushes). ``?feed=syslog`` tags the source.
    POST /ingest/alerts       already-normalised AEGIS alerts, one JSON object per line
                              (custom forwarders, the purple-team harness).
    GET  /ingest/blocklist    the active enforcement set (IPs, CIDRs, client fingerprints)
    GET  /ingest/license      the installation's licence state (status, edition, tier, features, limits) — the
                              Kafka bridge checks the ``kafka_bridge`` feature here before it starts
    GET  /ingest/verdicts     cursor feed of finalised evidence chains for a message bus (the Kafka
                              bridge): ``?after=<seq>&limit=<n>`` returns chains with seq > after, in
                              order, with ``next`` to pass back; seq is the chain's 1-based position in
                              the audit log, so the cursor survives restarts and the hash chain verifies
                              for an edge enforcer — Envoy ext_authz, a Cloudflare Worker, the
                              Go tier-0 filter — to apply inline without any vendor API.
    GET  /healthz             queue depth and counters (no auth).
    GET  /metrics             Prometheus text: verdicts, actions, HITL queue, feed ages / silent
                              feeds, audit integrity, token spend. Open unless ``AEGIS_METRICS_TOKEN``
                              is set (then ``Authorization: Bearer``); serve it on the internal network.

Auth: every ``/ingest/*`` call must carry ``AEGIS_INGEST_TOKEN`` as ``Authorization: Bearer``,
``X-Amz-Firehose-Access-Key`` (what Firehose sends) or ``X-AEGIS-Token``; compared in constant
time. The server refuses to start without a token unless bound to loopback. TLS terminates at
the bank's load balancer / reverse proxy in front of this port (document in the runbook).

Replies: 200 accepted · 401 bad token · 413 body over ``AEGIS_INGEST_MAX_MB`` (64) · 415 wrong
shape · 503 queue full (vendors retry; nothing is silently dropped).
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import re
import json
import logging
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlsplit

from .console_api import console_api_from_env
from .stream import InflateTooLarge, StreamQueue, get_stream, gunzip_bounded, lines_from_body

logger = logging.getLogger("aegis.ingest.http")

DEFAULT_BIND = "0.0.0.0:8787"
DEFAULT_MAX_MB = 64
_LOOPBACK = ("127.0.0.1", "::1", "localhost")


def _is_loopback(host: str) -> bool:
    return host in _LOOPBACK


class _AuthFailLimiter:
    """Log at most one auth failure per client IP per minute — a scanner must not fill the log."""

    def __init__(self):
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def should_log(self, ip: str, now: Optional[float] = None) -> bool:
        now = now or time.time()
        with self._lock:
            last = self._seen.get(ip, 0.0)
            if now - last < 60:
                return False
            self._seen[ip] = now
            if len(self._seen) > 10_000:
                self._seen.clear()
            return True


class PushServer:
    """Threaded HTTP server feeding the shared ``StreamQueue``; ``start()`` returns at once."""

    def __init__(self, *, token: str, bind: str = DEFAULT_BIND, queue: Optional[StreamQueue] = None,
                 max_mb: int = DEFAULT_MAX_MB, blocklist: Optional[Callable[[], list[Any]]] = None,
                 audit_path: Optional[Path] = None, license: Optional[Callable[[], Any]] = None, read_token: str = "",
                 status: Optional[Callable[[], dict]] = None, console: Optional[Any] = None, console_token: str = ""):
        host, _, port = bind.rpartition(":")
        self.host, self.port = (host or "0.0.0.0"), int(port or 8787)
        if not token and not _is_loopback(self.host):
            raise ValueError("AEGIS_INGEST_TOKEN is required unless AEGIS_INGEST_BIND is loopback")
        self.token = token
        # the read side (/ingest/verdicts, /ingest/blocklist, /ingest/license) is for the Kafka bridge / SOAR, not for
        # every syslog relay that holds the push token: a separate AEGIS_INGEST_READ_TOKEN gates it when set
        self.read_token = read_token or token
        self._verdict_cache: tuple[int, int, str, int] = (0, 0, "0" * 64, 0)   # (seq, byte offset, prev_hash, generation)
        self.queue = queue if queue is not None else get_stream()   # an empty queue is falsy
        self.max_bytes = int(max_mb) * 1024 * 1024
        self.blocklist = blocklist
        self.audit_path = Path(audit_path) if audit_path else None
        self.license = license
        self.status = status                       # extra operator-facing health (audit writable? last checkpoint?)
        # the analyst console's read/decide API (/api/soc/*, /api/approvals); decisions need their own token
        self.console = console
        self.console_token = console_token
        self.limiter = _AuthFailLimiter()
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    # -- lifecycle
    def start(self) -> "PushServer":
        server = self
        handler = type("AegisPushHandler", (_Handler,), {"server_ref": server})
        self._httpd = ThreadingHTTPServer((self.host, self.port), handler)
        self._httpd.daemon_threads = True
        self.port = self._httpd.server_address[1]
        self.queue.enabled = True
        self._thread = threading.Thread(target=self._httpd.serve_forever, name="AegisPushServer", daemon=True)
        self._thread.start()
        logger.info("[ingest:http] push receiver listening on %s:%d (%s)", self.host, self.port,
                    "token required" if self.token else "loopback, no token")
        return self

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None

    @property
    def url(self) -> str:
        host = "127.0.0.1" if self.host in ("0.0.0.0", "") else self.host
        return f"http://{host}:{self.port}"

    # -- auth
    @staticmethod
    def _presented(headers: Any) -> str:
        presented = ""
        auth = headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            presented = auth[7:].strip()
        return presented or headers.get("X-Amz-Firehose-Access-Key", "") or headers.get("X-AEGIS-Token", "")

    def authorized(self, headers: Any) -> bool:
        if not self.token:
            return True
        presented = self._presented(headers)
        return bool(presented) and hmac.compare_digest(presented.encode(), self.token.encode())

    def read_authorized(self, headers: Any) -> bool:
        if not self.read_token:
            return True
        presented = self._presented(headers)
        if not presented:
            return False
        return (hmac.compare_digest(presented.encode(), self.read_token.encode())
                or (bool(self.console_token) and hmac.compare_digest(presented.encode(), self.console_token.encode())))

    def console_authorized(self, headers: Any) -> bool:
        """Decisions: only the console token (never the push or read token, which relays and bridges hold)."""
        if not self.console_token:
            return False
        presented = self._presented(headers)
        return bool(presented) and hmac.compare_digest(presented.encode(), self.console_token.encode())

    def console_get(self, path: str, query: dict) -> tuple[int, dict]:
        api = self.console
        if api is None:
            return 404, {"error": "console API not attached"}
        if path == "/api/soc/chains":
            try:
                limit = int((query.get("limit") or ["200"])[0])
            except ValueError:
                return 400, {"error": "limit must be an integer"}
            return 200, api.chains(limit)
        if path.startswith("/api/soc/chains/"):
            c = api.chain(path[len("/api/soc/chains/"):])
            return (200, c) if c else (404, {"error": "unknown chain"})
        if path == "/api/approvals":
            return 200, api.approvals()
        if path == "/api/soc/proposals":
            return 200, api.proposals()
        return 404, {"error": "not found"}

    def console_post(self, path: str, body: dict, headers: Any) -> tuple[int, dict]:
        api = self.console
        if api is None:
            return 404, {"error": "console API not attached"}
        who = re.sub(r"[^A-Za-z0-9 ._:@/-]", "", str(headers.get("X-AEGIS-User", "") or ""))[:120]   # role:user shape only — no log/line injection
        m = re.match(r"^/api/approvals/([^/]+)/(approve|reject)$", path)
        if m:
            status = "approved" if m.group(2) == "approve" else "rejected"
            return api.decide(m.group(1), status, decided_by=who, reason=str(body.get("rationale") or body.get("reason") or ""),
                              corrected_verdict=str(body.get("corrected_verdict") or ""))
        m = re.match(r"^/api/soc/proposals/([^/]+)/decide$", path)
        if m:
            return api.decide_proposal(m.group(1), str(body.get("decision") or ""), decided_by=who,
                                       rationale=str(body.get("rationale") or ""))
        return 404, {"error": "not found"}

    # -- the four ingest shapes; each returns (status, body_dict)
    def ingest_cloudflare(self, body: bytes) -> tuple[int, dict]:
        lines = lines_from_body(body)
        if len(lines) == 1 and lines[0].strip() in ('{"content":"test"}', '{"content": "test"}'):
            return 200, {"ok": True, "note": "logpush validation"}
        if not self.queue.put_many("cloudflare", lines):
            return 503, {"error": "queue full, retry"}
        return 200, {"ok": True, "accepted": len(lines)}

    def ingest_firehose(self, body: bytes, headers: Any) -> tuple[int, dict]:
        req_id = headers.get("X-Amz-Firehose-Request-Id", "")
        now_ms = int(time.time() * 1000)
        try:
            if body[:2] == b"\x1f\x8b":
                body = gunzip_bounded(body)
            payload = json.loads(body.decode("utf-8"))
            req_id = req_id or str(payload.get("requestId", ""))
            records = payload["records"]
            lines: list[str] = []
            for rec in records:
                data = base64.b64decode(rec["data"])
                if data[:2] == b"\x1f\x8b":
                    data = gunzip_bounded(data)
                lines.extend(lines_from_body(data))
                if sum(len(x) for x in lines) > self.max_bytes * 4:
                    raise InflateTooLarge("records expand past the receiver's inflate budget")
        except InflateTooLarge as e:
            return 413, {"requestId": req_id, "timestamp": now_ms, "errorMessage": str(e)[:120]}
        except (KeyError, TypeError, ValueError, UnicodeDecodeError, RecursionError) as e:
            return 400, {"requestId": req_id, "timestamp": now_ms, "errorMessage": f"malformed Firehose request: {str(e)[:120]}"}
        if not self.queue.put_many("firehose", lines):
            return 503, {"requestId": req_id, "timestamp": now_ms, "errorMessage": "queue full, retry"}
        return 200, {"requestId": req_id, "timestamp": now_ms}

    def ingest_waf(self, body: bytes, source: str) -> tuple[int, dict]:
        lines = lines_from_body(body)
        if not self.queue.put_many(source or "waf", lines):
            return 503, {"error": "queue full, retry"}
        return 200, {"ok": True, "accepted": len(lines)}

    def ingest_alerts(self, body: bytes) -> tuple[int, dict]:
        lines = lines_from_body(body)
        bad = 0
        good: list[str] = []
        for ln in lines:
            try:
                obj = json.loads(ln)
            except ValueError:
                bad += 1
                continue
            if isinstance(obj, dict) and obj.get("id"):
                if obj.get("alert_type") == "network_fault" and isinstance(obj.get("netops"), dict):
                    # a pre-correlated network fault would skip the LLM and go straight to config_rollback / revoke_sessions
                    # proposals; faults are derived here from raw syslog/telemetry (/ingest/netops), never accepted ready-made
                    obj.pop("netops", None)
                    obj["alert_type"] = "network_event"
                    obj["note"] = "pushed as network_fault; demoted — correlation happens inside AEGIS"
                    ln = json.dumps(obj, separators=(",", ":"))
                good.append(ln)
            else:
                bad += 1
        if lines and not good:
            return 415, {"error": "expected one AEGIS alert JSON object (with id) per line", "rejected": bad}
        if not self.queue.put_many("alerts", good, passthrough=True):
            return 503, {"error": "queue full, retry"}
        return 200, {"ok": True, "accepted": len(good), "rejected": bad}

    def blocklist_payload(self) -> dict:
        from ..agents.shared.fingerprint import is_fingerprint_target, parse_target
        ips: list[dict] = []
        fps: list[dict] = []
        if self.blocklist is not None:
            try:
                receipts = self.blocklist()
            except Exception as e:  # noqa: BLE001 — a broken registry must not take the receiver down
                logger.warning("[ingest:http] blocklist source failed: %s", str(e)[:120])
                receipts = []
            for r in receipts:
                if getattr(r, "dry_run", False) or getattr(r, "action_type", "") not in ("block", "challenge", "throttle"):
                    continue
                row = {"action": r.action_type, "expires_at": r.expires_at, "receipt": r.receipt_id}
                t = str(r.target)
                if is_fingerprint_target(t):
                    try:
                        kind, value, ua = parse_target(t)
                    except ValueError:
                        continue
                    fps.append({**row, "kind": kind, "value": value, "user_agent": ua or None})
                else:
                    ips.append({**row, "target": t})
        return {"generated_at": time.time(), "ips": ips, "fingerprints": fps}

    def verdicts_payload(self, after: int, limit: int) -> dict:
        """Chains with seq > ``after`` from the audit log. ``seq`` is the 1-based line number: append-only,
        so a consumer that stores ``next`` resumes exactly where it stopped, and ``integrity_hash`` /
        ``prev`` let it re-verify the chain on its side."""
        limit = max(1, min(int(limit), 1000))
        out: list[dict] = []
        seq, offset, prev = 0, 0, "0" * 64
        generation = self._generation()
        if self.audit_path is not None and self.audit_path.exists():
            c_seq, c_off, c_prev, c_gen = self._verdict_cache
            size = self.audit_path.stat().st_size
            if c_gen == generation and after >= c_seq and c_off <= size:
                seq, offset, prev = c_seq, c_off, c_prev          # resume from the last served row instead of re-reading the file
            with self.audit_path.open("rb") as fh:
                fh.seek(offset)
                while True:
                    raw = fh.readline()
                    if not raw:
                        break
                    if not raw.endswith(b"\n"):
                        break                                       # a row still being written
                    offset += len(raw)
                    line = raw.decode("utf-8", "replace")
                    if not line.strip():
                        continue
                    seq += 1
                    if seq <= after:
                        try:
                            prev = json.loads(line).get("integrity_hash", prev)
                        except json.JSONDecodeError:
                            pass
                        continue
                    try:
                        chain = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    out.append({"seq": seq, "prev_hash": prev, "chain": chain})
                    prev = chain.get("integrity_hash", prev)
                    if len(out) >= limit:
                        break
            if seq >= after:
                self._verdict_cache = (seq, offset, prev, generation)
        return {"after": after, "next": out[-1]["seq"] if out else after, "count": len(out), "verdicts": out,
                "generation": generation}

    def _generation(self) -> int:
        """Identifies THIS audit log: inode + the first row's hash. A consumer whose stored generation differs
        (rotation, truncation, restore) resets its cursor to 0 instead of waiting forever for seq to catch up."""
        if self.audit_path is None or not self.audit_path.exists():
            return 0
        try:
            st = self.audit_path.stat()
            with self.audit_path.open("rb") as fh:
                head = fh.readline()
            return (st.st_ino & 0xFFFFFFFF) * 1000003 + (int.from_bytes(hashlib.sha1(head).digest()[:4], "big") if head else 0)
        except OSError:
            return 0


class _Handler(BaseHTTPRequestHandler):
    server_ref: PushServer
    timeout = 30
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:     # stdlib logs to stderr; route to our logger at DEBUG
        logger.debug("[ingest:http] " + fmt, *args)

    def _reply(self, status: int, body: dict) -> None:
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _unauthorized(self, path: str, body: Optional[dict] = None) -> None:
        ip = self.client_address[0] if self.client_address else "?"
        if self.server_ref.limiter.should_log(ip):
            logger.warning("[ingest:http] unauthorized %s %s from %s", self.command, path, ip)
        self._refuse(401, body or {"error": "unauthorized"})

    def _refuse(self, status: int, body: dict) -> None:
        """Reply without reading the body and drop the connection — leftover bytes must not be parsed as the next request."""
        self.close_connection = True
        self._reply(status, body)

    def _body(self) -> Optional[bytes]:
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._refuse(400, {"error": "bad Content-Length"})
            return None
        if n < 0:
            self._refuse(400, {"error": "bad Content-Length"})
            return None
        if n > self.server_ref.max_bytes:
            self._refuse(413, {"error": f"body over {self.server_ref.max_bytes} bytes"})
            return None
        return self.rfile.read(n) if n else b""

    def do_GET(self) -> None:  # noqa: N802 — stdlib naming
        try:
            self._get()
        except Exception as e:  # noqa: BLE001 — a bad row in a file must answer 500, not a dropped socket + stderr traceback
            logger.error("[ingest:http] GET %s failed: %s", urlsplit(self.path).path, str(e)[:200], exc_info=True)
            try:
                self._reply(500, {"error": "internal"})
            except Exception:  # noqa: BLE001
                pass

    def _get(self) -> None:
        path = urlsplit(self.path).path
        if path == "/healthz":
            body = {"ok": True, "queue": len(self.server_ref.queue), **self.server_ref.queue.stats.to_dict()}
            if self.server_ref.license is not None:
                try:
                    st = self.server_ref.license()
                    body["license"] = {"status": st.status, "days_left": st.days_left}     # the id is on the authenticated /ingest/license
                except Exception:  # noqa: BLE001
                    pass
            if self.server_ref.status is not None:
                try:
                    body.update(self.server_ref.status())
                except Exception:  # noqa: BLE001
                    pass
            self._reply(503 if body.get("degraded") else 200, body)
            return
        if path == "/ingest/license":
            if not self.server_ref.read_authorized(self.headers):
                self._reply(401, {"error": "unauthorized"})
                return
            if self.server_ref.license is None:
                self._reply(503, {"error": "no licence state attached to this receiver"})
                return
            self._reply(200, self.server_ref.license().to_dict())
            return
        if path == "/metrics":
            from aegis.agents.shared.observability import METRICS, PROMETHEUS_CONTENT_TYPE, metrics_authorized
            if not metrics_authorized(self.headers):
                self._reply(401, {"error": "unauthorized"})
                return
            raw = METRICS.prometheus_text().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", PROMETHEUS_CONTENT_TYPE)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        if path == "/ingest/blocklist":
            if not self.server_ref.read_authorized(self.headers):
                self._reply(401, {"error": "unauthorized"})
                return
            self._reply(200, self.server_ref.blocklist_payload())
            return
        if path == "/ingest/verdicts":
            if not self.server_ref.read_authorized(self.headers):
                self._reply(401, {"error": "unauthorized"})
                return
            if self.server_ref.audit_path is None:
                self._reply(503, {"error": "no audit log attached to this receiver"})
                return
            q = parse_qs(urlsplit(self.path).query)
            try:
                after = int((q.get("after") or ["0"])[0])
                limit = int((q.get("limit") or ["200"])[0])
            except ValueError:
                self._reply(400, {"error": "after and limit must be integers"})
                return
            self._reply(200, self.server_ref.verdicts_payload(max(0, after), limit))
            return
        if path.startswith("/api/"):
            if not self.server_ref.read_authorized(self.headers):
                self._unauthorized(path)
                return
            status, out = self.server_ref.console_get(path, parse_qs(urlsplit(self.path).query))
            self._reply(status, out)
            return
        self._reply(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        srv = self.server_ref
        parts = urlsplit(self.path)
        path = parts.path
        if path.startswith("/api/"):
            if not srv.console_authorized(self.headers):
                self._unauthorized(path)
                return
            raw = self._body()
            if raw is None:
                return
            try:
                body = json.loads(raw.decode("utf-8")) if raw.strip() else {}
            except (ValueError, UnicodeDecodeError, RecursionError):
                self._reply(400, {"error": "body must be JSON"})
                return
            try:
                status, out = srv.console_post(path, body if isinstance(body, dict) else {}, self.headers)
            except Exception as e:  # noqa: BLE001
                logger.error("[ingest:http] %s failed: %s", path, str(e)[:200], exc_info=True)
                status, out = 500, {"error": "internal"}
            self._reply(status, out)
            return
        if not path.startswith("/ingest/"):
            self._reply(404, {"error": "not found"})
            return
        if not srv.authorized(self.headers):
            self._unauthorized(path, {"error": "unauthorized", "requestId": self.headers.get("X-Amz-Firehose-Request-Id", ""),
                                      "timestamp": int(time.time() * 1000), "errorMessage": "unauthorized"})
            return
        body = self._body()
        if body is None:
            return
        try:
            if path == "/ingest/cloudflare":
                status, out = srv.ingest_cloudflare(body)
            elif path == "/ingest/firehose":
                status, out = srv.ingest_firehose(body, self.headers)
            elif path == "/ingest/waf":
                source = (parse_qs(parts.query).get("source") or [self.headers.get("X-AEGIS-Source", "")])[0]
                status, out = srv.ingest_waf(body, (source or "waf").strip().lower()[:32])
            elif path == "/ingest/apigw":
                gw = (parse_qs(parts.query).get("gateway") or [""])[0].strip().lower()[:24]
                status, out = srv.ingest_waf(body, f"apigw-{gw}" if gw else "apigw")
            elif path == "/ingest/ndr":
                sensor = (parse_qs(parts.query).get("sensor") or [""])[0].strip().lower()[:24]
                status, out = srv.ingest_waf(body, f"ndr-{sensor}" if sensor else "ndr")
            elif path == "/ingest/netops":
                from aegis.license import allows
                if not allows("netops"):
                    self._reply(402, {"error": "network assurance is not included in this installation's licence"})
                    return
                feed = (parse_qs(parts.query).get("feed") or [""])[0].strip().lower()[:24]   # syslog | snmp | netflow | telemetry | config | lldp
                status, out = srv.ingest_waf(body, f"netops-{feed}" if feed else "netops")
            elif path == "/ingest/alerts":
                status, out = srv.ingest_alerts(body)
            else:
                status, out = 404, {"error": "not found"}
        except Exception as e:  # noqa: BLE001 — one bad batch must not kill the receiver thread
            logger.error("[ingest:http] %s failed: %s", path, str(e)[:200], exc_info=True)
            status, out = 500, {"error": "internal"}
        self._reply(status, out)


def push_server_from_env(blocklist: Optional[Callable[[], list[Any]]] = None, *,
                         audit_path: Optional[Path] = None, license: Optional[Callable[[], Any]] = None,
                         status: Optional[Callable[[], dict]] = None) -> Optional[PushServer]:
    """``AEGIS_INGEST_HTTP=1`` (or any ``AEGIS_INGEST_BIND``) starts the receiver; ``AEGIS_INGEST_TOKEN``
    is required off loopback. Returns the running server or ``None``."""
    on = os.environ.get("AEGIS_INGEST_HTTP", "").strip().lower() in ("1", "true", "yes", "on")
    bind = os.environ.get("AEGIS_INGEST_BIND", "").strip()
    if not (on or bind):
        return None
    try:
        srv = PushServer(token=os.environ.get("AEGIS_INGEST_TOKEN", "").strip(), bind=bind or DEFAULT_BIND,
                         max_mb=int(os.environ.get("AEGIS_INGEST_MAX_MB", str(DEFAULT_MAX_MB))), blocklist=blocklist,
                         audit_path=audit_path, license=license, read_token=os.environ.get("AEGIS_INGEST_READ_TOKEN", "").strip(),
                         status=status, console=console_api_from_env(audit_path),
                         console_token=os.environ.get("AEGIS_CONSOLE_TOKEN", "").strip())
        return srv.start()
    except Exception as e:  # noqa: BLE001 — a bad bind must not take the SOC down; polling still works
        logger.error("[ingest:http] push receiver not started: %s", str(e)[:200])
        return None


__all__ = ["PushServer", "push_server_from_env", "DEFAULT_BIND"]
