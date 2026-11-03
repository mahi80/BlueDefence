#!/usr/bin/env python3
"""AEGIS Edge Shim — put the SOC in front of *any* local HTTP app, no app changes.

AEGIS is a detection+response brain, not an inline proxy: to protect a site it needs
to *see* its traffic and have a way to *enforce*. This shim is both seams in one small
stdlib reverse proxy you drop in front of an app:

    browser ──▶  aegis_edge (this)  ──▶  your app (--upstream)
                      │  every request, inspected
                      ├──▶ AEGIS  /ingest/alerts     (eyes: telemetry the SOC triages)
                      └──◀ AEGIS  /ingest/blocklist  (hands: who to deny at the edge)

It reuses the Ledger Demo Bank's signature inspection (``demo_target.inspect`` /
``to_alert``) so the SOC sees the same alert shape, forwards every request as telemetry,
and polls the SOC's active blocklist. A source the SOC has called malicious (auto-block,
or a human-approved containment) lands on that blocklist and its next request is denied
here — never reaching the app.

Two modes (``--mode``):
    shadow  (default)  everything is forwarded upstream; a block is logged as "would deny"
                       so you can confirm zero collateral before arming it.
    live               blocked sources get 403 at the edge.

This is the *defender* side only. The app behind it is unchanged and not made vulnerable;
no attack traffic is generated here. Drive your own testing against the shim's address.

stdlib only. Example:

    export AEGIS_INGEST_TOKEN=... ; python3 scripts/aegis_edge.py \
        --listen 127.0.0.1:9000 --upstream http://127.0.0.1:3000 \
        --aegis-url http://127.0.0.1:8787/ingest/alerts --mode shadow
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import os
import sys
import threading
import time
import uuid
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit
import hashlib
import hmac
import urllib.error
import urllib.request

# Reuse the demo bank's signature engine + AEGIS alert shape + forwarder, so the SOC sees
# one consistent alert contract whether traffic hits the demo bank or a shimmed third app.
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # repo root, so `aegis.*` is importable
import demo_target as dt  # noqa: E402
# Response-side secret guard reuses the perimeter detector's exfil logic, so the shim withholds exactly
# what the SOC's secret_exfil_probe flags — one source of truth for "what is a leaked credential".
from aegis.agents.perimeter.tools import secret_exfil_probe  # noqa: E402

# Hop-by-hop headers never forwarded across a proxy (RFC 7230 §6.1) + ones we set ourselves.
_HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
               "trailer", "transfer-encoding", "upgrade", "host", "content-length"}
_MAX_BODY = 2 * 1024 * 1024
_MAX_PUSHED = int(os.environ.get("AEGIS_EDGE_MAX_PUSHED", "10000"))     # SOC-pushed targets kept
_MAX_CLIENTS = int(os.environ.get("AEGIS_EDGE_MAX_CLIENTS", "50000"))   # per-source state kept (LRU)


class _BadExpiry(ValueError):
    pass


def _expiry(v: Any) -> float | None:
    """``expires_at`` as epoch seconds (None = permanent). Accepts a number or an ISO-8601 string; anything
    else raises. ``is_blocked`` compares it with a float on every request, so a string stored as-is (one
    push of ``"2026-11-02T12:00:00Z"``) used to raise TypeError for every later request and take the edge down."""
    if v is None or v == "":
        return None
    if isinstance(v, bool):
        raise _BadExpiry("boolean expires_at")
    if isinstance(v, (int, float)):
        f = float(v)
    else:
        from datetime import UTC, datetime
        try:
            dtv = datetime.fromisoformat(str(v).strip())
        except ValueError as e:
            raise _BadExpiry(f"expires_at {str(v)[:40]!r} is not a time") from e
        if dtv.tzinfo is None:
            dtv = dtv.replace(tzinfo=UTC)
        f = dtv.timestamp()
    if not math.isfinite(f):
        raise _BadExpiry("expires_at is not finite")
    return f
_ENFORCE_ACTIONS = {"block"}            # a plain HTTP edge can hard-deny; challenge/throttle are advisory here


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A transparent proxy must NOT follow 3xx itself. urllib's default opener auto-follows
    redirects: on an auth flow (login POST -> 302 + Set-Cookie -> dashboard) it would chase the
    Location with no cookie jar, swallow the Set-Cookie, and report the *followed* final status.
    That (a) breaks the real client's session — the attacker/scanner can't authenticate through
    the shim, so a whole stream silently measures nothing — and (b) collapses two app hits into
    one distorted event. Returning None relays the 3xx verbatim (its Location + Set-Cookie go to
    the real client, which follows it), so every client request is exactly one upstream hit and
    one telemetry event carrying the true status."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


#: Shared opener that relays redirects instead of following them (see _NoRedirect). A non-followed
#: 3xx surfaces as urllib.error.HTTPError and is relayed by _forward_upstream's existing handler.
_OPENER = urllib.request.build_opener(_NoRedirect)


# ---- caller identity (for IDOR / id-enumeration correlation) -----------

_SESSION_COOKIE_NAMES = ("session", "sessionid", "session_id", "phpsessid", "sid", "jsessionid",
                         "connect.sid", "auth", "authtoken", "auth_token", "token", "sess", "_session",
                         "laravel_session", "ci_session")
_PRINCIPAL_SALT = (os.environ.get("AEGIS_PRINCIPAL_SALT")
                   or os.environ.get("AEGIS_DATASET_SALT") or "aegis-edge").encode("utf-8")


def _principal(hl: dict) -> str:
    """A stable, privacy-preserving fingerprint of the caller — an HMAC of the session cookie
    value or the Authorization bearer, never the raw credential. Lets the SOC attribute requests
    to one identity (IDOR / id-enumeration) without the shim storing secrets. '' = anonymous."""
    secret = b""
    auth = str(hl.get("authorization", ""))
    if auth[:7].lower() == "bearer ":
        secret = auth[7:].strip().encode("utf-8", "replace")
    if not secret:
        for part in str(hl.get("cookie", "")).split(";"):
            k, _, v = part.strip().partition("=")
            if k.strip().lower() in _SESSION_COOKIE_NAMES and v.strip():
                secret = v.strip().encode("utf-8", "replace")
                break
    if not secret:
        return ""
    return "p:" + hmac.new(_PRINCIPAL_SALT, secret, hashlib.sha256).hexdigest()[:16]


def _blocklist_url(aegis_url: str) -> str:
    """Derive the blocklist endpoint from the alerts URL (same host, /ingest/blocklist)."""
    u = urlsplit(aegis_url)
    return f"{u.scheme}://{u.netloc}/ingest/blocklist"


class Blocklist:
    """The SOC's active enforcement set, pulled from ``GET /ingest/blocklist`` and pushed to via
    ``/control/enforce``. Membership is by IP or CIDR; expired entries (TTL'd blocks) fall off.

    Only ``block`` is hard-denied at this layer — a plain reverse proxy cannot issue a managed
    challenge or a true rate-limit, so ``challenge`` / ``throttle`` are kept as advisory and logged.
    """

    def __init__(self, url: str | None, token: str | None, poll_s: float = 2.0) -> None:
        self._url = url
        self._token = token
        self._poll_s = max(0.5, poll_s)
        self._poll_failures = 0
        self._lock = threading.Lock()
        self._nets: list[tuple[Any, float | None]] = []    # (ip_network, expires_at|None) from the SOC poll
        # target -> (network, expires_at|None) from /control/enforce; capped (oldest evicted, expired first)
        self._pushed: dict[str, tuple[Any, float | None]] = {}
        self._last_ok = 0.0

    def start(self) -> "Blocklist":
        if self._url:
            threading.Thread(target=self._loop, name="aegis-edge-blocklist", daemon=True).start()
        return self

    def _loop(self) -> None:
        while True:
            try:
                self._poll_once()
                if self._poll_failures:
                    print(f"[aegis-edge] blocklist poll recovered after {self._poll_failures} failure(s)", file=sys.stderr)
                self._poll_failures = 0
            except Exception as e:  # noqa: BLE001 — a transient SOC outage must never take the edge down
                # ...but it must be visible: new containment does not reach the edge while this fails
                self._poll_failures += 1
                if self._poll_failures in (1, 10) or self._poll_failures % 100 == 0:
                    print(f"[aegis-edge] blocklist poll failed ({self._poll_failures}x, keeping the last good list): "
                          f"{type(e).__name__}: {str(e)[:160]}", file=sys.stderr)
            time.sleep(self._poll_s)

    def _poll_once(self) -> None:
        req = urllib.request.Request(self._url, method="GET")
        if self._token:
            req.add_header("Authorization", f"Bearer {self._token}")
        with urllib.request.urlopen(req, timeout=3.0) as r:
            payload = json.loads(r.read().decode("utf-8", "replace"))
        nets: list[tuple[Any, float | None]] = []
        for row in payload.get("ips", []):
            if str(row.get("action", "")).lower() not in _ENFORCE_ACTIONS:
                continue
            try:
                nets.append((ipaddress.ip_network(str(row["target"]), strict=False), _expiry(row.get("expires_at"))))
            except (KeyError, ValueError):          # _BadExpiry is a ValueError: a malformed row is skipped
                continue
        with self._lock:
            self._nets = nets
            self._last_ok = time.time()

    def push(self, target: str, expires_at: Any) -> bool:
        try:
            net = ipaddress.ip_network(target, strict=False)
            exp = _expiry(expires_at)
        except ValueError:
            return False
        now = time.time()
        with self._lock:
            self._pushed.pop(target, None)                 # re-insert: the newest push is the last evicted
            if len(self._pushed) >= _MAX_PUSHED:
                for t in [t for t, (_n, e) in self._pushed.items() if e is not None and e <= now]:
                    self._pushed.pop(t, None)
                while len(self._pushed) >= _MAX_PUSHED:
                    self._pushed.pop(next(iter(self._pushed)))
            self._pushed[target] = (net, exp)
        return True

    def is_blocked(self, ip: str | None) -> bool:
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        now = time.time()
        with self._lock:
            for net, exp in self._nets:
                if (exp is None or exp > now) and addr in net:
                    return True
            for target, (net, exp) in list(self._pushed.items()):
                if exp is not None and exp <= now:
                    self._pushed.pop(target, None)
                    continue
                if addr.version == net.version and addr in net:
                    return True
        return False

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {"soc_nets": [str(n) for n, _ in self._nets], "pushed": sorted(self._pushed),
                    "last_poll_ok_s_ago": round(time.time() - self._last_ok, 1) if self._last_ok else None}


class EdgeState:
    def __init__(self, *, upstream: str, aegis_url: str | None, token: str | None, asset: str,
                 mode: str, inline_waf: bool, blocklist: Blocklist,
                 redact_secrets: bool = True) -> None:
        self.upstream = upstream.rstrip("/")
        self.aegis_url = aegis_url
        self.token = token
        self.asset = asset
        self.mode = mode                      # "shadow" | "live"
        self.inline_waf = inline_waf
        self.redact_secrets = redact_secrets  # live mode: withhold a response body carrying a secret
        self.blocklist = blocklist
        self.clients: OrderedDict[str, dt.ClientState] = OrderedDict()     # LRU, capped at _MAX_CLIENTS
        self.denied = 0
        self.forwarded = 0
        self._lock = threading.Lock()

    def client_state(self, ip: str) -> dt.ClientState:
        with self._lock:
            st = self.clients.get(ip)
            if st is None:
                st = self.clients[ip] = dt.ClientState()
                while len(self.clients) > _MAX_CLIENTS:
                    self.clients.popitem(last=False)
            else:
                self.clients.move_to_end(ip)
            return st


class Handler(BaseHTTPRequestHandler):
    server_version = "AegisEdge/1.0"

    @property
    def state(self) -> "EdgeState":
        return self.server.state  # type: ignore[attr-defined] — set on the server in build_server

    def log_message(self, *_a: Any) -> None:
        pass

    # -- identity: the real peer IP. X-Demo-Src (a scripted demo's spoofed source) is honoured ONLY when the
    # shim is started with AEGIS_EDGE_TRUST_DEMO_SRC=1: in front of a real app any client could set it to
    # step around the blocklist or pin its attack on an innocent IP.
    def _client_ip(self) -> str:
        if os.environ.get("AEGIS_EDGE_TRUST_DEMO_SRC", "").strip() == "1":
            return self.headers.get("X-Demo-Src") or self.client_address[0]
        return self.client_address[0]

    def _headers_lc(self) -> dict[str, str]:
        return {k.lower(): v for k, v in self.headers.items()}

    def _read_body(self) -> bytes | None:
        """The whole request body, or None after replying 400/413. A chunked body used to be skipped
        entirely (never inspected, and forwarded empty) and an over-size one silently truncated."""
        te = self.headers.get("Transfer-Encoding", "").lower()
        if "chunked" in te:
            return self._read_chunked()
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            self._reply_close(400, b"bad Content-Length")
            return None
        if n > _MAX_BODY:
            self._reply_close(413, b"request body too large for the edge to inspect")
            return None
        return self.rfile.read(n) if n > 0 else b""

    def _read_chunked(self) -> bytes | None:
        out = bytearray()
        while True:
            line = self.rfile.readline(1024)
            size_txt = line.split(b";", 1)[0].strip()
            # hex digits only: int(b"-1", 16) is -1, and rfile.read(-1) reads to EOF with no cap
            if not size_txt or len(size_txt) > 8 or any(c not in b"0123456789abcdefABCDEF" for c in size_txt):
                self._reply_close(400, b"malformed chunked body")
                return None
            size = int(size_txt, 16)
            if size == 0:
                while self.rfile.readline(1024) not in (b"\r\n", b"\n", b""):   # trailers
                    pass
                return bytes(out)
            if len(out) + size > _MAX_BODY:
                self._reply_close(413, b"request body too large for the edge to inspect")
                return None
            out += self.rfile.read(size)
            self.rfile.readline(1024)                          # CRLF after the chunk

    def _local_peer(self) -> bool:
        return self.client_address[0] in ("127.0.0.1", "::1")

    def _reply_close(self, code: int, msg: bytes) -> None:
        self.close_connection = True                           # the rest of the body is still on the socket
        self._reply(code, msg, "text/plain", {"Connection": "close"})

    def _reply(self, code: int, body: bytes, ctype: str, extra: dict[str, str] | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def _json(self, code: int, obj: Any) -> None:
        self._reply(code, json.dumps(obj).encode(), "application/json", {"Cache-Control": "no-store"})

    # -- SOC → edge push enforcement (token-gated), mirrors demo_target /control/enforce -------- #
    def _control_authorized(self) -> bool:
        tok = self.state.token
        if not tok:
            return False
        got = self.headers.get("Authorization", "")
        if got.lower().startswith("bearer "):
            got = got[7:].strip()
        return bool(got) and hmac.compare_digest(got.encode(), tok.encode())

    def _handle_control(self, body: bytes) -> None:
        if not self._control_authorized():
            self._json(401, {"error": "control requires the shared bearer token (AEGIS_INGEST_TOKEN)"})
            return
        try:
            req = json.loads(body or b"{}")
        except ValueError:
            req = {}
        action = str(req.get("action", ""))
        target = str(req.get("target") or req.get("ip") or "")
        applied = {"action": action, "target": target}
        if action in ("isolate", "block_egress", "block_ip", "block") and target:
            applied["accepted"] = self.state.blocklist.push(target, req.get("expires_at"))
        else:
            applied["accepted"] = False
        self._json(200, {**applied, **self.state.blocklist.snapshot()})

    # -- routing ------------------------------------------------------------------------------- #
    def do_GET(self) -> None:
        self._dispatch()

    def do_POST(self) -> None:
        self._dispatch()

    def do_PUT(self) -> None:
        self._dispatch()

    def do_DELETE(self) -> None:
        self._dispatch()

    def do_PATCH(self) -> None:
        self._dispatch()

    def _dispatch(self) -> None:
        route = urlsplit(self.path).path
        if route == "/control/enforce" and self.command == "POST":
            body = self._read_body()
            if body is not None:
                self._handle_control(body)
            return
        if route == "/__edge/health":
            # liveness for anyone; the details (mode, upstream, the blocklist) only with the shared token or
            # from the box itself — they tell an attacker whether blocks are enforced and which IPs to avoid
            if not (self._control_authorized() or self._local_peer()):
                self._json(200, {"ok": True})
                return
            self._json(200, {"ok": True, "mode": self.state.mode, "upstream": self.state.upstream,
                             "inline_waf": self.state.inline_waf, "asset": self.state.asset,
                             "denied": self.state.denied, "forwarded": self.state.forwarded,
                             "clients": len(self.state.clients), "blocklist": self.state.blocklist.snapshot()})
            return
        self._proxy()

    # -- the proxy + SOC seams ----------------------------------------------------------------- #
    def _proxy(self) -> None:
        parts = urlsplit(self.path)
        ip = self._client_ip()
        hl = self._headers_lc()
        ua = hl.get("user-agent", "")
        body = self._read_body()
        if body is None:                       # already answered 400 / 413
            return

        # HANDS: a source the SOC has blocked is denied here before anything reaches the app.
        if self.state.blocklist.is_blocked(ip):
            if self.state.mode == "live":
                self.state.denied += 1
                self._forward("blocked", parts, ua, ip, body, hl, extra={"op": "soc_block", "severity": "high"})
                self._json(403, {"error": "blocked by SOC containment", "source": ip})
                return
            # shadow: record that we *would* have denied, then let it through so nothing breaks
            self._forward("would_block", parts, ua, ip, body, hl, extra={"op": "soc_block_shadow", "severity": "high"})

        # EYES: inspect with the shared signature engine. URL-encoding is normalized first (as a real
        # WAF does) so an encoded payload is caught like a plain one.
        findings = dt.inspect(self.command, unquote(parts.path), unquote(parts.query), hl,
                              unquote(body.decode("utf-8", "replace")), state=self.state.client_state(ip))

        # inline WAF hard-block short-circuits before the app is ever hit (no upstream response to attach)
        if findings and self.state.inline_waf and self.state.mode == "live":
            alert = dt.to_alert(findings, src_ip=ip, method=self.command, url=self.path, ua=ua, asset=self.state.asset)
            alert.update(self._raw_fields(parts, ip, hl, body, None))
            dt._forward_alert(self.state.aegis_url, self.state.token, alert)
            self.state.forwarded += 1
            self.state.denied += 1
            self._json(403, {"error": "request blocked at edge (inline WAF)", "rules": alert["rules"]})
            return

        # Forward to the app FIRST so telemetry can carry the response headers (CORS etc.), then send
        # ONE enriched event per request: the shim's own WAF verdict (if any) PLUS the raw request/
        # response, so the SOC's perimeter scorers evaluate what the edge signature rules missed.
        resp = self._forward_upstream(parts, body, ip)
        if findings:
            event = dt.to_alert(findings, src_ip=ip, method=self.command, url=self.path, ua=ua, asset=self.state.asset)
            self.state.forwarded += 1
        else:
            event = {
                "id": f"edge-{uuid.uuid4().hex[:10]}", "source": "waf", "ts": dt._now_iso(),
                "action": "allowed", "severity": "info", "op": "page_view",
                "src_ip": ip, "method": self.command, "url": self.path, "query": parts.query,
                "body": body[:4096].decode("utf-8", "replace"), "user_agent": ua,
                "ja3": self.headers.get("X-Demo-JA3", ""), "asset": self.state.asset,
            }
        event.update(self._raw_fields(parts, ip, hl, body, resp))
        kinds = getattr(self, "_exfil_kinds", None)
        if kinds:
            redacted = self.state.mode == "live" and self.state.redact_secrets
            event["op"] = "secret_exfil"
            event["severity"] = "high"
            event["action"] = "blocked" if redacted else "would_block"
            event["secret_kinds"] = kinds          # labels only — the secret is never forwarded
            self._exfil_kinds = None
        if self.state.aegis_url:
            dt._forward_alert(self.state.aegis_url, self.state.token, event)

    def _raw_fields(self, parts: Any, ip: str, hl: dict[str, str], body: bytes,
                    resp: "tuple[int, dict[str, str]] | None") -> dict[str, Any]:
        """The request (and, once forwarded, response) data the SOC's perimeter scorers read:
        payload / source_ip / request_headers / host / body_params / response_headers. Without
        these the scorers scan empty strings and never fire on shim traffic, and the triage brain
        never sees the attack string."""
        body_text = body.decode("utf-8", "replace")
        payload = (unquote(parts.query) + ((" " + body_text) if body_text else ""))[:8192]
        fields: dict[str, Any] = {
            "payload": payload,            # scan surface for the brain + decode_payload / ssrf_probe
            "source_ip": ip,               # the perimeter specialist reads source_ip, not src_ip
            "request_headers": dict(hl),
            "host": hl.get("host", ""),
        }
        principal = _principal(hl)
        if principal:
            fields["principal"] = principal   # hashed caller identity for IDOR / id-enumeration
        if body_text and "application/x-www-form-urlencoded" in hl.get("content-type", ""):
            try:
                fields["body_params"] = {k: (v[0] if v else "")
                                         for k, v in parse_qs(body_text, keep_blank_values=True).items()}
            except Exception:  # noqa: BLE001 — not a form body; mass_assignment falls back to the payload
                pass
        if resp is not None:
            fields["response_status"], fields["response_headers"] = resp
        return fields

    def _forward(self, action: str, parts: Any, ua: str, ip: str, body: bytes, hl: dict[str, str], *,
                 resp: "tuple[int, dict[str, str]] | None" = None,
                 extra: dict[str, Any] | None = None) -> None:
        """Send one telemetry event to AEGIS so the SOC sees the full request stream, not only blocks —
        carrying the raw request/response so the perimeter scorers can evaluate it."""
        if not self.state.aegis_url:
            return
        event = {
            "id": f"edge-{uuid.uuid4().hex[:10]}", "source": "waf", "ts": dt._now_iso(),
            "action": action, "severity": "info" if action == "allowed" else "high",
            "src_ip": ip, "method": self.command, "url": self.path, "query": parts.query,
            "body": body[:4096].decode("utf-8", "replace"), "user_agent": ua,
            "ja3": self.headers.get("X-Demo-JA3", ""), "asset": self.state.asset, "op": "page_view",
        }
        event.update(self._raw_fields(parts, ip, hl, body, resp))
        if extra:
            event.update(extra)
        dt._forward_alert(self.state.aegis_url, self.state.token, event)

    def _forward_upstream(self, parts: Any, body: bytes, ip: str) -> tuple[int, dict[str, str]] | None:
        """Relay to the app and return (status, response_headers) so telemetry can carry the
        response (CORS reflection etc.). None when the upstream was unreachable."""
        url = f"{self.state.upstream}{parts.path}" + (f"?{parts.query}" if parts.query else "")
        fwd_headers = {k: v for k, v in self.headers.items() if k.lower() not in _HOP_BY_HOP}
        up = urlsplit(self.state.upstream).netloc
        fwd_headers["Host"] = up
        fwd_headers["X-Forwarded-For"] = ip
        fwd_headers["X-Forwarded-Proto"] = "http"
        fwd_headers["X-Real-IP"] = ip
        req = urllib.request.Request(url, data=(body or None), method=self.command, headers=fwd_headers)
        try:
            # _OPENER relays 3xx instead of following them — the real client handles the redirect,
            # keeping its cookie/session and making every request exactly one hit + one event.
            with _OPENER.open(req, timeout=15.0) as r:
                rhdrs = {k.lower(): v for k, v in r.headers.items()}
                code = self._guard_and_relay(r.status, r.read(), r.headers)
                return code, rhdrs
        except urllib.error.HTTPError as e:                # upstream 4xx/5xx is a real response — relay it
            rhdrs = {k.lower(): v for k, v in e.headers.items()}
            code = self._guard_and_relay(e.code, e.read(), e.headers)
            return code, rhdrs
        except (urllib.error.URLError, OSError) as e:
            self._json(502, {"error": "upstream unreachable", "upstream": self.state.upstream, "detail": str(e)[:200]})
            return None

    def _relay(self, code: int, body: bytes, headers: Any) -> None:
        ctype = headers.get("Content-Type") or "application/octet-stream"
        passthru = {k: v for k, v in headers.items()
                    if k.lower() not in _HOP_BY_HOP and k.lower() != "content-type"}
        self._reply(code, body, ctype, passthru)

    def _guard_and_relay(self, code: int, body: bytes, headers: Any) -> int:
        """Response-side secret guard. Scan the body the app returned, and in live mode WITHHOLD it
        when it carries a credential — a private key, a cloud/API key, a DSN with an inline password,
        or ``DB_PASSWORD=``-style env assignments. The guard reuses the SOC's ``secret_exfil_probe`` so
        it stops exactly what the detector flags. Shadow mode relays the body unchanged and only records
        'would redact', keeping the shim's observe-first default. Either way the SOC gets one event; the
        secret itself is never put in telemetry, only the KIND labels. A guard must never turn a good
        response into a 500, so any scan error falls through to a normal relay."""
        kinds: list[str] = []
        try:
            text = body[:200_000].decode("utf-8", "replace")
            probe = secret_exfil_probe({"response_body": text, "status": code})
            if probe.weight == "high":
                kinds = list(probe.data.get("secret_kinds", []))
        except Exception:  # noqa: BLE001 — never let the guard break a legitimate response
            kinds = []
        if kinds:
            self._exfil_kinds = kinds
            if self.state.mode == "live" and self.state.redact_secrets:
                self.state.denied += 1
                self._reply(403, json.dumps(
                    {"error": "response withheld by AEGIS: a credential was detected in the response body",
                     "secret_kinds": kinds}).encode(), "application/json")
                return 403
        self._relay(code, body, headers)
        return code


def build_server(listen: str, state: EdgeState) -> ThreadingHTTPServer:
    host, _, port = listen.partition(":")
    httpd = ThreadingHTTPServer((host or "127.0.0.1", int(port or 9000)), Handler)
    httpd.daemon_threads = True
    httpd.state = state  # type: ignore[attr-defined] — the handler reads self.server.state
    return httpd


def main() -> None:
    ap = argparse.ArgumentParser(description="AEGIS Edge Shim — front any local HTTP app with the SOC")
    ap.add_argument("--listen", default="127.0.0.1:9000", help="host:port the shim listens on")
    ap.add_argument("--upstream", required=True, help="the app to protect, e.g. http://127.0.0.1:3000")
    ap.add_argument("--aegis-url", default=os.environ.get("AEGIS_ALERTS_URL"),
                    help="AEGIS alerts ingest, e.g. http://127.0.0.1:8787/ingest/alerts (blocklist derived from it)")
    ap.add_argument("--token", default=os.environ.get("AEGIS_INGEST_TOKEN"),
                    help="shared bearer token for AEGIS ingest + /control/enforce (AEGIS_INGEST_TOKEN)")
    ap.add_argument("--asset", default="edge-shim-01", help="asset name reported in alerts")
    ap.add_argument("--mode", choices=["shadow", "live"], default="shadow",
                    help="shadow: forward everything, log 'would deny'; live: 403 blocked sources at the edge")
    ap.add_argument("--poll-interval", type=float, default=2.0, help="seconds between blocklist polls")
    ap.add_argument("--inline-waf", action="store_true",
                    help="also hard-block local signature hits at the edge (off by default; the SOC is the decider)")
    ap.add_argument("--redact-secrets", action=argparse.BooleanOptionalAction, default=True,
                    help="live mode: withhold a response whose body carries a credential (private key, "
                         "cloud/API key, DB DSN, DB_PASSWORD=…). On by default; --no-redact-secrets to disable.")
    args = ap.parse_args()

    bl = Blocklist(_blocklist_url(args.aegis_url) if args.aegis_url else None, args.token, args.poll_interval).start()
    state = EdgeState(upstream=args.upstream, aegis_url=args.aegis_url, token=args.token, asset=args.asset,
                      mode=args.mode, inline_waf=args.inline_waf, blocklist=bl, redact_secrets=args.redact_secrets)
    httpd = build_server(args.listen, state)
    print(f"AEGIS Edge Shim  →  http://{args.listen}   (mode: {args.mode})")
    print(f"  protecting   {args.upstream}")
    print(f"  SOC alerts → {args.aegis_url or '(none; set --aegis-url to feed the SOC)'}")
    print(f"  blocklist  ← {_blocklist_url(args.aegis_url) if args.aegis_url else '(none)'}")
    print("  the app behind the shim is untouched; drive your own traffic at the shim's address")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
