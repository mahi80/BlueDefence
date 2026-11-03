"""Edge shim hardening (code review 2026-11-02, console-scripts #3–#6): expiry typing, bounded state,
health detail behind the token, chunked and over-size bodies."""

from __future__ import annotations

import contextlib
import http.client
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import aegis_edge as E


class _Up(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        self.server.bodies.append(self.rfile.read(n))  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


@contextlib.contextmanager
def _stack(token="t0k3n-for-tests"):
    up = ThreadingHTTPServer(("127.0.0.1", 0), _Up)
    up.bodies = []  # type: ignore[attr-defined]
    threading.Thread(target=up.serve_forever, daemon=True).start()
    bl = E.Blocklist(None, token)
    state = E.EdgeState(upstream=f"http://127.0.0.1:{up.server_address[1]}", aegis_url=None, token=token,
                        asset="t", mode="shadow", inline_waf=False, blocklist=bl)
    edge = E.build_server("127.0.0.1:0", state)
    threading.Thread(target=edge.serve_forever, daemon=True).start()
    try:
        yield edge.server_address[1], up, state, bl
    finally:
        edge.shutdown(); up.shutdown()


def test_iso_or_garbage_expiry_never_breaks_is_blocked():
    bl = E.Blocklist(None, None)
    assert bl.push("203.0.113.9", "2999-01-01T00:00:00Z") is True
    assert bl.push("203.0.113.10", time.time() - 1) is True
    assert bl.push("203.0.113.11", "next tuesday") is False
    assert bl.push("203.0.113.12", True) is False
    assert bl.is_blocked("203.0.113.9") and not bl.is_blocked("203.0.113.10")   # no TypeError, expiry honoured
    assert not bl.is_blocked("203.0.113.11")


def test_pushed_and_client_state_are_capped(monkeypatch):
    monkeypatch.setattr(E, "_MAX_PUSHED", 50)
    monkeypatch.setattr(E, "_MAX_CLIENTS", 40)
    bl = E.Blocklist(None, None)
    for i in range(500):
        bl.push(f"198.51.{i // 256}.{i % 256}", None)
    assert len(bl._pushed) == 50 and bl.is_blocked("198.51.1.243")          # newest kept
    state = E.EdgeState(upstream="http://x", aegis_url=None, token=None, asset="t", mode="shadow",
                        inline_waf=False, blocklist=bl)
    for i in range(400):
        state.client_state(f"10.9.{i // 256}.{i % 256}")
    assert len(state.clients) == 40


def _get(port, path, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", path, headers=headers or {})
    r = c.getresponse()
    return r.status, json.loads(r.read())


def test_health_details_need_the_token_off_box(monkeypatch):
    with _stack() as (port, _up, _state, bl):
        bl.push("203.0.113.9", None)
        monkeypatch.setattr(E.Handler, "_local_peer", lambda self: False)
        assert _get(port, "/__edge/health") == (200, {"ok": True})
        code, body = _get(port, "/__edge/health", {"Authorization": "Bearer t0k3n-for-tests"})
        assert code == 200 and body["blocklist"]["pushed"] == ["203.0.113.9"] and "upstream" in body


def test_chunked_body_is_read_inspected_and_forwarded_whole():
    with _stack() as (port, up, _state, _bl):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        payload = [b"q=1' UNION ", b"SELECT password FROM users--"]
        c.request("POST", "/search", body=iter(payload), headers={"Transfer-Encoding": "chunked"},
                  encode_chunked=True)
        r = c.getresponse(); r.read()
        assert r.status == 200 and up.bodies[-1] == b"".join(payload)


def test_oversize_body_is_refused_not_truncated(monkeypatch):
    monkeypatch.setattr(E, "_MAX_BODY", 1024)
    with _stack() as (port, up, _state, _bl):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("POST", "/upload", body=b"x" * 4096)
        r = c.getresponse(); r.read()
        assert r.status == 413 and up.bodies == []
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("POST", "/upload", body=iter([b"y" * 800, b"y" * 800]), headers={"Transfer-Encoding": "chunked"},
                  encode_chunked=True)
        r = c.getresponse(); r.read()
        assert r.status == 413 and up.bodies == []
