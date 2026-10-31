"""AEGIS Edge Shim: a stdlib reverse proxy that fronts any local HTTP app, forwards request
telemetry to the SOC, and denies sources the SOC has blocked. Tests run a stub upstream and a
stub AEGIS receiver in-process and drive the shim over real sockets — no mocks of the proxy path.
"""

from __future__ import annotations

import contextlib
import json
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import aegis_edge as E  # noqa: E402


# ----------------------------------------------------------------- stubs -- #

class _Upstream(BaseHTTPRequestHandler):
    def log_message(self, *a):  # noqa: ANN002, D401
        pass

    def _handle(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        self.rfile.read(n)
        self.server.hits.append((self.command, self.path, self.headers.get("X-Forwarded-For")))  # type: ignore[attr-defined]
        out = json.dumps({"echo": self.path, "method": self.command,
                          "xff": self.headers.get("X-Forwarded-For")}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_GET = do_POST = _handle


class _Aegis(BaseHTTPRequestHandler):
    def log_message(self, *a):  # noqa: ANN002
        pass

    def do_POST(self):  # noqa: N802 — /ingest/alerts receiver
        n = int(self.headers.get("Content-Length", 0) or 0)
        for line in self.rfile.read(n).decode("utf-8", "replace").splitlines():
            if line.strip():
                self.server.alerts.append(json.loads(line))  # type: ignore[attr-defined]
        self._ok({"ok": True})

    def do_GET(self):  # noqa: N802 — /ingest/blocklist
        self._ok(self.server.blocklist_payload)  # type: ignore[attr-defined]

    def _ok(self, obj):
        b = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


@contextlib.contextmanager
def _serve(handler_cls, **attrs):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    httpd.daemon_threads = True
    for k, v in attrs.items():
        setattr(httpd, k, v)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield httpd, f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()


@contextlib.contextmanager
def _edge(upstream, *, aegis_base=None, mode="shadow", token=None, inline_waf=False, poll=0.25):
    aegis_url = f"{aegis_base}/ingest/alerts" if aegis_base else None
    bl = E.Blocklist(E._blocklist_url(aegis_url) if aegis_url else None, token, poll).start()
    state = E.EdgeState(upstream=upstream, aegis_url=aegis_url, token=token, asset="edge-test",
                        mode=mode, inline_waf=inline_waf, blocklist=bl)
    httpd = E.build_server("127.0.0.1:0", state)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}", state, bl
    finally:
        httpd.shutdown()


def _req(base, path, method="GET", data=None, src=None, extra=None):
    req = urllib.request.Request(base + path, data=data, method=method)
    if src:
        req.add_header("X-Demo-Src", src)
    for k, v in (extra or {}).items():
        req.add_header(k, v)
    try:
        r = urllib.request.urlopen(req, timeout=5)
        return r.status, r.read().decode(), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers


def _wait(pred, timeout=2.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.05)
    return pred()


# ----------------------------------------------------------------- tests -- #

def test_proxies_get_and_post_to_upstream():
    with _serve(_Upstream, hits=[]) as (up, upbase), _edge(upbase) as (base, _s, _bl):
        code, body, _ = _req(base, "/hello?x=1")
        assert code == 200 and json.loads(body)["echo"] == "/hello?x=1"
        code, body, _ = _req(base, "/submit", method="POST", data=b"a=b", src="203.0.113.7")
        assert code == 200 and json.loads(body)["method"] == "POST"
        assert any(p == "/submit" for _m, p, _x in up.hits)
        assert json.loads(body)["xff"] == "203.0.113.7"          # real client IP forwarded upstream


def test_live_mode_denies_a_blocked_source_before_upstream():
    with _serve(_Upstream, hits=[]) as (up, upbase), _edge(upbase, mode="live") as (base, _s, bl):
        bl.push("203.0.113.9", None)
        code, body, _ = _req(base, "/x", src="203.0.113.9")
        assert code == 403 and "SOC containment" in body
        assert up.hits == []                                     # never reached the app
        code, _b, _ = _req(base, "/x", src="198.51.100.2")       # a different client still passes
        assert code == 200 and any(p == "/x" for _m, p, _x in up.hits)


def test_shadow_mode_forwards_even_when_it_would_block():
    with _serve(_Upstream, hits=[]) as (up, upbase), \
         _serve(_Aegis, alerts=[], blocklist_payload={"ips": [], "fingerprints": []}) as (ag, agbase), \
         _edge(upbase, aegis_base=agbase, mode="shadow") as (base, _s, bl):
        bl.push("203.0.113.9", None)
        code, _b, _ = _req(base, "/x", src="203.0.113.9")
        assert code == 200 and any(p == "/x" for _m, p, _x in up.hits)   # shadow → still proxied
        assert _wait(lambda: any(a.get("op") == "soc_block_shadow" for a in ag.alerts))


def test_blocklist_poll_reflects_soc_and_honours_action_and_expiry():
    now = time.time()
    payload = {"ips": [
        {"action": "block", "target": "203.0.113.0/24", "expires_at": None},
        {"action": "block", "target": "198.51.100.5", "expires_at": now - 1},   # expired
        {"action": "throttle", "target": "192.0.2.9", "expires_at": None},      # not a hard block
    ], "fingerprints": []}
    with _serve(_Upstream, hits=[]) as (_up, upbase), \
         _serve(_Aegis, alerts=[], blocklist_payload=payload) as (_ag, agbase), \
         _edge(upbase, aegis_base=agbase, mode="live") as (_base, _s, bl):
        assert _wait(lambda: bl.is_blocked("203.0.113.42"))      # CIDR from the SOC poll
        assert not bl.is_blocked("198.51.100.5")                 # expired block fell off
        assert not bl.is_blocked("192.0.2.9")                    # throttle is advisory, not a hard deny


def test_control_enforce_is_token_gated_and_pushes_a_block():
    with _serve(_Upstream, hits=[]) as (_up, upbase), _edge(upbase, mode="live", token="s3cret") as (base, _s, bl):
        code, _b, _ = _req(base, "/control/enforce", method="POST",
                           data=b'{"action":"block","target":"203.0.113.50"}')
        assert code == 401                                       # no token
        code, body, _ = _req(base, "/control/enforce", method="POST",
                             data=b'{"action":"block","target":"203.0.113.50"}',
                             extra={"Authorization": "Bearer s3cret"})
        assert code == 200 and json.loads(body)["accepted"] is True
        assert bl.is_blocked("203.0.113.50")


def test_signature_finding_is_forwarded_to_the_soc_but_not_blocked_by_the_edge():
    q = "id=" + urllib.parse.quote("1' UNION SELECT 1,2,3--", safe="")
    with _serve(_Upstream, hits=[]) as (up, upbase), \
         _serve(_Aegis, alerts=[], blocklist_payload={"ips": [], "fingerprints": []}) as (ag, agbase), \
         _edge(upbase, aegis_base=agbase, mode="shadow") as (base, _s, _bl):
        code, _b, _ = _req(base, f"/api/account?{q}", src="203.0.113.7")
        assert code == 200                                       # SOC decides; the edge doesn't 403 on a raw signature
        assert any(p.startswith("/api/account") for _m, p, _x in up.hits)
        assert _wait(lambda: any(("SQLI" in (a.get("rules") or []) or a.get("rule") == "SQLI") for a in ag.alerts))


def test_inline_waf_opt_in_hard_blocks_a_signature_at_the_edge():
    q = "id=" + urllib.parse.quote("1' UNION SELECT 1,2,3--", safe="")
    with _serve(_Upstream, hits=[]) as (up, upbase), \
         _edge(upbase, mode="live", inline_waf=True) as (base, _s, _bl):
        code, body, _ = _req(base, f"/api/account?{q}", src="203.0.113.7")
        assert code == 403 and "edge" in body.lower()
        assert up.hits == []                                     # inline WAF kept it off the app


# -- enriched telemetry: the raw request/response the SOC's perimeter scorers read ------------- #

def test_enriched_event_carries_request_and_response_fields():
    with _serve(_Upstream, hits=[]) as (_up, upbase), \
         _serve(_Aegis, alerts=[], blocklist_payload={"ips": [], "fingerprints": []}) as (ag, agbase), \
         _edge(upbase, aegis_base=agbase, mode="shadow") as (base, _s, _bl):
        code, _b, _ = _req(base, "/fetch.php?url=http://169.254.169.254/latest/", src="203.0.113.7")
        assert code == 200
        assert _wait(lambda: any(a.get("payload") for a in ag.alerts))
        ev = next(a for a in ag.alerts if a.get("payload"))
        assert "169.254.169.254" in ev["payload"]                # the attack is in `payload` now
        assert ev["source_ip"] == "203.0.113.7"                  # the field the perimeter reads
        assert isinstance(ev.get("request_headers"), dict) and ev.get("host")
        assert "response_headers" in ev and ev.get("response_status") == 200   # captured from upstream (CORS)


def test_post_form_populates_body_params():
    with _serve(_Upstream, hits=[]) as (_up, upbase), \
         _serve(_Aegis, alerts=[], blocklist_payload={"ips": [], "fingerprints": []}) as (ag, agbase), \
         _edge(upbase, aegis_base=agbase, mode="shadow") as (base, _s, _bl):
        _req(base, "/profile.php", method="POST", data=b"name=Mahi&role=admin&credit_score=999",
             extra={"Content-Type": "application/x-www-form-urlencoded"}, src="203.0.113.7")
        assert _wait(lambda: any(a.get("body_params") for a in ag.alerts))
        ev = next(a for a in ag.alerts if a.get("body_params"))
        assert ev["body_params"].get("role") == "admin" and "credit_score" in ev["body_params"]


def test_enriched_event_actually_fires_the_perimeter_scorers():
    # the whole point of the wiring: shim telemetry → the SOC scorers fire, instead of scanning ""
    from aegis.agents.perimeter import tools
    with _serve(_Upstream, hits=[]) as (_up, upbase), \
         _serve(_Aegis, alerts=[], blocklist_payload={"ips": [], "fingerprints": []}) as (ag, agbase), \
         _edge(upbase, aegis_base=agbase, mode="shadow") as (base, _s, _bl):
        _req(base, "/fetch.php?url=http://meta:8000/token", src="45.155.205.233")
        assert _wait(lambda: any(a.get("payload") for a in ag.alerts))
        ev = next(a for a in ag.alerts if a.get("payload"))
        results = {r.name: r for r in tools.run_all_tools(ev["payload"], ev.get("source_ip", ""), None, alert=ev)}
        assert results["ssrf_probe"].weight == "high"            # SSRF detected straight off shim telemetry


# -- redirects are relayed, not followed: keeps the client's session + one event per request --- #

class _RedirectUpstream(BaseHTTPRequestHandler):
    """Auth flow: /login 302s to /dashboard and sets a session cookie; /dashboard is the target."""

    def log_message(self, *a):  # noqa: ANN002
        pass

    def _handle(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        self.rfile.read(n)
        self.server.hits.append((self.command, self.path))  # type: ignore[attr-defined]
        if self.path.startswith("/login"):
            self.send_response(302)
            self.send_header("Location", "/dashboard")
            self.send_header("Set-Cookie", "session=abc123; Path=/; HttpOnly")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        out = b'{"page": "dashboard"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_GET = do_POST = _handle


def _req_no_follow(base, path, method="GET", data=None, src=None):
    class _NR(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    opener = urllib.request.build_opener(_NR)
    req = urllib.request.Request(base + path, data=data, method=method)
    if src:
        req.add_header("X-Demo-Src", src)
    try:
        r = opener.open(req, timeout=5)
        return r.status, r.read().decode(), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers


def test_shim_relays_redirect_without_following_and_emits_one_true_event():
    with _serve(_RedirectUpstream, hits=[]) as (up, upbase), \
         _serve(_Aegis, alerts=[], blocklist_payload={"ips": [], "fingerprints": []}) as (ag, agbase), \
         _edge(upbase, aegis_base=agbase, mode="shadow") as (base, _s, _bl):
        code, _b, hdrs = _req_no_follow(base, "/login.php", method="POST", data=b"u=a&p=b", src="203.0.113.7")
        assert code == 302                                       # relayed to the client, not followed
        assert "session=" in (hdrs.get("Set-Cookie") or "")     # the session cookie reached the real client
        assert all(p != "/dashboard" for _m, p in up.hits)      # shim did NOT chase the Location itself
        assert up.hits == [("POST", "/login.php")]              # exactly one upstream hit
        # exactly one telemetry event, and it carries the real 302 (not a followed 200)
        assert _wait(lambda: any(a.get("response_status") == 302 for a in ag.alerts))
        assert len([a for a in ag.alerts if a.get("source_ip") == "203.0.113.7"]) == 1
