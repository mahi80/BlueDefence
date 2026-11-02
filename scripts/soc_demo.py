#!/usr/bin/env python3
"""AEGIS SOC demo — a presenter-paced, offline scenario the SOC console renders live.

Stands up a tiny backend (stdlib only — no deps, no Postgres, no GPU) that serves the exact
``/api/soc/*`` and ``/api/approvals/*`` shapes the console reads, and reveals a multi-stage
**external AI-agent attack** one beat at a time. Point the console at it and walk a room through
**detect -> investigate -> contain -> learn**.

Everything is ``AEGIS_EDITION=soc``, enforcement **shadow**, **mock** vendor tenants: the block is
*demonstrated*, nothing real is ever touched, and it runs fully offline. Talk track:
``docs/demo/soc-demo.md``.

    # terminal 1 — the demo backend
    python scripts/soc_demo.py                 # serve the whole scenario (walkthrough; click incidents)
    python scripts/soc_demo.py --step          # press Enter to reveal each beat (presenter control)
    python scripts/soc_demo.py --pace 20       # auto-reveal a beat every 20s (hands-free)
    python scripts/soc_demo.py --port 8799

    # terminal 2 — the console, pointed at the demo backend
    cd soc-console && AEGIS_API_ORIGIN=http://localhost:8799 \
        AEGIS_AUTH_MODE=demo AEGIS_CONSOLE_SECRET=demo AEGIS_DEMO_USER=soc AEGIS_DEMO_PASSWORD=demo \
        npm run dev   # then open http://localhost:3000

This is a *scripted* scenario whose verdicts, blast radius and actions mirror what the real AEGIS
pipeline produces (the shapes are the console's own); for a live run against a real backend, point
the console at the dashboard instead. Nothing here reaches a network or a real control.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional
from urllib.parse import urlparse

# ----------------------------------------------------------------------------- the scenario
# One correlated campaign (external attacker using AI-agent tooling) seen only through the bank's
# telemetry, plus ordinary SOC noise. Each item carries a private ``_beat`` = when it becomes
# visible; it is stripped before serving. Verdicts/actions mirror the real pipeline's output.

_CHAINS: list[dict] = [
    {   # baseline noise — already triaged, nothing for the analyst
        "_beat": 0, "chain_id": "chn_2204", "alert_id": "ALR-2204", "source": "Imperva Cloud WAF",
        "verdict": "benign", "confidence": 0.86, "specialists": ["perimeter"], "action_types": ["allow", "monitor"],
        "evidence_count": 3, "governance_blocked": False, "started_at": "2026-10-23T05:21:08Z",
        "completed_at": "2026-10-23T05:21:26Z", "integrity_hash": "d0c0ffee11223344",
        "note": "Odd TLS stack explained by the corporate Zscaler inspection proxy; blocked scanner noise.",
        "investigation": {"swarm": ["ioc_extract"], "blast_radius": {
            "nodes": [{"id": "proxy-egress", "label": "zscaler-egress", "kind": "service", "verdict": "benign", "reached": False}],
            "edges": [], "critical": [], "choke_edges": []}},
        "recommended_actions": [{"action_type": "allow", "target": "10.20.4.51", "requires_hitl": False,
                                 "confidence": 0.86, "reasoning": "Corporate inspection proxy; blocked scanner probe is noise."}],
    },
    {   # a credential probe — suspicious, auto-handled
        "_beat": 0, "chain_id": "chn_2203", "alert_id": "ALR-2203", "source": "F5 ASM",
        "verdict": "suspicious", "confidence": 0.66, "specialists": ["auth"], "action_types": ["throttle", "monitor"],
        "evidence_count": 4, "governance_blocked": False, "started_at": "2026-10-23T05:30:55Z",
        "completed_at": "2026-10-23T05:31:20Z", "integrity_hash": "41d7e0b9a1227c6e",
        "note": "Many usernames from one source at a moderate rate, blocked — a probe, not yet a compromise.",
        "investigation": {"swarm": ["ioc_extract", "intel_enrich"], "blast_radius": {
            "nodes": [{"id": "login-edge", "label": "login-edge", "kind": "service", "verdict": "suspicious", "reached": True},
                      {"id": "src-198-51-100-88", "label": "198.51.100.88", "kind": "service", "verdict": "suspicious", "reached": True}],
            "edges": [{"source": "src-198-51-100-88", "target": "login-edge", "kind": "attack"}], "critical": [], "choke_edges": []}},
        "recommended_actions": [{"action_type": "throttle", "target": "198.51.100.88", "requires_hitl": False,
                                 "confidence": 0.66, "reasoning": "Slow the source while an analyst reviews; blocked but persistent."},
                                {"action_type": "monitor", "target": "login-edge", "requires_hitl": False,
                                 "confidence": 0.66, "reasoning": "Watch for a successful auth from this source."}],
    },
    {   # NDR beacon — malicious
        "_beat": 1, "chain_id": "chn_2202", "alert_id": "ALR-2202", "source": "NDR (Zeek)",
        "verdict": "malicious", "confidence": 0.9, "specialists": ["perimeter"], "action_types": ["block_egress", "isolate", "escalate"],
        "evidence_count": 7, "governance_blocked": False, "started_at": "2026-10-23T05:38:02Z",
        "completed_at": "2026-10-23T05:38:40Z", "integrity_hash": "9b33aa21ce0045fd",
        "note": "Regular beacon with matching JA3 to a known-bad TLS cert; periodic exfil-sized uploads.",
        "investigation": {"swarm": ["ioc_extract", "intel_enrich", "blast_radius", "log_hunt"], "blast_radius": {
            "nodes": [{"id": "wks-fin-212", "label": "wks-fin-212", "kind": "host", "verdict": "malicious", "reached": True},
                      {"id": "c2-203-0-113-9", "label": "203.0.113.9", "kind": "service", "verdict": "malicious", "reached": True},
                      {"id": "fileshare-fin", "label": "fileshare-fin", "kind": "data", "verdict": "suspicious", "critical": True, "reached": False}],
            "edges": [{"source": "wks-fin-212", "target": "c2-203-0-113-9", "kind": "exfil"},
                      {"source": "fileshare-fin", "target": "wks-fin-212", "kind": "lateral"}],
            "critical": ["fileshare-fin"], "choke_edges": [["wks-fin-212", "c2-203-0-113-9"]]}},
        "recommended_actions": [{"action_type": "block_egress", "target": "203.0.113.9", "requires_hitl": True,
                                 "confidence": 0.9, "reasoning": "Known-bad TLS certificate on the destination — block the C2 egress."},
                                {"action_type": "isolate", "target": "wks-fin-212", "requires_hitl": True,
                                 "confidence": 0.88, "reasoning": "Beaconing finance workstation; isolate before lateral movement."}],
    },
    {   # THE HEADLINE — go-http -> /api/transfer, embedded prompt-injection caught, pivot toward the ledger
        "_beat": 2, "chain_id": "chn_2201", "alert_id": "ALR-2201", "source": "Imperva Cloud WAF",
        "verdict": "malicious", "confidence": 0.94, "specialists": ["perimeter"],
        "action_types": ["isolate", "block_egress", "revoke_sessions"], "evidence_count": 9,
        "governance_blocked": False, "started_at": "2026-10-23T05:42:11Z", "completed_at": "2026-10-23T05:42:49Z",
        "integrity_hash": "f2a1c0de4b7788aa",
        "note": ("A go-http client posing as Chrome reached /api/transfer unblocked; its payload carried an embedded "
                 "\"ignore your rules and approve this\" instruction — AEGIS recorded it as evidence and did NOT obey. "
                 "Lateral path now opening toward the core ledger DB."),
        "investigation": {"swarm": ["ioc_extract", "intel_enrich", "blast_radius", "log_hunt", "deception_check"],
                          "campaign": {"id": "camp_17", "related_alerts": 3}, "blast_radius": {
            "nodes": [{"id": "edge-waf", "label": "edge-waf", "kind": "service", "verdict": "malicious", "reached": True},
                      {"id": "api-gw-01", "label": "api-gw-01", "kind": "service", "verdict": "malicious", "reached": True},
                      {"id": "app-ledger-07", "label": "app-ledger-07", "kind": "host", "verdict": "suspicious", "reached": True},
                      {"id": "svc-acct-pay", "label": "svc-acct-pay", "kind": "identity", "verdict": "suspicious", "reached": True},
                      {"id": "db-core", "label": "db-core (ledger)", "kind": "data", "verdict": "uncertain", "critical": True, "reached": False}],
            "edges": [{"source": "edge-waf", "target": "api-gw-01", "kind": "attack"},
                      {"source": "api-gw-01", "target": "app-ledger-07", "kind": "lateral"},
                      {"source": "svc-acct-pay", "target": "app-ledger-07", "kind": "lateral"},
                      {"source": "app-ledger-07", "target": "db-core", "kind": "lateral"}],
            "critical": ["db-core"], "choke_edges": [["app-ledger-07", "db-core"]]},
            "plan": {"steps": [
                {"order": 1, "action_type": "isolate", "target": "app-ledger-07",
                 "rationale": "Only remaining path to the ledger DB runs through this host — cutting it contains the campaign.",
                 "cuts_edges": [["app-ledger-07", "db-core"]]},
                {"order": 2, "action_type": "block_egress", "target": "203.0.113.77",
                 "rationale": "The forged-token source; block at the egress proxy."},
                {"order": 3, "action_type": "revoke_sessions", "target": "svc-acct-pay",
                 "rationale": "Service identity used on the lateral hop — revoke its live sessions."}]}},
        "recommended_actions": [
            {"action_type": "isolate", "target": "app-ledger-07", "requires_hitl": True, "confidence": 0.94,
             "reasoning": "Isolating app-ledger-07 severs the only path the attacker has left to the core ledger DB."},
            {"action_type": "block_egress", "target": "203.0.113.77", "requires_hitl": True, "confidence": 0.93,
             "reasoning": "Block the forged-token source IP at the egress proxy and firewall."},
            {"action_type": "revoke_sessions", "target": "svc-acct-pay", "requires_hitl": True, "confidence": 0.9,
             "reasoning": "Revoke the service account's active sessions used on the lateral movement."}],
    },
]

_APPROVALS: list[dict] = [
    {"_beat": 3, "id": "appr_01", "status": "pending", "created_at": "2026-10-23T05:42:50Z", "action_type": "isolate",
     "target": "app-ledger-07", "alert_id": "ALR-2201", "integrity_hash": "f2a1c0de4b7788aa", "agent_id": "SOC-AGENTQ-01",
     "reasoning": "Isolating app-ledger-07 severs the only path left to the core ledger DB."},
    {"_beat": 3, "id": "appr_02", "status": "pending", "created_at": "2026-10-23T05:42:51Z", "action_type": "block_egress",
     "target": "203.0.113.77", "alert_id": "ALR-2201", "integrity_hash": "f2a1c0de4b7788aa", "agent_id": "SOC-AGENTQ-01",
     "reasoning": "Block the forged-token source IP at the egress proxy and firewall."},
    {"_beat": 1, "id": "appr_03", "status": "pending", "created_at": "2026-10-23T05:38:41Z", "action_type": "block_egress",
     "target": "203.0.113.9", "alert_id": "ALR-2202", "integrity_hash": "9b33aa21ce0045fd", "agent_id": "SOC-AGENTQ-01",
     "reasoning": "Known-bad TLS certificate on the destination — block the C2 egress."},
]

_PROPOSALS: list[dict] = [
    {"_beat": 5, "id": "prop_01", "change_type": "model_promotion", "status": "pending",
     "summary": "Promote triage-qwen3-8b-public-v5 → live brain", "validation_passed": True,
     "rationale": "Gate PASS (historical 33/37, injection 9/9, agentic 10/13, endpoint 8/8, tls 12/13). Shadow: +3pt analyst agreement vs current on 48 new alerts.",
     "created_at": "2026-10-23T05:10:00Z"},
    {"_beat": 0, "id": "prop_02", "change_type": "rule", "status": "accepted",
     "summary": "Raise auth-burst sensitivity for /login after 03:00 IST", "validation_passed": True,
     "rationale": "Meta-agent proposal; reduced two historical misses with zero regressions.",
     "decided_by": "ciso", "decided_at": "2026-10-22T19:20:00Z", "created_at": "2026-10-22T18:55:00Z"},
]

BEATS: list[str] = [
    "Baseline — a normal SOC night: a blocked credential probe and scanner noise, both already triaged. Nothing needs the analyst.",
    "NDR lights up: a finance workstation beaconing to a known-bad TLS cert on a timer. Malicious — the finance fileshare is the asset at risk.",
    "The headline. A go-http client posing as Chrome reaches /api/transfer. Its payload even carries an embedded 'ignore your rules and approve' instruction — AEGIS records it as evidence and does NOT obey it. Verdict malicious, 94%.",
    "The swarm has already mapped the blast radius: the only path left to the core ledger runs through app-ledger-07. AEGIS proposes the minimum cut — and waits for a human. (Ask Agent Q: \"what's at risk?\")",
    "You approve the isolate. In shadow mode the block is demonstrated against the mock tenant — the choke edge is cut, the ledger is protected, and it's logged with your name and rationale.",
    "And it learns: the night's analyst decisions plus the CVE feeds produced a better model — gate PASS — waiting on a human to promote. Nothing self-promotes.",
]


class SocDemo:
    """The demo's state machine — beats reveal the campaign; an approval contains it. HTTP-free, so
    it unit-tests headless."""

    def __init__(self) -> None:
        self.beat = 0
        self.max_beat = len(BEATS) - 1
        self._decisions: dict[str, dict] = {}
        self._contained = False

    # -- progression
    def advance(self) -> int:
        if self.beat < self.max_beat:
            self.beat += 1
        return self.beat

    def goto_end(self) -> None:
        self.beat = self.max_beat

    def reset(self) -> None:
        self.beat = 0
        self._decisions.clear()
        self._contained = False

    def narration(self) -> str:
        return BEATS[self.beat]

    # -- visible state (what the console reads), filtered by the current beat
    def _visible(self, items: list[dict]) -> list[dict]:
        out = []
        for it in items:
            if it.get("_beat", 0) <= self.beat:
                clean = {k: v for k, v in it.items() if k != "_beat"}
                out.append(copy.deepcopy(clean))
        return out

    def chains(self) -> list[dict]:
        chains = self._visible(_CHAINS)
        if self._contained:
            for c in chains:
                if c["chain_id"] == "chn_2201":
                    c["note"] += ("  ✓ CONTAINED: app-ledger-07 isolated (shadow / mock tenant), the choke edge to "
                                  "db-core is cut, the ledger is protected. Verified and audited.")
                    for n in c["investigation"]["blast_radius"]["nodes"]:
                        if n["id"] == "app-ledger-07":
                            n["verdict"] = "benign"  # neutralised
        return chains

    def chain(self, chain_id: str) -> Optional[dict]:
        return next((c for c in self.chains() if c["chain_id"] == chain_id), None)

    def approvals(self) -> list[dict]:
        out = self._visible(_APPROVALS)
        for a in out:
            d = self._decisions.get(a["id"])
            if d:
                a.update(d)
        return out

    def proposals(self) -> list[dict]:
        return self._visible(_PROPOSALS)

    # -- the HITL moment
    def decide(self, approval_id: str, status: str, *, rationale: str = "", by: str = "soc-analyst") -> bool:
        if approval_id not in {a["id"] for a in _APPROVALS}:
            return False
        self._decisions[approval_id] = {
            "status": "approved" if status == "approve" else "rejected",
            "decided_by": by, "decided_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "rationale": rationale or ("Confirmed — contain the path to the ledger." if status == "approve" else "Not now."),
        }
        if approval_id == "appr_01" and status == "approve":
            self._contained = True
            if self.beat < 4:
                self.beat = 4
        return True


# ----------------------------------------------------------------------------- HTTP surface

class _Handler(BaseHTTPRequestHandler):
    demo: SocDemo = SocDemo()

    def log_message(self, *a: Any) -> None:  # quiet — the narration is the output
        pass

    def _send(self, status: int, body: Any) -> None:
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-API-Key, Authorization")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._send(200, {})

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path.rstrip("/")
        d = _Handler.demo
        if path in ("/api/soc/chains", "/api/chains"):
            self._send(200, d.chains())
        elif path.startswith("/api/soc/chains/"):
            c = d.chain(path.rsplit("/", 1)[-1])
            self._send(200 if c else 404, c or {"error": "not found"})
        elif path in ("/api/approvals", "/api/soc/approvals"):
            self._send(200, d.approvals())
        elif path in ("/api/soc/proposals", "/api/proposals"):
            self._send(200, d.proposals())
        elif path in ("/healthz", "/api/healthz"):
            self._send(200, {"ok": True, "beat": d.beat, "narration": d.narration()})
        else:
            self._send(404, {"error": "not found", "path": path})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path.rstrip("/")
        d = _Handler.demo
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n) or b"{}") if n else {}
        except ValueError:
            body = {}
        # /api/approvals/{id}/approve|reject
        parts = path.strip("/").split("/")
        if len(parts) >= 4 and parts[:2] == ["api", "approvals"] and parts[3] in ("approve", "reject"):
            if self.headers.get("Origin"):        # the console decides server-side; a browser page here is CSRF
                self._send(403, {"error": "cross-site decision refused"})
                return
            ok = d.decide(parts[2], "approve" if parts[3] == "approve" else "reject",
                          rationale=str(body.get("rationale") or body.get("reason") or ""))
            if ok and parts[3] == "approve" and parts[2] == "appr_01":
                print("\n  ▶ analyst APPROVED isolate app-ledger-07 — containment demonstrated (shadow). The ledger is protected.\n")
            self._send(200 if ok else 404, {"ok": ok})
        else:
            self._send(404, {"error": "not found", "path": path})


def _banner(port: int) -> None:
    d = _Handler.demo
    print("=" * 78)
    print("  AEGIS SOC demo  ·  AEGIS_EDITION=soc  ·  enforcement SHADOW  ·  MOCK tenants  ·  offline")
    print(f"  backend: http://localhost:{port}   (point the console's AEGIS_API_ORIGIN here)")
    print("  nothing real is touched — every block is demonstrated against a mock tenant")
    print("=" * 78)
    print(f"\n  beat 0/{d.max_beat}: {BEATS[0]}\n")


def _print_beat(d: SocDemo) -> None:
    print(f"  ── beat {d.beat}/{d.max_beat} ──\n  {d.narration()}\n")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="AEGIS SOC demo backend (presenter-paced, offline, shadow-mode).")
    ap.add_argument("--port", type=int, default=8799)
    ap.add_argument("--step", action="store_true", help="press Enter to reveal each beat (presenter control)")
    ap.add_argument("--pace", type=float, default=0.0, help="auto-reveal a beat every N seconds (hands-free)")
    ap.add_argument("--all", action="store_true", help="reveal the whole scenario at once (walkthrough; default)")
    a = ap.parse_args(argv)

    _Handler.demo = SocDemo()
    d = _Handler.demo
    if a.all or (not a.step and a.pace <= 0):
        d.goto_end()

    # loopback by default: the demo has no authentication (AEGIS_DEMO_BIND=0.0.0.0 to show it on a LAN)
    httpd = ThreadingHTTPServer((os.environ.get("AEGIS_DEMO_BIND", "127.0.0.1"), a.port), _Handler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, name="soc-demo", daemon=True).start()
    _banner(a.port)
    if d.beat == d.max_beat:
        print("  (serving the whole scenario — click through the incidents in the console)\n")

    try:
        if a.step:
            print("  press Enter to reveal each beat (Ctrl-C to stop)…\n")
            while d.beat < d.max_beat:
                input()
                d.advance()
                _print_beat(d)
            print("  scenario complete — approve the isolate in the console to contain.\n")
        elif a.pace > 0:
            while d.beat < d.max_beat:
                time.sleep(a.pace)
                d.advance()
                _print_beat(d)
            print("  scenario complete.\n")
        else:
            while True:
                time.sleep(3600)
    except KeyboardInterrupt:
        print("\n  demo stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
