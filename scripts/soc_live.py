#!/usr/bin/env python3
"""AEGIS SOC **live** backend — turns the demo bank's traffic into live incidents the console draws.

Where ``scripts/soc_demo.py`` replays a *scripted* scenario, this is driven by **actual traffic**.
Point the demo bank's ``--aegis-url`` at ``/ingest/alerts``, point the console's ``AEGIS_API_ORIGIN``
here, then attack the bank from **any** tool: the SOC correlates each source into one incident with a
blast radius toward the core ledger and a human-in-the-loop containment, in the console's own shapes.

Design notes (hardened after review):
  * **It sees the whole stream, not just blocks.** The bank forwards *allowed* requests too
    (``action="allowed"``); the SOC re-inspects the full request — body included, multiline-aware — so
    attacks that evade the edge signature (SQLi in a POST body, ``UNION`` across a newline, an empty
    User-Agent) are still caught. The input is fixed, not the edge rules.
  * **Correlation is fingerprint-aware, not just ``src_ip``.** Sources behind one IP are split by JA3 /
    User-Agent / identity, and each incident reports how many distinct clients that IP showed — because
    agents sharing one host IP are one source at L3 and only an app-layer fingerprint separates them.
  * **It binds loopback and authenticates ingest.** ``/ingest/*`` requires a bearer token when one is
    set (``AEGIS_INGEST_TOKEN``), required off-loopback, so a stray POST can't mint a campaign.

Still ``AEGIS_EDITION=soc``, enforcement **shadow**, **mock** tenants — the containment is
*demonstrated*, nothing real is isolated. stdlib only.

    export AEGIS_INGEST_TOKEN=$(python3 -c "import secrets;print(secrets.token_hex(16))")
    python3 scripts/soc_live.py                                   # binds 127.0.0.1:8799
    python3 scripts/demo_target.py --aegis-url http://127.0.0.1:8799/ingest/alerts   # same env → token
    cd soc-console && AEGIS_API_ORIGIN=http://localhost:8799 ... npm run dev
    python3 scripts/demo_attack_traffic.py --step                # or any tool that hits the bank
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional
import urllib.request
from urllib.parse import unquote, urlparse

_SEV_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0, "info": 0}
_VRANK = {"benign": 0, "suspicious": 1, "malicious": 2}
_MALICIOUS_RULES = {"SQLI", "WEBSHELL_UPLOAD", "CMD_INJECTION", "PROMPT_INJECTION", "SSRF_METADATA",
                    "AUTH_BURST", "LEDGER_HARVEST", "AUTHZ_VIOLATION",
                    "COOKIE_TAMPER", "TOKEN_FORGERY", "SESSION_FIXATION"}
_LARGE_TRANSFER = 100_000.0

# Second-pass detection the SOC runs over the FULL request (query + body), multiline-aware (DOTALL),
# so it catches what the edge signature missed — not a longer edge ruleset, a deeper look at the
# traffic the edge let through.
_D = re.IGNORECASE | re.DOTALL
_DEEP: list[tuple[str, str, re.Pattern[str]]] = [
    ("SQLI", "critical", re.compile(
        r"(\bunion\b.{0,120}\bselect\b|\bor\b\s+1\s*=\s*1|'\s*or\s*'1'\s*=\s*'1|';\s*--|\bsleep\s*\(|"
        r"\bwaitfor\s+delay\b|\binformation_schema\b|\bdrop\s+table\b|\bselect\b.{0,80}\bfrom\b.{0,80}\bwhere\b)", _D)),
    ("CMD_INJECTION", "critical", re.compile(
        r"(;\s*(cat|id|whoami|uname|nc|bash|sh|curl|wget)\b|\|\s*(cat|id|whoami|nc)\b|\$\([^)]*\)|`[^`]+`|&&\s*(curl|wget)\b)", _D)),
    ("WEBSHELL_UPLOAD", "critical", re.compile(
        r"(filename\s*=\s*\"?[^\"]*\.(php[0-9]?|phtml|jsp|jspx|asp|aspx|cfm|sh)\b|<\?php|<%\s*eval|system\s*\(\s*\$_)", _D)),
    ("PATH_TRAVERSAL", "high", re.compile(r"(\.\./|\.\.\\|/etc/passwd|/proc/self/|%2e%2e%2f|c:\\windows\\)", _D)),
    ("SSRF_METADATA", "high", re.compile(r"(169\.254\.169\.254|metadata\.google\.internal|/latest/meta-data/)", _D)),
    ("PROMPT_INJECTION", "high", re.compile(
        r"(ignore\s+(your|all|the|previous)\s+(rules|instructions)|disregard\s+(the\s+)?(above|previous)|"
        r"approve\s+this\s+(transfer|request|payment))", _D)),
    ("XSS", "medium", re.compile(r"(<script\b|onerror\s*=|javascript:|<img\b[^>]*onerror)", _D)),
]


def deep_inspect(event: dict) -> list[tuple[str, str]]:
    """Attack findings from the full request (query + body + cookie), newline-tolerant. The cookie is
    in the haystack because a payload smuggled into a Cookie header evades an edge WAF that only
    inspects the query and body. Returns (rule, severity)."""
    hay = "\n".join(unquote(str(event.get(f, ""))) for f in ("query", "body", "cookie"))
    return [(name, sev) for name, sev, pat in _DEEP if pat.search(hay)]


# The cookie is a client-controlled trust boundary. A privilege baked into a cookie by a session
# that the server did not authenticate as admin, or a token that asserts it is unsigned, is tampering
# the application sees but a payload-only WAF does not. Signal-level, inert — the detector's view.
_COOKIE_PRIV = re.compile(
    r"\b(role|is_?admin|isadmin|priv|access_level|user_?type|grp|group)\s*[=:]\s*"
    r"\"?(admin|administrator|root|superuser|elevated|1|true|yes)\b", re.IGNORECASE)
_TOKEN_UNSIGNED = re.compile(r"\"alg\"\s*:\s*\"none\"|\balg\s*[=:]\s*none\b", re.IGNORECASE)


def cookie_inspect(event: dict) -> list[tuple[str, str]]:
    """Cookie-layer findings a payload-only WAF cannot see: a privilege claim in a cookie from a
    session the server did NOT authenticate as admin (role mismatch = client-forged), or a token
    asserting no signature. Returns (rule, severity)."""
    cookie = str(event.get("cookie", ""))
    if not cookie:
        return []
    out: list[tuple[str, str]] = []
    if _COOKIE_PRIV.search(cookie) and str(event.get("role", "")).lower() != "admin":
        out.append(("COOKIE_TAMPER", "high"))
    if _TOKEN_UNSIGNED.search(cookie):
        out.append(("TOKEN_FORGERY", "critical"))
    return out


def behavioral_inspect(event: dict) -> list[tuple[str, str]]:
    """Catch *authorized* abuse that carries no attack signature — a ledger harvest, a funds
    transfer, an authorization denial. This is what a WAF structurally cannot see; it reads the
    operation the bank attached to the request, not a payload."""
    action = str(event.get("action", ""))
    op = str(event.get("op", ""))
    if action == "denied":
        return [("AUTHZ_VIOLATION", "high")]        # someone tried to exceed their authorization
    if action == "allowed":
        if op == "ledger_read_all":
            return [("LEDGER_HARVEST", "high")]     # bulk read of the entire ledger
        if op == "transfer":
            try:
                big = float(event.get("amount") or 0) >= _LARGE_TRANSFER
            except (TypeError, ValueError):
                big = False
            return [("FUNDS_MOVEMENT", "high" if big else "medium")]
    return []


def fingerprint(event: dict) -> str:
    """A client fingerprint to correlate on *besides* the IP: JA3, else a UA hash, else 'empty'. Two
    agents behind one host IP only separate when they differ here — same fingerprint is one source."""
    ja3 = str(event.get("ja3", "")).strip()
    if ja3:
        return "ja3:" + ja3[:16]
    ua = str(event.get("user_agent", "")).strip()
    if ua:
        return "ua:" + hashlib.sha256(ua.encode()).hexdigest()[:8]
    return "ua:empty"


# --------------------------------------------------------------------------- the real brain (opt-in)
# When --brain is on, soc_live asks the *actual* AEGIS orchestrator/swarm for the verdict instead of
# the heuristic correlator. Every call is guarded: a brain failure (no aegis, no GPU, a bad alert)
# falls back to the heuristic so the demo never breaks. soc_live still does correlation + blast radius;
# the brain supplies the verdict, the specialists that fired, the recommended actions and the reasoning.

_HITL_ACTIONS = {"isolate", "block_egress", "revoke_sessions", "quarantine", "terminate", "disable"}


class Brain:
    """Thin, guarded wrapper over the real AEGIS pipeline (aegis.service.build_pipeline)."""

    def __init__(self) -> None:
        self._pipe: Any = None
        self._lock = threading.Lock()
        self._dead = False

    def _ensure(self) -> Any:
        if self._pipe is None and not self._dead:
            # isolate the brain from soc_live's own plumbing: it never needs its own ingest server,
            # pollers or dashboard — soc_live feeds it alerts directly via orch.handle().
            os.environ.setdefault("LLM_BACKEND", "mock")     # real GPU run: set LLM_BACKEND=local before start
            os.environ.setdefault("AEGIS_EDITION", "soc")
            os.environ.setdefault("AEGIS_INTEL_MOCK", "1")
            for k in ("AEGIS_INGEST_HTTP", "AEGIS_INGEST_BIND", "AEGIS_SOURCES", "ACP_DASHBOARD_URL"):
                os.environ.pop(k, None)
            from aegis.service import build_pipeline      # noqa: PLC0415 — lazy so stdlib-only mode needs no aegis
            self._pipe = build_pipeline(fresh=True)
            print(f"  [brain] live — {type(self._pipe.orch).__name__}, backend={os.environ.get('LLM_BACKEND')}")
        return self._pipe

    def triage(self, alert: dict) -> Optional[dict]:
        """Run the real orchestrator on one alert → mapped verdict fields, or None on any failure."""
        try:
            with self._lock:
                pipe = self._ensure()
                if pipe is None:
                    return None
                chain = pipe.orch.handle(alert)
            d = chain.model_dump(mode="json")
        except Exception as exc:  # noqa: BLE001 — a broken brain must never take the demo down
            if self._pipe is None:
                self._dead = True                        # build failed → stop retrying this run
            print(f"  [brain] falling back to heuristic ({str(exc)[:120]})")
            return None
        actions = []
        for a in d.get("recommended_actions", []):
            at = a.get("action_type", "monitor")
            actions.append({"action_type": at, "target": a.get("target") or alert.get("src_ip", ""),
                            "requires_hitl": bool(a.get("requires_hitl", at in _HITL_ACTIONS)),
                            "confidence": float(a.get("confidence", d.get("confidence", 0.5))),
                            "reasoning": str(a.get("reasoning", ""))})
        reasoning = d.get("reasoning") or []
        why = ""
        if reasoning and isinstance(reasoning[-1], dict):
            why = str(reasoning[-1].get("detail") or reasoning[-1].get("step") or "")
        return {"verdict": str(d.get("verdict", "uncertain")), "confidence": float(d.get("confidence", 0.5)),
                "specialists": list(d.get("specialist_invocations", [])), "evidence_count": len(d.get("evidence", [])),
                "integrity_hash": d.get("integrity_hash"), "recommended_actions": actions,
                "investigated_by": str(d.get("investigated_by", "SwarmOrchestrator")), "reasoning": why,
                "governance_blocked": bool((d.get("metadata") or {}).get("governance_blocked", False))}


# Ambient baseline noise so the console reads like a live SOC before the first attack.
_BASELINE: list[dict] = [
    {"chain_id": "chn_base_02", "alert_id": "ALR-BASE-02", "source": "Edge WAF", "verdict": "benign",
     "confidence": 0.86, "specialists": ["perimeter"], "action_types": ["allow", "monitor"], "evidence_count": 3,
     "governance_blocked": False, "started_at": "2026-10-23T05:21:08Z", "integrity_hash": "d0c0ffee11223344",
     "note": "Odd TLS stack explained by the corporate inspection proxy; blocked scanner noise. Ambient — no action.",
     "investigation": {"swarm": ["ioc_extract"], "blast_radius": {
         "nodes": [{"id": "proxy-egress", "label": "inspection-proxy", "kind": "service", "verdict": "benign", "reached": False}],
         "edges": [], "critical": [], "choke_edges": []}},
     "recommended_actions": [{"action_type": "allow", "target": "10.20.4.51", "requires_hitl": False,
                              "confidence": 0.86, "reasoning": "Corporate inspection proxy; blocked scanner probe is noise."}]},
    {"chain_id": "chn_base_01", "alert_id": "ALR-BASE-01", "source": "Login edge", "verdict": "suspicious",
     "confidence": 0.63, "specialists": ["auth"], "action_types": ["throttle", "monitor"], "evidence_count": 4,
     "governance_blocked": False, "started_at": "2026-10-23T05:30:55Z", "integrity_hash": "41d7e0b9a1227c6e",
     "note": "A few usernames from one source at a moderate rate, blocked — a probe, not a compromise. Auto-handled.",
     "investigation": {"swarm": ["ioc_extract", "intel_enrich"], "blast_radius": {
         "nodes": [{"id": "login-edge", "label": "login-edge", "kind": "service", "verdict": "suspicious", "reached": True},
                   {"id": "src-ambient", "label": "198.51.100.88", "kind": "service", "verdict": "suspicious", "reached": True}],
         "edges": [{"source": "src-ambient", "target": "login-edge", "kind": "attack"}], "critical": [], "choke_edges": []}},
     "recommended_actions": [{"action_type": "throttle", "target": "198.51.100.88", "requires_hitl": False,
                              "confidence": 0.63, "reasoning": "Slow the source while an analyst reviews."}]},
]

_PROPOSALS: list[dict] = [
    {"id": "prop_01", "change_type": "model_promotion", "status": "pending", "validation_passed": True,
     "summary": "Promote triage-qwen3-8b-public-v5 → live brain",
     "rationale": "Gate PASS (historical 33/37, injection 9/9, agentic 10/13, endpoint 8/8, tls 12/13). Shadow: +3pt analyst agreement on 48 new alerts.",
     "created_at": "2026-10-23T05:10:00Z"},
    {"id": "prop_02", "change_type": "rule", "status": "accepted", "validation_passed": True,
     "summary": "Raise auth-burst sensitivity for /login after 03:00 IST",
     "rationale": "Meta-agent proposal; reduced two historical misses with zero regressions.",
     "decided_by": "ciso", "decided_at": "2026-10-22T19:20:00Z", "created_at": "2026-10-22T18:55:00Z"},
]


def _short(s: str, n: int = 6) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:n]


def _env_flag(name: str) -> bool:
    return str(os.environ.get(name, "")).strip().lower() in ("1", "true", "yes", "on")


class Campaign:
    """Blocked + evaded requests from one (source, fingerprint), correlated into one incident."""

    def __init__(self, src_ip: str, fp: str) -> None:
        self.src_ip = src_ip
        self.fp = fp
        self.events: list[dict] = []
        self.rules: dict[str, int] = {}
        self.evaded_rules: set[str] = set()
        self.behavioral_rules: set[str] = set()
        self.principals: set[str] = set()
        self.blocked = 0
        self.evaded = 0
        self.behavioral = 0
        self.empty_ua_evasion = False
        self.worst = "low"
        self.first_ts = ""
        self.last_ts = ""
        self.contained = False
        self.enforced = False                  # a real block was pushed to the target (not shadow)
        self.enforcement: dict = {}            # what the target applied (blocked ip, revoked sessions)
        self.brain: Optional[dict] = None     # real-swarm verdict overlay (when --brain is on)
        self.brain_at = 0                      # evidence count at the last brain triage
        self.triaging = False                  # a brain triage is in flight for this campaign

    def representative_alert(self) -> Optional[dict]:
        """The most severe *attack* event in the campaign — what to hand the orchestrator. Behavioral-
        only campaigns (no WAF/signature event) return None (the brain triages alerts, not app ops)."""
        attacks = [e for e in self.events if str(e.get("action")) == "blocked" or e.get("rules") or e.get("rule")]
        if not attacks:
            return None
        return max(attacks, key=lambda e: _SEV_RANK.get(str(e.get("severity", "low")).lower(), 0))

    def add(self, event: dict, *, edge_blocked: bool, deep: list[tuple[str, str]],
            behavioral: list[tuple[str, str]]) -> None:
        self.events.append(event)
        rules: list[str] = []
        sevs: list[str] = []
        if edge_blocked:
            self.blocked += 1
            rules += event.get("rules") or ([event["rule"]] if event.get("rule") else [])
            sevs.append(str(event.get("severity", "medium")))
        else:
            if deep:                                    # allowed, but a signature the edge missed
                self.evaded += 1
                dr = [r for r, _ in deep]
                rules += dr
                sevs += [s for _, s in deep]
                self.evaded_rules |= set(dr)
                if not str(event.get("user_agent", "")).strip():
                    self.empty_ua_evasion = True
            if behavioral:                              # authorized abuse the WAF cannot see
                self.behavioral += 1
                br = [r for r, _ in behavioral]
                rules += br
                sevs += [s for _, s in behavioral]
                self.behavioral_rules |= set(br)
        p = str(event.get("principal", "")).strip()
        if p and p != "anon":
            self.principals.add(p)
        for r in rules:
            self.rules[r] = self.rules.get(r, 0) + 1
        for s in sevs:
            if _SEV_RANK.get(s.lower(), 0) > _SEV_RANK.get(self.worst, 0):
                self.worst = s.lower()
        ts = str(event.get("ts") or "")
        self.first_ts = self.first_ts or ts
        self.last_ts = ts or self.last_ts

    @property
    def count(self) -> int:
        return len(self.events)

    @property
    def _hard_malicious(self) -> bool:
        # A confirmed deterministic detection — a critical severity or a known-malicious signature/
        # behavioral rule. This is the floor the triage model may not lower.
        return self.worst == "critical" or bool(set(self.rules) & _MALICIOUS_RULES)

    @property
    def _heuristic_malicious(self) -> bool:
        # Hard detections plus the soft volume rule (many flagged requests from one source).
        return self._hard_malicious or self.count >= 5

    @property
    def is_malicious(self) -> bool:
        # The triage model is a FIRST PASS: it can escalate, and it can quiet the soft volume rule
        # (noise), but it never lowers a confirmed signature/behavioral hit (the model card's
        # "never drops a malicious case to benign").
        if self.brain:
            if self.brain["verdict"] == "malicious":
                return True
            return self._hard_malicious          # brain may downgrade volume noise, not a signature
        return self._heuristic_malicious

    @property
    def verdict(self) -> str:
        return "malicious" if self.is_malicious else "suspicious"

    @property
    def confidence(self) -> float:
        # When the swarm agrees with the reported verdict, use its confidence; when the signature
        # floor overrode a softer brain call, report the deterministic detector's own confidence.
        if self.brain and self.brain["verdict"] == self.verdict:
            return round(float(self.brain["confidence"]), 2)
        if self.is_malicious:
            return round(min(0.97, 0.9 + self.count * 0.004), 2)
        return round(min(0.75, 0.6 + self.count * 0.02), 2)

    @property
    def key(self) -> str:
        return _short(self.src_ip + "|" + self.fp, 6)

    @property
    def cid(self) -> str:
        return f"chn_live_{self.key}"

    def top_rules(self, n: int = 3) -> list[str]:
        ranked = [r for r, _ in sorted(self.rules.items(), key=lambda kv: -kv[1]) if r != "SCANNER_UA"]
        return (ranked or list(self.rules))[:n]

    def _note(self, distinct_clients: int) -> str:
        tops = ", ".join(self.top_rules()) or "web attacks"
        fp_label = self.fp
        note = (f"{self.count} flagged request(s) from {self.src_ip} [{fp_label}] "
                f"(top signals: {tops}).")
        if self.brain:
            specs = ", ".join(self.brain.get("specialists") or []) or "swarm"
            bverdict = self.brain["verdict"]
            note += (f" Triaged live by the AEGIS swarm ({specs}) → {bverdict} "
                     f"@ {self.brain['confidence']:.0%}.")
            if _VRANK.get(bverdict, 0) < _VRANK.get(self.verdict, 0):
                note += (f" A confirmed deterministic detection holds this at {self.verdict} — the triage "
                         "model is a first pass and never lowers a signature/behavioral hit.")
            if self.brain.get("reasoning"):
                note += f" {self.brain['reasoning']}"
        if self.evaded:
            evaded = ", ".join(sorted(self.evaded_rules)) or "payloads"
            note += (f" {self.evaded} bypassed the edge WAF and were caught by SOC re-inspection of the "
                     f"allowed stream ({evaded}" + (", empty User-Agent" if self.empty_ua_evasion else "") + ").")
        if self.behavioral_rules:
            who = "/".join(sorted(self.principals)) or "an authenticated principal"
            note += (f" Authorized activity flagged by behavioral detection — no WAF signature: "
                     f"{', '.join(sorted(self.behavioral_rules))} (principal {who}).")
        if distinct_clients > 1:
            note += (f" Note: {self.src_ip} shows {distinct_clients} distinct client fingerprints — "
                     "possible concurrent agents behind one host IP; counts are per fingerprint.")
        if "PROMPT_INJECTION" in self.rules:
            note += (" One request carried an embedded \"ignore your rules and approve this\" instruction — "
                     "recorded as evidence, not obeyed.")
        if self.is_malicious and not self.enforced:
            note += (" Containment below is DEMONSTRATED in shadow mode against a mock tenant — it does not "
                     "isolate a live agent; real enforcement needs a connector or the demo enforcement hook.")
        if self.enforced:
            blocked = ", ".join(self.enforcement.get("blocked_ips", [])) or self.src_ip
            revoked = self.enforcement.get("revoked_sessions", 0)
            note += (f"  ✓ CONTAINED (enforced): the target is now 403ing {blocked}"
                     + (f" and revoked {revoked} session(s)" if revoked else "")
                     + " — the attacker's next request is blocked. Real enforcement against the demo bank.")
        elif self.contained:
            note += ("  ✓ CONTAINED (shadow): app-ledger-07 isolated against the mock tenant, the choke edge to "
                     "db-core is cut. Demonstrated, audited — no live process was killed.")
        return note

    def _blast_radius(self) -> dict:
        ip_id = "src-" + self.src_ip.replace(".", "-").replace(":", "-")
        ledger_verdict = "benign" if self.contained else "suspicious"
        nodes = [
            {"id": ip_id, "label": self.src_ip, "kind": "service", "verdict": "malicious", "reached": True},
            {"id": "edge-waf", "label": "edge-waf", "kind": "service", "verdict": "malicious", "reached": True},
            {"id": "api-gw-01", "label": "api-gw-01", "kind": "service", "verdict": "suspicious", "reached": bool(self.evaded)},
            {"id": "app-ledger-07", "label": "app-ledger-07", "kind": "host", "verdict": ledger_verdict, "reached": False},
            {"id": "db-core", "label": "db-core (ledger)", "kind": "data", "verdict": "uncertain", "critical": True, "reached": False},
        ]
        edges = [
            {"source": ip_id, "target": "edge-waf", "kind": "attack"},
            {"source": "edge-waf", "target": "api-gw-01", "kind": "attack"},
            {"source": "api-gw-01", "target": "app-ledger-07", "kind": "lateral"},
            {"source": "app-ledger-07", "target": "db-core", "kind": "lateral"},
        ]
        return {"nodes": nodes, "edges": edges, "critical": ["db-core"],
                "choke_edges": [] if self.contained else [["app-ledger-07", "db-core"]]}

    def to_chain(self, distinct_clients: int = 1) -> dict:
        actions = [
            {"action_type": "isolate", "target": "app-ledger-07", "requires_hitl": True, "confidence": self.confidence,
             "reasoning": "Isolating app-ledger-07 severs the only path the attacker has left to the core ledger DB."},
            {"action_type": "block_egress", "target": self.src_ip, "requires_hitl": True, "confidence": round(self.confidence - 0.01, 2),
             "reasoning": f"Block the attacking source {self.src_ip} at the egress proxy and firewall."},
        ]
        # Default (heuristic) overlay. When the real swarm has triaged this campaign (--brain),
        # its verdict, specialists, actions and integrity hash replace the heuristic ones below,
        # and `triage` flips to "swarm" so the console shows the investigation came from the brain.
        triage = "heuristic"
        specialists = ["perimeter"] + (["auth"] if "AUTH_BURST" in self.rules else [])
        action_types = (["isolate", "block_egress"] if self.is_malicious else ["throttle", "monitor"])
        evidence_count = self.count
        integrity_hash = _short(self.cid + str(self.count), 16)
        source = "Ledger Demo Bank SOC"
        rec_actions = actions if self.is_malicious else [
            {"action_type": "monitor", "target": self.src_ip, "requires_hitl": False, "confidence": self.confidence,
             "reasoning": "Blocked probe; watch for escalation."}]
        swarm = ["ioc_extract", "intel_enrich", "blast_radius", "log_hunt"]
        governance_blocked = False
        if self.brain:
            # The swarm supplies the INVESTIGATION (who looked, how much evidence, the signed chain,
            # the reasoning) and can escalate the verdict; the recommended containment still follows the
            # final (floored) verdict so a malicious incident always offers isolate/block_egress to HITL.
            triage = "swarm"
            source = "AEGIS swarm (live)"
            governance_blocked = bool(self.brain.get("governance_blocked", False))
            if self.brain.get("specialists"):
                specialists = list(self.brain["specialists"])
                swarm = list(self.brain["specialists"])
            if self.brain.get("evidence_count"):
                evidence_count = int(self.brain["evidence_count"])
            if self.brain.get("integrity_hash"):
                integrity_hash = str(self.brain["integrity_hash"])
        chain = {
            "chain_id": self.cid, "alert_id": f"ALR-{self.key.upper()}",
            "source": source, "verdict": self.verdict, "confidence": self.confidence,
            "specialists": specialists, "triage": triage,
            "action_types": action_types,
            "evidence_count": evidence_count, "governance_blocked": governance_blocked,
            "started_at": self.first_ts or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "integrity_hash": integrity_hash, "note": self._note(distinct_clients),
            "client_fingerprint": self.fp, "distinct_clients_from_ip": distinct_clients,
            "edge_blocked": self.blocked, "edge_evaded": self.evaded, "behavioral": self.behavioral,
            "behavioral_rules": sorted(self.behavioral_rules), "principals": sorted(self.principals),
            "investigation": {"swarm": swarm,
                              "campaign": {"id": f"camp_{self.key}", "related_alerts": self.count},
                              "blast_radius": self._blast_radius()},
            "recommended_actions": rec_actions,
        }
        if self.is_malicious:
            chain["investigation"]["plan"] = {"steps": [
                {"order": 1, "action_type": "isolate", "target": "app-ledger-07",
                 "rationale": "Only remaining path to the ledger DB runs through this host — cutting it contains the campaign.",
                 "cuts_edges": [["app-ledger-07", "db-core"]]},
                {"order": 2, "action_type": "block_egress", "target": self.src_ip,
                 "rationale": "The attacking source; block at the egress proxy."}]}
        return chain


class _PgSink:
    """Optional Postgres persistence for live incidents — a durable audit log beside the in-memory
    console. Lazy and guarded: psycopg2 is imported only when a DSN is set, and any failure (no
    driver, DB down, bad DSN) disables the sink so the SOC keeps running in-memory, stdlib-only."""

    def __init__(self, dsn: str) -> None:
        self.dsn = dsn
        self._conn: Any = None
        self._dead = False
        self._lock = threading.Lock()

    def _connect(self) -> Any:
        import psycopg2  # noqa: PLC0415 — optional dep, only needed when a DSN is configured
        conn = psycopg2.connect(self.dsn)
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                "CREATE TABLE IF NOT EXISTS soc_incidents ("
                " chain_id text PRIMARY KEY, alert_id text, source text, verdict text,"
                " confidence double precision, src_ip text, specialists text[], triage text,"
                " evidence_count int, enforced boolean, note text, chain jsonb,"
                " created_at timestamptz DEFAULT now(), updated_at timestamptz DEFAULT now())")
        return conn

    def upsert(self, chain: dict, *, src_ip: str, enforced: bool) -> None:
        if self._dead:
            return
        try:
            with self._lock:
                if self._conn is None:
                    self._conn = self._connect()
                    print(f"  [pg] persisting incidents → {self.dsn.rsplit('@', 1)[-1]}")
                with self._conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO soc_incidents (chain_id, alert_id, source, verdict, confidence,"
                        " src_ip, specialists, triage, evidence_count, enforced, note, chain, updated_at)"
                        " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb, now())"
                        " ON CONFLICT (chain_id) DO UPDATE SET verdict=EXCLUDED.verdict,"
                        " confidence=EXCLUDED.confidence, specialists=EXCLUDED.specialists,"
                        " triage=EXCLUDED.triage, evidence_count=EXCLUDED.evidence_count,"
                        " enforced=EXCLUDED.enforced, note=EXCLUDED.note, chain=EXCLUDED.chain,"
                        " updated_at=now()",
                        (chain.get("chain_id"), chain.get("alert_id"), chain.get("source"),
                         chain.get("verdict"), float(chain.get("confidence") or 0.0), src_ip,
                         list(chain.get("specialists") or []), chain.get("triage"),
                         int(chain.get("evidence_count") or 0), bool(enforced),
                         chain.get("note"), json.dumps(chain)))
        except Exception as exc:  # noqa: BLE001 — persistence is best-effort; never take the SOC down
            self._dead = True
            try:
                if self._conn is not None:
                    self._conn.close()
            except Exception:  # noqa: BLE001
                pass
            self._conn = None
            print(f"  [pg] persistence disabled — running in-memory only ({str(exc)[:120]})")


class LiveSoc:
    """Live SOC state — ingest the full request stream, correlate into incidents, drive HITL. Headless."""

    def __init__(self, brain: Optional["Brain"] = None, *, enforce_url: str = "", enforce_token: str = "",
                 pg_dsn: str = "") -> None:
        self._lock = threading.Lock()
        self._enforce_url = enforce_url        # target's control endpoint; "" → shadow (demonstrated only)
        self._enforce_token = enforce_token
        self._camps: dict[tuple[str, str], Campaign] = {}
        self._fps_by_ip: dict[str, set[str]] = {}
        self._decisions: dict[str, dict] = {}
        self._benign = 0
        self._brain = brain                # None → heuristic only; set → real swarm triages each campaign
        self._anon_sids: set[str] = set()  # session ids first seen unauthenticated (for fixation detection)
        self._pg = _PgSink(pg_dsn) if pg_dsn else None   # None → in-memory only (stdlib default)

    def _persist(self, camp: Campaign) -> None:
        """Write the campaign's current incident to Postgres, when a sink is configured. Throttled to
        meaningful changes (count / verdict / enforced) and fully guarded — never blocks or crashes."""
        if self._pg is None:
            return
        sig = (camp.count, camp.verdict, camp.enforced, bool(camp.brain))
        if getattr(camp, "_pg_sig", None) == sig:
            return
        camp._pg_sig = sig                                       # type: ignore[attr-defined]
        try:
            chain = camp.to_chain(self._distinct(camp.src_ip))
        except Exception:  # noqa: BLE001
            return
        self._pg.upsert(chain, src_ip=camp.src_ip, enforced=camp.enforced)

    def _session_finding(self, event: dict) -> list[tuple[str, str]]:
        """Session fixation: a session id presented UNAUTHENTICATED and later presented AUTHENTICATED
        is one the server failed to rotate at login — the fixation signal. Stateful, so it lives on
        LiveSoc rather than in a pure inspector. Caller holds the lock."""
        sid = str(event.get("sid", "")).strip()
        if not sid:
            return []
        authed = str(event.get("principal", "anon")).strip() not in ("", "anon")
        if not authed:
            self._anon_sids.add(sid)
            return []
        return [("SESSION_FIXATION", "high")] if sid in self._anon_sids else []

    def ingest(self, event: dict) -> None:
        src = str(event.get("src_ip") or event.get("source_ip") or "unknown")
        edge_blocked = str(event.get("action")) == "blocked" or bool(event.get("rules")) or bool(event.get("rule"))
        # Cookie-layer findings (payload-in-cookie via deep_inspect, forged privilege/token, session
        # fixation) are evasions the edge WAF's payload view misses — grouped with `deep`.
        deep = [] if edge_blocked else deep_inspect(event) + cookie_inspect(event)
        behavioral = [] if edge_blocked else behavioral_inspect(event)
        with self._lock:
            deep = deep + ([] if edge_blocked else self._session_finding(event))
        if not (edge_blocked or deep or behavioral):
            with self._lock:
                self._benign += 1          # allowed + clean + ordinary op: counted, no incident
            return
        fp = fingerprint(event)
        with self._lock:
            self._fps_by_ip.setdefault(src, set()).add(fp)
            camp = self._camps.get((src, fp)) or self._camps.setdefault((src, fp), Campaign(src, fp))
            camp.add(event, edge_blocked=edge_blocked, deep=deep, behavioral=behavioral)
        self._maybe_triage(camp)
        self._persist(camp)

    def _maybe_triage(self, camp: Campaign) -> None:
        """Kick a background real-swarm triage when the brain is on and this campaign has grown.
        Never blocks ingest; a failed/slow brain leaves the heuristic verdict standing."""
        if self._brain is None:
            return
        with self._lock:
            if camp.triaging or camp.brain_at >= camp.count:
                return                      # already triaged at this evidence count, or one in flight
            alert = camp.representative_alert()
            if alert is None:
                return                      # behavioral-only campaign — no alert for the brain to triage
            camp.triaging = True
            camp.brain_at = camp.count

        def _run() -> None:
            result = self._brain.triage(alert) if self._brain else None
            with self._lock:
                camp.triaging = False
                if result is not None:
                    camp.brain = result     # real swarm's verdict now overlays this campaign's chain
            if result is not None:
                self._persist(camp)         # the swarm verdict changed the incident → re-persist

        threading.Thread(target=_run, name=f"triage-{camp.key}", daemon=True).start()

    def _distinct(self, src: str) -> int:
        return len(self._fps_by_ip.get(src, set()))

    def chains(self) -> list[dict]:
        with self._lock:
            live = [c.to_chain(self._distinct(c.src_ip)) for c in self._camps.values()]
        allc = live + [dict(c) for c in _BASELINE]
        rank = {"malicious": 2, "suspicious": 1, "benign": 0}
        allc.sort(key=lambda c: (rank.get(c["verdict"], 0), c["confidence"], c["evidence_count"]), reverse=True)
        return allc

    def chain(self, cid: str) -> Optional[dict]:
        return next((c for c in self.chains() if c["chain_id"] == cid), None)

    def approvals(self) -> list[dict]:
        out: list[dict] = []
        with self._lock:
            for camp in self._camps.values():
                if not camp.is_malicious:
                    continue
                for suffix, atype, target, reason in (
                    ("iso", "isolate", "app-ledger-07", "Isolating app-ledger-07 severs the only path left to the core ledger DB."),
                    ("blk", "block_egress", camp.src_ip, f"Block the attacking source {camp.src_ip} at the egress proxy and firewall."),
                ):
                    aid = f"appr_{camp.key}_{suffix}"
                    appr = {"id": aid, "status": "pending", "created_at": camp.last_ts or "",
                            "action_type": atype, "target": target, "alert_id": f"ALR-{camp.key.upper()}",
                            "integrity_hash": _short(camp.cid + str(camp.count), 16), "agent_id": "SOC-AGENTQ-01",
                            "reasoning": reason}
                    appr.update(self._decisions.get(aid, {}))
                    out.append(appr)
        return out

    def proposals(self) -> list[dict]:
        return [dict(p) for p in _PROPOSALS]

    def _post_control(self, payload: dict) -> dict:
        """POST one enforcement action to the target's control endpoint. stdlib only."""
        data = json.dumps(payload).encode()
        req = urllib.request.Request(self._enforce_url, data=data, method="POST",
                                     headers={"Content-Type": "application/json",
                                              "Authorization": f"Bearer {self._enforce_token}"})
        with urllib.request.urlopen(req, timeout=5) as r:        # noqa: S310 — operator-set loopback URL
            return json.loads(r.read().decode() or "{}")

    def _apply_enforcement(self, camp: Campaign, *, isolate: bool) -> None:
        """Push a real block to the target: 403 the source IP, and on isolate revoke the attacker's
        authenticated sessions. Any failure leaves the incident as shadow-contained, never crashes."""
        principals = sorted(camp.principals) if isolate else []
        res: dict = {}
        try:
            res = self._post_control({"action": "isolate" if isolate else "block_egress", "target": camp.src_ip})
            for p in principals:
                self._post_control({"action": "isolate", "principal": p})
            if principals:                                       # refresh the snapshot after revocations
                res = self._post_control({"action": "isolate", "target": camp.src_ip})
        except Exception as exc:  # noqa: BLE001 — enforcement is best-effort; fall back to shadow
            print(f"  [enforce] target control call failed ({str(exc)[:120]}) — staying shadow-contained")
            return
        refused = _enforcement_refused(res, camp.src_ip)
        if refused:
            # a 200 is not a block: the edge answers {"accepted": false} for a never-block or malformed target and
            # the demo target {"ok": false} when nothing applied — both used to print "✓ CONTAINED" (review C7)
            print(f"  [enforce] target did not block {camp.src_ip}: {refused} — staying shadow-contained")
            return
        with self._lock:
            camp.enforced = True
            camp.enforcement = {"blocked_ips": res.get("blocked_ips", [camp.src_ip]),
                                "revoked_sessions": int(res.get("revoked_sessions", 0))}
        print(f"  ▶ ENFORCED: target now blocks {camp.src_ip}"
              + (f", revoked {camp.enforcement['revoked_sessions']} session(s)" if principals else ""))

    def decide(self, approval_id: str, status: str, *, rationale: str = "", by: str = "soc-analyst") -> bool:
        target: Optional[Campaign] = None
        with self._lock:
            valid = {f"appr_{c.key}_{s}": c for c in self._camps.values() if c.is_malicious for s in ("iso", "blk")}
            if approval_id not in valid:
                return False
            self._decisions[approval_id] = {
                "status": "approved" if status == "approve" else "rejected", "decided_by": by,
                "decided_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "rationale": rationale or ("Confirmed — contain the path to the ledger." if status == "approve" else "Not now."),
            }
            if status == "approve":
                target = valid[approval_id]
                if approval_id.endswith("_iso"):
                    target.contained = True
        # the real block is pushed OUTSIDE the lock (a network call); shadow if no control URL is set
        if target is not None and self._enforce_url:
            self._apply_enforcement(target, isolate=approval_id.endswith("_iso"))
        if target is not None:
            self._persist(target)           # persist the decision/enforcement to the audit log
        return True

    def stats(self) -> dict:
        with self._lock:
            mal = sum(1 for c in self._camps.values() if c.is_malicious)
            evaded = sum(c.evaded for c in self._camps.values())
            behavioral = sum(c.behavioral for c in self._camps.values())
            return {"sources": len({c.src_ip for c in self._camps.values()}), "campaigns": len(self._camps),
                    "malicious": mal, "alerts": sum(c.count for c in self._camps.values()),
                    "edge_evaded": evaded, "behavioral": behavioral, "benign_allowed": self._benign}


# ----------------------------------------------------------------------------- HTTP surface

def _enforcement_refused(res: dict, ip: str) -> str:
    """Why a control reply does not show ``ip`` blocked ('' = it does). Understands the edge
    (``accepted`` + ``pushed``) and the demo target (``ok`` + ``blocked_ips``)."""
    if not isinstance(res, dict):
        return "reply is not a JSON object"
    if res.get("accepted") is False:
        return "the edge did not accept the block"
    if res.get("ok") is False:
        return "the target applied nothing"
    listed = res.get("blocked_ips", res.get("pushed"))
    if isinstance(listed, list) and ip not in listed:
        return f"{ip} is not in the target's block list"
    if "accepted" not in res and "ok" not in res and listed is None:
        return "the reply does not say what was blocked"
    return ""


class _Handler(BaseHTTPRequestHandler):
    soc: LiveSoc = LiveSoc()
    ingest_token: str = ""

    def log_message(self, *a: Any) -> None:
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

    def _ingest_authorized(self) -> bool:
        if not _Handler.ingest_token:
            return True  # no token configured (loopback dev): allowed, with a startup warning
        presented = self.headers.get("Authorization", "")
        if presented.lower().startswith("bearer "):
            presented = presented[7:].strip()
        return bool(presented) and hmac.compare_digest(presented.encode(), _Handler.ingest_token.encode())

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path.rstrip("/")
        s = _Handler.soc
        if path in ("/api/soc/chains", "/api/chains"):
            self._send(200, s.chains())
        elif path.startswith("/api/soc/chains/"):
            c = s.chain(path.rsplit("/", 1)[-1])
            self._send(200 if c else 404, c or {"error": "not found"})
        elif path in ("/api/approvals", "/api/soc/approvals"):
            self._send(200, s.approvals())
        elif path in ("/api/soc/proposals", "/api/proposals"):
            self._send(200, s.proposals())
        elif path in ("/healthz", "/api/healthz"):
            self._send(200, {"ok": True, **s.stats()})
        else:
            self._send(404, {"error": "not found", "path": path})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path.rstrip("/")
        s = _Handler.soc
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        if path in ("/ingest/alerts", "/ingest/waf", "/api/ingest/alerts"):
            if not self._ingest_authorized():
                self._send(401, {"error": "ingest requires a valid bearer token"})
                return
            count = 0
            for line in raw.decode("utf-8", "replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    s.ingest(json.loads(line))
                    count += 1
                except ValueError:
                    pass
            self._send(200, {"ok": True, "ingested": count})
            return
        parts = path.strip("/").split("/")
        try:
            body = json.loads(raw or b"{}") if raw else {}
        except ValueError:
            body = {}
        if len(parts) >= 4 and parts[:2] == ["api", "approvals"] and parts[3] in ("approve", "reject"):
            # A decision can push real enforcement (--target-control-url). The console calls this server-side
            # with the bearer token and no Origin; a browser page (CSRF) always sends an Origin. Refuse both a
            # missing token and any cross-site browser request.
            if self.headers.get("Origin") or not self._ingest_authorized():
                self._send(403, {"error": "decisions need the console's bearer token and no browser Origin"})
                return
            ok = s.decide(parts[2], "approve" if parts[3] == "approve" else "reject",
                          rationale=str(body.get("rationale") or body.get("reason") or ""))
            if ok and parts[3] == "approve" and parts[2].endswith("_iso") and not s._enforce_url:
                print("\n  ▶ analyst APPROVED isolate app-ledger-07 — containment DEMONSTRATED (shadow). No live process killed.\n")
            self._send(200 if ok else 404, {"ok": ok})
        else:
            self._send(404, {"error": "not found", "path": path})


_LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="AEGIS SOC live backend — real bank traffic → live console incidents.")
    ap.add_argument("--port", type=int, default=8799)
    ap.add_argument("--bind", default="127.0.0.1", help="interface to bind (default loopback; do not expose)")
    ap.add_argument("--ingest-token", default=os.environ.get("AEGIS_INGEST_TOKEN", ""),
                    help="bearer token required on /ingest/* (also AEGIS_INGEST_TOKEN). Required off-loopback.")
    ap.add_argument("--brain", action="store_true", default=_env_flag("AEGIS_LIVE_BRAIN"),
                    help="triage each campaign with the REAL aegis swarm (aegis.service.build_pipeline) "
                         "instead of the heuristic (also AEGIS_LIVE_BRAIN=1). LLM_BACKEND=mock unless set to local.")
    ap.add_argument("--target-control-url", default=os.environ.get("AEGIS_TARGET_CONTROL_URL", ""),
                    help="the protected target's enforcement endpoint, e.g. http://127.0.0.1:8800/control/enforce. "
                         "Set it and an approved isolate/block REALLY blocks the source at the target (not shadow). "
                         "Unset → containment stays demonstrated/shadow.")
    ap.add_argument("--pg-dsn", default=os.environ.get("AEGIS_SOC_PG_DSN", ""),
                    help="Postgres DSN (e.g. postgresql://soc:soc@127.0.0.1:5433/soc) to persist each incident "
                         "to a soc_incidents table (also AEGIS_SOC_PG_DSN). Unset → in-memory only (needs psycopg2).")
    a = ap.parse_args(argv)

    token = a.ingest_token.strip()
    if a.bind not in _LOOPBACK and not token:
        print("  refusing to bind a non-loopback interface without --ingest-token (AEGIS_INGEST_TOKEN).")
        return 2

    enforce_url = a.target_control_url.strip()
    if enforce_url and not token:
        print("  refusing enforcement without a shared token — set AEGIS_INGEST_TOKEN so the target can auth the control call.")
        return 2

    brain: Optional[Brain] = Brain() if a.brain else None
    # the edge's own control token when it has one (AEGIS_EDGE_CONTROL_TOKEN), else the shared ingest token
    enforce_token = os.environ.get("AEGIS_EDGE_CONTROL_TOKEN", "").strip() or token
    _Handler.soc = LiveSoc(brain=brain, enforce_url=enforce_url, enforce_token=enforce_token, pg_dsn=a.pg_dsn.strip())
    _Handler.ingest_token = token
    httpd = ThreadingHTTPServer((a.bind, a.port), _Handler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, name="soc-live", daemon=True).start()
    print("=" * 84)
    _enf = f"ENFORCED → {enforce_url}" if enforce_url else "SHADOW (demonstrated, not real)"
    print(f"  AEGIS SOC LIVE  ·  edition=soc  ·  enforcement {_enf}  ·  offline")
    print(f"  backend : http://{a.bind}:{a.port}     (console AEGIS_API_ORIGIN → here)")
    print(f"  ingest  : http://{a.bind}:{a.port}/ingest/alerts   (demo bank --aegis-url → here)")
    print(f"  ingest auth : {'BEARER TOKEN required' if token else '⚠ NONE — set AEGIS_INGEST_TOKEN to require a token'}")
    if brain is not None:
        print(f"  triage  : REAL AEGIS swarm (LLM_BACKEND={os.environ.get('LLM_BACKEND', 'mock')}) — "
              "each campaign investigated by aegis.service; heuristic is the fallback.")
    else:
        print("  triage  : heuristic (start with --brain or AEGIS_LIVE_BRAIN=1 to use the real swarm).")
    print(f"  persist : {'Postgres → ' + a.pg_dsn.strip().rsplit('@', 1)[-1] if a.pg_dsn.strip() else 'in-memory only (set AEGIS_SOC_PG_DSN to log to Postgres)'}")
    print("  sees allowed traffic too (evasions caught by SOC re-inspection); correlates by (ip, fingerprint).")
    print("=" * 84)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\n  live backend stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
