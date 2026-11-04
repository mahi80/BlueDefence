"""ACP governance consumer — what Q saw on the governed agents becomes SOC alerts (the Q ↔ AEGIS bridge).

Q (the dashboard) watches the *inside*: rogue detectors, Q37 infrastructure-guard blocks, the
pause-gate. Until now a LangGraph agent going rogue produced a card on the Watch tab and (maybe)
a pause — and that was the end of it. This consumer polls ``GET /api/soc/events`` and turns
each event into an AEGIS alert, so the same pipeline that handles an external intrusion runs on
it: triage → swarm → blast radius (what did the agent touch before the pause?) → min-cut plan →
HITL card, and the campaign context joins it to any external traffic from the same host.

    AEGIS_SOURCES=acp,sentinel,waf   ACP_DASHBOARD_URL=…  ACP_API_KEY=…
    AEGIS_ACP_MIN_SEVERITY=MEDIUM    AEGIS_ACP_KINDS=rogue_alert,governance_block,agent_paused

The watermark is the dashboard's ``next_since``; ids are deduped through the shared checkpoint.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Iterator, Optional

from .base import CONSUMED, AlertCheckpoint, BaseConsumer, severity_to_score

logger = logging.getLogger("aegis.ingest.acp")

Transport = Callable[[str, str, Optional[bytes], dict, float], tuple[int, str]]


def _urllib_transport(method: str, url: str, body: Optional[bytes], headers: dict, timeout: float) -> tuple[int, str]:
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — the bank's own dashboard
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


# issue_type / control → the specialist vocabulary the triage model was trained on
_ISSUE_HINTS = {
    "infra_attack": ("cloud_controlplane", "T1552.005"),         # metadata / link-local / outbound attack
    "budget_runaway": ("api_abuse", "T1499"),
    "control_spike": ("api_abuse", "T1499"),
    "undeclared_subagent": ("edr", "T1055"),
    "heartbeat_silence": ("edr", "T1562.001"),
    "audit_chain_break": ("edr", "T1070"),
    "memory_retention_breach": ("dlp", "T1530"),
    "tier_escalation": ("auth", "T1078"),
    "threat_impact": ("perimeter", "T1190"),
    "threat_intel_pulse": ("perimeter", "T1190"),
}
_CONTROL_HINTS = {
    "ACP-737": ("cloud_controlplane", "T1552.005", "Q37 infrastructure guard"),
    "ACP-730": ("api_abuse", "T1106", "Q30 tool allowlist"),
    "ACP-733": ("api_abuse", "T1499", "Q33 rate limiter"),
    "ACP-720": ("auth", "T1078", "Q20 intent"),
    "ACP-726": ("dlp", "T1530", "Q26 data residency"),
}


_SEV_RANK = {"INFO": 0, "INFORMATIONAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class AcpFeedError(RuntimeError):
    """The ACP events feed could not be read this poll (outage, 401, 5xx)."""


class AcpGovernanceConsumer(BaseConsumer):
    name = "acp"

    def __init__(self, dashboard_url: Optional[str] = None, api_key: Optional[str] = None, *,
                 checkpoint: Optional[AlertCheckpoint] = None, transport: Optional[Transport] = None,
                 min_severity: Optional[str] = None, kinds: Optional[str] = None, timeout: float = 10.0, page: int = 200):
        super().__init__(checkpoint)
        self.dashboard_url = (dashboard_url or os.environ.get("ACP_DASHBOARD_URL", "")).rstrip("/")
        self.api_key = api_key if api_key is not None else os.environ.get("ACP_API_KEY", "")
        self.min_severity = (min_severity or os.environ.get("AEGIS_ACP_MIN_SEVERITY", "MEDIUM")).upper()
        self.kinds = kinds if kinds is not None else os.environ.get("AEGIS_ACP_KINDS", "")
        self.timeout = timeout; self.page = page
        self._transport: Transport = transport or _urllib_transport
        self.last_error = ""

    @property
    def configured(self) -> bool:
        return bool(self.dashboard_url)

    # ------------------------------------------------------------- fetch --
    def fetch(self, **kwargs) -> Iterator[dict]:
        since = kwargs.get("since") or self.checkpoint.watermark(self.name) or ""
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        for _ in range(20):                                   # bounded pages per poll
            # INFO, not the configured floor: the dashboard applied min_severity AFTER its per-table LIMIT, and
            # next_since then jumped past MEDIUM+ rogue alerts hidden behind a page of LOW rows (round 7 G-8). The
            # floor is applied here, per event, after the page is read. (The server-side fix — filter in SQL before
            # LIMIT — belongs to the ACP dashboard.)
            q = urllib.parse.urlencode({"since": since, "limit": self.page, "min_severity": "INFO", "kinds": self.kinds})
            try:
                status, body = self._transport("GET", f"{self.dashboard_url}/api/soc/events?{q}", None, headers, self.timeout)
            except Exception as e:  # the watermark holds; the cycle counts it as a source error
                self.last_error = f"{type(e).__name__}: {str(e)[:160]}"
                raise AcpFeedError(f"ACP events feed unreachable: {self.last_error}") from e
            if status != 200:
                # an outage or a 401 used to log a warning and return: the cycle looked clean while rogue, Q37 and
                # pause events stopped arriving (review E13). Raise so the service counts a failed source.
                self.last_error = f"HTTP {status}: {body[:160]}"
                raise AcpFeedError(f"ACP events feed refused: {self.last_error}")
            try:
                data = json.loads(body or "{}")
            except json.JSONDecodeError as e:
                self.last_error = f"bad JSON: {e}"; logger.warning("[ingest:acp] events feed returned non-JSON"); return
            events = data.get("events") or []
            for ev in events:
                if isinstance(ev, dict):
                    yield ev
                    # resumed: the base loop handled this event (yielded and marked its alert, or read it past as
                    # below the floor). The watermark is the last event READ, not the last alert yielded: below-floor
                    # events never moved it, so 20 pages of LOW rows were re-read from the same point every poll
                    # and a CRITICAL behind them was never reached (round 8 G8-9). A caller stopping on an alert
                    # never resumes here, so that alert's event is re-read next poll (at-least-once).
                    ts = ev.get("ts")
                    if ts:
                        self.checkpoint.advance(self.name, str(ts))
            nxt = str(data.get("next_since") or "")
            if not events or not nxt or nxt == since:
                return
            since = nxt

    # --------------------------------------------------------- normalize --
    def normalize(self, ev: dict) -> Optional[dict]:
        eid = str(ev.get("id") or "").strip()
        if not eid:
            return None
        kind = str(ev.get("kind") or "")
        sev = str(ev.get("severity") or "MEDIUM").lower()
        if _SEV_RANK.get(sev.upper(), 2) < _SEV_RANK.get(self.min_severity, 2):
            return CONSUMED                                # below the floor: read past, never an alert
        fw = str(ev.get("framework") or "").lower()
        agent = str(ev.get("agent_code") or ev.get("agent_id") or "")
        endpoint = str(ev.get("endpoint") or "")
        host = urllib.parse.urlparse(endpoint).hostname if endpoint.startswith(("http://", "https://")) else ""
        alert: dict[str, Any] = {
            "id": f"ACP-{eid.replace(':', '-')}",
            "source": f"ACP/{kind}",
            "severity": sev,
            "anomaly_score": severity_to_score(sev),
            "timestamp": str(ev.get("ts") or ""),
            "alert_type": kind,
            "agent_id": agent,
            "agent_name": str(ev.get("agent_name") or ""),
            "agent_framework": fw,
            "bu": str(ev.get("bu") or ""),
            "host": host or agent,                                  # seeds the endpoint walker
            "governed_agent": True,
            "agent_paused": bool(ev.get("paused")),
        }
        if kind == "rogue_alert":
            issue = str(ev.get("issue_type") or "")
            spec, tech = _ISSUE_HINTS.get(issue, ("edr", "T1059"))
            ctx = ev.get("context") if isinstance(ev.get("context"), dict) else {}
            alert.update({"issue_type": issue, "title": str(ev.get("title") or "")[:256], "description": str(ev.get("message") or "")[:2000],
                          "techniques": [tech], "suggested_specialist": spec, "context": ctx})
            for k in ("destination", "dest_ip", "url", "host", "source_ip", "user_id", "tool_name", "count", "window_min"):
                if ctx.get(k) is not None and k not in alert:
                    alert[k] = ctx[k] if isinstance(ctx[k], (str, int, float)) else json.dumps(ctx[k])[:500]
            alert["payload"] = f"{issue}: {alert['title']} — {alert['description'][:400]}"
        elif kind == "governance_block":
            code = str(ev.get("control_code") or "")
            spec, tech, ctl = _CONTROL_HINTS.get(code, ("api_abuse", "T1106", code or "governance control"))
            args = ev.get("args") if isinstance(ev.get("args"), dict) else {}
            alert.update({"control_code": code, "control": ctl, "tool_name": str(ev.get("tool_name") or ""), "reason": str(ev.get("reason") or "")[:1000],
                          "techniques": [tech], "suggested_specialist": spec, "blocked": True})
            for k in ("url", "host", "destination", "dest_ip", "method", "path"):
                if isinstance(args.get(k), str) and k not in alert:
                    alert[k] = args[k][:500]
            if code == "ACP-737":
                alert["title"] = "Governed agent attempted an infrastructure attack (blocked by Q37)"
            alert["payload"] = f"{ctl} blocked {alert['tool_name']}: {alert['reason'][:400]}"
        elif kind == "agent_paused":
            alert.update({"title": "Governed agent paused by the control plane", "reason": str(ev.get("reason") or "")[:1000],
                          "paused_by": str(ev.get("paused_by") or ""), "techniques": ["T1562.001"], "suggested_specialist": "edr"})
            alert["payload"] = f"agent paused ({alert['paused_by']}): {alert['reason'][:400]}"
        else:
            alert.update({"title": kind, "payload": json.dumps({k: v for k, v in ev.items() if k not in ("id",)})[:1000]})
        alert["note"] = f"{alert.get('title') or kind} — {agent or 'unknown agent'} ({fw or 'unknown framework'})"
        alert["raw"] = {k: v for k, v in ev.items() if k not in ("context", "args", "message")}
        return alert


__all__ = ["AcpFeedError", "AcpGovernanceConsumer"]
