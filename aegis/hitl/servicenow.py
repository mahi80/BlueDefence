"""HITL over ServiceNow (Table API) — approvals without the ACP dashboard (AEGIS External edition).

One approval = one ``incident`` (or the table in ``AEGIS_SERVICENOW_TABLE``). The analyst decides
in ServiceNow; we read the decision back from ``u_aegis_decision`` (``approved`` / ``rejected``) —
a custom field the bank adds — or, when that field is empty, from the record's state
(Resolved/Closed + ``close_code``). The investigation (blast radius / plan) lands in ``work_notes``.

    AEGIS_HITL_TRANSPORT=servicenow
    AEGIS_SERVICENOW_URL=https://<instance>.service-now.com
    AEGIS_SERVICENOW_USER / AEGIS_SERVICENOW_PASS   (basic)  or  AEGIS_SERVICENOW_TOKEN (bearer)
    AEGIS_SERVICENOW_TABLE=incident   AEGIS_SERVICENOW_ASSIGNMENT_GROUP=<sys_id or name>

Built against the public Table API shape; ``transport`` is injectable (tests, mock tenants).
"""

from __future__ import annotations

import base64
import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Optional

from .base import BaseHITL, PendingApproval

logger = logging.getLogger("aegis.hitl.servicenow")

Transport = Callable[[str, str, Optional[dict], dict, float], tuple[int, dict]]

_URGENCY = {"malicious": "1", "suspicious": "2", "uncertain": "2", "benign": "3"}
_DECISION_STATES = {"6": "resolved", "7": "closed", "resolved": "resolved", "closed": "closed"}


def _urllib_transport(method: str, url: str, body: Optional[dict], headers: dict, timeout: float) -> tuple[int, dict]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — the bank's own instance
            return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8") or "{}")
        except Exception:  # noqa: BLE001
            return e.code, {}


class ServiceNowHITL(BaseHITL):
    name = "servicenow"

    def __init__(self, url: Optional[str] = None, *, user: Optional[str] = None, password: Optional[str] = None,
                 token: Optional[str] = None, table: Optional[str] = None, assignment_group: Optional[str] = None,
                 transport: Optional[Transport] = None, timeout: float = 10.0, state_path: Optional[str] = None):
        super().__init__(state_path=state_path)
        self.url = (url or os.environ.get("AEGIS_SERVICENOW_URL", "")).rstrip("/")
        self.user = user if user is not None else os.environ.get("AEGIS_SERVICENOW_USER", "")
        self.password = password if password is not None else os.environ.get("AEGIS_SERVICENOW_PASS", "")
        self.token = token if token is not None else os.environ.get("AEGIS_SERVICENOW_TOKEN", "")
        self.table = table or os.environ.get("AEGIS_SERVICENOW_TABLE", "incident")
        self.assignment_group = assignment_group or os.environ.get("AEGIS_SERVICENOW_ASSIGNMENT_GROUP", "")
        self._transport: Transport = transport or _urllib_transport
        self.timeout = timeout
        self.last_error = ""

    @property
    def enabled(self) -> bool:
        return bool(self.url)

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        elif self.user:
            h["Authorization"] = "Basic " + base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        return h

    def _api(self, path: str = "") -> str:
        return f"{self.url}/api/now/table/{self.table}{path}"

    # ---- hooks
    def _file(self, card: dict) -> Optional[str]:
        a = card["args"]
        desc = (f"AEGIS approval {card['id']}\nAlert: {a['alert_id']}\nAction: {card['action']}\n"
                f"Verdict: {a['verdict']} (chain confidence {a['chain_confidence']}, action confidence {a['action_confidence']})\n"
                f"Investigated by: {a['investigated_by']}; specialists: {', '.join(a['specialists'])}; evidence items: {a['evidence_count']}\n"
                f"Why: {a['reasoning']}\n"
                f"Integrity hash: {a['integrity_hash']}\n\n"
                f"To decide: set u_aegis_decision to 'approved' or 'rejected' (or resolve the record with that close code).")
        body = {"short_description": f"[AEGIS] {card['action']} — alert {a['alert_id']} ({a['verdict']})"[:160],
                "description": desc, "urgency": _URGENCY.get(a["verdict"], "2"), "impact": _URGENCY.get(a["verdict"], "2"),
                "category": "security", "u_aegis_approval_id": card["id"], "correlation_id": card["id"]}
        if self.assignment_group:
            body["assignment_group"] = self.assignment_group
        status, data = self._transport("POST", self._api(), body, self._headers(), self.timeout)
        if status not in (200, 201):
            self.last_error = f"HTTP {status}: {json.dumps(data)[:160]}"
            raise RuntimeError(f"ServiceNow refused the incident: {self.last_error}")
        rec = data.get("result") or {}
        return str(rec.get("sys_id") or "") or None

    def _poll(self, p: PendingApproval) -> Optional[tuple[str, str, str]]:
        q = urllib.parse.urlencode({"sysparm_fields": "state,close_code,close_notes,u_aegis_decision,u_aegis_decided_by,resolved_by,closed_by,assigned_to",
                                    "sysparm_display_value": "true"})
        status, data = self._transport("GET", self._api(f"/{p.external_id}?{q}"), None, self._headers(), self.timeout)
        if status != 200:
            self.last_error = f"HTTP {status}"; return None
        rec = data.get("result") or {}
        decision = str(rec.get("u_aegis_decision") or "").strip().lower()
        who = _display(rec.get("u_aegis_decided_by")) or _display(rec.get("resolved_by")) or _display(rec.get("closed_by")) or _display(rec.get("assigned_to"))
        if decision in ("approved", "rejected"):
            return decision, who, str(rec.get("close_notes") or "")[:500]
        state = str(_display(rec.get("state")) or "").strip().lower()
        if state in _DECISION_STATES:
            code = str(_display(rec.get("close_code")) or "").strip().lower()
            if "approv" in code:
                return "approved", who, ""
            return "rejected", who, (str(rec.get("close_notes") or "") or f"closed with code '{code or 'none'}'")[:500]
        return None

    def _annotate(self, p: PendingApproval, card: dict) -> bool:
        br, plan, twin = card.get("blast_radius") or {}, card.get("plan") or {}, card.get("twin") or {}
        lines = ["[AEGIS investigation]"]
        if br:
            lines.append(f"Blast radius: {br.get('nodes_reached', 0)} nodes, critical reached: {', '.join(c['id'] for c in br.get('critical', [])) or 'none'}")
        for st in plan.get("steps", [])[:6]:
            lines.append(f"  step {st.get('n')}: {st.get('action')} -> {st.get('target')} ({'HITL' if st.get('hitl') else 'auto-safe'}) — {st.get('why', '')}")
        if twin and not twin.get("skipped"):
            lines.append(f"Twin: exposure {_pct(twin.get('exposure'))}, with plan {_pct(twin.get('with_plan'))}, plan stops {_pct(twin.get('plan_effectiveness'))}")
        for c in card.get("containment") or []:
            lines.append(f"Containment #{c.get('step')}: {c.get('action')} -> {c.get('target')}: critical {c.get('before')} -> {c.get('after')}")
        status, _ = self._transport("PATCH", self._api(f"/{p.external_id}"), {"work_notes": "\n".join(lines)[:4000]}, self._headers(), self.timeout)
        return status == 200


def _display(v: Any) -> str:
    if isinstance(v, dict):
        return str(v.get("display_value") or v.get("value") or "")
    return str(v or "")


def _pct(v: Any) -> str:
    return "—" if v is None else f"{round(float(v) * 100)} %"


__all__ = ["ServiceNowHITL"]
