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

_REOPEN_STATE = os.environ.get("AEGIS_SNOW_REOPEN_STATE", "2")      # incident: 2 = In Progress

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
        # ServiceNow accounts that are AEGIS itself: our own work-note PATCH makes us sys_updated_by, and that must
        # never count as a human approver (review round 4 R4-6). Learnt from our own writes as well.
        self._self_names: set[str] = {n.strip().lower() for n in
                                      (self.user, *os.environ.get("AEGIS_SERVICENOW_SELF", "").split(","))
                                      if n and n.strip()}
        # ServiceNow's own automation (business rules, SLA engine, scheduled jobs) writes as these: never a decider
        self._self_names |= {"system", "guest", "maint", "admin.system"}

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
        self._learn_self(rec)
        return str(rec.get("sys_id") or "") or None

    def _poll(self, p: PendingApproval) -> Optional[tuple[str, str, str]]:
        q = urllib.parse.urlencode({"sysparm_fields": "state,close_code,close_notes,u_aegis_decision,u_aegis_decided_by,resolved_by,closed_by,assigned_to,sys_updated_by",
                                    "sysparm_display_value": "true"})
        status, data = self._transport("GET", self._api(f"/{p.external_id}?{q}"), None, self._headers(), self.timeout)
        if status != 200:
            # an unreadable ticket is not "no decision yet": the analyst may have rejected it. Raise so sync()
            # holds the approval instead of letting the timeout policy auto-execute it.
            self.last_error = f"HTTP {status}"
            raise RuntimeError(f"ServiceNow poll for {p.external_id} returned HTTP {status}")
        rec = data.get("result") or {}
        decision = str(rec.get("u_aegis_decision") or "").strip().lower()
        who = self._decider(rec)
        if getattr(p, "first_approver", "") and who:
            # The SECOND approver must have made the decision themselves: the account that last wrote the record
            # AND the name typed in u_aegis_decided_by must be the same person. `sys_updated_by` alone is whoever
            # wrote last — a colleague's comment, an SLA business rule — and was read as a fresh approver of a
            # decision that never changed (review round 5 Y5-2). Unattributed = base waits.
            from .signing import same_person
            typed = _display(rec.get("u_aegis_decided_by")).strip()
            if not typed or not same_person(typed, who):
                who = ""
        if decision in ("approved", "rejected"):
            return decision, who, str(rec.get("close_notes") or "")[:500]
        if getattr(p, "first_approver", ""):
            # awaiting the second approver: only an explicit u_aegis_decision counts. The first approval may have
            # been given by resolving the ticket with an approve close code; that state stayed, and anyone who then
            # typed their own name into u_aegis_decided_by became the second approver without deciding anything
            # (review round 7 A-6).
            return None
        state = str(_display(rec.get("state")) or "").strip().lower()
        if state in _DECISION_STATES:
            code = str(_display(rec.get("close_code")) or "").strip().lower()
            # exact codes only: `"approv" in code` matched "Not Approved", "Unapproved", "Disapproved"
            if code in _approve_codes():
                return "approved", who, ""
            return "rejected", who, (str(rec.get("close_notes") or "") or f"closed with code '{code or 'none'}'")[:500]
        return None

    # the awaiting-second PATCH also re-opens the ticket (incident "In Progress") and clears the close code, so a
    # resolved-with-approve first approval does not read as a decision any more (review round 7 A-6)
    def _record_awaiting_second(self, p: PendingApproval, first: str) -> None:
        """Clear the decision fields so the second approval is a decision someone actually makes — the first one's
        `approved` stayed on the ticket and every later write to it looked like a new approval (Y5-2)."""
        note = (f"[AEGIS] First approval recorded from {first}. This action needs a second, different approver: set "
                "u_aegis_decision to 'approved' (or 'rejected') and u_aegis_decided_by to your own user id.")
        status, _data = self._transport("PATCH", self._api(f"/{p.external_id}"),
                                         {"u_aegis_decision": "", "u_aegis_decided_by": "", "state": _REOPEN_STATE,
                                          "close_code": "", "work_notes": note},
                                         self._headers(), self.timeout)
        if status not in (200, 204):
            logger.warning("[hitl:servicenow] could not reset the decision on %s after the first approval (HTTP %s); "
                           "the second approver is still required to name themselves", p.external_id, status)

    def _learn_self(self, rec: Any) -> None:
        if isinstance(rec, dict):
            for k in ("sys_created_by", "sys_updated_by"):
                v = _display(rec.get(k)).strip().lower()
                if v:
                    self._self_names.add(v)

    def _decider(self, rec: dict) -> str:
        """Who DECIDED, from what ServiceNow itself recorded: ``sys_updated_by`` (the authenticated account that last
        wrote the record), else resolved_by / closed_by. Never the assignee (review round 3 G1-7) and never the
        free-text ``u_aegis_decided_by`` alone: one user who typed another name there satisfied the two-person
        rule by himself (R4-6). The free-text name is used only when it IS the account that wrote the record.
        Our own writes (work notes) are not a decider. '' = unattributed: honoured, but never a second approver."""
        from .signing import same_person
        typed = _display(rec.get("u_aegis_decided_by")).strip()
        if "sys_updated_by" not in rec:
            # an instance (or proxy) that does not return the audit field at all: nothing better to go on
            return typed or _display(rec.get("resolved_by")) or _display(rec.get("closed_by"))
        actor = _display(rec.get("sys_updated_by")).strip()
        if actor.lower() in self._self_names:
            actor = ""
        if not actor:
            for k in ("resolved_by", "closed_by"):
                v = _display(rec.get(k)).strip()
                if v and v.lower() not in self._self_names:
                    actor = v
                    break
        if typed and actor and not same_person(typed, actor):
            logger.warning("[hitl:servicenow] u_aegis_decided_by says %r but the record was written by %r; using %r",
                           typed[:80], actor[:80], actor[:80])
        return actor

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
        status, data = self._transport("PATCH", self._api(f"/{p.external_id}"), {"work_notes": "\n".join(lines)[:4000]}, self._headers(), self.timeout)
        self._learn_self((data or {}).get("result") if isinstance(data, dict) else None)
        return status == 200


def _approve_codes() -> set[str]:
    """Close codes that mean "approved" (``AEGIS_SNOW_APPROVE_CODES``, comma-separated; default ``approved``).
    Anything else on a resolved/closed ticket is a rejection."""
    raw = os.environ.get("AEGIS_SNOW_APPROVE_CODES", "approved")
    return {c.strip().lower() for c in raw.split(",") if c.strip()}


def _display(v: Any) -> str:
    if isinstance(v, dict):
        return str(v.get("display_value") or v.get("value") or "")
    return str(v or "")


def _pct(v: Any) -> str:
    return "—" if v is None else f"{round(float(v) * 100)} %"


__all__ = ["ServiceNowHITL"]
