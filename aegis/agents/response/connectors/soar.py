"""SOAR connectors — Cortex XSOAR and Microsoft Sentinel playbooks (roadmap 1.2).

One connector reaches EDR / IAM / e-mail through the bank's *existing*
playbooks: a ``RecommendedAction`` whose type has a configured playbook
becomes one playbook run, with the action, target, alert id and chain hash
as inputs. Which action types are supported is exactly the configured map —
an unmapped action never reaches the vendor.

Playbook runs are one-shot: there is no TTL to extend (``default_ttl_sec=0``
→ permanent receipts) and no generic undo. Rollback runs the paired *undo*
playbook when one is configured (``isolate.undo=Release-Host``); otherwise
the rollback fails on purpose and the receipt says a human has to undo it.

API shapes (public documentation as of mid-2026; the mock implements these):

Cortex XSOAR (6.x / 8.x)
    POST {base}/incident
        headers  Authorization: <api key>   [x-xdr-auth-id: <key id>  — XSOAR 8]
        body     {"name", "type", "severity", "details", "playbookId", "createInvestigation": true,
                  "labels": [...], "customFields": {...}}
        →        {"id": "123", "name": …}
Microsoft Sentinel — playbook = Logic App with an HTTP trigger
    POST <trigger url of the playbook>   (the ``…/triggers/manual/paths/invoke?…sig=…`` URL)
        body     {"action", "target", "alert_id", "chain_hash", "approver", "source": "aegis"}
        →        202 Accepted, header x-ms-workflow-run-id
    (``runPlaybook`` on a Sentinel incident needs an incident id the alert may not have; the
    trigger URL works for every playbook the SOC already wires to HTTP.)
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

from .base import Connector, ConnectorError, Receipt
from .http import Transport, call, httpx_transport

logger = logging.getLogger("aegis.connectors.soar")

SEVERITY_BY_ACTION = {
    "isolate": 3, "kill_process": 3, "quarantine_file": 3, "rotate_credential": 3, "lock_account": 3,
    "revoke_sessions": 2, "force_logout": 2, "snapshot_forensic": 2, "block_export": 2, "block_egress": 2, "hold": 2,
    "escalate_to_fraud_team": 2, "escalate_to_hr": 2, "escalate": 1,
}


def parse_playbook_map(raw: str) -> dict[str, str]:
    """``"isolate=Isolate-Host,isolate.undo=Release-Host,lock_account=Disable-User"`` → dict."""
    out: dict[str, str] = {}
    for part in (raw or "").split(","):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            if k.strip() and v.strip():
                out[k.strip()] = v.strip()
    return out


class _PlaybookConnector(Connector):
    """Shared behaviour: supported actions = configured playbooks; undo via ``<action>.undo``."""

    def __init__(self, *, playbooks: dict[str, str], transport: Optional[Transport] = None,
                 default_ttl_sec: int = 0, **kw: Any):
        super().__init__(default_ttl_sec=default_ttl_sec, **kw)
        self.playbooks = dict(playbooks)
        self.actions = frozenset(k for k in self.playbooks if not k.endswith(".undo"))
        self._transport = transport or httpx_transport

    def _run(self, playbook: str, action: Any, key: str, *, undo_of: Optional[Receipt] = None) -> tuple[str, str]:
        raise NotImplementedError

    def _do_apply(self, action: Any, key: str, ttl_sec: Optional[int]) -> tuple[str, str, str]:
        playbook = self.playbooks.get(action.action_type)
        if not playbook:
            raise ConnectorError(f"no playbook configured for {action.action_type}")
        ref, detail = self._run(playbook, action, key)
        return ref, detail, ref

    def _do_rollback(self, receipt: Receipt) -> str:
        undo = self.playbooks.get(f"{receipt.action_type}.undo")
        if not undo:
            raise ConnectorError(f"{receipt.action_type} has no undo playbook — a human must reverse run {receipt.vendor_ref}")
        ref, detail = self._run(undo, _ActionView(receipt.action_type, receipt.target), receipt.idempotency_key,
                                undo_of=receipt)
        return f"{detail} (undo run {ref})"

    def _do_renew(self, receipt: Receipt, ttl_sec: int) -> str:
        return f"[{self.name}] run {receipt.vendor_ref} already executed; nothing to renew"


class _ActionView:
    def __init__(self, action_type: str, target: str):
        self.action_type, self.target = action_type, target
        self.reasoning, self.confidence = "", 0.0


class XsoarConnector(_PlaybookConnector):
    name = "xsoar"

    def __init__(self, *, base_url: str, api_key: str, auth_id: str = "", incident_type: str = "AEGIS Response",
                 **kw: Any):
        super().__init__(**kw)
        self.base_url = base_url.rstrip("/")
        self._headers = {"Authorization": api_key, "Content-Type": "application/json", "Accept": "application/json"}
        if auth_id:
            self._headers["x-xdr-auth-id"] = auth_id
        self.incident_type = incident_type

    def _run(self, playbook: str, action: Any, key: str, *, undo_of: Optional[Receipt] = None) -> tuple[str, str]:
        body = {
            "name": f"AEGIS {'undo ' if undo_of else ''}{action.action_type} {action.target}"[:200],
            "type": self.incident_type,
            "severity": SEVERITY_BY_ACTION.get(action.action_type, 1),
            "details": getattr(action, "reasoning", "") or f"aegis {action.action_type} on {action.target}",
            "playbookId": playbook,
            "createInvestigation": True,
            "labels": [{"type": "source", "value": "aegis"}, {"type": "action", "value": action.action_type},
                       {"type": "target", "value": str(action.target)[:200]}, {"type": "idempotency_key", "value": key}],
            "customFields": {"aegisaction": action.action_type, "aegistarget": str(action.target)[:200],
                             "aegisundoof": undo_of.vendor_ref if undo_of else ""},
        }
        res = call(self._transport, "POST", f"{self.base_url}/incident", json_body=body, headers=self._headers,
                   expect=(201,))
        incident_id = str(res.json().get("id") or "")
        if not incident_id:
            raise ConnectorError(f"XSOAR returned no incident id: {str(res.body)[:160]}")
        return incident_id, f"[xsoar] incident {incident_id} → playbook {playbook} ({action.action_type} {action.target})"


class SentinelPlaybookConnector(_PlaybookConnector):
    """Each configured playbook value is the Logic App HTTP-trigger URL."""

    name = "sentinel"

    def __init__(self, *, approver_header: str = "", **kw: Any):
        super().__init__(**kw)
        self.approver_header = approver_header

    def _run(self, playbook: str, action: Any, key: str, *, undo_of: Optional[Receipt] = None) -> tuple[str, str]:
        if not playbook.lower().startswith("https://"):
            raise ConnectorError(f"Sentinel playbook for {action.action_type} must be an https trigger URL")
        body = {"source": "aegis", "action": action.action_type, "target": str(action.target),
                "reason": getattr(action, "reasoning", ""), "idempotency_key": key,
                "undo_of": undo_of.vendor_ref if undo_of else ""}
        res = call(self._transport, "POST", playbook, json_body=body,
                   headers={"Content-Type": "application/json"}, expect=(202,))
        run_id = str(res.headers.get("x-ms-workflow-run-id") or res.headers.get("X-Ms-Workflow-Run-Id")
                     or res.json().get("run_id") or "")
        if not run_id:
            raise ConnectorError("Sentinel playbook accepted the call but returned no run id")
        return run_id, f"[sentinel] playbook run {run_id} ({action.action_type} {action.target})"


def soar_from_env(transport: Optional[Transport] = None) -> Optional[Connector]:
    """``AEGIS_SOAR_VENDOR=xsoar|sentinel|mock`` (default off); ``AEGIS_SOAR_PLAYBOOKS`` maps
    action types (and ``<action>.undo``) to playbook ids / trigger URLs."""
    vendor = os.environ.get("AEGIS_SOAR_VENDOR", "off").strip().lower()
    if vendor in ("", "off", "0", "none"):
        return None
    playbooks = parse_playbook_map(os.environ.get("AEGIS_SOAR_PLAYBOOKS", ""))
    if vendor == "mock":
        from .mock_vendor import MockXsoar
        playbooks = playbooks or {"isolate": "Isolate-Host", "isolate.undo": "Release-Host",
                                  "lock_account": "Disable-User", "lock_account.undo": "Enable-User",
                                  "revoke_sessions": "Revoke-Sessions", "kill_process": "Kill-Process",
                                  "quarantine_file": "Quarantine-File", "rotate_credential": "Rotate-Credential",
                                  "force_logout": "Force-Logout", "snapshot_forensic": "Snapshot-Forensic",
                                  "escalate_to_fraud_team": "Fraud-Escalation", "escalate_to_hr": "HR-Escalation"}
        return XsoarConnector(base_url="https://xsoar.mock", api_key="mock", playbooks=playbooks,
                              transport=transport or MockXsoar())
    if not playbooks:
        logger.warning("[soar] AEGIS_SOAR_VENDOR=%s needs AEGIS_SOAR_PLAYBOOKS (action=playbook,...)", vendor)
        return None
    if vendor == "xsoar":
        base, key = os.environ.get("AEGIS_SOAR_URL", ""), os.environ.get("AEGIS_SOAR_API_KEY", "")
        if not (base and key):
            logger.warning("[soar] AEGIS_SOAR_VENDOR=xsoar needs AEGIS_SOAR_URL and AEGIS_SOAR_API_KEY")
            return None
        return XsoarConnector(base_url=base, api_key=key, auth_id=os.environ.get("AEGIS_SOAR_AUTH_ID", ""),
                              incident_type=os.environ.get("AEGIS_SOAR_INCIDENT_TYPE", "AEGIS Response"),
                              playbooks=playbooks, transport=transport)
    if vendor == "sentinel":
        return SentinelPlaybookConnector(playbooks=playbooks, transport=transport)
    logger.warning("[soar] unknown AEGIS_SOAR_VENDOR=%r", vendor)
    return None
