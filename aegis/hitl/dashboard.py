"""HITL cards → ACP dashboard approvals, decisions → ResponseAgent (Phase 0.2).

Until now a high-impact action (``block``, ``isolate``, ``lock_account``,
...) printed an ``[HITL APPROVAL REQUEST]`` card to stdout and waited for
someone to call ``ResponseAgent.approve()`` by hand. This module routes the
card to the ACP dashboard's approvals queue — the same queue, page and
audit path the governed business agents use — and brings the human's
decision back:

    request()  POST /api/approvals/create   one card = one approval request
    sync()     GET  /api/approvals/{id}/status
    attach_investigation()  POST /api/approvals/{id}/context   async tier updates the card in place
               approved → ResponseAgent.approve(action, approver=<decider>)
               rejected → recorded, never executed

Every decision lands in the ACP audit chain on the dashboard side
(``HITL_APPROVAL_GRANTED`` / ``_REJECTED`` with the decider's email, role and
rationale — rbi #100). The evidence chain's integrity hash travels with
the request so the approver can tie the card to the exact chain.

Fail-safe: no dashboard (or an unreachable one) means ``request()`` returns
``None`` and the ResponseAgent falls back to the stdout card. A request is
never executed on a transport error, a malformed status, or an unknown
decision string.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Callable, Optional

from .base import BaseHITL, Decision, PendingApproval  # noqa: F401 — re-exported for callers

logger = logging.getLogger("aegis.hitl")

AGENT_NAME_DEFAULT = "aegis-soc-orchestrator"
BU_DEFAULT = "Security"
TIER_DEFAULT = "TIER_2"
_ARGS_TEXT_CAP = 600

#: transport(method, url, json_body, headers, timeout) -> dict (parsed JSON)
Transport = Callable[[str, str, Optional[dict], dict, float], dict]



def _httpx_transport(method: str, url: str, json_body: Optional[dict], headers: dict, timeout: float) -> dict:
    import httpx  # anthropic already depends on httpx, so it is always present

    resp = httpx.request(method, url, json=json_body, headers=headers, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    return data if isinstance(data, dict) else {"_raw": data}


def hitl_from_env(**overrides: Any) -> Optional[BaseHITL]:
    """The HITL transport for this deployment: ``AEGIS_HITL_TRANSPORT=dashboard|servicenow|file|stdout``.
    Unset → dashboard when ``ACP_DASHBOARD_URL`` is set, else ``None`` (the stdout card)."""
    transport = os.environ.get("AEGIS_HITL_TRANSPORT", "").strip().lower()
    url = os.environ.get("ACP_DASHBOARD_URL", "").strip()
    if not transport:
        transport = "dashboard" if url else "stdout"
    if transport == "dashboard":
        if not url:
            logger.warning("[hitl] AEGIS_HITL_TRANSPORT=dashboard but ACP_DASHBOARD_URL is unset; using the stdout card")
            return None
        return DashboardHITL(dashboard_url=url, **overrides)
    if transport == "servicenow":
        from .servicenow import ServiceNowHITL
        h = ServiceNowHITL(**overrides)
        if not h.enabled:
            logger.warning("[hitl] AEGIS_HITL_TRANSPORT=servicenow but AEGIS_SERVICENOW_URL is unset; using the stdout card")
            return None
        return h
    if transport == "file":
        from .filequeue import FileHITL
        return FileHITL(**overrides)
    if transport != "stdout":
        logger.warning("[hitl] unknown AEGIS_HITL_TRANSPORT=%r; using the stdout card", transport)
    return None


class DashboardHITL(BaseHITL):
    name = "dashboard"

    def __init__(
        self,
        dashboard_url: Optional[str] = None,
        api_key: Optional[str] = None,
        *,
        agent_name: Optional[str] = None,
        bu: Optional[str] = None,
        tier: str = TIER_DEFAULT,
        timeout: float = 5.0,
        transport: Optional[Transport] = None,
        state_path: Optional[str] = None,
    ):
        super().__init__(state_path=state_path)
        self.dashboard_url = (dashboard_url or os.environ.get("ACP_DASHBOARD_URL", "")).rstrip("/")
        self.api_key = api_key if api_key is not None else os.environ.get("ACP_API_KEY", "")
        self.agent_name = agent_name or os.environ.get("ACP_AGENT_NAME", AGENT_NAME_DEFAULT)
        self.bu = bu or os.environ.get("ACP_BU", BU_DEFAULT)
        self.tier = tier
        self.timeout = timeout
        self._transport: Transport = transport or _httpx_transport

    @property
    def enabled(self) -> bool:
        return bool(self.dashboard_url)

    # ---- transport hooks (bookkeeping lives in BaseHITL)
    def _file(self, card: dict) -> Optional[str]:
        payload = {"id": card["id"], "agent": self.agent_name, "bu": self.bu, "action": card["action"], "tier": self.tier, "args": card["args"]}
        data = self._transport("POST", f"{self.dashboard_url}/api/approvals/create", payload, self._headers(), self.timeout)
        if data.get("error"):
            raise RuntimeError(f"dashboard refused approval request: {str(data['error'])[:200]}")
        return str(data.get("approval_id") or card["id"])

    def _poll(self, p: PendingApproval) -> Optional[tuple[str, str, str]]:
        data = self.status(p.external_id or p.approval_id)
        if not isinstance(data, dict) or data.get("error"):
            # the dashboard answers some failures as 200 {"error": ...}: that is not "pending", so raise and let
            # sync() hold the approval (never fall through to the timeout auto-execute)
            raise RuntimeError(f"dashboard status for {p.approval_id} unreadable: "
                               f"{str((data or {}).get('error') if isinstance(data, dict) else data)[:160]}")
        st = str(data.get("status", "")).lower()
        if st == "approved":
            return "approved", str(data.get("decided_by") or "dashboard"), ""
        if st == "rejected":
            return "rejected", str(data.get("decided_by") or "dashboard"), str(data.get("reject_reason") or "")
        if st not in ("", "pending", "pending_hitl", "awaiting", "expired"):
            raise RuntimeError(f"dashboard status for {p.approval_id} is {st!r}, which this transport does not know")
        return None

    def _annotate(self, p: PendingApproval, card: dict) -> bool:
        data = self._transport("POST", f"{self.dashboard_url}/api/approvals/{p.external_id or p.approval_id}/context",
                               {"investigation": card}, self._headers(), self.timeout)
        if data.get("error"):
            logger.warning("[hitl] card update refused for %s: %s", p.approval_id, str(data["error"])[:160]); return False
        return True

    def status(self, approval_id: str) -> dict:
        return self._transport("GET", f"{self.dashboard_url}/api/approvals/{approval_id}/status",
                               None, self._headers(), self.timeout)

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["X-API-Key"] = self.api_key
        return h


__all__ = ["DashboardHITL", "Decision", "PendingApproval", "hitl_from_env"]
