"""EDR connector — CrowdStrike Falcon host containment + process kill (roadmap 1.3).

Backs ``isolate`` (network-contain a host) and ``kill_process`` — both stay
**HITL** (never in auto-block scope; the autonomy policy only ever auto-fires a
``block``). Containment is reversible: rollback lifts it. A kill is one-shot and
cannot be undone, so its receipt is permanent and rollback refuses with a note.

Where the bank already has a Falcon playbook in XSOAR/Sentinel, the SOAR
connector (1.2) handles ``isolate`` and this direct connector never routes —
the registry prefers the SOAR connector when it has the playbook. This is the
"direct connector only where no playbook exists" path.

API shapes (CrowdStrike Falcon, public docs mid-2026):

    OAuth2   POST {base}/oauth2/token   (form: client_id, client_secret) → {access_token, expires_in}
    resolve  GET  {base}/devices/queries/devices/v1?filter=hostname:'<h>'  → {resources:[aid]}
    contain  POST {base}/devices/entities/devices-actions/v2?action_name=contain   {"ids":[aid]}
    lift     POST {base}/devices/entities/devices-actions/v2?action_name=lift_containment   {"ids":[aid]}
    kill     RTR: POST {base}/real-time-response/combined/batch-init-session/v1 {"host_ids":[aid]} → batch_id
             POST {base}/real-time-response/combined/batch-command/v1
                  {"batch_id","base_command":"kill","command_string":"kill <pid>","optional_hosts":[aid]}

Mock tenant: ``mock_vendor.MockCrowdStrike`` (``AEGIS_EDR_VENDOR=mock``).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import time
from typing import Any, Callable, Optional

from ...shared.fingerprint import is_fingerprint_target
from .base import CannotUndo, Connector, ConnectorError, Receipt
from .http import RawBody, Transport, call, httpx_transport

logger = logging.getLogger("aegis.connectors.edr")

_AID = re.compile(r"^[0-9a-f]{32}$")


def _looks_like_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(str(target).split("/", 1)[0])
        return True
    except ValueError:
        return False


class CrowdStrikeConnector(Connector):
    """CrowdStrike Falcon: contain/lift a host, RTR-kill a process."""

    name = "crowdstrike"
    reapply_on_human_approval = True
    actions = frozenset({"isolate", "kill_process"})

    def __init__(self, *, base_url: str, token_provider: Callable[[], str],
                 transport: Optional[Transport] = None, **kw: Any):
        super().__init__(**kw)
        self.base_url = base_url.rstrip("/")
        self._token_provider = token_provider
        self._transport = transport or httpx_transport

    def supports_target(self, target: str) -> bool:
        # a host (name or Falcon device id); not a source fingerprint, not a bare IP
        t = str(target).strip()
        return bool(t) and not is_fingerprint_target(t) and not _looks_like_ip(t.split(":", 1)[0])

    def apply(self, action: Any, **kw: Any) -> Receipt:
        if action.action_type == "kill_process":
            kw["ttl_sec"] = 0          # a kill is one-shot: permanent receipt, no TTL auto-rollback
        return super().apply(action, **kw)

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._token_provider()}",
                "Content-Type": "application/json", "Accept": "application/json"}

    def _device_id(self, target: str) -> str:
        t = str(target).strip()
        if t.lower().startswith("host:"):
            t = t[5:]
        if _AID.match(t):
            return t                    # already a Falcon device id (aid)
        res = call(self._transport, "GET",
                   f"{self.base_url}/devices/queries/devices/v1?filter=hostname:'{t}'",
                   headers=self._headers(), expect=(200,))
        ids = res.json().get("resources") or []
        if not ids:
            raise ConnectorError(f"no CrowdStrike device for hostname {t!r}")
        return str(ids[0])

    def _device_action(self, device_id: str, action_name: str) -> Any:
        url = f"{self.base_url}/devices/entities/devices-actions/v2?action_name={action_name}"
        return call(self._transport, "POST", url, json_body={"ids": [device_id]},
                    headers=self._headers(), expect=(200, 202))

    def _kill(self, action: Any) -> tuple[str, str, str]:
        host, _, pid = str(action.target).partition(":")
        if not pid.isdigit():
            raise ConnectorError("kill_process target must be '<host-or-device-id>:<pid>'")
        did = self._device_id(host)
        init = call(self._transport, "POST", f"{self.base_url}/real-time-response/combined/batch-init-session/v1",
                    json_body={"host_ids": [did]}, headers=self._headers(), expect=(200, 201))
        batch_id = str(init.json().get("batch_id") or "")
        if not batch_id:
            raise ConnectorError("CrowdStrike RTR returned no batch_id")
        call(self._transport, "POST", f"{self.base_url}/real-time-response/combined/batch-command/v1",
             json_body={"batch_id": batch_id, "base_command": "kill", "command_string": f"kill {pid}",
                        "optional_hosts": [did]}, headers=self._headers(), expect=(200, 201))
        return f"{did}:{pid}", f"[crowdstrike] RTR kill pid {pid} on {host} (batch {batch_id})", ""

    def _do_apply(self, action: Any, key: str, ttl_sec: Optional[int]) -> tuple[str, str, str]:
        if action.action_type == "isolate":
            did = self._device_id(action.target)
            self._device_action(did, "contain")
            return did, f"[crowdstrike] contained host {action.target} (device {did})", did
        if action.action_type == "kill_process":
            return self._kill(action)
        raise ConnectorError(f"crowdstrike does not support {action.action_type}")

    def _do_rollback(self, receipt: Receipt) -> str:
        if receipt.action_type == "isolate":
            self._device_action(receipt.vendor_ref or self._device_id(receipt.target), "lift_containment")
            return f"[crowdstrike] lifted containment on {receipt.target}"
        raise CannotUndo("kill_process cannot be undone — a killed process cannot be restored "
                             "(snapshot_forensic first if evidence is needed)")

    def _do_verify(self, receipt: Receipt) -> bool | None:
        if receipt.action_type != "isolate" or not receipt.vendor_ref:
            return None                              # a kill is one-shot: nothing stays in force to read back
        res = call(self._transport, "GET", f"{self.base_url}/devices/entities/devices/v2?ids={receipt.vendor_ref}",
                   headers=self._headers(), expect=(200,))
        devs = res.json().get("resources") or []
        if not devs:
            return None
        return str(devs[0].get("status") or "").lower() in ("contained", "containment_pending")

    def _do_renew(self, receipt: Receipt, ttl_sec: int) -> str:
        if receipt.action_type == "isolate":
            return f"[crowdstrike] containment on {receipt.target} still active"
        return f"[crowdstrike] RTR kill {receipt.vendor_ref} already executed; nothing to renew"


class _FalconToken:
    """OAuth2 client-credentials token with in-process caching (refetch near expiry)."""

    def __init__(self, base_url: str, client_id: str, client_secret: str,
                 transport: Optional[Transport], clock: Callable[[], float] = time.time):
        self.base_url = base_url.rstrip("/")
        self._id, self._secret = client_id, client_secret
        self._transport = transport or httpx_transport
        self._clock = clock
        self._token = ""
        self._exp = 0.0

    def __call__(self) -> str:
        now = self._clock()
        if self._token and now < self._exp - 60:
            return self._token
        from urllib.parse import urlencode
        body = RawBody(urlencode({"client_id": self._id, "client_secret": self._secret}).encode())
        res = call(self._transport, "POST", f"{self.base_url}/oauth2/token", json_body=body,
                   headers={"Content-Type": "application/x-www-form-urlencoded"}, expect=(200, 201))
        tok = str(res.json().get("access_token") or "")
        if not tok:
            raise ConnectorError("CrowdStrike OAuth returned no access_token")
        self._token = tok
        self._exp = now + float(res.json().get("expires_in") or 1799)
        return tok


def crowdstrike_from_env(transport: Optional[Transport] = None) -> Optional[Connector]:
    """``AEGIS_EDR_VENDOR=crowdstrike|mock`` (default off). Live needs ``AEGIS_EDR_CLIENT_ID`` +
    ``AEGIS_EDR_CLIENT_SECRET`` (``AEGIS_EDR_URL`` defaults to the US-1 cloud)."""
    vendor = os.environ.get("AEGIS_EDR_VENDOR", "off").strip().lower()
    if vendor in ("", "off", "0", "none"):
        return None
    if vendor == "mock":
        from .mock_vendor import MockCrowdStrike
        return CrowdStrikeConnector(base_url="https://api.crowdstrike.mock",
                                    token_provider=lambda: "mock-cs-token",
                                    transport=transport or MockCrowdStrike())
    if vendor in ("crowdstrike", "falcon"):
        base = os.environ.get("AEGIS_EDR_URL", "https://api.crowdstrike.com")
        cid, sec = os.environ.get("AEGIS_EDR_CLIENT_ID", ""), os.environ.get("AEGIS_EDR_CLIENT_SECRET", "")
        if not (cid and sec):
            logger.warning("[edr] crowdstrike needs AEGIS_EDR_CLIENT_ID and AEGIS_EDR_CLIENT_SECRET")
            return None
        return CrowdStrikeConnector(base_url=base, token_provider=_FalconToken(base, cid, sec, transport),
                                    transport=transport)
    logger.warning("[edr] unknown AEGIS_EDR_VENDOR=%r", vendor)
    return None
