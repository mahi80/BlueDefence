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
    one_shot_actions = frozenset({"kill_process"})     # a kill runs every time it is approved; nothing stays in force

    def __init__(self, *, base_url: str, token_provider: Callable[[], str],
                 transport: Optional[Transport] = None, **kw: Any):
        super().__init__(**kw)
        self.base_url = base_url.rstrip("/")
        self._token_provider = token_provider
        self._transport = transport or httpx_transport

    def supports_target(self, target: str) -> bool:
        # a host (name or Falcon device id); not a source fingerprint, not a bare IP
        t = str(target).strip()
        if t.lower().startswith(("agent:", "sandbox:")):
            return False                # an AI agent's sandbox, not a Falcon host (OpenShell quarantines it)
        return bool(t) and not is_fingerprint_target(t) and not _looks_like_ip(t.split(":", 1)[0])

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


class _HostEdr(Connector):
    """Shared shape of the host-containment EDRs: isolate (reversible) only, on a host name or device id."""

    reapply_on_human_approval = True
    actions = frozenset({"isolate"})

    def __init__(self, *, base_url: str, transport: Transport | None = None, **kw: Any):
        super().__init__(**kw)
        self.base_url = base_url.rstrip("/")
        self._transport = transport or httpx_transport

    def supports_target(self, target: str) -> bool:
        t = str(target).strip()
        if t.lower().startswith(("agent:", "sandbox:")):
            return False
        host = t[5:] if t.lower().startswith("host:") else t
        return bool(_HOSTNAME.match(host)) and not is_fingerprint_target(t) and not _looks_like_ip(host)

    @staticmethod
    def _host(target: str) -> str:
        t = str(target).strip()
        t = t[5:] if t.lower().startswith("host:") else t
        if not _HOSTNAME.match(t):
            raise ConnectorError(f"not a host name: {target!r}")
        return t

    def _do_renew(self, receipt: Receipt, ttl_sec: int) -> str:
        return f"[{self.name}] isolation of {receipt.target} still active"


_HOSTNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
_MDE_ID = re.compile(r"^[0-9a-f]{40}$")


class DefenderConnector(_HostEdr):
    """Microsoft Defender for Endpoint: full network isolation of a device, released on undo.

    API (api.securitycenter.microsoft.com, application permission ``Machine.Isolate`` + ``Machine.Read.All``)::

        resolve  GET  /api/machines?$filter=computerDnsName eq '<host>'        → value[0].id
        isolate  POST /api/machines/{id}/isolate    {"Comment", "IsolationType": "Full"}
        release  POST /api/machines/{id}/unisolate  {"Comment"}
        verify   GET  /api/machineactions?$filter=machineId eq '{id}'  → newest Isolate / Unisolate action
    """

    name = "defender"

    def __init__(self, *, token_provider: Callable[[], str], **kw: Any):
        super().__init__(**kw)
        self._token = token_provider

    def _h(self) -> dict:
        return {"Authorization": f"Bearer {self._token()}", "Content-Type": "application/json"}

    def _machine(self, target: str) -> str:
        host = self._host(target)
        if _MDE_ID.match(host):
            return host
        from urllib.parse import quote
        flt = quote(f"computerDnsName eq '{host.lower()}'", safe="")
        res = call(self._transport, "GET", f"{self.base_url}/api/machines?$filter={flt}", headers=self._h())
        rows = res.json().get("value") or []
        if not rows:
            # a short name: match the first DNS label (Defender stores the FQDN)
            flt = quote(f"startswith(computerDnsName,'{host.lower()}.')", safe="")
            res = call(self._transport, "GET", f"{self.base_url}/api/machines?$filter={flt}", headers=self._h())
            rows = res.json().get("value") or []
        if len(rows) != 1:
            raise ConnectorError(f"{len(rows)} Defender devices match {host!r}; give the device id or FQDN")
        return str(rows[0]["id"])

    def _do_apply(self, action: Any, key: str, ttl_sec: int | None) -> tuple[str, str, str]:
        mid = self._machine(action.target)
        # read before acting: a device someone else isolated is recorded as pre-existing, and AEGIS's undo then
        # leaves it isolated instead of releasing it (round 6 C-7)
        if self._isolated(mid) is True:
            note = f"[defender] {action.target} ({mid}) was already isolated; AEGIS's undo will not release it"
            return mid, note, f"pre-existing:{mid}"
        res = call(self._transport, "POST", f"{self.base_url}/api/machines/{mid}/isolate",
                   json_body={"Comment": f"AEGIS {key[:16]}: {str(getattr(action, 'reasoning', ''))[:200]}",
                              "IsolationType": "Full"}, headers=self._h(), expect=(200, 201, 400))
        if res.status == 400:
            if "already" not in str(res.body).lower():
                raise ConnectorError(f"Defender refused isolation: {str(res.body)[:200]}")
            note = f"[defender] an isolation of {action.target} ({mid}) was already in progress; AEGIS's undo will not release it"
            return mid, note, f"pre-existing:{mid}"
        return mid, f"[defender] isolated device {action.target} ({mid}); only Defender cloud traffic is allowed", mid

    def _do_rollback(self, receipt: Receipt) -> str:
        if receipt.rollback_token.startswith("pre-existing"):
            return f"[defender] {receipt.target} was isolated before AEGIS acted; left isolated"
        mid = receipt.vendor_ref or self._machine(receipt.target)
        call(self._transport, "POST", f"{self.base_url}/api/machines/{mid}/unisolate",
             json_body={"Comment": f"AEGIS release of {receipt.receipt_id}"}, headers=self._h(), expect=(200, 201))
        return f"[defender] released isolation of {receipt.target}"

    def _do_verify(self, receipt: Receipt) -> bool | None:
        return self._isolated(receipt.vendor_ref)

    def _isolated(self, mid: str) -> bool | None:
        from urllib.parse import quote
        flt = quote(f"machineId eq '{mid}'", safe="")
        res = call(self._transport, "GET", f"{self.base_url}/api/machineactions?$filter={flt}", headers=self._h())
        acts = [a for a in (res.json().get("value") or []) if isinstance(a, dict)
                and a.get("type") in ("Isolate", "Unisolate") and a.get("status") not in ("Failed", "Cancelled", "TimeOut")]
        if not acts:
            return None
        newest = max(acts, key=lambda a: str(a.get("creationDateTimeUtc") or ""))
        return newest.get("type") == "Isolate"


class SentinelOneConnector(_HostEdr):
    """SentinelOne: disconnect an agent from the network, reconnect on undo.

    API (``{console}/web/api/v2.1``, ``Authorization: ApiToken <token>``)::

        resolve     GET  /agents?computerName=<host>                         → data[].id
        disconnect  POST /agents/actions/disconnect  {"filter": {"ids": [id]}}  → data.affected
        connect     POST /agents/actions/connect     {"filter": {"ids": [id]}}
        verify      GET  /agents?ids=<id>  → networkStatus disconnected / disconnecting
    """

    name = "sentinelone"

    def __init__(self, *, api_token: str, **kw: Any):
        super().__init__(**kw)
        self._tok = api_token

    def _h(self) -> dict:
        return {"Authorization": f"ApiToken {self._tok}", "Content-Type": "application/json"}

    def _agent(self, target: str) -> str:
        from urllib.parse import urlencode
        host = self._host(target)
        if host.isdigit():
            return host
        res = call(self._transport, "GET", f"{self.base_url}/web/api/v2.1/agents?{urlencode({'computerName': host})}",
                   headers=self._h())
        rows = res.json().get("data") or []
        if len(rows) != 1:
            raise ConnectorError(f"{len(rows)} SentinelOne agents named {host!r}; give the agent id")
        return str(rows[0]["id"])

    def _act(self, aid: str, what: str) -> int:
        res = call(self._transport, "POST", f"{self.base_url}/web/api/v2.1/agents/actions/{what}",
                   json_body={"filter": {"ids": [aid]}}, headers=self._h())
        return int((res.json().get("data") or {}).get("affected") or 0)

    def _do_apply(self, action: Any, key: str, ttl_sec: int | None) -> tuple[str, str, str]:
        aid = self._agent(action.target)
        if self._disconnected(aid) is True:                         # someone else's isolation: not ours to undo (C-7)
            note = f"[sentinelone] {action.target} (agent {aid}) was already disconnected; AEGIS's undo will not reconnect it"
            return aid, note, "pre-existing"
        if self._act(aid, "disconnect") < 1:
            raise ConnectorError(f"SentinelOne disconnected no agent for {action.target}")
        return aid, f"[sentinelone] disconnected {action.target} (agent {aid}) from the network", aid

    def _do_rollback(self, receipt: Receipt) -> str:
        if receipt.rollback_token == "pre-existing":
            return f"[sentinelone] {receipt.target} was disconnected before AEGIS acted; left disconnected"
        self._act(receipt.vendor_ref or self._agent(receipt.target), "connect")
        return f"[sentinelone] reconnected {receipt.target}"

    def _do_verify(self, receipt: Receipt) -> bool | None:
        return self._disconnected(receipt.vendor_ref)

    def _disconnected(self, aid: str) -> bool | None:
        res = call(self._transport, "GET", f"{self.base_url}/web/api/v2.1/agents?ids={aid}", headers=self._h())
        rows = res.json().get("data") or []
        if not rows:
            return None
        return str(rows[0].get("networkStatus") or "").lower() in ("disconnected", "disconnecting")


class TrendVisionOneConnector(_HostEdr):
    """Trend Vision One (Apex One / Server & Workload Protection agents): isolate an endpoint, restore on undo.

    API v3.0 (regional base, e.g. ``https://api.in.xdr.trendmicro.com`` for India; ``Authorization: Bearer``)::

        resolve  GET  /v3.0/endpointSecurity/endpoints    header TMV1-Query: endpointName eq '<host>'  → items[].agentGuid
        isolate  POST /v3.0/response/endpoints/isolate    [{"agentGuid", "description"}]  → 207, Operation-Location
        restore  POST /v3.0/response/endpoints/restore    [{"agentGuid", "description"}]
        task     GET  /v3.0/response/tasks/{id}           status succeeded / failed / running

    The read-back can only report a FAILED isolation task (False). A succeeded task does not say the endpoint is still
    isolated now — a restore in the Trend console would not show — so otherwise it reports "not verifiable" (None)
    rather than a "verified" that never changes (round 6 C-10). For the same reason AEGIS cannot see an isolation
    someone else placed before it acted; its undo restores the endpoint.
    """

    name = "trend"

    def __init__(self, *, token: str, **kw: Any):
        super().__init__(**kw)
        self._tok = token

    def _h(self, **extra: str) -> dict:
        return {"Authorization": f"Bearer {self._tok}", "Content-Type": "application/json;charset=utf-8", **extra}

    def _guid(self, target: str) -> str:
        host = self._host(target)
        if re.fullmatch(r"[0-9a-fA-F-]{36}", host):
            return host
        res = call(self._transport, "GET", f"{self.base_url}/v3.0/endpointSecurity/endpoints",
                   headers=self._h(**{"TMV1-Query": f"endpointName eq '{host}'"}))
        rows = res.json().get("items") or []
        if len(rows) != 1:
            raise ConnectorError(f"{len(rows)} Trend endpoints named {host!r}; give the agent GUID")
        return str(rows[0]["agentGuid"])

    def _act(self, guid: str, what: str, note: str) -> str:
        res = call(self._transport, "POST", f"{self.base_url}/v3.0/response/endpoints/{what}",
                   json_body=[{"agentGuid": guid, "description": note[:256]}], headers=self._h(), expect=(200, 202, 207))
        items = res.body if isinstance(res.body, list) else []
        first = items[0] if items and isinstance(items[0], dict) else {}
        if int(first.get("status") or 202) >= 400:
            raise ConnectorError(f"Trend refused {what}: {str(first)[:200]}")
        loc = next((h.get("value") for h in first.get("headers") or [] if str(h.get("name", "")).lower() == "operation-location"), "")
        return str(loc or "").rsplit("/", 1)[-1]

    def _do_apply(self, action: Any, key: str, ttl_sec: int | None) -> tuple[str, str, str]:
        guid = self._guid(action.target)
        task = self._act(guid, "isolate", f"AEGIS {key[:16]}: {getattr(action, 'reasoning', '')!s}")
        return f"{guid}#{task}", f"[trend] isolation of {action.target} (agent {guid}) requested, task {task or '?'}", guid

    def _do_rollback(self, receipt: Receipt) -> str:
        guid = receipt.rollback_token or self._guid(receipt.target)
        self._act(guid, "restore", f"AEGIS release of {receipt.receipt_id}")
        return f"[trend] restore of {receipt.target} requested"

    def _do_verify(self, receipt: Receipt) -> bool | None:
        task = (receipt.vendor_ref or "").partition("#")[2]
        if not task:
            return None
        res = call(self._transport, "GET", f"{self.base_url}/v3.0/response/tasks/{task}", headers=self._h())
        st = str(res.json().get("status") or "").lower()
        return False if st in ("failed", "rejected", "canceled", "cancelled") else None


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
    """``AEGIS_EDR_VENDOR = crowdstrike | defender | sentinelone | mock | mock-defender | mock-sentinelone`` (default
    off). CrowdStrike: ``AEGIS_EDR_CLIENT_ID`` + ``AEGIS_EDR_CLIENT_SECRET`` (``AEGIS_EDR_URL`` defaults to US-1).
    Defender: ``AEGIS_EDR_TENANT_ID`` + ``AEGIS_EDR_CLIENT_ID`` + ``AEGIS_EDR_CLIENT_SECRET`` (or a managed identity).
    SentinelOne: ``AEGIS_EDR_URL`` (console) + ``AEGIS_EDR_TOKEN``. Trend Vision One: ``AEGIS_EDR_URL`` (regional API
    base) + ``AEGIS_EDR_TOKEN``."""
    vendor = os.environ.get("AEGIS_EDR_VENDOR", "off").strip().lower()
    if vendor in ("", "off", "0", "none"):
        return None
    if vendor == "mock-defender":
        from .mock_bank import MockDefender
        return DefenderConnector(base_url="https://mde.mock", token_provider=lambda: "mock-mde-token",
                                 transport=transport or MockDefender())
    if vendor == "mock-sentinelone":
        from .mock_bank import MockSentinelOne
        return SentinelOneConnector(base_url="https://s1.mock", api_token="mock-s1-token",
                                    transport=transport or MockSentinelOne())
    if vendor == "mock-trend":
        from .mock_bank import MockTrend
        return TrendVisionOneConnector(base_url="https://trend.mock", token="mock-trend-token",
                                       transport=transport or MockTrend())
    if vendor in ("trend", "visionone", "trendmicro"):
        base, tok = os.environ.get("AEGIS_EDR_URL", "").strip(), os.environ.get("AEGIS_EDR_TOKEN", "")
        if not (base.startswith("https://") and tok):
            logger.warning("[edr] trend needs AEGIS_EDR_URL (regional https API base) and AEGIS_EDR_TOKEN")
            return None
        return TrendVisionOneConnector(base_url=base, token=tok, transport=transport)
    if vendor in ("defender", "mde"):
        from .cloud_auth import AzureToken
        tok = AzureToken(tenant_id=os.environ.get("AEGIS_EDR_TENANT_ID", ""), client_id=os.environ.get("AEGIS_EDR_CLIENT_ID", ""),
                         client_secret=os.environ.get("AEGIS_EDR_CLIENT_SECRET", ""), transport=transport,
                         scope="https://api.securitycenter.microsoft.com/.default")
        return DefenderConnector(base_url=os.environ.get("AEGIS_EDR_URL", "https://api.securitycenter.microsoft.com"),
                                 token_provider=tok, transport=transport)
    if vendor in ("sentinelone", "s1"):
        base, tok = os.environ.get("AEGIS_EDR_URL", "").strip(), os.environ.get("AEGIS_EDR_TOKEN", "")
        if not (base.startswith("https://") and tok):
            logger.warning("[edr] sentinelone needs AEGIS_EDR_URL (https console) and AEGIS_EDR_TOKEN")
            return None
        return SentinelOneConnector(base_url=base, api_token=tok, transport=transport)
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
