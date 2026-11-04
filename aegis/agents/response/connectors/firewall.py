"""Next-generation firewall connectors — Palo Alto PAN-OS and Fortinet FortiGate (integration plan #5).

Backs ``block`` (an attacking source IP) and ``block_egress`` (a destination IP a compromised host or agent is
talking to) on the bank's own perimeter / internal-segment firewalls — where most Indian banks enforce, instead of
a cloud WAF. One IP per action (never a CIDR: a firewall-wide range block is a change-window job); the never-block
guard still refuses loopback / reserved / operator-listed space before either connector is called.

Both use a timed, native mechanism, so a block the TTL sweep never reaches still lapses on the firewall itself:

**PAN-OS** — tag the IP in a Dynamic Address Group (User-ID ``register`` with a tag timeout). The security team
wires two DAGs once (``tag = aegis-block-src`` → deny from, ``aegis-block-dst`` → deny to); AEGIS never edits a
rule or commits config. ::

    POST {base}/api/   form: type=user-id, cmd=<uid-message> … <register><entry ip=…><tag>
                                <member timeout="ttl">aegis-block-src</member></tag></entry></register> …
    undo                   the same with <unregister>
    read-back  type=op, cmd=<show><object><registered-ip><ip>…</ip></registered-ip></object></show>
    auth       X-PAN-KEY: <API key of a role limited to User-ID + operational show>

**FortiGate** — the quarantine ("banned users") list, with an expiry. ::

    POST {base}/api/v2/monitor/user/banned/add_users     {"ip_addresses": [ip], "expiry": ttl}
    POST {base}/api/v2/monitor/user/banned/clear_users   {"ip_addresses": [ip]}
    GET  {base}/api/v2/monitor/user/banned               → results[].ipv4_address / ipv6_address
    auth Authorization: Bearer <REST API admin token>; ``?vdom=`` when ``AEGIS_FW_VDOM`` is set

Mock tenants: ``mock_bank.MockPanos`` / ``MockFortiGate`` (``AEGIS_FW_VENDOR=mock-panos | mock-fortigate``).
A firewall with a private CA: point ``SSL_CERT_FILE`` at the bank's CA bundle.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from typing import Any
from urllib.parse import urlencode
from xml.sax.saxutils import quoteattr

from .base import Connector, ConnectorError, Receipt
from .http import RawBody, Transport, call, httpx_transport

logger = logging.getLogger("aegis.connectors.firewall")

_MAX_PANOS_TIMEOUT = 2_592_000            # PAN-OS tag timeout ceiling (30 days)
_TAG_RX = re.compile(r"^[A-Za-z0-9_.-]{1,127}$")


def _ip(target: str) -> str:
    t = str(target).strip()
    for p in ("ip:", "src:", "dst:", "outbound:"):
        if t.lower().startswith(p):
            t = t[len(p):].strip()
    try:
        return str(ipaddress.ip_address(t.strip("[]")))
    except ValueError:
        raise ConnectorError(f"firewall block needs one IP address, got {target!r}") from None


def _is_ip(target: str) -> bool:
    try:
        _ip(target)
        return True
    except ConnectorError:
        return False


class _Firewall(Connector):
    actions = frozenset({"block", "block_egress"})
    reapply_on_human_approval = True          # re-registering / re-banning is idempotent and refreshes the timer

    def __init__(self, *, base_url: str, transport: Transport | None = None, **kw: Any):
        super().__init__(**kw)
        self.base_url = base_url.rstrip("/")
        self._transport = transport or httpx_transport

    def supports_target(self, target: str) -> bool:
        return _is_ip(target)


class PanosConnector(_Firewall):
    """Palo Alto PAN-OS: tag the IP into a Dynamic Address Group with a timeout."""

    name = "panos"

    def __init__(self, *, api_key: str, tag_src: str = "aegis-block-src", tag_dst: str = "aegis-block-dst", **kw: Any):
        super().__init__(**kw)
        for t in (tag_src, tag_dst):
            if not _TAG_RX.match(t):
                raise ValueError(f"bad PAN-OS tag {t!r}")
        self._key, self.tag_src, self.tag_dst = api_key, tag_src, tag_dst

    def _tag(self, action_type: str) -> str:
        return self.tag_dst if action_type == "block_egress" else self.tag_src

    def _post(self, form: dict) -> str:
        res = call(self._transport, "POST", f"{self.base_url}/api/", json_body=RawBody(urlencode(form).encode()),
                   headers={"X-PAN-KEY": self._key, "Content-Type": "application/x-www-form-urlencoded"})
        text = res.body if isinstance(res.body, str) else str(res.body or "")
        if 'status="success"' not in text:
            msg = re.sub(r"<[^>]+>", " ", text)
            raise ConnectorError(f"PAN-OS refused: {' '.join(msg.split())[:200]}")
        return text

    def _uid(self, op: str, ip: str, tag: str, timeout: int | None = None) -> None:
        member = (f"<member timeout=\"{timeout}\">{tag}</member>" if timeout is not None else f"<member>{tag}</member>")
        xml = (f"<uid-message><version>2.0</version><type>update</type><payload><{op}>"
               f"<entry ip={quoteattr(ip)} persistent=\"1\"><tag>{member}</tag></entry></{op}></payload></uid-message>")
        self._post({"type": "user-id", "cmd": xml})

    def _do_apply(self, action: Any, key: str, ttl_sec: int | None) -> tuple[str, str, str]:
        ip, tag = _ip(action.target), self._tag(action.action_type)
        timeout = 0 if not ttl_sec else min(int(ttl_sec), _MAX_PANOS_TIMEOUT)
        self._uid("register", ip, tag, timeout)
        life = "no timeout" if timeout == 0 else f"timeout {timeout}s"
        return f"{ip}#{tag}", f"[panos] tagged {ip} {tag} ({life}) — the {tag} DAG policy enforces it", tag

    def _do_rollback(self, receipt: Receipt) -> str:
        ip, tag = _ip(receipt.target), receipt.rollback_token or self._tag(receipt.action_type)
        self._uid("unregister", ip, tag)
        return f"[panos] untagged {ip} {tag}"

    def _do_verify(self, receipt: Receipt) -> bool | None:
        ip, tag = _ip(receipt.target), receipt.rollback_token or self._tag(receipt.action_type)
        text = self._post({"type": "op", "cmd": f"<show><object><registered-ip><ip>{ip}</ip></registered-ip></object></show>"})
        return f"<member>{tag}</member>" in text or f">{tag}<" in text


class FortiGateConnector(_Firewall):
    """Fortinet FortiGate: the banned-IP quarantine list, with an expiry."""

    name = "fortigate"

    def __init__(self, *, token: str, vdom: str = "", **kw: Any):
        super().__init__(**kw)
        self._token = token
        self._q = f"?{urlencode({'vdom': vdom})}" if vdom else ""

    def _h(self) -> dict:
        return {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json", "Accept": "application/json"}

    def _do_apply(self, action: Any, key: str, ttl_sec: int | None) -> tuple[str, str, str]:
        ip = _ip(action.target)
        expiry = 0 if not ttl_sec else int(ttl_sec)
        res = call(self._transport, "POST", f"{self.base_url}/api/v2/monitor/user/banned/add_users{self._q}",
                   json_body={"ip_addresses": [ip], "expiry": expiry}, headers=self._h())
        if str(res.json().get("status", "success")).lower() not in ("success", ""):
            raise ConnectorError(f"FortiGate refused: {str(res.json())[:200]}")
        life = "indefinitely" if expiry == 0 else f"for {expiry}s"
        return ip, f"[fortigate] banned {ip} {life} ({action.action_type})", ip

    def _do_rollback(self, receipt: Receipt) -> str:
        ip = _ip(receipt.target)
        call(self._transport, "POST", f"{self.base_url}/api/v2/monitor/user/banned/clear_users{self._q}",
             json_body={"ip_addresses": [ip]}, headers=self._h())
        return f"[fortigate] cleared ban on {ip}"

    def _do_verify(self, receipt: Receipt) -> bool | None:
        ip = _ip(receipt.target)
        res = call(self._transport, "GET", f"{self.base_url}/api/v2/monitor/user/banned{self._q}", headers=self._h())
        rows = res.json().get("results") or []
        return any(ip in (str(r.get("ipv4_address") or ""), str(r.get("ipv6_address") or "")) for r in rows
                   if isinstance(r, dict))


def firewall_from_env(transport: Transport | None = None) -> Connector | None:
    """``AEGIS_FW_VENDOR = panos | fortigate | mock-panos | mock-fortigate`` (default off). Live needs ``AEGIS_FW_URL``
    and ``AEGIS_FW_TOKEN`` (PAN-OS API key / FortiGate REST token); ``AEGIS_FW_TAG_SRC`` / ``AEGIS_FW_TAG_DST``
    (PAN-OS DAG tags), ``AEGIS_FW_VDOM`` (FortiGate)."""
    vendor = os.environ.get("AEGIS_FW_VENDOR", "off").strip().lower()
    if vendor in ("", "off", "0", "none"):
        return None
    tags = {"tag_src": os.environ.get("AEGIS_FW_TAG_SRC", "aegis-block-src"),
            "tag_dst": os.environ.get("AEGIS_FW_TAG_DST", "aegis-block-dst")}
    if vendor == "mock-panos":
        from .mock_bank import MockPanos
        return PanosConnector(base_url="https://panos.mock", api_key="mock-pan-key", transport=transport or MockPanos(), **tags)
    if vendor == "mock-fortigate":
        from .mock_bank import MockFortiGate
        return FortiGateConnector(base_url="https://fgt.mock", token="mock-fgt-token", transport=transport or MockFortiGate())
    base, token = os.environ.get("AEGIS_FW_URL", "").strip(), os.environ.get("AEGIS_FW_TOKEN", "")
    if vendor in ("panos", "paloalto", "fortigate", "fortinet") and not (base.startswith("https://") and token):
        logger.warning("[firewall] AEGIS_FW_VENDOR=%s needs AEGIS_FW_URL (https) and AEGIS_FW_TOKEN", vendor)
        return None
    if vendor in ("panos", "paloalto"):
        return PanosConnector(base_url=base, api_key=token, transport=transport, **tags)
    if vendor in ("fortigate", "fortinet"):
        return FortiGateConnector(base_url=base, token=token, vdom=os.environ.get("AEGIS_FW_VDOM", ""), transport=transport)
    logger.warning("[firewall] unknown AEGIS_FW_VENDOR=%r", vendor)
    return None


__all__ = ["FortiGateConnector", "PanosConnector", "firewall_from_env"]
