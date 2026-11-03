"""WAF connectors — Imperva Cloud WAF and F5 BIG-IP Advanced WAF (roadmap 1.2).

Cloudflare, AWS WAF and Azure WAF live in ``cloud_waf.py``; ``waf_from_env`` routes to both.

Both turn a ``RecommendedAction`` whose target is a client IP (or CIDR) into
a vendor-side rule, keep the rule id as the rollback token, and delete the
rule on rollback / TTL expiry (``Connector`` tracks the TTL — neither vendor
expires rules on its own).

API shapes (public documentation as of mid-2026; a real tenant may need a
field renamed — the mock in ``mock_vendor.py`` implements exactly these):

Imperva Cloud Application Security, Rules API v2
    POST   {base}/api/prov/v2/sites/{site_id}/rules            → {"rule_id": …}
    DELETE {base}/api/prov/v2/sites/{site_id}/rules/{rule_id}
    headers x-API-Id / x-API-Key
    body    {"name", "action", "filter", "enabled": true [, rate_context, rate_interval, rate_limit]}
    actions RULE_ACTION_BLOCK_IP (block), RULE_ACTION_CAPTCHA (challenge), RULE_ACTION_RATE (throttle)

F5 BIG-IP iControl REST (ASM / Advanced WAF)
    POST   {base}/mgmt/shared/authn/login                      → {"token": {"token": …}}   (or basic auth)
    POST   {base}/mgmt/tm/asm/policies/{policy_id}/whitelist-ips
           {"ipAddress", "ipMask", "blockRequests": "always", "description"}     → {"id": …}
    DELETE {base}/mgmt/tm/asm/policies/{policy_id}/whitelist-ips/{id}
    ("IP address exceptions" — with blockRequests=always the entry is a block, despite the URL name.)
    Rate limiting / challenge have no single REST object on BIG-IP → ``throttle`` and
    ``challenge`` are *unsupported* here and fall through to the registry fallback.

Only the target shapes the WAF understands are accepted (IPv4/IPv6 address or
CIDR); anything else is refused with a ``failed`` receipt — a WAF rule on
"user_id" would be a silent no-op at best.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from typing import Any, Optional

from ...shared.fingerprint import is_fingerprint_target
from .base import Connector, ConnectorError, Receipt
from .http import Transport, call, httpx_transport

logger = logging.getLogger("aegis.connectors.waf")

IMPERVA_DEFAULT_BASE = "https://my.imperva.com"
IMPERVA_ACTIONS = {
    "block": "RULE_ACTION_BLOCK_IP",
    "challenge": "RULE_ACTION_CAPTCHA",
    "throttle": "RULE_ACTION_RATE",
}
F5_ACTIONS = {"block"}


def _ip_target(target: str) -> tuple[str, Optional[str]]:
    """Return (address, mask) for an IP or CIDR target; raise ConnectorError otherwise."""
    t = str(target).strip()
    try:
        if "/" in t:
            net = ipaddress.ip_network(t, strict=False)
            return str(net.network_address), str(net.netmask) if net.version == 4 else str(net.prefixlen)
        ip = ipaddress.ip_address(t)
        return str(ip), "255.255.255.255" if ip.version == 4 else "128"
    except ValueError:
        raise ConnectorError(f"WAF target must be an IP address or CIDR, got {t!r}") from None


class ImpervaWafConnector(Connector):
    """Imperva Cloud WAF — one site rule per (action, IP); rule id is the rollback token."""

    name = "imperva"
    actions = frozenset(IMPERVA_ACTIONS)

    def supports_target(self, target: str) -> bool:
        return not is_fingerprint_target(target)   # IP / CIDR only; fingerprints go to a WAF that matches them

    def __init__(self, *, site_id: str, api_id: str, api_key: str, base_url: str = IMPERVA_DEFAULT_BASE,
                 rate_limit_per_min: int = 60, transport: Optional[Transport] = None, **kw: Any):
        super().__init__(**kw)
        self.site_id = str(site_id)
        self._headers = {"x-API-Id": api_id, "x-API-Key": api_key, "Accept": "application/json"}
        self.base_url = base_url.rstrip("/")
        self.rate_limit_per_min = max(1, int(rate_limit_per_min))
        self._transport = transport or httpx_transport

    def _rules_url(self, rule_id: str = "") -> str:
        return f"{self.base_url}/api/prov/v2/sites/{self.site_id}/rules" + (f"/{rule_id}" if rule_id else "")

    def _do_apply(self, action: Any, key: str, ttl_sec: Optional[int]) -> tuple[str, str, str]:
        addr, _ = _ip_target(action.target)
        body: dict[str, Any] = {
            "name": f"aegis-{action.action_type}-{key[:8]}",
            "action": IMPERVA_ACTIONS[action.action_type],
            "filter": f"ClientIP == {addr}",
            "enabled": True,
        }
        if action.action_type == "throttle":
            body.update({"rate_context": "IP", "rate_interval": 60, "rate_limit": self.rate_limit_per_min})
        res = call(self._transport, "POST", self._rules_url(), json_body=body, headers=self._headers)
        rule_id = str(res.json().get("rule_id") or res.json().get("id") or "")
        if not rule_id:
            raise ConnectorError(f"Imperva returned no rule_id: {str(res.body)[:160]}")
        detail = f"[imperva] {body['action']} rule {rule_id} on site {self.site_id} for {addr}" + (
            f" (TTL {ttl_sec}s)" if ttl_sec else " (permanent)")
        return rule_id, detail, rule_id

    def _do_rollback(self, receipt: Receipt) -> str:
        rule_id = receipt.rollback_token or receipt.vendor_ref
        if not rule_id:
            raise ConnectorError("no Imperva rule id on the receipt")
        call(self._transport, "DELETE", self._rules_url(rule_id), headers=self._headers, expect=(404,))
        return f"[imperva] rule {rule_id} deleted"

    def _do_renew(self, receipt: Receipt, ttl_sec: int) -> str:
        # the rule is still there; the TTL lives on our side
        return f"[imperva] rule {receipt.vendor_ref} kept for another {ttl_sec}s"

    def _do_verify(self, receipt: Receipt) -> bool | None:
        rule_id = receipt.rollback_token or receipt.vendor_ref
        if not rule_id:
            return None
        res = call(self._transport, "GET", self._rules_url(rule_id), headers=self._headers, expect=(404,))
        return res.status != 404


class F5WafConnector(Connector):
    """F5 BIG-IP Advanced WAF — ASM policy IP-address exception with blockRequests=always."""

    name = "f5"
    actions = frozenset(F5_ACTIONS)

    def supports_target(self, target: str) -> bool:
        return not is_fingerprint_target(target)   # IP / CIDR only; fingerprints go to a WAF that matches them

    def __init__(self, *, base_url: str, policy_id: str, username: str = "", password: str = "",
                 token: str = "", transport: Optional[Transport] = None, verify_tls: bool = True, **kw: Any):
        super().__init__(**kw)
        self.base_url = base_url.rstrip("/")
        self.policy_id = str(policy_id)
        self._username, self._password = username, password
        self._token = token
        self._transport = transport or httpx_transport
        self.verify_tls = verify_tls

    def _auth_headers(self) -> dict:
        if not self._token:
            if not (self._username and self._password):
                raise ConnectorError("F5 connector needs a token or username/password")
            res = call(self._transport, "POST", f"{self.base_url}/mgmt/shared/authn/login",
                       json_body={"username": self._username, "password": self._password, "loginProviderName": "tmos"})
            self._token = str(((res.json().get("token") or {}).get("token")) or "")
            if not self._token:
                raise ConnectorError("F5 login returned no token")
        return {"X-F5-Auth-Token": self._token, "Content-Type": "application/json"}

    def _ips_url(self, entry_id: str = "") -> str:
        return f"{self.base_url}/mgmt/tm/asm/policies/{self.policy_id}/whitelist-ips" + (f"/{entry_id}" if entry_id else "")

    def _request(self, method: str, url: str, body: Optional[dict] = None, expect: tuple[int, ...] = ()):
        """One authenticated call; an expired token (401) is renewed once when we hold a password."""
        try:
            return call(self._transport, method, url, json_body=body, headers=self._auth_headers(), expect=expect)
        except ConnectorError as e:
            if "HTTP 401" in str(e) and self._username:
                self._token = ""
                return call(self._transport, method, url, json_body=body, headers=self._auth_headers(), expect=expect)
            raise

    def _do_apply(self, action: Any, key: str, ttl_sec: Optional[int]) -> tuple[str, str, str]:
        addr, mask = _ip_target(action.target)
        body = {"ipAddress": addr, "ipMask": mask, "blockRequests": "always", "ignoreAnomalies": False,
                "description": f"aegis {action.action_type} {key[:8]}"}
        res = self._request("POST", self._ips_url(), body)
        entry_id = str(res.json().get("id") or "")
        if not entry_id:
            raise ConnectorError(f"F5 returned no entry id: {str(res.body)[:160]}")
        detail = f"[f5] policy {self.policy_id} blocks {addr}/{mask} (exception {entry_id})" + (
            f" (TTL {ttl_sec}s)" if ttl_sec else " (permanent)")
        return entry_id, detail, entry_id

    def _do_rollback(self, receipt: Receipt) -> str:
        entry_id = receipt.rollback_token or receipt.vendor_ref
        if not entry_id:
            raise ConnectorError("no F5 exception id on the receipt")
        self._request("DELETE", self._ips_url(entry_id), expect=(404,))
        return f"[f5] exception {entry_id} removed"

    def _do_renew(self, receipt: Receipt, ttl_sec: int) -> str:
        return f"[f5] exception {receipt.vendor_ref} kept for another {ttl_sec}s"


def waf_from_env(transport: Optional[Transport] = None) -> Optional[Connector]:
    """``AEGIS_WAF_VENDOR`` = imperva | f5 | cloudflare | aws | azure | mock | mock-<cloud vendor>
    (default off). ``mock`` runs the Imperva connector against the in-process fake tenant;
    ``mock-cloudflare`` / ``mock-aws`` / ``mock-azure`` do the same for the cloud WAFs
    (``cloud_waf.py``) — the whole chain, no credentials."""
    vendor = os.environ.get("AEGIS_WAF_VENDOR", "off").strip().lower()
    if vendor in ("", "off", "0", "none"):
        return None
    if vendor in ("cloudflare", "aws", "azure", "mock-cloudflare", "mock-aws", "mock-azure"):
        from .cloud_waf import cloud_waf_from_env
        return cloud_waf_from_env(vendor, transport)
    if vendor == "mock":
        from .mock_vendor import MockImperva
        return ImpervaWafConnector(site_id=os.environ.get("AEGIS_WAF_SITE_ID", "mock-site"), api_id="mock",
                                   api_key="mock", base_url="https://imperva.mock", transport=transport or MockImperva())
    if vendor == "imperva":
        site = os.environ.get("AEGIS_WAF_SITE_ID", "")
        api_id, api_key = os.environ.get("AEGIS_WAF_API_ID", ""), os.environ.get("AEGIS_WAF_API_KEY", "")
        if not (site and api_id and api_key):
            logger.warning("[waf] AEGIS_WAF_VENDOR=imperva needs AEGIS_WAF_SITE_ID / AEGIS_WAF_API_ID / AEGIS_WAF_API_KEY")
            return None
        return ImpervaWafConnector(site_id=site, api_id=api_id, api_key=api_key,
                                   base_url=os.environ.get("AEGIS_WAF_URL", IMPERVA_DEFAULT_BASE),
                                   rate_limit_per_min=int(os.environ.get("AEGIS_WAF_RATE_LIMIT", "60")),
                                   transport=transport)
    if vendor == "f5":
        base, policy = os.environ.get("AEGIS_WAF_URL", ""), os.environ.get("AEGIS_WAF_POLICY_ID", "")
        if not (base and policy):
            logger.warning("[waf] AEGIS_WAF_VENDOR=f5 needs AEGIS_WAF_URL and AEGIS_WAF_POLICY_ID")
            return None
        return F5WafConnector(base_url=base, policy_id=policy, username=os.environ.get("AEGIS_WAF_USER", ""),
                              password=os.environ.get("AEGIS_WAF_PASS", ""), token=os.environ.get("AEGIS_WAF_TOKEN", ""),
                              transport=transport)
    logger.warning("[waf] unknown AEGIS_WAF_VENDOR=%r", vendor)
    return None
