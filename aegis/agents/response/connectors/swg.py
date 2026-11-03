"""Secure Web Gateway connector — Zscaler ZIA URL/IP egress block (roadmap 1.3).

ZIA sits in the forward path, so to stop internal hosts reaching a malicious
destination we add that URL / domain / destination-IP to a **custom URL
category** the SOC already wires to a BLOCK rule, and remove it on rollback.
One mechanism covers URLs, domains and IPs (ZIA lets all three live in a URL
category).

Backs ``block_egress`` — blocking a *destination*, distinct from the WAF
connectors' ``block`` of a *source* IP. Reversible (rollback removes the
entry) and TTL'd like every receipt, so an un-renewed egress block self-expires.

API shape (Zscaler ZIA, public docs mid-2026; OneAPI OAuth2 bearer):

    PUT {base}/zia/api/v1/urlCategories/{categoryId}?action=ADD_TO_LIST
        headers  Authorization: Bearer <token>
        body     {"configuredName": <name>, "urls": [<entry>, ...]}
        →        200 {"id", "configuredName", "urls":[...]}
    rollback: the same call with action=REMOVE_FROM_LIST.

Legacy ZIA (obfuscated API key + session cookie) differs only in auth — the
connector takes a ``token_provider`` so either scheme drops in with no other
change. Mock tenant: ``mock_vendor.MockZscaler`` (``AEGIS_SWG_VENDOR=mock``).
"""

from __future__ import annotations

import logging
import os
from typing import Any, Callable, Optional

from ...shared.fingerprint import is_fingerprint_target
from .base import Connector, Receipt
from .http import Transport, call, httpx_transport

logger = logging.getLogger("aegis.connectors.swg")


class ZscalerConnector(Connector):
    """Zscaler ZIA forward-proxy egress block via a custom URL category."""

    name = "zscaler"
    reapply_on_human_approval = True
    actions = frozenset({"block_egress"})

    def __init__(self, *, base_url: str, category_id: str, category_name: str = "AEGIS_BLOCK",
                 token_provider: Optional[Callable[[], str]] = None, transport: Optional[Transport] = None,
                 **kw: Any):
        super().__init__(**kw)
        self.base_url = base_url.rstrip("/")
        self.category_id = category_id
        self.category_name = category_name
        self._token_provider = token_provider
        self._transport = transport or httpx_transport

    def supports_target(self, target: str) -> bool:
        # a destination URL / domain / IP; a client fingerprint is not an egress destination
        return bool(str(target).strip()) and not is_fingerprint_target(target)

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._token_provider:
            h["Authorization"] = f"Bearer {self._token_provider()}"
        return h

    @staticmethod
    def _entry(target: str) -> str:
        return str(target).strip().replace("https://", "").replace("http://", "").rstrip("/")

    def _category_op(self, target: str, action: str) -> Any:
        url = f"{self.base_url}/zia/api/v1/urlCategories/{self.category_id}?action={action}"
        body = {"configuredName": self.category_name, "urls": [self._entry(target)]}
        return call(self._transport, "PUT", url, json_body=body, headers=self._headers(), expect=(200,))

    def _do_apply(self, action: Any, key: str, ttl_sec: Optional[int]) -> tuple[str, str, str]:
        self._category_op(action.target, "ADD_TO_LIST")
        entry = self._entry(action.target)
        return (f"{self.category_id}:{entry}",
                f"[zscaler] block egress to {entry} (category {self.category_name})", entry)

    def _do_verify(self, receipt: Receipt) -> bool | None:
        res = call(self._transport, "GET", f"{self.base_url}/zia/api/v1/urlCategories/{self.category_id}",
                   headers=self._headers(), expect=(200,))
        return self._entry(receipt.target) in {str(u) for u in (res.json().get("urls") or [])}

    def _do_rollback(self, receipt: Receipt) -> str:
        self._category_op(receipt.target, "REMOVE_FROM_LIST")
        return f"[zscaler] removed {self._entry(receipt.target)} from {self.category_name}"


def zscaler_from_env(transport: Optional[Transport] = None) -> Optional[Connector]:
    """``AEGIS_SWG_VENDOR=zscaler|mock`` (default off). Live needs ``AEGIS_SWG_URL``,
    ``AEGIS_SWG_CATEGORY_ID`` (the custom category wired to a BLOCK rule) and ``AEGIS_SWG_TOKEN``."""
    vendor = os.environ.get("AEGIS_SWG_VENDOR", "off").strip().lower()
    if vendor in ("", "off", "0", "none"):
        return None
    if vendor == "mock":
        from .mock_vendor import MockZscaler
        return ZscalerConnector(base_url="https://zia.mock", category_id="CUSTOM_01",
                                token_provider=lambda: "mock", transport=transport or MockZscaler())
    if vendor == "zscaler":
        base = os.environ.get("AEGIS_SWG_URL", "")
        cat = os.environ.get("AEGIS_SWG_CATEGORY_ID", "")
        token = os.environ.get("AEGIS_SWG_TOKEN", "")
        if not (base and cat and token):
            logger.warning("[swg] AEGIS_SWG_VENDOR=zscaler needs AEGIS_SWG_URL, AEGIS_SWG_CATEGORY_ID, AEGIS_SWG_TOKEN")
            return None
        return ZscalerConnector(base_url=base, category_id=cat,
                                category_name=os.environ.get("AEGIS_SWG_CATEGORY_NAME", "AEGIS_BLOCK"),
                                token_provider=lambda: token, transport=transport)
    logger.warning("[swg] unknown AEGIS_SWG_VENDOR=%r", vendor)
    return None
