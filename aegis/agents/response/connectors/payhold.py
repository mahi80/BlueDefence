"""Payment hold — stop money at the rail before it settles (the one control point that was SOAR-only).

Indian banks run payments through many systems (Finacle / BaNCS / FinCore payment hubs, NEFT / RTGS / IMPS / UPI
switches, SWIFT gateways) and fraud engines (FICO Falcon, Clari5, in-house FRM). There is no common API, so AEGIS
defines one small contract — the **AEGIS Payment Hold API** (``deploy/payment-hold/openapi.yaml``) — and the bank
implements a thin adapter for it once, on the system that can actually park a payment. Every request is signed, so
the adapter can refuse anything that did not come from AEGIS.

Targets (from the treasury / outflow guard and the walkers):

* ``outbound:<account>`` — hold every outbound payment from an account (a drained treasury or compromised signer);
* ``txn:<id>`` or a bare transaction id — hold one transfer pending a call-back.

API::

    POST   {base}/holds              {"scope": "account"|"transaction", "ref", "reason", "expires_at", "idempotency_key",
                                      "requested_by": "aegis"}             → 201 {"hold_id", "state": "active"}
                                                                           → 409 {"state": "settled"}  (too late: recall)
    DELETE {base}/holds/{hold_id}                                          → 200 {"state": "released"}
    GET    {base}/holds/{hold_id}                                          → 200 {"state": "active"|"released"|"expired"}
    auth   Authorization: Bearer <token>
    sign   X-AEGIS-Timestamp: <unix s>; X-AEGIS-Signature: sha256=<hex HMAC-SHA256(key, timestamp + "." + body)>

A hold is TTL'd (``expires_at``), so one the sweep never reaches still lapses at the bank; undo releases it; the
read-back reads its state. A transfer that already settled is reported as such (a hold cannot stop it — recall
it through the fraud team), never as "applied". Severity stays with the action contracts: ``hold`` is HIGH, and
only the outflow circuit breaker may hold unattended, on a sender's outbound payments, under its own budget.

``AEGIS_PAYHOLD_VENDOR = api | mock`` with ``AEGIS_PAYHOLD_URL`` (https), ``AEGIS_PAYHOLD_TOKEN`` and
``AEGIS_PAYHOLD_SIGNING_KEY``. Registered before the SOAR connector, so a bank with the API never routes a hold to
a playbook.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from .base import Connector, ConnectorError, Receipt
from .http import RawBody, Transport, call, httpx_transport

logger = logging.getLogger("aegis.connectors.payhold")

_REF = re.compile(r"^[A-Za-z0-9._:/@-]{1,128}$")


def sign(key: bytes, ts: str, body: bytes) -> str:
    return "sha256=" + hmac.new(key, ts.encode() + b"." + body, hashlib.sha256).hexdigest()


def verify_signature(key: bytes, ts: str, body: bytes, presented: str, *, max_skew_s: int = 300,
                     now: float | None = None) -> bool:
    """For the bank's adapter (and the mock): signature matches and the timestamp is fresh."""
    try:
        if abs((now if now is not None else time.time()) - int(ts)) > max_skew_s:
            return False
    except ValueError:
        return False
    return hmac.compare_digest(sign(key, ts, body), presented or "")


def _scope_ref(target: str) -> tuple[str, str]:
    t = str(target).strip()
    low = t.lower()
    if low.startswith("outbound:"):
        scope, ref = "account", t[9:].strip()
    elif low.startswith(("txn:", "transaction:")):
        scope, ref = "transaction", t.split(":", 1)[1].strip()
    else:
        scope, ref = "transaction", t
    if not _REF.match(ref):
        raise ConnectorError(f"not a payment account or transaction reference: {target!r}")
    return scope, ref


class PaymentHoldConnector(Connector):
    """The AEGIS Payment Hold API: hold / release / read a hold on an account's outbound payments or one transfer."""

    name = "payhold"
    actions = frozenset({"hold"})
    reapply_on_human_approval = True

    def __init__(self, *, base_url: str, token: str, signing_key: str, transport: Transport | None = None,
                 clock: Callable[[], float] = time.time, **kw: Any):
        super().__init__(clock=clock, **kw)
        if len(signing_key) < 16:
            raise ValueError("AEGIS_PAYHOLD_SIGNING_KEY must be at least 16 characters")
        self.base_url = base_url.rstrip("/")
        self._token, self._key = token, signing_key.encode()
        self._transport = transport or httpx_transport
        self._now = clock

    def supports_target(self, target: str) -> bool:
        try:
            _scope_ref(target)
            return True
        except ConnectorError:
            return False

    def _req(self, method: str, path: str, body: dict | None = None, expect: tuple[int, ...] = ()) -> Any:
        raw = json.dumps(body, separators=(",", ":"), sort_keys=True).encode() if body is not None else b""
        ts = str(int(self._now()))
        headers = {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json",
                   "X-AEGIS-Timestamp": ts, "X-AEGIS-Signature": sign(self._key, ts, raw)}
        return call(self._transport, method, f"{self.base_url}{path}", json_body=RawBody(raw) if body is not None else None,
                    headers=headers, expect=expect)

    def _do_apply(self, action: Any, key: str, ttl_sec: int | None) -> tuple[str, str, str]:
        scope, ref = _scope_ref(action.target)
        expires = (datetime.fromtimestamp(self._now() + int(ttl_sec), UTC).isoformat() if ttl_sec else None)
        res = self._req("POST", "/holds", {"scope": scope, "ref": ref, "reason": str(getattr(action, "reasoning", ""))[:500],
                                           "expires_at": expires, "idempotency_key": key, "requested_by": "aegis"},
                        expect=(200, 201, 409))
        body = res.json()
        if res.status == 409 or str(body.get("state", "")).lower() == "settled":
            raise ConnectorError(f"{ref} has already settled — a hold cannot stop it; recall it through the fraud team "
                                 "(escalate_to_fraud_team)")
        hold_id = str(body.get("hold_id") or "")
        if not hold_id:
            raise ConnectorError("payment hold API returned no hold_id")
        what = "every outbound payment from account" if scope == "account" else "transfer"
        life = f"until {expires}" if expires else "until released"
        return hold_id, f"[payhold] holding {what} {ref} {life} (hold {hold_id})", hold_id

    def _do_rollback(self, receipt: Receipt) -> str:
        hid = receipt.rollback_token or receipt.vendor_ref
        self._req("DELETE", f"/holds/{quote(hid, safe='')}", expect=(200, 204, 404))
        return f"[payhold] released hold {hid} on {receipt.target}"

    def _do_verify(self, receipt: Receipt) -> bool | None:
        res = self._req("GET", f"/holds/{quote(receipt.vendor_ref, safe='')}", expect=(200, 404))
        if res.status == 404:
            return False
        st = str(res.json().get("state") or "").lower()
        return True if st == "active" else False if st in ("released", "expired", "cancelled") else None

    def _do_renew(self, receipt: Receipt, ttl_sec: int) -> str:
        ref, detail, _ = self._do_apply(_View(receipt), receipt.idempotency_key, ttl_sec)
        return detail or f"[payhold] renewed {ref}"


class _View:
    def __init__(self, r: Receipt):
        self.action_type, self.target, self.reasoning = r.action_type, r.target, "renewal of an approved hold"


def payhold_from_env(transport: Transport | None = None) -> Connector | None:
    """``AEGIS_PAYHOLD_VENDOR = api | mock`` (default off)."""
    vendor = os.environ.get("AEGIS_PAYHOLD_VENDOR", "off").strip().lower()
    if vendor in ("", "off", "0", "none"):
        return None
    if vendor == "mock":
        from .mock_bank import MockPaymentHub
        hub = MockPaymentHub()
        return PaymentHoldConnector(base_url="https://payhub.mock/aegis/v1", token=hub.token, signing_key=hub.key.decode(),
                                    transport=transport or hub)
    if vendor == "api":
        base = os.environ.get("AEGIS_PAYHOLD_URL", "").strip()
        tok, key = os.environ.get("AEGIS_PAYHOLD_TOKEN", ""), os.environ.get("AEGIS_PAYHOLD_SIGNING_KEY", "")
        if not (base.startswith("https://") and tok and len(key) >= 16):
            logger.warning("[payhold] api needs AEGIS_PAYHOLD_URL (https), AEGIS_PAYHOLD_TOKEN and "
                           "AEGIS_PAYHOLD_SIGNING_KEY (>= 16 chars)")
            return None
        return PaymentHoldConnector(base_url=base, token=tok, signing_key=key, transport=transport)
    logger.warning("[payhold] unknown AEGIS_PAYHOLD_VENDOR=%r (api | mock)", vendor)
    return None


__all__ = ["PaymentHoldConnector", "payhold_from_env", "sign", "verify_signature"]
