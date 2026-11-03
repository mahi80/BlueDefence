"""HTTP plumbing shared by the vendor connectors.

Every vendor connector talks through a ``transport(method, url, json_body,
headers, timeout) -> HttpResult`` callable — the same shape the rest of AEGIS
uses — so a test or ``AEGIS_*_VENDOR=mock`` can swap the vendor for an
in-process fake (``mock_vendor.py``) and the connector code under test is the
code that runs against the real tenant.

``call()`` adds what every vendor needs: bounded retries with backoff on 429 /
5xx / transport errors, and a ``ConnectorError`` with the vendor's status and
message for everything else, so ``Connector.apply`` turns it into a ``failed``
receipt instead of a crash.
"""

from __future__ import annotations

import json
import logging
import math
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .base import ConnectorError

logger = logging.getLogger("aegis.connectors.http")

DEFAULT_TIMEOUT = 20.0
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})


@dataclass
class HttpResult:
    status: int
    body: Any = None                 # parsed JSON (dict / list) or text
    headers: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def json(self) -> dict:
        return self.body if isinstance(self.body, dict) else {}


class RawBody(bytes):
    """A pre-serialised request body, sent byte-for-byte (``content=`` not ``json=``).

    Needed where the bytes on the wire must match what was signed (AWS SigV4) or
    the body is not JSON (an OAuth form post). Passed through ``call()`` in the
    ``json_body`` slot; mocks read it with ``.json()`` / ``.form()``."""

    def json(self) -> Any:
        return json.loads(self.decode() or "null")

    def form(self) -> dict:
        from urllib.parse import parse_qsl
        return dict(parse_qsl(self.decode()))


#: transport(method, url, json_body, headers, timeout) -> HttpResult
Transport = Callable[[str, str, Optional[dict], dict, float], HttpResult]


def httpx_transport(method: str, url: str, json_body: Optional[dict], headers: dict, timeout: float) -> HttpResult:
    import httpx

    if isinstance(json_body, RawBody):
        resp = httpx.request(method, url, content=bytes(json_body), headers=headers, timeout=timeout)
    else:
        resp = httpx.request(method, url, json=json_body, headers=headers, timeout=timeout)
    try:
        body: Any = resp.json()
    except Exception:  # noqa: BLE001 — not every vendor answers JSON
        body = resp.text
    return HttpResult(status=resp.status_code, body=body, headers=dict(resp.headers))


def max_retry_after() -> float:
    """Longest ``Retry-After`` a vendor call will sleep (``AEGIS_HTTP_MAX_RETRY_AFTER``, default 30 s)."""
    try:
        return max(0.0, float(os.environ.get("AEGIS_HTTP_MAX_RETRY_AFTER", "30")))
    except ValueError:
        return 30.0


def call(transport: Transport, method: str, url: str, *, json_body: Optional[dict] = None,
         headers: Optional[dict] = None, timeout: float = DEFAULT_TIMEOUT, retries: int = 3,
         backoff_s: float = 0.5, sleep: Optional[Callable[[float], None]] = None,
         expect: tuple[int, ...] = ()) -> HttpResult:
    """One vendor call with retries. Raises ``ConnectorError`` on a final failure."""
    sleep = sleep or time.sleep
    last: Optional[HttpResult] = None
    err: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            res = transport(method, url, json_body, dict(headers or {}), timeout)
        except Exception as e:  # noqa: BLE001 — network / TLS / DNS
            err, last = e, None
            logger.warning("[connector-http] %s %s attempt %d failed: %s", method, url, attempt + 1, str(e)[:120])
        else:
            err, last = None, res
            if res.ok or (expect and res.status in expect):
                return res
            if res.status not in RETRY_STATUSES:
                raise ConnectorError(f"HTTP {res.status} on {method} {_short(url)}: {_message(res)}")
        if attempt < retries:
            wait = backoff_s * (2 ** attempt)
            if last is not None and last.status == 429:
                try:
                    asked = float(last.headers.get("retry-after") or last.headers.get("Retry-After") or 0)
                except ValueError:
                    asked = 0.0
                cap = max_retry_after()
                if asked > cap or math.isnan(asked):
                    # sleeping a vendor's `Retry-After: 86400` stalled the response agent and the TTL sweep
                    # (code review 2026-11-03 W13): fail this call now; the caller's own retry picks it up later
                    raise ConnectorError(f"HTTP 429 on {method} {_short(url)}: vendor asked to wait {asked:.0f}s "
                                         f"(over the {cap:.0f}s cap, AEGIS_HTTP_MAX_RETRY_AFTER)")
                wait = max(wait, asked)
            sleep(wait)
    if last is not None:
        raise ConnectorError(f"HTTP {last.status} on {method} {_short(url)} after {retries + 1} attempts: {_message(last)}")
    raise ConnectorError(f"{type(err).__name__} on {method} {_short(url)} after {retries + 1} attempts: {str(err)[:160]}")


def _message(res: HttpResult) -> str:
    body = res.body
    if isinstance(body, dict):
        errs = body.get("errors")
        if isinstance(errs, list) and errs and isinstance(errs[0], dict) and errs[0].get("message"):
            # Cloudflare v4 envelope: {"success": false, "errors": [{"code": …, "message": …}]}
            return "; ".join(f"{e.get('code', '')} {e.get('message', '')}".strip() for e in errs[:3])[:200]
        if body.get("__type"):
            # AWS JSON-RPC: {"__type": "WAFOptimisticLockException", "message": …}
            return f"{str(body['__type']).rsplit('#', 1)[-1]}: {body.get('message') or body.get('Message') or ''}"[:200]
        err = body.get("error")
        if isinstance(err, dict) and err.get("message"):
            # Azure ARM: {"error": {"code": …, "message": …}}
            return f"{err.get('code', '')}: {err['message']}"[:200]
        for key in ("message", "error", "detail", "res_message", "errorMessage", "title"):
            if body.get(key):
                return str(body[key])[:200]
        return json.dumps(body)[:200]
    return str(body or "")[:200]


def _short(url: str) -> str:
    return url.split("?", 1)[0][:120]
