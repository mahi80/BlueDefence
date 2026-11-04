"""Credentials for the cloud WAF connectors — AWS SigV4 and Azure AD tokens.

Kept dependency-free on purpose: the connectors talk through the same
injectable ``transport`` as Imperva / F5, so the signer has to produce the
exact headers the request will carry. ``boto3`` / ``azure-identity`` are used
only, when installed, to *find* credentials (instance role, managed identity),
never to send the request.

AWS   ``sigv4_headers()`` — Signature Version 4 over a pre-serialised body.
      ``aws_credentials()`` — explicit keys → env → botocore's provider chain.
Azure ``AzureToken`` — static token → client-credentials (through the
      transport, so the mock can stand in for login.microsoftonline.com) →
      ``azure.identity.DefaultAzureCredential`` (managed identity on a bank VM).
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import quote, urlencode, urlsplit

from .base import ConnectorError
from .http import RawBody, Transport, call, httpx_transport

logger = logging.getLogger("aegis.connectors.cloud_auth")


# ------------------------------------------------------------------ AWS ---

@dataclass(frozen=True)
class AwsCredentials:
    access_key: str
    secret_key: str
    session_token: str = ""


def aws_credentials(access_key: str = "", secret_key: str = "", session_token: str = "") -> AwsCredentials:
    """Explicit keys win; then ``AWS_ACCESS_KEY_ID`` / ``AWS_SECRET_ACCESS_KEY`` / ``AWS_SESSION_TOKEN``;
    then botocore's chain (instance profile, SSO, ~/.aws) when botocore is installed."""
    if access_key and secret_key:
        return AwsCredentials(access_key, secret_key, session_token)
    ak, sk = os.environ.get("AWS_ACCESS_KEY_ID", ""), os.environ.get("AWS_SECRET_ACCESS_KEY", "")
    if ak and sk:
        return AwsCredentials(ak, sk, os.environ.get("AWS_SESSION_TOKEN", ""))
    try:
        import botocore.session  # type: ignore

        creds = botocore.session.get_session().get_credentials()
        if creds is not None:
            frozen = creds.get_frozen_credentials()
            return AwsCredentials(frozen.access_key, frozen.secret_key, frozen.token or "")
    except ImportError:
        pass
    except Exception as e:  # noqa: BLE001 — a broken ~/.aws must surface as a clear connector error
        raise ConnectorError(f"AWS credential chain failed: {str(e)[:160]}") from None
    raise ConnectorError("no AWS credentials: set AEGIS_AWS_WAF keys, AWS_ACCESS_KEY_ID/SECRET, or an instance role (needs botocore)")


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def sigv4_headers(method: str, url: str, body: bytes, headers: dict, *, creds: AwsCredentials,
                  region: str, service: str, now: Optional[_dt.datetime] = None) -> dict:
    """Return ``headers`` plus ``x-amz-date`` (+ ``x-amz-security-token``) and ``Authorization``.

    Every header passed in is signed, so pass only what will actually be sent."""
    now = now or _dt.datetime.now(_dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = amz_date[:8]
    parts = urlsplit(url)
    out = dict(headers)
    out["x-amz-date"] = amz_date
    if creds.session_token:
        out["x-amz-security-token"] = creds.session_token
    signed_src = {k.lower(): " ".join(str(v).strip().split()) for k, v in out.items()}
    signed_src["host"] = parts.netloc
    names = sorted(signed_src)
    canonical_headers = "".join(f"{k}:{signed_src[k]}\n" for k in names)
    signed_headers = ";".join(names)
    query = sorted((quote(k, safe="-_.~"), quote(v, safe="-_.~"))
                   for k, _, v in (p.partition("=") for p in parts.query.split("&") if p))
    canonical_query = "&".join(f"{k}={v}" for k, v in query)
    canonical_uri = quote(parts.path or "/", safe="/-_.~")
    canonical_request = "\n".join([method.upper(), canonical_uri, canonical_query, canonical_headers,
                                   signed_headers, hashlib.sha256(body).hexdigest()])
    scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope,
                                hashlib.sha256(canonical_request.encode()).hexdigest()])
    k = _hmac(("AWS4" + creds.secret_key).encode(), datestamp)
    k = _hmac(_hmac(_hmac(k, region), service), "aws4_request")
    signature = hmac.new(k, string_to_sign.encode(), hashlib.sha256).hexdigest()
    out["Authorization"] = (f"AWS4-HMAC-SHA256 Credential={creds.access_key}/{scope}, "
                            f"SignedHeaders={signed_headers}, Signature={signature}")
    return out


# ---------------------------------------------------------------- Azure ---

AZURE_MGMT_SCOPE = "https://management.azure.com/.default"
AZURE_LOGIN = "https://login.microsoftonline.com"


class AzureToken:
    """Bearer token for ARM, refreshed five minutes before expiry.

    Order: ``token`` (static, for a quick test) → ``tenant_id``/``client_id``/``client_secret``
    (client-credentials through ``transport``) → ``DefaultAzureCredential`` when
    ``azure-identity`` is installed (managed identity, workload identity, az login)."""

    def __init__(self, *, token: str = "", tenant_id: str = "", client_id: str = "", client_secret: str = "",
                 transport: Optional[Transport] = None, login_url: str = AZURE_LOGIN,
                 clock: Callable[[], float] = time.time, scope: str = AZURE_MGMT_SCOPE):
        self._static = token
        self.scope = scope                       # ARM by default; Graph / Defender pass their own
        self.tenant_id, self.client_id, self._secret = tenant_id, client_id, client_secret
        self._transport = transport or httpx_transport
        self.login_url = login_url.rstrip("/")
        self._clock = clock
        self._token, self._expires = "", 0.0
        self._lock = threading.Lock()

    def __call__(self) -> str:
        if self._static:
            return self._static
        with self._lock:
            if self._token and self._clock() < self._expires - 300:
                return self._token
            self._token, self._expires = self._fetch()
            return self._token

    def invalidate(self) -> None:
        with self._lock:
            self._token, self._expires = "", 0.0

    def _fetch(self) -> tuple[str, float]:
        if self.tenant_id and self.client_id and self._secret:
            form = RawBody(urlencode({"grant_type": "client_credentials", "client_id": self.client_id,
                                      "client_secret": self._secret, "scope": self.scope}).encode())
            res = call(self._transport, "POST", f"{self.login_url}/{self.tenant_id}/oauth2/v2.0/token",
                       json_body=form, headers={"Content-Type": "application/x-www-form-urlencoded"})
            tok = str(res.json().get("access_token") or "")
            if not tok:
                raise ConnectorError("Azure AD returned no access_token")
            return tok, self._clock() + float(res.json().get("expires_in") or 3600)
        try:
            from azure.identity import DefaultAzureCredential  # type: ignore
        except ImportError:
            raise ConnectorError("no Azure credentials: set AEGIS_AZURE_TENANT_ID/CLIENT_ID/CLIENT_SECRET, "
                                 "AEGIS_AZURE_TOKEN, or install azure-identity for managed identity") from None
        try:
            at = DefaultAzureCredential().get_token(self.scope)
        except Exception as e:  # noqa: BLE001
            raise ConnectorError(f"Azure DefaultAzureCredential failed: {str(e)[:160]}") from None
        return at.token, float(at.expires_on)


__all__ = ["AwsCredentials", "aws_credentials", "sigv4_headers", "AzureToken", "AZURE_MGMT_SCOPE"]
