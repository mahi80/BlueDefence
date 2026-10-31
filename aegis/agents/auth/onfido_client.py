"""Onfido client — identity verification for high-risk auth flows.

Different role from BioCatch / Castle (behavioral biometrics):
Onfido handles document + selfie verification for KYC and high-risk
re-auth. AEGIS auth specialist uses Onfido as a step-up control when
the behavioral / causal signal pushes ATO probability above the
challenge-but-don't-deny threshold — instead of blocking, we ask the
user to re-verify identity via Onfido and only allow if the check
passes.

API contract (Onfido v3):
  POST /v3/checks
    headers: Authorization: Token token=<api_token>
    body: { applicant_id, report_names: [...] }
  Response: { id, status, result, ... }
"""
from __future__ import annotations

import json
import logging
import os
import random
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Optional


_log = logging.getLogger("aegis.onfido")


@dataclass
class OnfidoCheckResult:
    check_id: str
    status: str         # "in_progress" | "complete"
    result: str         # "clear" | "consider" | "rejected"
    report_names: list[str] = field(default_factory=list)
    raw_response: dict = field(default_factory=dict)


class OnfidoClient:
    name = "onfido"

    def __init__(self, endpoint: str, api_token: str, *,
                 timeout_s: float = 10.0,
                 max_retries: int = 3,
                 initial_backoff_s: float = 0.5):
        self._endpoint = endpoint.rstrip("/")
        self._auth_header = f"Token token={api_token}"
        self._timeout = timeout_s
        self._max_retries = max_retries
        self._initial_backoff = initial_backoff_s

    def step_up_check(self, applicant_id: str,
                      report_names: Optional[list[str]] = None) -> OnfidoCheckResult:
        """Initiate a step-up identity check. Returns the check
        record; status is typically `in_progress` immediately after
        creation — caller polls or webhooks back when complete.
        """
        url = self._endpoint + "/v3/checks"
        body = json.dumps({
            "applicant_id": applicant_id,
            "report_names": report_names or ["document", "facial_similarity_photo"],
        }).encode("utf-8")
        req = urllib.request.Request(
            url, data=body, method="POST",
            headers={
                "Authorization": self._auth_header,
                "Content-Type": "application/json",
                "User-Agent": "aegis-onfido-client/1",
            },
        )
        backoff = self._initial_backoff
        for attempt in range(self._max_retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                return OnfidoCheckResult(
                    check_id=str(payload.get("id", "")),
                    status=str(payload.get("status", "in_progress")),
                    result=str(payload.get("result", "")),
                    report_names=list(payload.get("report_names", report_names or [])),
                    raw_response=payload,
                )
            except urllib.error.HTTPError as exc:
                if exc.code in (408, 429) or exc.code >= 500:
                    if attempt == self._max_retries:
                        raise
                    time.sleep(backoff * (0.5 + random.random()))
                    backoff *= 2
                    continue
                raise
            except (urllib.error.URLError, TimeoutError):
                if attempt == self._max_retries:
                    raise
                time.sleep(backoff * (0.5 + random.random()))
                backoff *= 2
        raise RuntimeError("retry loop exhausted")

    def get_check(self, check_id: str) -> OnfidoCheckResult:
        """Poll an in-progress check."""
        url = self._endpoint + f"/v3/checks/{check_id}"
        req = urllib.request.Request(
            url, method="GET",
            headers={
                "Authorization": self._auth_header,
                "User-Agent": "aegis-onfido-client/1",
            },
        )
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        return OnfidoCheckResult(
            check_id=str(payload.get("id", "")),
            status=str(payload.get("status", "complete")),
            result=str(payload.get("result", "clear")),
            report_names=list(payload.get("report_names", [])),
            raw_response=payload,
        )


class MockOnfidoClient:
    """Offline mock — produces deterministic results for the demo path."""
    name = "onfido_mock"

    def step_up_check(self, applicant_id: str,
                      report_names: Optional[list[str]] = None) -> OnfidoCheckResult:
        # Mock decision: applicants whose id starts with "u_blocked-" return
        # a rejection; everyone else returns 'clear'. Real Onfido takes
        # minutes to hours.
        result = "rejected" if applicant_id.startswith("u_blocked-") else "clear"
        return OnfidoCheckResult(
            check_id=f"mock-{applicant_id}-{int(time.time())}",
            status="complete",
            result=result,
            report_names=report_names or ["document", "facial_similarity_photo"],
            raw_response={"mode": "mock", "applicant_id": applicant_id},
        )

    def get_check(self, check_id: str) -> OnfidoCheckResult:
        return OnfidoCheckResult(
            check_id=check_id, status="complete", result="clear",
            raw_response={"mode": "mock"},
        )


def get_client() -> "OnfidoClient | MockOnfidoClient":
    endpoint = os.environ.get("ONFIDO_ENDPOINT")
    api_token = os.environ.get("ONFIDO_API_TOKEN")
    if endpoint and api_token:
        return OnfidoClient(endpoint, api_token)
    return MockOnfidoClient()
