"""Castle.io client — alternative to BioCatch for behavioral biometrics
and account-takeover risk scoring.

Same shape as biocatch_client.py: thin urllib-based HTTP client,
retries on 429/5xx, mock fallback when env not set. Production use:
the bank's frontend instruments user sessions with Castle's JS, and
the auth specialist's tools.run_all_tools() queries Castle for the
session's risk score.

Castle's API contract (as of 2026):
  POST /v1/risk
    headers: Authorization: Basic base64(":<api_secret>")
    body: { event, user, context }
  Response: { risk: { score, level, signals[] } }
"""
from __future__ import annotations

import base64
import json
import logging
import os
import random
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field


_log = logging.getLogger("aegis.castle")


@dataclass
class CastleRiskScore:
    request_token: str
    risk_score: float           # 0-1; higher = more anomalous (matches Castle "risk.score")
    risk_level: str             # "allow" | "challenge" | "deny" (Castle native classification)
    signals: list[str] = field(default_factory=list)
    raw_response: dict = field(default_factory=dict)


class CastleClient:
    name = "castle"

    def __init__(self, endpoint: str, api_secret: str, *,
                 timeout_s: float = 5.0,
                 max_retries: int = 3,
                 initial_backoff_s: float = 0.25):
        self._endpoint = endpoint.rstrip("/")
        self._auth_header = "Basic " + base64.b64encode(
            f":{api_secret}".encode("utf-8")
        ).decode("ascii")
        self._timeout = timeout_s
        self._max_retries = max_retries
        self._initial_backoff = initial_backoff_s

    def score(self, event: str, user_id: str, context: dict) -> CastleRiskScore:
        url = self._endpoint + "/v1/risk"
        body = json.dumps({
            "event": event,
            "user": {"id": user_id},
            "context": context,
        }).encode("utf-8")
        req = urllib.request.Request(
            url, data=body, method="POST",
            headers={
                "Authorization": self._auth_header,
                "Content-Type": "application/json",
                "User-Agent": "aegis-castle-client/1",
            },
        )
        backoff = self._initial_backoff
        for attempt in range(self._max_retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                risk = payload.get("risk") or {}
                return CastleRiskScore(
                    request_token=str(payload.get("request_token", "")),
                    risk_score=float(risk.get("score", 0.0)),
                    risk_level=str(risk.get("level", "allow")),
                    signals=[s.get("name", "") for s in risk.get("signals", []) if isinstance(s, dict)],
                    raw_response=payload,
                )
            except urllib.error.HTTPError as exc:
                if exc.code in (408, 429) or exc.code >= 500:
                    if attempt == self._max_retries:
                        raise
                    sleep_s = backoff * (0.5 + random.random())
                    _log.warning("Castle HTTP %d; retry %d/%d after %.2fs",
                                 exc.code, attempt + 1, self._max_retries, sleep_s)
                    time.sleep(sleep_s)
                    backoff *= 2
                    continue
                raise
            except (urllib.error.URLError, TimeoutError):
                if attempt == self._max_retries:
                    raise
                sleep_s = backoff * (0.5 + random.random())
                time.sleep(sleep_s)
                backoff *= 2
        raise RuntimeError("retry loop exhausted")


class MockCastleClient:
    """Offline mock — derives a risk score from local biometric baseline."""
    name = "castle_mock"

    def score(self, event: str, user_id: str, context: dict) -> CastleRiskScore:
        from .biometrics import behavioral_baseline_diff
        telemetry = context.get("behavioral_telemetry", {}) or {}
        result = behavioral_baseline_diff(user_id, telemetry)
        drift = float(result.data.get("drift_score", 0.0))
        level = "deny" if drift >= 0.7 else "challenge" if drift >= 0.4 else "allow"
        signals: list[str] = []
        if result.data.get("drift_severe"):
            signals.append("behavioral_drift_severe")
        return CastleRiskScore(
            request_token=f"mock-{int(time.time())}",
            risk_score=drift, risk_level=level,
            signals=signals,
            raw_response={"mode": "mock", "drift": drift},
        )


def get_client() -> "CastleClient | MockCastleClient":
    endpoint = os.environ.get("CASTLE_ENDPOINT")
    api_secret = os.environ.get("CASTLE_API_SECRET")
    if endpoint and api_secret:
        return CastleClient(endpoint, api_secret)
    return MockCastleClient()
