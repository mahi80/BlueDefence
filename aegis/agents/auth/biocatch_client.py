"""BioCatch-shape HTTP client for behavioral biometrics.

The walking-skeleton biometrics tool in biometrics.py uses local mock
baselines. Production banks license a vendor — BioCatch is the most
common in Indian retail-bank deployments. Once licensed, the bank's
JS instrumentation streams behavioral telemetry to the vendor; the
defender queries the vendor for a per-session risk score.

This module ships:

  - BioCatchClient: a thin urllib HTTP client matching the documented
    BioCatch Cloud API shape (POST /api/v3/risk-score with
    session_id + telemetry, returns risk_score + behavioral_anomalies).
  - get_client(): factory that picks real or mock based on
    BIOCATCH_ENDPOINT + BIOCATCH_API_KEY env vars.
  - MockBioCatchClient: deterministic, computes from local baselines
    via the existing biometrics.behavioral_baseline_diff path. Used in
    tests and offline demos.

The shape (request + response keys, status codes, retry policy)
matches BioCatch's public docs as of 2026-Q2; production clients
should pin to the vendor's contract version and update on doc revisions.
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


_log = logging.getLogger("aegis.biocatch")


@dataclass
class BioCatchRiskScore:
    session_id: str
    risk_score: float            # 0-1; higher = more anomalous
    is_bot_likelihood: float     # 0-1; bot-net / scripted activity
    behavioral_anomalies: list[str] = field(default_factory=list)
    confidence: float = 0.85
    raw_response: dict = field(default_factory=dict)


class BioCatchClient:
    """Production HTTP client. Requires BIOCATCH_ENDPOINT + BIOCATCH_API_KEY."""

    name = "biocatch"

    def __init__(self, endpoint: str, api_key: str, *,
                 timeout_s: float = 5.0,
                 max_retries: int = 3,
                 initial_backoff_s: float = 0.25):
        self._endpoint = endpoint.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout_s
        self._max_retries = max_retries
        self._initial_backoff = initial_backoff_s

    def score(self, session_id: str, telemetry: dict) -> BioCatchRiskScore:
        """POST /api/v3/risk-score with session+telemetry; return parsed."""
        url = self._endpoint + "/api/v3/risk-score"
        body = json.dumps({
            "session_id": session_id,
            "telemetry": telemetry,
        }).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
                "User-Agent": "aegis-biocatch-client/1",
            },
        )
        backoff = self._initial_backoff
        for attempt in range(self._max_retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                return BioCatchRiskScore(
                    session_id=session_id,
                    risk_score=float(payload.get("risk_score", 0.0)),
                    is_bot_likelihood=float(payload.get("is_bot_likelihood", 0.0)),
                    behavioral_anomalies=list(payload.get("behavioral_anomalies", [])),
                    confidence=float(payload.get("confidence", 0.85)),
                    raw_response=payload,
                )
            except urllib.error.HTTPError as exc:
                if exc.code in (408, 429) or exc.code >= 500:
                    if attempt == self._max_retries:
                        raise
                    sleep_s = backoff * (0.5 + random.random())
                    _log.warning("BioCatch HTTP %d; retry %d/%d after %.2fs",
                                 exc.code, attempt + 1, self._max_retries, sleep_s)
                    time.sleep(sleep_s)
                    backoff *= 2
                    continue
                raise
            except (urllib.error.URLError, TimeoutError) as exc:
                if attempt == self._max_retries:
                    raise
                sleep_s = backoff * (0.5 + random.random())
                _log.warning("BioCatch transient %s; retry %d/%d after %.2fs",
                             exc, attempt + 1, self._max_retries, sleep_s)
                time.sleep(sleep_s)
                backoff *= 2
        raise RuntimeError("retry loop exhausted")


class MockBioCatchClient:
    """Deterministic local mock — uses biometrics.behavioral_baseline_diff
    so the demo runs offline. Same return shape as the real client.
    """

    name = "biocatch_mock"

    def score(self, session_id: str, telemetry: dict) -> BioCatchRiskScore:
        # Lazy import to avoid circular: biometrics imports nothing
        from .biometrics import behavioral_baseline_diff

        # The mock telemetry includes user_id (BioCatch's session_id maps
        # to a known user via the bank's session cache). We accept it
        # via telemetry["user_id"] for the offline demo.
        user_id = telemetry.pop("user_id", None) if isinstance(telemetry, dict) else None
        result = behavioral_baseline_diff(user_id, telemetry)
        drift = float(result.data.get("drift_score", 0.0))
        anomalies: list[str] = []
        if result.data.get("drift_severe"):
            anomalies.append("drift_above_threshold")
        per_signal = result.data.get("per_signal_distance", {}) or {}
        for k, v in per_signal.items():
            if v >= 0.5:
                anomalies.append(f"{k}_anomaly")
        return BioCatchRiskScore(
            session_id=session_id,
            risk_score=drift,
            is_bot_likelihood=0.6 if drift >= 0.7 else 0.05,
            behavioral_anomalies=anomalies,
            confidence=0.85,
            raw_response={"mode": "mock", "drift": drift, "per_signal": per_signal},
        )


def get_client() -> "BioCatchClient | MockBioCatchClient":
    """Pick real BioCatch if env is set, else mock. Same return shape."""
    endpoint = os.environ.get("BIOCATCH_ENDPOINT")
    api_key = os.environ.get("BIOCATCH_API_KEY")
    if endpoint and api_key:
        return BioCatchClient(endpoint, api_key)
    return MockBioCatchClient()
