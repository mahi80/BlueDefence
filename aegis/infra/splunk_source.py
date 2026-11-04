"""Production-shape Splunk consumer for AEGIS alerts.

Talks to Splunk's REST API export endpoint to stream events matching an
SPL search and yield them as alert dicts compatible with the rest of
the AEGIS pipeline. Works against:

  - A real Splunk Enterprise / Cloud instance (set SPLUNK_URL, SPLUNK_TOKEN)
  - The local mock_splunk_server.py shim (default URL http://localhost:8089)

API used (subset of Splunk 9.x REST):
  POST /services/auth/login         (session-key auth, optional)
  GET  /services/search/jobs/export (streaming NDJSON of matching events)

Auth methods supported:
  1. Bearer / Splunk token via Authorization header (preferred — matches HEC + Splunk Cloud token auth)
  2. Username/password via /services/auth/login (fallback for legacy on-prem)

The consumer:
  - Retries 5xx + 429 with exponential backoff + jitter
  - Re-authenticates on 401 (token rotation)
  - Honors a wall-clock timeout per request
  - Yields alerts as plain dicts so the orchestrator code is unchanged
"""
from __future__ import annotations

import json
import logging
import os
import random
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Iterator, Optional


_log = logging.getLogger("aegis.splunk")


@dataclass
class SplunkConfig:
    base_url: str = "http://localhost:8089"
    token: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    verify_tls: bool = True
    request_timeout_s: float = 30.0
    max_retries: int = 5
    initial_backoff_s: float = 1.0
    max_backoff_s: float = 30.0

    @classmethod
    def from_env(cls) -> "SplunkConfig":
        return cls(
            base_url=os.environ.get("SPLUNK_URL", "http://localhost:8089"),
            token=os.environ.get("SPLUNK_TOKEN"),
            username=os.environ.get("SPLUNK_USERNAME"),
            password=os.environ.get("SPLUNK_PASSWORD"),
            verify_tls=os.environ.get("SPLUNK_VERIFY_TLS", "true").lower() != "false",
        )


@dataclass
class _State:
    session_key: Optional[str] = None


class SplunkAuthError(RuntimeError):
    pass


class SplunkConsumer:
    name = "splunk"

    def __init__(self, config: Optional[SplunkConfig] = None):
        self._cfg = config or SplunkConfig.from_env()
        self._state = _State()
        self._ssl_ctx = ssl.create_default_context()
        if not self._cfg.verify_tls:
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode = ssl.CERT_NONE

    # ---- public API --------------------------------------------------

    def iter_alerts(
        self,
        search: str = 'search index=aegis_security sourcetype="aegis:notable" | head 100',
        *,
        earliest_time: str = "-24h",
        latest_time: str = "now",
        max_count: int = 1000,
    ) -> Iterator[dict]:
        """Stream events matching `search` and yield AEGIS-shaped alerts.

        The Splunk export endpoint streams one JSON document per line.
        Each event has `_raw` (the original payload, often JSON itself
        for AEGIS-emitted events) plus extracted top-level fields.
        """
        params = {
            "search": search,
            "earliest_time": earliest_time,
            "latest_time": latest_time,
            "output_mode": "json",
            "count": str(max_count),
        }
        url = self._url("/services/search/jobs/export")
        body = urllib.parse.urlencode(params).encode("utf-8")
        for line in self._stream_with_retry(url, body):
            event = self._parse_event_line(line)
            if event is None:
                continue
            alert = self._event_to_alert(event)
            if alert is not None:
                yield alert

    # ---- HTTP plumbing -----------------------------------------------

    def _url(self, path: str) -> str:
        return self._cfg.base_url.rstrip("/") + path

    def _build_auth_header(self) -> dict[str, str]:
        if self._cfg.token:
            return {"Authorization": f"Bearer {self._cfg.token}"}
        if self._state.session_key:
            return {"Authorization": f"Splunk {self._state.session_key}"}
        return {}

    def _login(self) -> None:
        if not (self._cfg.username and self._cfg.password):
            raise SplunkAuthError("no token and no username/password configured")
        url = self._url("/services/auth/login")
        body = urllib.parse.urlencode({
            "username": self._cfg.username,
            "password": self._cfg.password,
            "output_mode": "json",
        }).encode("utf-8")
        req = urllib.request.Request(url, data=body, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self._cfg.request_timeout_s,
                                          context=self._ssl_ctx) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise SplunkAuthError(f"login failed: {exc}") from exc
        key = payload.get("sessionKey") or payload.get("sessionkey")
        if not key:
            raise SplunkAuthError(f"login response missing sessionKey: {payload}")
        self._state.session_key = key
        _log.info("splunk: authenticated as %s", self._cfg.username)

    def _stream_with_retry(self, url: str, body: bytes) -> Iterable[str]:
        attempt = 0
        reauths = 0
        backoff = self._cfg.initial_backoff_s
        while True:
            try:
                yield from self._stream_once(url, body)
                return
            except urllib.error.HTTPError as exc:
                if exc.code == 401 and not self._cfg.token:
                    # Session expired — re-auth ONCE. A 401 straight after a fresh login means the account
                    # cannot search (role lacks the capability, session invalidated): looping on it hammered
                    # Splunk and hung the service cycle forever.
                    if reauths >= 1:
                        _log.error("splunk: still 401 after re-authenticating as %s — check the account's search "
                                   "capability; giving up this cycle", self._cfg.username)
                        raise
                    reauths += 1
                    _log.warning("splunk: 401 — re-authenticating")
                    self._state.session_key = None
                    self._login()
                    continue
                if not self._is_retriable_status(exc.code) or attempt >= self._cfg.max_retries:
                    raise
            except (urllib.error.URLError, TimeoutError) as exc:
                if attempt >= self._cfg.max_retries:
                    raise
                _log.warning("splunk: transient %s — retry %d/%d", exc, attempt + 1, self._cfg.max_retries)
            attempt += 1
            sleep_s = min(backoff, self._cfg.max_backoff_s) * (0.5 + random.random())
            time.sleep(sleep_s)
            backoff = min(backoff * 2, self._cfg.max_backoff_s)

    def _stream_once(self, url: str, body: bytes) -> Iterable[str]:
        # Lazy auth: if no token and no session, try login first.
        if not self._cfg.token and not self._state.session_key:
            if self._cfg.username and self._cfg.password:
                self._login()
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        headers.update(self._build_auth_header())
        req = urllib.request.Request(url, data=body, method="POST", headers=headers)
        with urllib.request.urlopen(req, timeout=self._cfg.request_timeout_s,
                                      context=self._ssl_ctx) as resp:
            for raw in resp:
                line = raw.decode("utf-8", errors="replace").strip()
                if line:
                    yield line

    def _is_retriable_status(self, code: int) -> bool:
        return code in (408, 425, 429) or (500 <= code <= 599)

    # ---- event parsing ----------------------------------------------

    def _parse_event_line(self, line: str) -> Optional[dict]:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            _log.debug("splunk: skipping non-JSON line: %s", line[:80])
            return None
        # Splunk wraps each event in {"result": {...}} on the export endpoint
        if isinstance(obj, dict) and "result" in obj:
            return obj["result"]
        return obj

    def _event_to_alert(self, event: dict) -> Optional[dict]:
        """Convert a Splunk event into the alert shape AEGIS expects.

        AEGIS-emitted events store the alert dict as JSON in _raw. For
        non-AEGIS sources, the search SPL must already extract the
        relevant fields to top-level — we copy those through verbatim.
        """
        raw = event.get("_raw")
        if isinstance(raw, str):
            try:
                inner = json.loads(raw)
                if isinstance(inner, dict):
                    inner.setdefault("_splunk_meta", {
                        "_time": event.get("_time"),
                        "index": event.get("index"),
                        "sourcetype": event.get("sourcetype"),
                        "host": event.get("host"),
                    })
                    return inner
            except json.JSONDecodeError:
                pass
        # Fallback: take top-level fields, drop Splunk meta — but keep the event's ``_cd`` (index address) under a
        # non-underscore key so callers can still use it as a stable id (round-7 G-11).
        out = {k: v for k, v in event.items() if not k.startswith("_")}
        if event.get("_cd") and "splunk_cd" not in out:
            out["splunk_cd"] = event["_cd"]
        return out
