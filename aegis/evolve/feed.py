"""Pull the accepted-rule feed from the dashboard and apply it."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .applier import ApplyReport, RuleApplier

logger = logging.getLogger("aegis.evolve")

#: transport(method, url, json_body, headers, timeout) -> dict
Transport = Callable[[str, str, Optional[dict], dict, float], dict]


def _httpx_transport(method: str, url: str, json_body: Optional[dict], headers: dict, timeout: float) -> dict:
    import httpx

    resp = httpx.request(method, url, json=json_body, headers=headers, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    return data if isinstance(data, dict) else {"_raw": data}


@dataclass
class FeedSnapshot:
    version: str
    rules: list[dict] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.rules)


class RuleFeed:
    def __init__(self, dashboard_url: Optional[str] = None, api_key: Optional[str] = None, *,
                 timeout: float = 10.0, transport: Optional[Transport] = None,
                 applier: Optional[RuleApplier] = None):
        self.dashboard_url = (dashboard_url or os.environ.get("ACP_DASHBOARD_URL", "")).rstrip("/")
        self.api_key = api_key if api_key is not None else os.environ.get("ACP_API_KEY", "")
        self.timeout = timeout
        self._transport: Transport = transport or _httpx_transport
        self.applier = applier or RuleApplier()
        self.last_error = ""

    @property
    def enabled(self) -> bool:
        return bool(self.dashboard_url)

    def fetch(self) -> Optional[FeedSnapshot]:
        if not self.enabled:
            return None
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        try:
            data = self._transport("GET", f"{self.dashboard_url}/api/soc/rules", None, headers, self.timeout)
        except Exception as e:  # noqa: BLE001 — a feed outage keeps the last applied rules in force
            self.last_error = f"{type(e).__name__}: {str(e)[:160]}"
            logger.warning("[evolve] rule feed unreachable: %s", self.last_error)
            return None
        if data.get("error"):
            self.last_error = str(data["error"])[:200]
            logger.warning("[evolve] rule feed refused: %s", self.last_error)
            return None
        rules = data.get("rules") if isinstance(data.get("rules"), list) else []
        return FeedSnapshot(version=str(data.get("version", "")), rules=[r for r in rules if isinstance(r, dict)])

    def sync(self) -> Optional[ApplyReport]:
        """Fetch + apply. No-op when the version has not changed."""
        snap = self.fetch()
        if snap is None:
            return None
        if snap.version and snap.version == self.applier.version:
            return ApplyReport(version=snap.version, already=[str(r.get("id")) for r in snap.rules])
        report = self.applier.apply(snap.rules, version=snap.version)
        logger.info("[evolve] feed %s: %d applied, %d already, %d rejected",
                    snap.version, len(report.applied), len(report.already), len(report.rejected))
        return report


_shared_feed: Optional[RuleFeed] = None


def sync_from_env(**overrides: Any) -> Optional[ApplyReport]:
    """Pull and apply the feed when a dashboard is configured (AEGIS_RULE_FEED=0 disables)."""
    global _shared_feed
    url = os.environ.get("ACP_DASHBOARD_URL", "").strip()
    if not url or os.environ.get("AEGIS_RULE_FEED", "1").strip().lower() in {"0", "false", "no", "off"}:
        return None
    if _shared_feed is None or _shared_feed.dashboard_url != url.rstrip("/"):
        _shared_feed = RuleFeed(dashboard_url=url, **overrides)
    return _shared_feed.sync()
