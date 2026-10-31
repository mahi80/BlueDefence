"""Splunk Enterprise Security (ES) integration shapes.

The base SplunkConsumer in splunk_source.py speaks the generic
search/jobs/export REST API — works for any Splunk install. ES has
three additional concepts that map directly onto AEGIS' workflow:

  - **Notable Events**: ES correlation searches produce notable_event
    rows in the `notable` index. These are pre-triaged alerts, not
    raw logs — a much higher-signal AEGIS input than a raw search.
  - **Risk Objects**: ES Risk Framework attaches risk scores to users
    / hosts / accounts as time-decaying weighted aggregates. AEGIS'
    auth specialist can read these as a feature.
  - **Threat Intel Framework**: ES's own IOC store, populated from
    feeds. AEGIS' threat_intel agent can pull from it as another
    source alongside MISP / FS-ISAC.

This module ships:

  - SplunkESConsumer.iter_notable_events()
  - SplunkESConsumer.get_risk_score(entity, kind="user"|"host")
  - SplunkESConsumer.iter_threat_intel_iocs()
  - close_notable_event(event_id, status, comment) for response
    feedback (analyst / agent disposition flows back to ES)

Production: same SplunkConfig env vars as the generic consumer
(SPLUNK_URL, SPLUNK_TOKEN, etc.) plus optional SPLUNK_ES_APP_PATH if
ES isn't at the default location.
"""
from __future__ import annotations

import json
import logging
import urllib.parse
import urllib.request
from typing import Iterator, Optional

from .splunk_source import SplunkConfig, SplunkConsumer


_log = logging.getLogger("aegis.splunk_es")


# Default ES path; override via SPLUNK_ES_APP_PATH if non-standard.
_ES_APP_DEFAULT = "/services/SA-ThreatIntelligence"


class SplunkESConsumer:
    """Splunk ES specialization. Composes the base consumer for HTTP +
    auth + retry; layers ES-specific endpoints on top.
    """

    name = "splunk_es"

    def __init__(self, config: Optional[SplunkConfig] = None,
                 *, es_app_path: str = _ES_APP_DEFAULT):
        self._cfg = config or SplunkConfig.from_env()
        self._base = SplunkConsumer(self._cfg)
        self._es_path = es_app_path

    # ---- Notable events ---------------------------------------------

    def iter_notable_events(
        self,
        *,
        urgency: str = "high|medium",
        status: str = "unassigned",
        earliest_time: str = "-24h",
        max_count: int = 200,
    ) -> Iterator[dict]:
        """Yield ES notable_event rows as AEGIS-shaped alert dicts.

        ES notable_event columns include: rule_name, urgency, status,
        owner, src, dest, user, signature. We map a useful subset
        into the alert envelope the orchestrator already accepts.
        """
        spl = (
            f'search index=notable status="{status}" '
            f'urgency IN ({urgency.replace("|", ",")}) '
            "| head 500"
        )
        for event in self._base.iter_alerts(
            search=spl, earliest_time=earliest_time, latest_time="now",
            max_count=max_count,
        ):
            yield self._notable_to_alert(event)

    def _notable_to_alert(self, ev: dict) -> dict:
        """Map ES notable_event fields to AEGIS alert envelope."""
        return {
            "id": ev.get("event_id") or ev.get("_cd") or ev.get("rule_id") or "ES-NOTABLE",
            "source": "Splunk ES (notable)",
            "severity": ev.get("urgency", "medium"),
            "anomaly_score": _urgency_to_anomaly(ev.get("urgency")),
            "source_ip": ev.get("src"),
            "user_id": ev.get("user"),
            "host": ev.get("dest"),
            "url": ev.get("url"),
            "payload": ev.get("signature") or ev.get("rule_name") or "",
            "es_rule": ev.get("rule_name"),
            "es_owner": ev.get("owner"),
            "es_status": ev.get("status"),
            "_es_meta": ev.get("_splunk_meta", {}),
        }

    def close_notable_event(self, event_id: str, *, status: str = "closed",
                            comment: str = "") -> bool:
        """Update an ES notable event after AEGIS produces a verdict.

        Closes the loop so analysts see the agent's disposition in
        their existing ES queue. Production hardening: gate behind
        the response agent's HITL approval, not auto-call.
        """
        url = self._cfg.base_url.rstrip("/") + f"{self._es_path}/notable_update"
        body = urllib.parse.urlencode({
            "event_ids": event_id,
            "status": status,
            "comment": comment,
            "output_mode": "json",
        }).encode("utf-8")
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if self._cfg.token:
            headers["Authorization"] = f"Bearer {self._cfg.token}"
        req = urllib.request.Request(url, data=body, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self._cfg.request_timeout_s) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            _log.warning("notable_event close failed: %s", exc)
            return False
        return bool(payload.get("success", True))

    # ---- Risk Framework --------------------------------------------

    def get_risk_score(self, entity: str, *, kind: str = "user",
                       earliest_time: str = "-24h") -> Optional[float]:
        """Return the time-decaying risk score for a user/host/account.

        Splunk ES Risk Framework lives in the `risk` index. Each
        contribution is a row with risk_score + risk_object + ttl.
        Aggregation: sum of risk_scores within earliest_time.
        """
        spl = (
            f'search index=risk risk_object_type="{kind}" '
            f'risk_object="{entity}" | stats sum(risk_score) as total'
        )
        total = 0.0
        for event in self._base.iter_alerts(
            search=spl, earliest_time=earliest_time, latest_time="now",
            max_count=1,
        ):
            try:
                total = float(event.get("total", 0.0))
            except (TypeError, ValueError):
                pass
            break
        return total if total > 0 else None

    # ---- Threat Intel Framework ------------------------------------

    def iter_threat_intel_iocs(self, *, kinds: tuple[str, ...] = ("ip", "domain")) -> Iterator[dict]:
        """Yield IOCs from ES's local Threat Intel collections.

        ES stores intel in KV-store collections like `ip_intel`,
        `domain_intel`, etc. Each row has indicator + threat_key +
        threat_group + last_updated.
        """
        for kind in kinds:
            collection = f"{kind}_intel"
            spl = f'| inputlookup {collection} | head 5000'
            for ev in self._base.iter_alerts(
                search=spl, earliest_time="-7d", latest_time="now",
                max_count=5000,
            ):
                yield {
                    "kind": "ip" if kind == "ip" else kind,
                    "value": ev.get(kind) or ev.get("indicator"),
                    "threat_group": ev.get("threat_group"),
                    "threat_key": ev.get("threat_key"),
                    "last_updated": ev.get("last_updated"),
                    "source": "splunk_es_intel",
                }


# ---- Helpers --------------------------------------------------------

def _urgency_to_anomaly(urgency: Optional[str]) -> float:
    """ES uses urgency = informational / low / medium / high / critical.
    Map onto AEGIS' [0, 1] anomaly_score so the orchestrator's
    auto_close threshold (0.30) behaves predictably.
    """
    table = {
        "informational": 0.10,
        "low":           0.30,
        "medium":        0.60,
        "high":          0.85,
        "critical":      0.95,
    }
    return table.get((urgency or "").lower(), 0.50)
