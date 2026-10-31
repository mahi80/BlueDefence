"""Build the configured alert sources from the environment.

    AEGIS_SOURCES   comma list of: sample | splunk | sentinel | waf | apigw | ndr | acp | stream | eventhub   (default: sample)
    AEGIS_CHECKPOINT  path of the JSON checkpoint file (default: ./.aegis-ingest.json)
    WAF_EVENT_FILE  path of the WAF syslog/JSON export to read (for source "waf")
    APIGW_EVENT_FILE  API-gateway access log export (for source "apigw"; object-walk detector)
    NDR_EVENT_FILE    network sensor logs, comma list in join order: Zeek x509 / ssl / conn JSON, Suricata EVE,
                      generic flow JSON (for source "ndr"; egress detector)

``stream`` drains what the push receiver (``http_push.py``, ``AEGIS_INGEST_HTTP=1``) and the
Event Hub reader (``eventhub.py``, source ``eventhub``) have queued; it is added automatically
whenever one of those receivers is running, so ``AEGIS_SOURCES`` need not name it. The
receivers themselves are started once by the service (``aegis.service.build_pipeline``), not
here — this function runs every cycle.

Each entry is ``(name, iterator_of_alerts)``; a misconfigured source is
reported and skipped, never fatal — the demo stream is always available.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Iterator

from .base import AlertCheckpoint

logger = logging.getLogger("aegis.ingest")


def sources_from_env() -> list[tuple[str, Iterator[dict]]]:
    wanted = [s.strip().lower() for s in os.environ.get("AEGIS_SOURCES", "sample").split(",") if s.strip()]
    checkpoint = AlertCheckpoint(Path(os.environ.get("AEGIS_CHECKPOINT", ".aegis-ingest.json")))
    out: list[tuple[str, Iterator[dict]]] = []
    for name in wanted:
        try:
            if name == "sample":
                from aegis.infra.siem_source import iter_sample_alerts
                out.append(("sample", iter_sample_alerts()))
            elif name == "splunk":
                from aegis.infra.splunk_source import SplunkConfig, SplunkConsumer
                cfg = SplunkConfig.from_env()
                search = os.environ.get("AEGIS_SPLUNK_SEARCH", "search index=aegis_security sourcetype=aegis:notable")
                out.append(("splunk", SplunkConsumer(cfg).iter_alerts(search=search)))
            elif name == "sentinel":
                from .sentinel import SentinelConfig, SentinelConsumer
                cfg = SentinelConfig.from_env()
                if not cfg.configured:
                    logger.warning("[ingest] sentinel requested but SENTINEL_* env incomplete; skipped")
                    continue
                out.append(("sentinel", SentinelConsumer(cfg, checkpoint=checkpoint).iter_alerts()))
            elif name == "waf":
                from .waf import WafConsumer
                path = os.environ.get("WAF_EVENT_FILE", "")
                if not path or not Path(path).exists():
                    logger.warning("[ingest] waf requested but WAF_EVENT_FILE missing; skipped")
                    continue
                out.append(("waf", WafConsumer(checkpoint=checkpoint).iter_alerts(path=path)))
            elif name == "apigw":
                from .apigw import ApiGatewayConsumer, shared_detector
                path = os.environ.get("APIGW_EVENT_FILE", "")
                if not path or not Path(path).exists():
                    logger.warning("[ingest] apigw requested but APIGW_EVENT_FILE missing; skipped (push to /ingest/apigw works without it)")
                    continue
                out.append(("apigw", ApiGatewayConsumer(detector=shared_detector(), checkpoint=checkpoint).iter_alerts(path=path)))
            elif name == "ndr":
                from .ndr import NdrConsumer
                from .ndr import shared_detector as ndr_detector
                path = os.environ.get("NDR_EVENT_FILE", "")
                files = [f for f in (x.strip() for x in path.split(",")) if f and Path(f).exists()]
                if not files:
                    logger.warning("[ingest] ndr requested but NDR_EVENT_FILE missing; skipped (push to /ingest/ndr works without it)")
                    continue
                out.append(("ndr", NdrConsumer(detector=ndr_detector(), checkpoint=checkpoint).iter_alerts(path=",".join(files))))
            elif name in ("stream", "eventhub"):
                pass                                         # drained once below, after the loop
            elif name == "acp":
                from .acp import AcpGovernanceConsumer
                c = AcpGovernanceConsumer(checkpoint=checkpoint)
                if not c.configured:
                    logger.warning("[ingest] acp requested but ACP_DASHBOARD_URL unset; skipped")
                    continue
                out.append(("acp", c.iter_alerts()))
            else:
                logger.warning("[ingest] unknown source %r skipped", name)
        except Exception as e:  # noqa: BLE001 — one broken source must not take the others down
            logger.error("[ingest] source %s failed to start: %s", name, str(e)[:200], exc_info=True)
    try:
        from .stream import StreamConsumer, get_stream
        q = get_stream()
        if q.enabled or "stream" in wanted or "eventhub" in wanted:
            out.append(("stream", StreamConsumer(queue=q, checkpoint=checkpoint).iter_alerts()))
    except Exception as e:  # noqa: BLE001
        logger.error("[ingest] stream source failed to start: %s", str(e)[:200], exc_info=True)
    return out
