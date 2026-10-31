"""Alert consumers that turn bank telemetry into AEGIS alerts (roadmap Phase 0.5).

Every consumer yields plain alert dicts in the shape the orchestrator and
the specialists already read (``id``, ``source``, ``severity``,
``anomaly_score``, ``source_ip``, ``user_id``, ``url``, ``payload``,
``host`` ...) so nothing downstream changes when a new source is added.

    SentinelConsumer  Microsoft Sentinel — Log Analytics query API (KQL)
    WafConsumer       Imperva / F5 ASM / Cloudflare / AWS WAF / Azure WAF event exports (CEF, F5 key=value, JSON lines, .gz)
    SplunkConsumer    (existing) aegis.infra.splunk_source
    StreamConsumer    whatever the push receiver (Cloudflare Logpush / AWS Firehose / any forwarder,
                      ``http_push.py``) and the Azure Event Hub reader (``eventhub.py``) have queued

``sources_from_env()`` builds the configured set from ``AEGIS_SOURCES``.
"""

from .base import AlertCheckpoint, BaseConsumer, severity_to_score
from .sentinel import SentinelConfig, SentinelConsumer
from .waf import WafConsumer, parse_cef, parse_f5_kv
from .registry import sources_from_env
from .stream import StreamConsumer, StreamQueue, get_stream
from .watchdog import FeedAlert, FeedWatchdog, feed_watchdog_from_env

__all__ = [
    "AlertCheckpoint", "BaseConsumer", "severity_to_score",
    "SentinelConfig", "SentinelConsumer",
    "WafConsumer", "parse_cef", "parse_f5_kv",
    "sources_from_env",
    "StreamConsumer", "StreamQueue", "get_stream",
    "FeedWatchdog", "FeedAlert", "feed_watchdog_from_env",
]
