"""Network detection (NDR): what leaves the bank over TLS — beacons, exfiltration, known-bad
servers, shadow AI. Fed by ``aegis/ingest/ndr.py`` (Zeek, Suricata, generic flow exports)."""

from .ai_usage import AiRegister, AiService, AiUsageRegister, ai_service
from .egress import EgressDetector, beacon_stats, cert_flags, client_shape
from .tls_intel import TlsIndicator, TlsIntel

__all__ = [
           "AiRegister",
           "AiService",
           "AiUsageRegister",
           "EgressDetector",
           "TlsIndicator",
           "TlsIntel",
           "ai_service",
           "beacon_stats",
           "cert_flags",
           "client_shape",
]
