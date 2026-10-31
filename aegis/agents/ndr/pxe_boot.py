"""Network detection for the PXE network-boot window (CVE-2026-97631).

Defensive only: this scores *observed* ICMP telemetry a sensor (Zeek / Suricata)
reports while a host is network-booting, and flags anomalies. A normal PXE boot
sees few, small ICMP error messages; a flood of them, or error payloads whose
cumulative size runs past the firmware's small fixed boot buffer, is the on-wire
tell of an attempt against the boot-time network stack. No attack logic lives
here — it only measures sizes, counts and ICMP types to raise a finding for the
orchestrator to judge.
"""
from __future__ import annotations

from typing import Optional

# The PXE boot path parses ICMP error/status messages into a small fixed buffer.
# A cumulative error payload beyond this size, during a boot, is anomalous.
_PXE_ICMP_BUFFER = 504
# More than a handful of ICMP errors to a booting host is itself unusual.
_ICMP_BURST = 8
# ICMP error/status types that reach the boot-time parser.
_V4_ERROR_TYPES = {3, 4, 5, 11, 12}   # dest-unreach, source-quench, redirect, time-exceeded, param-problem
_V6_ERROR_TYPES = {1, 2, 3, 4}        # dest-unreach, packet-too-big, time-exceeded, param-problem


def scan_pxe_icmp(obs: dict) -> Optional[dict]:
    """Return a finding dict when ICMP telemetry during a network boot looks hostile, else None.

    ``obs`` (from the NDR sensor):
      - ``pxe_active``   bool   — the target is mid network-boot (only then is this meaningful)
      - ``host``         str    — the booting host
      - ``src``          str    — the source sending the ICMP errors
      - ``icmp_errors``  list   — ``[{"ver": 4|6, "type": int, "bytes": int}, ...]`` observed
    """
    if not isinstance(obs, dict) or not obs.get("pxe_active"):
        return None
    raw = obs.get("icmp_errors") if isinstance(obs.get("icmp_errors"), list) else []
    errs = [e for e in raw if isinstance(e, dict)
            and int(e.get("type", -1)) in (_V4_ERROR_TYPES if int(e.get("ver", 4)) == 4 else _V6_ERROR_TYPES)]
    if not errs:
        return None

    total = sum(max(0, int(e.get("bytes", 0))) for e in errs)
    count = len(errs)
    versions = sorted({int(e.get("ver", 4)) for e in errs})

    signals = []
    if total > _PXE_ICMP_BUFFER:
        signals.append({"name": "icmp_oversize_in_boot", "weight": "strong",
                        "detail": f"{total} B of ICMP error payload during PXE boot (> {_PXE_ICMP_BUFFER} B boot buffer)"})
    if count >= _ICMP_BURST:
        signals.append({"name": "icmp_error_burst", "weight": "medium",
                        "detail": f"{count} ICMP error messages to a booting host"})
    if not signals:
        return None

    return {
        "alert_type": "pxe_icmp_overflow",
        "source_ip": obs.get("src"),
        "pxe": {
            "cve": "CVE-2026-97631",
            "host": obs.get("host"),
            "src": obs.get("src"),
            "icmp_bytes": total,
            "icmp_count": count,
            "ip_versions": versions,
            "oversize": total > _PXE_ICMP_BUFFER,
            "signals": signals,
        },
    }


__all__ = ["scan_pxe_icmp"]
