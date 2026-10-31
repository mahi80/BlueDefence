"""Deterministic routing for host / endpoint telemetry.

Alerts from the host collectors (Sysmon, osquery — see
``aegis/agents/edr/collectors/``) and the host scorers' own signal fields go
straight to the EDR specialist, without spending an LLM triage call. The EDR
agent still produces the verdict and the independent-voter check runs as usual;
this only picks the specialist, the same way the other deterministic detectors
(egress, object-walk, auth-burst, ...) short-circuit triage.

Scope is deliberately narrow — the two new collectors and the host-only signal
fields — so existing EDR-vendor alerts keep their LLM-triage path unchanged.
"""
from __future__ import annotations

from typing import Optional

# the host collectors shipped in this module
_HOST_SOURCES = ("sysmon", "osquery")
# fields only host telemetry carries (set by edr.normalize / the host scorers)
_HOST_SIGNAL_KEYS = ("autostart_entries", "tcc_service", "ssh_key_fingerprint",
                     "egress_connect_times")


def is_host_endpoint(alert: dict) -> bool:
    """True when the alert is host/endpoint telemetry that the EDR specialist owns."""
    if not isinstance(alert, dict):
        return False
    src = str(alert.get("source") or "").lower()
    if any(src.startswith(s) for s in _HOST_SOURCES):
        return True
    return any(alert.get(k) for k in _HOST_SIGNAL_KEYS)


def host_route(alert: dict, has_edr: bool) -> Optional[str]:
    """Return ``"dispatch_edr"`` for host/endpoint telemetry when an EDR specialist
    is registered, else ``None`` (fall through to LLM triage)."""
    return "dispatch_edr" if (has_edr and is_host_endpoint(alert)) else None
