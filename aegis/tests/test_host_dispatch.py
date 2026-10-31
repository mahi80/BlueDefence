"""Deterministic host/endpoint routing in the orchestrator."""
from __future__ import annotations

from aegis.agents.orchestrator.host_endpoint import is_host_endpoint, host_route


def test_sysmon_and_osquery_sources_are_host():
    assert is_host_endpoint({"source": "sysmon", "event_id": 1})
    assert is_host_endpoint({"source": "osquery:persistence_crontab"})


def test_host_signal_fields_are_host():
    assert is_host_endpoint({"autostart_entries": [{"name": "x", "path": "/tmp/x"}]})
    assert is_host_endpoint({"tcc_service": "kTCCServiceMicrophone"})
    assert is_host_endpoint({"ssh_key_fingerprint": "SHA256:abc"})
    assert is_host_endpoint({"egress_connect_times": [1.0, 2.0, 3.0]})


def test_perimeter_and_empty_alerts_are_not_host():
    assert not is_host_endpoint({"source": "f5", "url": "/x?id=1' or 1=1", "request_headers": {}})
    assert not is_host_endpoint({})
    assert not is_host_endpoint(None)


def test_host_route_requires_registered_edr():
    host = {"source": "sysmon"}
    assert host_route(host, has_edr=True) == "dispatch_edr"
    assert host_route(host, has_edr=False) is None


def test_host_route_passes_perimeter_through_to_triage():
    assert host_route({"source": "f5", "url": "/x"}, has_edr=True) is None
