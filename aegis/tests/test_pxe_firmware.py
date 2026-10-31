"""PXE-boot ICMP detector + the firmware fast path (CVE-2026-97631)."""
from __future__ import annotations

from aegis.agents.ndr.pxe_boot import scan_pxe_icmp
from aegis.agents.orchestrator.pxe_firmware import (
    is_pxe_firmware_finding, pxe_firmware_chain)


# ---- detector ---------------------------------------------------------------
def test_oversize_icmp_in_boot_flags_strong():
    f = scan_pxe_icmp({"pxe_active": True, "host": "srv-1", "src": "10.0.0.9",
                       "icmp_errors": [{"ver": 4, "type": 3, "bytes": 600}]})
    assert f and f["alert_type"] == "pxe_icmp_overflow" and f["pxe"]["oversize"] is True
    assert any(s["weight"] == "strong" for s in f["pxe"]["signals"])


def test_icmp_burst_flags_medium():
    f = scan_pxe_icmp({"pxe_active": True, "host": "srv-2", "src": "10.0.0.9",
                       "icmp_errors": [{"ver": 6, "type": 1, "bytes": 40} for _ in range(10)]})
    assert f and f["pxe"]["oversize"] is False
    assert any(s["name"] == "icmp_error_burst" for s in f["pxe"]["signals"])


def test_small_icmp_during_boot_is_clean():
    assert scan_pxe_icmp({"pxe_active": True, "host": "s", "src": "x",
                          "icmp_errors": [{"ver": 4, "type": 3, "bytes": 80}]}) is None


def test_not_booting_is_ignored():
    assert scan_pxe_icmp({"pxe_active": False, "icmp_errors": [{"ver": 4, "type": 3, "bytes": 999}]}) is None


def test_non_error_icmp_types_ignored():
    # echo request (type 8) is not a boot-parser error type
    assert scan_pxe_icmp({"pxe_active": True, "host": "s", "src": "x",
                          "icmp_errors": [{"ver": 4, "type": 8, "bytes": 999}]}) is None


# ---- fast path --------------------------------------------------------------
def test_fast_path_recognises_finding():
    f = scan_pxe_icmp({"pxe_active": True, "host": "srv-1", "src": "10.0.0.9",
                       "icmp_errors": [{"ver": 4, "type": 3, "bytes": 600}]})
    assert is_pxe_firmware_finding(f)
    assert not is_pxe_firmware_finding({"alert_type": "tls_beacon"})


def test_oversize_chain_is_malicious_with_contain_actions():
    f = scan_pxe_icmp({"pxe_active": True, "host": "srv-1", "src": "10.0.0.9",
                       "icmp_errors": [{"ver": 4, "type": 3, "bytes": 600}]})
    chain = pxe_firmware_chain(f)
    assert chain.verdict == "malicious"
    kinds = {a.action_type for a in chain.recommended_actions}
    assert {"isolate", "block", "escalate"} <= kinds
    assert all(a.requires_hitl for a in chain.recommended_actions)          # never auto-contained
    assert any("CVE-2026-97631" in a.reasoning for a in chain.recommended_actions)


def test_burst_only_chain_is_suspicious_and_monitors():
    f = scan_pxe_icmp({"pxe_active": True, "host": "srv-2", "src": "10.0.0.9",
                       "icmp_errors": [{"ver": 6, "type": 1, "bytes": 40} for _ in range(10)]})
    chain = pxe_firmware_chain(f)
    assert chain.verdict == "suspicious"
    assert "monitor" in {a.action_type for a in chain.recommended_actions}
