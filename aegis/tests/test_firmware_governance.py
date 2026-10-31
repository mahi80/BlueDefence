"""Firmware-patch governance policy (CVE-2026-97631)."""
from __future__ import annotations

from datetime import date

from aegis.agents.vuln_discovery.firmware_governance import (
    evaluate_firmware_posture, scan_estate, is_affected, ADVISORY_CVE_2026_97631 as ADV)


def test_pxe_enabled_on_non_provisioning_is_flagged():
    a = {"id": "srv-web-1", "asset_class": "app-server", "firmware_vendor": "ami",
         "firmware_build": "edk2-stable202605", "pxe_enabled": True, "patched_cves": []}
    assert any(x.control == "PXE_ENABLED_UNNEEDED" for x in evaluate_firmware_posture(a, ADV))


def test_pxe_allowed_on_provisioning_class():
    a = {"id": "prov-1", "asset_class": "provisioning", "firmware_vendor": "insyde",
         "pxe_enabled": True, "patched_cves": ["CVE-2026-97631"]}
    assert not any(x.control == "PXE_ENABLED_UNNEEDED" for x in evaluate_firmware_posture(a, ADV))


def test_affected_unpatched_no_fix_is_fix_pending():
    a = {"id": "srv-2", "asset_class": "app-server", "firmware_vendor": "phoenix",
         "firmware_build": "edk2-stable202608", "pxe_enabled": False, "patched_cves": []}
    assert any(x.control == "FIRMWARE_FIX_PENDING" for x in evaluate_firmware_posture(a, ADV))


def test_patched_asset_has_no_firmware_finding():
    a = {"id": "srv-3", "asset_class": "app-server", "firmware_vendor": "ami",
         "firmware_build": "edk2-stable202608", "pxe_enabled": False,
         "patched_cves": ["CVE-2026-97631"]}
    assert evaluate_firmware_posture(a, ADV) == []


def test_unaffected_vendor_not_flagged():
    a = {"id": "srv-4", "asset_class": "app-server", "firmware_vendor": "coreboot",
         "pxe_enabled": False, "patched_cves": []}
    assert not is_affected(a, ADV)
    assert evaluate_firmware_posture(a, ADV) == []


def test_newer_build_not_affected():
    a = {"id": "srv-5", "asset_class": "app-server", "firmware_vendor": "ami",
         "firmware_build": "edk2-stable202611", "pxe_enabled": False, "patched_cves": []}
    assert not is_affected(a, ADV)


def test_sla_breach_when_fix_is_old():
    adv = {**ADV, "fix_available": True, "fix_date": "2026-01-01"}
    a = {"id": "srv-6", "asset_class": "app-server", "firmware_vendor": "ami",
         "firmware_build": "edk2-stable202605", "pxe_enabled": False, "patched_cves": []}
    f = evaluate_firmware_posture(a, adv, today=date(2026, 6, 1))
    assert any(x.control == "FIRMWARE_PATCH_SLA_BREACH" and x.severity == "critical" for x in f)


def test_within_sla_is_patch_due_not_breach():
    adv = {**ADV, "fix_available": True, "fix_date": "2026-06-01"}
    a = {"id": "srv-7", "asset_class": "app-server", "firmware_vendor": "ami",
         "firmware_build": "edk2-stable202605", "pxe_enabled": False, "patched_cves": []}
    f = evaluate_firmware_posture(a, adv, today=date(2026, 6, 5))
    assert any(x.control == "FIRMWARE_PATCH_DUE" for x in f)
    assert not any(x.control == "FIRMWARE_PATCH_SLA_BREACH" for x in f)


def test_scan_estate_returns_dicts():
    assets = [{"id": "s1", "asset_class": "app-server", "firmware_vendor": "ami",
               "firmware_build": "edk2-stable202608", "pxe_enabled": True, "patched_cves": []}]
    rows = scan_estate(assets)
    assert rows and isinstance(rows[0], dict) and rows[0]["cve"] == "CVE-2026-97631"
