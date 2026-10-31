"""Firmware-patch governance — policy-as-code for the server fleet.

Where the NDR fast path handles a live PXE firmware attack on the wire, this is the
posture side: given the asset inventory and a firmware advisory, it flags the controls
that matter for a flaw like CVE-2026-97631 —

  1. network boot (PXE) enabled on an asset that does not need it, and
  2. an affected firmware that is unpatched (past its SLA once a fix ships, or awaiting
     a vendor fix and so owed the interim mitigation).

Pure evaluation: it reads inventory + advisory and returns findings. It takes no action
and needs no network. A finding feeds the governance report / dashboard; remediation is
the platform team's change under HITL.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import date


# Days to patch once a vendor fix is available, by advisory severity.
_PATCH_SLA_DAYS = {"critical": 14, "high": 30, "medium": 90, "low": 180}
# Asset classes for which network boot is a legitimate requirement.
_PXE_REQUIRED_CLASSES = frozenset({"provisioning", "bare-metal-pool", "pxe-installer"})


# Seed advisory (facts per the TianoCore / vendor advisories, Oct 2026).
ADVISORY_CVE_2026_97631 = {
    "cve": "CVE-2026-97631",
    "cvss": 9.5,
    "severity": "critical",
    "component": "EDK II PXE boot (NetworkPkg/UefiPxeBcDxe)",
    "affects": {
        "firmware_vendors": ["ami", "insyde", "phoenix", "project-mu", "edk2"],
        "edk2_max": "edk2-stable202608",
    },
    "fix_available": False,          # no stable EDK II release carried the fix as of 2026-10-28
    "fix_date": None,                # set to the stable-release date once a vendor ships it
    "disclosed": "2026-10-22",
    "mitigation": "disable PXE/network boot where unneeded; monitor boot-time ICMP; "
                  "apply the vendor firmware update when shipped",
}


@dataclass
class FirmwareFinding:
    control: str
    severity: str          # critical | high | medium
    asset: str
    cve: str
    detail: str

    def as_dict(self) -> dict:
        return asdict(self)


def _edk2_num(tag: str | None) -> int | None:
    """YYYYMM from an ``edk2-stable<YYYYMM>`` tag, for an ordered comparison; None if not parseable."""
    if not tag:
        return None
    marker = "edk2-stable"
    if marker in tag:
        digits = "".join(c for c in tag.split(marker, 1)[1] if c.isdigit())[:6]
        return int(digits) if digits else None
    return None


def is_affected(asset: dict, advisory: dict) -> bool:
    """Affected = firmware vendor is on the advisory's list, and (when both are known) the
    asset's EDK II build is at or below the last-affected tag. Vendor match with no build
    info is treated as affected (conservative)."""
    aff = advisory.get("affects", {}) or {}
    vendor = str(asset.get("firmware_vendor") or "").lower()
    if vendor and vendor not in {str(v).lower() for v in aff.get("firmware_vendors", [])}:
        return False
    if not vendor:
        return False
    asset_num, max_num = _edk2_num(asset.get("firmware_build")), _edk2_num(aff.get("edk2_max"))
    if asset_num is not None and max_num is not None:
        return asset_num <= max_num
    return True


def evaluate_firmware_posture(asset: dict, advisory: dict, today: date | None = None) -> list[FirmwareFinding]:
    """Policy findings for one asset against one firmware advisory."""
    today = today or date.today()
    cve = str(advisory.get("cve") or "")
    sev = str(advisory.get("severity") or "high")
    out: list[FirmwareFinding] = []
    aid = str(asset.get("id") or "unknown")

    # 1) PXE enabled where it is not required.
    if asset.get("pxe_enabled") and not (
            asset.get("required_network_boot") or asset.get("asset_class") in _PXE_REQUIRED_CLASSES):
        out.append(FirmwareFinding(
            "PXE_ENABLED_UNNEEDED", "high", aid, cve,
            "Network boot (PXE) enabled on an asset that does not require it — disable it to remove the "
            f"boot-time attack surface ({cve})"))

    # 2) Affected and not yet patched for this CVE.
    if is_affected(asset, advisory) and cve not in {str(c) for c in (asset.get("patched_cves") or [])}:
        if advisory.get("fix_available"):
            fix_day = advisory.get("fix_date") or advisory.get("disclosed")
            try:
                elapsed = (today - date.fromisoformat(str(fix_day))).days
            except ValueError:
                elapsed = 0
            sla = _PATCH_SLA_DAYS.get(sev, 30)
            breached = elapsed > sla
            out.append(FirmwareFinding(
                "FIRMWARE_PATCH_SLA_BREACH" if breached else "FIRMWARE_PATCH_DUE",
                "critical" if breached else "high", aid, cve,
                f"Affected by {cve} (CVSS {advisory.get('cvss')}); vendor fix available, unpatched for "
                f"{elapsed}d (SLA {sla}d)"))
        else:
            out.append(FirmwareFinding(
                "FIRMWARE_FIX_PENDING", "high", aid, cve,
                f"Affected by {cve} (CVSS {advisory.get('cvss')}); no vendor firmware fix yet — apply the interim "
                f"mitigation now ({advisory.get('mitigation')}) and track the vendor advisory"))
    return out


def scan_estate(assets: list[dict], advisory: dict = ADVISORY_CVE_2026_97631,
                today: date | None = None) -> list[dict]:
    """Evaluate every asset; return findings as plain dicts for the governance report."""
    findings: list[dict] = []
    for a in assets or []:
        if isinstance(a, dict):
            findings.extend(f.as_dict() for f in evaluate_firmware_posture(a, advisory, today))
    return findings


__all__ = ["FirmwareFinding", "ADVISORY_CVE_2026_97631", "is_affected",
           "evaluate_firmware_posture", "scan_estate"]
