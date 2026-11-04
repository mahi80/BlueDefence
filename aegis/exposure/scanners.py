"""Native vulnerability-export readers for the scanners banks run (integration plan #6, CTEM loaders).

Each reads a file the scanner already produces — an export from its console or a saved API response — so nothing
here talks to the scanner, and the exposure engine stays read-only and air-gap friendly. ``load_vulns`` recognises
the format by its shape; no flag is needed.

==========================  =====================================================================================
Scanner                     File
==========================  =====================================================================================
Qualys VMDR                 scan / vulnerability report CSV (the preamble lines before the header row are skipped)
Rapid7 InsightVM / Nexpose  "Vulnerability details" CSV, or a SQL Query Export with the same column names
Wiz                         ``vulnerabilityFindings`` GraphQL nodes (JSON), or the Vulnerability Findings CSV
Defender Vulnerability Mgmt ``GET /api/machines/SoftwareVulnerabilitiesByMachine`` (``{"value": [...]}``) or its CSV
Prisma Cloud Compute        ``/api/v1/hosts`` / ``/api/v1/images`` scan results (JSON array)
==========================  =====================================================================================

Network scanners (Qualys, Rapid7) report a port, so reachability is judged per port. Agent / cloud scanners (Wiz,
Defender, Prisma) report packages, so their findings carry ``ANY_PORT``: judged by what the workload exposes.
Fixed / resolved findings and information-only checks are dropped. Exploit signals map onto ``poc`` (a public
exploit) and ``kev`` (exploited in the wild) only where the scanner says so; the KEV / EPSS feeds fill the rest.
"""

from __future__ import annotations

import csv
import io
import re
from typing import Any

from ..posture.sources import PostureSourceError
from .engine import ANY_PORT, Vuln

_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_EC2 = re.compile(r"(?<![\w-])i-[0-9a-z]{6,17}(?![\w-])")   # EC2 instance id (hex in AWS; the samples use readable ids)


def _f(v: Any) -> float | None:
    try:
        return float(str(v).strip()) if str(v).strip() not in ("", "None", "null", "-") else None
    except (TypeError, ValueError):
        return None


def _port(v: Any) -> int | None:
    try:
        p = int(str(v).strip())
    except (TypeError, ValueError):
        return None
    return p if p > 0 else None


def _cves(*vals: Any) -> list[str | None]:
    found: list[str] = []
    for v in vals:
        items = v if isinstance(v, (list, tuple)) else [v]
        for it in items:
            for c in _CVE.findall(str(it or "")):
                c = c.upper()
                if c not in found:
                    found.append(c)
    return list(found) or [None]


def _keys(*vals: Any) -> list[str]:
    out: list[str] = []
    for v in vals:
        for part in (v if isinstance(v, (list, tuple)) else str(v or "").replace(";", ",").split(",")):
            p = str(part).strip()
            if p and p not in out:
                out.append(p)
    return out


def _col(row: dict, *names: str) -> str:
    """First non-empty value among column names (case- and space-insensitive)."""
    norm = {re.sub(r"[\s_]+", "", k or "").lower(): v for k, v in row.items()}
    for n in names:
        v = norm.get(re.sub(r"[\s_]+", "", n).lower())
        if v not in (None, ""):
            return str(v).strip()
    return ""


# ---------------------------------------------------------------------------------------------------- CSV --

def _rows_from(text: str, must: tuple[str, ...]) -> list[dict] | None:
    """CSV rows under the first line that holds every ``must`` column (Qualys reports carry a preamble)."""
    lines = list(csv.reader(io.StringIO(text)))
    want = {re.sub(r"[\s_]+", "", m).lower() for m in must}
    for i, line in enumerate(lines[:60]):
        cells = {re.sub(r"[\s_]+", "", c or "").lower() for c in line}
        if want <= cells:
            header = [c.strip() for c in line]
            return [dict(zip(header, r)) for r in lines[i + 1:] if any(x.strip() for x in r)]
    return None


def _qualys(rows: list[dict]) -> list[Vuln]:
    out: list[Vuln] = []
    for r in rows:
        typ = _col(r, "Type").lower()
        # "Ig" = information gathered (no vulnerability); "Practice" is a *potential* vulnerability — kept
        if typ in ("ig", "information gathered") or _col(r, "Vuln Status", "Status").lower() == "fixed":
            continue
        keys = _keys(_col(r, "EC2 Instance ID", "Instance ID"), _col(r, "DNS", "FQDN"), _col(r, "NetBIOS"), _col(r, "IP"))
        if not keys:
            continue
        qid = _col(r, "QID")
        for c in _cves(_col(r, "CVE ID", "CVE")):
            out.append(Vuln(asset=keys[0], asset_alt=keys[1:], cve=c, title=_col(r, "Title") or f"QID {qid}",
                            port=_port(_col(r, "Port")), protocol=(_col(r, "Protocol") or "tcp").lower(),
                            cvss=_f(_col(r, "CVSS3.1 Base", "CVSS3 Base", "CVSS Base", "CVSS")),
                            poc=bool(_col(r, "Exploitability")), source=f"qualys:{qid or '?'}"))
    return out


def _rapid7(rows: list[dict]) -> list[Vuln]:
    out: list[Vuln] = []
    for r in rows:
        code = _col(r, "Vulnerability Test Result Code", "Result Code").upper()
        if code and code not in ("VE", "VV", "VP"):     # only vulnerable-exploited / -version / -potential; NV, SD, SV,
            continue                                    # ER, DS, NT, UK, EE, OV … are not open findings
        keys = _keys(_col(r, "Asset Names", "Asset Name", "Asset Host Name"), _col(r, "Asset IP Address", "Asset IP"))
        if not keys:
            continue
        vid = _col(r, "Vulnerability ID")
        for c in _cves(_col(r, "Vulnerability CVE IDs", "Vulnerability CVE ID", "CVE IDs", "CVE")):
            out.append(Vuln(asset=keys[0], asset_alt=keys[1:], cve=c, title=_col(r, "Vulnerability Title") or vid,
                            port=_port(_col(r, "Service Port", "Port")),
                            protocol=(_col(r, "Service Protocol", "Protocol") or "tcp").lower(),
                            cvss=_f(_col(r, "Vulnerability CVSSv3 Score", "CVSSv3 Score", "Vulnerability CVSS Score")),
                            poc=(_f(_col(r, "Exploit Count", "Exploits")) or 0) > 0 or _col(r, "Exploitable").lower() in ("true", "yes"),
                            kev=_col(r, "CISA KEV", "Known Exploited").lower() in ("true", "yes"),
                            source=f"rapid7:{vid or '?'}"))
    return out


def _wiz_csv(rows: list[dict]) -> list[Vuln]:
    out: list[Vuln] = []
    for r in rows:
        # the finding's own status — a plain "Status" column can be the resource's state in some Wiz reports
        if _col(r, "FindingStatus", "Finding Status", "Status").upper() in ("RESOLVED", "REJECTED"):
            continue
        keys = _keys(*_EC2.findall(_col(r, "Provider Unique Id", "Resource Provider Unique Id", "Resource External Id")),
                     _col(r, "Resource Name", "Asset Name"), _col(r, "Resource Id", "Asset Id"))
        if not keys:
            continue
        name = _col(r, "Name", "Vulnerability", "CVE")
        out.append(Vuln(asset=keys[0], asset_alt=keys[1:], cve=_cves(name)[0],
                        title=f"{_col(r, 'Detailed Name', 'Package')} {_col(r, 'Version')}: {name}".strip(": "),
                        port=ANY_PORT, cvss=_f(_col(r, "Score", "CVSS Score")), epss=_f(_col(r, "EPSS Probability", "EPSS")),
                        poc=_col(r, "Has Exploit").lower() == "true", kev=_col(r, "Has Cisa Kev Exploit").lower() == "true",
                        source="wiz"))
    return out


def _defender_rows(rows: list[dict]) -> list[Vuln]:
    out: list[Vuln] = []
    for r in rows:
        if not isinstance(r, dict):
            raise PostureSourceError("Defender export: a vulnerability row is not an object")
        cve = _col(r, "cveId", "CVE ID")
        keys = _keys(_col(r, "deviceName", "Device Name"), _col(r, "deviceId", "Device ID"))
        if not cve or not keys:
            continue
        if _col(r, "status", "Status").lower() in ("fixed", "remediated"):    # the delta export carries fixed rows
            continue
        expl = _col(r, "exploitabilityLevel", "Exploitability Level")
        out.append(Vuln(asset=keys[0].lower(), asset_alt=keys[1:], cve=_cves(cve)[0],
                        title=f"{_col(r, 'softwareVendor', 'Software Vendor')} {_col(r, 'softwareName', 'Software Name')} "
                              f"{_col(r, 'softwareVersion', 'Software Version')}: {cve}".strip(),
                        port=ANY_PORT, cvss=_f(_col(r, "cvssScore", "CVSS Score")),
                        # a public / verified / kit exploit exists → poc; "exploited in the wild" (KEV) is left to the
                        # CISA KEV feed — Defender's levels do not say that
                        poc=expl.lower() not in ("", "noexploit", "no exploit"),
                        source="defender-vm"))
    return out


CSV_FORMATS: list[tuple[str, tuple[str, ...], Any]] = [
    ("qualys", ("QID", "IP"), _qualys),
    ("rapid7", ("Asset IP Address", "Vulnerability ID"), _rapid7),
    ("defender-vm", ("Device Name", "CVE ID"), _defender_rows),
    ("defender-vm", ("deviceName", "cveId"), _defender_rows),
    ("wiz", ("Has Exploit", "Name"), _wiz_csv),
]


def from_csv(text: str) -> tuple[str, list[Vuln]] | None:
    """(format, vulns) for a recognised scanner CSV, else None."""
    for name, must, fn in CSV_FORMATS:
        rows = _rows_from(text, must)
        if rows is not None:
            return name, fn(rows)
    return None


# --------------------------------------------------------------------------------------------------- JSON --

def _wiz_nodes(nodes: list[dict]) -> list[Vuln]:
    out: list[Vuln] = []
    for n in nodes:
        if not isinstance(n, dict):
            raise PostureSourceError("Wiz export: a finding node is not an object")
        if str(n.get("status", "OPEN")).upper() in ("RESOLVED", "REJECTED"):
            continue
        a = n.get("vulnerableAsset") if isinstance(n.get("vulnerableAsset"), dict) else {}
        keys = _keys(*_EC2.findall(str(a.get("providerUniqueId") or "")), a.get("name"), a.get("providerUniqueId"), a.get("id"))
        if not keys:
            continue
        name = str(n.get("name") or "")
        out.append(Vuln(asset=keys[0], asset_alt=keys[1:], cve=_cves(name)[0],
                        title=f"{n.get('detailedName') or ''} {n.get('version') or ''}: {name}".strip(": "),
                        port=ANY_PORT, cvss=_f(n.get("score")), epss=_f(n.get("epssProbability")),
                        poc=bool(n.get("hasExploit")), kev=bool(n.get("hasCisaKevExploit")), source="wiz"))
    return out


def _prisma(items: list[dict]) -> list[Vuln]:
    out: list[Vuln] = []
    for it in items:
        if not isinstance(it, dict):
            raise PostureSourceError("Prisma export: an item is not an object")
        tag = it.get("repoTag") if isinstance(it.get("repoTag"), dict) else {}
        image = f"{tag.get('registry') + '/' if tag.get('registry') else ''}{tag.get('repo', '')}:{tag.get('tag', '')}" if tag.get("repo") else ""
        keys = _keys(*_EC2.findall(str((it.get("cloudMetadata") or {}).get("resourceID") or "")), it.get("hostname"), image,
                     image.rsplit("/", 1)[-1] if image else "", it.get("_id"))
        if not keys:
            continue
        for v in it.get("vulnerabilities") or []:
            if not isinstance(v, dict):
                raise PostureSourceError("Prisma export: a vulnerability entry is not an object")
            # "fixed in X" means a fix is available — the vulnerable package is still installed
            risk = {str(k).lower() for k in (v.get("riskFactors") or {})}
            out.append(Vuln(asset=keys[0], asset_alt=keys[1:], cve=_cves(v.get("cve"))[0],
                            title=f"{v.get('packageName', '?')} {v.get('packageVersion', '')}: {v.get('cve') or v.get('id')}".strip(),
                            port=ANY_PORT, cvss=_f(v.get("cvss")),
                            poc=bool(v.get("exploit")) or any("exploit exists" in r for r in risk),
                            kev=any("in the wild" in r for r in risk), source="prisma"))
    return out


def _partial(what: str) -> PostureSourceError:
    return PostureSourceError(f"{what} export is one page of several — export every page (a partial export would mark "
                              "the findings on the missing pages as resolved)")


def from_json(obj: Any) -> tuple[str, list[Vuln]] | None:
    """(format, vulns) for a recognised scanner JSON document, else None. A saved page of a paged API response
    (Defender ``@odata.nextLink``, Wiz ``pageInfo.hasNextPage``) is refused rather than read as the whole estate."""
    if isinstance(obj, dict):
        data = obj.get("data") if isinstance(obj.get("data"), dict) else {}
        vf = data.get("vulnerabilityFindings") if isinstance(data.get("vulnerabilityFindings"), dict) else {}
        nodes, page = vf.get("nodes") if vf else None, vf.get("pageInfo") if vf else None
        if nodes is None and isinstance(obj.get("nodes"), list):
            nodes, page = obj["nodes"], obj.get("pageInfo")
        if isinstance(nodes, list) and (not nodes or (isinstance(nodes[0], dict) and "vulnerableAsset" in nodes[0])):
            if isinstance(page, dict) and page.get("hasNextPage"):
                raise _partial("Wiz")
            return "wiz", _wiz_nodes(nodes)
        val = obj.get("value")
        if isinstance(val, list) and val and isinstance(val[0], dict) and "cveId" in val[0]:
            if obj.get("@odata.nextLink"):
                raise _partial("Defender")
            return "defender-vm", _defender_rows(val)
        return None
    if isinstance(obj, list) and obj and isinstance(obj[0], dict):
        first = obj[0]
        if "vulnerableAsset" in first:
            return "wiz", _wiz_nodes(obj)
        if "cveId" in first and ("deviceName" in first or "deviceId" in first):
            return "defender-vm", _defender_rows(obj)
        if "vulnerabilities" in first and ("hostname" in first or "repoTag" in first or "instances" in first):
            return "prisma", _prisma(obj)
    return None


__all__ = ["CSV_FORMATS", "from_csv", "from_json"]
