"""CISA KEV + NVD 2.0 consumer (list item #7): the vulnerability half of threat intel.

The IOC store carries IPs/domains/hashes; this module carries **CVE knowledge** — what is
known-exploited (KEV), how severe and what it affects (NVD CVSS + CPE), and how likely to be
exploited (EPSS) — and turns it into three things the rest of AEGIS already consumes:

    CveIntel.iocs()                  → ``kind="cve"`` IOCs with rich tags for the IOCStore (feeds.pull_cisa_kev)
    CveIntel.affected(pkg, version)  → live replacement for vuln_discovery's static CVE table (dependency_scan)
    CveIntel.get(cve_id)             → one merged record (cvss / kev / epss / cwes / products) for enrichment

Offline-first: everything is cached as JSON under ``cache_dir`` (default ``~/.cache/aegis-threat-intel``),
refreshes are incremental (KEV by catalog version, NVD by ``lastModStartDate`` window), and every
network call goes through one injectable ``fetch(url) -> dict`` so tests and air-gapped hosts never
touch the internet. NVD is rate-limited (5 req / 30 s without a key, 50 with ``NVD_API_KEY``); the
consumer sleeps between pages and gives up cleanly on 403/503 — the last good cache stays, like
every other feed here.

    python -m aegis.agents.threat_intel.cve_feeds refresh --days 7      # KEV catalog + NVD last 7 days
    python -m aegis.agents.threat_intel.cve_feeds show CVE-2024-3400
    python -m aegis.agents.threat_intel.cve_feeds affected openssl 3.0.1
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from .store import IOC

_log = logging.getLogger("aegis.threat_intel.cve")

KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"
NVD_PAGE = 2000
NVD_MAX_WINDOW_DAYS = 120            # NVD rejects lastMod windows longer than this
KEV_TTL_S = 6 * 3600                 # CISA publishes a few times a week; re-pull at most every 6 h
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


# --------------------------------------------------------------------------- records

@dataclass(frozen=True)
class KevEntry:
    cve_id: str
    vendor: str
    product: str
    name: str
    date_added: str
    due_date: str
    ransomware: bool
    cwes: tuple[str, ...] = ()
    action: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Affected:
    vendor: str
    product: str
    start_incl: str = ""
    start_excl: str = ""
    end_incl: str = ""
    end_excl: str = ""
    exact: str = ""                 # a single version in the CPE itself ("*" = any)


@dataclass
class CveRecord:
    cve_id: str
    cvss: Optional[float] = None
    cvss_vector: str = ""
    severity: str = ""
    cwes: tuple[str, ...] = ()
    affected: tuple[Affected, ...] = ()
    published: str = ""
    last_modified: str = ""
    description: str = ""
    kev: Optional[KevEntry] = None
    epss: Optional[float] = None
    source: str = "nvd"

    def to_dict(self) -> dict:
        d = asdict(self); d["kev"] = self.kev.to_dict() if self.kev else None
        return d

    @property
    def exploited(self) -> bool:
        return self.kev is not None

    def risk_inputs(self) -> dict:
        """The four inputs vuln_discovery's risk formula takes."""
        return {"cvss": self.cvss, "epss": self.epss, "kev": self.exploited, "poc_available": self.exploited}


# --------------------------------------------------------------------------- parsing

def parse_kev(payload: dict) -> list[KevEntry]:
    out = []
    for v in payload.get("vulnerabilities", []) or []:
        cid = str(v.get("cveID", "")).upper()
        if not _CVE_RE.match(cid):
            continue
        out.append(KevEntry(cid, str(v.get("vendorProject", "")), str(v.get("product", "")), str(v.get("vulnerabilityName", ""))[:200],
                            str(v.get("dateAdded", "")), str(v.get("dueDate", "")),
                            str(v.get("knownRansomwareCampaignUse", "")).strip().lower() == "known",
                            tuple(str(c) for c in (v.get("cwes") or [])), str(v.get("requiredAction", ""))[:300]))
    return out


def _cpe_parts(cpe: str) -> tuple[str, str, str]:
    # cpe:2.3:a:vendor:product:version:update:...
    p = cpe.split(":")
    if len(p) < 6 or p[0] != "cpe":
        return "", "", ""
    return p[3].lower(), p[4].lower(), p[5]


def parse_nvd_item(item: dict) -> Optional[CveRecord]:
    c = item.get("cve") or item
    cid = str(c.get("id", "")).upper()
    if not _CVE_RE.match(cid):
        return None
    metrics = c.get("metrics") or {}
    cvss, vector, sev = None, "", ""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key) or []:
            data = m.get("cvssData") or {}
            if data.get("baseScore") is not None:
                cvss = float(data["baseScore"]); vector = str(data.get("vectorString", ""))
                sev = str(data.get("baseSeverity") or m.get("baseSeverity") or "").lower()
                break
        if cvss is not None:
            break
    cwes = tuple(sorted({str(d.get("value")) for w in c.get("weaknesses") or [] for d in w.get("description") or []
                         if str(d.get("value", "")).startswith("CWE-")}))
    affected: list[Affected] = []
    for cfg in c.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable", True):
                    continue
                vendor, product, ver = _cpe_parts(str(m.get("criteria", "")))
                if product:
                    affected.append(Affected(vendor, product, str(m.get("versionStartIncluding", "")), str(m.get("versionStartExcluding", "")),
                                             str(m.get("versionEndIncluding", "")), str(m.get("versionEndExcluding", "")), ver))
    desc = next((d.get("value", "") for d in c.get("descriptions") or [] if d.get("lang") == "en"), "")
    return CveRecord(cid, cvss, vector, sev, cwes, tuple(affected[:64]), str(c.get("published", "")), str(c.get("lastModified", "")),
                     str(desc)[:400])


# --------------------------------------------------------------------------- version matching

def _ver(v: str):
    try:
        from packaging.version import Version
        return Version(v)
    except Exception:  # noqa: BLE001
        nums = re.findall(r"\d+", v)
        return tuple(int(x) for x in nums) if nums else None


def version_in_range(version: str, a: Affected) -> bool:
    if a.exact and a.exact not in ("*", "-", ""):
        return _ver(a.exact) == _ver(version)
    v = _ver(version)
    if v is None:
        return False
    try:
        if a.start_incl and v < _ver(a.start_incl): return False
        if a.start_excl and v <= _ver(a.start_excl): return False
        if a.end_incl and v > _ver(a.end_incl): return False
        if a.end_excl and v >= _ver(a.end_excl): return False
    except TypeError:
        return False
    return bool(a.start_incl or a.start_excl or a.end_incl or a.end_excl or a.exact == "*")


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


# --------------------------------------------------------------------------- the consumer

def _urlopen_json(url: str, *, headers: Optional[dict] = None, timeout_s: float = 30.0) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "aegis-threat-intel/1.0", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310 — fixed public https feeds
        return json.loads(resp.read().decode("utf-8"))


class CveIntel:
    """KEV + NVD (+ EPSS) with a JSON cache; one injectable ``fetch``."""

    def __init__(self, cache_dir: str | Path | None = None, *, fetch: Optional[Callable[..., dict]] = None,
                 nvd_api_key: Optional[str] = None, clock: Optional[Callable[[], float]] = None, sleep: Optional[Callable[[float], None]] = None):
        self.cache_dir = Path(cache_dir or os.environ.get("AEGIS_TI_CACHE") or Path.home() / ".cache" / "aegis-threat-intel")
        self._fetch = fetch or _urlopen_json
        self._key = nvd_api_key if nvd_api_key is not None else os.environ.get("NVD_API_KEY", "")
        self._clock, self._sleep = clock or time.time, sleep or (lambda s: time.sleep(s))
        self.kev: dict[str, KevEntry] = {}
        self.cves: dict[str, CveRecord] = {}
        self.epss: dict[str, float] = {}
        self.meta: dict[str, Any] = {"kev": {}, "nvd": {}, "epss": {}}
        self.last_error = ""
        self._load()

    # ---- cache
    def _load(self) -> None:
        try:
            m = self.cache_dir / "meta.json"
            if m.exists():
                self.meta = {**self.meta, **json.loads(m.read_text(encoding="utf-8"))}
            k = self.cache_dir / "kev.json"
            if k.exists():
                self.kev = {e.cve_id: e for e in parse_kev(json.loads(k.read_text(encoding="utf-8")))}
            n = self.cache_dir / "nvd.json"
            if n.exists():
                for d in json.loads(n.read_text(encoding="utf-8")).get("records", []):
                    d["affected"] = tuple(Affected(**a) for a in d.get("affected", [])); d["cwes"] = tuple(d.get("cwes", ())); d.pop("kev", None)
                    r = CveRecord(**d); self.cves[r.cve_id] = r
            e = self.cache_dir / "epss.json"
            if e.exists():
                self.epss = {k: float(v) for k, v in json.loads(e.read_text(encoding="utf-8")).items()}
        except Exception as exc:  # noqa: BLE001 — a corrupt cache is rebuilt by the next refresh
            _log.warning("cve cache unreadable (%s); starting empty", exc)
        self._link()

    def _save(self) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        (self.cache_dir / "nvd.json").write_text(json.dumps({"records": [r.to_dict() | {"kev": None} for r in self.cves.values()]}), encoding="utf-8")
        (self.cache_dir / "epss.json").write_text(json.dumps(self.epss), encoding="utf-8")
        (self.cache_dir / "meta.json").write_text(json.dumps(self.meta, indent=2), encoding="utf-8")

    def _link(self) -> None:
        for cid, r in self.cves.items():
            r.kev = self.kev.get(cid); r.epss = self.epss.get(cid, r.epss)

    # ---- refresh
    def refresh_kev(self, *, force: bool = False) -> int:
        """Full catalog (≈1 MB). Skipped inside KEV_TTL_S unless forced; new entries are counted."""
        last = float(self.meta["kev"].get("fetched_at", 0) or 0)
        if not force and self._clock() - last < KEV_TTL_S and self.kev:
            return 0
        try:
            payload = self._fetch(KEV_FEED)
        except Exception as exc:  # noqa: BLE001
            self.last_error = f"kev: {type(exc).__name__}: {str(exc)[:120]}"; _log.warning("KEV fetch failed: %s", self.last_error); return 0
        entries = parse_kev(payload)
        if not entries:
            self.last_error = "kev: empty catalog"; return 0
        before = set(self.kev)
        self.kev = {e.cve_id: e for e in entries}
        self.meta["kev"] = {"fetched_at": self._clock(), "catalog_version": payload.get("catalogVersion"), "date_released": payload.get("dateReleased"),
                            "count": len(self.kev)}
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        (self.cache_dir / "kev.json").write_text(json.dumps(payload), encoding="utf-8")
        self._link(); self._save()
        return len(set(self.kev) - before)

    def _nvd_headers(self) -> dict:
        return {"apiKey": self._key} if self._key else {}

    def _nvd_pause(self) -> float:
        return 0.7 if self._key else 6.5          # 50/30 s with a key, 5/30 s without

    def refresh_nvd(self, *, days: int = 7, since: Optional[str] = None, max_pages: int = 10, cve_ids: Iterable[str] = ()) -> int:
        """Incremental pull by ``lastModStartDate`` (default: since the last refresh, capped at ``days``),
        plus any explicit ``cve_ids`` (one call each). Returns records added or updated."""
        updated = 0
        start = since or self.meta["nvd"].get("last_mod_end")
        end_dt = datetime.fromtimestamp(self._clock(), timezone.utc)
        start_dt = datetime.fromisoformat(start.replace("Z", "+00:00")) if start else end_dt - timedelta(days=days)
        if start_dt < end_dt - timedelta(days=min(days, NVD_MAX_WINDOW_DAYS)):
            start_dt = end_dt - timedelta(days=min(days, NVD_MAX_WINDOW_DAYS))
        fmt = lambda d: d.strftime("%Y-%m-%dT%H:%M:%S.000")       # noqa: E731 — NVD's exact timestamp shape
        idx, pages = 0, 0
        while pages < max_pages:
            q = urllib.parse.urlencode({"lastModStartDate": fmt(start_dt), "lastModEndDate": fmt(end_dt), "resultsPerPage": NVD_PAGE, "startIndex": idx})
            try:
                payload = self._fetch(f"{NVD_API}?{q}", headers=self._nvd_headers())
            except Exception as exc:  # noqa: BLE001 — 403 (rate limit) / 503 end the pull; the cache stays
                self.last_error = f"nvd: {type(exc).__name__}: {str(exc)[:120]}"; _log.warning("NVD fetch failed: %s", self.last_error); break
            for it in payload.get("vulnerabilities", []) or []:
                r = parse_nvd_item(it)
                if r:
                    self.cves[r.cve_id] = r; updated += 1
            total = int(payload.get("totalResults", 0) or 0); idx += int(payload.get("resultsPerPage", NVD_PAGE) or NVD_PAGE); pages += 1
            if idx >= total:
                self.meta["nvd"] = {"last_mod_end": fmt(end_dt) + "Z", "fetched_at": self._clock(), "count": len(self.cves)}
                break
            self._sleep(self._nvd_pause())
        for cid in cve_ids:
            cid = cid.upper()
            if not _CVE_RE.match(cid) or cid in self.cves:
                continue
            try:
                payload = self._fetch(f"{NVD_API}?cveId={cid}", headers=self._nvd_headers())
            except Exception as exc:  # noqa: BLE001
                self.last_error = f"nvd:{cid}: {type(exc).__name__}"; continue
            for it in payload.get("vulnerabilities", []) or []:
                r = parse_nvd_item(it)
                if r:
                    self.cves[r.cve_id] = r; updated += 1
            self._sleep(self._nvd_pause())
        self._link(); self._save()
        return updated

    def refresh_epss(self, cve_ids: Optional[Iterable[str]] = None) -> int:
        """EPSS for the given ids (default: every KEV id we hold), batched 100 per call."""
        ids = sorted({c.upper() for c in (cve_ids if cve_ids is not None else self.kev)} - set(self.epss))
        n = 0
        for i in range(0, len(ids), 100):
            try:
                payload = self._fetch(f"{EPSS_API}?cve={','.join(ids[i:i + 100])}")
            except Exception as exc:  # noqa: BLE001
                self.last_error = f"epss: {type(exc).__name__}"; break
            for d in payload.get("data", []) or []:
                try:
                    self.epss[str(d["cve"]).upper()] = float(d["epss"]); n += 1
                except (KeyError, TypeError, ValueError):
                    continue
        if n:
            self.meta["epss"] = {"fetched_at": self._clock(), "count": len(self.epss)}
            self._link(); self._save()
        return n

    def refresh(self, *, days: int = 7, epss: bool = True) -> dict:
        return {"kev_new": self.refresh_kev(), "nvd_updated": self.refresh_nvd(days=days), "epss_added": self.refresh_epss() if epss else 0,
                "kev_total": len(self.kev), "nvd_total": len(self.cves), "last_error": self.last_error}

    # ---- lookups
    def get(self, cve_id: str) -> Optional[CveRecord]:
        cid = cve_id.upper()
        r = self.cves.get(cid)
        if r is None and cid in self.kev:
            k = self.kev[cid]
            r = CveRecord(cid, None, "", "", k.cwes, (Affected(k.vendor.lower(), _norm(k.product)),), k.date_added, "", k.name, k, self.epss.get(cid), source="kev")
        return r

    def kev_for(self, product: str, vendor: str = "") -> list[KevEntry]:
        p, v = _norm(product), _norm(vendor)
        return [e for e in self.kev.values() if p and p in _norm(e.product) and (not v or v in _norm(e.vendor))]

    def affected(self, package: str, version: str) -> list[CveRecord]:
        """CVEs whose NVD CPE ranges cover ``package==version`` (product name normalised)."""
        p = _norm(package)
        out = []
        for r in self.cves.values():
            if any(_norm(a.product) == p and version_in_range(version, a) for a in r.affected):
                out.append(r)
        out.sort(key=lambda r: (-(1 if r.kev else 0), -(r.cvss or 0)))
        return out

    def iocs(self) -> list[IOC]:
        """KEV entries as CVE-class IOCs for the IOCStore (rich tags; 90-day TTL — KEV items don't expire quickly)."""
        now = self._clock(); out = []
        for e in self.kev.values():
            r = self.cves.get(e.cve_id)
            tags = ["known-exploited", f"vendor:{_norm(e.vendor)}", f"product:{_norm(e.product)}", f"due:{e.due_date}"]
            if e.ransomware:
                tags.append("ransomware")
            if r and r.severity:
                tags.append(f"cvss:{r.severity}")
            tags += [c.lower() for c in e.cwes[:3]]
            out.append(IOC(kind="cve", value=e.cve_id, confidence=0.99, source="cisa.kev", first_seen=now, last_seen=now,
                           tags=tuple(tags), ttl_seconds=86400 * 90))
        return out

    def stats(self) -> dict:
        return {"kev": len(self.kev), "nvd": len(self.cves), "epss": len(self.epss), "kev_ransomware": sum(1 for e in self.kev.values() if e.ransomware),
                "meta": self.meta, "last_error": self.last_error}


def cve_intel_from_env() -> Optional[CveIntel]:
    """``AEGIS_CVE_INTEL=1`` turns the consumer on (cache from ``AEGIS_TI_CACHE``, key from ``NVD_API_KEY``)."""
    if os.environ.get("AEGIS_CVE_INTEL", "0").strip().lower() not in {"1", "true", "yes", "on"}:
        return None
    return CveIntel()


# --------------------------------------------------------------------------- CLI

def main(argv: Optional[list[str]] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="CISA KEV + NVD + EPSS consumer")
    ap.add_argument("--cache", default=None)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("refresh"); r.add_argument("--days", type=int, default=7); r.add_argument("--no-epss", action="store_true"); r.add_argument("--force-kev", action="store_true")
    s = sub.add_parser("show"); s.add_argument("cve_id")
    a = sub.add_parser("affected"); a.add_argument("package"); a.add_argument("version")
    sub.add_parser("stats")
    args = ap.parse_args(argv)
    ti = CveIntel(args.cache)
    if args.cmd == "refresh":
        if args.force_kev:
            ti.refresh_kev(force=True)
        print(json.dumps(ti.refresh(days=args.days, epss=not args.no_epss), indent=2))
    elif args.cmd == "show":
        rec = ti.get(args.cve_id)
        print(json.dumps(rec.to_dict(), indent=2) if rec else f"{args.cve_id}: not in cache (run refresh, or refresh_nvd(cve_ids=[...]))")
    elif args.cmd == "affected":
        for rec in ti.affected(args.package, args.version):
            print(f"{rec.cve_id}  cvss={rec.cvss}  kev={'yes' if rec.kev else 'no'}  epss={rec.epss}  {rec.description[:80]}")
    else:
        print(json.dumps(ti.stats(), indent=2))
    return 0


__all__ = ["Affected", "CveIntel", "CveRecord", "KevEntry", "cve_intel_from_env", "parse_kev", "parse_nvd_item", "version_in_range"]

if __name__ == "__main__":
    raise SystemExit(main())
