"""CISA KEV + NVD 2.0 + EPSS consumer — offline, through the injectable fetch."""

import json


from aegis.agents.threat_intel import feeds
from aegis.agents.threat_intel.agent import ThreatIntelAgent
from aegis.agents.threat_intel.cve_feeds import (
    EPSS_API, KEV_FEED, NVD_API, Affected, CveIntel, parse_kev, parse_nvd_item, version_in_range,
)

KEV = {"catalogVersion": "2026.10.22", "dateReleased": "2026-10-22T12:00:00.0000Z", "count": 2, "vulnerabilities": [
    {"cveID": "CVE-2024-0001", "vendorProject": "ExampleCorp", "product": "Gateway", "vulnerabilityName": "ExampleCorp Gateway Command Injection",
     "dateAdded": "2026-10-20", "requiredAction": "Apply mitigations per vendor instructions.", "dueDate": "2026-11-10",
     "knownRansomwareCampaignUse": "Known", "cwes": ["CWE-77"]},
    {"cveID": "CVE-2023-0002", "vendorProject": "Acme", "product": "libwidget", "vulnerabilityName": "Acme libwidget Overflow",
     "dateAdded": "2024-01-05", "requiredAction": "Update.", "dueDate": "2024-01-26", "knownRansomwareCampaignUse": "Unknown", "cwes": ["CWE-120"]},
    {"cveID": "not-a-cve", "vendorProject": "x", "product": "y"},
]}


def _nvd_item(cid, score, vendor, product, **rng):
    return {"cve": {"id": cid, "published": "2026-10-01T00:00:00.000", "lastModified": "2026-10-21T00:00:00.000",
                    "descriptions": [{"lang": "es", "value": "no"}, {"lang": "en", "value": f"{cid} description"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score, "vectorString": "CVSS:3.1/AV:N/AC:L", "baseSeverity": "HIGH" if score >= 7 else "MEDIUM"}}]},
                    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}, {"lang": "en", "value": "NVD-CWE-Other"}]}],
                    "configurations": [{"nodes": [{"cpeMatch": [
                        {"vulnerable": True, "criteria": f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*", **rng},
                        {"vulnerable": False, "criteria": "cpe:2.3:o:other:os:1.0:*:*:*:*:*:*:*"}]}]}]}}


NVD_PAGE1 = {"totalResults": 3, "resultsPerPage": 2, "startIndex": 0, "vulnerabilities": [
    _nvd_item("CVE-2024-0001", 9.8, "examplecorp", "gateway", versionEndExcluding="2.4.1"),
    _nvd_item("CVE-2025-0003", 7.5, "acme", "lib-widget", versionStartIncluding="1.0.0", versionEndIncluding="1.9.9")]}
NVD_PAGE2 = {"totalResults": 3, "resultsPerPage": 2, "startIndex": 2, "vulnerabilities": [
    _nvd_item("CVE-2025-0004", 5.3, "acme", "lib-widget", versionStartExcluding="2.0.0", versionEndExcluding="2.2.0")]}
EPSS = {"data": [{"cve": "CVE-2024-0001", "epss": "0.94"}, {"cve": "CVE-2023-0002", "epss": "0.12"}]}


class Fetch:
    def __init__(self, *, fail=()):
        self.urls = []; self.fail = set(fail)

    def __call__(self, url, headers=None, timeout_s=30.0):
        self.urls.append((url, dict(headers or {})))
        if any(f in url for f in self.fail):
            raise ConnectionError("403 rate limited")
        if url.startswith(KEV_FEED):
            return KEV
        if url.startswith(EPSS_API):
            return EPSS
        if url.startswith(NVD_API):
            if "cveId=" in url:
                cid = url.split("cveId=")[1]
                return {"totalResults": 1, "resultsPerPage": 1, "vulnerabilities": [_nvd_item(cid, 6.1, "solo", "thing", versionEndExcluding="9")]}
            return NVD_PAGE2 if "startIndex=2" in url else NVD_PAGE1
        raise AssertionError(url)


def _intel(tmp_path, **kw):
    sleeps = []
    ti = CveIntel(tmp_path / "ti", fetch=kw.pop("fetch", Fetch()), clock=kw.pop("clock", lambda: 1_800_000_000.0), sleep=sleeps.append, **kw)
    ti._sleeps = sleeps
    return ti


def test_parsers_handle_public_shapes():
    kev = parse_kev(KEV)
    assert [e.cve_id for e in kev] == ["CVE-2024-0001", "CVE-2023-0002"] and kev[0].ransomware and not kev[1].ransomware
    r = parse_nvd_item(NVD_PAGE1["vulnerabilities"][0])
    assert r.cvss == 9.8 and r.severity == "high" and r.cwes == ("CWE-79",) and r.description.endswith("description")
    assert r.affected == (Affected("examplecorp", "gateway", "", "", "", "2.4.1", "*"),)        # non-vulnerable CPE dropped
    assert parse_nvd_item({"cve": {"id": "junk"}}) is None


def test_version_ranges():
    a = Affected("acme", "libwidget", start_incl="1.0.0", end_incl="1.9.9")
    assert version_in_range("1.5", a) and version_in_range("1.9.9", a) and not version_in_range("2.0", a) and not version_in_range("0.9", a)
    b = Affected("acme", "libwidget", start_excl="2.0.0", end_excl="2.2.0")
    assert version_in_range("2.1", b) and not version_in_range("2.0.0", b) and not version_in_range("2.2.0", b)
    assert version_in_range("3.1.4", Affected("x", "y", exact="3.1.4")) and not version_in_range("3.1.5", Affected("x", "y", exact="3.1.4"))
    assert not version_in_range("1.0", Affected("x", "y", exact="-"))                       # no version info → no claim
    assert not version_in_range("garbage", a)


def test_refresh_kev_nvd_epss_and_cache_roundtrip(tmp_path):
    f = Fetch(); ti = _intel(tmp_path, fetch=f)
    out = ti.refresh(days=7)
    assert out["kev_new"] == 2 and out["nvd_updated"] == 3 and out["epss_added"] == 2 and out["last_error"] == ""
    assert ti._sleeps == [6.5]                                                                 # one page boundary, no key → 5/30 s pacing
    assert all("apiKey" not in h for u, h in f.urls if u.startswith(NVD_API))
    rec = ti.get("CVE-2024-0001")
    assert rec.cvss == 9.8 and rec.kev.ransomware and rec.epss == 0.94 and rec.risk_inputs() == {"cvss": 9.8, "epss": 0.94, "kev": True, "poc_available": True}
    kev_only = ti.get("CVE-2023-0002")                                                        # in KEV, not (yet) in NVD cache
    assert kev_only.source == "kev" and kev_only.kev.product == "libwidget" and kev_only.epss == 0.12 and kev_only.cvss is None
    # second instance reads the cache, no network
    f2 = Fetch(); ti2 = CveIntel(tmp_path / "ti", fetch=f2, sleep=lambda s: None)
    assert len(ti2.kev) == 2 and len(ti2.cves) == 3 and ti2.get("CVE-2024-0001").kev is not None and ti2.epss["CVE-2024-0001"] == 0.94
    assert ti2.refresh_kev() == 0 and f2.urls == []                                            # inside the KEV TTL
    assert ti2.refresh_kev(force=True) == 0 and len(f2.urls) == 1                               # forced, nothing new
    # incremental NVD: next pull starts where the last ended
    ti2.refresh_nvd(days=7)
    assert "lastModStartDate=2026-12-" not in f2.urls[-1][0] and ti2.meta["nvd"]["last_mod_end"].endswith("Z")


def test_affected_matches_cpe_ranges_and_ranks_kev_first(tmp_path):
    ti = _intel(tmp_path); ti.refresh()
    hits = ti.affected("lib_widget", "1.4.2")
    assert [h.cve_id for h in hits] == ["CVE-2025-0003"]                                        # name normalised, in range
    assert [h.cve_id for h in ti.affected("libwidget", "2.1.0")] == ["CVE-2025-0004"]
    assert ti.affected("libwidget", "2.5.0") == [] and ti.affected("nothing", "1") == []
    assert [h.cve_id for h in ti.affected("gateway", "2.3.0")] == ["CVE-2024-0001"] and ti.affected("gateway", "2.4.1") == []
    assert [e.cve_id for e in ti.kev_for("gateway", "examplecorp")] == ["CVE-2024-0001"] and ti.kev_for("gateway", "acme") == []


def test_iocs_carry_rich_tags_and_feed_the_store(tmp_path):
    ti = _intel(tmp_path); ti.refresh()
    iocs = ti.iocs()
    t = {i.value: set(i.tags) for i in iocs}
    assert {"known-exploited", "ransomware", "vendor:examplecorp", "product:gateway", "due:2026-11-10", "cvss:high", "cwe-77"} <= t["CVE-2024-0001"]
    assert "ransomware" not in t["CVE-2023-0002"] and all(i.kind == "cve" and i.ttl_seconds == 86400 * 90 for i in iocs)
    agent = ThreatIntelAgent(cve_intel=ti)
    res = agent.refresh_from_feeds(include_mock=False, include_kev=True, include_nvd=True)
    assert res["added"]["cisa.kev"] == 2 and res["by_kind"]["cve"] == 2
    assert agent.lookup_ioc("CVE-2024-0001").source == "cisa.kev"
    assert feeds.pull_cisa_kev(ti)[0].source == "cisa.kev"


def test_network_failure_keeps_last_good_cache(tmp_path):
    ti = _intel(tmp_path); ti.refresh()
    bad = CveIntel(tmp_path / "ti", fetch=Fetch(fail=(KEV_FEED, NVD_API, EPSS_API)), clock=lambda: 1_800_100_000.0, sleep=lambda s: None)
    out = bad.refresh(days=7)
    assert out["kev_new"] == 0 and out["nvd_updated"] == 0 and out["last_error"].startswith(("kev:", "nvd:", "epss:"))
    assert len(bad.kev) == 2 and len(bad.cves) == 3                                            # last good data still served


def test_nvd_api_key_header_and_explicit_ids(tmp_path):
    f = Fetch(); ti = _intel(tmp_path, fetch=f, nvd_api_key="k-123")
    n = ti.refresh_nvd(days=1, cve_ids=["CVE-2026-0009", "CVE-2024-0001", "bad"])
    assert n == 4 and ti.get("CVE-2026-0009").cvss == 6.1
    nvd_calls = [h for u, h in f.urls if u.startswith(NVD_API)]
    assert nvd_calls and all(h.get("apiKey") == "k-123" for h in nvd_calls) and ti._sleeps and max(ti._sleeps) == 0.7


def test_dependency_scan_uses_live_intel_and_dedups_static_table(tmp_path):
    from aegis.agents.vuln_discovery import tools
    ti = _intel(tmp_path); ti.refresh()
    f = tools.dependency_scan({"lib-widget": "1.2.0", "gateway": "2.0", "harmless": "1.0"}, intel=ti)
    ids = {x.id for x in f}
    assert ids == {"VULN-CVE-2025-0003-lib-widget", "VULN-CVE-2024-0001-gateway"}
    gw = next(x for x in f if "gateway" in x.id)
    assert gw.kev and gw.epss == 0.94 and gw.severity == "critical" and "ransomware" in gw.evidence and gw.recommended_remediation.startswith("Apply")
    assert tools.dependency_scan({"harmless": "1.0"}, intel=ti) == [] and tools.dependency_scan({"lib-widget": "1.2.0"}) == []   # no intel → static only


def test_cli_and_env_switch(tmp_path, monkeypatch, capsys):
    from aegis.agents.threat_intel import cve_feeds
    monkeypatch.setattr(cve_feeds, "_urlopen_json", Fetch())
    monkeypatch.setattr(cve_feeds.time, "sleep", lambda s: None)
    assert cve_feeds.main(["--cache", str(tmp_path / "c"), "refresh", "--days", "3"]) == 0
    assert json.loads(capsys.readouterr().out)["kev_total"] == 2
    assert cve_feeds.main(["--cache", str(tmp_path / "c"), "affected", "libwidget", "1.5"]) == 0
    assert "CVE-2025-0003" in capsys.readouterr().out
    assert cve_feeds.main(["--cache", str(tmp_path / "c"), "show", "CVE-9999-9999"]) == 0
    monkeypatch.delenv("AEGIS_CVE_INTEL", raising=False)
    assert cve_feeds.cve_intel_from_env() is None
    monkeypatch.setenv("AEGIS_CVE_INTEL", "1"); monkeypatch.setenv("AEGIS_TI_CACHE", str(tmp_path / "c"))
    assert len(cve_feeds.cve_intel_from_env().kev) == 2
