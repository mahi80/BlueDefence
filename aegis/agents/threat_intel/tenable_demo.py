"""Tenable findings ingestion smoke test.

Refreshes the IOC store from the Tenable mock client (real if
TENABLE_ACCESS_KEY+TENABLE_SECRET_KEY env set) and prints what flowed
through into the perimeter / EDR matchers and into vuln_discovery's
visible CVE set.

Run: python -m aegis.agents.threat_intel.tenable_demo
"""
from __future__ import annotations

import sys

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from aegis.agents.threat_intel.agent import ThreatIntelAgent


def main() -> int:
    ti = ThreatIntelAgent()
    stats = ti.refresh_from_feeds(include_mock=False, include_tenable=True)
    print(f"Tenable ingest: {stats['added']}")
    print(f"  total active IOCs: {stats['total_active']}")
    print(f"  by kind: {stats['by_kind']}")

    cves = [ioc for ioc in ti.store.all_active() if ioc.kind == "cve"]
    configs = [ioc for ioc in ti.store.all_active() if ioc.kind == "config"]
    print(f"  CVE-class findings: {len(cves)}")
    for c in cves[:5]:
        print(f"    {c.value}  conf={c.confidence:.2f}  source={c.source}  tags={c.tags}")
    print(f"  CSPM config findings: {len(configs)}")
    for c in configs[:5]:
        print(f"    {c.value}  conf={c.confidence:.2f}  tags={c.tags}")

    if not cves and not configs:
        print("ERROR: Tenable mock returned nothing", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
