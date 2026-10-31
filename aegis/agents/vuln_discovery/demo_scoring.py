"""Demo: how risk scoring re-ranks findings vs CVSS-only.

Three illustrative findings:
  A. CVSS 7.5, EPSS 0.05, no KEV, no PoC          (looks bad on CVSS, low real risk)
  B. CVSS 7.5, EPSS 0.10, KEV-listed, PoC public  (same CVSS, much higher real risk)
  C. CVSS 9.8, EPSS 0.97, KEV-listed, PoC public  (top priority)

Run:
  python -m aegis.agents.vuln_discovery.demo_scoring
"""
from __future__ import annotations

from .tools import Finding, _enrich_with_score


def main() -> int:
    samples = [
        Finding(
            id="DEMO-A", severity="info", confidence=0.95, category="dependency_cve",
            affected_component="libfoo==1.0", evidence="High CVSS but no exploitation signal",
            recommended_remediation="Patch on next maintenance window",
            cvss_estimate=7.5, epss=0.05, kev=False, poc_available=False,
        ),
        Finding(
            id="DEMO-B", severity="info", confidence=0.95, category="dependency_cve",
            affected_component="libbar==2.3", evidence="Same CVSS as A, but KEV + PoC public",
            recommended_remediation="Patch this week",
            cvss_estimate=7.5, epss=0.10, kev=True, poc_available=True,
        ),
        Finding(
            id="DEMO-C", severity="info", confidence=0.95, category="dependency_cve",
            affected_component="log4j==2.14.1", evidence="Log4Shell - all signals lit up",
            recommended_remediation="Stop deploys; emergency patch tonight",
            cvss_estimate=10.0, epss=0.97, kev=True, poc_available=True,
        ),
    ]

    print(f"\n{'ID':<8} {'CVSS':<5} {'EPSS':<5} {'KEV':<4} {'PoC':<4} {'risk':<6} {'severity':<10}")
    print("-" * 60)
    for f in samples:
        _enrich_with_score(f)
        print(
            f"{f.id:<8} {f.cvss_estimate:<5.1f} {f.epss:<5.2f} "
            f"{'Y' if f.kev else 'N':<4} {'Y' if f.poc_available else 'N':<4} "
            f"{f.risk_score:<6.3f} {f.severity:<10}"
        )

    print("\nNote: A and B have IDENTICAL CVSS but very different priority.")
    print("CVSS-only scoring would rank them equally; SOC drowns in A-class noise.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
