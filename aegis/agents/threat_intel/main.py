"""Threat Intel CLI demo.

Run:
  python -m aegis.agents.threat_intel.main refresh
      Pull mock + (optional) STIX + (optional) CISA KEV; print stats.

  python -m aegis.agents.threat_intel.main lookup <ip|domain|hash>
      Look up a value across the store.

  python -m aegis.agents.threat_intel.main distribute
      Merge active IOCs into perimeter._KNOWN_BAD and edr._IOC_*.

  python -m aegis.agents.threat_intel.main analyze <advisory.txt>
      Run an advisory through the LLM analyst.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from aegis.agents.shared.llm_client import get_client

from .agent import ThreatIntelAgent


_SAMPLE_ADVISORY = """\
URGENT - CERT-In Advisory CIAD-2026-XXXX
A new credential-stuffing campaign is targeting Indian retail banks.
Indicators observed in the wild over the past 72 hours:

  IPs:        198.51.100.99, 203.0.113.150
  Domain:     malware.example.test
  MD5:        9f8d24c1aa1f0bc4e0ddcc0bb8b56f00
  CVE:        CVE-2026-99999 (auth-bypass in legacy session token validation)

The campaign uses high-velocity API calls against /api/login from
residential proxies. Recommended action: block the listed IPs at the
edge and revoke any sessions issued from them in the last 24 hours.
"""


def main() -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("refresh")
    sp_lookup = sub.add_parser("lookup")
    sp_lookup.add_argument("value")
    sp_lookup.add_argument("--kind", default=None)
    sub.add_parser("distribute")
    sp_an = sub.add_parser("analyze")
    sp_an.add_argument("path", nargs="?", default=None,
                       help="Path to advisory text; omit for built-in sample")

    args = p.parse_args()

    agent = ThreatIntelAgent(llm=get_client())

    if args.cmd == "refresh":
        result = agent.refresh_from_feeds(include_mock=True)
        print("Threat-intel refresh result:")
        for k, v in result["added"].items():
            print(f"  {k}: +{v}")
        print(f"  total active IOCs: {result['total_active']}")
        print(f"  by kind: {result['by_kind']}")
        return 0

    if args.cmd == "lookup":
        agent.refresh_from_feeds(include_mock=True)
        ioc = agent.lookup_ioc(args.value, kind=args.kind)
        if ioc is None:
            print(f"no IOC for {args.value!r}")
            return 1
        print(f"hit: kind={ioc.kind} value={ioc.value} "
              f"confidence={ioc.confidence:.2f} source={ioc.source} "
              f"tags={list(ioc.tags)}")
        return 0

    if args.cmd == "distribute":
        agent.refresh_from_feeds(include_mock=True)
        n_p = agent.distribute_to_perimeter()
        n_e = agent.distribute_to_edr()
        print(f"merged into perimeter._KNOWN_BAD:  +{n_p}")
        print(f"merged into edr matchers:           +{n_e}")
        return 0

    if args.cmd == "analyze":
        if args.path:
            text = Path(args.path).read_text(encoding="utf-8")
        else:
            text = _SAMPLE_ADVISORY
            print("(using built-in sample advisory)\n")
        chain = agent.analyze_advisory(text, advisory_id="ADV-CLI-DEMO")
        print(f"verdict:    {chain.verdict}")
        print(f"confidence: {chain.confidence:.2f}")
        print(f"summary:    {chain.metadata.get('summary', '(none)')}")
        print(f"evidence ({len(chain.evidence)}):")
        for e in chain.evidence:
            print(f"  - [{e.source}] {e.weight}: {e.signal}")
        print(f"actions ({len(chain.recommended_actions)}):")
        for a in chain.recommended_actions:
            print(f"  - {a.action_type} -> {a.target} (HITL={a.requires_hitl}): {a.reasoning[:100]}")
        print(f"store now has {agent.store.stats().total} active IOCs")
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
