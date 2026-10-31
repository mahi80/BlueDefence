"""Multi-region IOC sync demo.

Stands up two ThreatIntelAgent instances (region A in Mumbai, region B
in Bengaluru), seeds them differently, and demonstrates that pulling
A->B converges B's store. Same pattern works production with mTLS.

Run:
  python -m aegis.agents.threat_intel.sync_demo
"""
from __future__ import annotations

import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from .feeds import pull_mock_seed
from .store import IOC, IOCStore
from .sync import PeerEndpoint, pull_from_peer


def main() -> int:
    print("=" * 70)
    print("AEGIS multi-region IOC sync demo")
    print("=" * 70)

    # Region A (Mumbai) — has the mock seed + a Mumbai-only IOC
    store_a = IOCStore()
    store_a.add_many(pull_mock_seed())
    store_a.add(IOC(
        kind="ip", value="103.21.198.4",
        confidence=0.93, source="mumbai_dc_detection",
        tags=("scanner", "ap-south-mumbai"),
        last_seen=time.time(),
    ))

    # Region B (Bengaluru) — has only a Bengaluru-only IOC
    store_b = IOCStore()
    store_b.add(IOC(
        kind="domain", value="phish.bengaluru.test",
        confidence=0.91, source="blr_dc_detection",
        tags=("phishing", "ap-south-bengaluru"),
        last_seen=time.time(),
    ))

    print(f"\n[before sync]")
    print(f"  region A (mumbai)    -> {store_a.stats().total} IOCs: {store_a.stats().by_kind}")
    print(f"  region B (bengaluru) -> {store_b.stats().total} IOCs: {store_b.stats().by_kind}")

    # Stand up A's peer endpoint
    peer_a = PeerEndpoint(store_a, region="ap-south-1-mumbai")
    peer_a.start()
    print(f"\n[peer A] serving at {peer_a.url}")

    # B pulls from A
    print(f"\n[pull A -> B]")
    result_ba = pull_from_peer(store_b, peer_a.url, trust_factor=0.95)
    print(f"  received={result_ba['received']}  merged={result_ba['merged']}  "
          f"store {result_ba['store_before']}->{result_ba['store_after']}")

    # Now A pulls from B (B's endpoint must also be up)
    peer_b = PeerEndpoint(store_b, region="ap-south-1-bengaluru")
    peer_b.start()
    print(f"\n[peer B] serving at {peer_b.url}")
    print(f"\n[pull B -> A]")
    result_ab = pull_from_peer(store_a, peer_b.url, trust_factor=0.95)
    print(f"  received={result_ab['received']}  merged={result_ab['merged']}  "
          f"store {result_ab['store_before']}->{result_ab['store_after']}")

    print(f"\n[after sync]")
    print(f"  region A (mumbai)    -> {store_a.stats().total} IOCs: {store_a.stats().by_kind}")
    print(f"  region B (bengaluru) -> {store_b.stats().total} IOCs: {store_b.stats().by_kind}")

    # Verify convergence: every IOC in A should be in B and vice versa
    a_keys = {(i.kind, i.value) for i in store_a.all_active()}
    b_keys = {(i.kind, i.value) for i in store_b.all_active()}
    diff_in_a_only = a_keys - b_keys
    diff_in_b_only = b_keys - a_keys
    converged = not diff_in_a_only and not diff_in_b_only

    print(f"\n[convergence check]")
    print(f"  in A only:  {sorted(diff_in_a_only)}")
    print(f"  in B only:  {sorted(diff_in_b_only)}")
    print(f"  converged:  {'YES' if converged else 'NO'}")

    # Spot check that the mumbai-only IOC made it to B with peer attribution
    mumbai_ioc = store_b.lookup("103.21.198.4", kind="ip")
    print(f"\n[spot check] mumbai-detected IOC visible in B:")
    if mumbai_ioc:
        print(f"  kind=ip value=103.21.198.4 source={mumbai_ioc.source}")
        print(f"  confidence={mumbai_ioc.confidence:.3f}  (peer trust factor 0.95 applied)")
        print(f"  tags={list(mumbai_ioc.tags)}")
    else:
        print("  NOT FOUND — sync failed")

    peer_a.stop()
    peer_b.stop()

    return 0 if converged else 1


if __name__ == "__main__":
    sys.exit(main())
