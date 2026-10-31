"""Multi-region IOC sync demo — gRPC variant.

Same pattern as sync_demo.py but uses gRPC transport. Demonstrates
the production-shape sync that would run over mTLS in deployment.

Run:
  pip install grpcio
  python -m aegis.agents.threat_intel.sync_grpc_demo

Skipped silently if grpcio isn't installed (the HTTP variant in
sync_demo.py is always available).
"""
from __future__ import annotations

import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def main() -> int:
    try:
        import grpc  # noqa: F401
    except ImportError:
        print("grpcio not installed; skipping gRPC sync demo.")
        print("  install: pip install grpcio")
        print("  HTTP variant remains available: python -m aegis.agents.threat_intel.sync_demo")
        return 0

    from .feeds import pull_mock_seed
    from .store import IOC, IOCStore
    from .sync_grpc import GrpcPeerEndpoint, pull_via_grpc

    print("=" * 70)
    print("AEGIS multi-region IOC sync — gRPC variant")
    print("=" * 70)

    # Region A — Mumbai
    store_a = IOCStore()
    store_a.add_many(pull_mock_seed())
    store_a.add(IOC(
        kind="ip", value="103.21.198.4",
        confidence=0.93, source="mumbai_grpc_dc",
        tags=("scanner", "ap-south-mumbai"),
        last_seen=time.time(),
    ))

    # Region B — Bengaluru
    store_b = IOCStore()
    store_b.add(IOC(
        kind="domain", value="phish.bengaluru.test",
        confidence=0.91, source="blr_grpc_dc",
        tags=("phishing",),
        last_seen=time.time(),
    ))

    print(f"\n[before sync]")
    print(f"  region A (mumbai)    -> {store_a.stats().total} IOCs")
    print(f"  region B (bengaluru) -> {store_b.stats().total} IOCs")

    peer_a = GrpcPeerEndpoint(store_a, region="ap-south-1-mumbai")
    peer_a.start()
    peer_b = GrpcPeerEndpoint(store_b, region="ap-south-1-bengaluru")
    peer_b.start()

    print(f"\n[gRPC servers]")
    print(f"  region A: grpc://{peer_a.address}")
    print(f"  region B: grpc://{peer_b.address}")

    # Bidirectional pull over gRPC (insecure here for demo; mTLS in prod)
    print(f"\n[pull A -> B over gRPC]")
    result_ba = pull_via_grpc(store_b, peer_a.address, trust_factor=0.95)
    print(f"  received={result_ba['received']}  merged={result_ba['merged']}  "
          f"store {result_ba['store_before']}->{result_ba['store_after']}")

    print(f"\n[pull B -> A over gRPC]")
    result_ab = pull_via_grpc(store_a, peer_b.address, trust_factor=0.95)
    print(f"  received={result_ab['received']}  merged={result_ab['merged']}  "
          f"store {result_ab['store_before']}->{result_ab['store_after']}")

    print(f"\n[after sync]")
    print(f"  region A (mumbai)    -> {store_a.stats().total} IOCs")
    print(f"  region B (bengaluru) -> {store_b.stats().total} IOCs")

    a_keys = {(i.kind, i.value) for i in store_a.all_active()}
    b_keys = {(i.kind, i.value) for i in store_b.all_active()}
    converged = a_keys == b_keys

    # Verify that an IOC from A reached B with peer attribution
    mumbai_ioc = store_b.lookup("103.21.198.4", kind="ip")
    print(f"\n[spot check] mumbai-detected IOC visible in B over gRPC:")
    if mumbai_ioc:
        print(f"  source={mumbai_ioc.source}  confidence={mumbai_ioc.confidence:.3f}  "
              f"tags={list(mumbai_ioc.tags)}")

    print(f"\n[convergence] {'YES' if converged else 'NO'}")
    print(f"[transport]   gRPC ({'mTLS prod' if False else 'insecure demo'})")

    peer_a.stop()
    peer_b.stop()
    return 0 if converged else 1


if __name__ == "__main__":
    sys.exit(main())
