"""Multi-tenant isolation demo.

Spins up two tenants (Bank A in Mumbai, Bank B in Bengaluru), runs
alerts through each under a TenantContext, and verifies:

  - Each tenant gets its own IOC store (no cross-contamination).
  - Each tenant's audit log lives under tenants/<tenant_id>/.
  - Each tenant's audit chain integrity verifies independently.

Run:
  python -m aegis.agents.shared.tenant_demo
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from aegis.agents.shared.audit import AuditLog
from aegis.agents.shared.evidence_chain import (
    EvidenceChain,
    EvidenceItem,
    RecommendedAction,
)
from aegis.agents.shared.tenant import (
    Tenant,
    TenantContext,
    TenantedIOCStore,
    current_tenant,
    tenant_audit_path,
)
from aegis.agents.threat_intel.store import IOC


def _build_chain(alert_id: str, verdict: str, action_target: str) -> EvidenceChain:
    chain = EvidenceChain(
        alert_id=alert_id,
        investigated_by="tenant_demo",
        verdict=verdict,
        confidence=0.9,
    )
    chain.evidence.append(EvidenceItem(
        source="demo", signal=f"tenant={current_tenant().id}",
        weight="medium", raw_data={"tenant_id": current_tenant().id},
    ))
    chain.recommended_actions.append(RecommendedAction(
        action_type="block", target=action_target,
        reasoning="demo", requires_hitl=True, confidence=0.9,
    ))
    return chain


def main() -> int:
    bank_a = Tenant(id="bank-a-mumbai", name="Bank A (Mumbai)", region="ap-south-1")
    bank_b = Tenant(id="bank-b-bengaluru", name="Bank B (Bengaluru)", region="ap-south-1")

    print("=" * 70)
    print("AEGIS multi-tenant isolation demo")
    print("=" * 70)

    with tempfile.TemporaryDirectory() as td:
        base = Path(td)

        # ---- Tenanted IOC store -----------------------------------
        ioc_store = TenantedIOCStore()

        # Bank A sees a Mumbai-detected IOC
        with TenantContext(bank_a):
            store_a = ioc_store.for_tenant()
            store_a.add(IOC(kind="ip", value="103.21.198.4",
                            confidence=0.93, source="bank-a-detection",
                            tags=("scanner",)))
            print(f"\n[bank-a] added 1 IOC; store has {store_a.stats().total} total")

        # Bank B sees a different IOC — should NOT see Bank A's
        with TenantContext(bank_b):
            store_b = ioc_store.for_tenant()
            store_b.add(IOC(kind="domain", value="phish.bank-b.test",
                            confidence=0.91, source="bank-b-detection",
                            tags=("phishing",)))
            print(f"[bank-b] added 1 IOC; store has {store_b.stats().total} total")

        # Verify isolation: each store sees only its own
        with TenantContext(bank_a):
            cross_a = ioc_store.for_tenant().lookup("phish.bank-b.test", kind="domain")
            print(f"\n[bank-a] lookup of bank-b's IOC: {'LEAK' if cross_a else 'isolated (None)'}")
        with TenantContext(bank_b):
            cross_b = ioc_store.for_tenant().lookup("103.21.198.4", kind="ip")
            print(f"[bank-b] lookup of bank-a's IOC: {'LEAK' if cross_b else 'isolated (None)'}")

        if cross_a is not None or cross_b is not None:
            print("\nFAIL: cross-tenant IOC leak")
            return 1

        # ---- Tenanted audit log -----------------------------------
        for tenant in (bank_a, bank_b):
            with TenantContext(tenant):
                p = tenant_audit_path(base)
                print(f"\n[{tenant.id}] audit path: {p}")
                audit = AuditLog(p)
                for i in range(3):
                    chain = _build_chain(
                        alert_id=f"{tenant.id}-evt-{i}",
                        verdict="malicious",
                        action_target=f"{tenant.id}-target",
                    )
                    audit.append(chain)
                ok = audit.verify()
                print(f"[{tenant.id}] wrote 3 entries; integrity: {'PASS' if ok else 'FAIL'}")

        # Verify independence: each tenant's audit log file must exist
        # and live under its own tenant subdirectory.
        a_path = base / "tenants" / bank_a.id / "audit.jsonl"
        b_path = base / "tenants" / bank_b.id / "audit.jsonl"
        a_exists = a_path.exists()
        b_exists = b_path.exists()
        print(f"\n[isolation] bank-a audit at {a_path.relative_to(base)}: {a_exists}")
        print(f"[isolation] bank-b audit at {b_path.relative_to(base)}: {b_exists}")
        if not (a_exists and b_exists):
            print("\nFAIL: per-tenant audit paths not separated")
            return 1

        # Multi-tenant stats
        all_stats = ioc_store.all_stats()
        print(f"\n[ops dashboard] per-tenant IOC stats:")
        for tid, stats in sorted(all_stats.items()):
            print(f"  {tid}: total={stats['total']}, by_kind={stats['by_kind']}")

    print(f"\nMulti-tenant isolation: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
