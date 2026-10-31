"""Multi-tenant isolation primitives.

Most of AEGIS is written single-tenant ("the bank"). For deployments
where one AEGIS instance serves multiple banks (regulator-hosted SOC,
SaaS offering, multi-subsidiary group), each tenant needs its own:

  - IOC store     (a Mumbai bank shouldn't see a Singapore bank's IOCs)
  - audit log     (per-tenant retention + access control + GRC export)
  - agent identity manifest scope (CIEM ingest per tenant)
  - LLM token budget (cost attribution)

This module ships the wiring; the agent layer remains tenant-agnostic
by reading the active tenant from a contextvar.

Usage:

    with TenantContext(Tenant(id="bank-a", name="Bank A", region="ap-south-1")):
        chain = orch.handle(alert)
        # IOC lookups, audit appends, manifest reads all scoped to bank-a

    with TenantContext(Tenant(id="bank-b", ...)):
        chain = orch.handle(alert)
        # Different store, different log, different budget

Production extensions:
  - Hard isolation: separate K8s namespaces per tenant + NetworkPolicy
  - Cryptographic isolation: per-tenant encryption keys for audit logs
    (HSM-backed, so even AEGIS operators can't read across tenants)
"""
from __future__ import annotations

import contextvars
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional


@dataclass(frozen=True)
class Tenant:
    """Identifies one AEGIS-tenant. The id is the persistence key."""
    id: str
    name: str
    region: str = "ap-south-1"
    # Hard-isolation flags (production extension points)
    audit_key_id: Optional[str] = None    # HSM key ref for audit encryption
    cost_attribution: Optional[str] = None  # billing dimension
    metadata: dict = field(default_factory=dict)


# Default tenant for single-tenant deployments — keeps existing demos
# unchanged; agents that don't enter a TenantContext get this by default.
DEFAULT_TENANT = Tenant(
    id="default",
    name="AEGIS default tenant",
    region="ap-south-1",
)


_CURRENT: contextvars.ContextVar[Tenant] = contextvars.ContextVar(
    "aegis.current_tenant", default=DEFAULT_TENANT,
)


def current_tenant() -> Tenant:
    """Return the active tenant. DEFAULT_TENANT outside any context."""
    return _CURRENT.get()


class TenantContext:
    """Context manager that sets the active tenant for the duration of
    its block. Re-entrant via contextvars (composes with asyncio + threads).
    """

    def __init__(self, tenant: Tenant):
        self._tenant = tenant
        self._token: Optional[contextvars.Token] = None

    def __enter__(self) -> Tenant:
        self._token = _CURRENT.set(self._tenant)
        return self._tenant

    def __exit__(self, *_exc) -> None:
        if self._token is not None:
            _CURRENT.reset(self._token)
            self._token = None


# ---- Multi-tenant IOC store -------------------------------------------

class TenantedIOCStore:
    """Per-tenant IOCStore wrapper. Lazy-creates a store on first
    access for a given tenant. Thread-safe.
    """

    def __init__(self):
        from .. import threat_intel  # noqa: F401  (ensures module is importable)
        from ..threat_intel.store import IOCStore
        self._cls = IOCStore
        self._stores: dict[str, "IOCStore"] = {}
        self._lock = threading.Lock()

    def for_tenant(self, tenant: Optional[Tenant] = None):
        """Return the IOCStore for `tenant` (or the active one)."""
        t = tenant or current_tenant()
        with self._lock:
            store = self._stores.get(t.id)
            if store is None:
                store = self._cls()
                self._stores[t.id] = store
            return store

    def all_stats(self) -> dict[str, dict]:
        """Per-tenant store stats — useful for ops dashboards."""
        with self._lock:
            return {
                tid: {
                    "total": s.stats().total,
                    "by_kind": s.stats().by_kind,
                    "by_source": s.stats().by_source,
                }
                for tid, s in self._stores.items()
            }

    def tenant_ids(self) -> list[str]:
        with self._lock:
            return sorted(self._stores.keys())


# ---- Tenant-scoped audit log paths ------------------------------------

def tenant_audit_path(base: Path, tenant: Optional[Tenant] = None) -> Path:
    """Return the per-tenant audit log path under `base`.

    Layout:
        base/audit.jsonl                       # default tenant
        base/tenants/<tenant_id>/audit.jsonl   # explicit tenant
    """
    t = tenant or current_tenant()
    if t.id == DEFAULT_TENANT.id:
        return base / "_audit_log.jsonl"
    p = base / "tenants" / t.id / "audit.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


# ---- Iteration helpers ------------------------------------------------

def iter_tenants(tenants: list[Tenant]) -> Iterator[Tenant]:
    """Iterate over a list of tenants, setting each as active during yield."""
    for tenant in tenants:
        with TenantContext(tenant):
            yield tenant
