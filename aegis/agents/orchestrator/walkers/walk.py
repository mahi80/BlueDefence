"""The six walkers and the time-boxed, hop-limited walk driver."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .graph import BlastGraph, Edge
from .sources import TelemetrySource

logger = logging.getLogger("aegis.walkers")

# alert keys that seed each entity type (vendor vocabularies from the training data + eval cases)
SEED_KEYS = {
    "account": ("user_id", "user", "actor_id", "principal_id", "caller_id", "userPrincipalName", "user_upn", "AccountName",
                "actor", "operator", "principal", "recipient", "Recipient"),
    "host": ("host", "hostname", "device", "DeviceName", "location", "src_host", "device_id", "endpoint_id", "unit_hostname"),
    "ip": ("source_ip", "client_ip", "ip_client", "clientIP", "src_ip", "ip", "from_ip"),
    "bank_account": ("account", "beneficiary_account", "acct"),
    "session": ("session_id", "session_token_hash"),
}


MAX_SEEDS = 20


def seeds_from(alert: dict, *, top_level_only: bool = False, limit: int = MAX_SEEDS) -> list[tuple[str, str]]:
    """(id, type) pairs found in the alert (top level and up to two levels of nesting), at most ``limit``
    (review B6: 400 padded nested ``user`` objects became 402 seeds that bypassed ``max_nodes``). Top-level
    keys come first. ``top_level_only`` is for anything that becomes an action target: a nested field is
    whatever the client put in its request body (review B7 — a POST naming the CFO got the CFO challenged)."""
    out: list[tuple[str, str]] = []
    nested: list[tuple[dict, int]] = []
    def scan(d: dict, depth: int):
        for k, v in d.items():
            if isinstance(v, dict):
                if depth < 2 and not top_level_only:
                    nested.append((v, depth + 1))
                continue
            if not isinstance(v, (str, int)) or v in ("", None):
                continue
            for typ, keys in SEED_KEYS.items():
                if k in keys:
                    out.append((str(v)[:80], typ))
    scan(alert, 0)
    while nested and len(out) < limit * 4:
        d, depth = nested.pop(0)
        scan(d, depth)
    seen = set(); uniq = []
    for s in out:
        if s not in seen:
            seen.add(s); uniq.append(s)
    return uniq[:limit]


HOST_TYPES = ("host", "server", "device_managed", "device_unmanaged", "jump_host", "file_server", "domain_controller",
              "backup_server")
PRINCIPAL_TYPES = ("account", "account_privileged")
SESSION_TYPES = ("session", "token")


@dataclass
class Walker:
    name: str
    seed_types: tuple[str, ...]
    step: Callable[[TelemetrySource, str, str, int], list[Edge]]   # (source, node_id, node_type, window) -> edges
    hops: int | None = None                                         # None = the run's hop limit


# ---- the six walkers: each step says what to ask the source for a node of a given type
def _identity(src, nid, ntype, w):
    if ntype in PRINCIPAL_TYPES:
        return src.sessions_for_user(nid, w) + src.devices_for_user(nid, w) + src.groups_and_roles(nid) + src.consented_apps(nid, w)
    return []


def _endpoint(src, nid, ntype, w):
    if ntype in HOST_TYPES:
        return src.process_children(nid, w) + src.lateral_from(nid, w) + src.files_written(nid, w)
    if ntype in SESSION_TYPES:                 # where a stolen session / token was used next
        return src.lateral_from(nid, w)
    if ntype in PRINCIPAL_TYPES:
        return src.hosts_for_user(nid, w)
    return []


def _network(src, nid, ntype, w):
    if ntype in HOST_TYPES or ntype == "ip":
        return src.flows_from(nid, w) + src.dns_from(nid, w)
    if ntype in PRINCIPAL_TYPES or ntype == "admin_role":
        return src.rules_touched_by(nid, w)
    return []


def _cloud(src, nid, ntype, w):
    if ntype in PRINCIPAL_TYPES or ntype in ("cloud_role", "access_key", "admin_role"):
        return src.keys_and_roles(nid, w) + src.resources_touched(nid, w)
    return []


def _data(src, nid, ntype, w):
    if ntype in PRINCIPAL_TYPES:
        return src.tables_queried(nid, w) + src.downloads(nid, w)
    return []


def _transaction(src, nid, ntype, w):
    if ntype in ("bank_account", "beneficiary_account", "mule_account"):
        return src.beneficiaries(nid, w) + src.fan_in(nid, w) + src.linked_accounts(nid)
    return []


DEFAULT_WALKERS: dict[str, Walker] = {
    "identity": Walker("identity", ("account",), _identity),
    "endpoint": Walker("endpoint", ("host", "account"), _endpoint),
    "network": Walker("network", ("host", "ip", "account"), _network),
    "cloud": Walker("cloud", ("account",), _cloud),
    "data": Walker("data", ("account",), _data),
    "transaction": Walker("transaction", ("bank_account",), _transaction),
}


@dataclass
class WalkReport:
    graph: BlastGraph
    elapsed_ms: int
    per_walker: dict[str, dict] = field(default_factory=dict)


def run_walkers(alert: dict, source: TelemetrySource, *, walkers: dict[str, Walker] | None = None,
                hops: int = 2, window_min: int = 120, max_seconds: float = 10.0,
                max_nodes: int = 400, guard: Any = None) -> WalkReport:
    """Seed from the alert, then expand hop by hop; every walker is time-boxed by the shared
    wall clock and each is a governed tool call (``walker.<name>``) when a guard is given."""
    walkers = walkers or DEFAULT_WALKERS
    g = BlastGraph(); t0 = time.time()
    # Seeds are the alert's TOP-LEVEL entities only. The mitigation plan cuts edges of this graph, so a graph grown
    # from nested client-written fields put revoke / force-logout / block-export on whoever the attacker named in a
    # request body (review round 7 O-5, B7 through the plan).
    for nid, ntype in seeds_from(alert, top_level_only=True):
        g.seed(nid, ntype)
    report: dict[str, dict] = {name: {"edges": 0, "elapsed_ms": 0, "truncated": False} for name in walkers}
    active: dict[str, Walker] = {}
    for name, w in walkers.items():
        if guard is not None:
            try:
                guard.pre_tool_call(f"walker.{name}", {"alert_id": str(alert.get("id", "?")), "walker": name})
            except Exception as e:  # noqa: BLE001 — governance block (incl. pause-gate) skips the walker
                logger.warning("[walker.%s] skipped by governance on alert %s: %s", name, alert.get("id", "?"), str(e)[:120])
                report[name] = {"skipped": f"governance: {str(e)[:100]}", "edges": 0}; continue
        active[name] = w
    # hop-outer loop: every walker expands the frontier each hop, so a node found by one walker
    # is expanded by all the others at the next hop (a 4-hop chain across sources still resolves)
    expanded: set[tuple[str, str]] = set()
    for hop in range(hops):
        frontier = [n for n in g.frontier(hop)]
        if not frontier:
            break
        for name, w in active.items():
            if w.hops is not None and hop >= w.hops:
                continue
            t1 = time.time()
            for n in frontier:
                if (name, n.id) in expanded:
                    continue
                if hop == 0 and n.type not in w.seed_types:
                    continue
                if time.time() - t0 >= max_seconds or len(g.nodes) >= max_nodes:
                    report[name]["truncated"] = True; break
                expanded.add((name, n.id))
                try:
                    report[name]["edges"] += g.add(w.step(source, n.id, n.type, window_min))
                    if len(g.nodes) >= max_nodes:          # one telemetry answer can carry many nodes (round 7 O-6)
                        report[name]["truncated"] = True; break
                except Exception as e:  # noqa: BLE001 — one bad query is a note, not a failed walk
                    if "error" not in report[name]:        # first failure per walker is logged; the rest are counted
                        logger.warning("[walker.%s] query failed on %s %s: %s: %s", name, n.type, n.id[:40], type(e).__name__, str(e)[:120])
                    report[name]["error"] = f"{type(e).__name__}: {str(e)[:100]}"; report[name]["errors"] = report[name].get("errors", 0) + 1
                    g.errors[name] = g.errors.get(name, 0) + 1
            report[name]["elapsed_ms"] += int((time.time() - t1) * 1000)
    for name, w in active.items():
        g.walkers_run.append(name)
        if report[name].get("truncated"):
            g.truncated.append(name)
        if guard is not None:
            try:
                guard.post_tool_call(f"walker.{name}", result={"edges": report[name]["edges"]}, success=True)
            except Exception as exc:  # noqa: BLE001 — post-hook only
                logger.debug("[acp] post_tool_call failed for walker.%s: %s", name, exc)
    return WalkReport(g, int((time.time() - t0) * 1000), report)


__all__ = ["DEFAULT_WALKERS", "MAX_SEEDS", "SEED_KEYS", "WalkReport", "Walker", "run_walkers", "seeds_from"]
