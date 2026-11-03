"""Telemetry sources the walkers query.

``TelemetrySource`` is the contract (one method per question a walker asks). ``MockTenant``
answers from a small deterministic world derived from the seed ids, so the walk, the graph and
the planner can be exercised end to end without a tenant — exactly the pattern the 1.2 vendor
connectors use. Real adapters (Sentinel KQL, Falcon/Defender APIs, CloudTrail Lake, Purview,
CBS) implement the same methods; the walkers do not change.

Every answer is a list of ``Edge``; a source that cannot answer a question returns ``[]``.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from .graph import Edge


class TelemetrySource(Protocol):
    name: str

    # identity
    def sessions_for_user(self, user: str, window_min: int) -> list[Edge]: ...
    def devices_for_user(self, user: str, window_min: int) -> list[Edge]: ...
    def groups_and_roles(self, user: str) -> list[Edge]: ...
    def consented_apps(self, user: str, window_min: int) -> list[Edge]: ...
    # endpoint
    def process_children(self, host: str, window_min: int) -> list[Edge]: ...
    def lateral_from(self, host: str, window_min: int) -> list[Edge]: ...
    def hosts_for_user(self, user: str, window_min: int) -> list[Edge]: ...
    def files_written(self, host: str, window_min: int) -> list[Edge]: ...
    # network
    def flows_from(self, host_or_ip: str, window_min: int) -> list[Edge]: ...
    def dns_from(self, host_or_ip: str, window_min: int) -> list[Edge]: ...
    def rules_touched_by(self, principal: str, window_min: int) -> list[Edge]: ...
    # cloud
    def keys_and_roles(self, principal: str, window_min: int) -> list[Edge]: ...
    def resources_touched(self, principal: str, window_min: int) -> list[Edge]: ...
    # data
    def tables_queried(self, user: str, window_min: int) -> list[Edge]: ...
    def downloads(self, user: str, window_min: int) -> list[Edge]: ...
    # transaction
    def beneficiaries(self, account: str, window_min: int) -> list[Edge]: ...
    def fan_in(self, account: str, window_min: int) -> list[Edge]: ...
    def linked_accounts(self, account: str) -> list[Edge]: ...


class MockTenant:
    """Deterministic world: the same seed always yields the same neighbourhood, so tests and
    demos are reproducible. ``spread`` controls how compromised the world looks (0 = quiet)."""

    name = "mock-tenant"

    def __init__(self, *, spread: float = 0.5, seed: int = 7):
        self.spread = max(0.0, min(1.0, spread)); self._seed = seed
        self._t0 = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)
        self.contained: dict[str, set[str] | None] = {}   # target -> relations severed (None = every edge)

    def mark_contained(self, action_type: str, target: str) -> None:
        """Reflect an executed action: the walkers stop seeing the edges *from* that target that the action cuts."""
        _mark(self.contained, action_type, target)

    def _r(self, *parts: str) -> random.Random:
        h = hashlib.sha256(("|".join(parts) + f"|{self._seed}").encode()).hexdigest()
        return random.Random(int(h[:16], 16))

    def _ts(self, r: random.Random, back_min: int = 120) -> str:
        return (self._t0 - timedelta(minutes=r.randint(0, back_min))).isoformat()

    def _edges(self, a: str, rel: str, kinds: list[tuple[str, str]], n: int, r: random.Random, src: str) -> list[Edge]:
        out = []
        if _severed(self.contained, a, rel):
            return out
        for i in range(n):
            label, typ = kinds[i % len(kinds)]
            out.append(Edge(a, rel, f"{label}-{r.randint(100, 999)}", self._ts(r), round(r.uniform(.6, 1.0), 2), src, typ))
        return out

    # ---- identity
    def sessions_for_user(self, user, window_min):
        r = self._r("sess", user); n = r.randint(1, 2 + int(4 * self.spread))
        return self._edges(user, "holds_session", [("sess", "session"), ("tok", "token")], n, r, "identity")

    def devices_for_user(self, user, window_min):
        r = self._r("dev", user); n = 1 + (1 if r.random() < self.spread else 0)
        kinds = [("LT", "device_managed")] + ([("BYOD", "device_unmanaged")] if self.spread > .4 else [])
        return self._edges(user, "logged_on_from", kinds, n, r, "identity")

    def groups_and_roles(self, user):
        r = self._r("grp", user)
        kinds = [("grp-retail-ops", "group")] + ([("role-cloud-admin", "admin_role")] if r.random() < self.spread * .6 else [])
        return [Edge(user, "member_of", k[0], self._ts(r), 1.0, "identity", k[1]) for k in kinds]

    def consented_apps(self, user, window_min):
        r = self._r("app", user)
        return self._edges(user, "consented", [("oauth-mailhelper", "oauth_app")], 1 if r.random() < self.spread * .5 else 0, r, "identity")

    # ---- endpoint
    def process_children(self, host, window_min):
        r = self._r("proc", host); n = r.randint(0, 1 + int(3 * self.spread))
        return self._edges(host, "spawned", [("proc-script", "host"), ("proc-archiver", "host")], n, r, "endpoint")

    def lateral_from(self, host, window_min):
        r = self._r("lat", host); n = r.randint(0, int(3 * self.spread))
        kinds = [("SRV", "server"), ("FS", "file_server"), ("DC", "domain_controller"), ("JMP", "jump_host")]
        return self._edges(host, "lateral_to", kinds, n, r, "endpoint")

    def hosts_for_user(self, user, window_min):
        r = self._r("uh", user); n = 1 + r.randint(0, int(2 * self.spread))
        return self._edges(user, "logged_on", [("LT", "host"), ("VDI", "host")], n, r, "endpoint")

    def files_written(self, host, window_min):
        r = self._r("fw", host); n = r.randint(0, int(2 * self.spread))
        return self._edges(host, "wrote", [("share-finance", "file_server")], n, r, "endpoint")

    # ---- network
    def flows_from(self, x, window_min):
        r = self._r("flow", x); n = r.randint(0, 1 + int(3 * self.spread))
        kinds = [("10.20.5", "server"), ("cbs-db", "core_banking_db"), ("10.41.9", "host")]
        return self._edges(x, "connected_to", kinds, n, r, "network")

    def dns_from(self, x, window_min):
        r = self._r("dns", x); n = r.randint(0, int(2 * self.spread))
        return self._edges(x, "resolved", [("young-domain", "domain")], n, r, "network")

    def rules_touched_by(self, principal, window_min):
        r = self._r("rule", principal); n = 1 if r.random() < self.spread * .4 else 0
        return self._edges(principal, "modified_rule", [("fw-rule", "firewall_rule")], n, r, "network")

    # ---- cloud
    def keys_and_roles(self, principal, window_min):
        r = self._r("key", principal); n = r.randint(0, 1 + int(2 * self.spread))
        return self._edges(principal, "assumed", [("role-deploy", "cloud_role"), ("akia", "access_key")], n, r, "cloud")

    def resources_touched(self, principal, window_min):
        r = self._r("res", principal); n = r.randint(0, 1 + int(2 * self.spread))
        kinds = [("bucket-logs", "bucket"), ("bucket-kyc", "storage_bucket_pii"), ("kms-main", "kms")]
        return self._edges(principal, "touched", kinds, n, r, "cloud")

    # ---- data
    def tables_queried(self, user, window_min):
        r = self._r("tbl", user); n = r.randint(0, 1 + int(2 * self.spread))
        return self._edges(user, "queried", [("tbl-customers", "table"), ("tbl-kyc", "table_pii")], n, r, "data")

    def downloads(self, user, window_min):
        r = self._r("dl", user); n = r.randint(0, int(2 * self.spread))
        return self._edges(user, "downloaded_from", [("sp-finance", "file_server")], n, r, "data")

    # ---- transaction
    def beneficiaries(self, account, window_min):
        r = self._r("ben", account); n = r.randint(0, 1 + int(2 * self.spread))
        kinds = [("ben", "beneficiary_account"), ("mule", "mule_account")]
        return self._edges(account, "sent_to", kinds, n, r, "transaction")

    def fan_in(self, account, window_min):
        r = self._r("fan", account); n = r.randint(0, int(3 * self.spread))
        return self._edges(account, "received_from", [("acct", "bank_account")], n, r, "transaction")

    def linked_accounts(self, account):
        r = self._r("link", account)
        return self._edges(account, "linked_to", [("acct", "bank_account")], 1 if r.random() < .5 else 0, r, "transaction")


# method name -> the edge relation it answers. This is the vocabulary MockTenant emits and the graph
# scores by ``b_type``; a real estate export in the same shape drops straight in, walkers unchanged.
_RELATION = {
    "sessions_for_user": "holds_session", "devices_for_user": "logged_on_from",
    "groups_and_roles": "member_of", "consented_apps": "consented",
    "process_children": "spawned", "lateral_from": "lateral_to", "hosts_for_user": "logged_on",
    "files_written": "wrote", "flows_from": "connected_to", "dns_from": "resolved",
    "rules_touched_by": "modified_rule", "keys_and_roles": "assumed", "resources_touched": "touched",
    "tables_queried": "queried", "downloads": "downloaded_from", "beneficiaries": "sent_to",
    "fan_in": "received_from", "linked_accounts": "linked_to",
}
# an executed containment action severs a node's outgoing edges (same set MockTenant honours)
_CONTAIN_ACTIONS = {"revoke_sessions", "lock_account", "isolate", "block", "kill_process",
                    "rotate_credential", "hold", "block_export", "force_logout"}
# What an action cuts on its target (review B2). Revoking a user's sessions does not stop the user's other
# paths (cloud roles, tables, devices): severing *every* edge made "revoke_sessions(u1)" read "confirmed 2 → 0"
# for paths it never touched, and every later alert on u1 walked one node. None = the target is cut off.
_SEVERS: dict[str, set[str] | None] = {
    "revoke_sessions": {"holds_session", "logged_on_from", "touched", "queried", "logged_on"},
    "force_logout": {"holds_session", "logged_on"},
    "rotate_credential": {"assumed"},
    "block_export": {"downloaded_from"},
    "hold": {"sent_to", "received_from"},
    "lock_account": None, "isolate": None, "block": None, "kill_process": None,
}


def _mark(contained: dict, action_type: str, target: str) -> None:
    if action_type not in _SEVERS:
        return
    cut, have = _SEVERS[action_type], contained.get(str(target), set())
    contained[str(target)] = None if (cut is None or have is None) else (have | cut)


def _severed(contained: dict, subject: str, relation: str) -> bool:
    if subject not in contained:
        return False
    cut = contained[subject]
    return cut is None or relation in cut


class InventorySource:
    """A real ``TelemetrySource`` backed by an estate export, not a random world.

    The bank (or the sandbox) supplies the graph its walkers reason over — host↔host lateral
    reach, user↔device↔session, principal↔cloud-role/bucket, account↔beneficiary — as a flat list
    of edges in the same vocabulary MockTenant emits::

        {"edges": [
            {"a": "host-ws-14", "relation": "lateral_to", "b": "SRV-finance-02", "b_type": "server",
             "ts": "2026-10-01T08:31:00Z", "confidence": 0.9, "source": "edr"},
            ...]}

    ``b_type`` uses the graph's sensitivity vocabulary (``core_banking_db``, ``domain_controller``,
    ``server``, ``host``, ``storage_bucket_pii`` …) so the blast graph, min-cut planner and
    containment loop behave exactly as on the mock. In production the estate is produced from CMDB +
    EDR + IAM + CBS exports on a schedule; here it is a static file so the investigation layer can
    reason over a *real* topology with no live API. ``window_min`` is accepted but not yet used for
    time-slicing (the export is treated as the current picture); that is a later refinement.

    Accepts a path to a JSON file, or an already-parsed ``dict``/``list`` (for tests)."""

    name = "inventory"

    def __init__(self, source: Any) -> None:
        self.contained: dict[str, set[str] | None] = {}
        self._index: dict[tuple[str, str], list[Edge]] = {}
        for rec in _load_estate(source):
            try:
                e = Edge(a=str(rec["a"]), relation=str(rec["relation"]), b=str(rec["b"]),
                         ts=str(rec.get("ts", "")), confidence=float(rec.get("confidence", 1.0)),
                         source=str(rec.get("source", "")), b_type=str(rec.get("b_type", "unknown")))
            except (KeyError, TypeError, ValueError):
                continue                                    # a malformed row is skipped, never fatal
            self._index.setdefault((e.a, e.relation), []).append(e)

    def mark_contained(self, action_type: str, target: str) -> None:
        _mark(self.contained, action_type, target)

    def _q(self, subject: str, method: str) -> list[Edge]:
        if _severed(self.contained, str(subject), _RELATION[method]):
            return []
        return list(self._index.get((str(subject), _RELATION[method]), ()))

    # identity
    def sessions_for_user(self, user, window_min): return self._q(user, "sessions_for_user")
    def devices_for_user(self, user, window_min): return self._q(user, "devices_for_user")
    def groups_and_roles(self, user): return self._q(user, "groups_and_roles")
    def consented_apps(self, user, window_min): return self._q(user, "consented_apps")
    # endpoint
    def process_children(self, host, window_min): return self._q(host, "process_children")
    def lateral_from(self, host, window_min): return self._q(host, "lateral_from")
    def hosts_for_user(self, user, window_min): return self._q(user, "hosts_for_user")
    def files_written(self, host, window_min): return self._q(host, "files_written")
    # network
    def flows_from(self, host_or_ip, window_min): return self._q(host_or_ip, "flows_from")
    def dns_from(self, host_or_ip, window_min): return self._q(host_or_ip, "dns_from")
    def rules_touched_by(self, principal, window_min): return self._q(principal, "rules_touched_by")
    # cloud
    def keys_and_roles(self, principal, window_min): return self._q(principal, "keys_and_roles")
    def resources_touched(self, principal, window_min): return self._q(principal, "resources_touched")
    # data
    def tables_queried(self, user, window_min): return self._q(user, "tables_queried")
    def downloads(self, user, window_min): return self._q(user, "downloads")
    # transaction
    def beneficiaries(self, account, window_min): return self._q(account, "beneficiaries")
    def fan_in(self, account, window_min): return self._q(account, "fan_in")
    def linked_accounts(self, account): return self._q(account, "linked_accounts")


def _load_estate(source: Any) -> list[dict]:
    doc = source if isinstance(source, (dict, list)) else json.load(open(source, encoding="utf-8"))
    edges = doc.get("edges", []) if isinstance(doc, dict) else doc
    if not isinstance(edges, list):
        raise ValueError('estate must be a list of edge dicts, or {"edges": [...]}')
    return edges


def tenant_from_env() -> TelemetrySource:
    """``AEGIS_TENANT=inventory`` + ``AEGIS_TENANT_FILE=<estate.json>`` → the real estate graph;
    anything else → the deterministic ``MockTenant`` (``AEGIS_MOCK_SPREAD``). Default is unchanged."""
    if os.environ.get("AEGIS_TENANT", "mock").strip().lower() in ("inventory", "file"):
        path = os.environ.get("AEGIS_TENANT_FILE", "").strip()
        if not path:
            raise ValueError("AEGIS_TENANT=inventory requires AEGIS_TENANT_FILE=<estate.json>")
        return InventorySource(path)
    return MockTenant(spread=float(os.environ.get("AEGIS_MOCK_SPREAD", "0.5")))


__all__ = ["MockTenant", "TelemetrySource", "InventorySource", "tenant_from_env"]
