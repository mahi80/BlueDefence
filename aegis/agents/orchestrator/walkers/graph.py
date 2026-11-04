"""The blast graph: nodes (entities) and edges (what touched what), scored for the planner."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Iterable

# how much it hurts if the attacker reaches this kind of node; the planner protects the top of this list
SENSITIVITY = {
    "core_banking_db": 1.0, "swift_gateway": 1.0, "domain_controller": 0.95, "kms": 0.95, "secret_store": 0.9,
    "jump_host": 0.85, "payment_api": 0.85, "storage_bucket_pii": 0.85, "admin_role": 0.8, "backup_server": 0.8,
    "file_server": 0.7, "mailbox": 0.5, "account_privileged": 0.8, "account": 0.4, "session": 0.35, "token": 0.45,
    "device_managed": 0.3, "device_unmanaged": 0.5, "host": 0.4, "server": 0.6, "ip": 0.2, "domain": 0.2,
    "table_pii": 0.85, "table": 0.4, "cloud_role": 0.7, "access_key": 0.6, "bucket": 0.5, "oauth_app": 0.5,
    "beneficiary_account": 0.5, "mule_account": 0.9, "bank_account": 0.6, "firewall_rule": 0.6, "group": 0.3, "unknown": 0.3,
}
CRITICAL = 0.85     # nodes at or above this sensitivity count as "critical assets reached"


class _ChokeTimeout(Exception):
    """choke_edges ran past its time box."""


@dataclass(eq=False)
class Node:
    id: str
    type: str
    distance: int = 99                      # hops from a seed; 0 = seed
    sensitivity: float = 0.3
    first_touch: str | None = None          # earliest edge timestamp that reaches this node
    via: str = ""                           # the walker that found it

    @property
    def score(self) -> float:
        """Impact-weighted reach: closer and more sensitive = higher."""
        return round(self.sensitivity / (1 + self.distance), 3)

    @property
    def critical(self) -> bool:
        return self.sensitivity >= CRITICAL


@dataclass(frozen=True)
class Edge:
    a: str                 # source node id
    relation: str          # logged_on | holds_token | spawned | lateral_to | wrote | read | assumed | opened | sent_to | ...
    b: str                 # target node id
    ts: str = ""           # ISO timestamp of the observation
    confidence: float = 1.0
    source: str = ""       # which walker / telemetry source produced it
    b_type: str = "unknown"


@dataclass
class BlastGraph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    walkers_run: list[str] = field(default_factory=list)
    truncated: list[str] = field(default_factory=list)      # walkers that hit their time box
    errors: dict[str, int] = field(default_factory=dict)     # walker -> failed telemetry queries (review B3)
    _choke_cache: tuple | None = field(default=None, repr=False, compare=False)

    # ------------------------------------------------------------------ build
    def seed(self, node_id: str, node_type: str) -> Node:
        n = self.nodes.get(node_id)
        if n is None:
            n = Node(node_id, node_type, 0, SENSITIVITY.get(node_type, 0.3), via="seed")
            self.nodes[node_id] = n
        else:
            n.distance = 0
        return n

    def add(self, edges: Iterable[Edge]) -> int:
        """Merge edges; node distance = min(distance of a) + 1; keeps the earliest first_touch."""
        added = 0
        seen = {(e.a, e.relation, e.b) for e in self.edges}
        for e in edges:
            key = (e.a, e.relation, e.b)
            if key in seen:
                continue
            seen.add(key); self.edges.append(e); added += 1
            a = self.nodes.get(e.a)
            if a is None:
                a = Node(e.a, "unknown", 99, SENSITIVITY["unknown"], via=e.source); self.nodes[e.a] = a
            b = self.nodes.get(e.b)
            if b is None:
                b = Node(e.b, e.b_type, a.distance + 1, SENSITIVITY.get(e.b_type, 0.3), via=e.source); self.nodes[e.b] = b
            else:
                b.distance = min(b.distance, a.distance + 1)
                if b.type == "unknown" and e.b_type != "unknown":
                    b.type = e.b_type; b.sensitivity = SENSITIVITY.get(e.b_type, 0.3)
            if e.ts and (b.first_touch is None or e.ts < b.first_touch):
                b.first_touch = e.ts
        return added

    # ------------------------------------------------------------------ read
    def reached(self) -> list[Node]:
        return [n for n in self.nodes.values() if n.distance < 99]

    def critical_reached(self) -> list[Node]:
        return sorted((n for n in self.reached() if n.critical), key=lambda n: (n.distance, -n.sensitivity))

    def frontier(self, hop: int) -> list[Node]:
        return [n for n in self.nodes.values() if n.distance == hop]

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for n in self.reached():
            k = ("accounts" if n.type.startswith("account") or n.type in ("admin_role", "cloud_role") else
                 "hosts" if n.type in ("host", "server", "jump_host", "domain_controller", "file_server", "backup_server", "device_managed", "device_unmanaged") else
                 "sessions" if n.type in ("session", "token", "access_key", "oauth_app") else
                 "data" if n.type in ("table", "table_pii", "bucket", "storage_bucket_pii", "mailbox", "secret_store", "kms") else
                 "money" if n.type in ("bank_account", "beneficiary_account", "mule_account", "swift_gateway", "payment_api") else "other")
            out[k] = out.get(k, 0) + 1
        return out

    def earliest_touch(self) -> str | None:
        ts = [n.first_touch for n in self.reached() if n.first_touch]
        return min(ts) if ts else None

    def choke_edges(self, top: int = 5, max_seconds: float | None = None) -> list[dict]:
        """Edges whose removal disconnects the most critical nodes from the seeds — the 2.6
        minimum-cut candidates, exact for one-edge cuts.

        An edge is a one-edge cut for a critical node exactly when it dominates that node from the seeds. It used
        to be found by removing each edge in turn and re-walking the graph — O(E²): a dense 400-node / 15,000-edge
        telemetry answer took 8 s, with no time box, before the (time-boxed) planner even started (review round 8
        O8-12). Now each edge is a node of its own in the graph (a → edge → b), the dominator tree from a virtual
        root over the seeds is computed once (Cooper–Harvey–Kennedy), and each critical node's cut edges are the
        edge-nodes on its dominator chain. Also time-boxed (``AEGIS_CHOKE_MAX_SECONDS``, default 2 s, the planner's
        budget): past it the answer is ``[]`` and ``"choke_edges"`` is listed in ``truncated``."""
        key = (len(self.edges), len(self.nodes), top)
        if self._choke_cache is not None and self._choke_cache[0] == key:
            return self._choke_cache[1]
        crit = {n.id for n in self.critical_reached()}
        if not crit:
            return []
        if max_seconds is None:
            try:
                max_seconds = float(os.environ.get("AEGIS_CHOKE_MAX_SECONDS", "") or 2.0)
            except ValueError:
                max_seconds = 2.0
        deadline = time.monotonic() + max(0.05, max_seconds)
        try:
            out = self._choke_by_dominators(crit, deadline)
        except _ChokeTimeout:
            if "choke_edges" not in self.truncated:
                self.truncated.append("choke_edges")
            out = []
        out.sort(key=lambda d: (-d["n"], d["edge"]))
        self._choke_cache = (key, out[:top])
        return out[:top]

    def _choke_by_dominators(self, crit: set[str], deadline: float) -> list[dict]:
        seeds = [n.id for n in self.nodes.values() if n.distance == 0]
        idx: dict[str, int] = {}
        succ: list[list[int]] = [[]]                         # 0 = virtual root
        edge_of: dict[int, int] = {}                         # graph vertex -> index into self.edges
        def vid(x: str) -> int:
            v = idx.get(x)
            if v is None:
                v = idx[x] = len(succ); succ.append([])
            return v
        for sd in seeds:
            succ[0].append(vid(sd))
        for i, e in enumerate(self.edges):
            ev = len(succ); succ.append([]); edge_of[ev] = i
            succ[vid(e.a)].append(ev)
            succ[ev].append(vid(e.b))
        n = len(succ)
        # iterative DFS post-order from the root (only what the seeds reach)
        post = [-1] * n
        order: list[int] = []
        seen = [False] * n
        seen[0] = True
        stack: list[tuple[int, int]] = [(0, 0)]
        while stack:
            v, k = stack[-1]
            if k < len(succ[v]):
                stack[-1] = (v, k + 1)
                w = succ[v][k]
                if not seen[w]:
                    seen[w] = True; stack.append((w, 0))
            else:
                stack.pop(); post[v] = len(order); order.append(v)
        preds: list[list[int]] = [[] for _ in range(n)]
        for v in order:
            for w in succ[v]:
                preds[w].append(v)
        idom = [-1] * n
        idom[0] = 0
        rpo = order[::-1]
        changed, rounds = True, 0
        while changed:
            changed, rounds = False, rounds + 1
            if time.monotonic() > deadline:
                raise _ChokeTimeout
            for b in rpo:
                if b == 0:
                    continue
                new = -1
                for p in preds[b]:
                    if idom[p] < 0:
                        continue
                    if new < 0:
                        new = p
                        continue
                    f1, f2 = p, new
                    while f1 != f2:
                        while post[f1] < post[f2]:
                            f1 = idom[f1]
                        while post[f2] < post[f1]:
                            f2 = idom[f2]
                    new = f1
                if new >= 0 and idom[b] != new:
                    idom[b] = new; changed = True
        protects: dict[int, list[str]] = {}
        for c in crit:
            v = idx.get(c)
            if v is None or not seen[v]:
                continue
            steps = 0
            while v != 0:
                v = idom[v]
                if v in edge_of:
                    protects.setdefault(edge_of[v], []).append(c)
                steps += 1
                if steps % 4096 == 0 and time.monotonic() > deadline:
                    raise _ChokeTimeout
        out = []
        for i, lost in protects.items():
            e = self.edges[i]
            out.append({"edge": f"{e.a} -{e.relation}-> {e.b}", "protects": sorted(lost), "n": len(lost), "source": e.source})
        return out

    @staticmethod
    def _reach(seeds: set[str], edges: list[Edge]) -> set[str]:
        adj: dict[str, list[str]] = {}
        for e in edges:
            adj.setdefault(e.a, []).append(e.b)
        seen = set(seeds); stack = list(seeds)
        while stack:
            x = stack.pop()
            for y in adj.get(x, ()):
                if y not in seen:
                    seen.add(y); stack.append(y)
        return seen

    def summary(self) -> dict:
        crit = self.critical_reached()
        # the display list is capped; the count and the id list are not — they used to be read off the
        # capped list, so 20 critical assets reported as 10 and a cut of 6 read "10 → 10" (review B1)
        return {"nodes_reached": len(self.reached()), "edges": len(self.edges), "counts": self.counts(),
                "critical_assets_reached": [{"id": n.id, "type": n.type, "distance": n.distance} for n in crit[:10]],
                "critical_count": len(crit), "critical_ids": [n.id for n in crit],
                "query_errors": dict(self.errors), "incomplete": bool(self.errors or self.truncated),
                "earliest_touch": self.earliest_touch(), "walkers": self.walkers_run, "truncated": self.truncated,
                "top_nodes": [{"id": n.id, "type": n.type, "distance": n.distance, "score": n.score}
                              for n in sorted(self.reached(), key=lambda n: -n.score)[:10]],
                "choke_edges": self.choke_edges()}

    def to_dict(self) -> dict:
        return {"nodes": [{"id": n.id, "type": n.type, "distance": n.distance, "sensitivity": n.sensitivity,
                           "first_touch": n.first_touch, "via": n.via} for n in self.nodes.values()],
                "edges": [e.__dict__ for e in self.edges], "summary": self.summary()}

    def signal(self) -> str:
        s = self.summary(); c = s["counts"]
        crit = s["critical_assets_reached"]
        failed = sum(s["query_errors"].values())
        return (f"Blast radius: {c.get('accounts', 0)} account(s), {c.get('hosts', 0)} host(s), {c.get('sessions', 0)} session/token(s), "
                f"{c.get('data', 0)} data store(s), {c.get('money', 0)} money node(s); "
                f"{s['critical_count']} critical asset(s) reached" + (f" ({', '.join(x['id'] for x in crit[:3])})" if crit else "") +
                (f"; earliest touch {s['earliest_touch']}" if s["earliest_touch"] else "") +
                (f"; {len(s['truncated'])} walker(s) time-boxed" if s["truncated"] else "") +
                (f"; INCOMPLETE: {failed} telemetry quer{'y' if failed == 1 else 'ies'} failed "
                 f"({', '.join(sorted(s['query_errors']))}) — the radius may be larger" if failed else ""))
