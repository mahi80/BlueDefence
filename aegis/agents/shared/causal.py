"""Causal-inference layer for evidence chains.

The project plan calls this out: "Causal layer distinguishes correlation
('user logged in from new device') from causation ('attacker used
phished credentials') — directly improves evidence chain quality and
reduces FPs."

Design constraint: dep-free. Production agents would use DoWhy / pgmpy
for richer SCM operations, but they're heavy ML deps and add supply-
chain surface. The walking skeleton ships a small Bayesian-network
inference engine in pure stdlib that's good enough for the ATO and
fraud scenarios we care about.

Structural Causal Model representation:
  - Nodes: discrete variables with finite domains
  - Edges: directed dependencies (parent -> child)
  - CPTs:  conditional probability tables, P(child | parents)

Inference: enumerate joint probabilities over hidden variables given
observed evidence. Exact inference (variable elimination is overkill
for our 5-7 node networks).
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Iterable, Mapping


@dataclass
class CausalNode:
    name: str
    domain: tuple[str, ...]
    parents: tuple[str, ...] = ()
    # CPT keyed by tuple of parent values (in `parents` order).
    # Each value is dict[child_value -> probability], summing to 1.
    cpt: dict[tuple[str, ...], dict[str, float]] = field(default_factory=dict)

    def prior(self) -> dict[str, float]:
        """For nodes with no parents."""
        if self.parents:
            raise ValueError(f"{self.name} has parents; use cpt directly")
        return self.cpt[()]

    def p(self, value: str, parent_values: tuple[str, ...]) -> float:
        """P(this_node = value | parents = parent_values)."""
        row = self.cpt.get(parent_values)
        if row is None:
            raise KeyError(f"missing CPT row for {self.name} given {parent_values}")
        return row.get(value, 0.0)


class CausalGraph:
    def __init__(self):
        self._nodes: dict[str, CausalNode] = {}
        self._topo: list[str] = []

    def add(self, node: CausalNode) -> None:
        self._nodes[node.name] = node
        self._recompute_topo()

    def _recompute_topo(self) -> None:
        seen: set[str] = set()
        order: list[str] = []
        def visit(n: str):
            if n in seen:
                return
            for p in self._nodes[n].parents:
                visit(p)
            seen.add(n)
            order.append(n)
        for name in self._nodes:
            visit(name)
        self._topo = order

    def joint_probability(self, assignment: Mapping[str, str]) -> float:
        """P(assignment) over a complete configuration."""
        prob = 1.0
        for name in self._topo:
            node = self._nodes[name]
            value = assignment[name]
            parent_values = tuple(assignment[p] for p in node.parents)
            prob *= node.p(value, parent_values)
            if prob == 0.0:
                return 0.0
        return prob

    def all_assignments(self) -> Iterable[dict[str, str]]:
        names = list(self._topo)
        domains = [self._nodes[n].domain for n in names]
        for combo in itertools.product(*domains):
            yield dict(zip(names, combo))

    def posterior(self, evidence: Mapping[str, str],
                  query: str) -> dict[str, float]:
        """P(query_node | evidence) by exact enumeration."""
        if query not in self._nodes:
            raise KeyError(query)
        unnorm: dict[str, float] = {v: 0.0 for v in self._nodes[query].domain}
        for assignment in self.all_assignments():
            # Filter to those consistent with evidence
            if any(assignment.get(k) != v for k, v in evidence.items()):
                continue
            unnorm[assignment[query]] += self.joint_probability(assignment)
        total = sum(unnorm.values())
        if total <= 0.0:
            return {v: 1.0 / len(unnorm) for v in unnorm}  # uniform fallback
        return {k: v / total for k, v in unnorm.items()}

    def most_likely(self, evidence: Mapping[str, str],
                    query: str) -> tuple[str, float]:
        post = self.posterior(evidence, query)
        return max(post.items(), key=lambda kv: kv[1])


# ---- Domain-specific networks ---------------------------------------

def build_ato_network() -> CausalGraph:
    """Account-takeover causal model.

    Latent root cause: 'phished_credentials' (yes/no).
    Latent intermediate: 'attacker_active' (yes/no).
    Observed: impossible_travel, new_device, mfa_failure_burst.

    A legitimate "new geo + new device" combo (e.g. user travels and
    buys new phone) is RARE but possible; ATO is more common in the
    population we ever see an alert for.
    """
    g = CausalGraph()

    # Root: was the user phished recently?
    g.add(CausalNode(
        name="phished",
        domain=("yes", "no"),
        parents=(),
        cpt={(): {"yes": 0.05, "no": 0.95}},  # base rate among alerted users
    ))

    # Intermediate: is an attacker actively using stolen creds?
    # Nearly certain if phished; very rare otherwise.
    g.add(CausalNode(
        name="attacker_active",
        domain=("yes", "no"),
        parents=("phished",),
        cpt={
            ("yes",): {"yes": 0.90, "no": 0.10},
            ("no",):  {"yes": 0.005, "no": 0.995},
        },
    ))

    # Observable: impossible travel.
    # Very likely under attacker, rare otherwise (fast intl flight).
    g.add(CausalNode(
        name="impossible_travel",
        domain=("yes", "no"),
        parents=("attacker_active",),
        cpt={
            ("yes",): {"yes": 0.70, "no": 0.30},
            ("no",):  {"yes": 0.02, "no": 0.98},
        },
    ))

    # Observable: new device login.
    # Common under attacker (their device); rare-but-possible legit (new phone).
    g.add(CausalNode(
        name="new_device",
        domain=("yes", "no"),
        parents=("attacker_active",),
        cpt={
            ("yes",): {"yes": 0.85, "no": 0.15},
            ("no",):  {"yes": 0.05, "no": 0.95},
        },
    ))

    # Observable: MFA failure burst (attacker doesn't have the second factor).
    g.add(CausalNode(
        name="mfa_burst",
        domain=("yes", "no"),
        parents=("attacker_active",),
        cpt={
            ("yes",): {"yes": 0.40, "no": 0.60},   # not always — token-stuffing exists
            ("no",):  {"yes": 0.01, "no": 0.99},
        },
    ))

    return g


def infer_ato(observations: Mapping[str, str]) -> dict:
    """Convenience: take observation dict, return posterior over root cause.

    Returns:
      {
        "p_phished":     0.97,
        "p_attacker_active": 0.94,
        "most_likely_root_cause": ("phished", 0.97),
        "evidence_consistent": True,
      }
    """
    g = build_ato_network()
    p_phished = g.posterior(observations, "phished")
    p_attacker = g.posterior(observations, "attacker_active")
    most_likely = g.most_likely(observations, "phished")
    # Sanity: if no observations, posterior == prior; flag that
    consistent = bool(observations)
    return {
        "p_phished": round(p_phished["yes"], 3),
        "p_attacker_active": round(p_attacker["yes"], 3),
        "most_likely_root_cause": most_likely,
        "evidence_consistent": consistent,
        "observations": dict(observations),
    }


def build_fraud_network() -> CausalGraph:
    """Transaction-fraud causal model.

    Latent root cause: 'compromise' — a credential / device / account
    has been compromised, OR the customer is being coerced (mule / scam).
    Latent intermediate: 'attacker_extracting' — an attacker is
    actively trying to drain funds.
    Observed: mule_destination, novel_high_value_rail, structuring,
    velocity_anomaly.

    Base rates: among ALERTED transactions, compromise prior is higher
    than the population (alerts already reflect anomaly screening).
    """
    g = CausalGraph()

    g.add(CausalNode(
        name="compromise",
        domain=("yes", "no"),
        parents=(),
        cpt={(): {"yes": 0.10, "no": 0.90}},  # 10% base among alerted txns
    ))

    g.add(CausalNode(
        name="attacker_extracting",
        domain=("yes", "no"),
        parents=("compromise",),
        cpt={
            ("yes",): {"yes": 0.85, "no": 0.15},
            ("no",):  {"yes": 0.005, "no": 0.995},
        },
    ))

    # Mule destination — strong signal; legit customers very rarely send to mules
    g.add(CausalNode(
        name="mule_destination",
        domain=("yes", "no"),
        parents=("attacker_extracting",),
        cpt={
            ("yes",): {"yes": 0.65, "no": 0.35},
            ("no",):  {"yes": 0.005, "no": 0.995},
        },
    ))

    # Novel high-value rail switch — evasion signal
    g.add(CausalNode(
        name="novel_high_value_rail",
        domain=("yes", "no"),
        parents=("attacker_extracting",),
        cpt={
            ("yes",): {"yes": 0.55, "no": 0.45},
            ("no",):  {"yes": 0.03, "no": 0.97},      # legit users do switch sometimes
        },
    ))

    # Structuring pattern (just-under-CTR) — strong AML signal
    g.add(CausalNode(
        name="structuring",
        domain=("yes", "no"),
        parents=("attacker_extracting",),
        cpt={
            ("yes",): {"yes": 0.40, "no": 0.60},
            ("no",):  {"yes": 0.002, "no": 0.998},
        },
    ))

    # Velocity anomaly (count or amount p99x)
    g.add(CausalNode(
        name="velocity_anomaly",
        domain=("yes", "no"),
        parents=("attacker_extracting",),
        cpt={
            ("yes",): {"yes": 0.70, "no": 0.30},
            ("no",):  {"yes": 0.05, "no": 0.95},
        },
    ))

    return g


def infer_fraud(observations: Mapping[str, str]) -> dict:
    g = build_fraud_network()
    p_compromise = g.posterior(observations, "compromise")
    p_attacker = g.posterior(observations, "attacker_extracting")
    most_likely = g.most_likely(observations, "compromise")
    return {
        "p_compromise": round(p_compromise["yes"], 3),
        "p_attacker_extracting": round(p_attacker["yes"], 3),
        "most_likely_root_cause": most_likely,
        "evidence_consistent": bool(observations),
        "observations": dict(observations),
    }


def build_lateral_movement_network() -> CausalGraph:
    """EDR / lateral-movement causal model.

    Latent root cause: 'initial_access' — attacker has gained a foothold
    on at least one host (phishing / exploit / supply-chain).
    Latent intermediate: 'pivoting' — actively moving across hosts.
    Observed: suspicious_process_tree, cross_zone_admin, ioc_match,
    file_integrity_drift.
    """
    g = CausalGraph()

    g.add(CausalNode(
        name="initial_access",
        domain=("yes", "no"),
        parents=(),
        cpt={(): {"yes": 0.08, "no": 0.92}},  # 8% base among EDR-alerted hosts
    ))

    g.add(CausalNode(
        name="pivoting",
        domain=("yes", "no"),
        parents=("initial_access",),
        cpt={
            ("yes",): {"yes": 0.70, "no": 0.30},   # not always — some attackers stay quiet
            ("no",):  {"yes": 0.001, "no": 0.999},
        },
    ))

    # Suspicious parent->child process (winword spawning powershell, etc.)
    g.add(CausalNode(
        name="suspicious_process_tree",
        domain=("yes", "no"),
        parents=("pivoting",),
        cpt={
            ("yes",): {"yes": 0.80, "no": 0.20},
            ("no",):  {"yes": 0.02, "no": 0.98},   # rare admin actions can mimic
        },
    ))

    # Cross-zone admin protocol use (SMB/WinRM/RDP across security zones)
    g.add(CausalNode(
        name="cross_zone_admin",
        domain=("yes", "no"),
        parents=("pivoting",),
        cpt={
            ("yes",): {"yes": 0.60, "no": 0.40},
            ("no",):  {"yes": 0.01, "no": 0.99},   # legitimate admins rarely cross zones
        },
    ))

    # IOC match (hash / domain / IP from threat-intel)
    g.add(CausalNode(
        name="ioc_match",
        domain=("yes", "no"),
        parents=("pivoting",),
        cpt={
            ("yes",): {"yes": 0.45, "no": 0.55},   # not all attackers reuse known IOCs
            ("no",):  {"yes": 0.001, "no": 0.999},  # legit traffic almost never matches
        },
    ))

    # File integrity drift (e.g., /etc/passwd modified)
    g.add(CausalNode(
        name="file_integrity_drift",
        domain=("yes", "no"),
        parents=("pivoting",),
        cpt={
            ("yes",): {"yes": 0.35, "no": 0.65},
            ("no",):  {"yes": 0.005, "no": 0.995},
        },
    ))

    return g


def infer_lateral_movement(observations: Mapping[str, str]) -> dict:
    g = build_lateral_movement_network()
    p_initial = g.posterior(observations, "initial_access")
    p_pivot = g.posterior(observations, "pivoting")
    most_likely = g.most_likely(observations, "initial_access")
    return {
        "p_initial_access": round(p_initial["yes"], 3),
        "p_pivoting": round(p_pivot["yes"], 3),
        "most_likely_root_cause": most_likely,
        "evidence_consistent": bool(observations),
        "observations": dict(observations),
    }
