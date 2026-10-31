"""Blast radius as a graph walk (roadmap 2.5) + the post-verdict investigation tier (2.4b).

Today's ``worker_blast_radius`` reads the entities *in the alert* — one hop, no lookups. A real
blast radius is a graph walk from those seeds across the vendor stack:

    identity     user → sessions, tokens, devices, groups, consented apps, admin roles
    endpoint     host → child processes, lateral logons from it, files written, other hosts
    network      host/IP → internal flows, DNS, rules touched
    cloud        principal → keys, roles assumed, resources, buckets opened
    data         user → tables, downloads, DLP hits in the window
    transaction  account → beneficiaries, mule fan-in, linked accounts

Each walker is 2 hops, time-boxed, and talks to a :class:`TelemetrySource` (a mock tenant until
the real connectors exist — same pattern as the 1.2 vendor connectors). Edges merge into one
:class:`BlastGraph`; nodes are scored by distance × asset sensitivity; the result is one
evidence item ("radius: N accounts, M hosts, K critical assets reached, earliest touch T−x")
plus ``chain.metadata["blast_graph"]``; :mod:`.mitigation` then finds the minimum cut (2.6) and attaches
an ordered HITL plan (``metadata["mitigation_plan"]`` + ``RecommendedAction``s).

It runs in the **async investigation tier**: :class:`Investigator` takes a sealed chain after the
verdict is out, walks, re-seals the chain with the graph attached, and never changes the verdict
(the swarm's confirming-evidence rule still applies only to intel / decoy hits).
"""

from .campaign import EventStore, attach_campaign_context, campaign_summary
from .graph import BlastGraph, Edge, Node
from .investigation import Investigator, investigate
from .loop import ContainmentLoop, LoopEntry
from .mitigation import Plan, attach_plan, plan_mitigation
from .sources import InventorySource, MockTenant, TelemetrySource, tenant_from_env
from .twin import Persona, TwinReport, run_twin, simulate
from .walk import DEFAULT_WALKERS, Walker, run_walkers

__all__ = ["BlastGraph", "ContainmentLoop", "DEFAULT_WALKERS", "Edge", "EventStore", "Investigator", "InventorySource", "LoopEntry", "MockTenant", "Node", "TelemetrySource", "tenant_from_env",
           "attach_campaign_context", "campaign_summary",
           "Persona", "Plan", "TwinReport", "Walker", "attach_plan", "investigate", "plan_mitigation", "run_twin", "run_walkers", "simulate"]
