"""What the async investigation tier adds to a HITL card (roadmap 2.4b "updating the HITL card in place").

The approval is filed when the verdict is out; the blast graph, plan, twin and containment arrive
later. ``investigation_card(chain)`` folds ``chain.metadata`` into one compact, size-capped block the
dashboard renders — no raw payloads, no alert body, abstract node ids only.
"""

from __future__ import annotations

import json
from typing import Any

CARD_CAP = 24_000          # bytes; the approvals table stores args_json as TEXT, keep the card readable
MAX_NODES = 60
MAX_EDGES = 80


def _shrink(d: dict, nodes: int, edges: int) -> dict:
    g = d.get("blast_radius")
    if g:
        g["nodes"] = g["nodes"][:nodes]; g["edges"] = g["edges"][:edges]
        g["truncated_for_card"] = True
    return d


def investigation_card(chain: Any) -> dict | None:
    """Compact investigation block from a chain's metadata, or None when the async tier has not run."""
    md = getattr(chain, "metadata", None) or {}
    bg, plan, twin, cont, camp = md.get("blast_graph"), md.get("mitigation_plan"), md.get("twin"), md.get("containment"), md.get("campaign_context")
    if not any((bg, plan, twin, cont, camp)):
        return None
    card: dict[str, Any] = {"verdict": getattr(chain, "verdict", ""), "tier": (md.get("investigation") or {}).get("tier", "async")}
    if bg:
        s = bg.get("summary", {})
        nodes = sorted(bg.get("nodes", []), key=lambda n: (n.get("distance", 9), -float(n.get("sensitivity", 0))))
        keep = {n["id"] for n in nodes[:MAX_NODES]}
        card["blast_radius"] = {
            "nodes": [{"id": n["id"], "type": n.get("type", ""), "d": n.get("distance", 0), "s": round(float(n.get("sensitivity", 0)), 2)} for n in nodes[:MAX_NODES]],
            "edges": [{"a": e["a"], "r": e.get("relation", ""), "b": e["b"]} for e in bg.get("edges", []) if e.get("a") in keep and e.get("b") in keep][:MAX_EDGES],
            "counts": s.get("counts", {}), "nodes_reached": s.get("nodes_reached", 0),
            "critical": s.get("critical_assets_reached", [])[:10],
            "critical_count": s.get("critical_count", len(s.get("critical_assets_reached", []))),
            # failed telemetry queries: the analyst must not read "0 critical" as "nothing reachable" (review B3)
            "incomplete": bool(s.get("incomplete")), "query_errors": s.get("query_errors", {}),
            "choke_edges": [{"edge": c.get("edge"), "protects": c.get("protects", [])[:5]} if isinstance(c, dict) else {"edge": str(c), "protects": []}
                            for c in s.get("choke_edges", [])[:6]],
            "walkers": s.get("walkers", []), "truncated": s.get("truncated", []),
            "earliest_touch": s.get("earliest_touch"),
        }
    if plan:
        card["plan"] = {
            "steps": [{"n": st.get("order"), "action": st.get("action_type"), "target": st.get("target"), "why": str(st.get("why", ""))[:200],
                       "protects": st.get("protects", [])[:6], "reduction": st.get("radius_reduction"), "disruption": st.get("disruption"),
                       "rollback": str(st.get("rollback", ""))[:160], "hitl": bool(st.get("requires_hitl"))} for st in plan.get("steps", [])[:8]],
            "protected": plan.get("protected", [])[:10], "unprotected": plan.get("unprotected", [])[:10],
            "disruption": plan.get("disruption"), "efficiency": plan.get("efficiency"), "note": str(plan.get("note", ""))[:200],
        }
    if twin:
        card["twin"] = ({"skipped": twin["skipped"]} if twin.get("skipped") else
                        {"personas": twin.get("personas"), "rounds": twin.get("rounds"), "exposure": twin.get("crown_rate"),
                         "with_plan": (twin.get("with_plan") or {}).get("crown_rate"), "plan_effectiveness": twin.get("plan_effectiveness"),
                         "median_rounds": twin.get("median_rounds_to_crown"), "low_sample": bool(twin.get("low_sample")),
                         "by_archetype": twin.get("by_archetype", {}), "top_cuts": twin.get("ranked_cuts", [])[:5],
                         "persona_source": twin.get("persona_source"), "stale": twin.get("stale"),
                         "simulated": twin.get("simulated")})
    if cont:
        card["containment"] = [{"step": c.get("step"), "action": c.get("action"), "target": c.get("target"),
                                "before": len(c.get("critical_before", [])), "after": len(c.get("critical_after", [])),
                                "shrank": len(c.get("critical_after", [])) < len(c.get("critical_before", [])),
                                "new_nodes": c.get("new_nodes", [])[:5], "measured": c.get("baseline", True)} for c in cont[-10:]]
    if camp:
        card["campaign"] = {"events": camp.get("events_in_window"), "window_min": camp.get("window_minutes"), "sources": camp.get("sources", [])[:6],
                            "endpoints": (camp.get("enumeration") or {}).get("distinct_endpoints"), "requests_per_min": (camp.get("automation") or {}).get("requests_per_min"),
                            "waf_blocked": (camp.get("waf") or {}).get("blocked"), "attack_classes": (camp.get("waf") or {}).get("attack_classes", [])[:6],
                            "cross_owner_reads": (camp.get("access") or {}).get("cross_owner_reads"), "cross_owner_writes": (camp.get("access") or {}).get("cross_owner_writes"),
                            "span_minutes": (camp.get("timeline") or {}).get("span_minutes"), "first_event_at": (camp.get("timeline") or {}).get("first_event_at")}
    # size cap: shrink the graph first, then drop it
    n, e = MAX_NODES, MAX_EDGES
    while len(json.dumps(card)) > CARD_CAP and card.get("blast_radius"):
        if n <= 10:
            card["blast_radius"].pop("nodes", None); card["blast_radius"].pop("edges", None); break
        n //= 2; e //= 2; _shrink(card, n, e)
    return card


__all__ = ["investigation_card", "CARD_CAP"]
