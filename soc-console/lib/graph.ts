import type { Chain, SocGraph, GraphNode, GraphEdge } from "./types";

// Compose the visualization graph from a chain's investigation:
//   alert → AEGIS orchestrator → swarm workers (fan-out)
//   plus the blast-radius assets and attack edges, with the min-cut (choke) edges
//   that form the isolate plan, and any containment action pinned to its target node.
export function chainToGraph(chain: Chain): SocGraph {
  const inv = chain.investigation;
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const seen = new Set<string>();
  const add = (n: GraphNode) => {
    if (!seen.has(n.id)) {
      seen.add(n.id);
      nodes.push(n);
    }
  };

  // origin
  add({ id: "__alert", label: chain.source || "alert", kind: "alert", verdict: chain.verdict });

  if (inv) {
    const critical = new Set(inv.blast_radius.critical ?? []);
    const choke = new Set((inv.blast_radius.choke_edges ?? []).map(([a, b]) => `${a}->${b}`));
    for (const n of inv.blast_radius.nodes) {
      add({ ...n, critical: n.critical || critical.has(n.id) });
    }
    for (const e of inv.blast_radius.edges) {
      edges.push({ ...e, choke: e.choke || choke.has(`${e.source}->${e.target}`) });
    }
    // swarm fan-out
    if (inv.swarm && inv.swarm.length) {
      add({ id: "__aegis", label: "AEGIS", kind: "worker" });
      edges.push({ source: "__alert", target: "__aegis", kind: "swarm" });
      for (const w of inv.swarm) {
        const id = `__w_${w}`;
        add({ id, label: w, kind: "worker" });
        edges.push({ source: "__aegis", target: id, kind: "swarm" });
      }
    }
  }

  // pin containment actions to their target node
  for (const a of chain.recommended_actions ?? []) {
    const target = nodes.find((n) => n.id === a.target || n.label === a.target);
    if (target) target.action = a;
  }
  return { nodes, edges };
}

export const VERDICT_RANK: Record<string, number> = {
  malicious: 3,
  suspicious: 2,
  uncertain: 1,
  benign: 0,
};
