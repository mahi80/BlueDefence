// Domain types for the AEGIS SOC console. These mirror the shapes the existing
// ACP dashboard already serves at /api/soc/* and /api/approvals/* (see soc_store.py).

export type Verdict = "benign" | "suspicious" | "malicious" | "uncertain";

export interface RecommendedAction {
  action_type: string; // e.g. isolate | block | block_egress | revoke_sessions | monitor | escalate
  target: string;
  requires_hitl: boolean;
  confidence?: number;
  reasoning?: string;
}

// One signal the swarm recorded on the chain. Mirrors the backend EvidenceItem
// (aegis.agents.shared.evidence_chain.EvidenceItem): source, human-readable signal,
// weight. This is what Agent Q cites when an analyst asks "why?".
export type Weight = "low" | "medium" | "high";
export interface EvidenceItem {
  source: string; // which specialist/worker observed it (e.g. perimeter, intel_enrich)
  signal: string; // the finding, in plain language
  weight: Weight;
  raw_data?: Record<string, unknown>;
}

// One asset in the blast radius the swarm mapped.
export interface BlastNode {
  id: string;
  label: string;
  kind: "alert" | "host" | "identity" | "service" | "data" | "worker";
  verdict?: Verdict;
  critical?: boolean; // a crown-jewel asset
  reached?: boolean; // attacker is believed to have reached it
}

export interface BlastEdge {
  source: string;
  target: string;
  kind?: "attack" | "lateral" | "exfil" | "swarm"; // swarm = orchestrator→worker fan-out
  choke?: boolean; // part of the min-cut = the isolate plan
}

export interface PlanStep {
  order: number;
  action_type: string;
  target: string;
  rationale?: string;
  cuts_edges?: Array<[string, string]>;
}

// The async-tier investigation attached to a chain (blast radius + mitigation plan).
export interface Investigation {
  blast_radius: {
    nodes: BlastNode[];
    edges: BlastEdge[];
    critical?: string[];
    choke_edges?: Array<[string, string]>;
  };
  plan?: { steps: PlanStep[] };
  swarm?: string[]; // workers that fanned out: ioc_extract, intel_enrich, blast_radius, ...
  campaign?: { id?: string; related_alerts?: number };
}

// Summary row from GET /api/soc/chains.
export interface ChainSummary {
  chain_id: string;
  alert_id: string;
  source: string;
  verdict: Verdict;
  confidence: number;
  specialists: string[];
  action_types: string[];
  evidence_count: number;
  governance_blocked: boolean;
  started_at: string;
  completed_at?: string;
  note?: string;
  triage?: "swarm" | "heuristic"; // "swarm" = investigated by the real AEGIS swarm (soc_live --brain)
}

// Full chain from GET /api/soc/chains/{id}.
export interface Chain extends ChainSummary {
  investigation?: Investigation;
  recommended_actions: RecommendedAction[];
  evidence?: EvidenceItem[]; // the signals behind the verdict — what Agent Q cites
  integrity_hash: string;
}

// HITL card from GET /api/approvals (args carry the AEGIS context).
export interface Approval {
  id: string;
  status: "pending" | "approved" | "rejected";
  created_at: string;
  action_type: string;
  target: string;
  alert_id?: string;
  integrity_hash?: string;
  reasoning?: string;
  agent_id?: string;
  decided_by?: string;
  decided_at?: string;
  rationale?: string;
}

// Meta-agent / model-promotion proposal from GET /api/soc/proposals.
export interface Proposal {
  id: string;
  change_type: string; // model_promotion | rule | ...
  status: "pending" | "accepted" | "rejected";
  summary: string;
  validation_passed?: boolean;
  rationale?: string;
  decided_by?: string;
  decided_at?: string;
  created_at: string;
}

// ---- visualization graph (composed from a Chain for the D3 map) ----
export interface GraphNode extends BlastNode {
  action?: RecommendedAction; // a containment action proposed against this node
}
export interface GraphEdge extends BlastEdge {}
export interface SocGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}
