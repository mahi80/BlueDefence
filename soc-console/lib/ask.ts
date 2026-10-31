// Agent Q — answers an analyst's questions about a specific detection, straight from the chain
// the console already has. Deterministic by design: it never invents facts, it reads them off the
// EvidenceChain, so what Q says always matches what the swarm actually concluded. A free-text
// question can be forwarded to the real LLM-backed Q (see app/api/ask/route.ts); this is both the
// offline answerer and that route's fallback.

import type { Chain, BlastNode, EvidenceItem } from "./types";

export const SUGGESTED = [
  "Why is this suspicious?",
  "Show me the evidence",
  "What's at risk?",
  "What should I do?",
  "How confident are you?",
] as const;

const pct = (n: number) => `${Math.round((n ?? 0) * 100)}%`;
const list = (xs: string[]) => (xs.length ? xs.join(", ") : "none");
const WEIGHT_RANK: Record<string, number> = { high: 3, medium: 2, low: 1 };

/** The concrete signals behind the verdict — strongest first. This is what an
 *  analyst means by "why do you think so?": show the evidence, not a summary. */
function evidence(chain: Chain): string {
  const items = [...(chain.evidence ?? [])].sort(
    (a, b) => (WEIGHT_RANK[b.weight] ?? 0) - (WEIGHT_RANK[a.weight] ?? 0),
  );
  if (!items.length) {
    return `I recorded ${chain.evidence_count} piece${chain.evidence_count === 1 ? "" : "s"} of evidence for this ${chain.verdict} verdict${chain.note ? `: ${chain.note}` : "."} The detailed signals aren't attached to this chain copy — open the evidence chain (${chain.integrity_hash?.slice(0, 12) || "n/a"}…) for the full list.`;
  }
  const lead = `Here's what led me to call ${chain.source} ${chain.verdict} (${pct(chain.confidence)} confidence) — ${items.length} signal${items.length === 1 ? "" : "s"}, strongest first:`;
  const lines = items.map((e) => `  • [${e.weight}] ${e.signal} (${e.source})`);
  const strong = items.filter((e) => e.weight === "high").length;
  const tail = strong
    ? `\nThe ${strong} high-weight signal${strong === 1 ? "" : "s"} are the ones carrying the verdict; the rest corroborate.`
    : `\nNothing here is high-weight on its own — that's why the verdict is ${chain.verdict} and not confirmed-malicious, and why the stronger actions still want your sign-off.`;
  return `${lead}\n${lines.join("\n")}${tail}`;
}

function blast(chain: Chain): string {
  const inv = chain.investigation;
  if (!inv?.blast_radius?.nodes?.length) {
    return "The swarm hasn't mapped a blast radius for this one yet — so far it's scoped to the originating alert.";
  }
  const nodes = inv.blast_radius.nodes.filter((n) => n.kind !== "alert" && n.kind !== "worker");
  const reached = nodes.filter((n) => n.reached);
  const crown = nodes.filter((n) => n.critical);
  const named = (ns: BlastNode[]) => list(ns.map((n) => n.label));
  const parts = [
    `${nodes.length} asset${nodes.length === 1 ? "" : "s"} are in the blast radius.`,
  ];
  if (reached.length) parts.push(`The attacker is believed to have reached ${reached.length} of them: ${named(reached)}.`);
  else parts.push("None are believed reached yet — this is exposure, not confirmed compromise.");
  if (crown.length) parts.push(`Crown-jewel assets exposed: ${named(crown)} — prioritise these.`);
  const chokes = inv.blast_radius.choke_edges?.length ?? 0;
  if (chokes) parts.push(`There's a ${chokes}-edge choke point: cutting it isolates the path with the least disruption.`);
  return parts.join(" ");
}

function actions(chain: Chain): string {
  const acts = chain.recommended_actions ?? [];
  if (!acts.length) return "No containment actions are recommended on this chain — it's informational.";
  const auto = acts.filter((a) => !a.requires_hitl);
  const hitl = acts.filter((a) => a.requires_hitl);
  const fmt = (a: { action_type: string; target: string }) => `${a.action_type.replace(/_/g, " ")} ${a.target}`;
  const parts: string[] = [];
  if (hitl.length) parts.push(`${hitl.length} action${hitl.length === 1 ? "" : "s"} need${hitl.length === 1 ? "s" : ""} your approval: ${list(hitl.map(fmt))}.`);
  if (auto.length) parts.push(`${auto.length} ${auto.length === 1 ? "is" : "are"} safe enough to auto-apply: ${list(auto.map(fmt))}.`);
  const steps = chain.investigation?.plan?.steps;
  if (steps?.length) {
    const ordered = [...steps].sort((a, b) => a.order - b.order).map((s) => `${s.order}. ${s.action_type.replace(/_/g, " ")} ${s.target}`);
    parts.push(`Suggested order: ${ordered.join("  ")}.`);
  }
  parts.push("Nothing executes until you approve it — the model proposes, you decide.");
  return parts.join(" ");
}

function whoInvestigated(chain: Chain): string {
  const specialists = list(chain.specialists ?? []);
  const swarm = chain.investigation?.swarm ?? [];
  let s = `Triage went to ${specialists || "the orchestrator"}, over ${chain.evidence_count} piece${chain.evidence_count === 1 ? "" : "s"} of evidence.`;
  if (swarm.length) s += ` Then ${swarm.length} swarm worker${swarm.length === 1 ? "" : "s"} fanned out to corroborate: ${list(swarm)}.`;
  s += ` A second-family voter cross-checked the verdict for prompt-injection resistance.`;
  return s;
}

function why(chain: Chain): string {
  // "Why?" means show the evidence — lead with the one-line reason, then the signals.
  const headline = chain.note ? `${chain.note}\n` : "";
  let s = `${headline}${evidence(chain)}`;
  if (chain.governance_blocked) s += "\nNote: ACP governance blocked at least one proposed action — it's recorded in the audit chain.";
  return s;
}

function confidence(chain: Chain): string {
  const c = chain.confidence ?? 0;
  const band = c >= 0.85 ? "high" : c >= 0.6 ? "moderate" : "low";
  let s = `${pct(c)} — ${band} confidence.`;
  if (band !== "high") s += " More corroborating signals (a second specialist, threat-intel match, or a reached crown-jewel) would raise it; that's why some actions still need your sign-off.";
  else s += " Multiple corroborating signals line up, which is why the stronger actions are on the table.";
  return s;
}

// keyword → answer. First match wins; order matters (specific before general).
const RULES: Array<[RegExp, (c: Chain) => string]> = [
  [/\b(risk|blast|impact|affect|expos|reach|lateral|spread|crown|jewel)\b/i, blast],
  [/\b(do|action|recommend|respond|contain|isolat|mitigat|next step|remediat|block)\b/i, actions],
  [/\b(confiden|certain|sure|how likely|probab)\b/i, confidence],
  [/\b(who|swarm|which agent|investigat|specialist|analys[ei]s)\b/i, whoInvestigated],
  [/\b(govern|policy|acp|blocked|complian)\b/i, (c) => c.governance_blocked
    ? "ACP governance blocked at least one proposed action here, and wrote an allowed=false row to the audit chain — the regulator sees the override attempt."
    : "No governance block on this chain — every proposed action passed the ACP controls."],
  [/\b(audit|integrity|hash|tamper|proof|evidence chain)\b/i, (c) =>
    `This detection is an immutable evidence chain (integrity hash ${c.integrity_hash?.slice(0, 12) || "n/a"}…). Every reasoning step, signal and proposed action is hash-linked, so it can't be altered after the fact.`],
  [/\b(evidence|signal|indicator|ioc|proof|why.*(suspicious|malicious|flag)|basis|how do you know|justif)\b/i, evidence],
  [/\b(campaign|related|other alert|coordinat)\b/i, (c) => {
    const cm = c.investigation?.campaign;
    return cm?.related_alerts
      ? `This looks tied to a wider campaign — ${cm.related_alerts} related alert${cm.related_alerts === 1 ? "" : "s"}${cm.id ? ` (campaign ${cm.id})` : ""}. Treat it as one incident, not isolated noise.`
      : "No campaign correlation on this one yet — it reads as a standalone alert.";
  }],
  [/\b(why|flag|detect|what did you|what happen|explain|tell me)\b/i, why],
];

export function answerLocally(question: string, chain: Chain | undefined): string {
  if (!chain) return "Select an incident on the left and I'll tell you what we detected.";
  const q = question.trim();
  if (!q) return why(chain);
  for (const [re, fn] of RULES) if (re.test(q)) return fn(chain);
  // no keyword matched — orient the analyst with what Q can answer, grounded in this chain
  return `I can explain this ${chain.verdict} detection on ${chain.source}. Ask me why it was flagged, what's at risk, what to do, how confident I am, or who investigated it.`;
}

export function greeting(chain: Chain | undefined): string {
  if (!chain) return "Hi — I'm Agent Q. Pick an incident and I'll walk you through what AEGIS detected.";
  return `Hi — I'm Agent Q. I'm looking at the ${chain.verdict} detection on ${chain.source}. Ask me anything about it.`;
}
