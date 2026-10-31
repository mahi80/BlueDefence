"use client";

import { useMemo } from "react";
import type { Chain, GraphNode, RecommendedAction } from "../lib/types";
import { chainToGraph } from "../lib/graph";

/**
 * Calm attack-path map (decision-first redesign).
 *
 * The old view was a D3 force-directed graph: nodes drifted, you had to drag them
 * to read labels, and the swarm fan-out animated in. Great demo, hard to read under
 * pressure. This replaces it with a deterministic left→right layered layout computed
 * once — seed on the left, then each hop of the attack, crown-jewel assets ringed on
 * the right. The min-cut "isolate plan" edges are drawn as a distinct dashed cut, and
 * any asset AEGIS proposes a containment action on is badged and clickable to jump to
 * that action in the decision panel. No physics, nothing to drag, no animation.
 *
 * Pure SVG — no d3. Swarm/worker nodes are intentionally dropped here; this map is the
 * attack path an analyst reasons about, not the orchestrator's internal fan-out.
 */

const VCOLOR: Record<string, string> = {
  malicious: "var(--v-malicious)",
  suspicious: "var(--v-suspicious)",
  benign: "var(--v-benign)",
  uncertain: "var(--v-uncertain)",
};
const GLYPH: Record<string, string> = { alert: "!", host: "H", service: "S", identity: "ID", data: "DB" };

function nodeColor(n: GraphNode): string {
  return VCOLOR[n.verdict ?? "uncertain"] ?? "var(--v-uncertain)";
}
function nodeRadius(n: GraphNode): number {
  if (n.kind === "alert") return 18;
  return n.critical ? 16 : 12;
}

type Placed = GraphNode & { x: number; y: number; hop: number };

// Geometry (SVG user units; the <svg> scales to its container via viewBox).
const MARGIN_X = 70;
const MARGIN_Y = 44;
const COL_GAP = 168;
const ROW_GAP = 92;

/** Assign each asset a hop (column) by walking the attack edges forward from the
 *  roots (nodes nothing points at), then fill any stragglers undirected. Deterministic. */
function layout(chain: Chain): { placed: Placed[]; edges: { a: Placed; b: Placed; choke: boolean; implicit: boolean }[]; cols: number; w: number; h: number } {
  const graph = chainToGraph(chain);
  const assets = graph.nodes.filter((n) => n.kind !== "worker");
  const assetIds = new Set(assets.map((n) => n.id));
  const alert = assets.find((n) => n.kind === "alert");
  const flow = graph.edges.filter(
    (e) => e.kind !== "swarm" && e.source !== e.target && assetIds.has(e.source) && assetIds.has(e.target),
  );

  const fwd = new Map<string, string[]>();
  const undirected = new Map<string, string[]>();
  const indeg = new Map<string, number>();
  for (const n of assets) {
    fwd.set(n.id, []);
    undirected.set(n.id, []);
    indeg.set(n.id, 0);
  }
  for (const e of flow) {
    fwd.get(e.source)!.push(e.target);
    undirected.get(e.source)!.push(e.target);
    undirected.get(e.target)!.push(e.source);
    indeg.set(e.target, (indeg.get(e.target) ?? 0) + 1);
  }

  // roots = asset nodes nothing points at (excluding the alert marker)
  const roots = assets.filter((n) => n.kind !== "alert" && (indeg.get(n.id) ?? 0) === 0).map((n) => n.id);
  const hop = new Map<string, number>();
  const q: string[] = [];
  for (const r of roots.length ? roots : assets.filter((n) => n.kind !== "alert").map((n) => n.id)) {
    hop.set(r, 1);
    q.push(r);
  }
  while (q.length) {
    const id = q.shift()!;
    for (const nx of fwd.get(id) ?? []) {
      if (!hop.has(nx)) {
        hop.set(nx, (hop.get(id) ?? 1) + 1);
        q.push(nx);
      }
    }
  }
  // stragglers (no forward path reached them) — place undirected-adjacent, else hop 1
  for (const n of assets) {
    if (n.kind === "alert" || hop.has(n.id)) continue;
    const near = (undirected.get(n.id) ?? []).map((x) => hop.get(x)).filter((v): v is number => v != null);
    hop.set(n.id, near.length ? Math.max(...near) + 1 : 1);
  }
  if (alert) hop.set(alert.id, 0);

  // group by column, place rows evenly
  const byCol = new Map<number, GraphNode[]>();
  for (const n of assets) {
    const h = hop.get(n.id) ?? 1;
    byCol.set(h, [...(byCol.get(h) ?? []), n]);
  }
  const cols = Math.max(...byCol.keys(), 0) + 1;
  const maxRows = Math.max(...[...byCol.values()].map((c) => c.length), 1);
  const w = MARGIN_X * 2 + (cols - 1) * COL_GAP;
  const h = MARGIN_Y * 2 + (maxRows - 1) * ROW_GAP + 40;

  const pos = new Map<string, Placed>();
  for (const [c, group] of byCol) {
    group.forEach((n, i) => {
      const x = MARGIN_X + c * COL_GAP;
      const y = MARGIN_Y + (group.length === 1 ? (maxRows - 1) * ROW_GAP * 0.5 : i * ((maxRows - 1) * ROW_GAP) / Math.max(1, group.length - 1));
      pos.set(n.id, { ...n, x, y, hop: c });
    });
  }

  const edges = flow
    .map((e) => ({ a: pos.get(e.source)!, b: pos.get(e.target)!, choke: !!e.choke, implicit: false }))
    .filter((e) => e.a && e.b);
  // link the seed to the attack roots so the path reads from one origin
  if (alert) {
    const seed = pos.get(alert.id)!;
    for (const r of roots) {
      const rp = pos.get(r);
      if (rp) edges.push({ a: seed, b: rp, choke: false, implicit: true });
    }
  }
  return { placed: [...pos.values()], edges, cols, w, h };
}

export default function BlastGraph({ chain, onSelectAction }: { chain: Chain; onSelectAction?: (a: RecommendedAction, nodeId: string) => void }) {
  const { placed, edges, w, h } = useMemo(() => layout(chain), [chain]);

  return (
    <svg
      className="pathmap"
      viewBox={`0 0 ${w} ${h}`}
      preserveAspectRatio="xMidYMid meet"
      role="img"
      aria-label="Attack path from the alert to crown-jewel assets, with the proposed isolate plan"
    >
      <defs>
        <marker id="pm-arrow" markerWidth="7" markerHeight="7" refX="6.5" refY="3.5" orient="auto">
          <path d="M0,0 L7,3.5 L0,7 z" fill="var(--ink-faint)" />
        </marker>
      </defs>

      {edges.map((e, i) => (
        <line
          key={i}
          x1={e.a.x}
          y1={e.a.y}
          x2={e.b.x}
          y2={e.b.y}
          className={`pm-link${e.choke ? " cut" : ""}${e.implicit ? " seed" : ""}`}
          markerEnd={e.implicit ? undefined : "url(#pm-arrow)"}
        />
      ))}

      {placed.map((n) => {
        const r = nodeRadius(n);
        const clickable = !!n.action && !!onSelectAction;
        const filled = n.reached || n.kind === "alert";
        return (
          <g
            key={n.id}
            className={`pm-node${n.reached ? " reached" : ""}${filled ? " filled" : ""}${n.critical ? " crit" : ""}${clickable ? " act" : ""}`}
            style={{ color: nodeColor(n) }}
            transform={`translate(${n.x},${n.y})`}
            tabIndex={clickable ? 0 : -1}
            onClick={clickable ? () => onSelectAction!(n.action!, n.id) : undefined}
            onKeyDown={clickable ? (ev) => { if (ev.key === "Enter" || ev.key === " ") onSelectAction!(n.action!, n.id); } : undefined}
          >
            <title>
              {(n.id === "__alert" ? "alert" : n.label)}
              {` — ${n.kind}`}
              {n.verdict ? ` · ${n.verdict}` : ""}
              {n.critical ? " · crown-jewel" : ""}
              {n.reached ? " · reached" : ""}
              {n.action ? ` · proposed: ${n.action.action_type} (click to review)` : ""}
            </title>
            {n.critical && <circle className="ring" r={r + 5} />}
            <circle className="dot" r={r} fill={filled ? nodeColor(n) : "var(--surface-2)"} stroke={nodeColor(n)} />
            <text className="glyph" textAnchor="middle" dy="0.34em">{GLYPH[n.kind] ?? ""}</text>
            {n.action && <circle className="shield" r={5} cx={r - 2} cy={-r + 2} />}
            <text className="lbl" textAnchor="middle" dy={r + 15}>{n.id === "__alert" ? "alert" : n.label}</text>
          </g>
        );
      })}
    </svg>
  );
}
