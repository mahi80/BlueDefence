// Pure HITL card logic for the console (round 7 review U-1 … U-4). Kept free of React and JSON imports so the
// node test runner can exercise it directly.
import type { Approval, Chain, RecommendedAction } from "./types";

export type SettledStatus = "approved" | "rejected" | "failed" | "expired";
export type LocalDecision = { status: "approved" | "rejected"; note: string };

/** What one recommended action shows in the panel.
 *  - decide:   an approval card is pending (or awaiting a second approver) — Approve / Reject
 *  - settled:  the card is decided (approved / rejected / failed / expired)
 *  - no_card:  needs a human but the service has not filed a card yet
 *  - proposed: auto-eligible and no card was filed — the console cannot tell whether it ran (enforcement may be
 *              shadow), so it is never shown as "applied" (U-1) */
export type CardState =
  | { kind: "decide"; approval: Approval; awaitingSecond: boolean }
  | { kind: "settled"; approval?: Approval; status: SettledStatus; note: string }
  | { kind: "no_card" }
  | { kind: "proposed" };

const SETTLED = new Set(["approved", "rejected", "failed", "expired"]);

function ts(a: Approval): number {
  const t = Date.parse(a.created_at ?? "");
  return Number.isFinite(t) ? t : 0;
}

/** Newest card for (alert, action, target). An old settled card never hides a newer pending one (U-3). */
export function latestApprovalFor(approvals: Approval[], alertId: string, action: Pick<RecommendedAction, "action_type" | "target">):
  Approval | undefined {
  let best: Approval | undefined;
  for (const p of approvals) {
    if (p.alert_id !== alertId || p.action_type !== action.action_type || p.target !== action.target) continue;
    if (!best || ts(p) > ts(best)) best = p;                    // ties: the first row wins (the receiver lists newest first)
  }
  return best;
}

/** The state of one action card. A card filed for the action decides it, whatever `requires_hitl` says on the
 * chain (U-1); a local decision is keyed by the approval id it was made on (U-3). */
export function cardState(
  action: RecommendedAction,
  approval: Approval | undefined,
  local: Record<string, LocalDecision>,
  fixtureMode = false,
): CardState {
  if (approval) {
    const mine = local[approval.id];
    if (mine) return { kind: "settled", approval, status: mine.status, note: mine.note };
    if (SETTLED.has(approval.status)) {
      return { kind: "settled", approval, status: approval.status as SettledStatus, note: approval.rationale ?? "" };
    }
    return { kind: "decide", approval, awaitingSecond: approval.status === "awaiting_second" };
  }
  if (action.requires_hitl === false) return { kind: "proposed" };   // missing flag ≠ auto
  return fixtureMode ? { kind: "decide", approval: fixtureCard(action), awaitingSecond: false } : { kind: "no_card" };
}

function fixtureCard(a: RecommendedAction): Approval {
  return { id: `fixture:${a.action_type}:${a.target}`, status: "pending", created_at: "", action_type: a.action_type, target: a.target };
}

/** Cards awaiting a decision, newest first — the queue shown regardless of which incidents are loaded (U-2). */
export function pendingQueue(approvals: Approval[]): Approval[] {
  return approvals
    .filter((a) => a.status === "pending" || a.status === "awaiting_second")
    .map((a, i) => ({ a, i }))
    .sort((x, y) => ts(y.a) - ts(x.a) || x.i - y.i)
    .map(({ a }) => a);
}

/** Alert ids that have a pending card but are not in the loaded window, so the server hydrates them too (U-2). */
export function missingPendingAlerts(approvals: Approval[], loadedAlertIds: Set<string>, cap = 60): string[] {
  const out: string[] = [];
  for (const a of pendingQueue(approvals)) {
    const id = a.alert_id ?? "";
    if (id && !loadedAlertIds.has(id) && !out.includes(id)) out.push(id);
    if (out.length >= cap) break;
  }
  return out;
}

/** A chain that could not be read, rebuilt from its pending cards so they can still be decided (U-2 / U-4). */
export function stubChainFromApprovals(alertId: string, approvals: Approval[]): Chain {
  const mine = approvals.filter((a) => a.alert_id === alertId);
  const first = mine[0];
  return {
    chain_id: first?.integrity_hash || `alert:${alertId}`,
    alert_id: alertId,
    source: "unavailable",
    verdict: "uncertain",
    confidence: 0,
    specialists: [],
    action_types: mine.map((a) => a.action_type),
    evidence_count: 0,
    governance_blocked: false,
    started_at: first?.created_at ?? "",
    integrity_hash: first?.integrity_hash ?? "",
    recommended_actions: mine.map((a) => ({ action_type: a.action_type, target: a.target, requires_hitl: true, reasoning: a.reasoning })),
    partial: true,
  };
}

/** Merge detail reads with their summaries: a failed read keeps the summary row but is marked partial so the UI
 * says "details unavailable" instead of "no recommended actions" (U-4). Returns the chains and how many failed. */
export function mergeDetails<S extends { chain_id: string }>(
  summaries: S[],
  results: PromiseSettledResult<Chain | null>[],
): { chains: Chain[]; failed: number } {
  let failed = 0;
  const chains: Chain[] = [];
  results.forEach((r, i) => {
    if (r.status === "fulfilled") {
      if (r.value) chains.push(r.value);
    } else {
      failed++;
      chains.push({ ...(summaries[i] as unknown as Chain), recommended_actions: [], partial: true });
    }
  });
  return { chains, failed };
}
