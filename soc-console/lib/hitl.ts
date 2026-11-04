// Pure HITL card logic for the console (round 7 review U-1 … U-4, round 8 U8-1 … U8-4). Kept free of React and JSON imports so the
// node test runner can exercise it directly.
import type { Approval, Chain, RecommendedAction } from "./types";

export type SettledStatus = "approved" | "rejected" | "failed" | "expired";
export type LocalDecision = { status: "approved" | "rejected"; note: string };

/** What one recommended action shows in the panel.
 *  - decide:   an approval card is pending (or awaiting a second approver) — Approve / Reject
 *  - settled:  the card is decided (approved / rejected / failed / expired)
 *  - awaiting_execution: approved, but the service has not run (settled) it yet — it can still be rejected (U8-2)
 *  - no_card:  needs a human but the service has not filed a card yet
 *  - proposed: auto-eligible and no card was filed — the console cannot tell whether it ran (enforcement may be
 *              shadow), so it is never shown as "applied" (U-1) */
export type CardState =
  | { kind: "decide"; approval: Approval; awaitingSecond: boolean }
  | { kind: "settled"; approval?: Approval; status: SettledStatus; note: string }
  | { kind: "awaiting_execution"; approval: Approval; note: string }
  | { kind: "no_card" }
  | { kind: "proposed" };

const SETTLED = new Set(["approved", "rejected", "failed", "expired"]);

function ts(a: Approval): number {
  const t = Date.parse(a.created_at ?? "");
  return Number.isFinite(t) ? t : 0;
}

/** The full target a card binds to. `target` is a display cut (256 chars); the receiver serves `target_full`, and
 * both the AEGIS card and the ACP dashboard row carry `action` = "type -> full target" (round 8 U8-1). */
export function fullTarget(a: Approval): string {
  if (typeof a.target_full === "string" && a.target_full) return a.target_full;
  const pre = `${a.action_type} -> `;
  if (typeof a.action === "string" && a.action.startsWith(pre)) return a.action.slice(pre.length);
  return a.target;
}

/** Newest card for (alert, action, full target). An old settled card never hides a newer pending one (U-3); a
 * target longer than the display cut still matches (U8-1). */
export function latestApprovalFor(approvals: Approval[], alertId: string, action: Pick<RecommendedAction, "action_type" | "target">):
  Approval | undefined {
  let best: Approval | undefined;
  for (const p of approvals) {
    if (p.alert_id !== alertId || p.action_type !== action.action_type || fullTarget(p) !== action.target) continue;
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
    // approved here, or approved on the backend, but the service has not settled (run) it yet: still rejectable —
    // the receiver accepts a reject until the settled marker lands (U8-2). Only when the backend says so
    // (`settled: false`); a backend that does not report it keeps the final "Approved".
    const unsettled = approval.settled === false;
    if (mine) {
      if (mine.status === "approved" && unsettled && approval.status !== "awaiting_second") {
        return { kind: "awaiting_execution", approval, note: mine.note };
      }
      return { kind: "settled", approval, status: mine.status, note: mine.note };
    }
    if (approval.status === "approved" && unsettled) return { kind: "awaiting_execution", approval, note: approval.rationale ?? "" };
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

/** Alert ids that have a pending card but are not in the loaded window, so the server hydrates them too (U-2).
 * Pass only the alerts whose chain loaded in full: a chain whose detail read failed is partial and has no actions,
 * so its pending cards must be hydrated or stubbed like any other (round 8 U8-3). */
export function missingPendingAlerts(approvals: Approval[], loadedAlertIds: Set<string>, cap = 60): string[] {
  const out: string[] = [];
  for (const a of pendingQueue(approvals)) {
    const id = a.alert_id ?? "";
    if (id && !loadedAlertIds.has(id) && !out.includes(id)) out.push(id);
    if (out.length >= cap) break;
  }
  return out;
}

/** A chain that could not be read, rebuilt from its pending cards so they can still be decided (U-2 / U-4). The
 * stub's actions carry each card's FULL target, so the card matches its action again (U8-1). */
export function stubChainFromApprovals(alertId: string, approvals: Approval[]): Chain {
  const seen = new Set<string>();
  const mine = approvals.filter((a) => {
    if (a.alert_id !== alertId) return false;
    const k = `${a.action_type}\u0000${fullTarget(a)}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
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
    recommended_actions: mine.map((a) => ({ action_type: a.action_type, target: fullTarget(a), requires_hitl: true, reasoning: a.reasoning })),
    partial: true,
  };
}

/** Merge detail reads with their summaries: a failed read keeps the summary row but is marked partial so the UI
 * says "details unavailable" instead of "no recommended actions" (U-4). A detail that came back 404 / empty is
 * partial too — it used to be dropped silently, taking its pending cards' incident with it (round 8). Returns the
 * chains and how many could not be read. */
export function mergeDetails<S extends { chain_id: string }>(
  summaries: S[],
  results: PromiseSettledResult<Chain | null>[],
): { chains: Chain[]; failed: number } {
  let failed = 0;
  const chains: Chain[] = [];
  results.forEach((r, i) => {
    if (r.status === "fulfilled" && r.value) {
      chains.push(r.value);
    } else {
      failed++;
      chains.push({ ...(summaries[i] as unknown as Chain), recommended_actions: [], partial: true });
    }
  });
  return { chains, failed };
}

/** Fold the pending-card hydration into the loaded chains (U-2 / U8-3). `extra[i]` is an alert id with a pending
 * card and `results[i]` its detail read. A read that worked replaces the partial chain for that alert (or is
 * added); one that failed rebuilds the actions from the cards — onto the partial chain when there is one, so a
 * top-40 incident whose detail failed still lists its decidable cards instead of "details unavailable" and nothing. */
export function attachPending(
  chains: Chain[],
  approvals: Approval[],
  extra: string[],
  results: PromiseSettledResult<Chain | null>[],
): Chain[] {
  const out = [...chains];
  extra.forEach((id, i) => {
    const r = results[i];
    const at = out.findIndex((c) => c.alert_id === id);
    if (r && r.status === "fulfilled" && r.value) {
      if (at >= 0) out[at] = r.value;
      else out.push(r.value);
      return;
    }
    const stub = stubChainFromApprovals(id, approvals);
    if (at >= 0) {
      const cur = out[at];
      out[at] = { ...cur, recommended_actions: stub.recommended_actions, action_types: cur.action_types?.length ? cur.action_types : stub.action_types,
                  integrity_hash: cur.integrity_hash || stub.integrity_hash, partial: true };
    } else {
      out.push(stub);
    }
  });
  return out;
}

const str = (v: unknown): string | undefined => (typeof v === "string" && v !== "" ? v : undefined);

/** One row of GET /api/approvals in the console's shape. The AEGIS receiver serves the fields at the top level;
 * the ACP dashboard serves `alert_id` / `action_type` / `target` / `integrity_hash` inside an `args` JSON string,
 * `reject_reason` for the note and "" for undecided — so its cards matched no action, had no alert to open and
 * were never hydrated (round 8 U8-4). Top-level fields win; `args` (string or object) fills the gaps. Null for a
 * row that is not an object or has no id. */
export function normalizeApproval(raw: unknown): Approval | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const r = raw as Record<string, unknown>;
  const id = r.id;
  if ((typeof id !== "string" && typeof id !== "number") || id === "") return null;
  let args: Record<string, unknown> = {};
  if (typeof r.args === "string") {
    try {
      const j = JSON.parse(r.args);
      if (j && typeof j === "object" && !Array.isArray(j)) args = j as Record<string, unknown>;
    } catch { /* unreadable args: top-level fields only */ }
  } else if (r.args && typeof r.args === "object" && !Array.isArray(r.args)) {
    args = r.args as Record<string, unknown>;
  }
  const pick = (k: string) => str(r[k]) ?? str(args[k]);
  const action = str(r.action);
  const actionType = pick("action_type") ?? (action ? action.split(" -> ")[0] : "") ?? "";
  const out: Approval = {
    id: String(id),
    status: (str(r.status) ?? "pending") as Approval["status"],
    created_at: str(r.created_at) ?? "",
    action_type: actionType,
    target: pick("target") ?? (action && action.startsWith(`${actionType} -> `) ? action.slice(actionType.length + 4) : ""),
  };
  const opt: Array<[keyof Approval, string | undefined]> = [
    ["target_full", str(r.target_full) ?? str(args.target_full)],
    ["action", action],
    ["alert_id", pick("alert_id")],
    ["integrity_hash", pick("integrity_hash")],
    ["reasoning", pick("reasoning")],
    ["agent_id", pick("agent_id") ?? str(args.investigated_by)],
    ["decided_by", str(r.decided_by)],
    ["decided_at", str(r.decided_at)],
    ["rationale", str(r.rationale) ?? str(r.reject_reason)],
  ];
  for (const [k, v] of opt) if (v !== undefined) (out as unknown as Record<string, unknown>)[k] = v;
  if (typeof r.settled === "boolean") out.settled = r.settled;
  return out;
}
