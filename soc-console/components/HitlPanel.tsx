"use client";

import { useEffect, useState } from "react";
import type { Chain, Approval } from "../lib/types";
import { cardState, latestApprovalFor, type LocalDecision, type SettledStatus } from "../lib/hitl";

const key = (actionType: string, target: string) => `${actionType}:${target}`;
const VERB: Record<string, string> = {
  isolate: "Isolate host",
  block: "Block",
  block_egress: "Block egress",
  revoke_sessions: "Revoke sessions",
  lock_account: "Lock account",
  rotate_credential: "Rotate credential",
  throttle: "Throttle",
  challenge: "Challenge",
  monitor: "Monitor",
  escalate: "Escalate",
  allow: "Allow",
};

const SETTLED_LABEL: Record<SettledStatus, string> = {
  approved: "Approved",
  rejected: "Rejected",
  failed: "Approved — NOT executed",
  expired: "Expired — no decision",
};

export default function HitlPanel({
  chain,
  approvals,
  focusKey,
  fixtureMode,
  canDecide,
}: {
  chain: Chain;
  approvals: Approval[];
  focusKey: string | null;
  fixtureMode: boolean;
  canDecide: boolean;
}) {
  // local decisions are keyed by the approval id they were made on, never by action:target — an old decision on
  // the same action and target must not settle a newer card (round 7 U-3)
  const [decided, setDecided] = useState<Record<string, LocalDecision>>({});
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [corrected, setCorrected] = useState<Record<string, string>>({});
  useEffect(() => { setDecided({}); }, [chain.alert_id]);

  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  async function decide(appr: Approval, status: "approved" | "rejected") {
    const note = draft[appr.id] ?? "";
    setError(null);
    if (fixtureMode) { setDecided((d) => ({ ...d, [appr.id]: { status, note } })); return; }
    setBusy(appr.id);
    try {
      const r = await fetch(`/api/approvals/${encodeURIComponent(appr.id)}/${status === "approved" ? "approve" : "reject"}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(status === "approved" ? { rationale: note } : { reason: note, corrected_verdict: corrected[appr.id] ?? "" }),
      });
      if (!r.ok) {
        const body = await r.json().catch(() => ({}));
        setError(`${status === "approved" ? "Approve" : "Reject"} failed (${r.status}): ${body.error ?? r.statusText}`);
        return;                                               // nothing recorded: the card stays open
      }
      setDecided((d) => ({ ...d, [appr.id]: { status, note } }));
    } catch (e) {
      setError(`Could not reach the console server: ${(e as Error).message}`);
    } finally {
      setBusy(null);
    }
  }

  const actions = chain.recommended_actions ?? [];
  const cards = actions.map((a) => ({ a, st: cardState(a, latestApprovalFor(approvals, chain.alert_id, a), decided, fixtureMode) }));
  const pendingCount = cards.filter((c) => c.st.kind === "decide").length;

  return (
    <aside className="panel" aria-label="Human-in-the-loop actions">
      {error && <div className="hitl-error" role="alert">{error}</div>}
      <div className="panel-head">
        <h2>Human-in-the-loop</h2>
        <div className="sub">
          {pendingCount > 0 ? `${pendingCount} action${pendingCount > 1 ? "s" : ""} awaiting your decision` : "no actions awaiting you"}
        </div>
      </div>
      <div className="panel-body">
        {chain.partial && (
          <div className="hitl-error" role="status">
            Details unavailable — the backend did not return this incident&apos;s full chain. Pending approval cards are
            still listed below; evidence and other actions are not.
          </div>
        )}
        {actions.length === 0 && !chain.partial && <div className="empty">No recommended actions on this chain.</div>}

        {cards.map(({ a, st }) => {
          const k = key(a.action_type, a.target);
          const focused = focusKey === k;
          const conf = <span className="conf">{Math.round((a.confidence ?? chain.confidence) * 100)}%</span>;
          return (
            <div
              key={"approval" in st && st.approval ? st.approval.id : k}
              className="action-card"
              style={{ borderLeftColor: focused ? "var(--swarm)" : "var(--line)", boxShadow: focused ? "var(--shadow)" : "none" }}
            >
              <div className="verb">
                {VERB[a.action_type] ?? a.action_type}
                {st.kind === "proposed" && <span className="hitl-tag" style={{ color: "var(--ink-faint)" }}>proposed</span>}
                {(st.kind === "decide" || st.kind === "no_card") && <span className="hitl-tag">needs human</span>}
              </div>
              <div className="target mono">{a.target}</div>
              {a.reasoning && <div className="reason">{a.reasoning}</div>}
              {st.kind === "decide" && st.awaitingSecond && (
                <div className="reason" role="status">
                  Approved by {st.approval.decided_by || "one analyst"} — protected target, a second, different approver is needed.
                </div>
              )}

              {st.kind === "proposed" ? (
                <div className="foot">
                  {conf}
                  <span className="decided">proposed — no approval card filed; the console cannot confirm it ran (check enforcement mode and receipts)</span>
                </div>
              ) : st.kind === "no_card" ? (
                <div className="foot">
                  {conf}
                  <span className="viewonly">Needs a human — the service has not filed an approval card yet</span>
                </div>
              ) : st.kind === "settled" ? (
                <div className="foot">
                  {conf}
                  <span className={`decided ${st.status === "approved" ? "" : "rej"}`}>
                    <b>{SETTLED_LABEL[st.status]}</b>
                    {st.note ? ` — ${st.note}` : ""}
                  </span>
                </div>
              ) : !canDecide ? (
                <div className="foot">
                  {conf}
                  <span className="viewonly">Awaiting approval — your role is view-only</span>
                </div>
              ) : (
                <>
                  <input
                    className="btn"
                    style={{ width: "100%", marginTop: 10, background: "var(--bg)", cursor: "text" }}
                    placeholder="Rationale (recorded with your decision)"
                    value={draft[st.approval.id] ?? ""}
                    onChange={(e) => setDraft((d) => ({ ...d, [st.approval.id]: e.target.value }))}
                  />
                  <select
                    className="btn"
                    style={{ width: "100%", marginTop: 8, background: "var(--bg)" }}
                    value={corrected[st.approval.id] ?? ""}
                    onChange={(e) => setCorrected((c) => ({ ...c, [st.approval.id]: e.target.value }))}
                  >
                    <option value="">If rejecting — the correct verdict (teaches the model)</option>
                    <option value="benign">benign</option>
                    <option value="suspicious">suspicious</option>
                    <option value="malicious">malicious</option>
                  </select>
                  <div className="foot">
                    {conf}
                    <span className="btns">
                      <button className="btn btn-reject" disabled={busy === st.approval.id} onClick={() => decide(st.approval, "rejected")}>Reject</button>
                      <button className="btn btn-approve" disabled={busy === st.approval.id} onClick={() => decide(st.approval, "approved")}>Approve</button>
                    </span>
                  </div>
                </>
              )}
            </div>
          );
        })}
      </div>
    </aside>
  );
}
