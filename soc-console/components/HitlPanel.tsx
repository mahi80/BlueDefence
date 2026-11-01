"use client";

import { useEffect, useState } from "react";
import type { Chain, Approval, RecommendedAction } from "../lib/types";

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

type Decision = { status: "approved" | "rejected"; note: string };

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
  const [decided, setDecided] = useState<Record<string, Decision>>({});
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [corrected, setCorrected] = useState<Record<string, string>>({});

  // seed from already-decided approvals for this chain
  useEffect(() => {
    const seed: Record<string, Decision> = {};
    for (const a of approvals) {
      if (a.alert_id === chain.alert_id && (a.status === "approved" || a.status === "rejected")) {
        seed[key(a.action_type, a.target)] = { status: a.status, note: a.rationale ?? "" };
      }
    }
    setDecided(seed);
  }, [chain.alert_id, approvals]);

  const approvalFor = (a: RecommendedAction): Approval | undefined =>
    approvals.find((p) => p.alert_id === chain.alert_id && p.action_type === a.action_type && p.target === a.target);

  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  async function decide(a: RecommendedAction, status: "approved" | "rejected") {
    const k = key(a.action_type, a.target);
    const note = draft[k] ?? "";
    setError(null);
    if (fixtureMode) { setDecided((d) => ({ ...d, [k]: { status, note } })); return; }
    const appr = approvalFor(a);
    if (!appr) { setError("This action has no approval card yet — the service has not filed it."); return; }
    setBusy(k);
    try {
      const r = await fetch(`/api/approvals/${encodeURIComponent(appr.id)}/${status === "approved" ? "approve" : "reject"}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(status === "approved" ? { rationale: note } : { reason: note, corrected_verdict: corrected[k] ?? "" }),
      });
      if (!r.ok) {
        const body = await r.json().catch(() => ({}));
        setError(`${status === "approved" ? "Approve" : "Reject"} failed (${r.status}): ${body.error ?? r.statusText}`);
        return;                                               // nothing recorded: the card stays open
      }
      setDecided((d) => ({ ...d, [k]: { status, note } }));
    } catch (e) {
      setError(`Could not reach the console server: ${(e as Error).message}`);
    } finally {
      setBusy(null);
    }
  }

  const actions = chain.recommended_actions ?? [];
  const pendingCount = actions.filter((a) => a.requires_hitl && !decided[key(a.action_type, a.target)]).length;

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
        {actions.length === 0 && <div className="empty">No recommended actions on this chain.</div>}

        {actions.map((a) => {
          const k = key(a.action_type, a.target);
          const dec = decided[k];
          const focused = focusKey === k;
          const auto = !a.requires_hitl;
          return (
            <div
              key={k}
              className="action-card"
              style={{ borderLeftColor: focused ? "var(--swarm)" : "var(--line)", boxShadow: focused ? "var(--shadow)" : "none" }}
            >
              <div className="verb">
                {VERB[a.action_type] ?? a.action_type}
                {auto && <span className="hitl-tag" style={{ color: "var(--v-benign)", borderColor: "rgba(53,214,164,.4)" }}>auto</span>}
                {!auto && !dec && <span className="hitl-tag">needs human</span>}
              </div>
              <div className="target mono">{a.target}</div>
              {a.reasoning && <div className="reason">{a.reasoning}</div>}

              {auto ? (
                <div className="foot">
                  <span className="conf">{Math.round((a.confidence ?? chain.confidence) * 100)}%</span>
                  <span className="decided">applied automatically — no approval needed</span>
                </div>
              ) : dec ? (
                <div className="foot">
                  <span className="conf">{Math.round((a.confidence ?? chain.confidence) * 100)}%</span>
                  <span className={`decided ${dec.status === "rejected" ? "rej" : ""}`}>
                    <b>{dec.status === "approved" ? "Approved" : "Rejected"}</b>
                    {dec.note ? ` — ${dec.note}` : ""}
                  </span>
                </div>
              ) : !canDecide ? (
                <div className="foot">
                  <span className="conf">{Math.round((a.confidence ?? chain.confidence) * 100)}%</span>
                  <span className="viewonly">Awaiting approval — your role is view-only</span>
                </div>
              ) : (
                <>
                  <input
                    className="btn"
                    style={{ width: "100%", marginTop: 10, background: "var(--bg)", cursor: "text" }}
                    placeholder="Rationale (recorded with your decision)"
                    value={draft[k] ?? ""}
                    onChange={(e) => setDraft((d) => ({ ...d, [k]: e.target.value }))}
                  />
                  <select
                    className="btn"
                    style={{ width: "100%", marginTop: 8, background: "var(--bg)" }}
                    value={corrected[k] ?? ""}
                    onChange={(e) => setCorrected((c) => ({ ...c, [k]: e.target.value }))}
                  >
                    <option value="">If rejecting — the correct verdict (teaches the model)</option>
                    <option value="benign">benign</option>
                    <option value="suspicious">suspicious</option>
                    <option value="malicious">malicious</option>
                  </select>
                  <div className="foot">
                    <span className="conf">{Math.round((a.confidence ?? chain.confidence) * 100)}%</span>
                    <span className="btns">
                      <button className="btn btn-reject" disabled={busy === key(a.action_type, a.target)} onClick={() => decide(a, "rejected")}>Reject</button>
                      <button className="btn btn-approve" disabled={busy === key(a.action_type, a.target)} onClick={() => decide(a, "approved")}>Approve</button>
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
