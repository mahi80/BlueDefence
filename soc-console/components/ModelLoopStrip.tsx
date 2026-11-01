"use client";

import { useState } from "react";
import type { Proposal } from "../lib/types";

export default function ModelLoopStrip({
  proposals,
  fixtureMode,
  canDecide,
}: {
  proposals: Proposal[];
  fixtureMode: boolean;
  canDecide: boolean;
}) {
  const [status, setStatus] = useState<Record<string, "accepted" | "rejected">>({});
  const [error, setError] = useState<string | null>(null);

  async function decide(p: Proposal, decision: "accept" | "reject") {
    setError(null);
    if (fixtureMode) { setStatus((s) => ({ ...s, [p.id]: decision === "accept" ? "accepted" : "rejected" })); return; }
    try {
      const r = await fetch(`/api/soc/proposals/${encodeURIComponent(p.id)}/decide`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ decision }),
      });
      if (!r.ok) {
        const body = await r.json().catch(() => ({}));
        setError(`${decision === "accept" ? "Promote" : "Reject"} failed (${r.status}): ${body.error ?? r.statusText}`);
        return;
      }
      setStatus((s) => ({ ...s, [p.id]: decision === "accept" ? "accepted" : "rejected" }));
    } catch (e) {
      setError(`Could not reach the console server: ${(e as Error).message}`);
    }
  }

  return (
    <footer className="footer" aria-label="Model evolution">
      <span className="flabel">Model loop</span>
      {proposals.length === 0 && <span className="flabel">no proposals in the queue</span>}
      {error && <span className="flabel ferror" role="alert">{error}</span>}
      {proposals.map((p) => {
        let st: "accepted" | "rejected" | "pending" =
          p.status === "accepted" ? "accepted" : p.status === "rejected" ? "rejected" : "pending";
        const override = status[p.id];
        if (override) st = override;
        return (
          <div className="prop" key={p.id} title={p.rationale ?? ""}>
            <span className={`st ${st}`} aria-hidden />
            <span className="s">
              {p.summary}
              {p.change_type === "model_promotion" && p.validation_passed ? " · gate PASS" : ""}
            </span>
            {st === "pending" ? (
              canDecide ? (
                <>
                  <button className="mini" onClick={() => decide(p, "accept")}>
                    {p.change_type === "model_promotion" ? "Promote" : "Accept"}
                  </button>
                  <button className="mini mini-reject" onClick={() => decide(p, "reject")}>Reject</button>
                </>
              ) : (
                <span className="r">awaiting approval</span>
              )
            ) : (
              <span className="r">{st}</span>
            )}
          </div>
        );
      })}
    </footer>
  );
}
