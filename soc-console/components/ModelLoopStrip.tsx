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

  async function decide(p: Proposal, decision: "accept" | "reject") {
    setStatus((s) => ({ ...s, [p.id]: decision === "accept" ? "accepted" : "rejected" }));
    if (!fixtureMode) {
      try {
        await fetch(`/api/soc/proposals/${encodeURIComponent(p.id)}/decide`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ decision }),
        });
      } catch {
        /* optimistic; real decision is role-gated server-side */
      }
    }
  }

  return (
    <footer className="footer" aria-label="Model evolution">
      <span className="flabel">Model loop</span>
      {proposals.length === 0 && <span className="flabel">no proposals in the queue</span>}
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
                <button className="mini" onClick={() => decide(p, "accept")}>
                  {p.change_type === "model_promotion" ? "Promote" : "Accept"}
                </button>
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
