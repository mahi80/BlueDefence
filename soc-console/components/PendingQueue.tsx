"use client";

import { useState } from "react";
import type { Approval } from "../lib/types";
import { fullTarget, pendingQueue } from "../lib/hitl";

const PAGE = 50;

/** Every approval card waiting on a human, newest first — independent of which incidents are loaded, so a card on
 * an older incident is never out of reach (round 7 U-2). Selecting one opens its incident. */
export default function PendingQueue({
  approvals,
  onOpen,
}: {
  approvals: Approval[];
  onOpen: (alertId: string, focus: string) => void;
}) {
  // every card is reachable: the list used to stop at the first 50 with "+N more" and no way to open them (round 8)
  const [shown, setShown] = useState(PAGE);
  const queue = pendingQueue(approvals);
  if (!queue.length) return null;
  return (
    <section className="pending-queue" aria-label="Approvals awaiting a decision">
      <h2>Awaiting decision <span className="n">{queue.length}</span></h2>
      <ul>
        {queue.slice(0, shown).map((a) => (
          <li key={a.id}>
            {/* focus on the FULL target: the panel keys actions by it, not by the 256-char display cut (U8-1) */}
            <button className="pq-item" onClick={() => onOpen(a.alert_id ?? "", `${a.action_type}:${fullTarget(a)}`)}>
              <span className="pq-act">{a.action_type}</span> <span className="mono">{a.target}</span>
              <span className="pq-meta">
                {a.status === "awaiting_second" ? "needs a second approver · " : ""}
                {a.alert_id || "unknown alert"}
              </span>
            </button>
          </li>
        ))}
      </ul>
      {queue.length > shown && (
        <div className="pq-more">
          Showing {shown} of {queue.length}, newest first —{" "}
          <button className="btn" onClick={() => setShown((n) => n + PAGE)}>show {Math.min(PAGE, queue.length - shown)} more</button>{" "}
          <button className="btn" onClick={() => setShown(queue.length)}>show all</button>
        </div>
      )}
    </section>
  );
}
