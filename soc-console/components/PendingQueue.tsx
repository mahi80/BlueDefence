"use client";

import type { Approval } from "../lib/types";
import { pendingQueue } from "../lib/hitl";

/** Every approval card waiting on a human, newest first — independent of which incidents are loaded, so a card on
 * an older incident is never out of reach (round 7 U-2). Selecting one opens its incident. */
export default function PendingQueue({
  approvals,
  onOpen,
}: {
  approvals: Approval[];
  onOpen: (alertId: string, focus: string) => void;
}) {
  const queue = pendingQueue(approvals);
  if (!queue.length) return null;
  return (
    <section className="pending-queue" aria-label="Approvals awaiting a decision">
      <h2>Awaiting decision <span className="n">{queue.length}</span></h2>
      <ul>
        {queue.slice(0, 50).map((a) => (
          <li key={a.id}>
            <button className="pq-item" onClick={() => onOpen(a.alert_id ?? "", `${a.action_type}:${a.target}`)}>
              <span className="pq-act">{a.action_type}</span> <span className="mono">{a.target}</span>
              <span className="pq-meta">
                {a.status === "awaiting_second" ? "needs a second approver · " : ""}
                {a.alert_id || "unknown alert"}
              </span>
            </button>
          </li>
        ))}
      </ul>
      {queue.length > 50 && <div className="pq-more">+{queue.length - 50} more — newest shown first</div>}
    </section>
  );
}
