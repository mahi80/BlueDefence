import type { Chain } from "../lib/types";

function timeAgo(iso: string): string {
  const d = Date.now() - new Date(iso).getTime();
  const m = Math.round(d / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  return `${h}h ago`;
}

/** Triage priority an analyst reads at a glance: the worst, highest-confidence incidents are P1 and
 * carry a CRITICAL tag so they get worked first. Verdict sets the band, confidence splits within it. */
function priority(c: Chain): { sev: "critical" | "high" | "elevated" | "low"; label: string } {
  const conf = c.confidence ?? 0;
  if (c.verdict === "malicious") {
    return conf >= 0.9
      ? { sev: "critical", label: "P1 · CRITICAL" }
      : { sev: "high", label: "P1 · HIGH" };
  }
  if (c.verdict === "suspicious") {
    return conf >= 0.8
      ? { sev: "high", label: "P2 · HIGH" }
      : { sev: "elevated", label: "P2 · ELEVATED" };
  }
  if (c.verdict === "uncertain") return { sev: "elevated", label: "P3 · REVIEW" };
  return { sev: "low", label: "P4 · INFO" };
}

export default function IncidentList({
  chains,
  selectedId,
  onSelect,
}: {
  chains: Chain[];
  selectedId?: string;
  onSelect: (id: string) => void;
}) {
  const criticalCount = chains.filter((c) => priority(c).sev === "critical").length;
  return (
    <nav className="rail" aria-label="Incidents">
      <div className="rail-head">
        <h2>Incidents</h2>
        <div className="sub">
          {chains.length} chains · by priority
          {criticalCount > 0 && (
            <span className="rail-crit" role="status"> · {criticalCount} critical — act now</span>
          )}
        </div>
      </div>
      {chains.map((c) => {
        const p = priority(c);
        const needsAction = (c.action_types?.length ?? 0) > 0;
        return (
          <button
            key={c.chain_id}
            className="incident"
            data-sev={p.sev}
            aria-selected={c.chain_id === selectedId}
            onClick={() => onSelect(c.chain_id)}
          >
            <span className="vbar" style={{ background: `var(--v-${c.verdict})` }} aria-hidden />
            <span className="incident-body">
              <span className="incident-top">
                <span className={`sev-badge sev-${p.sev}`}>{p.label}</span>
                {needsAction && <span className="act-flag" title="Containment proposed — awaiting a decision">● action</span>}
              </span>
              <span className="src">{c.source}</span>
              <span className="meta mono">
                {c.alert_id} · {timeAgo(c.started_at)}
              </span>
              <span className="acts">{c.action_types.join(" · ")}</span>
            </span>
            <span className={`conf v-${c.verdict}`}>{Math.round(c.confidence * 100)}%</span>
          </button>
        );
      })}
    </nav>
  );
}
