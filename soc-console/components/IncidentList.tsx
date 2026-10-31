import type { Chain } from "../lib/types";

function timeAgo(iso: string): string {
  const d = Date.now() - new Date(iso).getTime();
  const m = Math.round(d / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  return `${h}h ago`;
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
  return (
    <nav className="rail" aria-label="Incidents">
      <div className="rail-head">
        <h2>Incidents</h2>
        <div className="sub">{chains.length} chains · most severe first</div>
      </div>
      {chains.map((c) => (
        <button
          key={c.chain_id}
          className="incident"
          aria-selected={c.chain_id === selectedId}
          onClick={() => onSelect(c.chain_id)}
        >
          <span className="vbar" style={{ background: `var(--v-${c.verdict})` }} aria-hidden />
          <span>
            <span className="src">{c.source}</span>
            <span className="meta mono">
              {c.alert_id} · {timeAgo(c.started_at)}
            </span>
            <span className="acts">{c.action_types.join(" · ")}</span>
          </span>
          <span className={`conf v-${c.verdict}`}>{Math.round(c.confidence * 100)}%</span>
        </button>
      ))}
    </nav>
  );
}
