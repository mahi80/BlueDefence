"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import type { Chain, Approval, Proposal, RecommendedAction, EvidenceItem } from "../lib/types";
import { VERDICT_RANK } from "../lib/graph";
import BlastGraph from "./BlastGraph";
import IncidentList from "./IncidentList";
import HitlPanel from "./HitlPanel";
import ModelLoopStrip from "./ModelLoopStrip";
import AskAgentQ from "./AskAgentQ";

const WEIGHT_RANK: Record<string, number> = { high: 3, medium: 2, low: 1 };
const pct = (n: number) => Math.round((n ?? 0) * 100);

/** The decision-first hero: verdict, source, confidence and the one-line reason. */
function IncidentBanner({ chain }: { chain: Chain }) {
  return (
    <div className="incident-banner">
      <div className="banner-top">
        <span className={`vpill v-${chain.verdict}`}>{chain.verdict}</span>
        <span className="banner-src">{chain.source}</span>
        {chain.triage === "swarm" && (
          <span className="triage-badge" title="Investigated by the live AEGIS swarm">⚡ live swarm</span>
        )}
        <span className="banner-conf">
          <span className="confmeter"><i style={{ width: `${pct(chain.confidence)}%`, background: `var(--v-${chain.verdict})` }} /></span>
          <span className="confval">{pct(chain.confidence)}%</span>
        </span>
      </div>
      <div className="banner-why">
        <b>{chain.specialists?.length ? chain.specialists.join(", ") : "The orchestrator"}</b> investigated across{" "}
        {chain.evidence_count} signal{chain.evidence_count === 1 ? "" : "s"}.
        {chain.note ? ` ${chain.note}` : ""}
        {chain.governance_blocked ? " · ACP governance blocked a proposed action (audited)." : ""}
      </div>
    </div>
  );
}

/** The evidence behind the verdict — what an analyst wants when they ask "why?". */
function EvidencePanel({ chain, onAsk }: { chain: Chain; onAsk: () => void }) {
  const items = useMemo<EvidenceItem[]>(
    () => [...(chain.evidence ?? [])].sort((a, b) => (WEIGHT_RANK[b.weight] ?? 0) - (WEIGHT_RANK[a.weight] ?? 0)),
    [chain],
  );
  return (
    <div className="evidence">
      <div className="evidence-head">
        <div>
          <h3>Why Agent&nbsp;Q flagged this</h3>
          <div className="sub">
            {items.length || chain.evidence_count} signal{(items.length || chain.evidence_count) === 1 ? "" : "s"} behind the {chain.verdict} verdict · strongest first
          </div>
        </div>
        <button className="ask-q" onClick={onAsk} title="Ask Agent Q to explain, with evidence">Ask Agent&nbsp;Q why</button>
      </div>
      {items.length ? (
        items.map((e, i) => (
          <div className="ev-item" key={i}>
            <span className={`ev-w ${e.weight}`}>{e.weight}</span>
            <div>
              <div className="ev-sig">{e.signal}</div>
              <div className="ev-src">{e.source}</div>
            </div>
          </div>
        ))
      ) : (
        <div className="ev-empty">
          {chain.evidence_count} piece{chain.evidence_count === 1 ? "" : "s"} of evidence recorded; the per-signal detail isn&apos;t
          attached to this chain copy. Ask Agent&nbsp;Q for the summary.
        </div>
      )}
    </div>
  );
}

export default function Console({
  chains,
  approvals,
  proposals,
  fixtureMode,
  backendError = null,
  session,
  canDecide,
}: {
  chains: Chain[];
  approvals: Approval[];
  proposals: Proposal[];
  fixtureMode: boolean;
  backendError?: string | null;
  session: { user: string; role: string };
  canDecide: boolean;
}) {
  const router = useRouter();
  // In live mode re-pull server data on a timer so incidents from a running attack appear
  // without a manual refresh. router.refresh() is soft, so local UI state is preserved.
  useEffect(() => {
    if (fixtureMode) return;
    const id = setInterval(() => router.refresh(), 4000);
    return () => clearInterval(id);
  }, [router, fixtureMode]);

  async function logout() {
    try {
      await fetch("/api/auth/logout", { method: "POST" });
    } catch {
      /* fall through to the redirect regardless */
    }
    window.location.href = "/login";
  }

  const sorted = useMemo(
    () =>
      [...chains].sort((a, b) => {
        // Triage order: worst verdict first, then by confidence (a 97% malicious outranks a 63% one),
        // then most recent — so the row an analyst should touch first is always at the top.
        const r = (VERDICT_RANK[b.verdict] ?? 0) - (VERDICT_RANK[a.verdict] ?? 0);
        if (r !== 0) return r;
        const c = (b.confidence ?? 0) - (a.confidence ?? 0);
        if (Math.abs(c) > 1e-9) return c;
        return b.started_at.localeCompare(a.started_at);
      }),
    [chains],
  );
  const [selId, setSelId] = useState<string>(sorted[0]?.chain_id ?? "");
  const [focusKey, setFocusKey] = useState<string | null>(null);
  const selected = sorted.find((c) => c.chain_id === selId) ?? sorted[0];

  // Agent Q drawer — controlled here so the evidence panel can open it with a question.
  const [ask, setAsk] = useState<{ open: boolean; q?: string; nonce: number }>({ open: false, nonce: 0 });
  const askWhy = () => setAsk((a) => ({ open: true, q: "Why is this suspicious? Show me the evidence.", nonce: a.nonce + 1 }));

  const counts = useMemo(() => {
    const c = { malicious: 0, suspicious: 0 };
    for (const ch of chains) {
      if (ch.verdict === "malicious") c.malicious++;
      else if (ch.verdict === "suspicious") c.suspicious++;
    }
    return c;
  }, [chains]);

  const onSelectAction = (a: RecommendedAction) => setFocusKey(`${a.action_type}:${a.target}`);

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="logo"><b>AEGIS</b> SOC</span>
          <span className="tag">autonomous defense · human-in-the-loop</span>
        </div>
        <nav className="tabs" aria-label="Views">
          <Link href="/" aria-current="page">Incidents</Link>
          <Link href="/posture">Posture</Link>
          <Link href="/exposure">Exposures</Link>
        </nav>
        <div className="live">
          <span className="pulse-dot" aria-hidden style={backendError ? { background: "var(--v-malicious)" } : undefined} />{" "}
          {fixtureMode ? "sample stream" : backendError ? `backend unreachable · ${backendError}` : "live"}
        </div>
        <div className="counts">
          <span className="chip"><span className="dot" style={{ background: "var(--v-malicious)" }} /> malicious <span className="n">{counts.malicious}</span></span>
          <span className="chip"><span className="dot" style={{ background: "var(--v-suspicious)" }} /> suspicious <span className="n">{counts.suspicious}</span></span>
        </div>
        <div className="whoami">
          <span className="u"><b>{session.user}</b></span>
          <span className="role">{session.role}</span>
          <button className="logout" onClick={logout}>Sign out</button>
        </div>
      </header>

      <div className="cols">
        <IncidentList
          chains={sorted}
          selectedId={selected?.chain_id}
          onSelect={(id) => { setSelId(id); setFocusKey(null); }}
        />

        <section className="decide" aria-label="Incident decision">
          {selected ? (
            <>
              <IncidentBanner chain={selected} />
              <EvidencePanel chain={selected} onAsk={askWhy} />
              <HitlPanel chain={selected} approvals={approvals} focusKey={focusKey} fixtureMode={fixtureMode} canDecide={canDecide} />
            </>
          ) : (
            <div className="empty">No incident selected.</div>
          )}
        </section>

        <aside className="map-rail" aria-label="Attack-path map">
          <div className="map-rail-head">
            <h2>Attack path</h2>
            <div className="sub">alert → each hop → crown jewels · dashed = proposed isolate (min-cut)</div>
          </div>
          <div className="map-box">
            {selected && <BlastGraph chain={selected} onSelectAction={onSelectAction} />}
          </div>
          <div className="legend">
            <span><i className="reached" /> reached asset</span>
            <span><i className="ring" /> crown-jewel</span>
            <span><i className="cut" /> isolate plan</span>
          </div>
        </aside>
      </div>

      <ModelLoopStrip proposals={proposals} fixtureMode={fixtureMode} canDecide={canDecide} />

      <AskAgentQ
        chain={selected}
        fixtureMode={fixtureMode}
        open={ask.open}
        onOpenChange={(o) => setAsk((a) => ({ ...a, open: o }))}
        autoAsk={ask.q ? { q: ask.q, nonce: ask.nonce } : undefined}
        mood={counts.malicious > 0 ? "critical" : counts.suspicious > 0 ? "alert" : "calm"}
        pending={approvals.filter((a) => a.status === "pending" || a.status === "awaiting_second").length}
      />
    </div>
  );
}
