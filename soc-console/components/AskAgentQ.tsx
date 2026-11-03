"use client";

import { useEffect, useRef, useState } from "react";
import type { Chain } from "../lib/types";
import { answerLocally, greeting, SUGGESTED } from "../lib/ask";
import QMascot, { type Mood, type Pos } from "./QMascot";

type Msg = { role: "you" | "q"; text: string };
type AutoAsk = { q: string; nonce: number };

/** Agent Q — an original sentinel mark: a Q inside a shield, with a live scanning eye. */
function QMark({ size = 26 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 48 48" aria-hidden focusable="false">
      <path
        d="M24 4 L40 10 V24 C40 34 33 42 24 45 C15 42 8 34 8 24 V10 Z"
        fill="var(--swarm)" fillOpacity="0.16" stroke="var(--swarm)" strokeWidth="1.6"
      />
      <circle cx="24" cy="22" r="8.4" fill="none" stroke="var(--swarm)" strokeWidth="2.6" />
      <path d="M29 27 L34 32" stroke="var(--swarm)" strokeWidth="2.6" strokeLinecap="round" />
      <circle cx="24" cy="22" r="2.4" fill="var(--v-benign)">
        <animate attributeName="opacity" values="1;0.35;1" dur="2.4s" repeatCount="indefinite" />
      </circle>
    </svg>
  );
}

export default function AskAgentQ({
  chain,
  fixtureMode,
  open,
  onOpenChange,
  autoAsk,
  mood = "calm",
  pending = 0,
}: {
  chain?: Chain;
  fixtureMode: boolean;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  autoAsk?: AutoAsk;
  mood?: Mood;
  pending?: number;
}) {
  const setOpen = (o: boolean) => onOpenChange(o);
  const [mpos, setMpos] = useState<Pos | null>(null);
  // the drawer opens on whichever side of the mascot has room
  const drawerStyle: React.CSSProperties = (() => {
    if (!mpos || typeof window === "undefined") return {};
    const W = window.innerWidth, H = window.innerHeight, S = 84, gap = 12;
    const st: React.CSSProperties = {};
    if (mpos.x + S / 2 > W / 2) { st.right = Math.max(12, W - (mpos.x + S)); st.left = "auto"; }
    else { st.left = Math.max(12, mpos.x); st.right = "auto"; }
    if (mpos.y + S / 2 > H / 2) { st.bottom = Math.max(12, H - mpos.y + gap); st.top = "auto"; }
    else { st.top = Math.max(12, mpos.y + S + gap); st.bottom = "auto"; }
    return st;
  })();
  const [msgs, setMsgs] = useState<Msg[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const endRef = useRef<HTMLDivElement>(null);
  const lastAuto = useRef(0);

  // seed the conversation with a context-aware greeting the first time it opens
  useEffect(() => {
    if (open && msgs.length === 0) setMsgs([{ role: "q", text: greeting(chain) }]);
    if (open) setTimeout(() => inputRef.current?.focus(), 60);
  }, [open]); // eslint-disable-line react-hooks/exhaustive-deps

  // when the console asks a question for the analyst (e.g. "Ask Agent Q why"), send it once
  useEffect(() => {
    if (open && autoAsk && autoAsk.nonce > lastAuto.current) {
      lastAuto.current = autoAsk.nonce;
      ask(autoAsk.q);
    }
  }, [open, autoAsk]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [msgs, open]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  async function ask(question: string) {
    const q = question.trim();
    if (!q || busy) return;
    setInput("");
    setMsgs((m) => [...m, { role: "you", text: q }]);
    setBusy(true);
    let answer = "";
    try {
      const r = await fetch("/api/ask", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: q, chain_id: chain?.chain_id }),
      });
      answer = (await r.json())?.answer ?? "";
    } catch {
      /* console degrades to the same grounded answer it would serve offline */
    }
    if (!answer) answer = answerLocally(q, chain);
    setMsgs((m) => [...m, { role: "q", text: answer }]);
    setBusy(false);
    setTimeout(() => inputRef.current?.focus(), 30);
  }

  return (
    <>
      {open && (
        <aside className="aq-drawer" role="dialog" aria-label="Ask Agent Q" style={drawerStyle}>
          <header className="aq-head">
            <span className="aq-ava"><QMark size={24} /></span>
            <div className="aq-id">
              <b>Agent&nbsp;Q</b>
              <span className="aq-ctx">
                {chain ? <>on <span className={`v-${chain.verdict}`}>{chain.verdict}</span> · {chain.source}</>
                       : "no incident selected"}
                {fixtureMode ? " · sample" : ""}
              </span>
            </div>
            <button className="aq-x" onClick={() => setOpen(false)} aria-label="Close">✕</button>
          </header>

          <div className="aq-msgs">
            {msgs.map((m, i) => (
              <div key={i} className={`aq-msg ${m.role}`}>
                {m.role === "q" && <span className="aq-mini"><QMark size={16} /></span>}
                <p>{m.text}</p>
              </div>
            ))}
            {busy && <div className="aq-msg q"><span className="aq-mini"><QMark size={16} /></span><p className="aq-typing"><i /><i /><i /></p></div>}
            <div ref={endRef} />
          </div>

          {msgs.length <= 1 && (
            <div className="aq-chips">
              {SUGGESTED.map((s) => (
                <button key={s} className="aq-chip" onClick={() => ask(s)} disabled={busy}>{s}</button>
              ))}
            </div>
          )}

          <form
            className="aq-input-row"
            onSubmit={(e) => { e.preventDefault(); ask(input); }}
          >
            <input
              ref={inputRef}
              className="aq-input"
              placeholder="Ask about this detection…"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              disabled={busy}
            />
            <button className="aq-send" type="submit" disabled={busy || !input.trim()} aria-label="Send">→</button>
          </form>
        </aside>
      )}

      <QMascot
        mood={fixtureMode ? "offline" : mood}
        pending={pending}
        open={open}
        onTap={() => setOpen(!open)}
        onMove={setMpos}
      />
    </>
  );
}
