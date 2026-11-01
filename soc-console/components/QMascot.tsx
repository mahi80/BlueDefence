"use client";

/**
 * Agent Q — the console's living sentinel.
 *
 * An original character drawn in SVG: a rounded shield body with a visor, two eyes that blink and
 * follow the pointer, a mouth that reads the room, an antenna lamp that carries the mood, and a slow
 * breath. Mood comes from the live verdict counts (calm / alert / critical); pending approvals sit
 * in a badge. Drag it anywhere — the spot is remembered per browser; a tap (no movement) opens Q.
 */

import { useCallback, useEffect, useRef, useState } from "react";

export type Mood = "calm" | "alert" | "critical" | "offline";
export type Pos = { x: number; y: number };

const SIZE = 84;
const STORE = "aegis.q.pos.v1";
const TAP_MAX_DIST = 6;
const TAP_MAX_MS = 400;

const MOOD = {
  calm:     { lamp: "var(--v-benign)",     ring: "rgba(15,157,107,.45)",  label: "All quiet — Q is watching" },
  alert:    { lamp: "var(--v-suspicious)", ring: "rgba(194,65,12,.5)",    label: "Suspicious activity under review" },
  critical: { lamp: "var(--v-malicious)",  ring: "rgba(217,45,75,.55)",   label: "Malicious verdicts need a decision" },
  offline:  { lamp: "var(--ink-faint)",    ring: "rgba(120,130,150,.4)",  label: "Sample stream — not connected" },
} as const;

function clamp(p: Pos): Pos {
  if (typeof window === "undefined") return p;
  const pad = 8;
  return {
    x: Math.min(Math.max(p.x, pad), window.innerWidth - SIZE - pad),
    y: Math.min(Math.max(p.y, pad), window.innerHeight - SIZE - pad),
  };
}

function defaultPos(): Pos {
  if (typeof window === "undefined") return { x: 0, y: 0 };
  return { x: window.innerWidth - SIZE - 22, y: window.innerHeight - SIZE - 22 };
}

export function loadPos(): Pos {
  try {
    const raw = localStorage.getItem(STORE);
    if (raw) {
      const p = JSON.parse(raw);
      if (typeof p?.x === "number" && typeof p?.y === "number") return clamp(p);
    }
  } catch { /* storage unavailable: use the default corner */ }
  return defaultPos();
}

export default function QMascot({
  mood, pending, open, onTap, onMove,
}: {
  mood: Mood;
  pending: number;
  open: boolean;
  onTap: () => void;
  onMove?: (p: Pos) => void;
}) {
  const [pos, setPos] = useState<Pos | null>(null);
  const [eye, setEye] = useState({ dx: 0, dy: 0 });
  const [blink, setBlink] = useState(false);
  const [hover, setHover] = useState(false);
  const [dragging, setDragging] = useState(false);
  const drag = useRef<{ sx: number; sy: number; ox: number; oy: number; t: number; moved: boolean } | null>(null);
  const ref = useRef<HTMLDivElement>(null);
  const reduced = typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

  // position: restore, publish, keep on screen when the window changes size
  useEffect(() => {
    const p = loadPos();
    setPos(p); onMove?.(p);
    const onResize = () => setPos((cur) => { const n = clamp(cur ?? defaultPos()); onMove?.(n); return n; });
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // eyes follow the pointer (gently), unless the viewer prefers reduced motion
  useEffect(() => {
    if (reduced) return;
    let raf = 0;
    const onPointer = (e: PointerEvent) => {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => {
        const r = ref.current?.getBoundingClientRect();
        if (!r) return;
        const cx = r.left + r.width / 2, cy = r.top + r.height * 0.42;
        const dx = e.clientX - cx, dy = e.clientY - cy;
        const d = Math.hypot(dx, dy) || 1;
        const k = Math.min(1, d / 260) * 2.6;         // max 2.6 px of travel
        setEye({ dx: (dx / d) * k, dy: (dy / d) * k });
      });
    };
    window.addEventListener("pointermove", onPointer, { passive: true });
    return () => { window.removeEventListener("pointermove", onPointer); cancelAnimationFrame(raf); };
  }, [reduced]);

  // blink: irregular, sometimes twice
  useEffect(() => {
    if (reduced) return;
    let t1 = 0, t2 = 0, t3 = 0;
    const schedule = () => {
      t1 = window.setTimeout(() => {
        setBlink(true);
        t2 = window.setTimeout(() => {
          setBlink(false);
          if (Math.random() < 0.25) {
            t3 = window.setTimeout(() => { setBlink(true); window.setTimeout(() => setBlink(false), 110); }, 160);
          }
          schedule();
        }, 120);
      }, 2200 + Math.random() * 3800);
    };
    schedule();
    return () => { clearTimeout(t1); clearTimeout(t2); clearTimeout(t3); };
  }, [reduced]);

  const onPointerDown = useCallback((e: React.PointerEvent) => {
    if (!pos) return;
    (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
    drag.current = { sx: e.clientX, sy: e.clientY, ox: pos.x, oy: pos.y, t: Date.now(), moved: false };
  }, [pos]);

  const onPointerMove = useCallback((e: React.PointerEvent) => {
    const d = drag.current;
    if (!d) return;
    const dx = e.clientX - d.sx, dy = e.clientY - d.sy;
    if (!d.moved && Math.hypot(dx, dy) > TAP_MAX_DIST) { d.moved = true; setDragging(true); }
    if (d.moved) {
      const n = clamp({ x: d.ox + dx, y: d.oy + dy });
      setPos(n); onMove?.(n);
    }
  }, [onMove]);

  const onPointerUp = useCallback(() => {
    const d = drag.current;
    drag.current = null;
    setDragging(false);
    if (!d) return;
    if (!d.moved && Date.now() - d.t < TAP_MAX_MS) { onTap(); return; }
    if (d.moved) {
      try { localStorage.setItem(STORE, JSON.stringify(pos)); } catch { /* fine without */ }
    }
  }, [onTap, pos]);

  if (!pos) return null;
  const m = MOOD[mood];
  const excited = mood === "critical";
  const mouth = mood === "critical" ? "M30 54 Q42 49 54 54"        // worried
             : mood === "alert"    ? "M32 54 L52 54"               // flat
             : mood === "offline"  ? "M33 55 L51 55"
             :                       "M30 52 Q42 59 54 52";        // smile

  return (
    <div
      ref={ref}
      className={`qm ${dragging ? "dragging" : ""} ${open ? "open" : ""} mood-${mood}`}
      style={{ left: pos.x, top: pos.y, width: SIZE, height: SIZE }}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      onPointerCancel={onPointerUp}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      role="button"
      tabIndex={0}
      aria-label={`Agent Q — ${m.label}. Tap to ask, drag to move.`}
      onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onTap(); } }}
    >
      {/* mood halo + pulse */}
      <span className="qm-halo" style={{ background: `radial-gradient(circle, ${m.ring} 0%, transparent 70%)` }} aria-hidden />
      {(mood === "critical" || mood === "alert") && !reduced && (
        <span className="qm-pulse" style={{ borderColor: m.lamp }} aria-hidden />
      )}

      <svg className={`qm-body ${excited && !reduced ? "excited" : ""}`} viewBox="0 0 84 84" width={SIZE} height={SIZE} aria-hidden focusable="false">
        <defs>
          <linearGradient id="qm-shell" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="#f7f9ff" />
            <stop offset="1" stopColor="#dfe6f5" />
          </linearGradient>
          <linearGradient id="qm-visor" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor="#1e293b" />
            <stop offset="1" stopColor="#0b1220" />
          </linearGradient>
          <clipPath id="qm-visor-clip"><rect x="20" y="28" width="44" height="22" rx="11" /></clipPath>
        </defs>

        {/* antenna + lamp */}
        <line x1="42" y1="16" x2="42" y2="8" stroke="#64748b" strokeWidth="2.2" strokeLinecap="round" />
        <circle cx="42" cy="6.5" r="3.6" fill={m.lamp} className="qm-lamp" />

        {/* shield body */}
        <path d="M42 13 L68 21 V46 C68 61 57 71 42 76 C27 71 16 61 16 46 V21 Z"
              fill="url(#qm-shell)" stroke="#2563eb" strokeWidth="2" />
        <path d="M42 18 L63 24.5 V46 C63 58 54 66 42 70.5 C30 66 21 58 21 46 V24.5 Z"
              fill="none" stroke="#2563eb" strokeOpacity=".18" strokeWidth="1.2" />

        {/* visor */}
        <rect x="20" y="28" width="44" height="22" rx="11" fill="url(#qm-visor)" />
        <g clipPath="url(#qm-visor-clip)">
          <rect className="qm-scan" x="20" y="28" width="10" height="22" fill="#60a5fa" fillOpacity=".18" />
        </g>

        {/* eyes: whites, pupils that track, lids that blink */}
        <g transform={`translate(${eye.dx} ${eye.dy})`}>
          <ellipse cx="33" cy="39" rx="4.6" ry={blink ? 0.6 : 5.2} fill="#e0f2fe" className="qm-eye" />
          <ellipse cx="51" cy="39" rx="4.6" ry={blink ? 0.6 : 5.2} fill="#e0f2fe" className="qm-eye" />
          {!blink && (
            <>
              <circle cx={33 + eye.dx * 0.5} cy={39 + eye.dy * 0.5} r="2.2" fill="#0b1220" />
              <circle cx={51 + eye.dx * 0.5} cy={39 + eye.dy * 0.5} r="2.2" fill="#0b1220" />
              <circle cx={32 + eye.dx * 0.5} cy={37.6 + eye.dy * 0.5} r="0.8" fill="#fff" />
              <circle cx={50 + eye.dx * 0.5} cy={37.6 + eye.dy * 0.5} r="0.8" fill="#fff" />
            </>
          )}
        </g>

        {/* mouth */}
        <path d={mouth} fill="none" stroke="#2563eb" strokeWidth="2.2" strokeLinecap="round" />

        {/* Q mark on the chest */}
        <circle cx="42" cy="61" r="3.8" fill="none" stroke="#2563eb" strokeWidth="1.6" />
        <path d="M44.4 63.4 L46.6 65.6" stroke="#2563eb" strokeWidth="1.6" strokeLinecap="round" />
      </svg>

      {pending > 0 && <span className="qm-badge" aria-label={`${pending} pending approvals`}>{pending > 99 ? "99+" : pending}</span>}

      {hover && !dragging && (
        <span className="qm-tip" role="tooltip">
          <b style={{ color: m.lamp }}>●</b> {m.label}
          <small>tap to ask · drag to move</small>
        </span>
      )}
    </div>
  );
}
