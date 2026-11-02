"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import type { ExposureExtra, PostureFinding, PostureResult, PostureRun, PostureScan } from "../lib/posture";
import { TopNav, when } from "./PostureView";

type Tier = ExposureExtra["tier"];
const TIERS: Tier[] = ["ACT_NOW", "ACT", "SCHEDULE", "MONITOR"];
const TIER_LABEL: Record<Tier, string> = { ACT_NOW: "Act now", ACT: "Act", SCHEDULE: "Schedule", MONITOR: "Monitor" };
const REACH_LABEL: Record<ExposureExtra["reach"], string> = {
  internet: "Internet-facing", one_hop: "One hop from the internet", local: "Local only", isolated: "No internet path",
};
const DEF_LABEL: Record<ExposureExtra["defended"], string> = { none: "No blocking control", partial: "WAF in front", full: "Virtual patch" };

type Level = "bad" | "warn" | "ok";
function levels(x: ExposureExtra): Level[] {
  return [
    x.exploitable ? "bad" : "ok",
    x.reach === "internet" ? "bad" : x.reach === "one_hop" ? "warn" : "ok",
    x.defended === "none" ? "bad" : x.defended === "partial" ? "warn" : "ok",
    x.crown_distance === 0 ? "bad" : x.crown_distance === 1 ? "warn" : "ok",
  ];
}
const QUESTIONS = ["Exploitable", "Reachable", "Defended", "Crown jewels"];

function Funnel({ scan, waivedNow }: { scan: PostureScan; waivedNow: number }) {
  const f = scan.meta!.funnel;
  const steps: [string, number, string][] = [
    ["Scanner findings", f.raw, "everything the scanners reported"],
    ["Exploitable", f.exploitable, "KEV, EPSS or a public exploit"],
    ["Reachable", f.reachable, "from the internet, or one hop in"],
    ["Undefended", f.undefended, "no blocking WAF or virtual patch"],
    ["Act now", f.act_now, waivedNow ? `all of the above · ${waivedNow} accepted as risk` : "all of the above"],
  ];
  const max = Math.max(f.raw, 1);
  const pct = f.raw ? (100 * f.act_now) / f.raw : 0;
  return (
    <section className="ex-funnel" aria-label={`Exposure funnel for ${scan.name}`}>
      <div className="ex-funnel-head">
        <h2>{scan.name}</h2>
        <span className="sub">
          {f.act_now} of {f.raw} findings need action now ({pct < 1 && pct > 0 ? pct.toFixed(1) : Math.round(pct)}%) · {scan.meta!.assets} assets ·{" "}
          {scan.meta!.protections} WAF protections
        </span>
      </div>
      <ol className="ex-steps">
        {steps.map(([label, n, hint], i) => (
          <li key={label} className={i === steps.length - 1 ? "ex-step last" : "ex-step"}>
            <div className="ex-bar"><i style={{ width: `${Math.max(4, (100 * n) / max)}%` }} /></div>
            <div className="ex-n mono">{n}</div>
            <div className="ex-label">{label}</div>
            <div className="ex-hint">{hint}</div>
          </li>
        ))}
      </ol>
      {scan.meta!.monitor_only > 0 && (
        <p className="ex-monitor">
          <b>{scan.meta!.monitor_only} WAF protection{scan.meta!.monitor_only === 1 ? " is" : "s are"} in monitor mode.</b> They log attacks and let them
          through, so they are not counted as defences.
        </p>
      )}
    </section>
  );
}

function Card({ f, waived }: { f: PostureFinding & { waiver?: { reason: string; approved_by: string; expires: string } }; waived?: boolean }) {
  const x = f.extra!;
  const lv = levels(x);
  const answers = [
    x.exploitable ? "Yes" : "No signal",
    REACH_LABEL[x.reach],
    DEF_LABEL[x.defended],
    x.crown_distance === 0 ? "Is a crown jewel" : x.crown_distance === 1 ? "Next to one" : "Not nearby",
  ];
  return (
    <article className="ex-card" data-tier={x.tier}>
      <header className="ex-card-head">
        <span className={`ex-tier t-${x.tier}`}>{TIER_LABEL[x.tier]}</span>
        <span className="mono ex-cve">{f.id}</span>
        <span className="ex-title">{x.title}</span>
        {f.new && <span className="flag flag-new">new</span>}
        {!waived && <span className={`ex-sla mono${f.overdue ? " overdue" : ""}`} suppressHydrationWarning>{f.overdue ? "past SLA" : `SLA ${when(f.sla_due)}`}</span>}
      </header>
      <div className="ex-asset">{f.affected_component} <span className="sub">· {f.scan}{x.source ? ` · ${x.source}` : ""}</span></div>
      <div className="ex-answers">
        {QUESTIONS.map((q, i) => (
          <div key={q} className={`ex-answer lv-${lv[i]}`} title={x.reasons[i]}>
            <span className="ex-q">{q}</span>
            <span className="ex-a">{answers[i]}</span>
            <span className="ex-why">{x.reasons[i]}</span>
          </div>
        ))}
      </div>
      {waived && f.waiver ? (
        <p className="ex-fix">Accepted risk: {f.waiver.reason} — {f.waiver.approved_by}, until {f.waiver.expires}</p>
      ) : (
        <p className="ex-fix"><b>Fix:</b> {f.recommended_remediation}</p>
      )}
    </article>
  );
}

export default function ExposureView({ result, session }: { result: PostureResult; session: { user: string; role: string } }) {
  const router = useRouter();
  const fixture = result.state === "ok" && result.source === "fixture";
  useEffect(() => {
    if (fixture || result.state !== "ok") return;
    const id = setInterval(() => router.refresh(), 30_000);
    return () => clearInterval(id);
  }, [router, fixture, result.state]);

  const run: PostureRun | null = result.state === "ok" ? result.run : null;
  const scans = useMemo(() => (run?.scans ?? []).filter((s) => s.type === "exposure" && s.meta), [run]);
  const open = useMemo(() => (run?.open ?? []).filter((f) => f.scanner === "exposure" && f.extra), [run]);
  const waived = useMemo(() => (run?.waived ?? []).filter((f) => f.scanner === "exposure" && f.extra), [run]);
  const counts = useMemo(() => Object.fromEntries(TIERS.map((t) => [t, open.filter((f) => f.extra!.tier === t).length])), [open]);
  const [tier, setTier] = useState<Tier | "WAIVED">("ACT_NOW");
  const shown = tier === "WAIVED" ? waived : open.filter((f) => f.extra!.tier === tier);

  if (!run || !scans.length) {
    const msg = result.state !== "ok" ? result.message
      : "No exposure scan in this run. Add a `type: exposure` scan to posture.yaml (scanner exports, KEV / EPSS, the asset model and WAF coverage).";
    return (
      <div className="app posture-app">
        <TopNav active="exposure" session={session} />
        <div className="posture-empty"><h2>Exposures</h2><p>{msg}</p></div>
        <div />
      </div>
    );
  }

  return (
    <div className="app posture-app">
      <TopNav active="exposure" session={session}>
        <div className="live">
          <span className="pulse-dot" aria-hidden /> {fixture ? "sample run" : `last run ${when(run.started_at)}`}
        </div>
        <div className="counts">
          <span className="chip"><span className="dot" style={{ background: "var(--v-malicious)" }} /> act now <span className="n">{counts.ACT_NOW}</span></span>
          <span className="chip"><span className="dot" style={{ background: "var(--v-suspicious)" }} /> act <span className="n">{counts.ACT}</span></span>
        </div>
      </TopNav>
      <main className="ex-main">
        {scans.map((s) => (
          <Funnel key={s.name} scan={s} waivedNow={waived.filter((w) => w.scan === s.name && w.extra!.tier === "ACT_NOW").length} />
        ))}
        <div className="ex-tabs" role="tablist" aria-label="Tier">
          {TIERS.map((t) => (
            <button key={t} role="tab" aria-selected={tier === t} className={`t-${t}`} onClick={() => setTier(t)}>
              {TIER_LABEL[t]} <span className="mono">{counts[t]}</span>
            </button>
          ))}
          <button role="tab" aria-selected={tier === "WAIVED"} onClick={() => setTier("WAIVED")}>
            Accepted risk <span className="mono">{waived.length}</span>
          </button>
        </div>
        <div className="ex-list">
          {shown.length ? shown.map((f) => <Card key={f.fingerprint} f={f} waived={tier === "WAIVED"} />)
            : <div className="ev-empty">Nothing in this tier.</div>}
        </div>
      </main>
      <div />
    </div>
  );
}
