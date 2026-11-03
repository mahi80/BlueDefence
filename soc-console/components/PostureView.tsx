"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import type { PostureFinding, PostureResult, PostureRun, Severity } from "../lib/posture";

const SEVS: Severity[] = ["critical", "high", "medium", "low", "info"];
const SCAN_LABEL: Record<string, string> = { iam: "IAM", cspm: "AWS", azure: "Azure", k8s: "K8s", iac: "IaC", exposure: "Exposure" };

// One explicit locale + zone so the server render and the browser agree (no hydration mismatch). Banks
// read SOC timestamps in their own zone; override with NEXT_PUBLIC_AEGIS_TZ.
const FMT = new Intl.DateTimeFormat("en-IN", {
  timeZone: process.env.NEXT_PUBLIC_AEGIS_TZ || "Asia/Kolkata",
  day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", hour12: false, timeZoneName: "short",
});

export function when(iso: string): string {
  return FMT.format(new Date(iso));
}

function dueLabel(f: PostureFinding): string {
  const days = Math.round((new Date(f.sla_due).getTime() - Date.now()) / 86_400_000);
  if (f.overdue) return `${Math.abs(days)}d overdue`;
  return days <= 0 ? "due today" : `due in ${days}d`;
}

export function TopNav({ active, session, children }: { active: "incidents" | "posture" | "exposure"; session: { user: string; role: string }; children?: React.ReactNode }) {
  async function logout() {
    try {
      await fetch("/api/auth/logout", { method: "POST" });
    } catch {
      /* redirect regardless */
    }
    window.location.href = "/login";
  }
  return (
    <header className="topbar">
      <div className="brand">
        <span className="logo"><b>AEGIS</b> SOC</span>
      </div>
      <nav className="tabs" aria-label="Views">
        <Link href="/" aria-current={active === "incidents" ? "page" : undefined}>Incidents</Link>
        <Link href="/posture" aria-current={active === "posture" ? "page" : undefined}>Posture</Link>
        <Link href="/exposure" aria-current={active === "exposure" ? "page" : undefined}>Exposures</Link>
      </nav>
      {children}
      <div className="whoami">
        <span className="u"><b>{session.user}</b></span>
        <span className="role">{session.role}</span>
        <button className="logout" onClick={logout}>Sign out</button>
      </div>
    </header>
  );
}

function Empty({ message, session }: { message: string; session: { user: string; role: string } }) {
  return (
    <div className="app posture-app">
      <TopNav active="posture" session={session} />
      <div className="posture-empty">
        <h2>Posture</h2>
        <p>{message}</p>
      </div>
      <div />
    </div>
  );
}

export default function PostureView({ result, session }: { result: PostureResult; session: { user: string; role: string } }) {
  if (result.state !== "ok") return <Empty message={result.message} session={session} />;
  return <PostureBody run={result.run} fixture={result.source === "fixture"} session={session} />;
}

function PostureBody({ run, fixture, session }: { run: PostureRun; fixture: boolean; session: { user: string; role: string } }) {
  const router = useRouter();
  useEffect(() => {
    if (fixture) return;
    const id = setInterval(() => router.refresh(), 30_000); // posture moves in hours, not seconds
    return () => clearInterval(id);
  }, [router, fixture]);

  const [scan, setScan] = useState<string | null>(null);
  const [sevs, setSevs] = useState<Set<Severity>>(new Set(["critical", "high", "medium", "low", "info"]));
  const [only, setOnly] = useState<"all" | "overdue" | "new">("all");
  const [q, setQ] = useState("");

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return run.open.filter(
      (f) =>
        (!scan || f.scan === scan) &&
        sevs.has(f.severity) &&
        (only === "all" || (only === "overdue" ? f.overdue : f.new)) &&
        (!needle || `${f.id} ${f.affected_component} ${f.evidence} ${f.control ?? ""}`.toLowerCase().includes(needle)),
    );
  }, [run.open, scan, sevs, only, q]);

  const [selFp, setSelFp] = useState<string | null>(run.open[0]?.fingerprint ?? null);
  const selected = rows.find((f) => f.fingerprint === selFp) ?? rows[0] ?? null;

  const toggleSev = (s: Severity) =>
    setSevs((cur) => {
      const n = new Set(cur);
      if (n.has(s)) n.delete(s);
      else n.add(s);
      return n.size ? n : new Set(SEVS);
    });

  const overdueCrit = run.open.filter((f) => f.overdue && f.severity === "critical").length;
  const registerBroken = run.notes.some((n) => n.startsWith("WAIVER REGISTER NOT APPLIED"));

  return (
    <div className="app posture-app">
      <TopNav active="posture" session={session}>
        <div className="live">
          <span className="pulse-dot" aria-hidden style={run.counts.scans_failed ? { background: "var(--v-suspicious)" } : undefined} />{" "}
          {fixture ? "sample run" : `last run ${when(run.started_at)}`} · {run.scans.length - run.counts.scans_failed}/{run.scans.length} scans ok
        </div>
        <div className="counts">
          <span className="chip"><span className="dot" style={{ background: "var(--v-malicious)" }} /> critical <span className="n">{run.summary.critical}</span></span>
          <span className="chip"><span className="dot" style={{ background: "var(--v-suspicious)" }} /> past SLA <span className="n">{run.counts.overdue}</span></span>
        </div>
      </TopNav>

      <div className="posture-cols">
        <aside className="rail posture-filters" aria-label="Filters">
          <div className="rail-head">
            <h2>Scans</h2>
            <div className="sub">{run.counts.open} open · {run.counts.new} new · {run.counts.resolved} resolved</div>
          </div>
          <button className="scan-row" aria-pressed={scan === null} onClick={() => setScan(null)}>
            <span className="scan-name">All scans</span>
            <span className="scan-n mono">{run.counts.open}</span>
          </button>
          {run.scans.map((s) => {
            const n = run.open.filter((f) => f.scan === s.name).length;
            return (
              <button key={s.name} className="scan-row" data-status={s.status} aria-pressed={scan === s.name} onClick={() => setScan(s.name)}
                      title={s.status === "error" ? s.error : (s.notes ?? []).join("\n")}>
                <span className="scan-type">{SCAN_LABEL[s.type] ?? s.type}</span>
                <span className="scan-name">{s.name}{s.live ? " · live" : ""}</span>
                <span className="scan-n mono">{s.status === "error" ? "failed" : n}</span>
              </button>
            );
          })}
          <div className="rail-head"><h2>Severity</h2></div>
          <div className="sev-filters">
            {SEVS.filter((s) => s !== "info" || run.summary.info).map((s) => (
              <label key={s} className={`sev-toggle sev-${s}`}>
                <input type="checkbox" checked={sevs.has(s)} onChange={() => toggleSev(s)} />
                {s} <span className="mono">{run.summary[s]}</span>
              </label>
            ))}
          </div>
          <div className="rail-head"><h2>Show</h2></div>
          <div className="only-filters" role="radiogroup">
            {(["all", "overdue", "new"] as const).map((o) => (
              <button key={o} role="radio" aria-checked={only === o} onClick={() => setOnly(o)}>
                {o === "all" ? "All open" : o === "overdue" ? `Past SLA (${run.counts.overdue})` : `New (${run.counts.new})`}
              </button>
            ))}
          </div>
        </aside>

        <section className="posture-main" aria-label="Findings">
          {overdueCrit > 0 && (
            <div className="posture-alert" role="alert">
              <b>{overdueCrit} critical finding{overdueCrit === 1 ? "" : "s"} past the {run.sla_days.critical}-day SLA.</b> Remediate or record an approved waiver.
            </div>
          )}
          {registerBroken && (
            <div className="posture-alert" role="alert">
              <b>Waiver register not applied.</b> {run.notes.find((n) => n.startsWith("WAIVER REGISTER NOT APPLIED"))?.replace("WAIVER REGISTER NOT APPLIED — ", "")}
            </div>
          )}
          <div className="posture-tools">
            <input className="posture-search" type="search" placeholder="Search finding, resource, control…" value={q} onChange={(e) => setQ(e.target.value)} />
            <span className="sub">{rows.length} of {run.counts.open}</span>
          </div>
          <div className="posture-table" role="table">
            <div className="pt-row pt-head" role="row">
              <span role="columnheader">Severity</span>
              <span role="columnheader">Finding</span>
              <span role="columnheader">Resource</span>
              <span role="columnheader">Scan</span>
              <span role="columnheader">SLA</span>
            </div>
            {rows.map((f) => (
              <button key={f.fingerprint} role="row" className="pt-row" data-sev={f.severity} data-overdue={f.overdue || undefined}
                      aria-selected={selected?.fingerprint === f.fingerprint} onClick={() => setSelFp(f.fingerprint)}>
                <span role="cell"><span className={`sev-badge sev-${f.severity === "medium" ? "elevated" : f.severity === "info" ? "low" : f.severity}`}>{f.severity}</span></span>
                <span role="cell" className="pt-id mono">
                  {f.id}
                  {f.new && <span className="flag flag-new">new</span>}
                  {f.stale && <span className="flag flag-stale" title="This scan failed in the latest run; last known state shown">stale</span>}
                </span>
                <span role="cell" className="pt-res">{f.affected_component}</span>
                <span role="cell" className="pt-scan">{f.scan}</span>
                <span role="cell" className={`pt-sla mono${f.overdue ? " overdue" : ""}`} suppressHydrationWarning>{dueLabel(f)}</span>
              </button>
            ))}
            {!rows.length && <div className="ev-empty">Nothing matches these filters.</div>}
          </div>
        </section>

        <aside className="posture-detail" aria-label="Finding detail">
          {selected ? (
            <div className="pd-card">
              <div className="banner-top">
                <span className={`sev-badge sev-${selected.severity === "medium" ? "elevated" : selected.severity === "info" ? "low" : selected.severity}`}>{selected.severity}</span>
                <span className="mono pd-id">{selected.id}</span>
              </div>
              <h3 className="pd-res">{selected.affected_component}</h3>
              <dl>
                <dt>What is wrong</dt><dd>{selected.evidence}</dd>
                <dt>Fix</dt><dd>{selected.recommended_remediation}</dd>
                {selected.control && (<><dt>Control</dt><dd>{selected.control}</dd></>)}
                {selected.resource && selected.resource !== selected.affected_component && (<><dt>Resource</dt><dd className="mono">{selected.resource}</dd></>)}
                <dt>Scan</dt><dd>{selected.scan} ({selected.scanner})</dd>
                <dt>First seen</dt><dd>{when(selected.first_seen)} · {selected.age_days}d open</dd>
                <dt>SLA</dt><dd className={selected.overdue ? "overdue" : undefined} suppressHydrationWarning>{when(selected.sla_due)} · {dueLabel(selected)}</dd>
              </dl>
              <p className="pd-hint">Remediate in the source (Terraform, manifest or console), or add an entry to the waiver register with a reason, approver and expiry. The next run shows it as resolved or waived.</p>
            </div>
          ) : (
            <div className="ev-empty">Select a finding.</div>
          )}

          {run.waived.length > 0 && (
            <div className="pd-section">
              <h3>Accepted risk <span className="sub">({run.waived.length})</span></h3>
              {run.waived.map((w) => (
                <div key={w.fingerprint} className="pd-item">
                  <div className="mono">{w.id}</div>
                  <div>{w.affected_component}</div>
                  <div className="sub">{w.waiver.reason} — {w.waiver.approved_by}, until {w.waiver.expires}</div>
                </div>
              ))}
            </div>
          )}
          {run.resolved.length > 0 && (
            <div className="pd-section">
              <h3>Resolved since last run <span className="sub">({run.resolved.length})</span></h3>
              {run.resolved.map((r) => (
                <div key={r.fingerprint} className="pd-item resolved">
                  <span className="mono">{r.id}</span> <span>{r.affected_component}</span>
                </div>
              ))}
            </div>
          )}
          {run.notes.filter((n) => !n.startsWith("WAIVER REGISTER NOT APPLIED")).length > 0 && (
            <div className="pd-section">
              <h3>Register notes</h3>
              {run.notes.filter((n) => !n.startsWith("WAIVER REGISTER NOT APPLIED")).map((n) => <div key={n} className="pd-item sub">{n}</div>)}
            </div>
          )}
        </aside>
      </div>
      <div />
    </div>
  );
}
