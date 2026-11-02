import { readFile } from "node:fs/promises";
import path from "node:path";
import { cached } from "./cache";
import fixturePosture from "../fixtures/posture.json";

// The posture runner (python -m aegis.posture run) writes latest.json into its store directory on the
// SOC host; the console reads it from there. Same host, same trust zone — no new backend endpoint and
// no cloud credentials anywhere near the console.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface PostureFinding {
  fingerprint: string;
  id: string;
  severity: Severity;
  scan: string;
  scanner: string;
  affected_component: string;
  resource: string | null;
  evidence: string;
  recommended_remediation: string;
  control: string | null;
  confidence: number;
  first_seen: string;
  age_days: number;
  sla_due: string;
  overdue: boolean;
  new: boolean;
  stale: boolean;
  extra?: ExposureExtra | null;
}

// scanner === "exposure": the engine's verdict behind the severity
export interface ExposureExtra {
  tier: "ACT_NOW" | "ACT" | "SCHEDULE" | "MONITOR";
  reach: "internet" | "one_hop" | "local" | "isolated";
  defended: "full" | "partial" | "none";
  exploitable: boolean;
  crown_distance: number | null;
  port: number | null;
  title: string;
  reasons: string[];
  source?: string;
}

export interface ExposureMeta {
  funnel: { raw: number; scored: number; exploitable: number; reachable: number; undefended: number; act_now: number };
  tiers: Record<string, number>;
  assets: number;
  protections: number;
  monitor_only: number;
}

export interface PostureScan {
  name: string;
  type: "iam" | "cspm" | "azure" | "k8s" | "iac" | "exposure";
  status: "ok" | "error";
  live: boolean;
  seconds: number;
  error?: string;
  notes?: string[];
  summary?: Record<Severity, number>;
  meta?: ExposureMeta;
}

export interface PostureRun {
  run_id: string;
  started_at: string;
  scans: PostureScan[];
  summary: Record<Severity, number>;
  sla_days: Record<string, number>;
  counts: { open: number; new: number; resolved: number; overdue: number; waived: number; stale: number; scans_failed: number };
  open: PostureFinding[];
  resolved: { fingerprint: string; id: string; severity: Severity; scan: string; affected_component: string; first_seen?: string; resolved_at: string }[];
  waived: (PostureFinding & { waiver: { reason: string; approved_by: string; expires: string } })[];
  notes: string[];
}

export type PostureResult =
  | { state: "ok"; run: PostureRun; source: "store" | "fixture" }
  | { state: "unconfigured" | "empty" | "error"; message: string };

const POSTURE_DIR = process.env.AEGIS_POSTURE_DIR || "";
const API_ORIGIN = process.env.AEGIS_API_ORIGIN || "";
const USE_FIXTURES = !POSTURE_DIR && (!API_ORIGIN || process.env.NEXT_PUBLIC_AEGIS_USE_FIXTURES === "1");

export async function getPosture(): Promise<PostureResult> {
  if (USE_FIXTURES) return { state: "ok", run: fixturePosture as unknown as PostureRun, source: "fixture" };
  if (!POSTURE_DIR) {
    // live console but no posture store: say so rather than show sample data next to real incidents
    return { state: "unconfigured", message: "Posture scanning is not connected. Set AEGIS_POSTURE_DIR to the runner's store directory." };
  }
  // shared across every analyst session, like the incident snapshot (lib/cache.ts)
  return cached("posture", 10_000, async (): Promise<PostureResult> => {
    const file = path.join(POSTURE_DIR, "latest.json");
    try {
      const run = JSON.parse(await readFile(file, "utf8")) as PostureRun;
      if (!run || !Array.isArray(run.open)) return { state: "error", message: `${file} is not a posture run record.` };
      return { state: "ok", run, source: "store" };
    } catch (e) {
      const err = e as NodeJS.ErrnoException;
      if (err.code === "ENOENT") return { state: "empty", message: "No posture run yet. Start the runner: python -m aegis.posture run --config posture.yaml" };
      return { state: "error", message: `Cannot read ${file}: ${err.message}`.slice(0, 200) };
    }
  });
}
