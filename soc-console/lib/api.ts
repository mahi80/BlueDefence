import type { Chain, ChainSummary, Approval, Proposal } from "./types";
import { cached, SNAPSHOT_TTL_MS } from "./cache";
import fixtureChains from "../fixtures/chains.json";
import fixtureApprovals from "../fixtures/approvals.json";
import fixtureProposals from "../fixtures/proposals.json";

const API_ORIGIN = process.env.AEGIS_API_ORIGIN || "";
const USE_FIXTURES = !API_ORIGIN || process.env.NEXT_PUBLIC_AEGIS_USE_FIXTURES === "1";

const CHAINS = fixtureChains as unknown as Chain[];

// Set when a live backend call failed during this render; the page shows it instead of pretending.
// (Module-level is fine: the console is rendered per request in a single Node process.)
export let backendError: string | null = null;

async function backend<T>(path: string, fallback: T, empty: T): Promise<T> {
  if (USE_FIXTURES) return fallback;
  try {
    const res = await fetch(`${API_ORIGIN}${path}`, {
      headers: process.env.AEGIS_API_KEY ? { Authorization: `Bearer ${process.env.AEGIS_API_KEY}` } : {},
      cache: "no-store",
    });
    if (!res.ok) throw new Error(`${path} -> ${res.status}`);
    backendError = null;
    return (await res.json()) as T;
  } catch (e) {
    // Live mode never substitutes sample data: an empty list plus a visible error, so nobody approves a fixture.
    backendError = `${(e as Error).message}`.slice(0, 160);
    return empty;
  }
}

export async function listChains(): Promise<ChainSummary[]> {
  const live = await backend<{ chains?: ChainSummary[] } | ChainSummary[]>("/api/soc/chains", CHAINS, []);
  const rows = Array.isArray(live) ? live : (live.chains ?? []);
  return rows as ChainSummary[];
}

export async function getChain(id: string): Promise<Chain | null> {
  if (USE_FIXTURES) return CHAINS.find((c) => c.chain_id === id) ?? CHAINS[0] ?? null;
  // The detail endpoint returns the summary fields at the top level plus the full
  // stored chain (recommended_actions, investigation, evidence) under `chain`.
  // Flatten so the UI and Agent Q see one Chain with evidence present.
  const live = await backend<(Chain & { chain?: Partial<Chain> }) | null>(
    `/api/soc/chains/${encodeURIComponent(id)}`,
    null,
    null,
  );
  if (!live) return null;
  const { chain: inner, ...top } = live;
  return { ...top, ...(inner ?? {}) } as Chain;
}

export async function listApprovals(): Promise<Approval[]> {
  if (USE_FIXTURES) return fixtureApprovals as Approval[];
  // Cached + coalesced so every watching analyst shares one detector fetch (see lib/cache.ts).
  return cached("approvals", SNAPSHOT_TTL_MS, async () => {
    const live = await backend<{ approvals?: Approval[] } | Approval[]>("/api/approvals", fixtureApprovals as Approval[], []);
    return (Array.isArray(live) ? live : (live.approvals ?? [])) as Approval[];
  });
}

export async function listProposals(): Promise<Proposal[]> {
  if (USE_FIXTURES) return fixtureProposals as Proposal[];
  return cached("proposals", SNAPSHOT_TTL_MS, async () => {
    const live = await backend<{ proposals?: Proposal[] } | Proposal[]>("/api/soc/proposals", fixtureProposals as Proposal[], []);
    return (Array.isArray(live) ? live : (live.proposals ?? [])) as Proposal[];
  });
}

// Full chains for the live map. Fixtures carry the whole chain; against the backend we list summaries
// then hydrate the most recent few — an N+1 that is shared across all analysts by the snapshot cache,
// so the detector sees one list + hydrate per TTL window regardless of how many are watching.
export async function getRecentChains(): Promise<Chain[]> {
  if (USE_FIXTURES) return CHAINS;
  return cached("recent-chains", SNAPSHOT_TTL_MS, async () => {
    const summaries = await listChains();
    const full = await Promise.all(summaries.slice(0, 40).map((s) => getChain(s.chain_id)));
    return full.filter((c): c is Chain => c !== null);
  });
}

export const isFixtureMode = USE_FIXTURES;
export function lastBackendError(): string | null { return backendError; }
