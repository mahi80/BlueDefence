import type { Chain, ChainSummary, Approval, Proposal } from "./types";
import fixtureChains from "../fixtures/chains.json";
import fixtureApprovals from "../fixtures/approvals.json";
import fixtureProposals from "../fixtures/proposals.json";

const API_ORIGIN = process.env.AEGIS_API_ORIGIN || "";
const USE_FIXTURES = !API_ORIGIN || process.env.NEXT_PUBLIC_AEGIS_USE_FIXTURES === "1";

const CHAINS = fixtureChains as unknown as Chain[];

async function backend<T>(path: string, fallback: T): Promise<T> {
  if (USE_FIXTURES) return fallback;
  try {
    const res = await fetch(`${API_ORIGIN}${path}`, {
      headers: process.env.AEGIS_API_KEY ? { Authorization: `Bearer ${process.env.AEGIS_API_KEY}` } : {},
      cache: "no-store",
    });
    if (!res.ok) throw new Error(`${path} -> ${res.status}`);
    return (await res.json()) as T;
  } catch {
    // The console degrades to fixtures rather than erroring the whole page.
    return fallback;
  }
}

export async function listChains(): Promise<ChainSummary[]> {
  const live = await backend<{ chains?: ChainSummary[] } | ChainSummary[]>("/api/soc/chains", CHAINS);
  const rows = Array.isArray(live) ? live : (live.chains ?? CHAINS);
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
  );
  if (!live) return null;
  const { chain: inner, ...top } = live;
  return { ...top, ...(inner ?? {}) } as Chain;
}

export async function listApprovals(): Promise<Approval[]> {
  const live = await backend<{ approvals?: Approval[] } | Approval[]>("/api/approvals", fixtureApprovals as Approval[]);
  return (Array.isArray(live) ? live : (live.approvals ?? [])) as Approval[];
}

export async function listProposals(): Promise<Proposal[]> {
  const live = await backend<{ proposals?: Proposal[] } | Proposal[]>("/api/soc/proposals", fixtureProposals as Proposal[]);
  return (Array.isArray(live) ? live : (live.proposals ?? [])) as Proposal[];
}

// Full chains for the live map. Fixtures carry the whole chain; against the
// backend we list summaries then hydrate the most recent few.
export async function getRecentChains(): Promise<Chain[]> {
  if (USE_FIXTURES) return CHAINS;
  const summaries = await listChains();
  const full = await Promise.all(summaries.slice(0, 40).map((s) => getChain(s.chain_id)));
  return full.filter((c): c is Chain => c !== null);
}

export const isFixtureMode = USE_FIXTURES;
