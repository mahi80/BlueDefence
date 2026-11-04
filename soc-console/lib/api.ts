import type { Chain, ChainSummary, Approval, Proposal } from "./types";
import { cached, SNAPSHOT_TTL_MS } from "./cache";
import { attachPending, mergeDetails, missingPendingAlerts, normalizeApproval } from "./hitl";
import fixtureChains from "../fixtures/chains.json";
import fixtureApprovals from "../fixtures/approvals.json";
import fixtureProposals from "../fixtures/proposals.json";

const API_ORIGIN = process.env.AEGIS_API_ORIGIN || "";
const USE_FIXTURES = !API_ORIGIN || process.env.NEXT_PUBLIC_AEGIS_USE_FIXTURES === "1";

const CHAINS = fixtureChains as unknown as Chain[];

/** A live backend read failed. Thrown, never turned into an empty list: an empty list used to be cached
 * for the snapshot window and shared by every analyst, and one shared module variable carried the error, so
 * a 500 from /api/approvals rendered as "live, 0 pending" (code review 2026-11-03 C3). */
export class BackendError extends Error {
  constructor(public path: string, public status: number | null, message: string) {
    super(message);
    this.name = "BackendError";
  }
}

async function backend<T>(path: string, fallback: T, opts: { notFound?: T } = {}): Promise<T> {
  if (USE_FIXTURES) return fallback;
  let res: Response;
  try {
    res = await fetch(`${API_ORIGIN}${path}`, {
      headers: process.env.AEGIS_API_KEY ? { Authorization: `Bearer ${process.env.AEGIS_API_KEY}` } : {},
      cache: "no-store",
    });
  } catch (e) {
    throw new BackendError(path, null, `${path} unreachable: ${(e as Error).message}`.slice(0, 160));
  }
  if (res.status === 404 && "notFound" in opts) return opts.notFound as T;
  if (!res.ok) throw new BackendError(path, res.status, `${path} -> ${res.status}`);
  return (await res.json()) as T;
}

export async function listChains(): Promise<ChainSummary[]> {
  const live = await backend<{ chains?: ChainSummary[] } | ChainSummary[]>("/api/soc/chains", CHAINS);
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
    { notFound: null },
  );
  if (!live) return null;
  const { chain: inner, ...top } = live;
  return { ...top, ...(inner ?? {}) } as Chain;
}

export async function listApprovals(): Promise<Approval[]> {
  if (USE_FIXTURES) return fixtureApprovals as Approval[];
  // Cached + coalesced so every watching analyst shares one detector fetch (see lib/cache.ts).
  return cached("approvals", SNAPSHOT_TTL_MS, async () => {
    const live = await backend<{ approvals?: unknown[] } | unknown[]>("/api/approvals", fixtureApprovals as Approval[]);
    const rows = Array.isArray(live) ? live : (live.approvals ?? []);
    // the ACP dashboard nests alert_id / action_type / target in an `args` JSON string (round 8 U8-4)
    return (Array.isArray(rows) ? rows : []).map(normalizeApproval).filter((a): a is Approval => a !== null);
  });
}

export async function listProposals(): Promise<Proposal[]> {
  if (USE_FIXTURES) return fixtureProposals as Proposal[];
  return cached("proposals", SNAPSHOT_TTL_MS, async () => {
    const live = await backend<{ proposals?: Proposal[] } | Proposal[]>("/api/soc/proposals", fixtureProposals as Proposal[]);
    return (Array.isArray(live) ? live : (live.proposals ?? [])) as Proposal[];
  });
}

// Full chains for the live map. Fixtures carry the whole chain; against the backend we list summaries
// then hydrate the most recent few — an N+1 that is shared across all analysts by the snapshot cache,
// so the detector sees one list + hydrate per TTL window regardless of how many are watching.
// Chains that carry a pending approval card are hydrated too, however old: a card on an incident that fell out
// of the newest-40 window used to be undecidable from the console (round 7 U-2).
export async function getRecentChains(): Promise<Chain[]> {
  if (USE_FIXTURES) return CHAINS;
  return cached("recent-chains", SNAPSHOT_TTL_MS, async () => {
    const summaries = await listChains();
    const top = summaries.slice(0, 40);
    // one failed detail read used to reject the whole Promise.all and empty the map (review round 3 R3-12):
    // a detail that fails shows its summary, marked partial (U-4); only when every read fails is the backend down
    const res = await Promise.allSettled(top.map((s) => getChain(s.chain_id)));
    if (top.length && res.every((r) => r.status === "rejected")) {
      throw (res[0] as PromiseRejectedResult).reason;
    }
    const { chains } = mergeDetails(top, res);
    let approvals: Approval[] = [];
    try {
      approvals = await listApprovals();
    } catch {
      return chains;                                    // the approvals read reports its own error on the page
    }
    // a partial chain (its detail read failed or came back empty) does not count as loaded: its pending cards are
    // hydrated again or stubbed onto it, never left behind "details unavailable" with no actions (round 8 U8-3)
    const extra = missingPendingAlerts(approvals, new Set(chains.filter((c) => !c.partial).map((c) => c.alert_id)));
    const more = await Promise.allSettled(extra.map((id) => getChain(id)));
    return attachPending(chains, approvals, extra, more);   // the cards stay decidable
  });
}

export const isFixtureMode = USE_FIXTURES;

export { settle } from "./settle";
