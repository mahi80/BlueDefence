// Shared server-side snapshot cache.
//
// The console is read by many analysts at once, and each render of the live view pulls the whole SOC
// state (getRecentChains alone is an N+1: one list + up to 40 detail fetches). Without coalescing,
// 100 analysts polling every few seconds multiply into ~1000 backend requests/second for identical
// data. This memoizes each read for a short TTL and shares the in-flight promise, so the detector
// sees ONE fetch per key per window no matter how many analysts are watching — backend load becomes
// O(1) in the number of analysts instead of O(analysts × fan-out).
//
// Module scope lives for the life of the Node server process (one per instance), which is exactly the
// sharing boundary we want. TTL is deliberately short (default 1.5s) so the view stays live.

type Entry<T> = { at: number; val: Promise<T> };

const store = new Map<string, Entry<unknown>>();

export const SNAPSHOT_TTL_MS = Number(process.env.AEGIS_SNAPSHOT_TTL_MS) || 1500;

/** Run `fn` at most once per `ttlMs` per `key`, sharing the in-flight promise with every concurrent
 * caller. A rejected fetch is evicted so the next caller retries rather than caching the failure. */
export function cached<T>(key: string, ttlMs: number, fn: () => Promise<T>): Promise<T> {
  const now = Date.now();
  const hit = store.get(key) as Entry<T> | undefined;
  if (hit && now - hit.at < ttlMs) return hit.val;
  const val = fn().catch((e) => {
    // only evict if this entry is still the one we stored (a newer call may have replaced it)
    if (store.get(key)?.val === val) store.delete(key);
    throw e;
  });
  store.set(key, { at: now, val });
  return val;
}
