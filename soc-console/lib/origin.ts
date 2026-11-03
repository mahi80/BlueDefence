// Cross-site request check for the console's state-changing routes (review round 3 G6-7: the decide routes had
// no Origin / CSRF check, so a page on another site could post an approval with the analyst's cookie).
// sameSite=lax already keeps the cookie off most cross-site POSTs; this is the explicit check behind it.

/** Origins configured as this console (`AEGIS_CONSOLE_ORIGIN`, comma-separated, e.g. `https://soc.bank.in`). */
function configuredOrigins(): string[] {
  return (process.env.AEGIS_CONSOLE_ORIGIN || "")
    .split(",")
    .map((o) => o.trim().replace(/\/+$/, "").toLowerCase())
    .filter(Boolean);
}

/** True when the request comes from this console.
 *
 * - `Sec-Fetch-Site` is set by the browser and cannot be set by a page: `same-origin` (or `none`, typed by the
 *   user) passes, anything else is refused.
 * - Otherwise the `Origin`, when the browser sends one, must be one of `AEGIS_CONSOLE_ORIGIN`, or — when that is
 *   unset — this host (`X-Forwarded-Host`, else `Host`). A reverse proxy that rewrites `Host` and sets no
 *   `X-Forwarded-Host` used to refuse every analyst's POST (review round 4 X4-8): set `AEGIS_CONSOLE_ORIGIN`.
 * - A request with neither header (curl, server-side) passes: it carries no ambient browser cookie to abuse. */
export function sameOrigin(headers: { get(name: string): string | null }): boolean {
  const site = (headers.get("sec-fetch-site") || "").toLowerCase();
  if (site && site !== "same-origin" && site !== "none") return false;
  const origin = headers.get("origin");
  if (!origin) return true;
  if (origin === "null") return false;
  let o: URL;
  try {
    o = new URL(origin);
  } catch {
    return false;
  }
  const allowed = configuredOrigins();
  if (allowed.length) return allowed.includes(o.origin.toLowerCase());
  if (site === "same-origin") return true;
  const host = (headers.get("x-forwarded-host") || headers.get("host") || "").split(",")[0].trim().toLowerCase();
  return o.host.toLowerCase() === host;
}

/** Where `/api/ask` may forward a question, and with which key. Never the console's own backend key: that is the
 * decision-capable `AEGIS_CONSOLE_TOKEN`, and whoever holds it can post approvals under any analyst's name
 * (review round 4 D4-7). `AEGIS_ASK_KEY` is its own credential; the URL must be https (loopback http is allowed
 * for a co-located Q). Returns null when forwarding is off or not safe. */
export function askUpstream(env: Record<string, string | undefined> = process.env):
    { url: string; headers: Record<string, string> } | null {
  const raw = (env.AEGIS_ASK_URL || "").trim();
  if (!raw) return null;
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname.toLowerCase());
  if (u.protocol !== "https:" && !(u.protocol === "http:" && loopback)) return null;
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const key = (env.AEGIS_ASK_KEY || "").trim();
  if (key) {
    if (key === (env.AEGIS_API_KEY || "").trim()) return null;   // same secret under another name: refuse
    headers["X-API-Key"] = key;
  }
  return { url: u.toString(), headers };
}
