// Cross-site request check for the console's state-changing routes (review round 3 G6-7: the decide routes had
// no Origin / CSRF check, so a page on another site could post an approval with the analyst's cookie).
// sameSite=lax already keeps the cookie off most cross-site POSTs; this is the explicit check behind it.

/** True when the request comes from this console: Origin (when the browser sends one) must be this host, and
 * Sec-Fetch-Site, when present, must not be cross-site. A request with neither (curl, server-side) passes —
 * it carries no ambient browser cookie to abuse. */
export function sameOrigin(headers: { get(name: string): string | null }): boolean {
  const site = (headers.get("sec-fetch-site") || "").toLowerCase();
  if (site && site !== "same-origin" && site !== "none") return false;
  const origin = headers.get("origin");
  if (!origin) return true;
  if (origin === "null") return false;
  const host = (headers.get("x-forwarded-host") || headers.get("host") || "").split(",")[0].trim().toLowerCase();
  try {
    return new URL(origin).host.toLowerCase() === host;
  } catch {
    return false;
  }
}
