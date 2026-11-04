// The console's signing secret (session cookie, OIDC login transaction). No Next.js imports, so the pure modules
// that sign with it stay testable under `node --test`.
// Resolved on first use, not at import: `next build` evaluates modules without the runtime env.
export function consoleSecret(): string {
  const v = process.env.AEGIS_CONSOLE_SECRET;
  if (v && v.length >= 16) return v;
  if (process.env.NODE_ENV === "production") {
    // a known default would let anyone who has read the repo forge an admin cookie
    throw new Error("AEGIS_CONSOLE_SECRET must be set (16+ chars) in production");
  }
  return "dev-insecure-change-me";
}
