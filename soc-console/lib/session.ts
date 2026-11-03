// Is a signed session still backed by an account? Pure, so it can be tested without Next's cookie store.
import type { Role, Session } from "./auth";

export interface SessionClaims extends Session {
  mode?: string;
  epoch?: string;
}

/** Local mode, re-checked on every request.
 *
 * - users file ok: the account must exist and be enabled; its current role wins.
 * - no users file: only the demo account's own session is valid.
 * - users file unreadable: nobody. It used to accept every signed cookie with the role baked into it, so a
 *   disabled or demoted analyst kept their old role for up to 8 h while the file was corrupt or being restored
 *   (review round 4 D4-16). */
export function checkLocalSession(
  s: SessionClaims,
  state: "missing" | "ok" | "unreadable",
  users: { users: Record<string, { role: Role; disabled?: boolean }> } | null,
  demo: { user: string; role: Role } | null,
  validRole: (r: string) => boolean,
): Session | null {
  if (state === "unreadable") return null;
  if (state === "missing") {
    return demo && s.user === demo.user && s.role === demo.role ? { user: s.user, role: s.role } : null;
  }
  if (!users) return null;
  const rec = Object.hasOwn(users.users, s.user) ? users.users[s.user] : undefined;
  if (!rec || rec.disabled) return null;
  return { user: s.user, role: validRole(rec.role) ? rec.role : "analyst" };
}

/** A cookie minted under another auth mode, or before the session epoch was bumped, is void: switching to OIDC
 * used to leave every local-mode cookie valid, and logout revoked nothing (D4-16). `AEGIS_SESSION_EPOCH` — change
 * it to sign everyone out. */
export function claimsCurrent(c: SessionClaims, mode: string, epoch: string): boolean {
  return (c.mode ?? "local") === mode && (c.epoch ?? "") === epoch;
}
