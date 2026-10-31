import { cookies } from "next/headers";
import crypto from "node:crypto";

// Roles mirror the dashboard's model. The BACKEND is the enforcement point for
// every high-impact action (isolate/block/revoke, model promotion) and audits
// each decision with who + role + rationale; the console reflects permissions.
export type Role = "admin" | "cio" | "ciso" | "bu_head" | "analyst";
export interface Session {
  user: string;
  role: Role;
}

export const SESSION_COOKIE = "aegis_session";
export const SESSION_TTL = 60 * 60 * 8; // 8h
const SECRET = process.env.AEGIS_CONSOLE_SECRET || "dev-insecure-change-me";
const ROLES: Role[] = ["admin", "cio", "ciso", "bu_head", "analyst"];

export function authMode(): "demo" | "oidc" {
  return process.env.AEGIS_AUTH_MODE === "oidc" ? "oidc" : "demo";
}

// Only these roles may approve a containment action or promote a model.
export function canDecide(role: Role): boolean {
  return role === "admin" || role === "cio" || role === "ciso" || role === "bu_head";
}

export function signSession(s: Session): string {
  const payload = JSON.stringify({ u: s.user, r: s.role, exp: Math.floor(Date.now() / 1000) + SESSION_TTL });
  const body = Buffer.from(payload).toString("base64url");
  const sig = crypto.createHmac("sha256", SECRET).update(body).digest("base64url");
  return `${body}.${sig}`;
}

function verify(token: string): Session | null {
  const dot = token.indexOf(".");
  if (dot < 0) return null;
  const body = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const expect = crypto.createHmac("sha256", SECRET).update(body).digest("base64url");
  const a = Buffer.from(sig);
  const b = Buffer.from(expect);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    if (typeof p.exp !== "number" || p.exp < Math.floor(Date.now() / 1000)) return null;
    const role = ROLES.includes(p.r) ? (p.r as Role) : "analyst";
    return { user: String(p.u || "user"), role };
  } catch {
    return null;
  }
}

export async function getSession(): Promise<Session | null> {
  const c = (await cookies()).get(SESSION_COOKIE);
  return c ? verify(c.value) : null;
}

// OIDC group → role mapping for production SSO (Entra ID / SAML groups).
// AEGIS_OIDC_ROLE_MAP = "group-admins:admin,soc-leads:bu_head,soc-analysts:analyst".
// The most-privileged matching role wins; default analyst.
export function mapGroupsToRole(groups: string[]): Role {
  const map = new Map<string, Role>();
  for (const pair of (process.env.AEGIS_OIDC_ROLE_MAP || "").split(",")) {
    const [g, r] = pair.split(":").map((x) => x.trim());
    if (g && ROLES.includes(r as Role)) map.set(g, r as Role);
  }
  let best: Role = "analyst";
  for (const g of groups) {
    const r = map.get(g);
    if (r && ROLES.indexOf(r) < ROLES.indexOf(best)) best = r;
  }
  return best;
}
