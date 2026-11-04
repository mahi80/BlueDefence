// OIDC login transaction state (round 7 U-5). `start` used to send a random `state` it never stored, and no nonce or
// PKCE, so a callback wired "as documented" could not verify any of them (login CSRF / code injection). The values
// now live in a short-lived httpOnly cookie that only this browser holds, and the callback checks them.
//
// The cookie is HMAC-signed with the console secret and verified in constant time (round 8 U8-5): unsigned, a
// cookie planted by a sibling subdomain (or any script that can set cookies for the parent domain) with the
// attacker's own state/verifier passed the check — login CSRF straight past the state guard. Over HTTPS the
// cookie is also `__Host-` prefixed (Secure, Path=/, no Domain), so a sibling host cannot set it at all.
import crypto from "node:crypto";
import { consoleSecret } from "./secret.ts";

export const OIDC_COOKIE = "aegis_oidc_tx";
export const OIDC_COOKIE_HOST = "__Host-aegis_oidc_tx";
export const OIDC_TX_MAX_AGE_S = 600;

/** Name, path and Secure flag for the login-transaction cookie. `__Host-` needs Secure + Path=/ + no Domain, so
 * it is used whenever the cookie is Secure (production); plain-HTTP dev keeps the unprefixed, path-scoped name
 * (browsers drop a `__Host-` cookie that is not Secure). */
export function oidcCookie(secure: boolean = process.env.NODE_ENV === "production"): { name: string; path: string; secure: boolean } {
  return secure ? { name: OIDC_COOKIE_HOST, path: "/", secure: true } : { name: OIDC_COOKIE, path: "/api/auth/oidc", secure: false };
}

export interface OidcTx { state: string; nonce: string; verifier: string; issuedAt: number }

const b64url = (b: Buffer) => b.toString("base64url");

export function newOidcTx(now = Date.now()): OidcTx & { challenge: string } {
  const state = b64url(crypto.randomBytes(24));
  const nonce = b64url(crypto.randomBytes(24));
  const verifier = b64url(crypto.randomBytes(48));          // RFC 7636: 43–128 chars
  const challenge = b64url(crypto.createHash("sha256").update(verifier).digest());
  return { state, nonce, verifier, challenge, issuedAt: Math.floor(now / 1000) };
}

const mac = (body: string, secret: string) =>
  crypto.createHmac("sha256", secret).update(`aegis-oidc-tx.${body}`).digest("base64url");   // domain-separated from the session MAC

export function encodeTx(tx: OidcTx, secret: string = consoleSecret()): string {
  const body = b64url(Buffer.from(JSON.stringify({ s: tx.state, n: tx.nonce, v: tx.verifier, t: tx.issuedAt })));
  return `${body}.${mac(body, secret)}`;
}

function decodeTx(raw: string | undefined | null, secret: string): OidcTx | null {
  if (!raw || typeof raw !== "string") return null;
  const dot = raw.indexOf(".");
  if (dot <= 0) return null;                                   // unsigned (or legacy) cookie: refused
  const body = raw.slice(0, dot);
  if (!sameString(raw.slice(dot + 1), mac(body, secret))) return null;
  try {
    const j = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    if (typeof j?.s !== "string" || typeof j?.n !== "string" || typeof j?.v !== "string" || typeof j?.t !== "number") return null;
    return { state: j.s, nonce: j.n, verifier: j.v, issuedAt: j.t };
  } catch {
    return null;
  }
}

function sameString(a: string, b: string): boolean {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

/** The callback's check: the `state` the IdP sent back must equal the one in this browser's cookie, and the
 * cookie must be fresh. Returns the nonce (to compare with the id_token's `nonce` claim) and the PKCE verifier
 * (for the token request), or null — reject the login. */
export function verifyCallbackState(cookie: string | undefined | null, returnedState: string | null,
                                    now = Date.now(), secret: string = consoleSecret()): { nonce: string; verifier: string } | null {
  const tx = decodeTx(cookie, secret);
  if (!tx || !returnedState) return null;
  const age = Math.floor(now / 1000) - tx.issuedAt;
  if (age < 0 || age > OIDC_TX_MAX_AGE_S) return null;
  if (!sameString(tx.state, returnedState)) return null;
  return { nonce: tx.nonce, verifier: tx.verifier };
}

/** The id_token's nonce must equal the one this login started with. */
export function nonceMatches(expected: string, idTokenNonce: unknown): boolean {
  return typeof idTokenNonce === "string" && sameString(expected, idTokenNonce);
}
