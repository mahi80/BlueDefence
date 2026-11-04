import { NextResponse, type NextRequest } from "next/server";
import { authMode } from "@/lib/auth";
import { oidcCookie, verifyCallbackState } from "@/lib/oidc";

// Production SSO seam — completed at deployment against the bank's IdP.
//
// A secure completion must, in order:
//   0. verify `state` against the login cookie (done below) — and keep its nonce + PKCE verifier;
//   1. exchange `code` (with the PKCE `code_verifier`) at the IdP token endpoint (AEGIS_OIDC_TOKEN_URL) for an id_token;
//   2. VERIFY the id_token signature against the issuer JWKS and check iss/aud/exp/nonce —
//      do this with a vetted library (e.g. `openid-client` or `jose`), never by decoding
//      the token unverified;
//   3. read the groups claim and call mapGroupsToRole(groups) for the role;
//   4. set the session cookie with signSession({ user, role }).
//
// We intentionally do not ship an unverified token path: accepting an id_token without
// JWKS verification would let a forged token grant a role. This route stays a 501 until
// the deployment wires the verified flow, so no insecure default can reach production.
export async function GET(req: NextRequest) {
  if (authMode() !== "oidc") {
    return NextResponse.redirect(new URL("/login", process.env.AEGIS_CONSOLE_URL || "http://localhost:3000"));
  }
  // login CSRF / code injection guard (round 7 U-5): the state must match this browser's login transaction
  // the cookie is HMAC-signed by /start; an unsigned or foreign-signed one is refused (U8-5)
  const c = oidcCookie();
  const tx = verifyCallbackState(req.cookies.get(c.name)?.value, req.nextUrl.searchParams.get("state"));
  if (!tx) {
    const bad = NextResponse.json({ error: "login state mismatch or expired — start the sign-in again" }, { status: 400 });
    bad.cookies.delete({ name: c.name, path: c.path, secure: c.secure });
    return bad;
  }
  // tx.verifier → the token request's code_verifier; tx.nonce → must equal the verified id_token's nonce (nonceMatches)
  const res = NextResponse.json(
    { error: "OIDC callback is wired at deployment with verified id_token handling (see docs/deploy/onprem-bank.md)." },
    { status: 501 },
  );
  res.cookies.delete({ name: c.name, path: c.path, secure: c.secure });   // one-shot: a state is never reused
  return res;
}
