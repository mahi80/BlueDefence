import { NextResponse } from "next/server";
import { authMode } from "@/lib/auth";

// Production SSO seam — completed at deployment against the bank's IdP.
//
// A secure completion must, in order:
//   1. exchange `code` at the IdP token endpoint (AEGIS_OIDC_TOKEN_URL) for an id_token;
//   2. VERIFY the id_token signature against the issuer JWKS and check iss/aud/exp/nonce —
//      do this with a vetted library (e.g. `openid-client` or `jose`), never by decoding
//      the token unverified;
//   3. read the groups claim and call mapGroupsToRole(groups) for the role;
//   4. set the session cookie with signSession({ user, role }).
//
// We intentionally do not ship an unverified token path: accepting an id_token without
// JWKS verification would let a forged token grant a role. This route stays a 501 until
// the deployment wires the verified flow, so no insecure default can reach production.
export async function GET() {
  if (authMode() !== "oidc") {
    return NextResponse.redirect(new URL("/login", process.env.AEGIS_CONSOLE_URL || "http://localhost:3000"));
  }
  return NextResponse.json(
    { error: "OIDC callback is wired at deployment with verified id_token handling (see docs/deploy/onprem-bank.md)." },
    { status: 501 },
  );
}
