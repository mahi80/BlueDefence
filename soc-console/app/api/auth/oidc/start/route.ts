import { NextResponse } from "next/server";
import crypto from "node:crypto";
import { authMode } from "@/lib/auth";

// Production SSO seam. Redirects to the bank IdP's authorize endpoint (from OIDC
// discovery, provided as AEGIS_OIDC_AUTHORIZE_URL at deployment). The callback
// completes the code exchange + id_token verification.
export async function GET() {
  if (authMode() !== "oidc") {
    return NextResponse.redirect(new URL("/login", process.env.AEGIS_CONSOLE_URL || "http://localhost:3000"));
  }
  const authorize = process.env.AEGIS_OIDC_AUTHORIZE_URL;
  const clientId = process.env.AEGIS_OIDC_CLIENT_ID;
  const redirectUri = process.env.AEGIS_OIDC_REDIRECT_URI;
  if (!authorize || !clientId || !redirectUri) {
    return NextResponse.json(
      { error: "OIDC not configured. Set AEGIS_OIDC_AUTHORIZE_URL, AEGIS_OIDC_CLIENT_ID, AEGIS_OIDC_REDIRECT_URI." },
      { status: 501 },
    );
  }
  const url = new URL(authorize);
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("scope", process.env.AEGIS_OIDC_SCOPE || "openid profile email groups");
  url.searchParams.set("state", crypto.randomBytes(16).toString("hex"));
  return NextResponse.redirect(url);
}
