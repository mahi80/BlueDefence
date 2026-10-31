import { NextResponse } from "next/server";
import { signSession, SESSION_COOKIE, SESSION_TTL, authMode, type Role } from "@/lib/auth";

// Demo-only local login. Disabled when AUTH_MODE=oidc (production rides the bank IdP).
export async function POST(req: Request) {
  if (authMode() !== "demo") {
    return NextResponse.json({ error: "Local login is off. Sign in with your organization." }, { status: 403 });
  }
  const { user, password } = await req.json().catch(() => ({ user: "", password: "" }));
  const U = process.env.AEGIS_DEMO_USER || "soc";
  const P = process.env.AEGIS_DEMO_PASSWORD || "demo";
  const role = (process.env.AEGIS_DEMO_ROLE as Role) || "bu_head";
  if (user === U && password === P) {
    const res = NextResponse.json({ ok: true, role });
    res.cookies.set(SESSION_COOKIE, signSession({ user: String(user), role }), {
      httpOnly: true,
      sameSite: "lax",
      path: "/",
      maxAge: SESSION_TTL,
      secure: process.env.NODE_ENV === "production",
    });
    return res;
  }
  return NextResponse.json({ error: "Wrong username or password." }, { status: 401 });
}
