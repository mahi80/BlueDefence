import { NextResponse } from "next/server";
import { signSession, SESSION_COOKIE, SESSION_TTL, authMode, type Role } from "@/lib/auth";
import { loadUsers, verifyPassword, lockedUntil, noteFailure, clearFailures, validUsername } from "@/lib/users";

// Local sign-in. Off when AEGIS_AUTH_MODE=oidc (production rides the bank IdP).
// Accounts come from the users file (scrypt hashes, per-user role); with no file,
// AEGIS_DEMO_USER / AEGIS_DEMO_PASSWORD / AEGIS_DEMO_ROLE keep the single demo account.
export async function POST(req: Request) {
  if (authMode() !== "local") {
    return NextResponse.json({ error: "Local sign-in is off. Sign in with your organization." }, { status: 403 });
  }
  const { user, password } = await req.json().catch(() => ({ user: "", password: "" }));
  const name = String(user || "").trim();
  const pw = String(password || "");
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0].trim() || "local";
  const key = `${ip}|${name.toLowerCase()}`;
  const until = lockedUntil(key);
  if (until) {
    const mins = Math.ceil((until - Date.now()) / 60000);
    return NextResponse.json({ error: `Too many failed sign-ins. Try again in ${mins} min.` }, { status: 429 });
  }
  let role: Role | null = null;
  const users = loadUsers();
  if (users) {
    const rec = validUsername(name) ? users.users[name] : undefined;
    if (rec && !rec.disabled && verifyPassword(pw, rec.hash)) role = rec.role;
  } else if (process.env.AEGIS_DEMO_USER || process.env.AEGIS_DEMO_PASSWORD) {
    const U = process.env.AEGIS_DEMO_USER || "soc";
    const P = process.env.AEGIS_DEMO_PASSWORD || "demo";
    if (name === U && pw === P) role = (process.env.AEGIS_DEMO_ROLE as Role) || "bu_head";
  } else {
    return NextResponse.json({ error: "No accounts yet. Create one: npm run user -- add <name> <role>" }, { status: 503 });
  }
  if (!role) {
    noteFailure(key);
    return NextResponse.json({ error: "Wrong username or password." }, { status: 401 });
  }
  clearFailures(key);
  const res = NextResponse.json({ ok: true, role });
  res.cookies.set(SESSION_COOKIE, signSession({ user: name, role }), {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    maxAge: SESSION_TTL,
    secure: process.env.NODE_ENV === "production",
  });
  return res;
}
