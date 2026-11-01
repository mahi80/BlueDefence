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
  // the proxy (nginx) sets X-Real-IP to the connecting address; X-Forwarded-For is client-controlled, so the
  // counter is keyed on the account as well — a forged header must not reset the lockout
  const ip = req.headers.get("x-real-ip")?.trim() || "local";
  const keys = [`${ip}|${name.toLowerCase()}`, `*|${name.toLowerCase()}`];
  const until = Math.max(...keys.map((k) => lockedUntil(k) || 0));
  if (until) {
    const mins = Math.ceil((until - Date.now()) / 60000);
    return NextResponse.json({ error: `Too many failed sign-ins. Try again in ${mins} min.` }, { status: 429 });
  }
  let role: Role | null = null;
  const users = loadUsers();
  if (users) {
    const rec = validUsername(name) && Object.hasOwn(users.users, name) ? users.users[name] : undefined;
    if (rec && typeof rec.hash === "string" && !rec.disabled && verifyPassword(pw, rec.hash)) role = rec.role;
  } else if (process.env.AEGIS_DEMO_USER || process.env.AEGIS_DEMO_PASSWORD) {
    const U = process.env.AEGIS_DEMO_USER || "soc";
    const P = process.env.AEGIS_DEMO_PASSWORD || "demo";
    if (name === U && pw === P) role = (process.env.AEGIS_DEMO_ROLE as Role) || "bu_head";
  } else {
    return NextResponse.json({ error: "No accounts yet. Create one: npm run user -- add <name> <role>" }, { status: 503 });
  }
  if (!role) {
    keys.forEach(noteFailure);
    return NextResponse.json({ error: "Wrong username or password." }, { status: 401 });
  }
  keys.forEach(clearFailures);
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
