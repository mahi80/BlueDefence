import { NextResponse } from "next/server";
import { signSession, SESSION_COOKIE, SESSION_TTL, authMode, type Role } from "@/lib/auth";
import { loadUsers, verifyOrBurn, lockedUntil, noteFailure, clearFailures, validUsername, usersFileState, demoAccount, ACCOUNT_MAX_FAILS } from "@/lib/users";
import { sameOrigin } from "@/lib/origin";

// Local sign-in. Off when AEGIS_AUTH_MODE=oidc (production rides the bank IdP).
// Accounts come from the users file (scrypt hashes, per-user role); with no file,
// AEGIS_DEMO_USER + AEGIS_DEMO_PASSWORD (both required) / AEGIS_DEMO_ROLE keep the single demo account.
export async function POST(req: Request) {
  if (!sameOrigin(req.headers)) return NextResponse.json({ error: "cross-site request refused" }, { status: 403 });
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
  const demo = demoAccount();
  if (users) {
    const rec = validUsername(name) && Object.hasOwn(users.users, name) ? users.users[name] : undefined;
    const usable = rec && typeof rec.hash === "string" && !rec.disabled ? rec.hash : undefined;
    if (verifyOrBurn(pw, usable) && rec) role = rec.role;     // same cost whether or not the name exists
  } else if (usersFileState() === "unreadable") {
    // a corrupt users file must not fall back to the demo account (review round 3 G6-7)
    return NextResponse.json({ error: "The accounts file cannot be read. Restore it or recreate the accounts." }, { status: 503 });
  } else if (demo) {
    if (name === demo.user && pw === demo.password) role = demo.role;
  } else {
    return NextResponse.json({ error: "No accounts yet. Create one: npm run user -- add <name> <role>" }, { status: 503 });
  }
  if (!role) {
    noteFailure(keys[0]);                       // this address + account: locks at 5
    noteFailure(keys[1], ACCOUNT_MAX_FAILS);    // the account from anywhere: only a sustained attack locks it
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
