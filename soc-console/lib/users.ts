import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import type { Role } from "./auth";

// Local accounts for the console ("local" auth mode). Production rides the bank's IdP
// (AEGIS_AUTH_MODE=oidc); this is for pilots, labs and the first weeks before SSO is wired.
//
// AEGIS_CONSOLE_USERS points at a JSON file:
//   { "users": { "r.verma": { "role": "ciso", "hash": "scrypt$<salt>$<key>" }, ... } }
// written by `npm run user -- add <name> <role>` (prompts for the password, never logs it).
// Passwords are scrypt-hashed (N=2^15) with a per-user salt; comparison is constant-time.
// A missing file with AEGIS_DEMO_USER/PASSWORD set keeps the old single demo account working.

export interface UserRecord {
  role: Role;
  hash: string;
  disabled?: boolean;
}
export interface UsersFile {
  users: Record<string, UserRecord>;
}

const ROLES: Role[] = ["admin", "cio", "ciso", "bu_head", "analyst"];
const N = 1 << 15, r = 8, p = 1, KEYLEN = 32;

export function usersPath(): string {
  return process.env.AEGIS_CONSOLE_USERS || path.join(process.cwd(), ".aegis-console-users.json");
}

export function loadUsers(): UsersFile | null {
  try {
    const raw = fs.readFileSync(usersPath(), "utf8");
    const j = JSON.parse(raw);
    if (!j || typeof j !== "object" || typeof j.users !== "object") return null;
    return j as UsersFile;
  } catch {
    return null;
  }
}

export function saveUsers(u: UsersFile): void {
  const file = usersPath();
  const tmp = `${file}.${process.pid}.${crypto.randomBytes(4).toString("hex")}.tmp`;   // two concurrent adds never share a temp file
  const fd = fs.openSync(tmp, "w", 0o600);
  try {
    fs.writeSync(fd, JSON.stringify(u, null, 2) + "\n");
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, file);
}

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(password, salt, KEYLEN, { N, r, p, maxmem: 64 * 1024 * 1024 });
  return `scrypt$${salt.toString("base64url")}$${key.toString("base64url")}`;
}

export function verifyPassword(password: string, hash: string): boolean {
  const [algo, saltB, keyB] = hash.split("$");
  if (algo !== "scrypt" || !saltB || !keyB) return false;
  const want = Buffer.from(keyB, "base64url");
  const got = crypto.scryptSync(password, Buffer.from(saltB, "base64url"), want.length, { N, r, p, maxmem: 64 * 1024 * 1024 });
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}

export function validRole(r: string): r is Role {
  return ROLES.includes(r as Role);
}

export function validUsername(u: string): boolean {
  return /^[a-z0-9][a-z0-9._@-]{1,63}$/i.test(u);
}

// ---- failed-attempt lockout (per process; the console is a single instance) ----
const WINDOW_MS = 15 * 60 * 1000, MAX_FAILS = 5, LOCK_MS = 15 * 60 * 1000;
// Keys are usernames/IPs an attacker chooses, so the map is capped: past MAX_KEYS, expired entries are
// swept, then the oldest entry that is not currently locked goes (flooding new names cannot unlock a victim).
const MAX_KEYS = 10_000;
const fails = new Map<string, { n: number; first: number; until: number }>();

function makeRoom(now: number): void {
  if (fails.size < MAX_KEYS) return;
  for (const [k, f] of fails) {
    if (f.until <= now && now - f.first > WINDOW_MS) fails.delete(k);
  }
  if (fails.size < MAX_KEYS) return;
  for (const [k, f] of fails) {
    if (f.until <= now) { fails.delete(k); return; }
  }
  const oldest = fails.keys().next();
  if (!oldest.done) fails.delete(oldest.value);
}

export function lockedUntil(key: string): number {
  const f = fails.get(key);
  if (!f) return 0;
  if (f.until && f.until > Date.now()) return f.until;
  if (Date.now() - f.first > WINDOW_MS) fails.delete(key);
  return 0;
}

export function noteFailure(key: string): void {
  const now = Date.now();
  const f = fails.get(key);
  if (!f || now - f.first > WINDOW_MS) {
    if (!f) makeRoom(now);
    fails.set(key, { n: 1, first: now, until: 0 });
    return;
  }
  f.n += 1;
  if (f.n >= MAX_FAILS) f.until = now + LOCK_MS;
}

export function clearFailures(key: string): void {
  fails.delete(key);
}
