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
// A missing file with BOTH AEGIS_DEMO_USER and AEGIS_DEMO_PASSWORD set keeps the single demo account working.

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

/** "missing" (no file: first run), "ok", or "unreadable" (exists but cannot be read or parsed). A corrupt users
 * file used to look like "no file" and fell back to the demo account (review round 3 G6-7). */
export function usersFileState(): "missing" | "ok" | "unreadable" {
  if (!fs.existsSync(usersPath())) return "missing";
  return loadUsers() ? "ok" : "unreadable";
}

/** The demo account only when BOTH its name and its password are set: AEGIS_DEMO_USER alone used to mean
 * password "demo" (review round 3 G6-7). */
export function demoAccount(): { user: string; password: string; role: Role } | null {
  const user = process.env.AEGIS_DEMO_USER || "";
  const password = process.env.AEGIS_DEMO_PASSWORD || "";
  if (!user || !password) return null;
  const role = validRole(process.env.AEGIS_DEMO_ROLE || "") ? (process.env.AEGIS_DEMO_ROLE as Role) : "bu_head";
  return { user, password, role };
}

// Verifying an unknown account cost nothing while a real one cost an scrypt run, so response time told which
// names exist (review round 3 G6-7). An unknown name is checked against this throwaway hash instead.
let DUMMY_HASH = "";
export function verifyOrBurn(password: string, hash: string | undefined): boolean {
  if (typeof hash === "string" && hash) return verifyPassword(password, hash);
  if (!DUMMY_HASH) DUMMY_HASH = hashPassword(crypto.randomBytes(12).toString("hex"));
  verifyPassword(password, DUMMY_HASH);
  return false;
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

/** Account-wide failures (from any address) lock only at this higher count: at MAX_FAILS anyone could lock any
 * analyst out with five wrong guesses (review round 3 G6-7). Per-address failures still lock at MAX_FAILS. */
export const ACCOUNT_MAX_FAILS = 50;

export function noteFailure(key: string, max: number = MAX_FAILS): void {
  const now = Date.now();
  const f = fails.get(key);
  if (!f || now - f.first > WINDOW_MS) {
    if (!f) makeRoom(now);
    fails.set(key, { n: 1, first: now, until: max <= 1 ? now + LOCK_MS : 0 });
    return;
  }
  f.n += 1;
  if (f.n >= max) f.until = now + LOCK_MS;
}

export function clearFailures(key: string): void {
  fails.delete(key);
}
