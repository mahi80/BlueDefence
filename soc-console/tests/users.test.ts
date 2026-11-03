// Unit tests for the console's local accounts and sign-in lockout (code review 2026-11-03 T10).
// Run with `npm test` (node:test with type stripping; no extra dependencies).
import { test, mock } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  clearFailures, hashPassword, loadUsers, lockedUntil, noteFailure, saveUsers, validRole, validUsername, verifyPassword,
} from "../lib/users.ts";

test("password hash round-trips and rejects the wrong password or a malformed hash", () => {
  const h = hashPassword("correct horse battery");
  assert.match(h, /^scrypt\$[\w-]+\$[\w-]+$/);
  assert.equal(verifyPassword("correct horse battery", h), true);
  assert.equal(verifyPassword("correct horse batterY", h), false);
  assert.equal(verifyPassword("x", "plain$abc$def"), false);
  assert.equal(verifyPassword("x", "scrypt$$"), false);
  assert.notEqual(hashPassword("same"), hashPassword("same"));          // per-user salt
});

test("usernames and roles are validated", () => {
  for (const ok of ["r.verma", "ciso@bank.in", "a1"]) assert.equal(validUsername(ok), true, ok);
  for (const bad of ["", "a", ".hidden", "has space", "x".repeat(65), "../etc"]) assert.equal(validUsername(bad), false, bad);
  assert.equal(validRole("ciso"), true);
  assert.equal(validRole("root"), false);
});

test("users file is written atomically, private, and read back", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-users-"));
  process.env.AEGIS_CONSOLE_USERS = path.join(dir, "users.json");
  try {
    assert.equal(loadUsers(), null);
    saveUsers({ users: { "r.verma": { role: "ciso", hash: hashPassword("pw-123456") } } } as never);
    assert.equal(loadUsers()?.users["r.verma"].role, "ciso");
    assert.equal(fs.statSync(process.env.AEGIS_CONSOLE_USERS).mode & 0o077, 0);
    assert.deepEqual(fs.readdirSync(dir), ["users.json"]);                // no temp file left behind
    fs.writeFileSync(process.env.AEGIS_CONSOLE_USERS, "{not json");
    assert.equal(loadUsers(), null);
  } finally {
    delete process.env.AEGIS_CONSOLE_USERS;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("five failures lock the key for 15 minutes; clearing unlocks it", () => {
  mock.timers.enable({ apis: ["Date"], now: 1_000_000 });
  try {
    for (let i = 0; i < 4; i++) noteFailure("victim");
    assert.equal(lockedUntil("victim"), 0);
    noteFailure("victim");
    assert.equal(lockedUntil("victim"), 1_000_000 + 15 * 60 * 1000);
    mock.timers.tick(15 * 60 * 1000 + 1);
    assert.equal(lockedUntil("victim"), 0);
    for (let i = 0; i < 5; i++) noteFailure("v2");
    clearFailures("v2");
    assert.equal(lockedUntil("v2"), 0);
  } finally {
    mock.timers.reset();
  }
});

test("flooding new usernames cannot unlock a locked account", () => {
  mock.timers.enable({ apis: ["Date"], now: 5_000_000 });
  try {
    for (let i = 0; i < 5; i++) noteFailure("locked-admin");
    const until = lockedUntil("locked-admin");
    assert.ok(until > Date.now());
    for (let i = 0; i < 12_000; i++) noteFailure(`spray-${i}`);         // past the 10k cap
    assert.equal(lockedUntil("locked-admin"), until);
  } finally {
    mock.timers.reset();
  }
});
