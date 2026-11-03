// Round-3 review G6-7: console sign-in and decision hardening.
import { test } from "node:test";
import assert from "node:assert/strict";
import { sameOrigin } from "../lib/origin.ts";
import { ACCOUNT_MAX_FAILS, demoAccount, lockedUntil, noteFailure, verifyOrBurn, hashPassword } from "../lib/users.ts";

const h = (o: Record<string, string>) => ({ get: (n: string) => o[n.toLowerCase()] ?? null });

test("cross-site posts are refused, same-site and non-browser ones pass", () => {
  assert.equal(sameOrigin(h({ host: "soc.bank.in", origin: "https://soc.bank.in" })), true);
  assert.equal(sameOrigin(h({ host: "soc.bank.in", origin: "https://evil.example" })), false);
  assert.equal(sameOrigin(h({ host: "soc.bank.in", "sec-fetch-site": "cross-site" })), false);
  assert.equal(sameOrigin(h({ host: "soc.bank.in", origin: "null" })), false);
  assert.equal(sameOrigin(h({ host: "soc.bank.in" })), true);
});

test("the demo account needs both a name and a password", () => {
  const keep = { ...process.env };
  try {
    process.env.AEGIS_DEMO_USER = "soc";
    delete process.env.AEGIS_DEMO_PASSWORD;
    assert.equal(demoAccount(), null);
    process.env.AEGIS_DEMO_PASSWORD = "a-long-pass";
    assert.equal(demoAccount()?.password, "a-long-pass");
  } finally {
    process.env = keep;
  }
});

test("an unknown account costs an scrypt run too", () => {
  const t0 = performance.now();
  assert.equal(verifyOrBurn("x", hashPassword("y")), false);
  const known = performance.now() - t0;
  const t1 = performance.now();
  assert.equal(verifyOrBurn("x", undefined), false);
  verifyOrBurn("x", undefined);
  const unknown = (performance.now() - t1) / 2;
  assert.ok(unknown > known / 4, `unknown ${unknown}ms vs known ${known}ms`);
});

test("account-wide failures lock only at the higher threshold", () => {
  for (let i = 0; i < 10; i++) noteFailure("*|analyst-x", ACCOUNT_MAX_FAILS);
  assert.equal(lockedUntil("*|analyst-x"), 0);
  for (let i = 0; i < ACCOUNT_MAX_FAILS; i++) noteFailure("*|analyst-x", ACCOUNT_MAX_FAILS);
  assert.ok(lockedUntil("*|analyst-x") > 0);
});
