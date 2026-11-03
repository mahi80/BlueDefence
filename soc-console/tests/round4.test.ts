// Round-4 review: console session and upstream hardening (D4-7, D4-16, X4-8).
import { test } from "node:test";
import assert from "node:assert/strict";
import { askUpstream, sameOrigin } from "../lib/origin.ts";
import { checkLocalSession, claimsCurrent } from "../lib/session.ts";

const h = (o: Record<string, string>) => ({ get: (n: string) => o[n.toLowerCase()] ?? null });
const valid = (r: string) => ["admin", "cio", "ciso", "bu_head", "analyst"].includes(r);

test("Q never receives the console's decision key", () => {
  assert.equal(askUpstream({ AEGIS_ASK_URL: "https://q.bank.in/ask", AEGIS_API_KEY: "console-tok" })?.headers["X-API-Key"], undefined);
  assert.equal(askUpstream({ AEGIS_ASK_URL: "https://q.bank.in/ask", AEGIS_ASK_KEY: "q-key" })?.headers["X-API-Key"], "q-key");
  assert.equal(askUpstream({ AEGIS_ASK_URL: "https://q.bank.in/ask", AEGIS_ASK_KEY: "same", AEGIS_API_KEY: "same" }), null);
  assert.equal(askUpstream({ AEGIS_ASK_URL: "http://q.bank.in/ask", AEGIS_ASK_KEY: "q-key" }), null);   // no https
  assert.ok(askUpstream({ AEGIS_ASK_URL: "http://127.0.0.1:8000/ask" }));
  assert.equal(askUpstream({}), null);
});

test("an unreadable users file signs nobody in; no file accepts only the demo session", () => {
  const s = { user: "alice", role: "ciso" as const };
  assert.equal(checkLocalSession(s, "unreadable", null, null, valid), null);
  assert.equal(checkLocalSession(s, "missing", null, { user: "soc", role: "bu_head" }, valid), null);
  assert.deepEqual(checkLocalSession({ user: "soc", role: "bu_head" }, "missing", null, { user: "soc", role: "bu_head" }, valid),
                   { user: "soc", role: "bu_head" });
  const users = { users: { alice: { role: "analyst" as const }, bob: { role: "ciso" as const, disabled: true } } };
  assert.deepEqual(checkLocalSession(s, "ok", users, null, valid), { user: "alice", role: "analyst" });
  assert.equal(checkLocalSession({ user: "bob", role: "ciso" }, "ok", users, null, valid), null);
});

test("a cookie from another auth mode or session epoch is void", () => {
  assert.equal(claimsCurrent({ user: "a", role: "ciso" }, "oidc", ""), false);
  assert.equal(claimsCurrent({ user: "a", role: "ciso", mode: "local", epoch: "1" }, "local", "2"), false);
  assert.equal(claimsCurrent({ user: "a", role: "ciso" }, "local", ""), true);
});

test("behind a Host-rewriting proxy: Sec-Fetch-Site or AEGIS_CONSOLE_ORIGIN lets analysts post", () => {
  const behind = { host: "127.0.0.1:3000", origin: "https://soc.bank.in" };
  assert.equal(sameOrigin(h(behind)), false);
  assert.equal(sameOrigin(h({ ...behind, "sec-fetch-site": "same-origin" })), true);
  const keep = process.env.AEGIS_CONSOLE_ORIGIN;
  try {
    process.env.AEGIS_CONSOLE_ORIGIN = "https://soc.bank.in/";
    assert.equal(sameOrigin(h(behind)), true);
    assert.equal(sameOrigin(h({ ...behind, origin: "https://evil.example", "sec-fetch-site": "same-origin" })), false);
  } finally {
    if (keep === undefined) delete process.env.AEGIS_CONSOLE_ORIGIN; else process.env.AEGIS_CONSOLE_ORIGIN = keep;
  }
});
