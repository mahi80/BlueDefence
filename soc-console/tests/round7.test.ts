// Round-7 review: console HITL state, pending queue, partial details, OIDC transaction, users CLI (U-1 … U-6).
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { cardState, latestApprovalFor, mergeDetails, missingPendingAlerts, pendingQueue, stubChainFromApprovals } from "../lib/hitl.ts";
import { encodeTx, newOidcTx, nonceMatches, verifyCallbackState, OIDC_TX_MAX_AGE_S } from "../lib/oidc.ts";
import type { Approval, Chain, RecommendedAction } from "../lib/types.ts";

const appr = (o: Partial<Approval>): Approval =>
  ({ id: "a1", status: "pending", created_at: "2026-11-04T00:00:00Z", action_type: "block", target: "203.0.113.9",
     alert_id: "ALR-1", ...o }) as Approval;
const act = (o: Partial<RecommendedAction> = {}): RecommendedAction =>
  ({ action_type: "block", target: "203.0.113.9", requires_hitl: false, ...o }) as RecommendedAction;

test("U-1: a filed card decides the state even when the chain says requires_hitl=false", () => {
  const card = appr({});
  const st = cardState(act(), latestApprovalFor([card], "ALR-1", act()), {});
  assert.equal(st.kind, "decide");
  // no card + auto-eligible: proposed, never "applied"
  assert.equal(cardState(act(), undefined, {}).kind, "proposed");
  // a missing flag is not auto
  assert.equal(cardState({ action_type: "isolate", target: "h" } as RecommendedAction, undefined, {}).kind, "no_card");
  assert.equal(cardState(act({ requires_hitl: true }), undefined, {}).kind, "no_card");
  assert.equal(cardState(act({ requires_hitl: true }), undefined, {}, true).kind, "decide");   // fixture demo
  const aw = cardState(act(), appr({ status: "awaiting_second", decided_by: "ciso:asha" }), {});
  assert.ok(aw.kind === "decide" && aw.awaitingSecond);
  const failed = cardState(act(), appr({ status: "failed", rationale: "vendor 503" }), {});
  assert.ok(failed.kind === "settled" && failed.status === "failed" && failed.note === "vendor 503");
});

test("U-3: an old decision never hides a newer pending card; local decisions are keyed by approval id", () => {
  const old = appr({ id: "old", status: "rejected", created_at: "2026-11-01T00:00:00Z", rationale: "fp" });
  const fresh = appr({ id: "new", status: "pending", created_at: "2026-11-04T00:00:00Z" });
  for (const rows of [[fresh, old], [old, fresh]]) {
    const latest = latestApprovalFor(rows, "ALR-1", act());
    assert.equal(latest?.id, "new");
    assert.equal(cardState(act(), latest, { old: { status: "rejected", note: "fp" } }).kind, "decide");
  }
  const st = cardState(act(), fresh, { new: { status: "approved", note: "ok" } });
  assert.ok(st.kind === "settled" && st.status === "approved");
});

test("U-2: the pending queue is newest first and missing alerts are hydrated (or stubbed)", () => {
  const rows = [
    appr({ id: "p1", alert_id: "OLD-1", created_at: "2026-10-28T00:00:00Z", action_type: "isolate", target: "host-core-banking-07" }),
    appr({ id: "s1", alert_id: "X", status: "approved" }),
    appr({ id: "p2", alert_id: "NEW-1", created_at: "2026-11-04T00:00:00Z" }),
    appr({ id: "p3", alert_id: "OLD-1", status: "awaiting_second", created_at: "2026-10-29T00:00:00Z" }),
  ];
  assert.deepEqual(pendingQueue(rows).map((a) => a.id), ["p2", "p3", "p1"]);
  assert.deepEqual(missingPendingAlerts(rows, new Set(["NEW-1"])), ["OLD-1"]);
  const stub = stubChainFromApprovals("OLD-1", rows);
  assert.equal(stub.partial, true);
  assert.deepEqual(stub.recommended_actions.map((a) => [a.action_type, a.requires_hitl]), [["isolate", true], ["block", true]]);
});

test("U-4: a failed detail read is marked partial and counted", () => {
  const sums = [{ chain_id: "c1" }, { chain_id: "c2" }];
  const ok = { chain_id: "c1", recommended_actions: [act()] } as unknown as Chain;
  const { chains, failed } = mergeDetails(sums, [
    { status: "fulfilled", value: ok }, { status: "rejected", reason: new Error("503") },
  ]);
  assert.equal(failed, 1);
  assert.equal(chains[0].partial, undefined);
  assert.equal(chains[1].partial, true);
  assert.deepEqual(chains[1].recommended_actions, []);
});

test("U-5: OIDC state is stored, verified, single-purpose and time-limited; PKCE is S256", async () => {
  const tx = newOidcTx(1_000_000);
  const crypto = await import("node:crypto");
  assert.equal(tx.challenge, crypto.createHash("sha256").update(tx.verifier).digest("base64url"));
  assert.ok(tx.verifier.length >= 43 && tx.verifier.length <= 128);
  const cookie = encodeTx(tx);
  assert.deepEqual(verifyCallbackState(cookie, tx.state, 1_000_000 + 5_000), { nonce: tx.nonce, verifier: tx.verifier });
  assert.equal(verifyCallbackState(cookie, "attacker-state", 1_000_500), null);
  assert.equal(verifyCallbackState(undefined, tx.state, 1_000_500), null);                  // no login started here
  assert.equal(verifyCallbackState("garbage", tx.state, 1_000_500), null);
  assert.equal(verifyCallbackState(cookie, tx.state, 1_000_000 + (OIDC_TX_MAX_AGE_S + 1) * 1000), null);
  assert.ok(nonceMatches(tx.nonce, tx.nonce));
  assert.equal(nonceMatches(tx.nonce, "other"), false);
  assert.equal(nonceMatches(tx.nonce, undefined), false);
});

test("U-6: the users CLI never overwrites an unreadable or corrupt users file", async () => {
  const { loadUsersFile, saveUsersFile } = await import("../scripts/users.mjs");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-users-"));
  const f = path.join(dir, "users.json");
  assert.deepEqual(loadUsersFile(f), { users: {} });                                         // missing = first run
  fs.writeFileSync(f, '{"users": {"ciso": {"role": "ciso", "hash": "x"}, "admin": {"ro');    // truncated
  assert.throws(() => loadUsersFile(f), /not valid JSON/);
  fs.writeFileSync(f, '{"accounts": {}}');
  assert.throws(() => loadUsersFile(f), /no "users" object/);
  fs.writeFileSync(f, JSON.stringify({ users: { ciso: { role: "ciso", hash: "x" } } }));
  const u = loadUsersFile(f);
  u.users.bob = { role: "analyst", hash: "y" };
  saveUsersFile(f, u);
  assert.deepEqual(Object.keys(JSON.parse(fs.readFileSync(f, "utf8")).users).sort(), ["bob", "ciso"]);
  assert.equal(fs.readdirSync(dir).filter((n) => n.endsWith(".tmp")).length, 0);
  assert.equal(fs.statSync(f).mode & 0o777, 0o600);
});
