// Round-8 review: long targets, approved-but-not-run cards, partial chains, dashboard approvals shape, signed OIDC
// transaction cookie, {"users": null}, and the pending-queue paging (U8-1 … U8-6 + U-4 leftover).
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import {
  attachPending, cardState, fullTarget, latestApprovalFor, mergeDetails, missingPendingAlerts, normalizeApproval,
  pendingQueue, stubChainFromApprovals,
} from "../lib/hitl.ts";
import { encodeTx, newOidcTx, oidcCookie, verifyCallbackState } from "../lib/oidc.ts";
import type { Approval, Chain, RecommendedAction } from "../lib/types.ts";

const LONG = "https://netbanking.example.in/retail/api/v2/payments/transfer?x=" + "A".repeat(300);
const appr = (o: Partial<Approval>): Approval =>
  ({ id: "a1", status: "pending", created_at: "2026-11-04T00:00:00Z", action_type: "block", target: "203.0.113.9",
     alert_id: "ALR-1", ...o }) as Approval;
const act = (o: Partial<RecommendedAction> = {}): RecommendedAction =>
  ({ action_type: "block", target: "203.0.113.9", requires_hitl: true, ...o }) as RecommendedAction;

test("U8-1: a card whose target was cut at 256 chars still matches its action (receiver target_full / action text)", () => {
  const cut = LONG.slice(0, 256);
  const longAct = act({ target: LONG, requires_hitl: false });
  // receiver row: display cut + target_full
  const rx = appr({ id: "rx", target: cut, target_full: LONG });
  assert.equal(latestApprovalFor([rx], "ALR-1", longAct)?.id, "rx");
  assert.equal(cardState(longAct, latestApprovalFor([rx], "ALR-1", longAct), {}).kind, "decide");
  // dashboard / raw card: only the full `action` text
  const dash = appr({ id: "dash", target: cut, action: `block -> ${LONG}` });
  assert.equal(fullTarget(dash), LONG);
  assert.equal(latestApprovalFor([dash], "ALR-1", longAct)?.id, "dash");
  // the display cut alone never matches a different (longer) target, and a different long target is not matched
  assert.equal(latestApprovalFor([appr({ target: cut })], "ALR-1", longAct), undefined);
  assert.equal(latestApprovalFor([appr({ target: cut, target_full: LONG + "B" })], "ALR-1", longAct), undefined);
  // a stub rebuilt from the card carries the full target, so the card matches its stub action
  const stub = stubChainFromApprovals("ALR-1", [rx]);
  assert.equal(stub.recommended_actions[0].target, LONG);
  assert.equal(latestApprovalFor([rx], "ALR-1", stub.recommended_actions[0])?.id, "rx");
});

test("U8-2: approved but not yet executed -> awaiting execution (rejectable) until the settled marker", () => {
  const open = appr({ status: "approved", settled: false, decided_by: "ciso:alice", rationale: "go" });
  const st = cardState(act(), open, {});
  assert.equal(st.kind, "awaiting_execution");
  assert.ok(st.kind === "awaiting_execution" && st.note === "go" && st.approval.id === "a1");
  // settled by the service -> final
  const done = cardState(act(), appr({ status: "approved", settled: true }), {});
  assert.ok(done.kind === "settled" && done.status === "approved");
  // a backend that does not report it keeps the final label
  assert.equal(cardState(act(), appr({ status: "approved" }), {}).kind, "settled");
  // approved here a moment ago, backend still pending + unsettled -> awaiting execution, not final
  assert.equal(cardState(act(), appr({ settled: false }), { a1: { status: "approved", note: "" } }).kind, "awaiting_execution");
  // a local reject of the awaiting card settles it as rejected
  const rej = cardState(act(), open, { a1: { status: "rejected", note: "wrong host" } });
  assert.ok(rej.kind === "settled" && rej.status === "rejected");
  // failed stays failed
  assert.equal(cardState(act(), appr({ status: "failed", settled: true }), {}).kind, "settled");
});

test("U8-3: a top-40 chain whose detail read failed still gets its pending cards hydrated or stubbed", () => {
  const cards = [appr({ id: "p1", alert_id: "A-9", action_type: "isolate", target: "host-9" })];
  const { chains } = mergeDetails([{ chain_id: "h9", alert_id: "A-9" } as unknown as Chain],
    [{ status: "rejected", reason: new Error("500") }]);
  assert.equal(chains[0].partial, true);
  const loaded = new Set(chains.filter((c) => !c.partial).map((c) => c.alert_id));
  const extra = missingPendingAlerts(cards, loaded);
  assert.deepEqual(extra, ["A-9"]);
  // the re-read fails too: the cards are stubbed onto the partial chain (no duplicate incident)
  const stubbed = attachPending(chains, cards, extra, [{ status: "rejected", reason: new Error("500") }]);
  assert.equal(stubbed.length, 1);
  assert.equal(stubbed[0].chain_id, "h9");
  assert.equal(stubbed[0].partial, true);
  assert.deepEqual(stubbed[0].recommended_actions.map((a) => [a.action_type, a.target]), [["isolate", "host-9"]]);
  assert.equal(cardState(stubbed[0].recommended_actions[0], latestApprovalFor(cards, "A-9", stubbed[0].recommended_actions[0]), {}).kind, "decide");
  // the re-read works: the full chain replaces the partial one
  const full = { chain_id: "h9", alert_id: "A-9", recommended_actions: [act({ action_type: "isolate", target: "host-9" })] } as unknown as Chain;
  const hydrated = attachPending(chains, cards, extra, [{ status: "fulfilled", value: full }]);
  assert.equal(hydrated.length, 1);
  assert.equal(hydrated[0].partial, undefined);
  // an alert not loaded at all is appended
  const added = attachPending([], cards, ["A-9"], [{ status: "fulfilled", value: null }]);
  assert.equal(added.length, 1);
  assert.equal(added[0].partial, true);
});

test("U-4 leftover: a detail that comes back 404 / null is kept as partial, not dropped", () => {
  const { chains, failed } = mergeDetails([{ chain_id: "c1", alert_id: "A" } as unknown as Chain],
    [{ status: "fulfilled", value: null }]);
  assert.equal(chains.length, 1);
  assert.equal(chains[0].partial, true);
  assert.deepEqual(chains[0].recommended_actions, []);
  assert.equal(failed, 1);
});

test("U8-4: ACP dashboard approval rows (fields inside an `args` JSON string) are normalised", () => {
  const raw = { id: "d1", agent_id: "aegis", action: "isolate -> host-7",
    args: JSON.stringify({ alert_id: "A-1", action_type: "isolate", target: "host-7", integrity_hash: "h1", reasoning: "lateral" }),
    tier: "high", status: "pending", decided_by: "", decided_at: "", reject_reason: "", created_at: "2026-11-04 10:00:00" };
  const a = normalizeApproval(raw)!;
  assert.equal(a.alert_id, "A-1");
  assert.equal(a.action_type, "isolate");
  assert.equal(a.target, "host-7");
  assert.equal(a.integrity_hash, "h1");
  assert.equal(a.decided_by, undefined);
  const iso = act({ action_type: "isolate", target: "host-7" });
  assert.equal(latestApprovalFor([a], "A-1", iso)?.id, "d1");
  assert.equal(cardState(iso, latestApprovalFor([a], "A-1", iso), {}).kind, "decide");
  assert.deepEqual(pendingQueue([a]).map((x) => x.alert_id), ["A-1"]);
  assert.deepEqual(missingPendingAlerts([a], new Set()), ["A-1"]);
  // a dashboard long target: args.target is the cut, `action` the full text
  const longRow = normalizeApproval({ ...raw, id: "d2", action: `block -> ${LONG}`,
    args: JSON.stringify({ alert_id: "A-1", action_type: "block", target: LONG.slice(0, 256) }) })!;
  assert.equal(latestApprovalFor([longRow], "A-1", act({ target: LONG }))?.id, "d2");
  // rejected: reject_reason becomes the note; object args work too; top-level fields win
  const r = normalizeApproval({ ...raw, status: "rejected", reject_reason: "fp", decided_by: "ciso:bob" })!;
  assert.equal(r.rationale, "fp");
  const obj = normalizeApproval({ id: 7, status: "pending", created_at: "", alert_id: "TOP",
    args: { alert_id: "ARG", action_type: "block", target: "x" } })!;
  assert.equal(obj.id, "7");
  assert.equal(obj.alert_id, "TOP");
  // AEGIS receiver rows pass through unchanged in the fields the console uses
  const rx = { id: "r1", status: "approved", created_at: "2026-11-04T00:00:00+00:00", action_type: "block", target: "x",
    target_full: "x", settled: false, alert_id: "A", integrity_hash: "h", reasoning: "r", agent_id: "aegis",
    decided_by: "ciso:a", decided_at: "2026-11-04T00:00:01+00:00", rationale: "go" };
  assert.deepEqual(normalizeApproval(rx), rx);
  // junk rows are dropped, broken args do not throw
  assert.equal(normalizeApproval(null), null);
  assert.equal(normalizeApproval([1]), null);
  assert.equal(normalizeApproval({ status: "pending" }), null);
  assert.equal(normalizeApproval({ id: "z", args: "{not json" })?.alert_id, undefined);
});

test("U8-5: the OIDC transaction cookie is HMAC-signed; unsigned or foreign-signed cookies are refused", () => {
  const SECRET = "test-secret-0123456789";
  const tx = newOidcTx();
  const good = encodeTx(tx, SECRET);
  assert.deepEqual(verifyCallbackState(good, tx.state, Date.now(), SECRET), { nonce: tx.nonce, verifier: tx.verifier });
  // what a sibling subdomain could plant before: the bare base64url payload with the attacker's own state
  const atk = { s: "attacker-state", n: "attacker-nonce", v: "attacker-verifier-".padEnd(50, "x"), t: Math.floor(Date.now() / 1000) };
  const unsigned = Buffer.from(JSON.stringify(atk)).toString("base64url");
  assert.equal(verifyCallbackState(unsigned, "attacker-state", Date.now(), SECRET), null);
  // signed with another key
  const other = encodeTx({ state: atk.s, nonce: atk.n, verifier: atk.v, issuedAt: atk.t }, "some-other-secret-xxxx");
  assert.equal(verifyCallbackState(other, "attacker-state", Date.now(), SECRET), null);
  // tampered body under a valid signature
  const [, sig] = good.split(".");
  const body2 = Buffer.from(JSON.stringify({ ...atk, s: tx.state })).toString("base64url");
  assert.equal(verifyCallbackState(`${body2}.${sig}`, tx.state, Date.now(), SECRET), null);
  // truncated / wrong-length signature
  assert.equal(verifyCallbackState(good.slice(0, -3), tx.state, Date.now(), SECRET), null);
  assert.equal(verifyCallbackState(`${good}.x`, tx.state, Date.now(), SECRET), null);
  // the MAC is not the session cookie's MAC over the same body (domain-separated)
  const body = good.split(".")[0];
  assert.notEqual(sig, crypto.createHmac("sha256", SECRET).update(body).digest("base64url"));
  // __Host- over HTTPS (Secure, Path=/), plain path-scoped name on HTTP dev
  assert.deepEqual(oidcCookie(true), { name: "__Host-aegis_oidc_tx", path: "/", secure: true });
  assert.deepEqual(oidcCookie(false), { name: "aegis_oidc_tx", path: "/api/auth/oidc", secure: false });
});

test("U8-6: a users file with users null / array / non-object is unreadable (503), never ok", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-u8-"));
  const f = path.join(dir, "users.json");
  process.env.AEGIS_CONSOLE_USERS = f;
  const { loadUsers, usersFileState } = await import("../lib/users.ts");
  const { checkLocalSession } = await import("../lib/session.ts");
  for (const body of ['{"users": null}', '{"users": []}', '{"users": "x"}', "[]", "null", "42", '{"users": 1}']) {
    fs.writeFileSync(f, body);
    assert.equal(loadUsers(), null, body);
    assert.equal(usersFileState(), "unreadable", body);
    assert.equal(checkLocalSession({ user: "alice", role: "ciso" }, usersFileState(), loadUsers(), null, () => true), null);
  }
  fs.writeFileSync(f, JSON.stringify({ users: { alice: { role: "ciso", hash: "x" } } }));
  assert.equal(usersFileState(), "ok");
  assert.deepEqual(checkLocalSession({ user: "alice", role: "analyst" }, "ok", loadUsers(), null, () => true), { user: "alice", role: "ciso" });
});

test("pending queue: every card stays reachable past the first page", async () => {
  const src = fs.readFileSync(new URL("../components/PendingQueue.tsx", import.meta.url), "utf8");
  assert.doesNotMatch(src, /slice\(0,\s*50\)/);                  // the hard cut is gone
  assert.match(src, /show all/);
  assert.match(src, /fullTarget\(a\)/);                           // focus by the full target, not the display cut
  const con = fs.readFileSync(new URL("../components/Console.tsx", import.meta.url), "utf8");
  assert.match(con, /stubChainFromApprovals\(alertId, approvals\)/); // a card on an unhydrated alert still opens
});
