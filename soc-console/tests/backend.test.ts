// A failed backend read must surface, not render as "live, 0 pending" (code review 2026-11-03 C3).
import { test } from "node:test";
import assert from "node:assert/strict";
import { cached } from "../lib/cache.ts";
import { settle } from "../lib/settle.ts";

test("a failed read is not cached for the snapshot window", async () => {
  let calls = 0;
  const fail = () => { calls++; return Promise.reject(new Error("/api/approvals -> 500")); };
  await assert.rejects(cached("k-fail", 60_000, fail), /500/);
  await assert.rejects(cached("k-fail", 60_000, fail), /500/);
  assert.equal(calls, 2);                                       // retried, not served from the cache
  const ok = await cached("k-fail", 60_000, async () => ["a"]);
  assert.deepEqual(ok, ["a"]);
});

test("settle keeps the good reads and reports each failed one", async () => {
  const { values, errors } = await settle<[string[], number[], string[]]>(
    [Promise.resolve(["c1"]), Promise.reject(new Error("/api/approvals -> 500")), Promise.resolve([])],
    [[], [], []],
  );
  assert.deepEqual(values, [["c1"], [], []]);
  assert.deepEqual(errors, ["/api/approvals -> 500"]);
});
