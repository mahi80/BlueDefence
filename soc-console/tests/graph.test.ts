// Unit tests for the incident graph the console draws (code review 2026-11-03 T10).
import { test } from "node:test";
import assert from "node:assert/strict";
import { chainToGraph } from "../lib/graph.ts";

const chain = {
  alert_id: "A1", source: "Imperva", verdict: "malicious", confidence: 0.9, integrity_hash: "h",
  recommended_actions: [{ action_type: "isolate", target: "LT-9", requires_hitl: true }],
  investigation: {
    swarm: ["perimeter", "identity"],
    blast_radius: {
      nodes: [{ id: "LT-9", label: "LT-9", kind: "host" }, { id: "cbs-db", label: "cbs-db", kind: "asset" }],
      edges: [{ source: "LT-9", target: "cbs-db", kind: "attack" }],
      critical: ["cbs-db"], choke_edges: [["LT-9", "cbs-db"]],
    },
  },
} as never;

test("critical assets, choke edges and actions land on the right nodes", () => {
  const g = chainToGraph(chain);
  const node = (id: string) => g.nodes.find((n) => n.id === id)!;
  assert.equal(node("cbs-db").critical, true);
  assert.equal(node("LT-9").critical, false);
  assert.equal(g.edges.find((e) => e.source === "LT-9")!.choke, true);
  assert.equal(node("LT-9").action?.action_type, "isolate");
  assert.equal(g.nodes.filter((n) => n.kind === "worker").length, 3);       // AEGIS + two swarm workers
  assert.equal(new Set(g.nodes.map((n) => n.id)).size, g.nodes.length);    // no duplicate ids
});

test("a chain with no investigation is just the alert", () => {
  const g = chainToGraph({ alert_id: "A2", verdict: "benign", recommended_actions: [], integrity_hash: "h" } as never);
  assert.deepEqual(g.nodes.map((n) => n.id), ["__alert"]);
  assert.deepEqual(g.edges, []);
});
