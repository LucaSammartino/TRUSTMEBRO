import { test } from "node:test";
import assert from "node:assert/strict";
import type { State } from "../src/types.ts";
import { addCallees, basedOn, calleeContext, calleesFromReaFunction, cleanCallees, graphStats, normalizeAddress, readiness } from "../src/graph.ts";
import { claimTask, submitAnalysis } from "../src/server.ts";
import { NOTE_PROTOCOL } from "../src/trust.ts";

const rules = { allowedKinds: ["function_name", "comment"], maxTextLength: 500, maxEvidenceItems: 5, leaseMinutes: 30, protocol: NOTE_PROTOCOL, maxAttempts: 3, maxVotes: 5, maxContributors: 50 };

// a calls b and c; b calls c; c calls nothing.
function makeState(): State {
  const task = (n: string, callees?: string[]) => ({ id: `fn-0x${n}`, kind: "analyze" as const, label: n, address: `0x${n}`, state: "open" as const, attempts: 1, callees });
  return {
    project: { schema: "rea-pool/1", name: "t", created: "", target: { filename: "x", sha256: "00", size: 1 }, tools: [], rules },
    joinCode: "jc",
    contributors: [],
    tasks: [task("a", ["0xb", "0xc"]), task("b", ["0xc"]), task("c", [])],
    notes: [],
    proposals: [],
  };
}

const named = (value: string) => [
  { kind: "function_name", value, confidence: "high" },
  { kind: "comment", value: "Does a thing.", confidence: "high" },
];

test("addresses are written one way", () => {
  assert.equal(normalizeAddress("0x00401234"), "0x401234");
  assert.equal(normalizeAddress("0X65B886B0"), "0x65b886b0");
  assert.equal(normalizeAddress("0x0"), "0x0");
  assert.equal(normalizeAddress("EXTERNAL:0x1"), null);
  assert.equal(normalizeAddress("FUN_00401234"), null);
  assert.equal(normalizeAddress(5), null);
});

test("callee lists are cleaned: junk, duplicates and the function itself are dropped", () => {
  assert.deepEqual(cleanCallees(["0x0b", "0xB", "nope", 7, "0xa"], "0x0A"), ["0xb"]);
  assert.deepEqual(cleanCallees("0xb", "0xa"), []);
});

test("callees come from rea function output; imports are skipped and thunks point at their target", () => {
  const result = {
    callees: [
      { address: "0x65b87c00", name: "f", classification: { external: false, thunk: false } },
      { address: "EXTERNAL:0x1", name: "ext", classification: { external: true, thunk: false } },
      { address: "0x65b90000", name: "thunk", classification: { external: false, thunk: true, thunk_target: "0x65b91000" } },
      { address: "0x65b92000", name: "thunk2", classification: { external: false, thunk: true, thunk_target: null } },
    ],
  };
  assert.deepEqual(calleesFromReaFunction(result, "0x65b886b0"), ["0x65b87c00", "0x65b91000", "0x65b92000"]);
  assert.deepEqual(calleesFromReaFunction({}, "0x1"), []);
});

test("functions whose callees are named are handed out first", () => {
  const s = makeState();
  assert.equal(readiness(s, s.tasks[2]), 0, "a leaf is ready");
  assert.equal(readiness(s, s.tasks[0]), 3, "a has two unresolved callees");
  assert.equal(claimTask(s, "alice")!.id, "fn-0xc", "the leaf goes first even though it is last in the list");
  submitAnalysis(s, "alice", s.tasks[2], named("leaf_fn"));
  assert.equal(readiness(s, s.tasks[1]), 0, "b is ready once c is trusted");
  assert.equal(claimTask(s, "bob")!.id, "fn-0xb");
});

test("a function whose callee is finished without a name is not blocked forever", () => {
  const s = makeState();
  s.tasks[2].state = "done";
  assert.equal(readiness(s, s.tasks[1]), 0);
});

test("functions with unknown callees rank between ready and blocked ones", () => {
  const s = makeState();
  s.tasks[1].callees = undefined;
  assert.equal(readiness(s, s.tasks[1]), 1);
  assert.ok(readiness(s, s.tasks[0]) > 1);
});

test("only trusted names are shown as context, and notes remember what they were built on", () => {
  const s = makeState();
  assert.deepEqual(calleeContext(s, "0xb"), []);
  submitAnalysis(s, "alice", s.tasks[2], named("leaf_fn"));
  assert.deepEqual(calleeContext(s, "0xb"), [{ address: "0xc", name: "leaf_fn" }]);
  const claimed = claimTask(s, "bob")!;
  assert.equal(claimed.id, "fn-0xb");
  submitAnalysis(s, "bob", claimed, named("mid_fn"));
  const note = s.notes.find((n) => n.value === "mid_fn")!;
  assert.deepEqual(note.basedOn, basedOn([{ address: "0xc", name: "leaf_fn" }]));
});

test("a pending (unchecked) name is not shown to the next person", () => {
  const s = makeState();
  submitAnalysis(s, "alice", s.tasks[2], [{ kind: "function_name", value: "maybe_fn", confidence: "medium" }]);
  assert.deepEqual(calleeContext(s, "0xb"), []);
});

test("addCallees merges and reports whether anything changed", () => {
  const s = makeState();
  const t = s.tasks[0];
  assert.equal(addCallees(t, ["0xb"]), false);
  assert.equal(addCallees(t, ["0xd", "0xa"]), true, "a new callee was added; the function itself is ignored");
  assert.deepEqual(t.callees, ["0xb", "0xc", "0xd"]);
  const fresh = { ...s.tasks[1], callees: undefined };
  assert.equal(addCallees(fresh, []), true, "learning that a function calls nothing is a change");
  assert.deepEqual(fresh.callees, []);
});

test("graph statistics", () => {
  const s = makeState();
  s.tasks[1].callees = undefined;
  assert.deepEqual(graphStats(s), { known: 2, unknown: 1, edges: 2, ready: 1 });
});
