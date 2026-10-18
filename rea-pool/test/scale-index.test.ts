import { test } from "node:test";
import assert from "node:assert/strict";
import type { Note, State, Task } from "../src/types.ts";
import { buildIndex, calleeContext, callerContext, graphStats, needsRefinement, readiness, staleNotes, trustedName } from "../src/graph.ts";
import { twinHints, twinPotential } from "../src/similar.ts";
import { claimTask } from "../src/server.ts";
import { NOTE_PROTOCOL } from "../src/trust.ts";

function baseState(tasks: Task[], notes: Note[] = []): State {
  return {
    project: {
      schema: "rea-pool/1", name: "idx", created: "",
      target: { filename: "x.bin", sha256: "00", size: 1 }, tools: [],
      rules: { allowedKinds: ["function_name"], maxTextLength: 500, maxEvidenceItems: 5, leaseMinutes: 30, protocol: NOTE_PROTOCOL, maxAttempts: 3, maxVotes: 5, maxContributors: 50 },
    },
    joinCode: "jc", contributors: [], notes, proposals: [], tasks,
  };
}

const task = (i: number, extra: Partial<Task> = {}): Task => ({ id: `fn-${i}`, kind: "analyze", label: `F${i}`, address: `0x${i.toString(16)}`, state: "open", attempts: 1, ...extra });

const note = (taskId: string, value: string, over: Partial<Note> = {}): Note => ({
  id: `n-${taskId}-${value}`, taskId, author: "a", kind: "function_name", value, evidence: [], confidence: "high", model: "m",
  at: "2026-01-01T00:00:00.000Z", status: "trusted", ...over,
});

test("indexed and index-less helpers agree on a small state", () => {
  const tasks = [
    task(1, { callees: ["0x2", "0x3", "0x9"], shape: "aaaaaaaaaaaaaaaa" }),
    task(2, { callees: ["0x3"], shape: "aaaaaaaaaaaaaaaa" }),
    task(3, { callees: [], shape: "aaaaaaaaaaaaaaaa", state: "done" }),
    task(4, { callees: ["0x2", "0x3"], shape: "bbbbbbbbbbbbbbbb" }),
    task(5, { known: { name: "known_fn", source: "ghidra" }, callees: ["0x1"], state: "done" }),
    task(6, { callees: ["0x5", "0x2"], shape: "bbbbbbbbbbbbbbbb", state: "done" }),
    task(7),
    { ...task(8), kind: "review", proposalId: "p1" } as Task,
  ];
  const notes = [
    note("fn-2", "second_best", { agrees: 0 }),
    note("fn-2", "best_name", { agrees: 2 }),
    note("fn-3", "three", { status: "hint" }),
    note("fn-4", "four"),
    note("fn-1", "uses_old", { basedOn: ["0x2=best_name", "0x5=gone"] }),
    note("fn-4", "uses_ok", { kind: "comment", basedOn: ["0x2=best_name"] }),
  ];
  const state = baseState(tasks, notes);
  const idx = buildIndex(state);

  assert.equal(trustedName(state, "0x2", idx), "best_name");
  for (const a of ["0x1", "0x2", "0x3", "0x4", "0x5", "0x9", "0xzz"]) assert.equal(trustedName(state, a, idx), trustedName(state, a), a);
  for (const t of tasks) {
    assert.equal(readiness(state, t, idx), readiness(state, t), `readiness ${t.id}`);
    assert.deepEqual(calleeContext(state, t.address, idx), calleeContext(state, t.address), `callees ${t.id}`);
    assert.deepEqual(callerContext(state, t.address, idx), callerContext(state, t.address), `callers ${t.id}`);
    assert.deepEqual(twinHints(state, t, idx), twinHints(state, t), `twins ${t.id}`);
    assert.equal(twinPotential(state, t, idx), twinPotential(state, t), `potential ${t.id}`);
    assert.equal(needsRefinement(state, t, idx), needsRefinement(state, t), `refine ${t.id}`);
  }
  assert.deepEqual(graphStats(state, idx), graphStats(state));
  assert.deepEqual(staleNotes(state, idx), staleNotes(state));
  assert.equal(staleNotes(state).length, 1);
  assert.ok(callerContext(state, "0x2").length > 0);
});

test("claimTask and graphStats stay fast with 20,000 open functions", () => {
  const N = 20_000;
  const tasks: Task[] = [];
  for (let i = 0; i < N; i++) {
    tasks.push(task(i, { callees: [1, 7, 13].map((d) => `0x${((i + d) % N).toString(16)}`), shape: i % 4 === 0 ? `${(i % 50).toString(16).padStart(16, "0")}` : undefined }));
  }
  const notes: Note[] = [];
  for (let i = 0; i < N; i += 1) if (i % 2 === 0) notes.push(note(`fn-${i}`, `name_${i}`));
  const state = baseState(tasks, notes);

  let t0 = performance.now();
  const got = claimTask(state, "probe", Date.now());
  const claimMs = performance.now() - t0;
  assert.ok(got);
  t0 = performance.now();
  const stats = graphStats(state);
  const statsMs = performance.now() - t0;
  assert.equal(stats.known, N);
  assert.ok(claimMs < 500, `claimTask took ${claimMs.toFixed(0)} ms`);
  assert.ok(statsMs < 500, `graphStats took ${statsMs.toFixed(0)} ms`);
});
