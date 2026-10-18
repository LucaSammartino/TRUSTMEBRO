import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { State, Note } from "../src/types.ts";
import { buildApplyEntries, writeApplyBundle } from "../src/apply.ts";

function makeState(): State {
  return {
    project: { schema: "rea-pool/1", name: "example", created: "", target: { filename: "x", sha256: "abc", size: 1 }, tools: [],
      rules: { allowedKinds: ["function_name", "comment"], maxTextLength: 500, maxEvidenceItems: 5, leaseMinutes: 30 } },
    joinCode: "jc", contributors: [], proposals: [], notes: [],
    tasks: [{ id: "a", label: "a", address: "0X000A", state: "open" }],
  };
}

function note(value: string, changes: Partial<Note> = {}): Note {
  return { id: value, taskId: "a", author: "alice", kind: "function_name", value, evidence: [], confidence: "high",
    model: "test", at: "2026-01-01", status: "trusted", ...changes };
}

test("best trusted names and comments win, with stable ties and proposal alternatives", () => {
  const s = makeState();
  s.notes = [note("weaker"), note("winner", { agrees: 2, proposalId: "p" }), note("tie", { agrees: 2 }),
    note("pending", { status: "pending", agrees: 99 }), note("hint", { status: "hint", agrees: 99 }),
    note("rejected", { status: "rejected", agrees: 99 }),
    note("weak comment", { kind: "comment" }), note("best comment", { kind: "comment", agrees: 3 }),
    note("pending comment", { kind: "comment", status: "pending", agrees: 99 })];
  s.proposals = [{ id: "p", taskId: "a", author: "alice", confidence: "high", status: "trusted", votes: [], at: "",
    ...{ alternatives: ["other", "another"] } }];
  assert.deepEqual(buildApplyEntries(s), [{ address: "0xa", name: "winner", comment: "best comment",
    alternatives: ["other", "another"], confidence: "high", agrees: 2 }]);
});

test("known, review, invalid addresses and tasks without trusted names are skipped; addresses sort", () => {
  const s = makeState();
  s.tasks.push(...[
    { ...s.tasks[0], id: "known", ...{ known: true } },
    { ...s.tasks[0], id: "review", kind: "review" as const },
    { ...s.tasks[0], id: "invalid", address: "invalid" },
    { ...s.tasks[0], id: "pending" },
    { ...s.tasks[0], id: "b", kind: "analyze" as const, address: "0x0002" },
  ]);
  s.notes = s.tasks.map((t) => note(t.id, { taskId: t.id, status: t.id === "pending" ? "pending" : "trusted" }));
  assert.deepEqual(buildApplyEntries(s), [
    { address: "0x2", name: "b", confidence: "high", agrees: 0 },
    { address: "0xa", name: "a", confidence: "high", agrees: 0 },
  ]);
});

test("bundle writes parseable names and copies the Ghidra script", () => {
  const dir = mkdtempSync(join(tmpdir(), "pool-apply-test-"));
  try {
    const s = makeState();
    s.notes = [note("chosen", { proposalId: "missing" })];
    const result = writeApplyBundle(s, join(dir, "bundle"));
    const data = JSON.parse(readFileSync(result.namesFile, "utf8"));
    assert.equal(result.count, 1);
    assert.equal(data.project, "example");
    assert.equal(data.target, "abc");
    assert.deepEqual(data.functions, buildApplyEntries(s));
    assert.equal(data.functions.length, result.count);
    assert.match(readFileSync(result.scriptFile, "utf8"), /APPLYNAMES/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
