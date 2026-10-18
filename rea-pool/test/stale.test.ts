import { test } from "node:test";
import assert from "node:assert/strict";
import type { State } from "../src/types.ts";
import { staleNotes } from "../src/graph.ts";
import { flagStale, overrideNote, submitAnalysis } from "../src/server.ts";
import { NOTE_PROTOCOL } from "../src/trust.ts";

const rules = { allowedKinds: ["function_name", "comment"], maxTextLength: 500, maxEvidenceItems: 5, leaseMinutes: 30, protocol: NOTE_PROTOCOL, maxAttempts: 3, maxVotes: 5, maxContributors: 50 };

// b calls c; c calls nothing.
function makeState(): State {
  const task = (n: string, callees: string[]) => ({ id: `fn-0x${n}`, kind: "analyze" as const, label: n, address: `0x${n}`, state: "open" as const, attempts: 1, callees });
  return {
    project: { schema: "rea-pool/1", name: "t", created: "", target: { filename: "x", sha256: "00", size: 1 }, tools: [], rules },
    joinCode: "jc",
    contributors: [],
    tasks: [task("b", ["0xc"]), task("c", [])],
    notes: [],
    proposals: [],
  };
}

const named = (value: string) => [
  { kind: "function_name", value, confidence: "high" },
  { kind: "comment", value: "Does a thing.", confidence: "high" },
];

function build() {
  const s = makeState();
  const [b, c] = s.tasks;
  submitAnalysis(s, "alice", c, named("callee_x"));
  submitAnalysis(s, "bob", b, named("caller_y"));
  const calleeNote = s.notes.find((n) => n.taskId === c.id && n.kind === "function_name")!;
  const callerNote = s.notes.find((n) => n.taskId === b.id && n.kind === "function_name")!;
  return { s, b, c, calleeNote, callerNote };
}

test("a caller note is flagged stale and its task reopened once when the callee name is rejected", () => {
  const { s, b, calleeNote, callerNote } = build();
  assert.deepEqual(callerNote.basedOn, ["0xc=callee_x"]);
  assert.equal(b.state, "done");
  assert.deepEqual(staleNotes(s), []);
  overrideNote(s, calleeNote.id, "rejected");
  assert.ok(staleNotes(s).includes(callerNote));
  assert.equal(callerNote.stale, true);
  assert.equal(b.state, "open");
  assert.equal(b.reopened, 1);
  assert.deepEqual(b.doneBy, ["bob"]);
  flagStale(s);
  assert.equal(b.reopened, 1, "flagging again does not reopen twice");
});

test("nothing is flagged while names still match", () => {
  const { s, b, calleeNote, callerNote } = build();
  overrideNote(s, calleeNote.id, "trusted");
  assert.equal(callerNote.stale, undefined);
  assert.equal(b.state, "done");
  assert.equal(b.reopened, undefined);
});

test("a task already reopened maxReopens times is flagged but not reopened again", () => {
  const { s, b, calleeNote, callerNote } = build();
  b.reopened = 1;
  overrideNote(s, calleeNote.id, "rejected");
  assert.equal(callerNote.stale, true);
  assert.equal(b.state, "done");
  assert.equal(b.reopened, 1);
});
