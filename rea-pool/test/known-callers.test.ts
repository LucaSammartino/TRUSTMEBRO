import { test } from "node:test";
import assert from "node:assert/strict";
import type { State, Task } from "../src/types.ts";
import { callerContext, calleeContext, needsRefinement, trustedName } from "../src/graph.ts";
import { claimTask, cleanAlternatives, flagStale, scheduleRefinement, submitAnalysis, DUPLICATE_NAME } from "../src/server.ts";
import { buildActivity } from "../src/activity.ts";
import { NOTE_PROTOCOL } from "../src/trust.ts";

const rules = { allowedKinds: ["function_name", "comment"], maxTextLength: 500, maxEvidenceItems: 5, leaseMinutes: 30, protocol: NOTE_PROTOCOL, maxAttempts: 3, maxVotes: 5, maxContributors: 50 };

function makeState(tasks: Task[]): State {
  return {
    project: { schema: "rea-pool/1", name: "t", created: "", target: { filename: "x", sha256: "00", size: 1 }, tools: [], rules },
    joinCode: "jc",
    contributors: [],
    tasks,
    notes: [],
    proposals: [],
  };
}

const task = (n: string, callees: string[], extra: Partial<Task> = {}): Task => ({ id: `fn-0x${n}`, kind: "analyze", label: n, address: `0x${n}`, state: "open", attempts: 1, callees, ...extra });
const known = (n: string, name: string): Task => task(n, [], { state: "done", known: { name, source: "ghidra" } });
const named = (value: string, confidence = "high", model = "m1") => [
  { kind: "function_name", value, confidence, model },
  { kind: "comment", value: "Does a thing.", confidence, model },
];

test("known names are trusted context and count as resolved", () => {
  const s = makeState([task("a", ["0xe"]), known("e", "memcpy_like")]);
  assert.equal(trustedName(s, "0xe"), "memcpy_like");
  assert.deepEqual(calleeContext(s, "0xa"), [{ address: "0xe", name: "memcpy_like" }]);
  assert.equal(flagStaleSafe(s), 0);
  assert.equal(claimTask(s, "alice")?.id, "fn-0xa");
  assert.doesNotThrow(() => buildActivity(s, Date.now(), "alice"));
});
function flagStaleSafe(s: State) {
  return flagStale(s);
}

test("callerContext lists named callers, known or trusted", () => {
  const s = makeState([task("c", []), task("d", ["0xc"], { state: "done" }), task("f", ["0xc"]), known("e", "main_loop")]);
  s.tasks[3].callees = ["0xc"];
  assert.deepEqual(callerContext(s, "0xc"), [{ address: "0xe", name: "main_loop" }]);
  submitAnalysis(s, "alice", s.tasks[2], named("quux_handler"));
  assert.deepEqual(
    callerContext(s, "0xc").map((c) => c.name).sort(),
    ["main_loop", "quux_handler"],
  );
  assert.deepEqual(callerContext(s, "0x99"), []);
});

test("refinement reopens a done function without a trusted name once, after all work ends", () => {
  const s = makeState([task("c", [], { attempts: 3 }), task("d", ["0xc"])]);
  const [c, p] = s.tasks;
  submitAnalysis(s, "alice", c, named("guess", "low"));
  c.state = "done";
  c.attempts = 3;
  assert.equal(needsRefinement(s, c), false, "no named caller yet");
  submitAnalysis(s, "bob", p, named("parent_fn"));
  assert.equal(p.state, "done");
  assert.equal(c.refined, true);
  assert.equal(c.state, "open");
  assert.equal(c.attempts, 1);
  assert.ok(c.doneBy?.includes("alice"));
  assert.equal(claimTask(s, "alice"), null, "same person does not repeat it");
  assert.equal(claimTask(s, "carol")?.id, c.id);
  c.state = "done";
  assert.equal(scheduleRefinement(s), 0, "never reopened twice");
});

test("refinement waits while other work is open", () => {
  const s = makeState([task("c", [], { state: "done" }), task("d", ["0xc"]), task("1", [])]);
  submitAnalysis(s, "bob", s.tasks[1], named("parent_fn"));
  assert.equal(s.tasks[0].refined, undefined);
  assert.equal(s.tasks[0].state, "done");
});

test("duplicate names are rejected, own retries are fine", () => {
  const s = makeState([task("a", []), task("b", []), known("e", "Taken_Known")]);
  const [a, b] = s.tasks;
  submitAnalysis(s, "alice", a, named("shared_name"));
  const r = submitAnalysis(s, "bob", b, named("SHARED_name"));
  assert.equal(r[0].ok, false);
  assert.equal(r[0].status, "rejected");
  assert.equal(r[0].reason, DUPLICATE_NAME);
  assert.equal(r[1].ok, true, "other notes are unaffected");
  const k = submitAnalysis(s, "bob", b, named("taken_known"));
  assert.equal(k[0].reason, DUPLICATE_NAME);
  s.tasks[0].state = "claimed";
  const again = submitAnalysis(s, "carol", a, named("shared_name"));
  assert.equal(again[0].ok, true, "same task may reuse its own name");
});

test("alternatives are cleaned and stored", () => {
  assert.deepEqual(cleanAlternatives(["good_a", "good_a", "bad name", 5, "Main", "x1", "x2", "x3"], "main"), ["good_a", "x1", "x2"]);
  assert.deepEqual(cleanAlternatives("nope", "m"), []);
  const s = makeState([task("a", [])]);
  submitAnalysis(s, "alice", s.tasks[0], named("main_fn", "medium"), new Date(), ["alt_one", "main_fn", "alt two"]);
  assert.deepEqual(s.proposals[0].alternatives, ["alt_one"]);
});

test("reviewers prefer a proposal from a different model, but fall back", () => {
  const s = makeState([task("a", []), task("b", []), task("c", [])]);
  submitAnalysis(s, "alice", s.tasks[0], named("name_a", "medium", "claude"));
  submitAnalysis(s, "bob", s.tasks[1], named("name_b", "medium", "gpt"));
  submitAnalysis(s, "dave", s.tasks[2], named("name_c", "low", "gpt"));
  const authorOf = (t: Task | null) => (t ? s.proposals.find((p) => p.id === t.proposalId)?.author : undefined);
  // eve has no known model: first takeable review; she hands it back.
  const first = claimTask(s, "eve")!;
  assert.equal(authorOf(first), "alice");
  first.state = "open";
  delete first.claimedBy;
  delete first.leaseUntil;
  // dave last used gpt: he gets alice's (claude) review although bob's is also takeable.
  assert.equal(authorOf(claimTask(s, "dave")), "alice");
  // frank used claude: prefers bob's gpt proposal.
  s.notes.push({ ...s.notes[0], author: "frank", model: "claude", id: "x" });
  assert.equal(authorOf(claimTask(s, "frank")), "bob");
});

test("reviewer with the same model as the only available author still gets the review", () => {
  const s = makeState([task("a", [])]);
  submitAnalysis(s, "bob", s.tasks[0], named("name_b", "medium", "gpt"));
  s.notes.push({ ...s.notes[0], author: "gina", model: "GPT", id: "y" });
  const rv = claimTask(s, "gina");
  assert.equal(rv?.kind, "review");
});
