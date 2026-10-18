import { test } from "node:test";
import assert from "node:assert/strict";
import type { Proposal, State, Task } from "../src/types.ts";
import { buildActivity } from "../src/activity.ts";
import { LIVE_HTML } from "../src/live.ts";

const now = Date.parse("2026-10-18T12:00:00Z");
const at = (offset: number) => new Date(now + offset).toISOString();
function makeState(): State {
  return {
    project: { schema: "rea-pool/1", name: "Example", created: at(-10000), target: { filename: "x", sha256: "00", size: 1 }, tools: [],
      rules: { allowedKinds: ["function_name"], maxTextLength: 500, maxEvidenceItems: 5, leaseMinutes: 30 } },
    joinCode: "SECRET-JOIN-CODE", contributors: ["alice", "bob", "carol", "revoked"].map(name => ({ name, tokenHash: "SECRET-HASH-" + name, joined: at(-10000), revoked: name === "revoked" })),
    tasks: [], notes: [], proposals: [],
  };
}
function proposal(id: string, author = "alice", status: Proposal["status"] = "trusted", time = at(-1000)): Proposal {
  return { id, taskId: "fn", author, confidence: "high", status, votes: [], at: time };
}
function task(id: string, state: Task["state"], extra: Partial<Task> = {}): Task {
  return { id, label: id, address: "0x1", state, ...extra };
}

test("function totals exclude reviews and expired claims become waiting without mutation", () => {
  const s = makeState();
  s.tasks = [task("done", "done"), task("active", "claimed", { claimedBy: "alice", leaseUntil: at(1) }),
    task("expired", "claimed", { claimedBy: "bob", leaseUntil: at(0) }), task("open", "open"),
    task("review", "done", { kind: "review" })];
  const before = JSON.stringify(s);
  const a = buildActivity(s, now, "alice");
  assert.deepEqual(a.totals, { functions: 4, done: 1, inProgress: 1, waiting: 2, percentDone: 25 });
  assert.equal(a.people.find(p => p.name === "alice")?.working, true);
  assert.equal(a.people.find(p => p.name === "bob")?.working, false);
  assert.equal(a.people.find(p => p.name === "alice")?.you, true);
  assert.equal(a.project, "Example");
  assert.equal(a.generatedAt, at(0));
  assert.equal(JSON.stringify(s), before);
  assert.equal(buildActivity(makeState(), now).totals.percentDone, 0);
  s.tasks = [task("a", "done"), task("b", "open"), task("c", "open")];
  assert.equal(buildActivity(s, now).totals.percentDone, 33);
});

test("results and people count proposals and votes, sort by contribution, and omit revoked people", () => {
  const s = makeState();
  s.proposals = [proposal("a"), proposal("b", "bob", "pending"), proposal("c", "revoked", "hint"), proposal("d", "bob", "rejected")];
  s.proposals[0].votes = [{ by: "bob", verdict: "agree", at: at(-500) }, { by: "carol", verdict: "unsure", at: at(-400) }];
  s.tasks = [task("review", "claimed", { kind: "review", claimedBy: "carol" })];
  const a = buildActivity(s, now, "bob");
  assert.deepEqual(a.results, { trusted: 1, pending: 1, hints: 1, rejected: 1 });
  assert.deepEqual(a.people.map(p => p.name), ["bob", "alice", "carol"]);
  assert.deepEqual(a.people[0], { name: "bob", analyses: 2, checks: 1, trusted: 0, working: false, you: true });
  assert.equal(a.people[1].trusted, 1);
  assert.equal(a.people[2].working, true);
  const json = JSON.stringify(a);
  assert.ok(!json.includes(s.joinCode));
  for (const c of s.contributors) assert.ok(!json.includes(c.tokenHash));
});

test("recent events use names and statuses and sort proposals and all verdicts newest first", () => {
  const s = makeState();
  const p = proposal("p");
  p.votes = [ { by: "bob", verdict: "agree", at: at(-300) }, { by: "carol", verdict: "disagree", at: at(-200) }, { by: "bob", verdict: "unsure", at: at(-100) } ];
  s.proposals = [p, proposal("other", "carol", "pending", at(-2000))];
  s.notes = [{ id: "n", proposalId: "p", taskId: "fn", author: "alice", kind: "function_name", value: "foo_bar", evidence: [], confidence: "high", model: "test", at: p.at, status: "trusted" }];
  const recent = buildActivity(s, now).recent;
  assert.deepEqual(recent.map(e => e.at), [-100, -200, -300, -1000, -2000].map(at));
  assert.deepEqual(recent.map(e => e.what), ['was unsure about the name "foo_bar"', 'disagreed with the name "foo_bar"', 'agreed with the name "foo_bar"', 'named a function "foo_bar" (trusted)', 'submitted an analysis (pending)']);
});

test("recent caps at 30 while throughput counts all events within the last hour", () => {
  const s = makeState();
  s.proposals = Array.from({ length: 35 }, (_, i) => proposal(String(i), "alice", "trusted", at(-i * 1000)));
  s.proposals.push(proposal("boundary", "alice", "hint", at(-3600000)), proposal("old", "alice", "pending", at(-3600001)), proposal("future", "alice", "pending", at(1)));
  s.proposals[36].votes.push({ by: "bob", verdict: "agree", at: at(-200) });
  const a = buildActivity(s, now);
  assert.equal(a.recent.length, 30);
  assert.equal(a.recent[0].at, at(1));
  assert.equal(a.throughputPerHour, 37);
  assert.ok(a.recent.every((event, i, events) => !i || Date.parse(events[i - 1].at) >= Date.parse(event.at)));
});

test("live page is self-contained and uses safe DOM insertion", () => {
  assert.ok(LIVE_HTML.includes("/activity"));
  assert.ok(!LIVE_HTML.includes("innerHTML"));
  assert.ok(!/https?:\/\//i.test(LIVE_HTML));
  assert.ok(LIVE_HTML.includes("textContent"));
  assert.ok(LIVE_HTML.includes("sessionStorage"));
});
