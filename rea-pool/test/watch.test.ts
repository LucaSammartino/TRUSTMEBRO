import { test } from "node:test";
import assert from "node:assert/strict";
import { renderActivity } from "../src/watch.ts";
import type { Activity } from "../src/activity.ts";

const base = (over: Partial<Activity> = {}): Activity => ({
  project: "demo", generatedAt: "2026-01-01T12:00:00Z",
  totals: { functions: 10, done: 5, inProgress: 2, waiting: 3, percentDone: 50 },
  results: { trusted: 4, pending: 1, hints: 0, rejected: 2 },
  people: [{ name: "ann", analyses: 3, checks: 2, trusted: 1, working: true, you: true }, { name: "bob", analyses: 1, checks: 0, trusted: 0, working: false, you: false }],
  recent: Array.from({ length: 12 }, (_, i) => ({ at: new Date(2026, 0, 1, 10, i).toISOString(), who: "ann", what: `did thing ${i}` })),
  throughputPerHour: 3, ...over,
});

test("bar scales with width", () => {
  const count = (w: number) => (renderActivity(base(), { width: w }).match(/#/g) ?? []).length;
  assert.ok(count(100) > count(40));
  assert.ok(count(40) > 0);
});

test("plain output has no escape bytes and shows content", () => {
  const out = renderActivity(base());
  assert.ok(!out.includes("\x1b"));
  assert.match(out, /50%/);
  assert.match(out, /5 of 10/);
  assert.match(out, /working, you/);
  assert.equal(out.split("\n").filter((l) => /did thing/.test(l)).length, 8);
  assert.match(out, /\d\d:\d\d {2}ann did thing/);
});

test("colour only when asked", () => {
  assert.ok(renderActivity(base(), { color: true }).includes("\x1b["));
});

test("hostile text is neutralised", () => {
  const evil = "x\x1b[2Jy\nz\x1b]0;title\x07w\x07";
  const out = renderActivity(base({ project: evil, people: [{ name: evil, analyses: 0, checks: 0, trusted: 0, working: false, you: false }], recent: [{ at: "2026-01-01T10:00:00Z", who: evil, what: evil }] }));
  assert.ok(!/[\x00-\x09\x0b-\x1f\x7f]/.test(out));
  assert.ok(!out.includes("[2J"));
  const colored = renderActivity(base({ recent: [{ at: "2026-01-01T10:00:00Z", who: "a", what: evil }] }), { color: true });
  assert.ok(!colored.includes("\x1b[2J"));
});

test("lines are truncated to width", () => {
  const long = "q".repeat(300);
  const out = renderActivity(base({ recent: [{ at: "2026-01-01T10:00:00Z", who: long, what: long }] }), { width: 50 });
  for (const l of out.split("\n")) assert.ok(l.length <= 50, l);
});
