import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { State } from "../src/types.ts";

const root = mkdtempSync(join(tmpdir(), "worker-callers-"));
process.env.REA_POOL_CACHE = join(root, "cache");
const { cachePathFor, clearDumpMemo } = await import("../src/prepare.ts");
const { markKnownFromDump, analyzePrompt, reviewPrompt } = await import("../src/agent.ts");
const { cleanAlternatives } = await import("../src/rules.ts");

const target = join(root, "prog.bin");
writeFileSync(target, "fake program");
const names: Record<string, string> = {
  "0x401000": "strlen_like",
  "0x401100": "FUN_00401100",
  "0x401200": "thunk_FUN_00401200",
  "0x401300": "sub_401300",
  "0x401400": "deadbeef",
  "0x401500": "entry",
  "0x401600": "real_one",
  "0x401700": "has_progress",
  "0x401800": "claimed_one",
};
const { dir, dumpFile, metaFile } = cachePathFor(target);
mkdirSync(dir, { recursive: true });
writeFileSync(dumpFile, Object.entries(names).map(([address, name]) => JSON.stringify({ address, name, code: "void f(void) {}", callees: [] })).join("\n") + "\n");
writeFileSync(metaFile, JSON.stringify({ sha256: createHash("sha256").update("fake program").digest("hex"), functions: 9 }));
clearDumpMemo();

const task = (address: string, extra: object = {}) => ({ id: `fn-${address}`, kind: "analyze" as const, label: address, address, state: "open" as const, attempts: 1, ...extra });
function makeState(): State {
  return {
    project: {},
    joinCode: "jc",
    contributors: [],
    tasks: Object.keys(names).map((a) =>
      a === "0x401700" ? task(a, { doneBy: ["bob"] }) : a === "0x401800" ? task(a, { state: "claimed", claimedBy: "al" }) : task(a),
    ),
    notes: [],
    proposals: [],
  } as unknown as State;
}

test("markKnownFromDump marks real names and skips placeholders and touched tasks", () => {
  const state = makeState();
  assert.equal(markKnownFromDump(state, target), 2);
  const byAddr = (a: string) => state.tasks.find((t) => t.address === a) as any;
  assert.deepEqual(byAddr("0x401000").known, { name: "strlen_like", source: "ghidra" });
  assert.equal(byAddr("0x401000").state, "done");
  assert.equal(byAddr("0x401600").state, "done");
  for (const a of ["0x401100", "0x401200", "0x401300", "0x401400", "0x401500"]) {
    assert.equal(byAddr(a).known, undefined);
    assert.equal(byAddr(a).state, "open");
  }
  assert.equal(byAddr("0x401700").known, undefined);
  assert.equal(byAddr("0x401800").state, "claimed");
});

test("a task with a note is left alone", () => {
  const state = makeState();
  (state as any).notes.push({ id: "n1", taskId: "fn-0x401000" });
  assert.equal(markKnownFromDump(state, target), 1);
  assert.equal(state.tasks[0].state, "open");
});

test("keepNamed and a missing dump mark nothing", () => {
  assert.equal(markKnownFromDump(makeState(), target, { keepNamed: true }), 0);
  assert.equal(markKnownFromDump(makeState(), join(root, "nothing.bin")), 0);
});

test("prompts are unchanged without callers and show them with callers", () => {
  const callers = [{ address: "0x401000", name: "main_loop" }];
  assert.equal(analyzePrompt("x", [], {}, []), analyzePrompt("x"));
  assert.ok(!analyzePrompt("x").includes("<callers>"));
  assert.ok(analyzePrompt("x", [], {}, callers).includes("<callers>\n0x401000: main_loop\n</callers>"));
  const notes = [{ kind: "function_name", value: "foo" }];
  assert.equal(reviewPrompt("x", notes, [], []), reviewPrompt("x", notes));
  assert.ok(!reviewPrompt("x", notes).includes("<callers>"));
  assert.ok(reviewPrompt("x", notes, [], callers).includes("0x401000: main_loop"));
  assert.ok(analyzePrompt("x").includes('"alternatives"'));
});

test("cleanAlternatives keeps valid distinct names, drops the primary, max 3", () => {
  assert.deepEqual(cleanAlternatives(["a_b", "main", "a_b", "bad name", 5, "", "c", "d", "e"], "main"), ["a_b", "c", "d"]);
  assert.deepEqual(cleanAlternatives(undefined, "x"), []);
  assert.deepEqual(cleanAlternatives("nope", "x"), []);
});
