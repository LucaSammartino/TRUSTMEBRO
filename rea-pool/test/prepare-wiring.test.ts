import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { State } from "../src/types.ts";

const root = mkdtempSync(join(tmpdir(), "prep-wiring-"));
process.env.REA_POOL_CACHE = join(root, "cache");
const { cachePathFor, clearDumpMemo } = await import("../src/prepare.ts");
const { fillCalleesFromDump, inspectFunction, inspectFunctionAsync } = await import("../src/agent.ts");
const { shapeOf } = await import("../src/similar.ts");

const target = join(root, "prog.bin");
const bytes = "fake program";
writeFileSync(target, bytes);
const CODE = "int main(void)\r\n{\r\n  int local_14;\r\n  local_14 = FUN_00401000(param_1, param_1 + 2);\r\n  return local_14 * 3 + 12345 + (param_1 << 4) + (param_2 >> 2) + (param_1 ^ param_2) + 99999 + (local_14 | param_2) + (local_14 & param_1) + 77777 + 88888 + 66666 + 55555;\r\n}\r\n";
const entries = [
  { address: "0x401000", name: "main", code: CODE, callees: ["0x401100", "0x401000", "junk", "0x401100"] },
  { address: "0x401100", name: "leaf", code: "void x(void) {}", callees: [] },
];
const { dir, dumpFile, metaFile } = cachePathFor(target);
mkdirSync(dir, { recursive: true });
writeFileSync(dumpFile, entries.map((e) => JSON.stringify(e)).join("\n") + "\n");
writeFileSync(metaFile, JSON.stringify({ sha256: createHash("sha256").update(bytes).digest("hex"), functions: 2 }));
clearDumpMemo();

async function withoutRea<T>(fn: () => Promise<T> | T): Promise<T> {
  const empty = mkdtempSync(join(tmpdir(), "no-rea-"));
  const saved = { PATH: process.env.PATH, Path: process.env.Path };
  process.env.PATH = empty;
  if (process.platform === "win32") process.env.Path = empty;
  try {
    return await fn();
  } finally {
    process.env.PATH = saved.PATH;
    if (saved.Path !== undefined) process.env.Path = saved.Path;
  }
}

test("inspectFunction answers from the cache without running rea", async () => {
  const got = await withoutRea(() => inspectFunction(target, "0x401000"));
  assert.equal(got.code, CODE.replace(/\r/g, "").trim());
  assert.deepEqual(got.callees, ["0x401100"]);
  assert.equal(got.shape, shapeOf(CODE));
  const again = await withoutRea(() => inspectFunctionAsync(target, "0x00401000"));
  assert.deepEqual(again.callees, ["0x401100"]);
});

test("an address missing from the cache falls through to rea", async () => {
  await withoutRea(async () => {
    assert.throws(() => inspectFunction(target, "0x999999"), /Could not start rea|rea failed/);
    await assert.rejects(inspectFunctionAsync(target, "0x999999"), /Could not start rea|rea failed/);
  });
});

test("fillCalleesFromDump fills callees and fingerprints, and skips unknown functions", () => {
  const task = (a: string, extra: object = {}) => ({ id: `fn-${a}`, kind: "analyze" as const, label: a, address: a, state: "open" as const, attempts: 1, ...extra });
  const state = {
    project: {},
    joinCode: "jc",
    contributors: [],
    tasks: [task("0x401000"), task("0x401100"), task("0x777777"), task("0x401000", { id: "dup", callees: ["0xaaa"] })],
    notes: [],
    proposals: [],
  } as unknown as State;
  const filled = fillCalleesFromDump(state, target);
  assert.equal(filled, 3);
  assert.deepEqual(state.tasks[0].callees, ["0x401100"]);
  assert.equal(state.tasks[0].shape, shapeOf(CODE));
  assert.deepEqual(state.tasks[1].callees, []);
  assert.equal(state.tasks[2].callees, undefined);
  assert.deepEqual(state.tasks[3].callees, ["0xaaa"]);
  assert.equal(fillCalleesFromDump(state, join(root, "nothing.bin")), 0);
});
