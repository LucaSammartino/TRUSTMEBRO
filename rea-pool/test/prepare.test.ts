import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildAnalyzeCommand, cachePathFor, clearDumpMemo, loadDump, lookupFunction, prepareTarget, sha256FileSync } from "../src/prepare.ts";

function setup() {
  const root = mkdtempSync(join(tmpdir(), "prep-test-"));
  process.env.REA_POOL_CACHE = join(root, "cache");
  delete process.env.GHIDRA_INSTALL_DIR;
  clearDumpMemo();
  const target = join(root, "t.dll");
  writeFileSync(target, "binary-one");
  return { root, target };
}

function fakeCache(target: string, sha = sha256FileSync(target)) {
  const p = cachePathFor(target);
  mkdirSync(p.dir, { recursive: true });
  const rows = [
    { address: "0x65b886b0", name: "f1", code: "int f1(){}", callees: ["0x10"] },
    { address: "0x10", name: "f2", code: "void f2(){}", callees: [] },
  ];
  writeFileSync(p.dumpFile, rows.map((r) => JSON.stringify(r)).join("\n") + "\nnot json{\n");
  writeFileSync(p.metaFile, JSON.stringify({ sha256: sha, functions: 2 }));
}

test("buildAnalyzeCommand per platform", () => {
  const base = { ghidraDir: "/g", projectDir: "/p", targetPath: "/t.dll", scriptDir: "/s", outFile: "/o" };
  const w = buildAnalyzeCommand({ ...base, platform: "win32" });
  assert.match(w.program, /analyzeHeadless\.bat$/);
  const l = buildAnalyzeCommand({ ...base, platform: "linux" });
  assert.match(l.program, /analyzeHeadless$/);
  assert.ok(l.args.includes("-postScript") && l.args.includes("DumpAll.java") && l.args.includes("-deleteProject"));
  assert.ok(l.args.includes("/o") && l.args.includes("/t.dll"));
});

test("cachePathFor follows content", () => {
  const { root, target } = setup();
  try {
    const a = cachePathFor(target).dir;
    assert.equal(cachePathFor(target).dir, a);
    writeFileSync(target, "binary-two");
    clearDumpMemo();
    assert.notEqual(cachePathFor(target).dir, a);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("loadDump and lookupFunction", () => {
  const { root, target } = setup();
  try {
    assert.equal(loadDump(target), null);
    assert.equal(lookupFunction(target, "0x10"), null);
    fakeCache(target);
    clearDumpMemo();
    assert.equal(loadDump(target)?.size, 2);
    assert.equal(lookupFunction(target, "0x0065B886B0")?.name, "f1");
    assert.equal(lookupFunction(target, "0x65b886b0")?.callees[0], "0x10");
    assert.equal(lookupFunction(target, "0x99"), null);
    assert.equal(lookupFunction(target, "junk"), null);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("cache with wrong sha is ignored", () => {
  const { root, target } = setup();
  try {
    fakeCache(target, "0".repeat(64));
    assert.equal(loadDump(target), null);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("prepareTarget uses cache without Ghidra", async () => {
  const { root, target } = setup();
  try {
    fakeCache(target);
    const r = await prepareTarget(target);
    assert.equal(r.fromCache, true);
    assert.equal(r.functions, 2);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("prepareTarget without Ghidra or cache explains", async () => {
  const { root, target } = setup();
  try {
    await assert.rejects(prepareTarget(target), /Ghidra/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("DumpAll.java has its key pieces", () => {
  const src = readFileSync(new URL("../ghidra/DumpAll.java", import.meta.url), "utf8");
  for (const s of ["getCalledFunctions", "isThunk", "DUMPALL"]) assert.ok(src.includes(s), s);
});
