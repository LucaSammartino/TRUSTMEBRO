import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { appendOutbox, flushOutbox, importState, OUTBOX_CAP, readOutbox, validLeaderUrl, type SendResult } from "../src/handover.ts";

const tmp = () => mkdtempSync(join(tmpdir(), "outbox-"));

test("append and read keep order, and leave no temp file", () => {
  const p = join(tmp(), "o.json");
  assert.deepEqual(readOutbox(p), []);
  appendOutbox(p, { n: 1 });
  appendOutbox(p, { n: 2 });
  assert.deepEqual(readOutbox(p), [{ n: 1 }, { n: 2 }]);
  assert.equal(existsSync(p + ".tmp"), false);
});

test("the outbox keeps at most 200 items (newest)", () => {
  const p = join(tmp(), "o.json");
  for (let i = 0; i < OUTBOX_CAP + 5; i++) appendOutbox(p, i);
  const items = readOutbox(p);
  assert.equal(items.length, OUTBOX_CAP);
  assert.equal(items[0], 5);
  assert.equal(items.at(-1), OUTBOX_CAP + 4);
});

test("a corrupt outbox counts as empty and can be written again", () => {
  const p = join(tmp(), "o.json");
  writeFileSync(p, "{not json");
  assert.deepEqual(readOutbox(p), []);
  appendOutbox(p, "a");
  assert.deepEqual(readOutbox(p), ["a"]);
  writeFileSync(p, '{"a":1}');
  assert.deepEqual(readOutbox(p), []);
});

test("flush removes sent and refused items, in order", async () => {
  const p = join(tmp(), "o.json");
  for (const n of [1, 2, 3]) appendOutbox(p, n);
  const seen: unknown[] = [];
  const r = await flushOutbox(p, async (b) => {
    seen.push(b);
    return b === 2 ? "refused" : "sent";
  });
  assert.deepEqual(seen, [1, 2, 3]);
  assert.deepEqual(r, { sent: 2, refused: 1, left: 0 });
  assert.deepEqual(readOutbox(p), []);
});

test("flush keeps items on a network failure and stops there", async () => {
  const p = join(tmp(), "o.json");
  for (const n of [1, 2, 3, 4]) appendOutbox(p, n);
  const seen: unknown[] = [];
  const r = await flushOutbox(p, async (b): Promise<SendResult> => {
    seen.push(b);
    return b === 3 ? "offline" : "sent";
  });
  assert.deepEqual(seen, [1, 2, 3]);
  assert.deepEqual(r, { sent: 2, refused: 0, left: 2 });
  assert.deepEqual(readOutbox(p), [3, 4]);
});

test("set-leader accepts only http and https addresses", () => {
  assert.equal(validLeaderUrl("http://100.64.0.5:8787"), "http://100.64.0.5:8787");
  assert.equal(validLeaderUrl(" https://pool.example.com "), "https://pool.example.com");
  for (const bad of [undefined, "", "pool.example.com", "ftp://x", "file:///etc/passwd", "javascript:alert(1)", "http://"]) assert.equal(validLeaderUrl(bad), null);
});

test("import-state validates the file and refuses an existing project", () => {
  const dir = tmp();
  const good = join(dir, "export.json");
  writeFileSync(good, JSON.stringify({ project: { name: "p" }, tasks: [], contributors: [], notes: [] }));
  const data = join(dir, "data");

  assert.ok("error" in importState(join(dir, "missing.json"), data));
  const bad = join(dir, "bad.json");
  writeFileSync(bad, "nope");
  assert.ok("error" in importState(bad, data));
  writeFileSync(bad, JSON.stringify({ project: {}, tasks: [] }));
  assert.ok("error" in importState(bad, data));
  assert.equal(existsSync(join(data, "state.json")), false);

  assert.deepEqual(importState(good, data), { ok: true });
  assert.equal(JSON.parse(readFileSync(join(data, "state.json"), "utf8")).project.name, "p");

  const again = importState(good, data);
  assert.ok("error" in again && /already has a project/.test(again.error));
  assert.deepEqual(importState(good, data, true), { ok: true });
});
