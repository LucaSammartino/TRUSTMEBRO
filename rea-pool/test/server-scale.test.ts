import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import type { State } from "../src/types.ts";
import { createPoolServer, loadState, saveState, stateWriteCount } from "../src/server.ts";
import { NOTE_PROTOCOL } from "../src/trust.ts";

function makeState(n = 4): State {
  return {
    project: {
      schema: "rea-pool/1", name: "scale", created: "",
      target: { filename: "x.bin", sha256: "00", size: 1 }, tools: [],
      rules: {
        allowedKinds: ["function_name", "comment"], maxTextLength: 500,
        maxEvidenceItems: 5, leaseMinutes: 30, protocol: NOTE_PROTOCOL,
        maxAttempts: 3, maxVotes: 5, maxContributors: 500,
      },
    },
    joinCode: "jc_secret_code", contributors: [], notes: [], proposals: [],
    tasks: Array.from({ length: n }, (_, i) => ({
      id: `fn-${i}`, kind: "analyze" as const, label: `Function ${i}`,
      address: `0x${i}`, state: "open" as const, attempts: 1,
    })),
  };
}

const notes = (name: string) => [
  { kind: "function_name", value: name, confidence: "high" },
  { kind: "comment", value: "Processes the input.", confidence: "high" },
];

type Reply = { status: number; body: any };
type Call = (token: string | undefined, method: string, path: string, body?: unknown) => Promise<Reply>;

async function withServer(state: State, fn: (call: Call, statePath: string, port: number) => Promise<void>) {
  const dir = mkdtempSync(join(tmpdir(), "pool-scale-"));
  const statePath = join(dir, "state.json");
  const server = createPoolServer(statePath);
  try {
    saveState(statePath, state);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as AddressInfo).port;
    const call: Call = async (token, method, path, body) => {
      const res = await fetch(`http://127.0.0.1:${port}${path}`, {
        method,
        headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), "content-type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      const text = await res.text();
      let parsed: any;
      try { parsed = JSON.parse(text); } catch { parsed = undefined; }
      return { status: res.status, body: parsed };
    };
    await fn(call, statePath, port);
  } finally {
    await new Promise<void>((resolve) => { server.close(() => resolve()); server.closeAllConnections(); });
    rmSync(dir, { recursive: true, force: true });
  }
}

async function joinPool(call: Call, name: string): Promise<string> {
  const joined = await call(undefined, "POST", "/join", { code: "jc_secret_code", name });
  assert.equal(joined.status, 200);
  return joined.body.token;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

test("many fast requests make fewer writes, and close leaves every change on disk", async () => {
  const before = stateWriteCount();
  let statePath = "";
  await withServer(makeState(), async (call, p) => {
    statePath = p;
    const names = Array.from({ length: 30 }, (_, i) => `user${i}`);
    for (const n of names) await joinPool(call, n);
    assert.ok(stateWriteCount() - before < names.length, `${stateWriteCount() - before} writes for ${names.length} joins`);
    assert.equal(loadState(p).contributors.length, 30);
  });
  assert.ok(statePath);
});

test("an external edit is picked up when nothing is pending", async () => {
  await withServer(makeState(2), async (call, statePath) => {
    const alice = await joinPool(call, "alice");
    await sleep(500); // let the write finish
    const s = loadState(statePath);
    s.tasks.push({ id: "fn-new", kind: "analyze", label: "New", address: "0x99", state: "open", attempts: 1 });
    saveState(statePath, s);
    const status = await call(alice, "GET", "/status");
    assert.equal(status.body.tasks.open, 3);
  });
});

test("a late submit is accepted if nobody else took the task, refused if someone did", async () => {
  await withServer(makeState(1), async (call, statePath) => {
    const alice = await joinPool(call, "alice");
    const bob = await joinPool(call, "bob");
    const a = await call(alice, "POST", "/claim", {});
    const id = a.body.task.id;
    const expire = () => {
      const s = loadState(statePath);
      s.tasks[0].leaseUntil = new Date(Date.now() - 60_000).toISOString();
      saveState(statePath, s);
    };
    await sleep(300);
    expire();
    const late = await call(alice, "POST", "/submit", { protocol: NOTE_PROTOCOL, taskId: id, notes: notes("late") });
    assert.equal(late.status, 200);

    // Second round: bob takes the expired task over, so alice's late result is refused.
    const s = loadState(statePath);
    Object.assign(s.tasks[0], { state: "open", doneBy: [] });
    saveState(statePath, s);
    await sleep(300);
    const again = await call(bob, "POST", "/claim", {});
    assert.equal(again.body.task.id, id);
    await sleep(300);
    const s2 = loadState(statePath);
    s2.tasks[0].leaseUntil = new Date(Date.now() - 60_000).toISOString();
    saveState(statePath, s2);
    const carol = await joinPool(call, "carol");
    const taken = await call(carol, "POST", "/claim", {});
    assert.equal(taken.body.task.id, id);
    const refused = await call(bob, "POST", "/submit", { protocol: NOTE_PROTOCOL, taskId: id, notes: notes("nope") });
    assert.equal(refused.status, 409);
  });
});

test("claim with wait returns early on a change and times out with null otherwise", async () => {
  await withServer(makeState(1), async (call) => {
    const alice = await joinPool(call, "alice");
    const bob = await joinPool(call, "bob");
    const a = await call(alice, "POST", "/claim", {});
    assert.ok(a.body.task);

    // Nothing for bob, and alice is mid-task, so he is not finished: he waits the full time.
    const t0 = Date.now();
    const none = await call(bob, "POST", "/claim", { wait: 1 });
    const took = Date.now() - t0;
    assert.equal(none.body.task, null);
    assert.equal(none.body.finished, false);
    assert.ok(took >= 900 && took < 2500, `waited ${took} ms`);

    // Alice gives the task back: bob's waiting claim answers early with it.
    const t1 = Date.now();
    const waiting = call(bob, "POST", "/claim", { wait: 10 });
    await sleep(300);
    await call(alice, "POST", "/release", { note: "Could not tell what this does." });
    const got = await waiting;
    assert.ok(got.body.task);
    assert.ok(Date.now() - t1 < 5000);
  });
});

test("a client that disconnects while waiting leaves no waiter behind", async () => {
  await withServer(makeState(1), async (call, statePath, port) => {
    const alice = await joinPool(call, "alice");
    const bob = await joinPool(call, "bob");
    await call(alice, "POST", "/claim", {});
    const ctl = new AbortController();
    const pending = fetch(`http://127.0.0.1:${port}/claim`, {
      method: "POST", signal: ctl.signal,
      headers: { authorization: `Bearer ${bob}`, "content-type": "application/json" },
      body: JSON.stringify({ wait: 20 }),
    }).catch(() => "aborted");
    await sleep(300);
    ctl.abort();
    assert.equal(await pending, "aborted");
    await sleep(200);
    // If a dead waiter had stayed, the release would hand the task to bob; it must stay free.
    await call(alice, "POST", "/release", { note: "Gave up on this one." });
    await sleep(200);
    assert.equal(loadState(statePath).tasks[0].state, "open");
    assert.equal(loadState(statePath).tasks[0].claimedBy, undefined);
  });
});
