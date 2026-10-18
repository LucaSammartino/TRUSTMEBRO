import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import type { State } from "../src/types.ts";
import { createPoolServer, loadState, saveState, submitAnalysis } from "../src/server.ts";
import { NOTE_PROTOCOL } from "../src/trust.ts";

function makeState(): State {
  return {
    project: {
      schema: "rea-pool/1", name: "graph-http", created: "",
      target: { filename: "x.bin", sha256: "00", size: 1 }, tools: [],
      rules: {
        allowedKinds: ["function_name", "comment"], maxTextLength: 500,
        maxEvidenceItems: 5, leaseMinutes: 30, protocol: NOTE_PROTOCOL,
        maxAttempts: 3, maxVotes: 5, maxContributors: 50,
      },
    },
    joinCode: "jc_secret", contributors: [], notes: [], proposals: [],
    tasks: ["0xa", "0xb", "0xc"].map((address) => ({
      id: `fn-${address}`, kind: "analyze", label: `Function ${address}`,
      address, state: "open", attempts: 1,
    })),
  };
}

const notes = (name: string) => [
  { kind: "function_name", value: name, confidence: "high" },
  { kind: "comment", value: "Processes the input.", confidence: "high" },
];

type Call = (token: string | undefined, method: string, path: string, body?: unknown) => Promise<{ status: number; body: any }>;

async function withServer(state: State, fn: (call: Call, statePath: string) => Promise<void>) {
  const dir = mkdtempSync(join(tmpdir(), "pool-graph-http-"));
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
      return { status: res.status, body: await res.json() };
    };
    await fn(call, statePath);
  } finally {
    if (server.listening) {
      await new Promise<void>((resolve, reject) => server.close((err) => err ? reject(err) : resolve()));
    }
    rmSync(dir, { recursive: true, force: true });
  }
}

async function joinPool(call: Call, name: string): Promise<string> {
  const joined = await call(undefined, "POST", "/join", { code: "jc_secret", name });
  assert.equal(joined.status, 200);
  assert.equal(typeof joined.body.token, "string");
  return joined.body.token;
}

test("HTTP submissions persist normalized callees and exclude junk and self calls", async () => {
  await withServer(makeState(), async (call, statePath) => {
    const alice = await joinPool(call, "alice");
    // Repeat for fn-0xb so the same payload also exercises exclusion of 0x00B as self.
    for (const [taskId, expected] of [
      ["fn-0xa", ["0xb", "0xc"]],
      ["fn-0xb", ["0xc"]],
    ] as const) {
      const claimed = await call(alice, "POST", "/claim");
      assert.equal(claimed.status, 200);
      assert.equal(claimed.body.task.id, taskId);
      const submitted = await call(alice, "POST", "/submit", {
        protocol: NOTE_PROTOCOL, taskId: claimed.body.task.id,
        notes: notes(`process_input_${expected.length}`), callees: ["0x00B", "0xC", "junk"],
      });
      assert.equal(submitted.status, 200);
      assert.deepEqual(submitted.body.results.map((r: { status: string }) => r.status), ["trusted", "trusted"]);
      const task = loadState(statePath).tasks.find((t) => t.id === taskId);
      assert.ok(task);
      assert.deepEqual(task.callees, expected);
      assert.ok(!task.callees.includes(task.address));
    }
  });
});

test("HTTP claims include trusted callee names and prefer ready analysis tasks", async () => {
  const state = makeState();
  state.tasks[0].callees = ["0xb"];
  const results = submitAnalysis(state, "bob", state.tasks[1], notes("helper_fn"));
  assert.deepEqual(results.map((r) => r.status), ["trusted", "trusted"]);
  await withServer(state, async (call) => {
    const alice = await joinPool(call, "alice");
    const claimed = await call(alice, "POST", "/claim");
    assert.equal(claimed.status, 200);
    assert.equal(claimed.body.task.id, "fn-0xa");
    assert.deepEqual(claimed.body.callees, [{ address: "0xb", name: "helper_fn" }]);
  });
});

test("HTTP status contains numeric graph statistics", async () => {
  const state = makeState();
  state.tasks[0].callees = ["0xb"];
  state.tasks[1].callees = [];
  await withServer(state, async (call) => {
    const alice = await joinPool(call, "alice");
    const status = await call(alice, "GET", "/status");
    assert.equal(status.status, 200);
    assert.ok(status.body.graph);
    for (const key of ["known", "unknown", "edges", "ready"]) {
      assert.equal(typeof status.body.graph[key], "number", key);
    }
    assert.deepEqual(status.body.graph, { known: 2, unknown: 1, edges: 1, ready: 1 });
  });
});
