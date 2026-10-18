import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import type { State } from "../src/types.ts";
import { createInvite, createPoolServer, listInvites, loadState, revokeInvite, saveState } from "../src/server.ts";
import { NOTE_PROTOCOL } from "../src/trust.ts";

function makeState(): State {
  return {
    project: {
      schema: "rea-pool/1", name: "invites-retry", created: "",
      target: { filename: "x.bin", sha256: "00", size: 1 }, tools: [],
      rules: {
        allowedKinds: ["function_name", "comment"], maxTextLength: 500,
        maxEvidenceItems: 5, leaseMinutes: 30, protocol: NOTE_PROTOCOL,
        maxAttempts: 3, maxVotes: 5, maxContributors: 50,
      },
    },
    joinCode: "jc_secret_code", contributors: [], notes: [], proposals: [],
    tasks: [
      { id: "fn-0xa", kind: "analyze", label: "A", address: "0xa", state: "open", attempts: 1 },
      { id: "fn-0xb", kind: "analyze", label: "B", address: "0xb", state: "open", attempts: 2 },
      { id: "fn-0xc", kind: "analyze", label: "C", address: "0xc", state: "open", attempts: 1 },
    ],
  };
}

type Reply = { status: number; body: any };
type Call = (token: string | undefined, method: string, path: string, body?: unknown) => Promise<Reply>;

async function withServer(state: State, fn: (call: Call, statePath: string) => Promise<void>) {
  const dir = mkdtempSync(join(tmpdir(), "pool-invites-retry-"));
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
    await fn(call, statePath);
  } finally {
    if (server.listening) await new Promise<void>((resolve, reject) => server.close((err) => err ? reject(err) : resolve()));
    rmSync(dir, { recursive: true, force: true });
  }
}

const shared = (call: Call, name: string) => call(undefined, "POST", "/join", { code: "jc_secret_code", name });

test("an invite lets exactly one person join, under the invite's name", async () => {
  const state = makeState();
  const made = createInvite(state, "alice") as { code: string };
  assert.match(made.code, /^ji_/);
  assert.equal(JSON.stringify(state).includes(made.code), false);
  await withServer(state, async (call, statePath) => {
    assert.equal((await call(undefined, "GET", "/status")).status, 401);
    const joined = await call(undefined, "POST", "/join", { code: made.code, name: "mallory" });
    assert.equal(joined.status, 200);
    assert.equal(joined.body.name, "alice");
    const again = await call(undefined, "POST", "/join", { code: made.code, name: "bob" });
    assert.equal(again.status, 403);
    const status = await call(joined.body.token, "GET", "/status");
    assert.equal(status.body.invitesPending, 0);
    assert.ok(loadState(statePath).invites![0].usedAt);
  });
});

test("a revoked invite fails, and duplicates are rejected", () => {
  const state = makeState();
  const made = createInvite(state, "carol") as { code: string };
  assert.ok("error" in createInvite(state, "carol"));
  assert.ok("error" in createInvite(state, "bad name!"));
  assert.deepEqual(listInvites(state).map((i) => [i.name, i.used]), [["carol", false]]);
  assert.equal(revokeInvite(state, "carol"), true);
  assert.equal(revokeInvite(state, "carol"), false);
  return withServer(state, async (call) => {
    assert.equal((await call(undefined, "POST", "/join", { code: made.code, name: "carol" })).status, 403);
  });
});

test("an existing contributor name cannot be invited", async () => {
  const state = makeState();
  await withServer(state, async (call, statePath) => {
    assert.equal((await shared(call, "dave")).status, 200);
    const s = loadState(statePath);
    assert.ok("error" in createInvite(s, "dave"));
  });
});

test("the shared code is refused when sharedCodeOff", async () => {
  const state = makeState();
  state.sharedCodeOff = true;
  await withServer(state, async (call) => {
    const r = await shared(call, "erin");
    assert.equal(r.status, 403);
    assert.equal(r.body.error, "That join code is not right.");
  });
});

test("retry preference: listed model gets retries first, others last, nobody starves", async () => {
  const state = makeState();
  state.project.rules.retryModels = ["Strong-Model"];
  await withServer(state, async (call) => {
    const strong = (await shared(call, "strong")).body.token;
    const weak = (await shared(call, "weak")).body.token;
    const s1 = await call(strong, "POST", "/claim", { model: "strong-model" });
    assert.equal(s1.body.task.id, "fn-0xb");
    const w1 = await call(weak, "POST", "/claim", { model: "other" });
    assert.equal(w1.body.task.id, "fn-0xa");
    await call(weak, "POST", "/release", {});
    const w2 = await call(weak, "POST", "/claim", { model: "other" });
    assert.ok(w2.body.task);
    assert.notEqual(w2.body.task.id, "fn-0xb");
  });
  // With only a retry left, an unlisted model still gets it.
  const only = makeState();
  only.project.rules.retryModels = ["Strong-Model"];
  only.tasks = [only.tasks[1]];
  await withServer(only, async (call) => {
    const t = (await shared(call, "weak")).body.token;
    assert.equal((await call(t, "POST", "/claim", { model: "other" })).body.task.id, "fn-0xb");
  });
});

test("without retryModels the order is unchanged", async () => {
  await withServer(makeState(), async (call) => {
    const t = (await shared(call, "plain")).body.token;
    assert.equal((await call(t, "POST", "/claim", {})).body.task.id, "fn-0xa");
  });
});

test("/claim saves a valid model label and ignores an invalid one", async () => {
  await withServer(makeState(), async (call, statePath) => {
    const t = (await shared(call, "frank")).body.token;
    await call(t, "POST", "/claim", { model: "claude-opus-4" });
    assert.equal(loadState(statePath).contributors[0].model, "claude-opus-4");
    await call(t, "POST", "/claim", { model: "bad model!!" });
    assert.equal(loadState(statePath).contributors[0].model, "claude-opus-4");
  });
});

test("loadState adds the default kinds once", async () => {
  await withServer(makeState(), async (_call, statePath) => {
    const kinds = loadState(statePath).project.rules.allowedKinds;
    for (const k of ["function_name", "comment", "variable_name", "signature", "struct_def"]) assert.ok(kinds.includes(k));
    assert.equal(kinds.length, 5);
    assert.deepEqual(loadState(statePath).invites, []);
  });
});
