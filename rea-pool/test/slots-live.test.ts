import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import type { State } from "../src/types.ts";
import { createPoolServer, loadState, saveState } from "../src/server.ts";
import { NOTE_PROTOCOL } from "../src/trust.ts";

function makeState(): State {
  return {
    project: {
      schema: "rea-pool/1", name: "slots-live", created: "",
      target: { filename: "x.bin", sha256: "00", size: 1 }, tools: [],
      rules: {
        allowedKinds: ["function_name", "comment"], maxTextLength: 500,
        maxEvidenceItems: 5, leaseMinutes: 30, protocol: NOTE_PROTOCOL,
        maxAttempts: 3, maxVotes: 5, maxContributors: 50,
      },
    },
    joinCode: "jc_secret_code", contributors: [], notes: [], proposals: [],
    tasks: ["0xa", "0xb", "0xc", "0xd"].map((address) => ({
      id: `fn-${address}`, kind: "analyze", label: `Function ${address}`,
      address, state: "open", attempts: 1,
    })),
  };
}

const notes = (name: string) => [
  { kind: "function_name", value: name, confidence: "high" },
  { kind: "comment", value: "Processes the input.", confidence: "high" },
];

type Reply = { status: number; headers: Headers; text: string; body: any };
type Call = (token: string | undefined, method: string, path: string, body?: unknown) => Promise<Reply>;

async function withServer(state: State, fn: (call: Call, statePath: string) => Promise<void>) {
  const dir = mkdtempSync(join(tmpdir(), "pool-slots-live-"));
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
      return { status: res.status, headers: res.headers, text, body: parsed };
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
  const joined = await call(undefined, "POST", "/join", { code: "jc_secret_code", name });
  assert.equal(joined.status, 200);
  return joined.body.token;
}

test("GET /live needs no token and is locked down by a CSP", async () => {
  await withServer(makeState(), async (call) => {
    const live = await call(undefined, "GET", "/live");
    assert.equal(live.status, 200);
    assert.match(live.headers.get("content-type") ?? "", /text\/html/);
    assert.equal(
      live.headers.get("content-security-policy"),
      "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'",
    );
    assert.equal(live.headers.get("cache-control"), "no-store");
    assert.ok(live.text.includes("/activity"));
  });
});

test("GET /activity needs a token and leaks no join code", async () => {
  await withServer(makeState(), async (call) => {
    assert.equal((await call(undefined, "GET", "/activity")).status, 401);
    const alice = await joinPool(call, "alice");
    const activity = await call(alice, "GET", "/activity");
    assert.equal(activity.status, 200);
    assert.equal(activity.body.totals.functions, 4);
    assert.ok(!activity.text.includes("jc_secret_code"));
  });
});

test("two slots give two different tasks and both can be submitted", async () => {
  await withServer(makeState(), async (call, statePath) => {
    const alice = await joinPool(call, "alice");
    const a = await call(alice, "POST", "/claim", { slot: 0 });
    const b = await call(alice, "POST", "/claim", { slot: 1 });
    assert.equal(a.status, 200);
    assert.equal(b.status, 200);
    assert.ok(a.body.task && b.body.task);
    assert.notEqual(a.body.task.id, b.body.task.id);
    const again = await call(alice, "POST", "/claim", { slot: 0 });
    assert.equal(again.body.task.id, a.body.task.id);
    const again1 = await call(alice, "POST", "/claim", { slot: 1 });
    assert.equal(again1.body.task.id, b.body.task.id);

    // Submitting slot 0 leaves slot 1's claim alone.
    const first = await call(alice, "POST", "/submit", { protocol: NOTE_PROTOCOL, taskId: a.body.task.id, notes: notes("one") });
    assert.equal(first.status, 200);
    const mid = loadState(statePath).tasks.find((t) => t.id === b.body.task.id)!;
    assert.equal(mid.state, "claimed");
    assert.equal(mid.claimedBy, "alice");
    assert.equal(mid.claimSlot, 1);
    const status = await call(alice, "GET", "/status");
    assert.equal(status.body.finished, false);

    const second = await call(alice, "POST", "/submit", { protocol: NOTE_PROTOCOL, taskId: b.body.task.id, notes: notes("two") });
    assert.equal(second.status, 200);
  });
});

test("slot out of range is refused; no body still means slot 0", async () => {
  await withServer(makeState(), async (call) => {
    const alice = await joinPool(call, "alice");
    const bad = await call(alice, "POST", "/claim", { slot: 9 });
    assert.equal(bad.status, 400);
    assert.equal((await call(alice, "POST", "/claim", { slot: -1 })).status, 400);
    assert.equal((await call(alice, "POST", "/claim", { slot: 1.5 })).status, 400);
    const old = await call(alice, "POST", "/claim");
    assert.equal(old.status, 200);
    assert.ok(old.body.task);
    const same = await call(alice, "POST", "/claim", { slot: 0 });
    assert.equal(same.body.task.id, old.body.task.id);
  });
});

test("releasing one taskId keeps the other claim", async () => {
  await withServer(makeState(), async (call, statePath) => {
    const alice = await joinPool(call, "alice");
    const a = await call(alice, "POST", "/claim", { slot: 0 });
    const b = await call(alice, "POST", "/claim", { slot: 1 });
    const released = await call(alice, "POST", "/release", { taskId: a.body.task.id, note: "Tried the obvious things; the callee is unclear." });
    assert.equal(released.status, 200);
    assert.equal(released.body.released, 1);
    const tasks = loadState(statePath).tasks;
    assert.equal(tasks.find((t) => t.id === a.body.task.id)!.state, "open");
    assert.equal(tasks.find((t) => t.id === a.body.task.id)!.claimSlot, undefined);
    const kept = tasks.find((t) => t.id === b.body.task.id)!;
    assert.equal(kept.state, "claimed");
    assert.equal(kept.claimedBy, "alice");

    // Without a taskId everything of this person's is released.
    const all = await call(alice, "POST", "/release", { note: "Giving up." });
    assert.equal(all.body.released, 1);
  });
});
