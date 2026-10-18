import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import type { AddressInfo } from "node:net";
import { runMcpServer } from "../src/mcp.ts";

const TOKEN = "tok_secret_value";

async function withLeader(fn: (ctl: { fail409: boolean; submitted: unknown[] }) => Promise<void>) {
  const ctl = { fail409: false, submitted: [] as unknown[] };
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {};
    const send = (code: number, data: object) => {
      res.writeHead(code, { "content-type": "application/json" });
      res.end(JSON.stringify(data));
    };
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return send(401, { error: "Not recognized." });
    const route = `${req.method} ${req.url}`;
    if (route === "POST /claim") return send(200, { task: { id: "t1", kind: "analyze", address: "0x10" }, callees: [{ address: "0x20", name: "helper" }], handoff: [{ text: "tried X" }], twins: [], finished: false });
    if (route === "POST /submit") {
      if (ctl.fail409) return send(409, { error: "You do not hold a current claim on that task. Claim a task first." });
      ctl.submitted.push(body);
      return send(200, { results: [{ status: "pending" }, { status: "pending" }] });
    }
    if (route === "POST /release") return send(200, { ok: true, released: 1, noted: true });
    if (route === "GET /status") return send(200, { tasks: { open: 1, claimed: 1, done: 0 }, trusted: 0, pending: 0, hints: 0, rejected: 0, yourProposals: 0, finished: false });
    if (route === "GET /project") return send(200, { project: { name: "p" }, you: "me" });
    send(404, { error: "Unknown request." });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const dir = mkdtempSync(join(tmpdir(), "mcp-test-"));
  const cfg = join(dir, "config.json");
  writeFileSync(cfg, JSON.stringify({ leaderUrl: url, token: TOKEN, name: "me", targetPath: "x.bin" }));
  process.env.REA_POOL_CONFIG = cfg;
  try {
    await fn(ctl);
  } finally {
    server.close();
    server.closeAllConnections();
  }
}

/** Send lines to the server, close input, and return the parsed output lines (plus the raw text). */
async function drive(lines: string[]): Promise<{ replies: any[]; raw: string }> {
  const input = new PassThrough();
  const output = new PassThrough();
  let raw = "";
  output.on("data", (d) => (raw += d));
  const done = runMcpServer(input, output, () => ({ code: "int f() { return 1; }", callees: ["0x20"], shape: null }));
  for (const l of lines) input.write(l + "\n");
  input.end();
  await done;
  return { replies: raw.split("\n").filter(Boolean).map((l) => JSON.parse(l)), raw };
}

const rpc = (id: number, method: string, params?: object) => JSON.stringify({ jsonrpc: "2.0", id, method, params });
const call = (id: number, name: string, args: object = {}) => rpc(id, "tools/call", { name, arguments: args });

test("initialize, ping, tools/list, unknown method, notification", async () => {
  const { replies } = await drive([
    rpc(1, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } }),
    JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
    rpc(2, "ping"),
    rpc(3, "tools/list"),
    rpc(4, "nope/whatever"),
  ]);
  assert.equal(replies.length, 4); // the notification got no reply
  assert.equal(replies[0].result.protocolVersion, "2025-06-18");
  assert.deepEqual(replies[0].result.serverInfo, { name: "rea-pool", version: "0.3.0" });
  assert.deepEqual(replies[0].result.capabilities, { tools: {} });
  assert.deepEqual(replies[1].result, {});
  const tools = replies[2].result.tools;
  assert.deepEqual(tools.map((t: any) => t.name).sort(), ["pool_next", "pool_release", "pool_status", "pool_submit", "pool_verdict"]);
  for (const t of tools) {
    assert.equal(t.inputSchema.type, "object");
    assert.match(t.description, /untrusted/);
  }
  assert.equal(replies[3].error.code, -32601);
});

test("next -> submit round trip, status and release", async () => {
  await withLeader(async (ctl) => {
    const { replies, raw } = await drive([
      call(1, "pool_next"),
      call(2, "pool_submit", { name: "parse_header", summary: "Parses the file header.", confidence: "medium" }),
      call(3, "pool_status"),
      call(4, "pool_release", { note: "nothing" }),
    ]);
    const next = replies[0].result;
    assert.equal(next.isError, false);
    const payload = JSON.parse(next.content[0].text);
    assert.deepEqual(payload.task, { id: "t1", kind: "analyze", address: "0x10" });
    assert.match(payload.code, /return 1/);
    assert.deepEqual(payload.earlier_attempts, ["tried X"]);
    assert.match(payload.note, /untrusted/);

    assert.equal(replies[1].result.isError, false);
    assert.match(replies[1].result.content[0].text, /waiting for an independent check/);
    const sent = ctl.submitted[0] as any;
    assert.equal(sent.taskId, "t1");
    assert.equal(sent.notes[0].value, "parse_header");
    assert.equal(sent.notes[0].confidence, "medium");

    assert.equal(JSON.parse(replies[2].result.content[0].text).tasks.open, 1);
    assert.match(replies[3].result.content[0].text, /Released/);
    assert.ok(!raw.includes(TOKEN), "token must never be output");
  });
});

test("leader 409 comes back as isError with a plain message", async () => {
  await withLeader(async (ctl) => {
    ctl.fail409 = true;
    const { replies } = await drive([call(1, "pool_submit", { name: "a_b", summary: "Does it.", confidence: "high" }), call(2, "pool_verdict", { verdict: "agree" })]);
    assert.equal(replies[0].result.isError, true);
    assert.match(replies[0].result.content[0].text, /do not hold a current claim/);
    // the fake leader's task is an analyze task, so a verdict is refused locally
    assert.equal(replies[1].result.isError, true);
    assert.match(replies[1].result.content[0].text, /not a check/);
  });
});

test("not joined is a tool error, not a crash", async () => {
  process.env.REA_POOL_CONFIG = join(mkdtempSync(join(tmpdir(), "mcp-none-")), "missing.json");
  const { replies } = await drive([call(1, "pool_status")]);
  assert.equal(replies[0].result.isError, true);
  assert.match(replies[0].result.content[0].text, /not joined/);
});

test("malformed JSON gives -32700 and the server keeps going", async () => {
  const { replies } = await drive(["{not json", rpc(2, "ping")]);
  assert.equal(replies[0].error.code, -32700);
  assert.equal(replies[0].id, null);
  assert.deepEqual(replies[1].result, {});
});
