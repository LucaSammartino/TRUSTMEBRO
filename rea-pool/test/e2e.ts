// End-to-end check with the REAL rea + Ghidra on any operating system.
//   node test/e2e.ts <software-file>
// Needs Java 21, Ghidra, rea and the GHIDRA_INSTALL_DIR / JAVA_HOME settings. Uses a pretend AI.
// Optional: E2E_FUNCTIONS_OUT=<file> writes the sorted list of functions found, to compare between systems.
import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import assert from "node:assert/strict";

const fixture = resolve(process.argv[2] ?? "test/fixtures/lua54.dll");
const work = mkdtempSync(join(tmpdir(), "rea-pool-e2e-"));
const data = join(work, "pool-data");
const port = 20000 + Math.floor(Math.random() * 20000);
const env = { ...process.env, REA_POOL_CONFIG: join(work, "contributor.json") };

const node = (args: string[], timeoutMinutes = 20) =>
  execFileSync(process.execPath, args, { env, encoding: "utf8", timeout: timeoutMinutes * 60_000, maxBuffer: 256 * 1024 * 1024 });
const leader = (...args: string[]) => node(["src/leader.ts", "--data", data, ...args]);
const log = (msg: string) => console.log(`[e2e ${process.platform}] ${msg}`);

log(`creating a project from ${fixture}`);
leader("init", fixture, "--name", "e2e");

log("asking rea (Ghidra) for the function list");
const tasksFile = join(work, "tasks.json");
leader("tasks-from-rea", fixture, "--out", tasksFile);
const tasks = JSON.parse(readFileSync(tasksFile, "utf8")) as { id: string; address: string }[];
assert.ok(tasks.length > 500, `expected hundreds of functions, got ${tasks.length}`);
const sorted = tasks.map((t) => t.address).sort();
const digest = createHash("sha256").update(sorted.join("\n")).digest("hex");
log(`found ${tasks.length} functions; list fingerprint ${digest}`);
if (process.env.E2E_FUNCTIONS_OUT) writeFileSync(process.env.E2E_FUNCTIONS_OUT, `${process.platform} ${tasks.length} ${digest}\n`);

// Only hand out three tasks so the test stays short.
const some = join(work, "three.json");
writeFileSync(some, JSON.stringify(tasks.slice(5, 8)));
leader("add-tasks", some);

log(`starting the leader's server on port ${port}`);
const server = spawn(process.execPath, ["src/leader.ts", "--data", data, "serve", "--port", String(port)], { env, stdio: "ignore" });
try {
  const base = `http://127.0.0.1:${port}`;
  for (let i = 0; ; i++) {
    try {
      await fetch(`${base}/project`);
      break;
    } catch {
      if (i > 50) throw new Error("the server did not start");
      await new Promise((r) => setTimeout(r, 200));
    }
  }

  const joinCode = (JSON.parse(readFileSync(join(data, "state.json"), "utf8")) as { joinCode: string }).joinCode;
  log("a contributor joins (this also runs the setup checks)");
  console.log(node(["src/cli.ts", "join", base, joinCode, "--name", "ci", "--target", fixture]));

  log("the contributor works until nothing is left");
  console.log(node(["src/cli.ts", "run", "--ai", "node test/fake-ai.ts"]));

  const state = JSON.parse(readFileSync(join(data, "state.json"), "utf8")) as { proposals: { status: string }[]; tasks: { state: string; kind?: string }[] };
  const trusted = state.proposals.filter((p) => p.status === "trusted").length;
  assert.equal(trusted, 3, `expected 3 trusted results, got ${trusted}`);
  assert.ok(state.tasks.every((t) => t.state === "done"), "every task should be done");
  log("PASS: analysis, join, work and trusted results all worked");
} finally {
  server.kill();
}
