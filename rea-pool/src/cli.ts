#!/usr/bin/env node
// Contributor tool. Two commands do almost everything:
//   pool join <address> <join-code> --target <your copy of the software>
//   pool run
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { homedir, userInfo } from "node:os";
import { join, resolve } from "node:path";
import type { NoteStatus, Project, Task } from "./types.ts";
import { allPassed, runAllChecks } from "./check.ts";
import { NOTE_PROTOCOL } from "./trust.ts";
import { analyze, detectAi, review, type AgentContext } from "./agent.ts";

interface Config {
  leaderUrl: string;
  token: string;
  name: string;
  targetPath?: string;
  aiCommand?: string;
  model?: string;
}

const CONFIG_PATH = process.env.REA_POOL_CONFIG ?? join(homedir(), ".rea-pool.json");
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function loadConfig(): Config {
  if (!existsSync(CONFIG_PATH)) {
    console.error('You have not joined a project yet. Use the "pool join ..." line your leader sent you.');
    process.exit(1);
  }
  return JSON.parse(readFileSync(CONFIG_PATH, "utf8")) as Config;
}

function saveConfig(config: Config): void {
  writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2), { mode: 0o600 });
}

async function rawApi<T>(leaderUrl: string, method: string, path: string, token: string | undefined, body?: unknown): Promise<{ ok: boolean; data: T & { error?: string } }> {
  const send = () =>
    fetch(leaderUrl.replace(/\/$/, "") + path, {
      method,
      headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  let res: Response;
  try {
    try {
      res = await send();
    } catch {
      // A connection kept open during a long job can be closed by the server; try once more on a fresh one.
      res = await send();
    }
  } catch {
    console.error(`Could not reach the leader at ${leaderUrl}. Is the server running and are you on the right network?`);
    process.exit(1);
  }
  return { ok: res.ok, data: (await res.json().catch(() => ({}))) as T & { error?: string } };
}

async function api<T>(config: Config, method: string, path: string, body?: unknown): Promise<T> {
  const { ok, data } = await rawApi<T>(config.leaderUrl, method, path, config.token, body);
  if (!ok) {
    console.error(`The leader said: ${data.error ?? "something went wrong"}`);
    process.exit(1);
  }
  return data;
}

function parseArgs(argv: string[]) {
  const positional: string[] = [];
  const flags: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith("--")) {
      const next = argv[i + 1];
      flags[argv[i].slice(2)] = next === undefined || next.startsWith("--") ? "true" : argv[++i];
    } else positional.push(argv[i]);
  }
  return { positional, flags };
}

async function doCheck(config: Config, project: Project, quiet = false): Promise<boolean> {
  const results = await runAllChecks(project, config.targetPath);
  const ok = allPassed(results);
  if (!quiet || !ok) for (const r of results) console.log(`${r.status === "pass" ? "  OK  " : " FAIL "} ${r.name}\n        ${r.message}`);
  console.log(ok ? "\nEverything matches." : "\nFix the items marked FAIL first. Everyone must use the same setup so results can be trusted.");
  return ok;
}

function describe(status: NoteStatus, reason?: string): string {
  if (status === "trusted") return "trusted";
  if (status === "pending") return "waiting for an independent check";
  if (status === "hint") return "kept as a hint (low confidence)";
  return `rejected${reason ? ` (${reason})` : ""}`;
}

interface ClaimReply {
  task: Task | null;
  proposal?: { notes: { kind: string; value: string }[] };
  finished: boolean;
}

async function runLoop(config: Config, flags: Record<string, string>): Promise<void> {
  const { project } = await api<{ project: Project }>(config, "GET", "/project");
  if (!(await doCheck(config, project, true))) process.exit(2);

  const model = flags.model ?? config.model ?? process.env.REA_POOL_MODEL ?? "unknown";
  const aiCommand = flags.ai ?? config.aiCommand ?? process.env.REA_POOL_AI ?? detectAi(model === "unknown" ? undefined : model);
  if (!aiCommand) {
    console.error('No AI found. Install the Claude command line and sign in, or pass your own with:  pool run --ai "<command that reads a prompt on stdin and prints an answer>"');
    process.exit(1);
  }
  if (flags.ai) {
    config.aiCommand = flags.ai;
    saveConfig(config);
  }
  const ctx: AgentContext = { targetPath: config.targetPath!, aiCommand, model };
  console.log(`Running as ${config.name}. Press Ctrl+C to stop; your task goes back to the pool.\n`);

  let failures = 0;
  let waiting = false;
  let done = 0;
  while (true) {
    const claim = await api<ClaimReply>(config, "POST", "/claim");
    if (!claim.task) {
      if (claim.finished) {
        console.log(`\nNothing left to do. You finished ${done} task(s). Thank you!`);
        return;
      }
      if (!waiting) console.log("Waiting for other contributors to finish (checking again every 30 seconds)...");
      waiting = true;
      await sleep(30_000);
      continue;
    }
    waiting = false;
    const task = claim.task;
    const isReview = task.kind === "review";
    process.stdout.write(`${isReview ? "Checking" : "Analyzing"} ${task.label} ... `);
    try {
      if (isReview) {
        const verdict = review(ctx, task.address, claim.proposal?.notes ?? []);
        await api(config, "POST", "/submit", { protocol: NOTE_PROTOCOL, taskId: task.id, verdict });
        console.log(`you said: ${verdict}`);
      } else {
        const notes = analyze(ctx, task.address);
        const { results } = await api<{ results: { status: NoteStatus; reason?: string }[] }>(config, "POST", "/submit", { protocol: NOTE_PROTOCOL, taskId: task.id, notes });
        console.log(describe(results.find((r) => r.status !== "rejected")?.status ?? "rejected", results.find((r) => r.status === "rejected")?.reason));
      }
      failures = 0;
      done++;
    } catch (err) {
      console.log(`failed: ${err instanceof Error ? err.message : err}`);
      await api(config, "POST", "/release");
      if (++failures >= 5) {
        console.error("\nToo many failures in a row, stopping. Fix the problem above and run again.");
        process.exit(1);
      }
      await sleep(10_000 * failures);
    }
    if (flags.once) return;
  }
}

async function main() {
  const { positional, flags } = parseArgs(process.argv.slice(2));
  const [command, ...rest] = positional;

  switch (command) {
    case "join": {
      const [url, code] = rest;
      if (!url || !code) {
        console.error("Usage: pool join <leader-address> <join-code> --target <your copy of the software> [--name <you>]");
        process.exit(1);
      }
      const name = flags.name && flags.name !== "true" ? flags.name : userInfo().username.replace(/[^\w-]/g, "").slice(0, 30) || "contributor";
      const { ok, data } = await rawApi<{ token: string; name: string; project: Project }>(url, "POST", "/join", undefined, { code, name });
      if (!ok) {
        console.error(`The leader said: ${data.error ?? "could not join"}`);
        process.exit(1);
      }
      const config: Config = { leaderUrl: url, token: data.token, name: data.name };
      if (flags.target && flags.target !== "true") {
        if (!existsSync(flags.target)) {
          console.error(`Joined, but the file ${flags.target} was not found. Set it later with: pool set-target <path>`);
        } else {
          config.targetPath = resolve(flags.target);
        }
      }
      saveConfig(config);
      console.log(`Joined "${data.project.name}" as ${data.name}.`);
      if (config.targetPath) {
        console.log("\nChecking your setup...\n");
        await doCheck(config, data.project);
        console.log("\nNext: pool run");
      } else {
        console.log(`Next: pool set-target <path to your copy of ${data.project.target.filename}>, then pool run`);
      }
      break;
    }
    case "set-target": {
      const config = loadConfig();
      if (!rest[0] || !existsSync(rest[0])) {
        console.error("File not found.");
        process.exit(1);
      }
      config.targetPath = resolve(rest[0]);
      saveConfig(config);
      console.log("Saved. Run: pool check");
      break;
    }
    case "check": {
      const config = loadConfig();
      const { project } = await api<{ project: Project }>(config, "GET", "/project");
      process.exit((await doCheck(config, project)) ? 0 : 2);
      break;
    }
    case "status": {
      const config = loadConfig();
      const s = await api<{ tasks: Record<string, number>; trusted: number; pending: number; hints: number; rejected: number; yourProposals: number; finished: boolean }>(config, "GET", "/status");
      console.log(`Tasks: ${s.tasks.open} open, ${s.tasks.claimed} in progress, ${s.tasks.done} done`);
      console.log(`Results: ${s.trusted} trusted, ${s.pending} waiting for a check, ${s.hints} hints, ${s.rejected} rejected (you contributed ${s.yourProposals})`);
      if (s.finished) console.log("Nothing left for you to do right now.");
      break;
    }
    case "run":
      await runLoop(loadConfig(), flags);
      break;
    case "release": {
      await api(loadConfig(), "POST", "/release");
      console.log("Released your task so someone else can take it.");
      break;
    }
    default:
      console.log(`rea-pool contributor tool

  join <address> <join-code> --target <file>   Join a project (--name to pick a name)
  run                                          Do tasks until there are none left (add --once for just one)
  check                                        Check your setup matches the project
  status                                       See progress
  set-target <path>                            Change where your copy of the software is
  release                                      Give your current task back

Options for run:  --ai "<command>"  use a specific AI command   --model <name>  label the model you use`);
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
