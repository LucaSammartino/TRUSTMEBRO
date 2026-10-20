#!/usr/bin/env node
// Leader tool. One command does the setup:  leader start <software-file>
import { listAndroidMethods } from "./android.ts";
import { CorvusClient, CORVUS_VERSION, listManagedMethods, selectProvider } from "./corvus.ts";
import { randomBytes } from "node:crypto";
import { runCommand, runCommandAsync } from "./exec.ts";
import { fillCalleesFromDump, markKnownFromDump } from "./agent.ts";
import { cachedImageBase, loadDump, prepareTarget } from "./prepare.ts";
import { addCallees, calleesFromReaFunction, graphStats, normalizeAddress } from "./graph.ts";
import { isShape, shapeOf } from "./similar.ts";
import { existsSync, mkdirSync, statSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { networkInterfaces } from "node:os";
import type { Note, Project, State, Task, ToolSpec } from "./types.ts";
import { createInvite, createPoolServer, listInvites, loadState, overrideNote, revokeInvite, saveState, submitAnalysis } from "./server.ts";
import { DETAIL_KINDS } from "./rules.ts";
import { readVersion } from "./check.ts";
import { buildActivity } from "./activity.ts";
import { renderActivity } from "./watch.ts";
import { compareNotes, NOTE_PROTOCOL } from "./trust.ts";
import { exportState, importState } from "./handover.ts";
import { readJson, sha256File, writeJsonAtomic } from "./util.ts";

// What contributors must have. `required` is replaced by the versions actually installed on the leader's computer.
const TOOL_TEMPLATE: { spec: ToolSpec; pin: (version: string) => { required: string; match: "exact" | "prefix" } }[] = [
  {
    spec: { name: "java", command: ["java", "-version"], versionRegex: 'version "([^"]+)"', required: "21", match: "prefix" },
    pin: (v) => ({ required: v.replace(/^1\./, "").split(/[._]/)[0], match: "prefix" }),
  },
  { spec: { name: "ghidra", command: [], versionRegex: "", required: "12.1.4", match: "exact" }, pin: (v) => ({ required: v, match: "exact" }) },
  // Node is not pinned: it only runs this tool and does not change analysis results.
  {
    spec: { name: "rea", command: ["rea", "--version"], versionRegex: "(\\d+\\.\\d+\\.\\d+)", required: "6.7.0", match: "exact" },
    pin: (v) => ({ required: v, match: "exact" }),
  },
];

function pinnedTools(): ToolSpec[] {
  return TOOL_TEMPLATE.map(({ spec, pin }) => {
    const read = readVersion(spec);
    if ("error" in read) {
      console.log(`  note: could not read your ${spec.name} version (${read.error}); using the default requirement ${spec.required}.`);
      return spec;
    }
    return { ...spec, ...pin(read.version) };
  });
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

function usage(): never {
  console.log(`rea-pool leader tool

  start <software-file> [--no-corvus] [--name "Project"] [--port 8787] [--host <address>]
        Set everything up (first time) and run the server. Run it again later to resume.
  link [--port 8787]                  Show the line friends use to join
  status                              Show progress
  watch [--once]                      Live progress screen, refreshed every 3 seconds
  notes [--status trusted|pending|hint|rejected]
                                      List what has been sent in
  export <out.json> [--best] [--include-unverified]
                                      Save trusted results (--best: one winner per function and kind)
  prepare <software-file> [--force]   Read the whole program once into a local cache (about a minute);
                                      after this, graph and every task are instant
  graph <software-file> [--no-prepare] [--keep-named] [--parallel 4] [--limit N]
                                      Read which function calls which. Prepares the cache first (see
                                      "prepare"). With --no-prepare, or for functions missing from the
                                      cache, asks rea one function at a time (slow: ~40s each, in
                                      parallel). Safe to stop with Ctrl+C and run again to continue.
                                      Functions Ghidra already named (not FUN_...) are skipped;
                                      --keep-named turns that off (for programs that still have symbols)
  apply [out-dir] [--target <file>]  Write trusted names for the project's reader (default ./pool-data/apply)
  revoke <person>                     Cancel someone's access
  approve <note-id> | reject <note-id>
                                      Optional overrides. You never need these.
  new-code                            Replace the join code (old code stops working)
  invite <name> | invites | uninvite <name>
                                      Personal one-use join codes (print the join line / list / cancel)
  close-shared | open-shared          Switch the shared join code off / on (personal invites keep working)
  export-state [file]                 Copy the whole project (default ./pool-export.json) to hand the leader job
                                      to someone else. Contains everyone's access: give it only to someone you trust
  import-names <results.json> <old-file> <new-file> --data <new-folder>
                                      Carry trusted names to a new native or .NET build with Corvus
  import-state <file> [--force]       New leader: load an exported project into the data folder, then run start.
                                      Everyone then runs  pool set-leader <new address>
  retry-models <label,label|none>    Model labels that get retries first (none clears)
  tasks-from-rea <file> | add-tasks <file.json> | init <file> | serve
                                      The steps "start" does for you, if you want them separately

Add  --data <folder>  to use a folder other than ./pool-data`);
  process.exit(1);
}

function newJoinCode(): string {
  return `jc_${randomBytes(9).toString("base64url")}`;
}

function listFunctions(file: string): Pick<Task, "id" | "label" | "address">[] {
  console.log("Asking rea to list every function (the first run can take a minute)...");
  let run;
  try {
    run = runCommand("rea", ["search", file, ".", "--kind", "procedures", "--mode", "regex", "--provider", "ghidra", "--json"], { timeout: 15 * 60_000, maxBuffer: 256 * 1024 * 1024 });
  } catch (err) {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  }
  if (run.error || run.status !== 0) {
    console.error(`rea failed. Run "rea doctor --provider ghidra" to see what is wrong.\n${(run.stderr ?? "").slice(0, 600)}`);
    process.exit(1);
  }
  const procs = (JSON.parse(run.stdout) as { normalized_result: { address: string; value: string }[] }).normalized_result;
  return procs
    .filter((p) => /^0x[0-9a-f]+$/i.test(p.address))
    .map((p) => ({ id: `fn-${p.address.toLowerCase()}`, label: `Function at ${p.address.toLowerCase()}`, address: p.address.toLowerCase() }));
}

function addTasks(state: State, incoming: { id: string; label?: string; address: string; size?: number }[]): number {
  const known = new Set(state.tasks.map((t) => t.id));
  let added = 0;
  for (const t of incoming) {
    if (!t.id || !t.address || known.has(t.id)) continue;
    state.tasks.push({ id: String(t.id), kind: "analyze", label: String(t.label ?? t.id), address: String(t.address), size: t.size, state: "open", attempts: 1 });
    known.add(String(t.id));
    added++;
  }
  return added;
}

async function createProject(file: string, dataDir: string, name: string | undefined, noCorvus = false): Promise<State> {
  mkdirSync(dataDir, { recursive: true });
  const provider = selectProvider(file, noCorvus);
  if (provider) {
    const found = readVersion({ name: "corvus", command: ["corvus", "--version"], versionRegex: "(\\d+\\.\\d+\\.\\d+)", required: CORVUS_VERSION, match: "exact" });
    if (!("version" in found) || found.version !== CORVUS_VERSION) {
      const { CORVUS_FIX } = await import("./corvus.ts");
      throw new Error(`This game needs Corvus ${CORVUS_VERSION}. Run: ${CORVUS_FIX}`);
    }
  }
  if (provider) writeJsonAtomic(join(dataDir, "corvus-target.json"), { path: resolve(file) });
  const project: Project = {
    schema: "rea-pool/1",
    name: name ?? basename(file),
    created: new Date().toISOString(),
    target: { filename: basename(file), sha256: await sha256File(file), size: statSync(file).size },
    ...(provider ? { provider, corvusVersion: CORVUS_VERSION } : {}),
    tools: provider ? [] : pinnedTools(),
    rules: {
      allowedKinds: ["function_name", "comment", "type_note", "rejected_hypothesis", ...(provider ? [] : DETAIL_KINDS)],
      maxTextLength: 500,
      maxEvidenceItems: 5,
      leaseMinutes: 30,
      protocol: NOTE_PROTOCOL,
      maxAttempts: 3,
      maxVotes: 5,
      maxContributors: 50,
      releaseCooldownMinutes: 15,
      maxParallel: 4,
    },
  };
  return { project, joinCode: newJoinCode(), contributors: [], tasks: [], notes: [], proposals: [] };
}

function addresses(host: string): string[] {
  if (host !== "0.0.0.0") return [host];
  return Object.values(networkInterfaces())
    .flat()
    .filter((i) => i && i.family === "IPv4" && !i.internal)
    .map((i) => i!.address);
}

function printJoinLine(state: State, port: string, host: string, code: string = state.joinCode): void {
  const where = addresses(host).map((a) => `http://${a}:${port}`);
  const address = where[0] ?? `http://<your-address>:${port}`;
  console.log("\nTo join, a friend runs (with their own copy of the software):\n");
  console.log(`  pool join ${address} ${code} --target <path to their copy of ${state.project.target.filename}>\n`);
  if (host === "127.0.0.1") {
    console.log("Right now only THIS computer can connect. For friends elsewhere, restart with a private network address, e.g. install Tailscale,");
    console.log("then:  start <file> --host 0.0.0.0   and give them your Tailscale address instead. See the README, section \"Letting friends connect\".");
  } else if (where.length > 1) {
    console.log(`Other addresses this computer has: ${where.slice(1).join(", ")}`);
  }
}

/** Short read-modify-write of state.json: copy known callees from the graph file into tasks that lack them. */
function mergeGraphIntoState(statePath: string, graph: Record<string, string[]>, shapes: Record<string, string> = {}): number {
  const state = loadState(statePath);
  let merged = 0;
  for (const task of state.tasks) {
    if ((task.kind ?? "analyze") !== "analyze") continue;
    const shape = shapes[normalizeAddress(task.address) ?? ""];
    if (shape && !task.shape && isShape(shape)) {
      task.shape = shape;
      merged++;
    }
    if (task.callees) continue;
    const callees = graph[normalizeAddress(task.address) ?? ""];
    if (!callees) continue;
    addCallees(task, callees);
    merged++;
  }
  if (merged > 0) saveState(statePath, state);
  return merged;
}

async function importGameNames(file: string, statePath: string, flags: Record<string, string>): Promise<void> {
  const snapshot = loadState(statePath);
  if (snapshot.project.provider || flags["no-corvus"] !== undefined || flags["keep-named"] !== undefined) return;
  // Check the file before trusting metadata from its folder.
  const { corvusAvailable, detectTargetKind, il2cppNames } = await import("./corvus.ts");
  if (!corvusAvailable() || detectTargetKind(file) !== "il2cpp") return;
  if (await sha256File(file) !== snapshot.project.target.sha256) throw new Error("This file does not match the project. Use the same game build.");
  try {
    const base = cachedImageBase(file);
    if (/\.so$/i.test(file) && base === null) {
      console.log("Corvus needs Ghidra's address base for this library. Run leader prepare <file> --force, then graph again. Continuing with rea/Ghidra.");
      return;
    }
    const names = await il2cppNames(file, undefined, base);
    const fresh = loadState(statePath);
    const { markCorvusNames } = await import("./agent.ts");
    const count = markCorvusNames(fresh, names);
    if (count) {
      saveState(statePath, fresh);
      console.log(`${count} functions already have Unity names from Corvus; skipping them`);
    }
  } catch {
    console.log("Corvus could not read the Unity names; continuing with rea/Ghidra.");
  }
}

async function buildGraph(file: string, dataDir: string, statePath: string, flags: Record<string, string>): Promise<void> {
  const project = loadState(statePath).project;
  if (project.provider) {
    if (await sha256File(file) !== project.target.sha256) throw new Error("This file does not match the project. Use the same game build.");
    await prepareTarget(file, { provider: project.provider, log: console.log });
    const fresh = loadState(statePath);
    const filled = fillCalleesFromDump(fresh, file);
    if (filled) saveState(statePath, fresh);
    console.log(`Filled ${filled} methods from Corvus.`);
    console.log(formatGraphStats(fresh));
    return;
  }
  const num = (v: string | undefined, fallback: number) => (v && v !== "true" && Number.isFinite(Number(v)) ? Math.floor(Number(v)) : fallback);
  const parallel = Math.min(16, Math.max(1, num(flags.parallel, 4)));
  const limit = num(flags.limit, Infinity);
  const graphPath = join(dataDir, "graph.json");
  const graph: Record<string, string[]> = existsSync(graphPath) ? readJson<Record<string, string[]>>(graphPath) : {};
  const shapesPath = join(dataDir, "shapes.json");
  const shapes: Record<string, string> = existsSync(shapesPath) ? readJson<Record<string, string>>(shapesPath) : {};

  if (flags["no-prepare"] === undefined) {
    try {
      if (!loadDump(file)) {
        console.log("Preparing a local copy of the program once (about a minute)...");
        await prepareTarget(file, { log: console.log, noCorvus: flags["no-corvus"] !== undefined });
      }
      const state = loadState(statePath);
      const filled = fillCalleesFromDump(state, file);
      if (filled > 0) {
        for (const t of state.tasks) {
          if ((t.kind ?? "analyze") !== "analyze") continue;
          const key = normalizeAddress(t.address) ?? t.address;
          if (t.callees && !graph[key]) graph[key] = t.callees;
          if (t.shape && !shapes[key]) shapes[key] = t.shape;
        }
        writeJsonAtomic(graphPath, graph);
        writeJsonAtomic(shapesPath, shapes);
        // Short read-modify-write: reload so changes made by the running server are not lost.
        mergeGraphIntoState(statePath, graph, shapes);
        console.log(`Filled ${filled} functions from the local cache.`);
      }
      // Short read-modify-write again, so the running server's changes are kept.
      const fresh = loadState(statePath);
      const known = markKnownFromDump(fresh, file, { keepNamed: flags["keep-named"] !== undefined });
      if (known > 0) {
        saveState(statePath, fresh);
        console.log(`${known} functions already have real names from Ghidra; skipping them`);
      }
    } catch (err) {
      console.log(`Could not use the quick method (${err instanceof Error ? err.message : err}); using the slower one.`);
    }
  }

  await importGameNames(file, statePath, flags);
  const first = loadState(statePath);
  const isCandidate = (t: Task) => (t.kind ?? "analyze") === "analyze" && t.callees === undefined;
  const fromFile = first.tasks.filter((t) => isCandidate(t) && graph[normalizeAddress(t.address) ?? ""]).length;
  if (fromFile > 0) {
    mergeGraphIntoState(statePath, graph, shapes);
    console.log(`Applied ${fromFile} functions saved by an earlier run.`);
  }
  const queue = loadState(statePath)
    .tasks.filter(isCandidate)
    .map((t) => ({ id: t.id, address: t.address }))
    .slice(0, limit);
  if (queue.length === 0) {
    console.log("Nothing to do: every function already has its callees.");
    console.log(formatGraphStats(loadState(statePath)));
    return;
  }
  console.log(`Reading callees of ${queue.length} functions, ${parallel} at a time. Each call takes about 40 seconds. Ctrl+C is safe; run the same command again to continue.`);

  let done = 0;
  let failed = 0;
  let sinceMerge = 0;
  let lastPrint = 0;
  const total = queue.length;
  const progress = (force = false) => {
    const now = Date.now();
    if (!force && now - lastPrint < 5000) return;
    lastPrint = now;
    console.log(`Graph: ${done}/${total} (${failed} failed) ...`);
  };
  const merge = () => {
    sinceMerge = 0;
    try {
      mergeGraphIntoState(statePath, graph, shapes);
    } catch (err) {
      console.error(`Could not update the project state: ${err instanceof Error ? err.message : err}`);
    }
  };

  let stopping = false;
  process.on("SIGINT", () => {
    if (stopping) process.exit(130);
    stopping = true;
    console.log("\nStopping; saving what was found...");
    merge();
    console.log(formatGraphStats(loadState(statePath)));
    process.exit(130);
  });

  let next = 0;
  const worker = async () => {
    while (!stopping) {
      const item = queue[next++];
      if (!item) return;
      try {
        const run = await runCommandAsync("rea", ["function", file, item.address, "--provider", "ghidra", "--json"], { timeout: 10 * 60_000, maxBuffer: 256 * 1024 * 1024 });
        if (run.error || run.status !== 0) throw new Error(run.error?.message ?? (run.stderr.trim().split("\n")[0] || `exit ${run.status}`));
        const parsed = JSON.parse(run.stdout) as { normalized_result?: unknown };
        if (!parsed.normalized_result) throw new Error("no normalized_result in output");
        graph[normalizeAddress(item.address) ?? item.address] = calleesFromReaFunction(parsed.normalized_result, item.address);
        writeJsonAtomic(graphPath, graph);
        const pseudocode = (parsed.normalized_result as { pseudocode?: unknown }).pseudocode;
        const shape = shapeOf(pseudocode);
        if (shape) {
          shapes[normalizeAddress(item.address) ?? item.address] = shape;
          writeJsonAtomic(shapesPath, shapes);
        }
        done++;
        if (++sinceMerge >= 25) merge();
      } catch (err) {
        failed++;
        console.error(`  ${item.address}: ${(err instanceof Error ? err.message : String(err)).slice(0, 160)}`);
      }
      progress();
    }
  };
  await Promise.all(Array.from({ length: Math.min(parallel, queue.length) }, worker));
  merge();
  progress(true);
  console.log(formatGraphStats(loadState(statePath)));
  if (failed > 0) console.log(`${failed} functions failed; run the command again to retry them.`);
}

function formatGraphStats(state: State): string {
  const g = graphStats(state);
  return `Call graph: ${g.known} of ${g.known + g.unknown} functions known, ${g.edges} edges, ${g.ready} ready`;
}

async function main() {
  const { positional, flags } = parseArgs(process.argv.slice(2));
  const [command, ...rest] = positional;
  if (!command) usage();
  const dataDir = flags.data ?? "pool-data";
  const statePath = join(dataDir, "state.json");
  const port = flags.port && flags.port !== "true" ? flags.port : "8787";
  const host = flags.host && flags.host !== "true" ? flags.host : "127.0.0.1";
  const needState = (): State => {
    if (!existsSync(statePath)) {
      console.error(`No project found in ${dataDir}. Run "start <software-file>" first.`);
      process.exit(1);
    }
    return loadState(statePath);
  };
  const serve = () =>
    createPoolServer(statePath).listen(Number(port), host, () => {
      console.log(`Server running on port ${port} (${host}). Press Ctrl+C to stop; progress is saved automatically.`);
    });

  switch (command) {
    case "start": {
      if (existsSync(statePath)) {
        const state = loadState(statePath);
        console.log(`Resuming "${state.project.name}".`);
        printJoinLine(state, port, host);
        serve();
        break;
      }
      const file = rest[0];
      if (!file || !existsSync(file)) {
        console.error('Give the path to your copy of the software: start <software-file> --name "My project"');
        process.exit(1);
      }
      const name = flags.name && flags.name !== "true" ? flags.name : undefined;
      const state = await createProject(file, dataDir, name, flags["no-corvus"] !== undefined);
      console.log(`Project "${state.project.name}" created. Software fingerprint: ${state.project.target.sha256.slice(0, 16)}...`);
      console.log("Contributors must have:");
      if (state.project.provider) console.log(`  - Corvus ${state.project.corvusVersion}`);
      for (const t of state.project.tools) console.log(`  - ${t.name} ${t.required}`);
      const incoming = state.project.provider
        ? (await (state.project.provider === "corvus-android" ? listAndroidMethods : listManagedMethods)(new CorvusClient(file))).map((m) => ({ id: `fn-${m.address}`, address: m.address, label: `Method at ${m.address}` }))
        : listFunctions(file);
      const added = addTasks(state, incoming);
      saveState(statePath, state);
      console.log(`Created ${added} tasks (one per function).`);
      printJoinLine(state, port, host);
      serve();
      break;
    }
    case "link": {
      printJoinLine(needState(), port, host);
      break;
    }
    case "new-code": {
      const state = needState();
      state.joinCode = newJoinCode();
      saveState(statePath, state);
      console.log("New join code created. People who already joined are not affected.");
      printJoinLine(state, port, host);
      break;
    }
    case "invite": {
      const state = needState();
      const made = rest[0] ? createInvite(state, rest[0]) : { error: "Give a name: invite <name>" };
      if ("error" in made) {
        console.error(made.error);
        process.exit(1);
      }
      saveState(statePath, state);
      console.log(`Personal invite for ${rest[0]} (works once).`);
      printJoinLine(state, port, host, made.code);
      break;
    }
    case "invites": {
      const list = listInvites(needState());
      if (list.length === 0) console.log("No invites.");
      for (const i of list) console.log(`${i.name}  ${i.used ? "used" : "unused"}  created ${i.created}`);
      break;
    }
    case "uninvite": {
      const state = needState();
      if (!rest[0] || !revokeInvite(state, rest[0])) {
        console.error("No such invite.");
        process.exit(1);
      }
      saveState(statePath, state);
      console.log(`Invite for ${rest[0]} cancelled.`);
      break;
    }
    case "close-shared":
    case "open-shared": {
      const state = needState();
      state.sharedCodeOff = command === "close-shared";
      saveState(statePath, state);
      console.log(state.sharedCodeOff ? "The shared join code is off. Personal invites still work." : "The shared join code is on again.");
      break;
    }
    case "retry-models": {
      const state = needState();
      if (!rest[0]) {
        console.error("Usage: retry-models <label,label|none>");
        process.exit(1);
      }
      const labels = rest[0] === "none" ? [] : rest[0].split(",").map((l) => l.trim()).filter((l) => /^[A-Za-z0-9][w.:/-]{0,59}$/.test(l));
      if (rest[0] !== "none" && labels.length === 0) {
        console.error("Give model labels such as claude-opus-5-5,claude-sonnet-5-5, or none.");
        process.exit(1);
      }
      if (labels.length) state.project.rules.retryModels = labels;
      else delete state.project.rules.retryModels;
      saveState(statePath, state);
      console.log(labels.length ? `Retries go to these models first: ${labels.join(", ")}` : "Retry preference cleared.");
      break;
    }
    case "init": {
      const file = rest[0];
      if (!file || !existsSync(file)) {
        console.error("Give the path to your copy of the software.");
        process.exit(1);
      }
      if (existsSync(statePath)) {
        console.error(`A project already exists in ${dataDir}. Refusing to overwrite it.`);
        process.exit(1);
      }
      const state = await createProject(file, dataDir, flags.name && flags.name !== "true" ? flags.name : undefined, flags["no-corvus"] !== undefined);
      if (flags.tools) state.project.tools = readJson<ToolSpec[]>(flags.tools);
      saveState(statePath, state);
      console.log(`Project "${state.project.name}" created.`);
      break;
    }
    case "tasks-from-rea": {
      const file = rest[0];
      if (!file || !existsSync(file)) {
        console.error("Give the path to your copy of the software.");
        process.exit(1);
      }
      const tasks = listFunctions(file);
      writeJsonAtomic(flags.out ?? "tasks.json", tasks);
      console.log(`Found ${tasks.length} functions. Saved to ${flags.out ?? "tasks.json"}. Next: add-tasks <file>`);
      break;
    }
    case "add-tasks": {
      const state = needState();
      const added = addTasks(state, readJson(rest[0]));
      saveState(statePath, state);
      console.log(`Added ${added} task(s). Total: ${state.tasks.length}.`);
      break;
    }
    case "serve": {
      needState();
      serve();
      break;
    }
    case "status": {
      const state = needState();
      const now = Date.now();
      const analysis = state.tasks.filter((t) => (t.kind ?? "analyze") === "analyze");
      const count = (s: string) => state.proposals.filter((p) => p.status === s).length;
      console.log(`${state.project.name}`);
      console.log(`  Functions: ${analysis.length}; done ${analysis.filter((t) => t.state === "done").length}, waiting ${analysis.filter((t) => t.state === "open").length}, in progress ${analysis.filter((t) => t.state === "claimed" && Date.parse(t.leaseUntil ?? "") > now).length}`);
      console.log(`  ${formatGraphStats(state)}`);
      console.log(`  Results: ${count("trusted")} trusted, ${count("pending")} waiting for a check, ${count("hint")} hints, ${count("rejected")} rejected`);
      console.log(`  People: ${state.contributors.filter((c) => !c.revoked).map((c) => c.name).join(", ") || "nobody yet"}`);
      break;
    }
    case "watch": {
      needState();
      const frame = () => {
        const out = renderActivity(buildActivity(loadState(statePath), Date.now()), { width: process.stdout.columns ?? 80, color: !!process.stdout.isTTY });
        if (process.stdout.isTTY && flags.once === undefined) process.stdout.write("\x1b[2J\x1b[H");
        console.log(out);
      };
      frame();
      if (flags.once !== undefined || !process.stdout.isTTY) break;
      setInterval(() => {
        try {
          frame();
        } catch {
          // The server may be mid-write; the next frame will do.
        }
      }, 3000);
      break;
    }
    case "prepare": {
      const file = rest[0];
      if (!file || !existsSync(file)) {
        console.error("Give the path to your copy of the software: prepare <software-file> [--force]");
        process.exit(1);
      }
      try {
        const provider = existsSync(statePath) ? loadState(statePath).project.provider : selectProvider(file, flags["no-corvus"] !== undefined);
        const r = await prepareTarget(file, { force: flags.force !== undefined, log: console.log, provider, noCorvus: flags["no-corvus"] !== undefined });
        if (existsSync(statePath)) await importGameNames(file, statePath, flags);
        console.log(r.fromCache ? `Already prepared: ${r.functions} functions` : `Ready: ${r.functions} functions cached (took ${r.seconds}s)`);
      } catch (err) {
        console.error(err instanceof Error ? err.message : String(err));
        process.exit(1);
      }
      break;
    }
    case "graph": {
      needState();
      const file = rest[0];
      if (!file || !existsSync(file)) {
        console.error("Give the path to your copy of the software: graph <software-file> [--parallel 4]");
        process.exit(1);
      }
      await buildGraph(file, dataDir, statePath, flags);
      break;
    }
    case "apply": {
      const state = needState();
      const outDir = rest[0] ?? join(dataDir, "apply");
      if (state.project.provider) {
        const { writeCorvusApplyBundle } = await import("./apply.ts");
        const local = join(dataDir, "corvus-target.json");
        const target = flags.target ?? (existsSync(local) ? readJson<{ path?: string }>(local).path : undefined);
        const r = writeCorvusApplyBundle(state, outDir, target);
        console.log(`Wrote ${r.count} checked names to ${r.namesFile}.`);
        if (r.batchFile) console.log(`To write a renamed copy, run: corvus batch "${r.batchFile}" --stop-on-error --no-index
The new assembly will be ${r.outputFile}. The original is kept. Comments are saved as Corvus notes and in ${r.sessionFile}.`);
        else console.log("Corvus 2.4.0 has no documented Android rename/save tool. Keep names.json as your name list; the APK or DEX has not been changed.");
        break;
      }
      let writeApplyBundle: (s: State, dir: string) => { namesFile: string; scriptFile: string; count: number };
      try {
        ({ writeApplyBundle } = await import("./apply.ts"));
      } catch {
        console.error("This version has no apply support (src/apply.ts is missing).");
        process.exit(1);
      }
      const r = writeApplyBundle(state, outDir);
      console.log(`Wrote ${r.count} names to ${r.namesFile}. To apply them in Ghidra: open your program, Window > Script Manager, add ${outDir} as a script folder and run ApplyNames.java, then choose names.json. Or headless: analyzeHeadless <projectDir> <project> -process <program> -scriptPath ${outDir} -postScript ApplyNames.java ${r.namesFile}`);
      break;
    }
    case "notes": {
      const state = needState();
      for (const n of state.notes) {
        if (flags.status && n.status !== flags.status) continue;
        console.log(`${n.id}  [${n.status}]  ${n.author}  ${n.confidence}${n.agrees ? `, ${n.agrees} agreed` : ""}  task ${n.taskId}  ${n.kind}: ${JSON.stringify(n.value)}${n.reason ? `  (${n.reason})` : ""}`);
      }
      break;
    }
    case "approve":
    case "reject": {
      const state = needState();
      if (!overrideNote(state, rest[0], command === "approve" ? "trusted" : "rejected")) {
        console.error("No such note id. See: notes");
        process.exit(1);
      }
      saveState(statePath, state);
      console.log(command === "approve" ? "Marked trusted." : "Marked rejected.");
      break;
    }
    case "export-state": {
      const out = rest[0] ?? "pool-export.json";
      const r = exportState(dataDir, out);
      if ("error" in r) {
        console.error(r.error);
        process.exit(1);
      }
      console.log(`Saved the whole project to ${out}.`);
      console.log("WARNING: this file contains everyone's access (their token hashes and the join code). Only give it to someone you trust.");
      console.log(`To hand over: the new leader runs  import-state ${out}  and then  start; everyone else runs  pool set-leader <new address>.`);
      break;
    }
    case "import-names": {
      const [resultsFile, oldFile, newFile] = rest;
      if (!resultsFile || !oldFile || !newFile || ![resultsFile, oldFile, newFile].every(existsSync)) throw new Error("Usage: leader import-names <results.json> <old program file> <new program file> --data <new project folder>");
      if (existsSync(statePath)) throw new Error("Choose an empty project folder with --data. Your existing project will be kept.");
      const { detectTargetKind, corvusAvailable, CORVUS_FIX } = await import("./corvus.ts");
      if (!corvusAvailable()) throw new Error(`Name carry-over needs Corvus. Run: ${CORVUS_FIX}`);
      const oldKind = detectTargetKind(oldFile), newKind = detectTargetKind(newFile);
      if (oldKind === "android" || newKind === "android") throw new Error("Android name carry-over is not supported yet. Keep the exported names for reference.");
      const managed = oldKind === "dotnet" && newKind === "dotnet";
      if ((oldKind === "dotnet" || newKind === "dotnet") && !managed) throw new Error("Both builds must use the same kind of code (.NET or native).");
      const { trustedBuildNames, migrateBuildNames, migrateManagedNames } = await import("./import-names.ts");
      const trusted = trustedBuildNames(readJson(resultsFile), await sha256File(oldFile));
      const managedState = managed ? await createProject(newFile, dataDir, flags.name && flags.name !== "true" ? flags.name : undefined) : undefined;
      const mapped = await (managed ? migrateManagedNames : migrateBuildNames)(oldFile, newFile, trusted);
      const state = managedState ?? await createProject(newFile, dataDir, flags.name && flags.name !== "true" ? flags.name : undefined, true);
      addTasks(state, managed
        ? (await listManagedMethods(new CorvusClient(newFile))).map((m) => ({ id: `fn-${m.address}`, address: m.address, label: `Method at ${m.address}` }))
        : listFunctions(newFile));
      const byAddress = new Map(state.tasks.map((t) => [normalizeAddress(t.address), t]));
      let seeded = 0;
      for (const name of mapped) {
        const task = byAddress.get(name.address);
        if (!task) continue;
        const accepted = submitAnalysis(state, "corvus", task, [{ kind: "function_name", value: name.name, confidence: "high", model: "corvus", evidence: ["Trusted name matched from the previous build by Corvus"] }]);
        if (accepted.some((r) => r.ok)) seeded++;
      }
      saveState(statePath, state);
      console.log(`Created the new project with ${seeded} trusted names carried over. Run leader start --data "${dataDir}" to share it, or leader apply --data "${dataDir}" to write the names for its reader.`);
      break;
    }
    case "import-state": {
      if (!rest[0]) {
        console.error("Usage: import-state <file> [--force]");
        process.exit(1);
      }
      const r = importState(rest[0], dataDir, flags.force !== undefined);
      if ("error" in r) {
        console.error(r.error);
        process.exit(1);
      }
      console.log(`Project imported into ${dataDir}. Next: start   (then tell everyone to run  pool set-leader <your address>).`);
      break;
    }
    case "revoke": {
      const state = needState();
      const person = state.contributors.find((c) => c.name === rest[0]);
      if (!person) {
        console.error("No such person.");
        process.exit(1);
      }
      person.revoked = true;
      saveState(statePath, state);
      console.log(`${person.name} can no longer connect.`);
      break;
    }
    case "export": {
      const state = needState();
      let chosen = state.notes.filter((n) => n.status === "trusted" || (flags["include-unverified"] !== undefined && (n.status === "pending" || n.status === "hint")));
      if (flags.best !== undefined) {
        const winners = new Map<string, Note>();
        for (const n of [...chosen].sort(compareNotes)) {
          const key = `${n.taskId}|${n.kind}`;
          if (!winners.has(key)) winners.set(key, n);
        }
        chosen = [...winners.values()];
      }
      const out = rest[0] ?? "results.json";
      writeJsonAtomic(out, { project: state.project.name, target: state.project.target.sha256, notes: chosen });
      console.log(`Saved ${chosen.length} notes to ${out}${flags["include-unverified"] !== undefined ? " (including unverified)" : " (trusted only)"}.`);
      break;
    }
    default:
      usage();
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
