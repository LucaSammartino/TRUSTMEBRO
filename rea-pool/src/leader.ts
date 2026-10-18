#!/usr/bin/env node
// Leader tool. One command does the setup:  leader start <software-file>
import { randomBytes } from "node:crypto";
import { runCommand } from "./exec.ts";
import { existsSync, mkdirSync, statSync } from "node:fs";
import { basename, join } from "node:path";
import { networkInterfaces } from "node:os";
import type { Note, Project, State, Task, ToolSpec } from "./types.ts";
import { createPoolServer, loadState, overrideNote, saveState } from "./server.ts";
import { readVersion } from "./check.ts";
import { compareNotes, NOTE_PROTOCOL } from "./trust.ts";
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

  start <software-file> [--name "Project"] [--port 8787] [--host <address>]
        Set everything up (first time) and run the server. Run it again later to resume.
  link [--port 8787]                  Show the line friends use to join
  status                              Show progress
  notes [--status trusted|pending|hint|rejected]
                                      List what has been sent in
  export <out.json> [--best] [--include-unverified]
                                      Save trusted results (--best: one winner per function and kind)
  revoke <person>                     Cancel someone's access
  approve <note-id> | reject <note-id>
                                      Optional overrides. You never need these.
  new-code                            Replace the join code (old code stops working)
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

async function createProject(file: string, dataDir: string, name: string | undefined): Promise<State> {
  mkdirSync(dataDir, { recursive: true });
  const project: Project = {
    schema: "rea-pool/1",
    name: name ?? basename(file),
    created: new Date().toISOString(),
    target: { filename: basename(file), sha256: await sha256File(file), size: statSync(file).size },
    tools: pinnedTools(),
    rules: {
      allowedKinds: ["function_name", "comment", "type_note", "rejected_hypothesis"],
      maxTextLength: 500,
      maxEvidenceItems: 5,
      leaseMinutes: 30,
      protocol: NOTE_PROTOCOL,
      maxAttempts: 3,
      maxVotes: 5,
      maxContributors: 50,
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

function printJoinLine(state: State, port: string, host: string): void {
  const where = addresses(host).map((a) => `http://${a}:${port}`);
  const address = where[0] ?? `http://<your-address>:${port}`;
  console.log("\nTo join, a friend runs (with their own copy of the software):\n");
  console.log(`  pool join ${address} ${state.joinCode} --target <path to their copy of ${state.project.target.filename}>\n`);
  if (host === "127.0.0.1") {
    console.log("Right now only THIS computer can connect. For friends elsewhere, restart with a private network address, e.g. install Tailscale,");
    console.log("then:  start <file> --host 0.0.0.0   and give them your Tailscale address instead. See the README, section \"Letting friends connect\".");
  } else if (where.length > 1) {
    console.log(`Other addresses this computer has: ${where.slice(1).join(", ")}`);
  }
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
      const state = await createProject(file, dataDir, name);
      console.log(`Project "${state.project.name}" created. Software fingerprint: ${state.project.target.sha256.slice(0, 16)}...`);
      console.log("Contributors must have:");
      for (const t of state.project.tools) console.log(`  - ${t.name} ${t.required}`);
      const added = addTasks(state, listFunctions(file));
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
      const state = await createProject(file, dataDir, flags.name && flags.name !== "true" ? flags.name : undefined);
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
      console.log(`  Results: ${count("trusted")} trusted, ${count("pending")} waiting for a check, ${count("hint")} hints, ${count("rejected")} rejected`);
      console.log(`  People: ${state.contributors.filter((c) => !c.revoked).map((c) => c.name).join(", ") || "nobody yet"}`);
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
