import { copyFileSync, existsSync, mkdirSync, realpathSync } from "node:fs";
import { basename, dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { State } from "./types.ts";
import { compareNotes } from "./trust.ts";
import { normalizeAddress } from "./graph.ts";
import { CORVUS_VERSION, detectTargetKind, methodToken, type CorvusStep } from "./corvus.ts";
import { checkText, IDENTIFIER } from "./rules.ts";
import { IS_WINDOWS } from "./exec.ts";
import { sha256FileSync } from "./prepare.ts";
import { writeJsonAtomic } from "./util.ts";

export interface ApplyEntry {
  address: string;
  name: string;
  comment?: string;
  alternatives?: string[];
  variables?: { from: string; to: string }[];
  signature?: string;
  structs?: string[];
  confidence: string;
  agrees: number;
}

const MAX_VARIABLES = 10;
const MAX_STRUCTS = 2;

function parseVariable(value: string): { from: string; to: string } | undefined {
  const m = /^\s*([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*$/.exec(value);
  return m && m[1] !== m[2] ? { from: m[1]!, to: m[2]! } : undefined;
}

export function buildApplyEntries(state: State): ApplyEntry[] {
  const entries: ApplyEntry[] = [];
  for (const task of state.tasks) {
    if ((task.kind ?? "analyze") !== "analyze" || (task as typeof task & { known?: boolean }).known) continue;
    const address = normalizeAddress(task.address);
    if (!address) continue;
    const notes = state.notes.filter((n) => n.taskId === task.id && n.status === "trusted").sort(compareNotes);
    const name = notes.find((n) => n.kind === "function_name");
    if (!name) continue;
    const comment = notes.find((n) => n.kind === "comment");
    const proposal = state.proposals.find((p) => p.id === name.proposalId);
    const alternatives = (proposal as { alternatives?: string[] } | undefined)?.alternatives;
    // Prefer detail notes from the proposal that produced the chosen name, else the best trusted ones.
    const pick = (kind: string) => {
      const all = notes.filter((n) => n.kind === kind);
      const own = name.proposalId ? all.filter((n) => n.proposalId === name.proposalId) : [];
      return own.length > 0 ? own : all;
    };
    const variables: { from: string; to: string }[] = [];
    const seenFrom = new Set<string>();
    for (const n of pick("variable_name")) {
      const v = parseVariable(n.value);
      if (!v || seenFrom.has(v.from)) continue;
      seenFrom.add(v.from);
      variables.push(v);
      if (variables.length >= MAX_VARIABLES) break;
    }
    const signature = pick("signature").map((n) => n.value.trim()).find((v) => v.length > 0);
    const structs = [...new Set(pick("struct_def").map((n) => n.value.trim()).filter((v) => v.length > 0))].slice(0, MAX_STRUCTS);
    entries.push({ address, name: name.value, confidence: name.confidence, agrees: name.agrees ?? 0,
      ...(comment ? { comment: comment.value } : {}), ...(alternatives ? { alternatives } : {}),
      ...(variables.length ? { variables } : {}), ...(signature ? { signature } : {}),
      ...(structs.length ? { structs } : {}) });
  }
  return entries.sort((a, b) => a.address.localeCompare(b.address));
}

export function writeApplyBundle(state: State, outDir: string): { namesFile: string; scriptFile: string; count: number } {
  const source = fileURLToPath(new URL("../ghidra/ApplyNames.java", import.meta.url));
  if (!existsSync(source)) throw new Error("Cannot find ghidra/ApplyNames.java");
  mkdirSync(outDir, { recursive: true });
  const functions = buildApplyEntries(state);
  const namesFile = join(outDir, "names.json");
  const scriptFile = join(outDir, "ApplyNames.java");
  writeJsonAtomic(namesFile, { project: state.project.name, target: state.project.target.sha256, functions });
  copyFileSync(source, scriptFile);
  return { namesFile, scriptFile, count: functions.length };
}

/** Generate instructions only. Running the batch is the owner's choice; the original is never a save target. */
export function writeCorvusApplyBundle(state: State, outDir: string, targetPath?: string): {
  namesFile: string; count: number; batchFile?: string; outputFile?: string; sessionFile?: string;
} {
  const android = state.project.provider === "corvus-android";
  if (!android && state.project.provider !== "corvus-dotnet") throw new Error("This project does not use Corvus.");
  if (state.project.corvusVersion !== CORVUS_VERSION) throw new Error(`This export needs the project's Corvus ${CORVUS_VERSION} reader.`);
  const functions = buildApplyEntries({ ...state, notes: state.notes.filter((n) => !n.stale) });
  for (const entry of functions) {
    if (!IDENTIFIER.test(entry.name) || checkText(entry.name, 64) || (entry.comment && checkText(entry.comment, state.project.rules.maxTextLength)) ||
        (!android && !methodToken(`0x${entry.address.slice(2).padStart(8, "0")}`))) throw new Error("A trusted name, comment or method token is unusable. Nothing was written.");
  }
  let assembly: string | undefined;
  if (!android) {
    if (!targetPath || !existsSync(targetPath)) throw new Error("Give your original assembly's path: leader apply --target <program file>. This is needed to write a batch for the right file.");
    assembly = resolve(targetPath);
    if (sha256FileSync(assembly) !== state.project.target.sha256 || detectTargetKind(assembly) !== "dotnet") throw new Error("That assembly does not match this project's fingerprint. Nothing was written.");
  }
  mkdirSync(outDir, { recursive: true });
  const namesFile = join(resolve(outDir), "names.json");
  if (targetPath && existsSync(targetPath)) {
    const spelling = (path: string) => IS_WINDOWS ? path.toLowerCase() : path;
    const original = spelling(realpathSync(targetPath));
    const files = [namesFile, join(resolve(outDir), "corvus-batch.json"), join(resolve(outDir), "corvus-session.json")];
    if (files.some((file) => spelling(join(realpathSync(dirname(file)), basename(file))) === original)) throw new Error("Choose a different output folder so the original file is kept.");
  }
  writeJsonAtomic(namesFile, { project: state.project.name, target: state.project.target.sha256, provider: state.project.provider, functions });
  if (!assembly) return { namesFile, count: functions.length };
  const extension = extname(assembly), base = basename(assembly, extension);
  const outputFile = join(resolve(outDir), `${base}.renamed${extension}`);
  const batchFile = join(resolve(outDir), "corvus-batch.json"), sessionFile = join(resolve(outDir), "corvus-session.json");
  const steps: CorvusStep[] = [{ tool: "load_assembly", args: { path: assembly } }];
  for (const entry of functions) {
    const symbol = `0x${entry.address.slice(2).padStart(8, "0")}`;
    steps.push({ tool: "rename_symbol", args: { assembly, symbol, kind: "method", newName: entry.name, dryRun: false } });
    if (entry.comment) steps.push({ tool: "record_note", args: { anchor: `${assembly}:${symbol}`, text: entry.comment, kind: "finding" } });
  }
  steps.push({ tool: "save_assembly", args: { assembly, outputPath: outputFile, overwrite: false } },
    { tool: "save_session", args: { outputPath: sessionFile, include: "edits,annotations,notes", overwrite: false } });
  writeJsonAtomic(batchFile, steps);
  return { namesFile, count: functions.length, batchFile, outputFile, sessionFile };
}
