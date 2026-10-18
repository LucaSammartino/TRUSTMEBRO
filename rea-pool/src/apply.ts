import { copyFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { State } from "./types.ts";
import { compareNotes } from "./trust.ts";
import { normalizeAddress } from "./graph.ts";
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
