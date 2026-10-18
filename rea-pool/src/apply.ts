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
  confidence: string;
  agrees: number;
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
    entries.push({ address, name: name.value, confidence: name.confidence, agrees: name.agrees ?? 0,
      ...(comment ? { comment: comment.value } : {}), ...(alternatives ? { alternatives } : {}) });
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
