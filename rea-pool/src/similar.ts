// Similar functions: programs often contain the same code more than once (statically linked libraries, copy-pasted
// helpers). Such copies decompile to the same shape, so a name found for one is a useful hint for the others.
import { createHash } from "node:crypto";
import type { State, Task } from "./types.ts";
import { normalizeAddress, trustedName, type Index, type ShapeInfo } from "./graph.ts";

/** Shorter than this and "the same shape" means nothing: thousands of functions are just `return 0;`. */
const MIN_SHAPE_LENGTH = 120;
const MAX_TWIN_HINTS = 5;

/**
 * Reduce decompiler output to its structure: names the decompiler invents (FUN_00401000, local_14, iVar3, param_1),
 * addresses and comments are replaced by placeholders, so two copies of a function at different addresses match.
 * Returns null for code too short to say anything with.
 */
export function shapeOf(code: unknown): string | null {
  if (typeof code !== "string") return null;
  const flat = code
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/\/\/[^\n]*/g, " ")
    .replace(/\b(?:thunk_)?(?:FUN|DAT|PTR|LAB|SUB|switchD|caseD)_[0-9a-fA-F]{4,}\b/g, "SYM")
    .replace(/\b0x[0-9a-fA-F]{5,}\b/g, "ADDR")
    .replace(/\b(?:local|Stack)_[0-9a-zA-Z]+\b/g, "V")
    .replace(/\bparam_\d+\b/g, "V")
    .replace(/\b[a-z]{0,3}Var\d+\b/g, "V")
    .replace(/\s+/g, " ")
    .trim();
  if (flat.length < MIN_SHAPE_LENGTH) return null;
  return createHash("sha256").update(flat).digest("hex").slice(0, 16);
}

export function isShape(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{16}$/.test(value);
}

function twinsOf(state: State, task: Task, idx?: Index): Task[] {
  if (!task.shape) return [];
  if (idx) return (idx.shapes.get(task.shape) ?? []).filter((t) => t !== task);
  return state.tasks.filter((t) => (t.kind ?? "analyze") === "analyze" && t !== task && t.shape === task.shape);
}

/** Per-shape summary, computed once per index: the first few named copies and how many copies are not done. */
function shapeInfo(state: State, shape: string, idx: Index): ShapeInfo {
  let info = idx.shapeInfo.get(shape);
  if (info) return info;
  info = { named: [], notDone: 0, members: new Set() };
  for (const t of idx.shapes.get(shape) ?? []) {
    info.members.add(t);
    if (t.state !== "done") info.notDone++;
    if (info.named.length > MAX_TWIN_HINTS) continue;
    const address = normalizeAddress(t.address);
    const name = address ? trustedName(state, address, idx) : undefined;
    if (address && name) info.named.push({ task: t, address, name });
  }
  idx.shapeInfo.set(shape, info);
  return info;
}

export interface TwinHint {
  address: string;
  name: string;
}

/** Trusted names of functions that look like copies of this one. A hint for whoever works on it, never a verdict. */
export function twinHints(state: State, task: Task, idx?: Index): TwinHint[] {
  const out: TwinHint[] = [];
  if (idx) {
    if (!task.shape) return out;
    for (const n of shapeInfo(state, task.shape, idx).named) {
      if (n.task === task) continue;
      out.push({ address: n.address, name: n.name });
      if (out.length >= MAX_TWIN_HINTS) break;
    }
    return out;
  }
  for (const twin of twinsOf(state, task)) {
    const address = normalizeAddress(twin.address);
    const name = address ? trustedName(state, address) : undefined;
    if (address && name) out.push({ address, name });
    if (out.length >= MAX_TWIN_HINTS) break;
  }
  return out;
}

/**
 * How many copies of this function are still waiting, when none of the copies has a trusted name yet. Doing such a
 * function first pays off the most: every copy then starts with a hint instead of from nothing.
 */
export function twinPotential(state: State, task: Task, idx?: Index): number {
  if (!task.shape) return 0;
  if (idx) {
    if (twinHints(state, task, idx).length > 0) return 0;
    const info = shapeInfo(state, task.shape, idx);
    return info.notDone - (info.members.has(task) && task.state !== "done" ? 1 : 0);
  }
  if (twinHints(state, task).length > 0) return 0;
  return twinsOf(state, task).filter((t) => t.state !== "done").length;
}
