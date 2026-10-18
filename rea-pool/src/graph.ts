// The call graph: which function calls which, so the pool can work from the bottom up.
// A function is easier to name once the functions it calls already have trusted names.
import type { Note, State, Task } from "./types.ts";
import { compareNotes } from "./trust.ts";

const MAX_CALLEES = 200;
const MAX_CONTEXT = 30;

/** One spelling for every address: 0x, lowercase, no leading zeros. Returns null if it is not an address. */
export function normalizeAddress(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const match = value.trim().match(/^0x([0-9a-f]{1,16})$/i);
  if (!match) return null;
  return `0x${match[1].toLowerCase().replace(/^0+(?=.)/, "")}`;
}

/** Clean a list of callee addresses sent by a worker or read from rea. Drops junk, duplicates and the function itself. */
export function cleanCallees(value: unknown, self: string): string[] {
  if (!Array.isArray(value)) return [];
  const me = normalizeAddress(self);
  const out = new Set<string>();
  for (const item of value) {
    const address = normalizeAddress(item);
    if (address && address !== me) out.add(address);
    if (out.size >= MAX_CALLEES) break;
  }
  return [...out];
}

/** Pull callee addresses out of the result of `rea function`. Imports from other libraries are skipped; thunks point at their real target. */
export function calleesFromReaFunction(result: unknown, self: string): string[] {
  const list = (result as { callees?: unknown })?.callees;
  if (!Array.isArray(list)) return [];
  const found: unknown[] = [];
  for (const callee of list as { address?: unknown; classification?: { external?: boolean; thunk?: boolean; thunk_target?: unknown } }[]) {
    if (callee?.classification?.external) continue;
    const target = callee?.classification?.thunk ? normalizeAddress(callee.classification.thunk_target) : null;
    found.push(target ?? callee?.address);
  }
  return cleanCallees(found, self);
}

type Resolution = "resolved" | "unresolved";

function analysisTaskAt(state: State, address: string): Task | undefined {
  return state.tasks.find((t) => (t.kind ?? "analyze") === "analyze" && normalizeAddress(t.address) === address);
}

/** The best trusted name the pool has for the function at this address, if any. */
export function trustedName(state: State, address: string): string | undefined {
  const task = analysisTaskAt(state, address);
  if (!task) return undefined;
  if (task.known) return task.known.name;
  const winners = state.notes.filter((n) => n.taskId === task.id && n.kind === "function_name" && n.status === "trusted").sort(compareNotes);
  return winners[0]?.value;
}

/**
 * Is this callee still worth waiting for? It is resolved when it has a trusted name, when its work is finished
 * (nothing more will come of it), or when it is not one of our functions (imports, unknown targets).
 */
function resolution(state: State, address: string): Resolution {
  const task = analysisTaskAt(state, address);
  if (!task || task.state === "done") return "resolved";
  return trustedName(state, address) ? "resolved" : "unresolved";
}

/**
 * How ready a function is, lower is better.
 *   0        callees are known and all resolved (or it calls nothing)
 *   1        callees are not known yet; we cannot tell
 *   1 + n    callees are known and n of them are still unresolved
 */
export function readiness(state: State, task: Task): number {
  if (!task.callees) return 1;
  const open = task.callees.filter((a) => resolution(state, a) === "unresolved").length;
  return open === 0 ? 0 : 1 + open;
}

export interface CalleeInfo {
  address: string;
  name: string;
}

/** The callee names a worker may be shown: only names that were trusted, never guesses that are still being checked. */
export function calleeContext(state: State, address: string): CalleeInfo[] {
  const task = analysisTaskAt(state, normalizeAddress(address) ?? "");
  if (!task?.callees) return [];
  const out: CalleeInfo[] = [];
  for (const callee of task.callees) {
    const name = trustedName(state, callee);
    if (name) out.push({ address: callee, name });
    if (out.length >= MAX_CONTEXT) break;
  }
  return out;
}

/** The functions that call this one and already have a trusted or known name (at most 30). Same shape as calleeContext. */
export function callerContext(state: State, address: string): CalleeInfo[] {
  const me = normalizeAddress(address);
  if (!me) return [];
  const out: CalleeInfo[] = [];
  for (const t of state.tasks) {
    if ((t.kind ?? "analyze") !== "analyze" || !t.callees?.includes(me)) continue;
    const name = trustedName(state, t.address);
    if (name) out.push({ address: normalizeAddress(t.address) ?? t.address, name });
    if (out.length >= MAX_CONTEXT) break;
  }
  return out;
}

/** Pure: should this finished function get one more pass now that its callers are named? */
export function needsRefinement(state: State, task: Task): boolean {
  if ((task.kind ?? "analyze") !== "analyze" || task.state !== "done" || task.known || task.refined) return false;
  if (state.proposals.some((p) => p.taskId === task.id && p.status === "trusted")) return false;
  return callerContext(state, task.address).length > 0;
}

/** The same list as text lines, for notes: which callee names this answer was built on. */
export function basedOn(context: CalleeInfo[]): string[] {
  return context.map((c) => `${c.address}=${c.name}`);
}

/** Trusted notes built on a callee name that is no longer the trusted one (changed, or no trusted name left). Pure. */
export function staleNotes(state: State): Note[] {
  return state.notes.filter((n) => {
    if (n.status !== "trusted" || !n.basedOn || n.basedOn.length === 0) return false;
    return n.basedOn.some((entry) => {
      const i = entry.indexOf("=");
      if (i < 0) return false;
      return trustedName(state, entry.slice(0, i)) !== entry.slice(i + 1);
    });
  });
}

/** Record callees for an analysis task. Returns true if anything changed. Existing knowledge is kept, new addresses are added. */
export function addCallees(task: Task, callees: string[]): boolean {
  const merged = cleanCallees([...(task.callees ?? []), ...callees], task.address);
  const changed = merged.length !== (task.callees ?? []).length || task.callees === undefined;
  task.callees = merged;
  return changed;
}

export interface GraphStats {
  known: number;
  unknown: number;
  edges: number;
  ready: number;
}

export function graphStats(state: State): GraphStats {
  const analysis = state.tasks.filter((t) => (t.kind ?? "analyze") === "analyze");
  const known = analysis.filter((t) => t.callees);
  return {
    known: known.length,
    unknown: analysis.length - known.length,
    edges: known.reduce((sum, t) => sum + (t.callees?.length ?? 0), 0),
    ready: known.filter((t) => readiness(state, t) === 0).length,
  };
}
