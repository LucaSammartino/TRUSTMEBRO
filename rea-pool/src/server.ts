import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { renameSync, statSync, unlinkSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { resolve as resolvePath } from "node:path";
import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import type { Confidence, Note, NoteStatus, Proposal, State, Task, Verdict } from "./types.ts";
import { checkText, IDENTIFIER, validateNote, type RawNote } from "./rules.ts";
import { initialStatus, proposalConfidence, resolveVotes, withDefaults } from "./trust.ts";
import { newToken, readJson, sha256Hex, writeJsonAtomic } from "./util.ts";
import { addCallees, basedOn, buildIndex, calleeContext, callerContext, cleanCallees, needsRefinement, graphStats, readiness, staleNotes, type Index } from "./graph.ts";
import { isShape, twinHints, twinPotential } from "./similar.ts";
import { buildActivity } from "./activity.ts";
import { LIVE_HTML } from "./live.ts";

const MAX_HANDOFFS = 5;

const MAX_BODY = 64 * 1024;

function readState(path: string): State {
  const state = readJson<State>(path);
  state.proposals ??= [];
  state.invites ??= [];
  const kinds = state.project?.rules?.allowedKinds;
  if (Array.isArray(kinds) && !state.project.provider) for (const k of ["variable_name", "signature", "struct_def"]) if (!kinds.includes(k)) kinds.push(k);
  return state;
}

/** Read the state file. Anything a running server in this process has not written yet is written first. */
export function loadState(path: string): State {
  const full = resolvePath(path);
  for (const h of live) if (h.path === full) h.flush();
  return readState(path);
}

const NAME_RE = /^[\w-]{1,30}$/;
const MODEL_RE = /^[A-Za-z0-9][\w.:/-]{0,59}$/;

/** Make a personal join code for one person. The code is returned once; only its hash is kept. */
export function createInvite(state: State, name: string): { code: string } | { error: string } {
  if (typeof name !== "string" || !NAME_RE.test(name)) return { error: "Pick a short name using letters, digits, - or _." };
  state.invites ??= [];
  if (state.contributors.some((c) => c.name === name)) return { error: "That name is already a contributor." };
  if (state.invites.some((i) => i.name === name && !i.usedAt)) return { error: "That name already has an unused invite." };
  const code = "ji_" + randomBytes(24).toString("base64url");
  state.invites.push({ name, codeHash: sha256Hex(code), created: new Date().toISOString() });
  return { code };
}

/** Remove an invite nobody has used yet. */
export function revokeInvite(state: State, name: string): boolean {
  const before = (state.invites ??= []).length;
  state.invites = state.invites.filter((i) => i.usedAt || i.name !== name);
  return state.invites.length < before;
}

export function listInvites(state: State): { name: string; created: string; used: boolean }[] {
  return (state.invites ?? []).map((i) => ({ name: i.name, created: i.created, used: !!i.usedAt }));
}

export function saveState(path: string, state: State): void {
  writeJsonAtomic(path, state);
}

// ---------------------------------------------------------------------------------------------
// The rules of the pool, as plain functions (no network), so they are easy to read and test.
// ---------------------------------------------------------------------------------------------

function isExpired(task: Task, now: number): boolean {
  return task.state === "claimed" && !!task.leaseUntil && Date.parse(task.leaseUntil) <= now;
}

function activeClaim(task: Task, now: number): boolean {
  return task.state === "claimed" && !isExpired(task, now);
}

function kindOf(task: Task): "analyze" | "review" {
  return task.kind ?? "analyze";
}

function proposalOf(state: State, task: Task, byId?: Map<string, Proposal>): Proposal | undefined {
  if (byId) return task.proposalId === undefined ? undefined : byId.get(task.proposalId);
  return state.proposals.find((p) => p.id === task.proposalId);
}

/** Proposals by id; the first one wins, like find. For loops that would otherwise scan every proposal per task. */
function proposalsById(state: State): Map<string, Proposal> {
  const m = new Map<string, Proposal>();
  for (const p of state.proposals) if (!m.has(p.id)) m.set(p.id, p);
  return m;
}

/** Can this person take this task right now? */
export function canTake(state: State, task: Task, who: string, now: number, byId?: Map<string, Proposal>): boolean {
  if (!(task.state === "open" || isExpired(task, now))) return false;
  if ((task.doneBy ?? []).includes(who)) return false;
  if (kindOf(task) === "review") {
    const proposal = proposalOf(state, task, byId);
    // Nobody checks their own work, and nobody votes twice on the same proposal.
    if (!proposal || proposal.status !== "pending" || proposal.author === who || proposal.votes.some((v) => v.by === who)) return false;
  }
  return true;
}

/** A function someone just gave up on waits at the back of the queue, so a crowd does not pass the same hard leftovers around. */
function isCooling(task: Task, now: number, cooldownMs: number): boolean {
  return !!task.releasedAt && Date.parse(task.releasedAt) + cooldownMs > now;
}

/** Lower sorts first: not cooling, callees most ready, given up on least, then the one with the most unnamed copies. */
function queueKey(state: State, task: Task, now: number, cooldownMs: number, strong = false, tiered = false, idx?: Index): number[] {
  const retry = (task.attempts ?? 1) > 1;
  return [tiered ? (retry === strong ? 0 : 1) : 0, isCooling(task, now, cooldownMs) ? 1 : 0, readiness(state, task, idx), task.abandons ?? 0, -twinPotential(state, task, idx)];
}

function keyBefore(a: number[], b: number[]): boolean {
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] < b[i];
  return false;
}

/** Of the analysis tasks someone can take, the best by queueKey; ties go to the earliest. */
function mostReady(state: State, who: string, now: number, model?: string): Task | undefined {
  const cooldownMs = withDefaults(state.project.rules).releaseCooldownMinutes * 60_000;
  const list = (state.project.rules.retryModels ?? []).map((m) => m.toLowerCase());
  const tiered = list.length > 0;
  const strong = !!model && list.includes(model.toLowerCase());
  const idx = buildIndex(state);
  let best: Task | undefined;
  let bestKey: number[] = [];
  for (const t of state.tasks) {
    if (kindOf(t) !== "analyze" || !canTake(state, t, who, now)) continue;
    const key = queueKey(state, t, now, cooldownMs, strong, tiered, idx);
    if (!best || keyBefore(key, bestKey)) {
      best = t;
      bestKey = key;
    }
  }
  return best;
}

/** Leases that ran out count as giving up: the function goes back to the pool, marked, and waits its turn. */
export function sweepExpired(state: State, now = Date.now()): number {
  let swept = 0;
  for (const t of state.tasks) {
    if (!isExpired(t, now)) continue;
    if (kindOf(t) === "analyze") {
      t.abandons = (t.abandons ?? 0) + 1;
      t.releasedAt = t.leaseUntil;
    }
    t.state = "open";
    release(t);
    swept++;
  }
  return swept;
}

export interface ReleaseResult {
  released: number;
  /** False when the note was missing or unusable and a generic one was stored instead. */
  noted: boolean;
}

const NO_NOTE = "Gave up without a usable note.";

/**
 * Someone gives their current task back, saying what they tried and what is unclear: the next person starts from
 * that, and the function waits at the back of the queue for a while. Never refuses: an unattended worker must not
 * get stuck on a bad note, so a missing or unusable one is replaced by a generic line.
 */
export function releaseTasks(state: State, who: string, note: unknown, now = Date.now(), taskId?: string): ReleaseResult {
  const mine = state.tasks.filter((t) => t.state === "claimed" && t.claimedBy === who && (taskId === undefined || t.id === taskId));
  const rules = withDefaults(state.project.rules);
  const trimmed = typeof note === "string" ? note.trim() : "";
  const noted = trimmed !== "" && checkText(trimmed, rules.maxTextLength) === null;
  const text = noted ? trimmed : NO_NOTE;
  for (const t of mine) {
    if (kindOf(t) === "analyze") {
      const at = new Date(now).toISOString();
      t.abandons = (t.abandons ?? 0) + 1;
      t.releasedAt = at;
      t.handoff = [...(t.handoff ?? []), { by: who, text, at }].slice(-MAX_HANDOFFS);
    }
    t.state = "open";
    release(t);
  }
  return { released: mine.length, noted };
}

const knownModel = (m: string | undefined): string | undefined => (m && m !== "unknown" ? m : undefined);

/** The model label on this person's most recent note. Self-reported, so only ever a soft preference. */
function latestModel(state: State, who: string): string | undefined {
  for (let i = state.notes.length - 1; i >= 0; i--) if (state.notes[i].author === who) return knownModel(state.notes[i].model);
  return undefined;
}

/** The model label the author of a review task's proposal gave. */
function authorModel(state: State, review: Task, byId: Map<string, Proposal>, noteOf: Map<string, Note>): string | undefined {
  const proposal = proposalOf(state, review, byId);
  return knownModel(proposal && noteOf.get(proposal.id)?.model);
}

/** Give someone their current task, or the next one. Checking other people's work comes before new work, then functions whose callees are already named. */
export function claimTask(state: State, who: string, now = Date.now(), slot = 0, model?: string): Task | null {
  sweepExpired(state, now);
  const mine = state.tasks.find((t) => t.claimedBy === who && (t.claimSlot ?? 0) === slot && activeClaim(t, now));
  if (mine) return mine;
  const byId = proposalsById(state);
  const reviews = state.tasks.filter((t) => kindOf(t) === "review" && canTake(state, t, who, now, byId));
  const own = reviews.length > 0 ? latestModel(state, who)?.toLowerCase() : undefined;
  let diverse: Task | undefined;
  if (own) {
    const noteOf = new Map<string, Note>();
    for (const n of state.notes) if (n.proposalId !== undefined && !noteOf.has(n.proposalId)) noteOf.set(n.proposalId, n);
    diverse = reviews.find((t) => {
      const theirs = authorModel(state, t, byId, noteOf)?.toLowerCase();
      return theirs !== undefined && theirs !== own;
    });
  }
  const next = diverse ?? reviews[0] ?? mostReady(state, who, now, model);
  if (!next) return null;
  next.state = "claimed";
  next.claimedBy = who;
  next.claimSlot = slot;
  next.leaseUntil = new Date(now + withDefaults(state.project.rules).leaseMinutes * 60_000).toISOString();
  return next;
}

/** True when this person has nothing left to do and nobody else is mid-task who might create more work. */
export function isFinishedFor(state: State, who: string, now = Date.now()): boolean {
  if (state.tasks.some((t) => t.claimedBy === who && activeClaim(t, now))) return false;
  const byId = proposalsById(state);
  if (state.tasks.some((t) => canTake(state, t, who, now, byId))) return false;
  return !state.tasks.some((t) => activeClaim(t, now) && t.claimedBy !== who);
}

export function proposalNotes(state: State, proposalId: string): Note[] {
  return state.notes.filter((n) => n.proposalId === proposalId && n.status !== "rejected");
}

function release(task: Task): void {
  delete task.claimedBy;
  delete task.claimSlot;
  delete task.leaseUntil;
}

function setProposalStatus(state: State, proposal: Proposal, status: NoteStatus, reason?: string): void {
  proposal.status = status;
  const agrees = proposal.votes.filter((v) => v.verdict === "agree").length;
  for (const n of state.notes) {
    if (n.proposalId !== proposal.id) continue;
    n.status = status;
    n.agrees = agrees;
    n.reason = reason;
  }
}

function addReviewTask(state: State, proposal: Proposal): void {
  const analyze = state.tasks.find((t) => t.id === proposal.taskId);
  const open = state.tasks.some((t) => kindOf(t) === "review" && t.proposalId === proposal.id && t.state !== "done");
  if (open || !analyze) return;
  state.tasks.push({
    id: `rv-${proposal.id.slice(0, 8)}-${proposal.votes.length + 1}`,
    kind: "review",
    label: `Check: ${analyze.label}`,
    address: analyze.address,
    state: "open",
    proposalId: proposal.id,
  });
}

/** After an attempt ends without anything trusted or pending, give the function to someone new, up to the limit. */
function settleAnalysisTask(state: State, task: Task): void {
  const alive = state.proposals.some((p) => p.taskId === task.id && (p.status === "trusted" || p.status === "pending"));
  const attempts = task.attempts ?? 1;
  if (!alive && attempts < withDefaults(state.project.rules).maxAttempts) {
    task.state = "open";
    task.attempts = attempts + 1;
  } else {
    task.state = "done";
  }
  release(task);
}

export interface NoteResult {
  ok: boolean;
  status: NoteStatus;
  reason?: string;
  id: string;
}

export const DUPLICATE_NAME = "that name is already used by another function";

/** Is this function name already a known name of another function, or a trusted/pending function_name note of another function? */
export function nameTakenElsewhere(state: State, task: Task, value: string): boolean {
  const v = value.toLowerCase();
  if (state.tasks.some((t) => t.id !== task.id && t.known?.name.toLowerCase() === v)) return true;
  return state.notes.some((n) => n.taskId !== task.id && n.kind === "function_name" && (n.status === "trusted" || n.status === "pending") && n.value.toLowerCase() === v);
}

/** Keep valid, distinct identifiers that differ from the main name; at most 3; ignore the rest silently. */
export function cleanAlternatives(value: unknown, primary?: string): string[] {
  if (!Array.isArray(value)) return [];
  const seen = new Set<string>(primary ? [primary.toLowerCase()] : []);
  const out: string[] = [];
  for (const item of value) {
    if (typeof item !== "string" || !IDENTIFIER.test(item) || seen.has(item.toLowerCase())) continue;
    seen.add(item.toLowerCase());
    out.push(item);
    if (out.length >= 3) break;
  }
  return out;
}

/** Someone finished an analysis task and sent notes. */
export function submitAnalysis(state: State, who: string, task: Task, rawNotes: RawNote[], now = new Date(), alternatives?: string[]): NoteResult[] {
  const proposalId = randomUUID();
  const based = basedOn(calleeContext(state, task.address));
  const notes: Note[] = rawNotes.map((raw) => {
    let verdict = validateNote(raw ?? {}, state.project.rules);
    if (verdict.ok && raw?.kind === "function_name" && nameTakenElsewhere(state, task, String(raw.value ?? "").slice(0, 600))) {
      verdict = { ok: false, reason: DUPLICATE_NAME };
    }
    return {
      id: randomUUID(),
      taskId: task.id,
      author: who,
      kind: String(raw?.kind ?? "").slice(0, 40),
      value: String(raw?.value ?? "").slice(0, 600),
      evidence: Array.isArray(raw?.evidence) ? (raw.evidence as unknown[]).slice(0, 5).map((e) => String(e).slice(0, 200)) : [],
      confidence: (["low", "medium", "high"].includes(raw?.confidence as string) ? raw.confidence : "low") as Confidence,
      model: typeof raw?.model === "string" ? raw.model.slice(0, 60) : "unknown",
      agent: typeof raw?.agent === "string" ? raw.agent.slice(0, 60) : undefined,
      at: now.toISOString(),
      status: verdict.ok ? "hint" : "rejected",
      reason: verdict.reason,
    } satisfies Note;
  });

  const valid = notes.filter((n) => n.status !== "rejected");
  if (valid.length > 0) {
    const confidence = proposalConfidence(valid.map((n) => n.confidence));
    const proposal: Proposal = { id: proposalId, taskId: task.id, author: who, confidence, status: initialStatus(confidence), votes: [], at: now.toISOString() };
    const alts = cleanAlternatives(alternatives, valid.find((n) => n.kind === "function_name")?.value);
    if (alts.length > 0) proposal.alternatives = alts;
    state.proposals.push(proposal);
    state.notes.push(...notes);
    for (const n of valid) {
      n.proposalId = proposalId;
      if (based.length > 0) n.basedOn = based;
    }
    const reason =
      proposal.status === "pending" ? "waiting for an independent check" : proposal.status === "hint" ? "low confidence: kept as a hint and the task will be retried by someone else" : undefined;
    setProposalStatus(state, proposal, proposal.status, reason);
    if (proposal.status === "pending") addReviewTask(state, proposal);
  } else {
    state.notes.push(...notes);
  }

  task.doneBy = [...(task.doneBy ?? []), who];
  settleAnalysisTask(state, task);
  flagStale(state, now.getTime());
  scheduleRefinement(state);
  return notes.map((n) => ({ ok: n.status !== "rejected", status: n.status, reason: n.reason, id: n.id }));
}

export interface ReviewResult {
  recorded: boolean;
  proposalStatus: NoteStatus;
}

/** Someone checked another person's proposal. */
export function submitReview(state: State, who: string, task: Task, verdict: Verdict, now = new Date()): ReviewResult {
  const proposal = proposalOf(state, task);
  task.doneBy = [...(task.doneBy ?? []), who];
  task.state = "done";
  release(task);
  if (!proposal || proposal.status !== "pending") return { recorded: false, proposalStatus: proposal?.status ?? "rejected" };

  proposal.votes.push({ by: who, verdict, at: now.toISOString() });
  const outcome = resolveVotes(proposal.votes, state.project.rules);
  const reasons: Partial<Record<NoteStatus, string>> = {
    trusted: "verified by an independent check",
    rejected: "checkers disagreed with it",
    hint: "checkers could not settle it; kept as a hint",
  };
  setProposalStatus(state, proposal, outcome, reasons[outcome] ?? "waiting for another independent check");
  if (outcome === "pending") {
    addReviewTask(state, proposal);
  } else {
    for (const t of state.tasks) if (kindOf(t) === "review" && t.proposalId === proposal.id && t.state !== "done") t.state = "done";
    const analysis = state.tasks.find((t) => t.id === proposal.taskId);
    if (analysis && outcome !== "trusted") settleAnalysisTask(state, analysis);
  }
  flagStale(state, now.getTime());
  scheduleRefinement(state);
  return { recorded: true, proposalStatus: outcome };
}

/**
 * When all work is finished, give each function that ended with no trusted name one more pass, now that its
 * callers are named. A function is reopened at most once (refined); whoever did it before is not given it again.
 */
export function scheduleRefinement(state: State): number {
  if (state.tasks.some((t) => t.state !== "done")) return 0;
  const idx = buildIndex(state);
  const todo = state.tasks.filter((t) => needsRefinement(state, t, idx));
  for (const t of todo) {
    t.refined = true;
    t.state = "open";
    t.attempts = 1;
  }
  return todo.length;
}

/**
 * Mark notes whose callee names changed as stale (and clear the mark when they match again). A finished function
 * with a stale note goes back to the pool, up to maxReopens times; people who did it before stay in doneBy.
 */
export function flagStale(state: State, now = Date.now()): number {
  const stale = new Set(staleNotes(state, buildIndex(state)));
  for (const n of state.notes) {
    if (stale.has(n)) n.stale = true;
    else if (n.stale) n.stale = false;
  }
  const max = withDefaults(state.project.rules).maxReopens;
  const ids = new Set([...stale].map((n) => n.taskId));
  for (const t of state.tasks) {
    if (!ids.has(t.id) || kindOf(t) !== "analyze" || t.state !== "done" || activeClaim(t, now)) continue;
    if ((t.reopened ?? 0) >= max) continue;
    if (state.proposals.some((p) => p.taskId === t.id && p.status === "pending")) continue;
    t.state = "open";
    t.reopened = (t.reopened ?? 0) + 1;
  }
  return stale.size;
}

/** Leader override: force a whole proposal trusted or rejected. */
export function overrideNote(state: State, noteId: string, status: "trusted" | "rejected"): boolean {
  const note = state.notes.find((n) => n.id === noteId);
  if (!note) return false;
  const proposal = state.proposals.find((p) => p.id === note.proposalId);
  if (proposal) {
    setProposalStatus(state, proposal, status, `set by leader`);
    for (const t of state.tasks) if (kindOf(t) === "review" && t.proposalId === proposal.id && t.state !== "done") t.state = "done";
  } else {
    note.status = status;
    note.reason = "set by leader";
  }
  flagStale(state);
  scheduleRefinement(state);
  return true;
}

// ---------------------------------------------------------------------------------------------
// The network side: a small web server.
// ---------------------------------------------------------------------------------------------

function send(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

function readBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject(new Error("too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (size === 0) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch {
        reject(new Error("bad json"));
      }
    });
    req.on("error", reject);
  });
}

function sameText(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

// ---------------------------------------------------------------------------------------------
// Live servers keep the state in memory and write it a moment after it changes.
// ---------------------------------------------------------------------------------------------

const WRITE_DELAY_MS = 200;
const MAX_WAIT_S = 25;

interface Live {
  path: string;
  flush(): void;
}
const live = new Set<Live>();
let hooked = false;
let writes = 0;

/** How many times a pool server has written its state file (for tests and diagnostics). */
export function stateWriteCount(): number {
  return writes;
}

/** Write out everything that is waiting to be saved. */
export function flushAllStates(): void {
  for (const h of [...live]) {
    try {
      h.flush();
    } catch {
      // nothing more can be done on the way out
    }
  }
}

function hookProcess(): void {
  if (hooked) return;
  hooked = true;
  process.on("exit", flushAllStates);
  for (const [sig, code] of [["SIGINT", 130], ["SIGTERM", 143]] as const) {
    process.on(sig, () => {
      flushAllStates();
      if (process.listenerCount(sig) === 1) process.exit(code);
    });
  }
}

const sigOf = (path: string): string => {
  const st = statSync(path);
  return `${st.mtimeMs}:${st.size}`;
};

interface Waiter {
  settle(final: boolean): void;
}

function claimReply(state: State, me: { name: string }, task: Task | null) {
  const proposal = task && kindOf(task) === "review" ? proposalOf(state, task) : undefined;
  const idx = task ? buildIndex(state) : undefined;
  return {
    task,
    // What the reviewer is asked to check. It is other people's text, so the reviewer treats it as data, never as instructions.
    proposal: proposal ? { notes: proposalNotes(state, proposal.id).map((n) => ({ kind: n.kind, value: n.value })), alternatives: proposal.alternatives ?? [] } : undefined,
    callees: task ? calleeContext(state, task.address, idx) : [],
    callers: task ? callerContext(state, task.address, idx) : [],
    // Other people's text again: the worker treats it as data. Only for functions being analyzed.
    handoff: task && kindOf(task) === "analyze" ? (task.handoff ?? []) : [],
    twins: task && kindOf(task) === "analyze" ? twinHints(state, task, idx) : [],
    finished: task ? false : isFinishedFor(state, me.name),
  };
}

export function createPoolServer(statePath: string): Server {
  const badJoinAttempts: number[] = [];
  const full = resolvePath(statePath);

  let cur: State | null = null;
  let sig = "";
  let dirty = false;
  let inflight = false;
  let syncGen = 0;
  let timer: NodeJS.Timeout | undefined;
  let wakePending = false;
  const waiters = new Set<Waiter>();

  /** Write now, on this thread (used on the way out, and when someone else is about to read the file). */
  const flush = (): void => {
    if (timer) clearTimeout(timer);
    timer = undefined;
    if (!cur || !(dirty || inflight)) return;
    syncGen++;
    dirty = false;
    writeJsonAtomic(full, cur);
    writes++;
    sig = sigOf(full);
  };

  const startWrite = (): void => {
    timer = undefined;
    if (!cur || !dirty || inflight) return;
    inflight = true;
    dirty = false;
    const gen = syncGen;
    const tmp = `${full}.async.tmp`;
    writeFile(tmp, JSON.stringify(cur, null, 2))
      .then(() => {
        if (gen !== syncGen) return void unlinkSync(tmp); // a synchronous write overtook this one
        renameSync(tmp, full);
        writes++;
        sig = sigOf(full);
      })
      .catch(() => {
        dirty = true;
      })
      .finally(() => {
        inflight = false;
        if (dirty && !timer) {
          timer = setTimeout(startWrite, WRITE_DELAY_MS);
          timer.unref();
        }
      });
  };

  const wake = (): void => {
    wakePending = false;
    for (const w of [...waiters]) w.settle(false);
  };

  const markDirty = (): void => {
    dirty = true;
    if (!timer && !inflight) {
      timer = setTimeout(startWrite, WRITE_DELAY_MS);
      timer.unref();
    }
    if (waiters.size > 0 && !wakePending) {
      wakePending = true;
      setImmediate(wake);
    }
  };

  /** The state every request works on: loaded once, and re-read only when another program changed the file. */
  const current = (): State => {
    if (!cur) {
      cur = readState(statePath);
      sig = sigOf(statePath);
      return cur;
    }
    if (inflight) return cur;
    let now = "";
    try {
      now = sigOf(statePath);
    } catch {
      return cur;
    }
    if (now === sig) return cur;
    if (dirty) {
      flush();
      return cur;
    }
    cur = readState(statePath);
    sig = now;
    return cur;
  };

  const handle: Live = { path: full, flush };
  live.add(handle);
  hookProcess();

  const server = createServer(async (req, res) => {
    try {
      const raw = req.method === "POST" ? await readBody(req) : {};
      const state = current();
      const url = new URL(req.url ?? "/", "http://x");
      const route = `${req.method} ${url.pathname}`;
      const rules = withDefaults(state.project.rules);

      // Joining is the one request that needs no personal token, only the project's shared code.
      if (route === "POST /join") {
        const now = Date.now();
        while (badJoinAttempts.length && badJoinAttempts[0] < now - 10 * 60_000) badJoinAttempts.shift();
        if (badJoinAttempts.length >= 20) return send(res, 429, { error: "Too many wrong join codes. Try again in a few minutes." });
        const body = raw as { code?: unknown; name?: unknown };
        const codeHash = typeof body.code === "string" ? sha256Hex(body.code) : "";
        const invite = codeHash ? (state.invites ?? []).find((i) => !i.usedAt && sameText(codeHash, i.codeHash)) : undefined;
        if (!invite && (typeof body.code !== "string" || state.sharedCodeOff || !sameText(body.code, state.joinCode))) {
          badJoinAttempts.push(now);
          return send(res, 403, { error: "That join code is not right." });
        }
        if (invite) body.name = invite.name;
        if (typeof body.name !== "string" || !NAME_RE.test(body.name)) {
          return send(res, 400, { error: "Pick a short name using letters, digits, - or _." });
        }
        if (state.contributors.some((c) => c.name === body.name)) return send(res, 409, { error: "That name is taken. Pick another with --name." });
        if (state.contributors.length >= rules.maxContributors) return send(res, 403, { error: "This project is full." });
        const token = newToken();
        if (invite) invite.usedAt = new Date().toISOString();
        state.contributors.push({ name: body.name, tokenHash: sha256Hex(token), joined: new Date().toISOString(), revoked: false });
        markDirty();
        return send(res, 200, { token, name: body.name, project: state.project });
      }

      // The live page holds no data (it fetches /activity with the person's token), so it needs no token itself.
      if (route === "GET /live") {
        res.writeHead(200, {
          "content-type": "text/html; charset=utf-8",
          "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'",
          "cache-control": "no-store",
        });
        return res.end(LIVE_HTML);
      }

      const header = req.headers.authorization ?? "";
      const token = header.startsWith("Bearer ") ? header.slice(7) : "";
      const hash = sha256Hex(token);
      const me = token ? state.contributors.find((c) => c.tokenHash === hash && !c.revoked) : undefined;
      if (!me) return send(res, 401, { error: "Not recognized. Join again with the join code, or ask the leader." });

      if (route === "GET /project") return send(res, 200, { project: state.project, you: me.name });

      if (route === "GET /status") {
        const now = Date.now();
        const counts = { open: 0, claimed: 0, done: 0 };
        const idx = buildIndex(state);
        for (const t of state.tasks) counts[isExpired(t, now) ? "open" : t.state]++;
        const count = (s: NoteStatus) => state.proposals.filter((p) => p.status === s).length;
        return send(res, 200, {
          tasks: counts,
          trusted: count("trusted"),
          pending: count("pending"),
          hints: count("hint"),
          rejected: count("rejected"),
          yourProposals: state.proposals.filter((p) => p.author === me.name).length,
          finished: isFinishedFor(state, me.name),
          graph: graphStats(state, idx),
          stale: staleNotes(state, idx).length,
          known: state.tasks.filter((t) => t.known).length,
          invitesPending: (state.invites ?? []).filter((i) => !i.usedAt).length,
        });
      }

      if (route === "GET /activity") return send(res, 200, buildActivity(state, Date.now(), me.name));

      if (route === "POST /claim") {
        const claimBody = raw as { slot?: unknown; model?: unknown; wait?: unknown } | null;
        const slot = claimBody?.slot ?? 0;
        if (typeof slot !== "number" || !Number.isInteger(slot) || slot < 0 || slot >= rules.maxParallel) {
          return send(res, 400, { error: `slot must be a whole number from 0 to ${rules.maxParallel - 1}.` });
        }
        const model = typeof claimBody?.model === "string" && MODEL_RE.test(claimBody.model) ? claimBody.model : undefined;
        const waitS = typeof claimBody?.wait === "number" && Number.isFinite(claimBody.wait) ? Math.min(MAX_WAIT_S, Math.max(0, Math.floor(claimBody.wait))) : 0;
        const name = me.name;
        // One attempt to give this person something, on whatever the current state is.
        const attempt = (): { task: Task | null; reply: ReturnType<typeof claimReply> } | null => {
          const st = current();
          const who = st.contributors.find((c) => c.name === name && !c.revoked);
          if (!who) return null;
          let changed = false;
          if (model && who.model !== model) {
            who.model = model;
            changed = true;
          }
          if (sweepExpired(st) > 0) changed = true;
          const task = claimTask(st, name, Date.now(), slot, model ?? who.model);
          if (task || changed) markDirty();
          return { task, reply: claimReply(st, who, task) };
        };
        const first = attempt();
        if (!first) return send(res, 401, { error: "Not recognized. Join again with the join code, or ask the leader." });
        if (first.task || first.reply.finished || waitS === 0) return send(res, 200, first.reply);
        await new Promise<void>((done) => {
          const waiter: Waiter = {
            settle: (final) => {
              const r = attempt();
              if (r && !final && !r.task && !r.reply.finished) return;
              clearTimeout(t);
              waiters.delete(waiter);
              if (!res.destroyed && !res.writableEnded) {
                if (r) send(res, 200, r.reply);
                else send(res, 401, { error: "Not recognized. Join again with the join code, or ask the leader." });
              }
              done();
            },
          };
          const t = setTimeout(() => waiter.settle(true), waitS * 1000);
          waiters.add(waiter);
          res.on("close", () => {
            clearTimeout(t);
            waiters.delete(waiter);
            done();
          });
        });
        return;
      }

      if (route === "POST /release") {
        const body = raw as { note?: unknown; taskId?: unknown };
        const result = releaseTasks(state, me.name, body.note, Date.now(), typeof body.taskId === "string" ? body.taskId : undefined);
        markDirty();
        return send(res, 200, { ok: true, ...result });
      }

      if (route === "POST /submit") {
        const body = raw as { taskId?: unknown; notes?: unknown; protocol?: unknown; verdict?: unknown; callees?: unknown; shape?: unknown; alternatives?: unknown };
        if (body.protocol !== rules.protocol) {
          return send(res, 400, { error: `This project uses note format "${rules.protocol}" but you sent "${String(body.protocol)}". Update your pool tool.` });
        }
        const task = state.tasks.find((t) => t.id === body.taskId);
        if (!task || task.state !== "claimed" || task.claimedBy !== me.name) {
          return send(res, 409, { error: "You do not hold a current claim on that task. Claim a task first." });
        }
        if (kindOf(task) === "review") {
          if (!["agree", "disagree", "unsure"].includes(body.verdict as string)) return send(res, 400, { error: 'verdict must be "agree", "disagree" or "unsure".' });
          const result = submitReview(state, me.name, task, body.verdict as Verdict);
          markDirty();
          return send(res, 200, { review: result });
        }
        if (!Array.isArray(body.notes) || body.notes.length === 0 || body.notes.length > 20) {
          return send(res, 400, { error: "Send between 1 and 20 notes." });
        }
        if (Array.isArray(body.callees)) addCallees(task, cleanCallees(body.callees, task.address));
        if (isShape(body.shape)) task.shape = body.shape;
        const results = submitAnalysis(state, me.name, task, body.notes as RawNote[], new Date(), cleanAlternatives(body.alternatives));
        markDirty();
        return send(res, 200, { results });
      }

      return send(res, 404, { error: "Unknown request." });
    } catch (err) {
      const message = err instanceof Error ? err.message : "error";
      return send(res, message === "too large" ? 413 : 400, { error: message });
    }
  });

  // Closing answers whoever is still waiting, writes what is pending, and leaves the registry.
  const finish = (): void => {
    for (const w of [...waiters]) w.settle(true);
    try {
      flush();
    } finally {
      live.delete(handle);
    }
  };
  const close = server.close.bind(server);
  server.close = ((cb?: (err?: Error) => void) => {
    finish();
    return close(cb);
  }) as typeof server.close;
  server.on("close", finish);
  return server;
}
