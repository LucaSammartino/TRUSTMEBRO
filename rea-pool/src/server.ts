import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { randomUUID, timingSafeEqual } from "node:crypto";
import type { Confidence, Note, NoteStatus, Proposal, State, Task, Verdict } from "./types.ts";
import { checkText, validateNote, type RawNote } from "./rules.ts";
import { initialStatus, proposalConfidence, resolveVotes, withDefaults } from "./trust.ts";
import { newToken, readJson, sha256Hex, writeJsonAtomic } from "./util.ts";
import { addCallees, basedOn, calleeContext, cleanCallees, graphStats, readiness, staleNotes } from "./graph.ts";
import { isShape, twinHints, twinPotential } from "./similar.ts";
import { buildActivity } from "./activity.ts";
import { LIVE_HTML } from "./live.ts";

const MAX_HANDOFFS = 5;

const MAX_BODY = 64 * 1024;

export function loadState(path: string): State {
  const state = readJson<State>(path);
  state.proposals ??= [];
  return state;
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

function proposalOf(state: State, task: Task): Proposal | undefined {
  return state.proposals.find((p) => p.id === task.proposalId);
}

/** Can this person take this task right now? */
export function canTake(state: State, task: Task, who: string, now: number): boolean {
  if (!(task.state === "open" || isExpired(task, now))) return false;
  if ((task.doneBy ?? []).includes(who)) return false;
  if (kindOf(task) === "review") {
    const proposal = proposalOf(state, task);
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
function queueKey(state: State, task: Task, now: number, cooldownMs: number): number[] {
  return [isCooling(task, now, cooldownMs) ? 1 : 0, readiness(state, task), task.abandons ?? 0, -twinPotential(state, task)];
}

function keyBefore(a: number[], b: number[]): boolean {
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] < b[i];
  return false;
}

/** Of the analysis tasks someone can take, the best by queueKey; ties go to the earliest. */
function mostReady(state: State, who: string, now: number): Task | undefined {
  const cooldownMs = withDefaults(state.project.rules).releaseCooldownMinutes * 60_000;
  let best: Task | undefined;
  let bestKey: number[] = [];
  for (const t of state.tasks) {
    if (kindOf(t) !== "analyze" || !canTake(state, t, who, now)) continue;
    const key = queueKey(state, t, now, cooldownMs);
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

/** Give someone their current task, or the next one. Checking other people's work comes before new work, then functions whose callees are already named. */
export function claimTask(state: State, who: string, now = Date.now(), slot = 0): Task | null {
  sweepExpired(state, now);
  const mine = state.tasks.find((t) => t.claimedBy === who && (t.claimSlot ?? 0) === slot && activeClaim(t, now));
  if (mine) return mine;
  const next = state.tasks.find((t) => kindOf(t) === "review" && canTake(state, t, who, now)) ?? mostReady(state, who, now);
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
  if (state.tasks.some((t) => canTake(state, t, who, now))) return false;
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

/** Someone finished an analysis task and sent notes. */
export function submitAnalysis(state: State, who: string, task: Task, rawNotes: RawNote[], now = new Date()): NoteResult[] {
  const proposalId = randomUUID();
  const based = basedOn(calleeContext(state, task.address));
  const notes: Note[] = rawNotes.map((raw) => {
    const verdict = validateNote(raw ?? {}, state.project.rules);
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
  return { recorded: true, proposalStatus: outcome };
}

/**
 * Mark notes whose callee names changed as stale (and clear the mark when they match again). A finished function
 * with a stale note goes back to the pool, up to maxReopens times; people who did it before stay in doneBy.
 */
export function flagStale(state: State, now = Date.now()): number {
  const stale = new Set(staleNotes(state));
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

export function createPoolServer(statePath: string): Server {
  const badJoinAttempts: number[] = [];

  return createServer(async (req, res) => {
    try {
      const state = loadState(statePath);
      const url = new URL(req.url ?? "/", "http://x");
      const route = `${req.method} ${url.pathname}`;
      const rules = withDefaults(state.project.rules);

      // Joining is the one request that needs no personal token, only the project's shared code.
      if (route === "POST /join") {
        const now = Date.now();
        while (badJoinAttempts.length && badJoinAttempts[0] < now - 10 * 60_000) badJoinAttempts.shift();
        if (badJoinAttempts.length >= 20) return send(res, 429, { error: "Too many wrong join codes. Try again in a few minutes." });
        const body = (await readBody(req)) as { code?: unknown; name?: unknown };
        if (typeof body.code !== "string" || !sameText(body.code, state.joinCode)) {
          badJoinAttempts.push(now);
          return send(res, 403, { error: "That join code is not right." });
        }
        if (typeof body.name !== "string" || !/^[\w-]{1,30}$/.test(body.name)) {
          return send(res, 400, { error: "Pick a short name using letters, digits, - or _." });
        }
        if (state.contributors.some((c) => c.name === body.name)) return send(res, 409, { error: "That name is taken. Pick another with --name." });
        if (state.contributors.length >= rules.maxContributors) return send(res, 403, { error: "This project is full." });
        const token = newToken();
        state.contributors.push({ name: body.name, tokenHash: sha256Hex(token), joined: new Date().toISOString(), revoked: false });
        saveState(statePath, state);
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
          graph: graphStats(state),
          stale: staleNotes(state).length,
        });
      }

      if (route === "GET /activity") return send(res, 200, buildActivity(state, Date.now(), me.name));

      if (route === "POST /claim") {
        const claimBody = (await readBody(req)) as { slot?: unknown } | null;
        const slot = claimBody?.slot ?? 0;
        if (typeof slot !== "number" || !Number.isInteger(slot) || slot < 0 || slot >= rules.maxParallel) {
          return send(res, 400, { error: `slot must be a whole number from 0 to ${rules.maxParallel - 1}.` });
        }
        const task = claimTask(state, me.name, Date.now(), slot);
        saveState(statePath, state);
        const proposal = task && kindOf(task) === "review" ? proposalOf(state, task) : undefined;
        return send(res, 200, {
          task,
          // What the reviewer is asked to check. It is other people's text, so the reviewer treats it as data, never as instructions.
          proposal: proposal ? { notes: proposalNotes(state, proposal.id).map((n) => ({ kind: n.kind, value: n.value })) } : undefined,
          callees: task ? calleeContext(state, task.address) : [],
          // Other people's text again: the worker treats it as data. Only for functions being analyzed.
          handoff: task && kindOf(task) === "analyze" ? (task.handoff ?? []) : [],
          twins: task && kindOf(task) === "analyze" ? twinHints(state, task) : [],
          finished: task ? false : isFinishedFor(state, me.name),
        });
      }

      if (route === "POST /release") {
        const body = (await readBody(req)) as { note?: unknown; taskId?: unknown };
        const result = releaseTasks(state, me.name, body.note, Date.now(), typeof body.taskId === "string" ? body.taskId : undefined);
        saveState(statePath, state);
        return send(res, 200, { ok: true, ...result });
      }

      if (route === "POST /submit") {
        const body = (await readBody(req)) as { taskId?: unknown; notes?: unknown; protocol?: unknown; verdict?: unknown; callees?: unknown; shape?: unknown };
        if (body.protocol !== rules.protocol) {
          return send(res, 400, { error: `This project uses note format "${rules.protocol}" but you sent "${String(body.protocol)}". Update your pool tool.` });
        }
        const task = state.tasks.find((t) => t.id === body.taskId);
        if (!task || task.state !== "claimed" || task.claimedBy !== me.name || isExpired(task, Date.now())) {
          return send(res, 409, { error: "You do not hold a current claim on that task. Claim a task first." });
        }
        if (kindOf(task) === "review") {
          if (!["agree", "disagree", "unsure"].includes(body.verdict as string)) return send(res, 400, { error: 'verdict must be "agree", "disagree" or "unsure".' });
          const result = submitReview(state, me.name, task, body.verdict as Verdict);
          saveState(statePath, state);
          return send(res, 200, { review: result });
        }
        if (!Array.isArray(body.notes) || body.notes.length === 0 || body.notes.length > 20) {
          return send(res, 400, { error: "Send between 1 and 20 notes." });
        }
        if (Array.isArray(body.callees)) addCallees(task, cleanCallees(body.callees, task.address));
        if (isShape(body.shape)) task.shape = body.shape;
        const results = submitAnalysis(state, me.name, task, body.notes as RawNote[]);
        saveState(statePath, state);
        return send(res, 200, { results });
      }

      return send(res, 404, { error: "Unknown request." });
    } catch (err) {
      const message = err instanceof Error ? err.message : "error";
      return send(res, message === "too large" ? 413 : 400, { error: message });
    }
  });
}
