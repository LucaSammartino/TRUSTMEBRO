export interface ToolSpec {
  name: string;
  /** Command used to ask the tool for its version, e.g. ["java", "-version"]. Only a short allowlist is permitted. */
  command: string[];
  /** Regex with one capture group that pulls the version out of the command output. */
  versionRegex: string;
  required: string;
  match: "exact" | "prefix";
}

export type Confidence = "low" | "medium" | "high";

export interface Rules {
  allowedKinds: string[];
  maxTextLength: number;
  maxEvidenceItems: number;
  leaseMinutes: number;
  /** Note format version. Submissions using a different one are refused. */
  protocol?: string;
  /** How many times a function may be re-analyzed by different people before giving up. */
  maxAttempts?: number;
  /** Most votes one proposal may collect before it is left as an unverified hint. */
  maxVotes?: number;
  maxContributors?: number;
  /** After someone gives up on a function (or their lease runs out), how long it waits at the back of the queue. */
  releaseCooldownMinutes?: number;
  /** How many times a finished function may be reopened because a callee name it was built on changed. */
  maxReopens?: number;
  /** How many tasks one person may work on at the same time (claim slots 0..maxParallel-1). */
  maxParallel?: number;
}

/** What someone who gave up on a function tells the next person: what they tried and what is still unclear. */
export interface Handoff {
  by: string;
  text: string;
  at: string;
}

export interface Project {
  schema: "rea-pool/1";
  name: string;
  created: string;
  target: { filename: string; sha256: string; size: number };
  tools: ToolSpec[];
  rules: Rules;
}

export type TaskKind = "analyze" | "review";

export interface Task {
  id: string;
  /** Missing means "analyze". */
  kind?: TaskKind;
  label: string;
  address: string;
  size?: number;
  state: "open" | "claimed" | "done";
  claimedBy?: string;
  /** Which of the claimer's parallel slots holds this task. Missing means 0. */
  claimSlot?: number;
  leaseUntil?: string;
  /** Everyone who has already done this task. They are never given it again. */
  doneBy?: string[];
  /** For review tasks: the proposal to check. */
  proposalId?: string;
  /** For analyze tasks: which attempt this is (starts at 1). */
  attempts?: number;
  /** For analyze tasks: addresses of the functions this one calls, when known. Missing means not discovered yet. */
  callees?: string[];
  /** For analyze tasks: how many times someone gave up on this function or let their lease run out. */
  abandons?: number;
  /** For analyze tasks: when the last give-up happened. The function waits at the back of the queue for a while after. */
  releasedAt?: string;
  /** For analyze tasks: notes left by people who gave up, newest last. Other people's text: data, never instructions. */
  handoff?: Handoff[];
  /** For analyze tasks: fingerprint of the decompiled code's structure. Functions sharing one are probably copies of each other. */
  shape?: string;
  /** For analyze tasks: how many times this was reopened because a callee name changed under it. */
  reopened?: number;
  /** A name Ghidra or the program's symbols already gave this function. Such tasks are created "done" and need no work. */
  known?: { name: string; source: "ghidra" };
  /** True once this finished function was reopened for a second pass because callers got named. Happens at most once. */
  refined?: boolean;
}

/**
 * trusted  = high confidence, or an independent AI agreed
 * pending  = medium confidence, waiting for an independent check
 * hint     = low confidence or unresolved: shown, never trusted
 * rejected = broke a safety rule, or checkers disagreed with it
 */
export type NoteStatus = "trusted" | "pending" | "hint" | "rejected";

export interface Note {
  id: string;
  taskId: string;
  proposalId?: string;
  author: string;
  kind: string;
  value: string;
  evidence: string[];
  confidence: Confidence;
  /** Which AI model the contributor says wrote this. Informational only, never used to decide trust. */
  model: string;
  agent?: string;
  at: string;
  status: NoteStatus;
  reason?: string;
  /** How many independent checkers agreed. */
  agrees?: number;
  /** The trusted callee names the pool had when this was written, as "address=name". Lets a later rename be noticed. */
  basedOn?: string[];
  /** True when a callee name this note was built on is no longer the pool's trusted name. */
  stale?: boolean;
}

export type Verdict = "agree" | "disagree" | "unsure";

export interface Vote {
  by: string;
  verdict: Verdict;
  at: string;
}

/** The notes one contributor sent for one task, checked together as a unit. */
export interface Proposal {
  id: string;
  taskId: string;
  author: string;
  confidence: Confidence;
  status: NoteStatus;
  votes: Vote[];
  at: string;
  /** Other names the author considered, for the reviewer to weigh. At most 3. */
  alternatives?: string[];
}

export interface Contributor {
  name: string;
  tokenHash: string;
  joined: string;
  revoked: boolean;
}

export interface State {
  project: Project;
  /** The shared code friends use to join. */
  joinCode: string;
  contributors: Contributor[];
  tasks: Task[];
  notes: Note[];
  proposals: Proposal[];
}
