import type { State, Task } from "./types.ts";

export type Activity = {
  project: string;
  generatedAt: string;
  totals: { functions: number; done: number; inProgress: number; waiting: number; percentDone: number };
  results: { trusted: number; pending: number; hints: number; rejected: number };
  people: { name: string; analyses: number; checks: number; trusted: number; working: boolean; you: boolean }[];
  recent: { at: string; who: string; what: string }[];
  throughputPerHour: number;
};

// Match the server: a claim without a lease is still active.
function activeClaim(task: Task, now: number): boolean {
  return task.state === "claimed" && !(task.leaseUntil && Date.parse(task.leaseUntil) <= now);
}

export function buildActivity(state: State, now = Date.now(), viewer?: string): Activity {
  const functions = state.tasks.filter((t) => (t.kind ?? "analyze") === "analyze");
  const done = functions.filter((t) => t.state === "done").length;
  const inProgress = functions.filter((t) => activeClaim(t, now)).length;
  const results = { trusted: 0, pending: 0, hints: 0, rejected: 0 };
  const recent: Activity["recent"] = [];
  let throughputPerHour = 0;
  const addEvent = (at: string, who: string, what: string) => {
    recent.push({ at, who, what });
    const time = Date.parse(at);
    if (time >= now - 60 * 60_000 && time <= now) throughputPerHour++;
  };
  const people = state.contributors.filter((c) => !c.revoked).map((c) => ({
    name: c.name, analyses: 0, checks: 0, trusted: 0,
    working: state.tasks.some((t) => t.claimedBy === c.name && activeClaim(t, now)),
    you: c.name === viewer,
  }));
  const byName = new Map(people.map((p) => [p.name, p]));
  const names = new Map<string, string>();
  for (const note of state.notes) {
    if (note.kind === "function_name" && note.proposalId && !names.has(note.proposalId)) names.set(note.proposalId, note.value);
  }
  for (const proposal of state.proposals) {
    results[proposal.status === "hint" ? "hints" : proposal.status]++;
    const person = byName.get(proposal.author);
    if (person) {
      person.analyses++;
      if (proposal.status === "trusted") person.trusted++;
    }
    const name = names.get(proposal.id);
    addEvent(proposal.at, proposal.author, name === undefined
      ? `submitted an analysis (${proposal.status})`
      : `named a function "${name}" (${proposal.status})`);
    for (const vote of proposal.votes) {
      const checker = byName.get(vote.by);
      if (checker) checker.checks++;
      const subject = name === undefined ? "an analysis" : `the name "${name}"`;
      addEvent(vote.at, vote.by, vote.verdict === "agree" ? `agreed with ${subject}`
        : vote.verdict === "disagree" ? `disagreed with ${subject}` : `was unsure about ${subject}`);
    }
  }
  people.sort((a, b) => (b.analyses + b.checks) - (a.analyses + a.checks));
  recent.sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
  return {
    project: state.project.name, generatedAt: new Date(now).toISOString(),
    totals: { functions: functions.length, done, inProgress, waiting: functions.length - done - inProgress,
      percentDone: functions.length ? Math.round(done / functions.length * 100) : 0 },
    results, people, recent: recent.slice(0, 30), throughputPerHour,
  };
}
