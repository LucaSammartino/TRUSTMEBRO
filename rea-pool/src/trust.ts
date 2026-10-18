import type { Confidence, Note, NoteStatus, Rules, Vote } from "./types.ts";

export const NOTE_PROTOCOL = "rea-note/2";

export const CONFIDENCE_ORDER: Record<Confidence, number> = { low: 0, medium: 1, high: 2 };

export function withDefaults(rules: Rules): Required<Rules> {
  return {
    ...rules,
    protocol: rules.protocol ?? NOTE_PROTOCOL,
    maxAttempts: rules.maxAttempts ?? 3,
    maxVotes: rules.maxVotes ?? 5,
    maxContributors: rules.maxContributors ?? 50,
  };
}

/** A proposal is only as confident as its least confident note. */
export function proposalConfidence(confidences: Confidence[]): Confidence {
  return confidences.reduce((low, c) => (CONFIDENCE_ORDER[c] < CONFIDENCE_ORDER[low] ? c : low), "high" as Confidence);
}

/**
 * What happens to a fresh proposal, based only on the AI's own confidence.
 * Our Lua test: high was right 10/10, medium 5/6, low only 1/13.
 */
export function initialStatus(confidence: Confidence): "trusted" | "pending" | "hint" {
  if (confidence === "high") return "trusted";
  if (confidence === "medium") return "pending";
  return "hint";
}

/**
 * Decide a pending proposal from the independent votes so far.
 * - more agrees than disagrees          -> trusted
 * - two or more disagrees and winning   -> rejected
 * - too many votes with no clear result -> hint (kept, not trusted)
 * - otherwise                           -> still pending, ask another checker
 * "unsure" votes count toward the vote limit but not toward either side.
 */
export function resolveVotes(votes: Vote[], rules: Rules): NoteStatus {
  const agrees = votes.filter((v) => v.verdict === "agree").length;
  const disagrees = votes.filter((v) => v.verdict === "disagree").length;
  if (agrees > disagrees) return "trusted";
  if (disagrees >= 2 && disagrees > agrees) return "rejected";
  if (votes.length >= withDefaults(rules).maxVotes) return "hint";
  return "pending";
}

const STATUS_ORDER: Record<NoteStatus, number> = { trusted: 0, pending: 1, hint: 2, rejected: 3 };

/** Which note wins when several describe the same thing: trusted first, then more checkers agreeing, then confidence, then older. */
export function compareNotes(a: Note, b: Note): number {
  return (
    STATUS_ORDER[a.status] - STATUS_ORDER[b.status] ||
    (b.agrees ?? 0) - (a.agrees ?? 0) ||
    CONFIDENCE_ORDER[b.confidence] - CONFIDENCE_ORDER[a.confidence] ||
    a.at.localeCompare(b.at)
  );
}
