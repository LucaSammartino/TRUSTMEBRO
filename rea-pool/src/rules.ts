import type { Rules } from "./types.ts";

export const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;

// Words that look like instructions aimed at an AI agent. This is a simple tripwire, not a guarantee.
const SUSPICIOUS = [
  /ignore (all |any |the )?(previous|prior|above)/i,
  /disregard/i,
  /system prompt/i,
  /\byou (are|must|should|will)\b/i,
  /\b(run|execute|invoke) (the |this |following )/i,
  /\b(curl|wget|powershell|cmd\.exe|bash|sudo|rm -rf)\b/i,
  /<\/?(system|assistant|user|tool)/i,
  /\bapi[_ -]?key\b/i,
];
const URL = /\b(https?|ftp|file):\/\/|\bwww\./i;
const PATH_LIKE = /(^|[\s"'])([A-Za-z]:\\|\\\\|\/(home|users|tmp|var|etc|opt)\/)/i;
// biome-ignore lint: control characters are exactly what we want to catch
const CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/;
const LONG_HEX = /\b[0-9a-fA-F]{40,}\b/;

export function checkText(text: string, maxLength: number): string | null {
  if (text.length === 0) return "is empty";
  if (text.length > maxLength) return `is longer than ${maxLength} characters`;
  if (CONTROL.test(text)) return "contains control characters";
  if (URL.test(text)) return "contains a web address";
  if (PATH_LIKE.test(text)) return "looks like a file path from someone's computer";
  if (LONG_HEX.test(text)) return "contains a long hex blob (possible copied bytes)";
  for (const pattern of SUSPICIOUS) {
    if (pattern.test(text)) return "looks like an instruction to an AI agent";
  }
  return null;
}

export interface RawNote {
  taskId?: unknown;
  kind?: unknown;
  value?: unknown;
  evidence?: unknown;
  confidence?: unknown;
  agent?: unknown;
  model?: unknown;
}

export interface Checked {
  ok: boolean;
  reason?: string;
}

export function validateNote(note: RawNote, rules: Rules): Checked {
  const fail = (reason: string): Checked => ({ ok: false, reason });
  if (typeof note.kind !== "string" || !rules.allowedKinds.includes(note.kind)) {
    return fail(`kind must be one of: ${rules.allowedKinds.join(", ")}`);
  }
  if (typeof note.value !== "string") return fail("value must be text");
  if (note.kind === "function_name") {
    if (!IDENTIFIER.test(note.value)) {
      return fail("function names may only use letters, digits and underscores (max 64, not starting with a digit)");
    }
  } else {
    const problem = checkText(note.value, rules.maxTextLength);
    if (problem) return fail(`value ${problem}`);
  }
  const evidence = note.evidence ?? [];
  if (!Array.isArray(evidence)) return fail("evidence must be a list");
  if (evidence.length > rules.maxEvidenceItems) return fail(`at most ${rules.maxEvidenceItems} evidence items`);
  for (const item of evidence) {
    if (typeof item !== "string") return fail("each evidence item must be text");
    const problem = checkText(item, 200);
    if (problem) return fail(`evidence ${problem}`);
  }
  if (note.confidence !== undefined && !["low", "medium", "high"].includes(note.confidence as string)) {
    return fail("confidence must be low, medium or high");
  }
  if (note.agent !== undefined && (typeof note.agent !== "string" || !/^[\w .:/-]{1,60}$/.test(note.agent))) {
    return fail("agent must be a short plain label");
  }
  // The model is informational only (it is never used to decide trust), but it must be a short plain label.
  if (note.model !== undefined && (typeof note.model !== "string" || !/^[A-Za-z0-9][\w.:/-]{0,59}$/.test(note.model))) {
    return fail("model must be a short label such as claude-opus-5-5 (letters, digits and . : / _ - only)");
  }
  return { ok: true };
}

/** Other plausible names from an AI or a user: strings only, valid identifiers, no duplicates, not the main name, at most 3. */
export function cleanAlternatives(list: unknown, primary?: string): string[] {
  if (!Array.isArray(list)) return [];
  const out: string[] = [];
  for (const item of list) {
    if (typeof item !== "string") continue;
    const name = item.trim();
    if (!IDENTIFIER.test(name) || name === primary || out.includes(name)) continue;
    out.push(name);
    if (out.length === 3) break;
  }
  return out;
}
