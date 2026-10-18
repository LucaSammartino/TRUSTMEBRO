// Small, side-effect-free helpers shared by the contributor and leader tools (cli.ts and leader.ts run on import, so they cannot be tested directly).
import { copyFileSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

// --- Outbox: results that could not be sent because the leader was unreachable ---------------------------------------

export const OUTBOX_CAP = 200;
export type SendResult = "sent" | "refused" | "offline";

/** The queued request bodies. A missing or corrupt file counts as empty. */
export function readOutbox(path: string): unknown[] {
  try {
    const items = JSON.parse(readFileSync(path, "utf8"));
    return Array.isArray(items) ? items : [];
  } catch {
    return [];
  }
}

function writeOutbox(path: string, items: unknown[]): void {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, JSON.stringify(items, null, 2), { mode: 0o600 });
  renameSync(tmp, path);
}

/** Add one request body at the end. Past the cap the oldest items are dropped. Returns the new length. */
export function appendOutbox(path: string, body: unknown): number {
  const items = [...readOutbox(path), body].slice(-OUTBOX_CAP);
  writeOutbox(path, items);
  return items.length;
}

/**
 * Send queued items in order. "sent" and "refused" (a definite no, e.g. the task is no longer yours) remove the item;
 * "offline" keeps it and stops. Returns how many were sent, refused and are still waiting.
 */
export async function flushOutbox(path: string, send: (body: unknown) => Promise<SendResult>): Promise<{ sent: number; refused: number; left: number }> {
  const items = readOutbox(path);
  let sent = 0;
  let refused = 0;
  let i = 0;
  for (; i < items.length; i++) {
    const r = await send(items[i]);
    if (r === "offline") break;
    if (r === "sent") sent++;
    else refused++;
    // Save after every item, so a crash never sends the same one twice.
    writeOutbox(path, items.slice(i + 1));
  }
  return { sent, refused, left: items.length - i };
}

// --- Moving to another leader ------------------------------------------------------------------------------------

/** The address as typed (trimmed) if it is a usable http(s) URL, otherwise null. */
export function validLeaderUrl(text: string | undefined): string | null {
  const s = (text ?? "").trim();
  try {
    const u = new URL(s);
    return (u.protocol === "http:" || u.protocol === "https:") && u.hostname ? s : null;
  } catch {
    return null;
  }
}

export function exportState(dataDir: string, out: string): { ok: true } | { error: string } {
  const statePath = join(dataDir, "state.json");
  if (!existsSync(statePath)) return { error: `No project found in ${dataDir}.` };
  copyFileSync(statePath, out);
  return { ok: true };
}

/** Put an exported state file in the data folder. Refuses to replace an existing project unless `force`. */
export function importState(file: string, dataDir: string, force = false): { ok: true } | { error: string } {
  const statePath = join(dataDir, "state.json");
  let data: Record<string, unknown>;
  try {
    data = JSON.parse(readFileSync(file, "utf8"));
  } catch {
    return { error: `Could not read ${file} as an exported project.` };
  }
  if (!data || typeof data !== "object" || !data.project || typeof data.project !== "object" || !Array.isArray(data.tasks) || !Array.isArray(data.contributors)) {
    return { error: `${file} is not an exported project (it needs a project, tasks and contributors).` };
  }
  if (existsSync(statePath) && !force) return { error: `${dataDir} already has a project. Use --force to replace it (the old one is lost).` };
  mkdirSync(dataDir, { recursive: true });
  const tmp = `${statePath}.tmp`;
  writeFileSync(tmp, JSON.stringify(data, null, 2));
  renameSync(tmp, statePath);
  return { ok: true };
}
