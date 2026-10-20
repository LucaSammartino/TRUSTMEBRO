// Carry only checked, trusted names. Both game builds stay on this computer.
import { resolve } from "node:path";
import { CorvusClient, methodToken, parseCorvusPage, type CorvusStep } from "./corvus.ts";
import { normalizeAddress } from "./graph.ts";
import { IDENTIFIER, checkText } from "./rules.ts";

export interface CarriedName { oldAddress: string; address: string; name: string }

export function trustedBuildNames(value: unknown, oldSha: string): { address: string; name: string }[] {
  const data = value as { target?: unknown; notes?: unknown } | null;
  if (!data || data.target !== oldSha || !Array.isArray(data.notes)) throw new Error("The results do not match the old program file. Use leader export <results.json> --best from that build.");
  const names = new Map<string, string>();
  const used = new Set<string>();
  for (const note of data.notes) {
    if (note?.kind !== "function_name" || note.status !== "trusted" || note.stale) continue;
    const address = typeof note.taskId === "string" && note.taskId.startsWith("fn-") ? normalizeAddress(note.taskId.slice(3)) : null;
    if (!address || typeof note.value !== "string" || !IDENTIFIER.test(note.value) || checkText(note.value, 64)) throw new Error("A trusted result has an unusable name or task address. Nothing was imported.");
    if (names.has(address) || used.has(note.value.toLowerCase())) throw new Error("The results contain duplicate names. Export them again with --best.");
    names.set(address, note.value);
    used.add(note.value.toLowerCase());
  }
  if (!names.size) throw new Error("There are no trusted function names to carry over.");
  return [...names].map(([address, name]) => ({ address, name }));
}

export function parseMigratedNames(rows: unknown[], trusted: { address: string; name: string }[]): CarriedName[] {
  const allowed = new Map(trusted.map((n) => [n.address, n.name]));
  const names: CarriedName[] = [];
  const seen = new Set<string>();
  for (const value of rows) {
    const row = value as Record<string, unknown> | null;
    if (!row || typeof row !== "object" || Array.isArray(row)) throw new Error("Corvus returned an unexpected migration row. Nothing was imported.");
    if (row.action === "skipped") continue;
    if (row.action !== "would_set") throw new Error("Corvus returned an unexpected migration action. Nothing was imported.");
    if (row.kind !== "name") continue;
    const oldAddress = normalizeAddress(row.oldAddress), address = normalizeAddress(row.newAddress);
    if (!oldAddress || !address || row.source !== "user" || typeof row.value !== "string" || allowed.get(oldAddress) !== row.value ||
        !IDENTIFIER.test(row.value) || checkText(row.value, 64) || !Number.isInteger(row.tier) || (row.tier as number) < 1 || (row.tier as number) > 2 ||
        typeof row.confidence !== "number" || row.confidence < 0.95 || row.confidence > 1 || seen.has(address)) {
      throw new Error("Corvus returned an unverified name match. Nothing was imported.");
    }
    seen.add(address);
    names.push({ oldAddress, address, name: row.value });
  }
  return names;
}

export async function migrateBuildNames(oldFile: string, newFile: string, trusted: { address: string; name: string }[], client = new CorvusClient(oldFile)): Promise<CarriedName[]> {
  const args = { oldImage: resolve(oldFile), newImage: resolve(newFile), dryRun: true, minTier: 2, minScore: 0.95, sources: ["user"], namesOnly: true, codeOnly: true };
  const setup: CorvusStep[] = [
    { tool: "load_assembly", args: { path: resolve(newFile) } },
    // rename_native records annotations in Corvus' local cache; it never rewrites the old program file.
    { tool: "rename_native", args: { image: resolve(oldFile), items: JSON.stringify(trusted), dryRun: false, stopOnError: true } },
  ];
  const result = await client.batch(setup);
  if (result[1].applied !== true || (result[1].failed !== undefined && result[1].failed !== null && result[1].failed !== 0)) throw new Error("Corvus could not read the old names. Nothing was imported.");
  // Each page reloads both builds in one session. The old annotations are retained by file hash.
  const rows: unknown[] = [];
  let offset = 0;
  const { parseCorvusPage } = await import("./corvus.ts");
  for (let n = 0; n < 10000; n++) {
    const outputs = await client.batch([{ tool: "load_assembly", args: { path: resolve(newFile) } },
      { tool: "migrate_native_names", args: { ...args, offset, limit: 150 } }]);
    const page = parseCorvusPage(outputs[1], offset);
    rows.push(...page.items);
    if (page.nextOffset === null) return parseMigratedNames(rows, trusted);
    offset = page.nextOffset;
  }
  throw new Error("Corvus returned too many migration pages. Nothing was imported.");
}

/** Managed matches are read-only previews; names always come from the checked old export. */
export function parseManagedMatches(rows: unknown[], trusted: { address: string; name: string }[]): CarriedName[] {
  const allowed = new Map(trusted.map((n) => [n.address, n.name]));
  const oldSeen = new Set<string>(), newSeen = new Set<string>(), result: CarriedName[] = [];
  for (const value of rows) {
    const row = value as Record<string, unknown> | null;
    if (!row || typeof row !== "object" || Array.isArray(row)) throw new Error("Corvus returned an unexpected managed match. Nothing was imported.");
    const oldAddress = methodToken(row.oldToken);
    if (row.kind !== "method" || !oldAddress || !allowed.has(oldAddress) || oldSeen.has(oldAddress)) throw new Error("Corvus returned an unexpected managed method. Nothing was imported.");
    oldSeen.add(oldAddress);
    if (row.candidates !== undefined && row.candidates !== null && !Array.isArray(row.candidates)) throw new Error("Corvus returned unexpected match candidates. Nothing was imported.");
    if ((Array.isArray(row.candidates) && row.candidates.length) || typeof row.how !== "string" || /ambiguous/i.test(row.how)) continue;
    const strong = (row.confidence === "exact" && row.tier === "full name + signature") ||
      (row.confidence === "strong" && ["IL hash", "IL hash, other type", "type match + name + signature"].includes(String(row.tier)));
    if (!strong || row.newToken == null) continue;
    const address = methodToken(row.newToken), name = allowed.get(oldAddress)!;
    if (!address || typeof row.new !== "string" || !IDENTIFIER.test(name) || checkText(name, 64) || newSeen.has(address)) throw new Error("Corvus returned an unverified managed name match. Nothing was imported.");
    newSeen.add(address);
    result.push({ oldAddress, address, name });
  }
  return result;
}

export async function migrateManagedNames(oldFile: string, newFile: string, trusted: { address: string; name: string }[], client = new CorvusClient(oldFile)): Promise<CarriedName[]> {
  const rows: unknown[] = [];
  const oldAssembly = resolve(oldFile), newAssembly = resolve(newFile);
  const used = new Set<string>(), names = new Set<string>();
  for (const n of trusted) {
    if (!methodToken(`0x${n.address.replace(/^0x/, "").padStart(8, "0")}`) || !IDENTIFIER.test(n.name) || checkText(n.name, 64) || used.has(n.address) || names.has(n.name.toLowerCase())) throw new Error("An old managed name or token is unusable. Nothing was imported.");
    used.add(n.address); names.add(n.name.toLowerCase());
  }
  for (let at = 0; at < trusted.length; at += 100) {
    const symbols = trusted.slice(at, at + 100).map((n) => `0x${n.address.slice(2).padStart(8, "0")}`);
    let offset = 0, done = false;
    for (let n = 0; n < 10000; n++) {
      // Both builds must be loaded in each CLI session; neither build is renamed or saved here.
      const outputs = await client.batch([{ tool: "load_assembly", args: { path: newAssembly } },
        { tool: "find_counterpart", args: { oldAssembly, newAssembly, symbols, offset, limit: 100 } }]);
      const page = parseCorvusPage(outputs[1], offset);
      if (outputs[1].total !== symbols.length) throw new Error("Corvus did not match the requested method list. Nothing was imported.");
      rows.push(...page.items);
      if (page.nextOffset === null) { done = true; break; }
      offset = page.nextOffset;
    }
    if (!done) throw new Error("Corvus returned too many managed match pages. Nothing was imported.");
  }
  return parseManagedMatches(rows, trusted);
}
