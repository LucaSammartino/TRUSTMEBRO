// Optional game reader. Its output, including names, is data, never instructions.
import { accessSync, closeSync, constants, existsSync, mkdtempSync, openSync, readFileSync, readSync, readdirSync, rmSync, statSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { basename, delimiter, dirname, join, resolve } from "node:path";
import { IS_WINDOWS, runCommand, runCommandAsync, type AsyncResult } from "./exec.ts";
import { cleanCallees, normalizeAddress } from "./graph.ts";
import { checkText, IDENTIFIER } from "./rules.ts";

export type AnalysisProvider = "corvus-dotnet" | "corvus-android";
export type TargetKind = "dotnet" | "android" | "il2cpp" | "native";
export const CORVUS_VERSION = "2.4.0";
export const CORVUS_FIX = IS_WINDOWS ? "powershell -ExecutionPolicy Bypass -File rea-pool\\setup.ps1 -Mode setup-only -Yes" : "bash rea-pool/setup.sh --mode setup-only --yes";

/** Finding it never starts it. CORVUS_BIN is a local override, never read from a project. */
export function findCorvus(): string | null {
  const binary = IS_WINDOWS ? "corvus.exe" : "corvus";
  const candidates = process.env.CORVUS_BIN ? [process.env.CORVUS_BIN] : [
    ...(process.env.PATH ?? "").split(delimiter).filter(Boolean).map((p) => join(p, binary)),
    join(homedir(), ".rea-pool", "tools", "corvus", binary),
    ...(IS_WINDOWS ? [join(homedir(), "rea-pool-tools", "corvus", binary)] : []),
  ];
  for (const file of candidates) {
    try {
      accessSync(file, IS_WINDOWS ? constants.F_OK : constants.X_OK);
      if (statSync(file).isFile()) return resolve(file);
    } catch { /* Try the next folder. */ }
  }
  return null;
}

export function corvusAvailable(): boolean { return findCorvus() !== null; }

function readAt(path: string, offset: number, size: number): Buffer {
  const fd = openSync(path, "r");
  try {
    const data = Buffer.alloc(size);
    return data.subarray(0, readSync(fd, data, 0, size, offset));
  } finally { closeSync(fd); }
}

function peHeader(path: string): { optional: Buffer; plus: boolean } | null {
  const dos = readAt(path, 0, 64);
  if (dos.length < 64 || dos.toString("ascii", 0, 2) !== "MZ") return null;
  const at = dos.readUInt32LE(60);
  if (at < 64 || at > statSync(path).size - 24) return null;
  const pe = readAt(path, at, 24);
  if (pe.toString("ascii", 0, 4) !== "PE\0\0") return null;
  const optional = readAt(path, at + 24, pe.readUInt16LE(20));
  if (optional.length < 2) return null;
  const magic = optional.readUInt16LE(0);
  return magic === 0x10b || magic === 0x20b ? { optional, plus: magic === 0x20b } : null;
}

/** Only well-known nearby Unity layouts; no recursive scan of a person's disk. */
export function il2cppMetadata(path: string): string | null {
  if (!/^(GameAssembly\.dll|libil2cpp\.so)$/i.test(basename(path))) return null;
  const dir = dirname(resolve(path));
  const roots = [dir, dirname(dir), dirname(dirname(dir))];
  for (const root of roots) {
    const candidates = [join(root, "global-metadata.dat"), join(root, "il2cpp_data", "Metadata", "global-metadata.dat"),
      join(root, "assets", "bin", "Data", "Managed", "Metadata", "global-metadata.dat")];
    try {
      for (const entry of readdirSync(root, { withFileTypes: true })) {
        if (entry.isDirectory() && entry.name.endsWith("_Data")) candidates.push(join(root, entry.name, "il2cpp_data", "Metadata", "global-metadata.dat"));
      }
    } catch { /* No readable game folder. */ }
    for (const candidate of candidates) {
      try { if (statSync(candidate).isFile()) return candidate; } catch { /* Try the next layout. */ }
    }
  }
  return null;
}

export function detectTargetKind(path: string): TargetKind {
  try {
    const magic = readAt(path, 0, 8);
    if (/^dex\n[0-9]{3}\0$/.test(magic.toString("ascii")) || androidZip(path)) return "android";
    const pe = peHeader(path);
    if (pe) {
      const start = pe.plus ? 112 : 96;
      const count = start - 4;
      const clr = start + 14 * 8;
      if (pe.optional.length >= clr + 8 && pe.optional.readUInt32LE(count) > 14 &&
          pe.optional.readUInt32LE(clr) !== 0 && pe.optional.readUInt32LE(clr + 4) >= 72) return "dotnet";
    }
    if (il2cppMetadata(path)) return "il2cpp";
  } catch { /* A missing or malformed header is left to the default reader. */ }
  return "native";
}

/** Read ZIP entry names only: no extraction, decompression or execution. ZIP64 is left unsupported. */
function androidZip(path: string): boolean {
  const size = statSync(path).size;
  if (size < 22 || readAt(path, 0, 4).toString("hex") !== "504b0304") return false;
  const start = Math.max(0, size - 65557), tail = readAt(path, start, size - start);
  for (let i = tail.length - 22; i >= 0; i--) {
    if (tail.readUInt32LE(i) !== 0x06054b50 || i + 22 + tail.readUInt16LE(i + 20) !== tail.length) continue;
    const count = tail.readUInt16LE(i + 10), bytes = tail.readUInt32LE(i + 12), at = tail.readUInt32LE(i + 16);
    if (tail.readUInt32LE(i + 4) !== 0 || tail.readUInt16LE(i + 8) !== count || count === 65535 || at + bytes !== start + i) return false;
    let cursor = at, found = false;
    for (let n = 0; n < count; n++) {
      const header = readAt(path, cursor, 46);
      if (header.length !== 46 || header.readUInt32LE(0) !== 0x02014b50) return false;
      const length = header.readUInt16LE(28), extra = header.readUInt16LE(30), comment = header.readUInt16LE(32);
      if (cursor + 46 + length + extra + comment > at + bytes) return false;
      const name = readAt(path, cursor + 46, length).toString("utf8");
      if (/^classes[0-9]*\.dex$/.test(name) || name === "AndroidManifest.xml") found = true;
      cursor += 46 + length + extra + comment;
    }
    return cursor === at + bytes && found;
  }
  return false;
}

export function selectProvider(path: string, noCorvus = false): AnalysisProvider | undefined {
  const kind = detectTargetKind(path);
  if (kind === "android") {
    if (noCorvus || !corvusAvailable()) throw new Error(`Android projects need Corvus ${CORVUS_VERSION}. Run: ${CORVUS_FIX}`);
    return "corvus-android";
  }
  return !noCorvus && kind === "dotnet" && corvusAvailable() ? "corvus-dotnet" : undefined;
}

type ObjectData = Record<string, unknown>;
function object(value: unknown, where: string): ObjectData {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`Corvus returned an unexpected ${where}. No results were imported.`);
  return value as ObjectData;
}
function unexpected(where: string): never { throw new Error(`Corvus returned an unexpected ${where}. No results were imported.`); }

export class CorvusToolError extends Error {}

export function parseCorvusResult(stdout: string, tool: string): ObjectData {
  let value: unknown;
  try { value = JSON.parse(stdout); } catch { return unexpected(`${tool} reply (expected JSON)`); }
  const reply = object(value, `${tool} reply`);
  if (reply.tool !== tool || typeof reply.isError !== "boolean") return unexpected(`${tool} envelope`);
  if (reply.isError) throw new CorvusToolError(`Corvus could not finish ${tool}. Check its local setup and try again.`);
  if (reply.error) return unexpected(`${tool} partial reply`);
  return object(reply.structured, `${tool} structured result`);
}

export function parseCorvusPage(value: unknown, offset: number): { items: unknown[]; nextOffset: number | null } {
  const page = object(value, "page");
  if (!Array.isArray(page.items) || page.offset !== offset || !Number.isSafeInteger(page.total) || (page.total as number) < offset + page.items.length ||
      (page.hasMore !== undefined && typeof page.hasMore !== "boolean") ||
      (page.totalExact !== undefined && page.totalExact !== null && typeof page.totalExact !== "boolean") || page.totalExact === false ||
      (page.notEvaluated !== undefined && page.notEvaluated !== null && page.notEvaluated !== 0)) return unexpected("page fields");
  const more = page.hasMore ?? offset + page.items.length < (page.total as number);
  const next = page.nextOffset ?? (more ? offset + page.items.length : null);
  if (!more) {
    if (next !== null || offset + page.items.length !== page.total) return unexpected("last page");
    return { items: page.items, nextOffset: null };
  }
  if (!page.items.length || !Number.isSafeInteger(next) || (next as number) !== offset + page.items.length) return unexpected("page cursor");
  return { items: page.items, nextOffset: next as number };
}

export interface CorvusStep { tool: string; args: Record<string, unknown> }
export type CorvusRunner = (program: string, args: string[], options: Parameters<typeof runCommandAsync>[2]) => Promise<AsyncResult>;
function commandArgs(target: string, loadTarget = true): string[] { return [...(loadTarget ? ["--load", resolve(target)] : []), "--json", "--max-output", "20000", "--no-index"]; }
function commandOptions(input?: string) {
  return { input, timeout: 30 * 60_000, maxBuffer: 256 * 1024 * 1024,
    env: { ...process.env, CORVUS_OFFLINE: "1", CORVUS_GHIDRA_DIR: process.env.CORVUS_GHIDRA_DIR || process.env.GHIDRA_INSTALL_DIR } };
}
function checkRun(run: AsyncResult): void {
  if (run.error || run.status !== 0) {
    const why = run.status === 124 ? "It took too long." : run.status === 3 ? "A reader it needs is missing." : "Check its local setup.";
    throw new CorvusToolError(`Corvus could not read this file. ${why} To install the extra reader: ${CORVUS_FIX}`);
  }
}
function batchResults(stdout: string, steps: CorvusStep[]): ObjectData[] {
  const lines = stdout.trim().split(/\r?\n/);
  if (lines.length !== steps.length) return unexpected("batch result count");
  return lines.map((line, i) => {
    const value = parseCorvusResult(line, steps[i].tool);
    const envelope = JSON.parse(line);
    if (envelope.step !== i + 1) return unexpected("batch step order");
    return value;
  });
}

export class CorvusClient {
  target: string;
  runner: CorvusRunner;
  loadTarget: boolean;
  constructor(target: string, runner: CorvusRunner = runCommandAsync) { this.target = target; this.runner = runner; this.loadTarget = detectTargetKind(target) !== "android"; }
  async batch(steps: CorvusStep[]): Promise<ObjectData[]> {
    const binary = findCorvus();
    if (!binary) throw new Error(`This project needs Corvus. Run: ${CORVUS_FIX}`);
    const run = await this.runner(binary, ["batch", "-", ...commandArgs(this.target, this.loadTarget), "--stop-on-error"], commandOptions(JSON.stringify(steps)));
    checkRun(run);
    return batchResults(run.stdout, steps);
  }
  batchSync(steps: CorvusStep[], runner = runCommand): ObjectData[] {
    const binary = findCorvus();
    if (!binary) throw new Error(`This project needs Corvus. Run: ${CORVUS_FIX}`);
    const run = runner(binary, ["batch", "-", ...commandArgs(this.target, this.loadTarget), "--stop-on-error"], commandOptions(JSON.stringify(steps)));
    checkRun(run);
    return batchResults(run.stdout, steps);
  }
  async call(tool: string, args: Record<string, unknown> = {}): Promise<ObjectData> {
    return (await this.batch([{ tool, args }]))[0];
  }
  async pages(tool: string, args: Record<string, unknown>): Promise<unknown[]> {
    const rows: unknown[] = [];
    let offset = 0;
    for (let n = 0; n < 10000; n++) {
      const page = parseCorvusPage(await this.call(tool, { ...args, offset, limit: 150 }), offset);
      rows.push(...page.items);
      if (page.nextOffset === null) return rows;
      offset = page.nextOffset;
    }
    return unexpected("listing (too many pages)");
  }
}

export interface ManagedMethod { address: string; assembly: string; name: string }
export async function listManagedMethods(client: CorvusClient): Promise<ManagedMethod[]> {
  const rows = await client.pages("search_symbols", { query: "*", kind: "method", assembly: resolve(client.target) });
  const seen = new Set<string>();
  return rows.map((value) => {
    const row = object(value, "method");
    const address = methodToken(row.token);
    if (!address || row.kind !== "method" || typeof row.label !== "string" || typeof row.assembly !== "string" || seen.has(address)) return unexpected("method identity");
    seen.add(address);
    return { address, name: row.label, assembly: row.assembly };
  });
}
export function methodToken(value: unknown): string | null {
  return typeof value === "string" && /^0x06[0-9a-f]{6}$/i.test(value) && !/^0x06000000$/i.test(value) ? normalizeAddress(value) : null;
}
function managedSteps(target: string, address: string): CorvusStep[] {
  if (!methodToken(`0x${address.replace(/^0x/, "").padStart(8, "0")}`)) throw new Error("The managed task token looks wrong.");
  return [{ tool: "decompile_member", args: { member: address, assembly: resolve(target), kind: "method" } },
    { tool: "get_call_tree", args: { method: address, assembly: resolve(target), direction: "callees", depth: 1, includeExternal: false, offset: 0, limit: 150 } }];
}
function managedCode(value: ObjectData, offset = 0): string {
  if (typeof value.code !== "string" || !["csharp", "il"].includes(String(value.language)) || value.offset !== offset || !Number.isSafeInteger(value.totalChars) || (value.totalChars as number) < offset + value.code.length ||
      ((value.nextOffset === null || value.nextOffset === undefined) ? value.totalChars !== offset + value.code.length :
        !value.code.length || value.nextOffset !== offset + value.code.length)) return unexpected("managed code (incomplete or unknown format)");
  return value.code;
}
export function parseManagedCallees(rows: unknown[], assembly: string, self: string): string[] {
  const addresses: string[] = [];
  for (const value of rows) {
    const row = object(value, "call row");
    if (row.assembly !== undefined && row.assembly !== null && typeof row.assembly !== "string") return unexpected("managed call assembly");
    if (row.edge === "external" || (row.assembly !== null && row.assembly !== undefined && row.assembly !== assembly)) continue;
    if (row.token === null || row.token === undefined) {
      if (typeof row.address === "string" || row.edge === "native" || row.edge === "pinvoke") continue;
      return unexpected("managed call token");
    }
    const token = methodToken(row.token);
    if (!token) return unexpected("managed call token");
    if (row.depth !== undefined && row.depth !== null && row.depth !== 1) return unexpected("managed call depth");
    addresses.push(token);
  }
  return cleanCallees(addresses, self);
}
export async function inspectManaged(client: CorvusClient, address: string, assembly?: string): Promise<{ code: string; callees: string[] }> {
  const steps = managedSteps(client.target, address);
  if (!assembly) steps.push({ tool: "get_assembly_info", args: { assembly: resolve(client.target) } });
  const [firstCode, calls, info] = await client.batch(steps);
  if (!assembly) {
    if (typeof info?.id !== "string") return unexpected("assembly identity");
    assembly = info.id;
  }
  let codePage = firstCode;
  let code = managedCode(codePage);
  for (let n = 0; codePage.nextOffset !== null && codePage.nextOffset !== undefined; n++) {
    if (n >= 10000 || code.length > 4 * 1024 * 1024) return unexpected("managed code size");
    const offset = code.length;
    codePage = await client.call("decompile_member", { ...steps[0].args, offset });
    code += managedCode(codePage, offset);
    if (codePage.totalChars !== firstCode.totalChars) return unexpected("managed code length changed between pages");
  }
  // Keep the existing worker's 6,000-character code window. Partial code is never cached as a full dump.
  const page = parseCorvusPage(calls, 0);
  const rows = page.nextOffset === null ? page.items : await client.pages("get_call_tree", steps[1].args);
  return { code, callees: parseManagedCallees(rows, assembly, address) };
}
export function inspectManagedSync(target: string, address: string, runner = runCommand): { code: string; callees: string[] } {
  const binary = findCorvus();
  if (!binary) throw new Error(`This project needs Corvus. Run: ${CORVUS_FIX}`);
  const batch = (steps: CorvusStep[]) => {
    const run = runner(binary, ["batch", "-", ...commandArgs(target), "--stop-on-error"], commandOptions(JSON.stringify(steps)));
    checkRun(run);
    return batchResults(run.stdout, steps);
  };
  const steps = managedSteps(target, address);
  steps.push({ tool: "get_assembly_info", args: { assembly: resolve(target) } });
  const [firstCode, calls, info] = batch(steps);
  if (typeof info.id !== "string") return unexpected("assembly identity");
  let codePage = firstCode;
  let code = managedCode(codePage);
  for (let n = 0; codePage.nextOffset !== null && codePage.nextOffset !== undefined; n++) {
    if (n >= 10000 || code.length > 4 * 1024 * 1024) return unexpected("managed code size");
    const offset = code.length;
    codePage = batch([{ tool: "decompile_member", args: { ...steps[0].args, offset } }])[0];
    code += managedCode(codePage, offset);
    if (codePage.totalChars !== firstCode.totalChars) return unexpected("managed code length changed between pages");
  }
  let page = parseCorvusPage(calls, 0);
  const rows = [...page.items];
  for (let n = 0; page.nextOffset !== null; n++) {
    if (n >= 10000) return unexpected("managed call pages");
    const offset = page.nextOffset;
    page = parseCorvusPage(batch([{ tool: "get_call_tree", args: { ...steps[1].args, offset } }])[0], offset);
    rows.push(...page.items);
  }
  return { code, callees: parseManagedCallees(rows, info.id, address) };
}

/** Il2Cpp exports use RVAs. Translate with the binary's preferred image base, never guessed task offsets. */
function imageBase(path: string): bigint {
  const pe = peHeader(path);
  if (pe && pe.optional.length >= 32) return pe.plus ? pe.optional.readBigUInt64LE(24) : BigInt(pe.optional.readUInt32LE(28));
  const elf = readAt(path, 0, 64);
  if (elf.length === 64 && elf.toString("hex", 0, 4) === "7f454c46" && elf[5] === 1 && [1, 2].includes(elf[4])) {
    const plus = elf[4] === 2;
    const at = plus ? Number(elf.readBigUInt64LE(32)) : elf.readUInt32LE(28);
    const size = elf.readUInt16LE(plus ? 54 : 42), count = elf.readUInt16LE(plus ? 56 : 44);
    if (size < (plus ? 56 : 32) || count > 4096 || at + size * count > statSync(path).size) return unexpected("ELF load segments");
    let base: bigint | undefined;
    for (let i = 0; i < count; i++) {
      const segment = readAt(path, at + size * i, size);
      if (segment.readUInt32LE(0) !== 1) continue;
      const va = plus ? segment.readBigUInt64LE(16) : BigInt(segment.readUInt32LE(8));
      if (base === undefined || va < base) base = va;
    }
    if (base !== undefined) return base;
  }
  return unexpected("Il2Cpp image base (supported: PE and little-endian ELF)");
}
export function parseIl2CppNames(value: unknown, base: bigint): Map<string, string> {
  const data = object(value, "Il2Cpp export");
  if (!Array.isArray(data.ScriptMethod)) return unexpected("Il2Cpp method list");
  const names = new Map<string, string>();
  for (const item of data.ScriptMethod) {
    const row = object(item, "Il2Cpp method");
    if (!Number.isSafeInteger(row.Address) || (row.Address as number) < 0 || typeof row.Name !== "string") return unexpected("Il2Cpp method fields");
    // Turn qualified metadata names into plain identifiers, then apply the pool's existing text rules.
    if (checkText(row.Name, 256)) continue;
    const name = row.Name.replace(/[^A-Za-z0-9_]/g, "_");
    if (!IDENTIFIER.test(name) || checkText(name, 64)) continue;
    const address = normalizeAddress(`0x${(base + BigInt(row.Address as number)).toString(16)}`);
    if (!address) return unexpected("Il2Cpp method address");
    if (!names.has(address)) names.set(address, name);
  }
  return names;
}
export async function il2cppNames(target: string, client = new CorvusClient(target), ghidraBase?: bigint | null): Promise<Map<string, string>> {
  const metadata = il2cppMetadata(target);
  if (!metadata) return new Map();
  const base = ghidraBase ?? imageBase(target);
  const dir = mkdtempSync(join(tmpdir(), "rea-pool-il2cpp-"));
  try {
    // Loading the binary itself pins the Android ABI; reloading only metadata could choose another ABI.
    await client.call("export_il2cpp_symbols", { outputDirectory: dir, formats: "json", baseName: "pool" });
    const file = join(dir, "pool_script.json");
    if (!existsSync(file) || statSync(file).size > 256 * 1024 * 1024) return unexpected("Il2Cpp export file");
    return parseIl2CppNames(JSON.parse(readFileSync(file, "utf8")), base);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
