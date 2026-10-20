// Android method identities stay local. Only stable task ids and checked notes go to the pool.
import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { CorvusClient, CorvusToolError, parseCorvusPage, type CorvusStep } from "./corvus.ts";
import { cleanCallees, normalizeAddress } from "./graph.ts";
import { runCommand } from "./exec.ts";

type Data = Record<string, unknown>;
type Plan<T> = Generator<CorvusStep[], T, Data[]>;
export interface AndroidMethod { address: string; name: string }
const indexes = new WeakMap<AndroidMethod[], { byAddress: Map<string, AndroidMethod>; bySymbol: Map<string, string> }>();
function indexOf(methods: AndroidMethod[]) {
  let index = indexes.get(methods);
  if (!index) {
    index = { byAddress: new Map(methods.map((m) => [m.address, m])), bySymbol: new Map(methods.map((m) => [m.name, m.address])) };
    indexes.set(methods, index);
  }
  return index;
}
function unexpected(): never { throw new Error("Corvus returned unexpected Android data. No results were imported."); }
function row(value: unknown): Data {
  if (!value || typeof value !== "object" || Array.isArray(value)) return unexpected();
  return value as Data;
}
function descriptor(value: unknown): value is string {
  return typeof value === "string" && value.length <= 4096 && /^L[^\s;()[\]<>]+;$/.test(value);
}
function methodId(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 16384) return false;
  const at = value.indexOf(";->");
  return at > 0 && descriptor(value.slice(0, at + 1)) && /^(?:<init>|<clinit>|[^\s;()[\]<>]+)\((?:\[*(?:[ZBSCIJFD]|L[^\s;()[\]<>]+;))*\)(?:V|\[*(?:[ZBSCIJFD]|L[^\s;()[\]<>]+;))$/.test(value.slice(at + 3));
}
export function androidAddress(symbol: string): string {
  if (!methodId(symbol)) return unexpected();
  return normalizeAddress(`0x${createHash("sha256").update(symbol).digest("hex").slice(0, 16)}`)!;
}
function* pages(tool: string, args: Data): Plan<unknown[]> {
  const rows: unknown[] = [];
  let offset = 0, total: unknown;
  for (let n = 0; n < 10000; n++) {
    const [data] = yield [{ tool, args: { ...args, offset, limit: 150 } }];
    const page = parseCorvusPage(data, offset);
    if (total !== undefined && data.total !== total) return unexpected();
    total = data.total;
    rows.push(...page.items);
    if (page.nextOffset === null) return rows;
    offset = page.nextOffset;
  }
  return unexpected();
}
function* methods(target: string): Plan<AndroidMethod[]> {
  const path = resolve(target), result: AndroidMethod[] = [], seen = new Set<string>(), classes = new Set<string>();
  for (const item of yield* pages("list_dex_classes", { path })) {
    const data = row(item);
    if (!descriptor(data.descriptor) || classes.has(data.descriptor)) return unexpected();
    classes.add(data.descriptor);
    for (const member of yield* pages("get_dex_class", { path, class: data.descriptor, members: "methods" })) {
      const m = row(member);
      if (m.kind !== "method" || !methodId(m.id) || !m.id.startsWith(`${data.descriptor}->`)) return unexpected();
      const address = androidAddress(m.id);
      // Duplicate definitions, including a hash collision, cannot safely share a task.
      if (seen.has(address)) return unexpected();
      seen.add(address);
      result.push({ address, name: m.id });
    }
  }
  return result;
}
function codePage(data: Data, offset: number): string {
  if (typeof data.code !== "string" || data.offset !== offset || !Number.isSafeInteger(data.totalChars) ||
      (data.totalChars as number) > 4 * 1024 * 1024 || (data.totalChars as number) < offset + data.code.length ||
      (data.nextOffset == null ? data.totalChars !== offset + data.code.length : !data.code.length || data.nextOffset !== offset + data.code.length)) return unexpected();
  return data.code;
}
function* methodCode(target: string, symbol: string, tool: string): Plan<string> {
  const args = { path: resolve(target), symbol, ...(tool === "disassemble_dex" ? { format: "smali" } : {}) };
  const [first] = yield [{ tool, args }];
  let data = first, code = codePage(first, 0);
  for (let n = 0; data.nextOffset != null; n++) {
    if (n >= 10000) return unexpected();
    const offset = code.length;
    [data] = yield [{ tool, args: { ...args, offset } }];
    code += codePage(data, offset);
    if (data.totalChars !== first.totalChars) return unexpected();
  }
  return code;
}
function* inspection(target: string, address: string, listed?: AndroidMethod[]): Plan<{ code: string; callees: string[] }> {
  const all = listed ?? (yield* methods(target));
  const { byAddress, bySymbol } = indexOf(all);
  const method = byAddress.get(normalizeAddress(address) ?? "");
  if (!method) throw new Error("This Android method is not in your copy of the program.");
  let code: string;
  try { code = yield* methodCode(target, method.name, "decompile_java"); }
  catch (error) {
    // Missing JADX or failed Java decompilation can still yield complete smali. Malformed replies fail closed.
    if (!(error instanceof CorvusToolError)) throw error;
    code = yield* methodCode(target, method.name, "disassemble_dex");
  }
  const callees: string[] = [];
  for (const item of yield* pages("find_dex_references", { path: resolve(target), target: method.name, kind: "method", direction: "from" })) {
    const ref = row(item);
    if (!["call", "read", "write", "string", "type"].includes(String(ref.kind)) || ref.method !== method.name) return unexpected();
    if (ref.kind !== "call") continue;
    if (!methodId(ref.target)) return unexpected();
    const callee = bySymbol.get(ref.target);
    if (callee) callees.push(callee);
  }
  return { code, callees: cleanCallees(callees, address) };
}
async function run<T>(client: CorvusClient, plan: Plan<T>): Promise<T> {
  let step = plan.next();
  while (!step.done) {
    let data: Data[];
    try { data = await client.batch(step.value); }
    catch (error) { step = plan.throw(error); continue; }
    step = plan.next(data);
  }
  return step.value;
}
export function listAndroidMethods(client: CorvusClient): Promise<AndroidMethod[]> { return run(client, methods(client.target)); }
export function inspectAndroid(client: CorvusClient, address: string, listed?: AndroidMethod[]): Promise<{ code: string; callees: string[] }> {
  return run(client, inspection(client.target, address, listed));
}
export function inspectAndroidSync(target: string, address: string, runner = runCommand): { code: string; callees: string[] } {
  const client = new CorvusClient(target), plan = inspection(target, address);
  let step = plan.next();
  while (!step.done) {
    let data: Data[];
    try { data = client.batchSync(step.value, runner); }
    catch (error) { step = plan.throw(error); continue; }
    step = plan.next(data);
  }
  return step.value;
}
