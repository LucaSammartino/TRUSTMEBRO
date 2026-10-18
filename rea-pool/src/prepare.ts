import { closeSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, readSync, renameSync, rmSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { homedir, tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { runCommandAsync } from "./exec.ts";
import { normalizeAddress } from "./graph.ts";
import { writeJsonAtomic } from "./util.ts";

export interface DumpEntry {
  address: string;
  name: string;
  code: string;
  callees: string[];
}

export function cacheRoot(): string {
  return process.env.REA_POOL_CACHE || join(homedir(), ".rea-pool", "cache");
}

export function sha256FileSync(path: string): string {
  const hash = createHash("sha256");
  const buf = Buffer.alloc(1024 * 1024);
  const fd = openSync(path, "r");
  try {
    for (;;) {
      const n = readSync(fd, buf, 0, buf.length, null);
      if (n === 0) break;
      hash.update(buf.subarray(0, n));
    }
  } finally {
    closeSync(fd);
  }
  return hash.digest("hex");
}

const hashMemo = new Map<string, string>();
const memo = new Map<string, Map<string, DumpEntry>>();

function hashOf(targetPath: string): string {
  const key = resolve(targetPath);
  let h = hashMemo.get(key);
  if (!h) {
    h = sha256FileSync(key);
    hashMemo.set(key, h);
  }
  return h;
}

export function cachePathFor(targetPath: string): { dir: string; dumpFile: string; metaFile: string } {
  const dir = join(cacheRoot(), hashOf(targetPath));
  return { dir, dumpFile: join(dir, "dump.jsonl"), metaFile: join(dir, "meta.json") };
}

export function buildAnalyzeCommand(o: {
  ghidraDir: string;
  projectDir: string;
  targetPath: string;
  scriptDir: string;
  outFile: string;
  platform?: NodeJS.Platform;
}): { program: string; args: string[] } {
  const win = (o.platform ?? process.platform) === "win32";
  const program = win ? join(o.ghidraDir, "support", "analyzeHeadless.bat") : join(o.ghidraDir, "support", "analyzeHeadless");
  const args = [o.projectDir, "dump", "-import", o.targetPath, "-scriptPath", o.scriptDir, "-postScript", "DumpAll.java", o.outFile, "-deleteProject"];
  return { program, args };
}

function validMeta(targetPath: string, metaFile: string, dumpFile: string): boolean {
  try {
    if (!existsSync(dumpFile) || !existsSync(metaFile)) return false;
    const meta = JSON.parse(readFileSync(metaFile, "utf8"));
    return typeof meta?.sha256 === "string" && meta.sha256 === hashOf(targetPath);
  } catch {
    return false;
  }
}

function metaFunctions(metaFile: string): number {
  try {
    const n = JSON.parse(readFileSync(metaFile, "utf8")).functions;
    return typeof n === "number" ? n : 0;
  } catch {
    return 0;
  }
}

function lastLine(text: string): string {
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const err = [...lines].reverse().find((l) => /error|exception|failed|unable|cannot/i.test(l));
  return (err ?? lines[lines.length - 1] ?? "").slice(0, 300);
}

export async function prepareTarget(
  targetPath: string,
  opts: { force?: boolean; log?: (m: string) => void } = {},
): Promise<{ dumpFile: string; functions: number; seconds: number; fromCache: boolean }> {
  const log = opts.log ?? (() => {});
  if (!existsSync(targetPath)) throw new Error(`The file to analyze was not found: ${targetPath}`);
  const sha = hashOf(targetPath);
  const { dir, dumpFile, metaFile } = cachePathFor(targetPath);
  if (!opts.force && validMeta(targetPath, metaFile, dumpFile)) {
    return { dumpFile, functions: metaFunctions(metaFile), seconds: 0, fromCache: true };
  }
  const ghidraDir = process.env.GHIDRA_INSTALL_DIR;
  if (!ghidraDir || !existsSync(join(ghidraDir, "support"))) {
    throw new Error("Ghidra was not found. Set GHIDRA_INSTALL_DIR to your Ghidra folder (run the setup to install it).");
  }
  const started = Date.now();
  mkdirSync(dir, { recursive: true });
  const tmpFile = `${dumpFile}.tmp`;
  const projectDir = mkdtempSync(join(tmpdir(), "rea-pool-ghidra-"));
  try {
    rmSync(tmpFile, { force: true });
    const scriptDir = join(dirname(fileURLToPath(import.meta.url)), "..", "ghidra");
    const cmd = buildAnalyzeCommand({ ghidraDir, projectDir, targetPath: resolve(targetPath), scriptDir, outFile: tmpFile });
    log("Dumping all functions with Ghidra (this can take a few minutes)...");
    const res = await runCommandAsync(cmd.program, cmd.args, { timeout: 30 * 60_000, maxBuffer: 256 * 1024 * 1024 });
    const output = `${res.stdout}\n${res.stderr}`;
    if (res.error) throw new Error(`Ghidra could not run: ${res.error.message}`);
    if (res.status !== 0) throw new Error(`Ghidra failed (exit ${res.status}): ${lastLine(output)}`);
    if (!existsSync(tmpFile) || statSync(tmpFile).size === 0) {
      throw new Error(`Ghidra produced no function dump: ${lastLine(output)}`);
    }
    const lines = readFileSync(tmpFile, "utf8").split("\n").filter((l) => l.trim() !== "");
    if (lines.length < 1) throw new Error(`Ghidra produced an empty function dump: ${lastLine(output)}`);
    for (const line of lines) {
      let ok = false;
      try {
        ok = typeof JSON.parse(line)?.address === "string";
      } catch {
        ok = false;
      }
      if (!ok) throw new Error("Ghidra produced a damaged function dump (a line is not valid).");
    }
    renameSync(tmpFile, dumpFile);
    writeJsonAtomic(metaFile, { sha256: sha, functions: lines.length, createdAt: new Date().toISOString(), ghidra: basename(ghidraDir) });
    memo.delete(resolve(targetPath));
    const seconds = Math.round((Date.now() - started) / 100) / 10;
    log(`Dumped ${lines.length} functions in ${seconds}s.`);
    return { dumpFile, functions: lines.length, seconds, fromCache: false };
  } finally {
    rmSync(tmpFile, { force: true });
    rmSync(projectDir, { recursive: true, force: true });
  }
}

export function clearDumpMemo(): void {
  memo.clear();
  hashMemo.clear();
}

export function loadDump(targetPath: string): Map<string, DumpEntry> | null {
  const key = resolve(targetPath);
  const hit = memo.get(key);
  if (hit) return hit;
  let paths;
  try {
    paths = cachePathFor(targetPath);
    if (!validMeta(targetPath, paths.metaFile, paths.dumpFile)) return null;
  } catch {
    return null;
  }
  const map = new Map<string, DumpEntry>();
  for (const line of readFileSync(paths.dumpFile, "utf8").split("\n")) {
    if (!line.trim()) continue;
    try {
      const o = JSON.parse(line);
      const address = normalizeAddress(o?.address);
      if (!address) continue;
      const callees = Array.isArray(o.callees) ? o.callees.filter((c: unknown): c is string => typeof c === "string") : [];
      map.set(address, { address, name: typeof o.name === "string" ? o.name : "", code: typeof o.code === "string" ? o.code : "", callees });
    } catch {
      // skip malformed line
    }
  }
  memo.set(key, map);
  return map;
}

export function lookupFunction(targetPath: string, address: string): DumpEntry | null {
  const a = normalizeAddress(address);
  if (!a) return null;
  return loadDump(targetPath)?.get(a) ?? null;
}
