import { IS_WINDOWS, runCommand } from "./exec.ts";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Project, ToolSpec } from "./types.ts";
import { fileExists, sha256File } from "./util.ts";

export interface CheckResult {
  name: string;
  status: "pass" | "fail";
  message: string;
}

// The leader's project file is not trusted to run arbitrary commands on your computer.
// Only these programs, asked only for their version, are ever run.
const ALLOWED_PROGRAMS = new Set(["java", "node", "rea", "python", "python3", "docker", "ghidraRun", "git"]);
const ALLOWED_ARGS = new Set(["--version", "-version", "version", "-v", "-V"]);

export function isSafeVersionCommand(command: string[]): boolean {
  const [program, ...args] = command;
  return !!program && ALLOWED_PROGRAMS.has(program) && args.length <= 1 && args.every((a) => ALLOWED_ARGS.has(a));
}

export function versionMatches(found: string, required: string, mode: "exact" | "prefix"): boolean {
  return mode === "exact" ? found === required : found === required || found.startsWith(required + ".");
}

/** Read an installed tool's version. Returns the version text, or a plain-English reason it could not be read. */
export function readVersion(tool: ToolSpec): { version: string } | { error: string } {
  if (tool.name === "ghidra") {
    // Ghidra has no version command; its install folder records the version in a small text file.
    const dir = process.env.GHIDRA_INSTALL_DIR;
    if (!dir) return { error: "GHIDRA_INSTALL_DIR is not set. Point it at your Ghidra folder." };
    const propsPath = join(dir, "Ghidra", "application.properties");
    if (!existsSync(propsPath)) return { error: `No Ghidra found at ${dir}.` };
    const found = readFileSync(propsPath, "utf8").match(/^application.version=(.+)$/m)?.[1]?.trim();
    return found ? { version: found } : { error: "Could not read the Ghidra version." };
  }
  if (!isSafeVersionCommand(tool.command)) {
    return { error: "The project asks to run a command this program does not allow. Tell the leader." };
  }
  const [rawProgram, ...args] = tool.command;
  // Use the Java that JAVA_HOME points at (that is the one Ghidra will use), not whatever is first on the PATH.
  const program = rawProgram === "java" && process.env.JAVA_HOME ? join(process.env.JAVA_HOME, "bin", IS_WINDOWS ? "java.exe" : "java") : rawProgram;
  let run;
  try {
    run = runCommand(program, args, { timeout: 15000 });
  } catch {
    return { error: `${tool.name} is installed in a folder whose name this tool cannot use. Move it to a simpler path.` };
  }
  if (run.error || run.status === null) return { error: `${tool.name} was not found on this computer.` };
  const output = `${run.stdout ?? ""}
${run.stderr ?? ""}`;
  let match: RegExpMatchArray | null = null;
  try {
    match = output.match(new RegExp(tool.versionRegex));
  } catch {
    return { error: "The project has a broken version pattern. Tell the leader." };
  }
  return match?.[1] ? { version: match[1] } : { error: `Could not read the ${tool.name} version from its output.` };
}

export function checkTool(tool: ToolSpec): CheckResult {
  const name = `Tool: ${tool.name} ${tool.required}`;
  const read = readVersion(tool);
  if ("error" in read) {
    const hint = read.error.endsWith("not found on this computer.") ? ` Install version ${tool.required}.` : "";
    return { name, status: "fail", message: read.error + hint };
  }
  if (!versionMatches(read.version, tool.required, tool.match)) {
    return { name, status: "fail", message: `You have ${tool.name} ${read.version}, but this project needs ${tool.required}.` };
  }
  return { name, status: "pass", message: `${tool.name} ${read.version}` };
}

export async function checkTarget(project: Project, targetPath: string | undefined): Promise<CheckResult> {
  const name = `Software file: ${project.target.filename}`;
  if (!targetPath) {
    return { name, status: "fail", message: "No file chosen yet. Run: pool set-target <path to your copy>" };
  }
  if (!fileExists(targetPath)) {
    return { name, status: "fail", message: `File not found: ${targetPath}` };
  }
  const found = await sha256File(targetPath);
  if (found !== project.target.sha256) {
    return {
      name,
      status: "fail",
      message: "Your copy is not identical to the leader's (the fingerprint differs). You need the exact same file.",
    };
  }
  return { name, status: "pass", message: "Your copy matches the leader's exactly." };
}

export async function runAllChecks(project: Project, targetPath: string | undefined): Promise<CheckResult[]> {
  const results: CheckResult[] = [await checkTarget(project, targetPath)];
  for (const tool of project.tools) results.push(checkTool(tool));
  return results;
}

export function allPassed(results: CheckResult[]): boolean {
  return results.every((r) => r.status === "pass");
}
