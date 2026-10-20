import { spawn, spawnSync, type ChildProcess, type SpawnSyncReturns } from "node:child_process";

export const IS_WINDOWS = process.platform === "win32";

export interface RunOptions {
  input?: string;
  env?: NodeJS.ProcessEnv;
  timeout?: number;
  maxBuffer?: number;
}

// On Windows, npm-installed tools (like rea) are .cmd files that can only be started through a shell.
// A shell reads these characters as commands, so we refuse them instead of trying to escape them.
const UNSAFE_ON_WINDOWS = /["&|<>^%\r\n]/;

function windowsQuote(part: string): string {
  return /\s/.test(part) ? `"${part}"` : part;
}

/**
 * Run a program with arguments, the same safe way on every system.
 * Linux/macOS: no shell at all, so a file name can never be read as a command.
 * Windows: one quoted command line, after refusing characters a shell would treat specially.
 * Never throws for a missing program; check `result.error`. Throws only for unusable characters on Windows.
 */
export function runCommand(program: string, args: string[], options: RunOptions = {}): SpawnSyncReturns<string> {
  const base = {
    encoding: "utf8" as const,
    input: options.input,
    ...(options.env ? { env: options.env } : {}),
    timeout: options.timeout ?? 120_000,
    maxBuffer: options.maxBuffer ?? 64 * 1024 * 1024,
  };
  if (!IS_WINDOWS) return spawnSync(program, args, { ...base, shell: false });
  for (const part of [program, ...args]) {
    if (UNSAFE_ON_WINDOWS.test(part)) throw new Error("A path or value contains characters this tool cannot use. Move the file to a simpler folder.");
  }
  return spawnSync([program, ...args].map(windowsQuote).join(" "), { ...base, shell: true });
}

export interface AsyncResult {
  status: number | null;
  stdout: string;
  stderr: string;
  error?: Error;
}

/**
 * Same as runCommand (same safety rules), but does not block: use it to run several programs at once.
 * Never rejects; check `result.error`. Throws only for unusable characters on Windows (before starting).
 */
export function runCommandAsync(program: string, args: string[], options: RunOptions = {}): Promise<AsyncResult> {
  const timeout = options.timeout ?? 120_000;
  const maxBuffer = options.maxBuffer ?? 64 * 1024 * 1024;
  let child: ChildProcess;
  if (!IS_WINDOWS) {
    child = spawn(program, args, { shell: false, stdio: ["pipe", "pipe", "pipe"], ...(options.env ? { env: options.env } : {}) });
  } else {
    for (const part of [program, ...args]) {
      if (UNSAFE_ON_WINDOWS.test(part)) throw new Error("A path or value contains characters this tool cannot use. Move the file to a simpler folder.");
    }
    child = spawn([program, ...args].map(windowsQuote).join(" "), { shell: true, stdio: ["pipe", "pipe", "pipe"], windowsHide: true, ...(options.env ? { env: options.env } : {}) });
  }
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let error: Error | undefined;
    let settled = false;
    const kill = () => {
      if (IS_WINDOWS && child.pid) spawnSync("taskkill", ["/pid", String(child.pid), "/T", "/F"], { stdio: "ignore" });
      else child.kill("SIGKILL");
    };
    const timer = setTimeout(() => {
      error = new Error(`timed out after ${Math.round(timeout / 1000)}s`);
      kill();
    }, timeout);
    const finish = (status: number | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ status, stdout, stderr, error });
    };
    const collect = (which: "out" | "err") => (chunk: Buffer) => {
      if (which === "out") stdout += chunk.toString("utf8");
      else stderr += chunk.toString("utf8");
      if (stdout.length + stderr.length > maxBuffer && !error) {
        error = new Error("output too large");
        kill();
      }
    };
    child.stdout?.on("data", collect("out"));
    child.stderr?.on("data", collect("err"));
    child.on("error", (err) => {
      error = error ?? err;
      finish(null);
    });
    child.on("close", (code) => finish(code));
    child.stdin?.on("error", () => {});
    child.stdin?.end(options.input);
  });
}

/** Run a command line the user wrote themselves (such as their AI command). It is theirs, so a shell is fine. */
export function runUserCommand(commandLine: string, options: RunOptions = {}): SpawnSyncReturns<string> {
  return spawnSync(commandLine, {
    encoding: "utf8",
    input: options.input,
    timeout: options.timeout ?? 120_000,
    maxBuffer: options.maxBuffer ?? 64 * 1024 * 1024,
    shell: true,
  });
}
