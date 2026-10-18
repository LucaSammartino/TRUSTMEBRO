import { spawnSync, type SpawnSyncReturns } from "node:child_process";

export const IS_WINDOWS = process.platform === "win32";

export interface RunOptions {
  input?: string;
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
    timeout: options.timeout ?? 120_000,
    maxBuffer: options.maxBuffer ?? 64 * 1024 * 1024,
  };
  if (!IS_WINDOWS) return spawnSync(program, args, { ...base, shell: false });
  for (const part of [program, ...args]) {
    if (UNSAFE_ON_WINDOWS.test(part)) throw new Error("A path or value contains characters this tool cannot use. Move the file to a simpler folder.");
  }
  return spawnSync([program, ...args].map(windowsQuote).join(" "), { ...base, shell: true });
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
