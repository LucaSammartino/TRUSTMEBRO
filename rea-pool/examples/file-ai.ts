// Not an AI. For tests where a person (or another AI session) answers by hand:
// it saves the prompt to a file, then waits for an answer file to appear and prints it.
// Use with: REA_POOL_AI="node examples/file-ai.ts" REA_POOL_DUMP_DIR=<folder>
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

let prompt = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (c) => (prompt += c));
process.stdin.on("end", async () => {
  const dir = process.env.REA_POOL_DUMP_DIR ?? ".";
  mkdirSync(dir, { recursive: true });
  const address = prompt.match(/FUN_([0-9a-f]+)/i)?.[1] ?? String(Date.now());
  writeFileSync(join(dir, `prompt-${address}.txt`), prompt);
  const answer = join(dir, `answer-${address}.json`);
  const deadline = Date.now() + 10 * 60_000;
  while (Date.now() < deadline) {
    if (existsSync(answer)) {
      await new Promise((r) => setTimeout(r, 300));
      console.log(readFileSync(answer, "utf8"));
      return;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  console.error("No answer arrived in time.");
  process.exit(1);
});
