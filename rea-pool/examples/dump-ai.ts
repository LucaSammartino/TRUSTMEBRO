// Not an AI. Saves each prompt to a file so another AI can answer it, and prints a placeholder answer.
// Use with: REA_POOL_AI="node examples/dump-ai.ts" REA_POOL_DUMP_DIR=<folder>
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

let prompt = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (c) => (prompt += c));
process.stdin.on("end", () => {
  const dir = process.env.REA_POOL_DUMP_DIR ?? ".";
  mkdirSync(dir, { recursive: true });
  const address = prompt.match(/FUN_([0-9a-f]+)/i)?.[1] ?? String(Date.now());
  writeFileSync(join(dir, `prompt-${address}.txt`), prompt);
  console.log(JSON.stringify({ name: "placeholder", summary: "placeholder", confidence: "low" }));
});
