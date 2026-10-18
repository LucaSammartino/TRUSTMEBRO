// Scores the agent on software that still has its real names: hides the names from the AI, then compares.
// Usage: node examples/score-agent.ts <software-file> <how-many> <results.json>
import { spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const [target, countArg, outFile] = process.argv.slice(2);
const count = Number(countArg ?? 6);
const here = dirname(fileURLToPath(import.meta.url));

const list = spawnSync("rea", ["search", target, ".", "--kind", "procedures", "--mode", "regex", "--provider", "ghidra", "--json"], {
  encoding: "utf8", shell: true, maxBuffer: 256 * 1024 * 1024,
});
const procs = (JSON.parse(list.stdout).normalized_result as { address: string; value: string }[])
  .filter((p) => /^0x[0-9a-f]+$/i.test(p.address))
  .filter((p) => /^[A-Za-z][A-Za-z0-9_]*$/.test(p.value) && !p.value.startsWith("FUN_") && !/CRT|^_|mingw|pei386/i.test(p.value));
const step = Math.floor(procs.length / count);
const picks = Array.from({ length: count }, (_, i) => procs[Math.min(procs.length - 1, Math.floor(step / 2) + i * step)]);

const results: object[] = [];
for (const p of picks) {
  const input = JSON.stringify({ task: { id: "x", address: p.address }, targetPath: target });
  const run = spawnSync("node", [join(here, "rea-agent.ts")], {
    input, encoding: "utf8", timeout: 15 * 60_000,
    env: { ...process.env, REA_POOL_HIDE_NAMES: "1" },
  });
  let name = "", summary = "", confidence = "", error = "";
  if (run.status === 0) {
    const notes = JSON.parse(run.stdout).notes as { kind: string; value: string; confidence: string }[];
    name = notes.find((n) => n.kind === "function_name")?.value ?? "";
    summary = notes.find((n) => n.kind === "comment")?.value ?? "";
    confidence = notes[0]?.confidence ?? "";
  } else {
    error = (run.stderr ?? "").slice(0, 300);
  }
  results.push({ address: p.address, truth: p.value, ai: name, summary, confidence, error });
  console.error(`done ${p.address} true=${p.value} ai=${name || "(failed)"}`);
}
writeFileSync(outFile, JSON.stringify(results, null, 2));
