// Builds a benchmark: picks N random functions that have real names, hides ALL function names in their code,
// and saves the prompts (for any AI to answer) plus the true names (kept separate, for grading).
// Usage: node examples/bench-prepare.ts <software-file> <how-many> <out-folder> [seed]
import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const [target, countArg, outDir, seedArg] = process.argv.slice(2);
const count = Number(countArg);
let seed = Number(seedArg ?? 42);
const here = dirname(fileURLToPath(import.meta.url));
mkdirSync(join(outDir, "prompts"), { recursive: true });

const list = spawnSync("rea", ["search", target, ".", "--kind", "procedures", "--mode", "regex", "--provider", "ghidra", "--json"], {
  encoding: "utf8", shell: true, maxBuffer: 256 * 1024 * 1024,
});
const procs = (JSON.parse(list.stdout).normalized_result as { address: string; value: string }[]).filter((p) => /^0x[0-9a-f]+$/i.test(p.address));
const named = procs.filter((p) => /^[A-Za-z][A-Za-z0-9_]*$/.test(p.value) && !p.value.startsWith("FUN_") && !/CRT|^_|mingw|pei386/i.test(p.value));

// Every named function goes in the hide-list, not just the ones we test.
const nameMap: Record<string, string> = {};
for (const p of procs) if (/^[A-Za-z_]\w*$/.test(p.value) && !p.value.startsWith("FUN_")) nameMap[p.value] = p.address;
const mapFile = join(outDir, "name-map.json");
writeFileSync(mapFile, JSON.stringify(nameMap));

// Seeded shuffle so the same seed always picks the same functions.
const rand = () => ((seed = (seed * 1664525 + 1013904223) % 4294967296) / 4294967296);
const pool = [...named];
for (let i = pool.length - 1; i > 0; i--) {
  const j = Math.floor(rand() * (i + 1));
  [pool[i], pool[j]] = [pool[j], pool[i]];
}
const picks = pool.slice(0, count);
console.error(`${named.length} candidate functions; testing ${picks.length}`);

const truth: { address: string; truth: string }[] = [];
for (const p of picks) {
  const run = spawnSync("node", [join(here, "rea-agent.ts")], {
    input: JSON.stringify({ task: { id: "x", address: p.address }, targetPath: target }),
    encoding: "utf8", timeout: 15 * 60_000,
    env: {
      ...process.env,
      REA_POOL_NAME_MAP: mapFile,
      REA_POOL_AI: `node ${join(here, "dump-ai.ts")}`,
      REA_POOL_DUMP_DIR: join(outDir, "prompts"),
    },
  });
  if (run.status === 0) truth.push({ address: p.address, truth: p.value });
  console.error(`${run.status === 0 ? "ok  " : "FAIL"} ${p.address}`);
}
writeFileSync(join(outDir, "truth.json"), JSON.stringify(truth, null, 2));
console.error(`Saved ${truth.length} prompts and truth.json in ${outDir}`);
