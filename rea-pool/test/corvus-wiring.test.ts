import { androidAddress } from "../src/android.ts";
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:net";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { runCommandAsync } from "../src/exec.ts";

const leader = fileURLToPath(new URL("../src/leader.ts", import.meta.url));
const cli = fileURLToPath(new URL("../src/cli.ts", import.meta.url));

for (const android of [false, true]) test(`leader and joined worker share the ${android ? "Android" : "managed"} reader, and a missing reader gives a one-line fix`, { skip: process.platform === "win32" }, async () => {
  const root = mkdtempSync(join(tmpdir(), "corvus-wire-"));
  const fake = join(root, "corvus"), target = join(root, android ? "classes.dex" : "game.dll"), data = join(root, "project");
  const b = Buffer.alloc(512); b.write("MZ"); b.writeUInt32LE(64, 60); b.write("PE\0\0", 64); b.writeUInt16LE(224, 84); b.writeUInt16LE(0x10b, 88);
  b.writeUInt32LE(16, 88 + 92); b.writeUInt32LE(0x2000, 88 + 96 + 112); b.writeUInt32LE(72, 88 + 96 + 116); writeFileSync(target, android ? Buffer.from("dex\n035\0") : b);
  // This is a mock executable, not Corvus. Every answer is fixed test data.
  writeFileSync(fake, `#!${process.execPath}
const fs = require('node:fs');
if (process.argv.includes('--version')) { console.log(process.env.MOCK_VERSION || '2.4.0'); process.exit(0); }
if (process.env.MOCK_FAIL) process.exit(3);
const steps = JSON.parse(fs.readFileSync(0, 'utf8'));
for (let i=0;i<steps.length;i++) {
 const {tool,args}=steps[i]; let structured;
 if(tool==='search_symbols') structured={items:[{kind:'method',label:'Game.C::Tick()',assembly:'Game',token:process.env.MOCK_NEW_TOKEN || '0x06000001'}],offset:0,total:1,hasMore:false,nextOffset:null};
 else if(tool==='decompile_member') structured={language:'csharp',code:'int Tick() { return 42; }',offset:0,totalChars:25,nextOffset:null};
 else if(tool==='get_call_tree') structured={items:[],offset:0,total:0,hasMore:false,nextOffset:null};
 else if(tool==='get_assembly_info') structured={id:'Game'};
 else if(tool==='load_assembly') structured={ids:['fixture']};
 else if(tool==='list_dex_classes') { if(process.argv.includes('--load')) process.exit(2); structured={items:[{descriptor:'Lsample/C;',dexFile:'classes.dex'}],offset:0,total:1}; }
 else if(tool==='get_dex_class') structured={items:[{kind:'method',id:'Lsample/C;->tick()I'}],offset:0,total:1};
 else if(tool==='decompile_java') structured={code:'int tick() { return 42; }',offset:0,totalChars:25,nextOffset:null};
 else if(tool==='find_dex_references') structured={items:[],offset:0,total:0};
 else if(tool==='find_counterpart') structured={items:[{kind:'method',oldToken:'0x06000001',newToken:'0x06000002',new:'New::Renamed()',how:'identical body (moved)',tier:'IL hash, other type',confidence:'strong'}],offset:0,total:1};
 else if(tool==='export_il2cpp_symbols') { fs.writeFileSync(require('node:path').join(args.outputDirectory,'pool_script.json'),JSON.stringify({ScriptMethod:[{Address:4096,Name:'Game.Player$$Tick'}]})); structured={functions:1,files:[]}; }
 else { console.error('unexpected mock tool '+tool); process.exit(2); }
 console.log(JSON.stringify({step:i+1,tool,isError:false,structured,error:null}));
}
`);
  chmodSync(fake, 0o755);
  const env = { ...process.env, CORVUS_BIN: fake, REA_POOL_CONFIG: join(root, "worker.json"), REA_POOL_CACHE: join(root, "cache") };
  const socket = createServer();
  await new Promise<void>((resolve) => socket.listen(0, "127.0.0.1", resolve));
  const port = (socket.address() as { port: number }).port;
  await new Promise<void>((resolve) => socket.close(() => resolve()));
  const child = spawn(process.execPath, [leader, "start", target, "--data", data, "--port", String(port)], { env, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  let errors = "";
  child.stderr.on("data", (c) => errors += c.toString());
  try {
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`Mock leader did not start: ${output} ${errors}`)), 10000);
      child.stdout.on("data", (chunk) => {
        output += chunk.toString();
        if (/Server running/i.test(output)) { clearTimeout(timer); resolve(); }
      });
      child.once("exit", () => { clearTimeout(timer); reject(new Error(`Mock leader exited: ${output} ${errors}`)); });
    });
    const address = output.match(/http:\/\/127\.0\.0\.1:(\d+)(?=\s|$)/g)?.at(-1);
    assert.ok(address, output);
    const state = JSON.parse(readFileSync(join(data, "state.json"), "utf8"));
    const provider = android ? "corvus-android" : "corvus-dotnet";
    assert.equal(state.project.provider, provider); assert.equal(state.project.corvusVersion, "2.4.0"); assert.equal(state.tasks[0].address, android ? androidAddress("Lsample/C;->tick()I") : "0x6000001");
    const run = (args: string[], extra = {}) => runCommandAsync(process.execPath, [cli, ...args], { env: { ...env, ...extra }, timeout: 15000 });
    const joined = await run(["join", address, state.joinCode, "--name", "alice", "--target", target]);
    assert.equal(joined.status, 0, joined.stdout + joined.stderr);
    assert.equal(JSON.parse(readFileSync(env.REA_POOL_CONFIG, "utf8")).provider, provider);
    const prepared = await run(["prepare"]); assert.equal(prepared.status, 0, prepared.stdout + prepared.stderr);
    const next = await run(["next"]); assert.equal(next.status, 0, next.stdout + next.stderr); assert.match(JSON.parse(next.stdout).code, /return 42/);
    const submitted = await run(["submit", "--name", "game_tick", "--summary", "Computes the next tick.", "--confidence", "high"]);
    assert.equal(submitted.status, 0, submitted.stdout + submitted.stderr);
    const missing = await run(["join", address, state.joinCode, "--name", "bob", "--target", target], { CORVUS_BIN: join(root, "missing"), REA_POOL_CONFIG: join(root, "bob.json") });
    assert.equal(missing.status, 2); assert.match(missing.stderr, /project needs Corvus.*setup.*setup-only/);
    const wrong = await run(["check"], { MOCK_VERSION: "2.3.0" }); assert.equal(wrong.status, 2); assert.match(wrong.stdout, /Corvus 2.4.0/);
    const applied = await runCommandAsync(process.execPath, [leader, "apply", "--data", data], { env });
    assert.equal(applied.status, 0, applied.stdout + applied.stderr);
    const names = JSON.parse(readFileSync(join(data, "apply", "names.json"), "utf8"));
    assert.equal(names.functions[0].name, "game_tick");
    if (android) assert.match(applied.stdout, /no documented Android rename/);
    else {
      const batch = JSON.parse(readFileSync(join(data, "apply", "corvus-batch.json"), "utf8"));
      assert.equal(batch[1].tool, "rename_symbol"); assert.equal(batch[1].args.newName, "game_tick");
      const exported = join(root, "results.json");
      const saved = await runCommandAsync(process.execPath, [leader, "export", exported, "--best", "--data", data], { env });
      assert.equal(saved.status, 0, saved.stdout + saved.stderr);
      const newer = join(root, "new.dll"), newData = join(root, "new-project"), bytes = Buffer.from(b); bytes[500] = 1; writeFileSync(newer, bytes);
      const imported = await runCommandAsync(process.execPath, [leader, "import-names", exported, target, newer, "--data", newData], { env: { ...env, MOCK_NEW_TOKEN: "0x06000002" } });
      assert.equal(imported.status, 0, imported.stdout + imported.stderr);
      const nextState = JSON.parse(readFileSync(join(newData, "state.json"), "utf8"));
      assert.equal(nextState.project.provider, "corvus-dotnet"); assert.equal(nextState.tasks[0].address, "0x6000002");
      assert.equal(nextState.notes.find((n: { kind: string }) => n.kind === "function_name").value, "game_tick");
      assert.equal(nextState.notes[0].status, "trusted");
    }
    const native = join(root, "GameAssembly.dll"), nativeData = join(root, "native");
    const bytes = Buffer.from(b); bytes.writeUInt32LE(0, 88 + 96 + 112); bytes.writeUInt32LE(0, 88 + 96 + 116); bytes.writeUInt32LE(0x400000, 88 + 28);
    writeFileSync(native, bytes); writeFileSync(join(root, "global-metadata.dat"), "fixture");
    const hash = createHash("sha256").update(bytes).digest("hex");
    const project = { ...state.project, target: { filename: "GameAssembly.dll", sha256: hash, size: bytes.length } };
    delete project.provider; delete project.corvusVersion;
    const freshState = { ...state, project, tasks: [{ id: "fn-0x401000", address: "0x401000", label: "Function", state: "open", callees: [] }] };
    mkdirSync(nativeData);
    const reset = () => writeFileSync(join(nativeData, "state.json"), JSON.stringify(freshState));
    const cache = join(env.REA_POOL_CACHE, hash); mkdirSync(cache, { recursive: true });
    writeFileSync(join(cache, "dump.jsonl"), JSON.stringify({ address: "0x401000", name: "FUN_401000", code: "void f() {}", callees: [] }) + "\n");
    writeFileSync(join(cache, "meta.json"), JSON.stringify({ sha256: hash, functions: 1 }));
    for (const command of ["graph", "prepare"]) {
      reset();
      const imported = await runCommandAsync(process.execPath, [leader, command, native, "--data", nativeData], { env });
      assert.equal(imported.status, 0, imported.stdout + imported.stderr);
      assert.deepEqual(JSON.parse(readFileSync(join(nativeData, "state.json"), "utf8")).tasks[0].known, { name: "Game_Player__Tick", source: "corvus" });
    }
    for (const extra of [{ CORVUS_BIN: join(root, "missing") }, { MOCK_FAIL: "1" }]) {
      reset();
      const fallback = await runCommandAsync(process.execPath, [leader, "graph", native, "--data", nativeData], { env: { ...env, ...extra } });
      assert.equal(fallback.status, 0, fallback.stdout + fallback.stderr);
      assert.equal(JSON.parse(readFileSync(join(nativeData, "state.json"), "utf8")).tasks[0].state, "open");
    }
    for (const flag of ["--no-corvus", "--keep-named"]) {
      reset();
      const skipped = await runCommandAsync(process.execPath, [leader, "graph", native, "--data", nativeData, flag], { env });
      assert.equal(skipped.status, 0, skipped.stdout + skipped.stderr);
      assert.equal(JSON.parse(readFileSync(join(nativeData, "state.json"), "utf8")).tasks[0].state, "open");
    }
  } finally {
    child.kill();
    await new Promise<void>((resolve) => child.exitCode !== null || child.signalCode !== null ? resolve() : child.once("exit", () => resolve()));
    rmSync(root, { recursive: true, force: true });
  }
});
