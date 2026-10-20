# rea-pool: details

You don't need this page to use the tool; the steps are in the [main README](../README.md). This is for when you want to know what is going on or do things by hand.

## By hand, without an AI agent

Windows uses `START-HERE.cmd` / `pool.cmd` / `leader.cmd`. macOS uses `START-HERE.command`. Linux/macOS use `bash setup.sh`, `./pool`, `./leader`.

| I want to... | Do this |
|---|---|
| Set up and join (friend) | Double-click `START-HERE.cmd` (Windows) or `START-HERE.command` (macOS), or `bash setup.sh` (Linux). It asks before installing anything. |
| Set up only (leader) | `SETUP-ONLY.cmd`, or `bash setup.sh --mode setup-only` |
| Start a project | `leader start <program file> --name "Name" --host 0.0.0.0` |
| Join | `pool join <address> <join-code> --target <program file>` |
| Work | `pool run` (needs the Claude command line: <https://claude.com/download>, then `claude auth login` once). Any other AI: `pool run --ai "<command: prompt on stdin, answer on stdout>"` |
| Work in parallel | `pool run --parallel 3` |
| Let an AI agent work | `pool connect`, or point your agent at the MCP server `node src/mcp.ts` |
| Watch | `pool watch`, `leader watch`, or open `http://<leader address>:8787/live` |
| Put the results into Ghidra | `leader apply` writes `names.json` and a Ghidra script (`ApplyNames.java`); run it in Ghidra to rename functions, variables and parameters, set signatures and add structs, plus comments |
| Invite one friend with their own code | `leader invite <name>` (single use; `leader invites`, `leader uninvite <name>`; `leader close-shared` turns the shared join line off) |
| Hand over to another leader | `leader export-state` (it holds everyone's access: give it only to someone you trust). The new leader runs `leader import-state <file>` then `leader start`; everyone runs `pool set-leader <new address>` |
| Send retries to stronger models | `leader retry-models <label,label>` (`none` clears it). It is only a preference, nothing gets stuck |
| See progress / results | `leader status`, `leader export results.json --best` |
| Read the whole program once (fast) | `pool prepare` (friends) or `leader prepare <program file>`: one Ghidra session, about a minute, cached on your own computer. `pool run` and `leader graph` do it automatically if you forget |
| Read the call graph up front | `leader graph <program file>` (uses the cache; `--no-prepare` falls back to one slow rea call per function, `--parallel 4`) |
| Remove someone / change the join code | `leader revoke <name>` / `leader new-code` |

Setup needs about 3 GB of disk and internet the first time. It installs Node 24, Java 21, Ghidra 12.1.4 (checked against its published fingerprint) and rea 6.7.0 into your own folder (`~/.rea-pool`); on Windows it sets `JAVA_HOME`, `GHIDRA_INSTALL_DIR` and `REA_ANALYSIS_PROVIDER` for your user. Apple Silicon Macs build Ghidra's decompiler once (needs `xcode-select --install` and `brew install bison`).

## Games: Unity, .NET and more (Corvus)

[Corvus](https://github.com/Albasha0x0/Corvus) is an optional extra reader (MIT license). rea and Ghidra remain the default. Existing projects keep their reader, and everything works as before when Corvus is absent.

Setup offers **Corvus (extra reader for Unity/.NET games)**. It downloads the pinned v2.4.0 archive from the project's GitHub release, checks its SHA-256 fingerprint against `requirements.json`, then unpacks it into your tools folder. A failed download or fingerprint check only warns; the usual setup can still finish. It never runs Corvus' installer or registers an MCP client.

- Linux/macOS: `bash setup.sh --mode setup-only --yes` includes Corvus. Add `--no-corvus` to skip it.
- Windows: `powershell -ExecutionPolicy Bypass -File setup.ps1 -Mode setup-only -Yes` includes it. Add `-NoCorvus` (also `-no-corvus`) to skip it.
- Linux/macOS use `~/.rea-pool/tools/corvus`; Windows uses the existing `~/rea-pool-tools/corvus` folder. Setup adds it to the same command environment as rea and sets `CORVUS_GHIDRA_DIR` to the installed Ghidra folder. Ghidra's Corvus worker needs a JDK and builds on first use.

| Your game file | What the pool uses |
|---|---|
| Unity Mono or another managed .NET `.dll` / `.exe` (PE CLR header, including ReadyToRun) | New projects automatically use Corvus when installed: one task per method, C# (or IL when needed), and method calls. Friends must have Corvus 2.4.0 too; joining or checking prints the setup command if it is missing or the wrong version. |
| Unity Il2Cpp `GameAssembly.dll` or `libil2cpp.so`, with nearby `global-metadata.dat` | rea/Ghidra still reads the code. `leader graph` and `leader prepare` optionally read names from the metadata and skip untouched functions that already have a usable, unique name. |
| Native PE, ELF or Mach-O game engine, including NativeAOT | The usual rea/Ghidra workflow. Corvus can also carry trusted names between native builds, as below. |
| APK / DEX or a packaged game | Corvus itself has APK, DEX and JADX tools. Pool tasks for these containers are **not connected yet**. Use the locally extracted managed assembly or native game binary with its metadata. |

To choose the usual reader for a new managed project, use `leader start <file> --no-corvus`. This choice is saved in the project; workers use the same reader. Managed caches are kept separately from Ghidra caches. `leader graph <file> --no-corvus` or `leader prepare <file> --no-corvus` skips the extra Il2Cpp name import. `--keep-named` also skips it. An unreadable metadata export warns and leaves the usual reader working. No generated Corvus scripts are executed.

Nearby metadata includes the binary's folder, `Game_Data/il2cpp_data/Metadata`, and Android's extracted `assets/bin/Data/Managed/Metadata` layout. Automatic Il2Cpp name rebasing supports PE and little-endian ELF. Preparation records Ghidra's actual address base when Corvus is installed; an older ELF cache needs `leader prepare <file> --force` before importing names. Metadata names are converted to plain identifiers, checked with the pool's existing rules and marked with source `corvus`; existing work is kept. All game code and Corvus output remain untrusted data. Corvus calls run with offline mode enabled; program files and code are never sent to the pool.

For managed projects, work commands stay the same: `pool prepare`, `pool run`, `pool next`, and the MCP tools all use the saved reader. Save results with `leader export results.json --best`. Ghidra's `leader apply` is for native programs; applying .NET names is not connected yet. C-style variable, signature and struct notes are not requested for managed methods.

### Carry names to a patched game

Keep both builds on your computer. Export the old project's trusted names with `leader export results.json --best`, then create a separate project:

```sh
leader import-names results.json "old/GameAssembly.dll" "new/GameAssembly.dll" --data new-project
leader start --data new-project
```

This checks that the old file matches the export's fingerprint and reads only trusted, non-stale function names with the standard `fn-0x...` task IDs. Corvus records those names as annotations in its local cache for the old build, then previews `migrate_native_names` with code matching, tiers 1–2 and confidence at least 0.95. Only checked matches to functions in the new project become trusted names, available through `leader apply`. The original files are not rewritten. Existing projects are never replaced; choose an empty folder with `--data`.

TODO: connect `update_to_new_build` / `find_counterpart` for managed games, and APK/DEX task scheduling. The current name migration is for native builds, including Il2Cpp. Actual Corvus output, platform archives, rebasing and migration accuracy still need an owner-approved real run; this integration has been checked only with mocks.

References: [tools](https://github.com/Albasha0x0/Corvus/blob/v2.4.0/docs/tools.md), [CLI](https://github.com/Albasha0x0/Corvus/blob/v2.4.0/docs/cli.md), [features](https://github.com/Albasha0x0/Corvus/blob/main/docs/features.md), [installation](https://github.com/Albasha0x0/Corvus/blob/main/docs/installation.md), [configuration](https://github.com/Albasha0x0/Corvus/blob/main/docs/configuration.md), [engine databases](https://github.com/Albasha0x0/Corvus/blob/main/docs/engine-databases.md).

## Letting friends connect

Friends connect to the leader's computer with ordinary web requests, so it must be reachable and stay on.

1. Install [Tailscale](https://tailscale.com) (free) on both computers and share the leader's computer. Its address looks like `100.x.y.z`.
2. Start with `--host 0.0.0.0` and give friends `http://100.x.y.z:8787`.
3. Do not put it on the open internet: traffic is not encrypted and anyone with the join code can join.

## How results become trusted

Each function is a task. An AI proposes a name and one sentence with a confidence.

| Confidence | What happens |
|---|---|
| High | Trusted immediately. |
| Medium | Another contributor's AI checks it (never the author). Agree: trusted. Two disagreements: rejected. |
| Low | Kept as a hint; someone else tries again (up to 3 attempts). |

Checking comes before new work and nobody does the same function twice. Every note is checked automatically: same program and tool versions, plain names, no links, file paths, hex blobs or instructions to an AI. Other people's notes are always treated as data.

## What keeps a crowd efficient

- **Bottom-up:** functions whose callees already have trusted names go first, and those names are shown to the AI. `basedOn` records which names a note used; if one later changes, the note is marked stale and the function is reopened once.
- **Known names are free:** functions Ghidra already named (symbols, library matches) are skipped and shown to the AI as trusted context. `leader graph --keep-named` turns this off (for testing on programs that still have symbols).
- **Callers help too:** each function is also shown the names of the functions that call it. Functions that ended as hints get one more try once their callers are named.
- **More than names:** besides the function name and comment, the AI may add variable names (`param_1=packet`), a signature and struct definitions when it is fairly sure. They share the name's review and are written into Ghidra by `leader apply`.
- **No duplicate names:** two functions cannot take the same name. The AI may add up to three alternative names, which are kept for the export.
- **Give-ups cool down** at the back of the queue (`releaseCooldownMinutes`, default 15), and leave a hand-off note for the next worker. Expired leases count as give-ups.
- **Copies:** functions with the same structure are fingerprinted; once one has a trusted name, the others get it as a hint, never as an answer.
- **Network blips:** `pool run` waits and retries for about ten minutes. A result finished while the leader is unreachable is saved on your computer and sent when it is back; a late result is accepted if nobody else took the function over.
- **Fast leader:** the leader keeps its state in memory and saves it a moment after changes, and waiting workers are woken the moment work appears instead of checking every 30 seconds.

## Limits

- Results pass checks but are not proven correct. Treat them as strong suggestions.
- Fake agreement between accounts one person controls is not prevented. Fine among friends; not for strangers.
- Not encrypted, not for the open internet.
- Accuracy has not been measured and will be lower on unfamiliar software. Tiny wrapper functions usually end as hints.
- Tested on Windows, Linux and macOS with a Windows `.dll`. Not yet tested: two real computers over a network, the winget installs on a clean Windows PC, and the Claude command line end to end.

## Files

`src/leader.ts`, `src/cli.ts` (the two tools), `src/server.ts` (rules and web server), `src/trust.ts` (voting), `src/graph.ts` (call graph, stale names), `src/similar.ts` (copies), `src/agent.ts` (rea and the AI), `src/mcp.ts` (MCP server), `src/handover.ts` (offline outbox and leader hand-over), `src/activity.ts` and `src/live.ts` (live view), `src/apply.ts` and `ghidra/ApplyNames.java` (put results into Ghidra), `src/rules.ts` (note safety), `src/check.ts` (setup checks), `skill/SKILL.md` (agent instructions), `test/`. Run the tests with `npm test`.
