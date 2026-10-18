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
| See progress / results | `leader status`, `leader export results.json --best` |
| Read the call graph up front | `leader graph <program file> --parallel 4` (slow: ~40 s per function; safe to stop and rerun) |
| Remove someone / change the join code | `leader revoke <name>` / `leader new-code` |

Setup needs about 3 GB of disk and internet the first time. It installs Node 24, Java 21, Ghidra 12.1.4 (checked against its published fingerprint) and rea 6.7.0 into your own folder (`~/.rea-pool`); on Windows it sets `JAVA_HOME`, `GHIDRA_INSTALL_DIR` and `REA_ANALYSIS_PROVIDER` for your user. Apple Silicon Macs build Ghidra's decompiler once (needs `xcode-select --install` and `brew install bison`).

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
- **Give-ups cool down** at the back of the queue (`releaseCooldownMinutes`, default 15), and leave a hand-off note for the next worker. Expired leases count as give-ups.
- **Copies:** functions with the same structure are fingerprinted; once one has a trusted name, the others get it as a hint, never as an answer.
- **Network blips:** `pool run` waits and retries for about ten minutes.

## Limits

- Results pass checks but are not proven correct. Treat them as strong suggestions.
- Fake agreement between accounts one person controls is not prevented. Fine among friends; not for strangers.
- Not encrypted, not for the open internet.
- Accuracy has not been measured and will be lower on unfamiliar software. Tiny wrapper functions usually end as hints.
- Tested on Windows, Linux and macOS with a Windows `.dll`. Not yet tested: two real computers over a network, the winget installs on a clean Windows PC, and the Claude command line end to end.

## Files

`src/leader.ts`, `src/cli.ts` (the two tools), `src/server.ts` (rules and web server), `src/trust.ts` (voting), `src/graph.ts` (call graph, stale names), `src/similar.ts` (copies), `src/agent.ts` (rea and the AI), `src/mcp.ts` (MCP server), `src/activity.ts` and `src/live.ts` (live view), `src/rules.ts` (note safety), `src/check.ts` (setup checks), `skill/SKILL.md` (agent instructions), `test/`. Run the tests with `npm test`.
