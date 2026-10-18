# rea-pool

Lets a group of people point their own AI at the **same piece of software** and pool the results. Nobody uploads the software or any code. Everyone already has their own copy; only small notes ("this function is called `parse_packet` and it does X") travel over the internet.

There is **one leader** (who sets it up once) and any number of **contributors** (who just run one command and leave it going). Nobody reviews anything by hand: the AIs check each other.

> Status: version 0.2. Works on **Windows, Linux and macOS** (including Apple Silicon). Automated tests run on all three on every change, including a clean-room install and a real analysis, and confirm all three systems find the identical list of functions in the same program. **Not yet tested:** two real computers talking over a network, and the Claude command-line step end to end (its login had expired during development).

## Easy install for friends

Get this folder (zip or copy) and put it anywhere, then:

| System | Do this |
|---|---|
| **Windows** | Double-click `START-HERE.cmd` |
| **macOS** | Double-click `START-HERE.command`. If macOS refuses (downloaded files lose their "runnable" mark), open Terminal, type `bash ` (with a space), drag `setup.sh` into the window and press Enter |
| **Linux** | Open a terminal in this folder and run `bash setup.sh` |

That is all. It checks each thing you need, **asks before installing anything that is missing**, and then walks you through joining. It needs about 3 GB of free disk space and an internet connection the first time.

What it checks and installs:

| Thing | Why | How |
|---|---|---|
| Node.js 24+ | runs this tool | Windows: winget. Linux/macOS: official download, fingerprint-checked, into `~/.rea-pool` |
| Java 21 (JDK) | Ghidra needs it; your other Java versions are untouched | Windows: winget. Linux/macOS: Eclipse Temurin download, fingerprint-checked |
| Ghidra 12.1.4 (about 570 MB) | reads the software | downloaded from the official GitHub page, **verified against its published fingerprint**, unpacked into your own folder |
| Ghidra's decompiler program | part of reading the software | normally included; **Apple Silicon Macs** need it built from source inside the download (a few minutes; needs Apple's developer tools: `xcode-select --install`, and `brew install bison`). The script tells you if something is missing |
| rea 6.7.0 | lets an AI read the software | npm |
| An AI | does the thinking | **not installed for you**: install the Claude command line from <https://claude.com/download>, run `claude auth login` in a normal window once, then run the start file again |

On Linux/macOS nothing needs administrator rights: everything goes into `~/.rea-pool`, and the settings are saved in `~/.rea-pool/env.sh`, which the `./pool` and `./leader` commands load for you. On Windows it sets three settings for your user (`JAVA_HOME`, `GHIDRA_INSTALL_DIR`, `REA_ANALYSIS_PROVIDER`). If something goes wrong it says exactly what, and running it again continues where it left off. When it asks, paste the "pool join" line your friend sent you and drag the software file into the window. Leave the window open and walk away; run the start file again any time to continue.

Everyone also needs their own copy of the software (the exact same file; it is checked by fingerprint). Tested with a Windows 64-bit program (`.dll`) analyzed on all three systems. rea supports other kinds of programs, but we have not tested them.

Other AIs work too if you pass a command: `pool run --ai "<command that reads a prompt on stdin and prints an answer>"`.

Tested on clean machines (in GitHub's test computers): the Linux and macOS installer, and the Windows installer for Ghidra and rea. **Not tested on a clean Windows computer:** the winget installs of Node and Java. If one fails, the script says where to download that piece by hand.

## Leader: set it up (once)

First run the setup (`SETUP-ONLY.cmd` on Windows; `bash setup.sh --mode setup-only` on Linux/macOS): same checks and installs as above, without joining anything. Then, in a terminal in this folder:

```
leader.cmd start <your copy of the software> --name "My project"      (Windows)
./leader start <your copy of the software> --name "My project"        (Linux/macOS)
```

That one command fingerprints the software, records the tool versions **you** have installed as the requirements, asks rea for every function (one task each), and starts the server. It then prints a line to send to friends:

```
pool join http://<your-address>:8787 jc_xxxxxxxx --target <path to their copy>
```

The same code works for everyone, so you do not create invites one by one. Run `start` again later to resume. `status` shows progress; `export results.json --best` saves the trusted results.

### Letting friends connect

Friends' tools connect to **your** computer over the internet (ordinary web requests). Your computer must be reachable, and your computer must stay on while they work.

1. Easiest and safest: both of you install [Tailscale](https://tailscale.com) (free), sign in, and share your computer with your friend. Your Tailscale address looks like `100.x.y.z`.
2. Start with `leader.cmd start <file> --host 0.0.0.0` (Windows) or `./leader start <file> --host 0.0.0.0` (Linux/macOS) and give your friend `http://100.x.y.z:8787` as the address.
3. Do **not** put this on the open internet as it is. Traffic is not encrypted, and anyone with the join code can join. Use `new-code` to replace the code, `revoke <name>` to remove someone.

## Contributor: join and run

Normally the start file does this for you. By hand (use `pool.cmd` on Windows, `./pool` on Linux/macOS):

```
pool join <address> <join-code> --target <your copy of the software>
pool run
```

`join` also checks your setup. `run` then takes a task, analyzes it with rea and your AI, sends the notes, and repeats until nothing is left. Stop any time with Ctrl+C. Your current task goes back to the pool.

## How results become trusted (automatically)

Each function is a task. Someone's AI proposes a name and a short description with a confidence (low/medium/high). What happens next depends only on that confidence, because an AI's own confidence is a reasonable guide to whether it is right:

| Confidence | What happens |
|---|---|
| **High** | Trusted immediately. |
| **Medium** | Another contributor's AI checks it (never the author). It agrees: trusted. It disagrees: a second checker decides. Two disagreements reject it. |
| **Low** | Kept only as a hint. The function goes back to the pool for a different contributor to try again (up to 3 attempts). |

Checking comes before new work, and nobody does the same function twice. If checkers cannot settle something it is left as an unverified hint, never trusted.

Safety rules run automatically on every note: same file and tool versions required, names limited to letters/digits/underscores, no web links, no file paths, no long hex blobs, and nothing that looks like instructions to an AI. Notes that break them are rejected. Other people's notes are always treated as data by the checking AI, never as instructions.

The model name a note carries is only informational (it cannot be proven), so it never affects trust.

## Working bottom-up (call graph)

Functions are easier to name once the functions they call already have trusted names. The pool uses this in two ways:

- Whoever analyzes a function also reports which functions it calls, so the pool learns the call graph as it goes.
- Functions whose callees are already named are handed out first, and those trusted names are shown to the AI as context. Names that are still being checked are never shown.

The leader can also read the whole graph up front with `leader graph <software file> --parallel 4`. Each function takes about 40 seconds because Ghidra starts fresh every time, so run it in parallel; it is safe to stop with Ctrl+C and run again to continue. `leader status` shows how much of the graph is known.

## Keeping unattended workers productive

Nothing here waits for a human. The pool is built to keep a crowd of AIs from wasting effort:

- **Leases expire by themselves.** A worker that vanishes loses its function after `leaseMinutes`; that counts as giving up.
- **Give-ups cool down.** A function someone gave up on goes to the back of the queue for `releaseCooldownMinutes` (default 15), so a crowd does not pass the same hard leftovers around. It still comes when nothing else is left. Among equals, the function given up on least goes first.
- **Hand-off notes.** `pool release --note "what I tried and what is unclear"` (the worker does this by itself after an error) leaves a note that the next worker sees as untrusted context. A missing or unacceptable note never blocks the release; a generic line is stored instead.
- **Copies.** Functions that decompile to the same structure (statically linked libraries, copy-pasted helpers) are fingerprinted. The first of a group of copies is done early, and once it has a trusted name the others are shown it as a hint (never as an answer). `leader graph` records fingerprints too (`shapes.json`).
- **Network blips.** `pool run` waits and retries for about ten minutes instead of stopping.

An AI agent such as Claude Code can work a pool without `pool run`: `pool connect` installs a skill (`skill/SKILL.md`) and the agent then loops over `pool next`, `pool submit`, `pool verdict` and `pool release` by itself.

## What it does not do

- It cannot prove a result is *correct*, only that it passed these checks. Treat results as strong suggestions.
- It does not stop fake agreement between accounts one person controls. That is fine among friends; do not open it to strangers without more protection.
- It is not encrypted and not meant for the open internet.
- Accuracy has not been measured; expect it to drop on software the AI has not seen much of.
- Many tasks are tiny wrapper functions where nobody can tell the purpose from the code alone; those end as hints.

## Files

`src/leader.ts` (leader tool), `src/cli.ts` (contributor tool), `src/server.ts` (the rules of the pool and the web server), `src/trust.ts` (confidence and voting rules), `src/agent.ts` (talks to rea and the AI), `src/graph.ts` (call graph: which function calls which), `src/similar.ts` (fingerprints for copies of a function), `skill/SKILL.md` (lets an AI agent work a pool unattended), `src/rules.ts` (note safety rules), `src/check.ts` (setup checks), `test/` (automated tests).

Run the tests with `npm test`.
