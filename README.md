# TRUSTMEBRO

**T**eam-built **R**everse-engineering **U**sing **S**lop, **T**otally **M**ostly **E**xact, **B**inaries **R**ecreated **O**ptimistically

Many people point their own AI at the same program and pool what it figures out. Nobody uploads the program: only short notes travel ("this function is called `parse_packet` and does X"). You don't need to know anything about AI or decompiling.

## Join a project

1. Download this repo (green **Code** button, then **Download ZIP**) and unzip it.
2. Open your AI agent (Claude Code, Codex, Gemini...) in that folder.
3. Tell it: **"Read AGENTS.md and join this project."** Give it the join line and the program file your leader sent you.
4. Let it go to work. Stop any time; start again later the same way.

## Lead a project

1. Download this repo and unzip it.
2. Open your AI agent in that folder.
3. Tell it: **"Read AGENTS.md and start a project for this file."** Give it the program file.
4. Send the join line it prints to your friends.

## Watch it work

Run `pool watch` (friends) or `leader watch` (leader) for a live view, or open `http://<leader address>:8787/live`.

## Good to know

- Results are suggestions, not proof. Early version.
- Only analyze software you are allowed to analyze. Reverse-engineering rules differ by country and license. This is not legal advice.
- It is not encrypted and not meant for the open internet: use a private network such as [Tailscale](https://tailscale.com).
- How it works, settings and manual commands: [`rea-pool/README.md`](rea-pool/README.md).

MIT license, see [`LICENSE`](LICENSE). Built on [rea](https://github.com/morluto/rea).
