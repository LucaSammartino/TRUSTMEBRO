# TRUSTMEBRO

**T**eam-built **R**everse-engineering **U**sing **S**lop, **T**otally **M**ostly **E**xact, **B**inaries **R**ecreated **O**ptimistically

A collaborative, vibecoded decompilation pipeline. Output is approximate, the code was written on vibes, and nobody using it needs to know how any of this works.

> Trust me, bro.

## What it does

Many people point their own AI at the **same piece of software** and pool the results. Nobody uploads the software or any code: everyone has their own copy, and only small notes ("this function is called `parse_packet` and does X") travel over the internet. One person is the **leader** and sets it up; everyone else just runs one command and leaves it going. Nobody reviews anything by hand, because the AIs check each other (high-confidence results are trusted, medium ones get an independent check, low ones are retried by someone else).

It is built on [rea](https://github.com/morluto/rea) (which lets an AI read software through Ghidra).

## Start here

- **Join a project:** Windows: double-click `rea-pool/START-HERE.cmd`. macOS: double-click `rea-pool/START-HERE.command`. Linux: run `bash rea-pool/setup.sh`. It checks what you need, asks before installing anything, and walks you through joining.
- **Run a project:** run the setup first (`SETUP-ONLY.cmd`, or `bash setup.sh --mode setup-only`), then `leader.cmd start <software file>` (Windows) or `./leader start <software file>` (Linux/macOS). See [`rea-pool/README.md`](rea-pool/README.md).

## Honest status

Early (v0.2). Runs on **Windows, Linux and macOS** (Apple Silicon included): automated tests on all three check the pool's rules (24 tests), a clean-room install, and a real Ghidra analysis, and confirm every system finds the same functions in the same program. **Not yet tested:** two real computers over a network, a clean Windows install of the Node/Java installers, and the Claude command-line step end to end. Accuracy has not been measured, and will be lower on unfamiliar software. Results are strong suggestions, not proof.

## Please use it responsibly

Only analyze software you are allowed to analyze. Reverse-engineering rules differ by country and by license (many licenses forbid it), and the tool does not check this for you. It never transmits the software itself, but shared notes can still describe it. This is not legal advice.

## License

MIT, see [`LICENSE`](LICENSE).
