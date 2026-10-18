# 02. decompdecomp (closest existing project)

Source: subagent read of github.com/n-delic/decompdecomp via page/raw fetches (summarizer output, not raw bytes). Treat details as likely, not certain.

## Facts

- Python 3.12+, uv, `src/decompnet`. MIT. 93 stars, 159 commits, 1.0.2-alpha, commits 16-17 Oct 2026, a "major app rewrite in progress" banner. 45 test files.
- Origin: continuation of decomp.wtf (495 stars, archived 2026-10-15; author's stated reason: community opposition to AI decompiling). decompdecomp's README says it is unrelated and not endorsed by decomp.wtf. The hosted coordinator was deliberately removed.
- Two modes: ROM mode (N64/PS1/PS2/GBA; link candidate at the real address, compare bytes) and fork mode (objdiff; 100% = match).
- Agents connect via `decomp mcp`, a stdio MCP bridge to a local localhost HTTP MCP with per-agent bearer tokens. Agents get no shell and cannot edit build scripts; AGENTS.md says the judge must not be weakened.
- Windows is experimental via WSL2.

## Rooms (collaboration)

- Host-authoritative hub. Host runs HTTP `/collab/*`; guests poll every 2 s. Reached via Cloudflare quick tunnel, or LAN/Tailscale over plain HTTP.
- Invite code (`token_urlsafe(16)`, hashed at rest), `dn_` bearer tokens, optional approval, member removal, rate limit 900/min, 256 KB body cap. Guest's game sha1 must equal the room's.
- Shared: claims, C attempts, matches, names, a versioned shared header (structs, prototypes), notes, scores, events. Fork rooms move code as git bundles up to 512 MB.
- Claims: host-assigned, 30-minute lease, 15-minute release cooldown.
- Header edits: version check with 3 retries plus a regression recompile of all matched functions; breaking edits rejected. Fork rooms: host tree wins.
- Verification: host recompiles and verifies against its own ROM. No local re-verification seen for ROM-mode guests (inferred from absence).

## Security

- No prompt-injection defense seen. Notes are length-capped (4000 chars; 600 each / 2500 total shown to agents) and passed as plain text to other agents. Not read: `server.py`, `routes/`, `tools.py`, so a warning in the agent prompt could exist.
- Trust model is "trust the host". Tunnel rooms get TLS from Cloudflare; LAN/Tailscale are plain HTTP.

## Verdict against our goals

| Goal | decompdecomp |
|---|---|
| Local target per user | Yes |
| Metadata only | No: matched C source and best-attempt source (up to 64 KB) are shared |
| P2P | No: single authoritative host, single point of failure |
| Signed provenance | No |
| Local re-verification by every peer | Not for ROM mode |
| Bring-your-own agent | Yes (MCP) |
| Injection defense | None seen |

## What to reuse

Claims with leases, versioned shared header with regression check, the judge/scoring split, MCP tool surface, MIT licence. Do not build on the tunnel/invite layer, polling, host-only verification, or git-bundle path.

Cheapest experiment: run a room over Tailscale or another overlay, no code change. A real serverless transport would need an adapter for roughly 15 `/collab` operations plus leader election. Given the rewrite in progress, prefer a pinned vendored copy or just borrow ideas.

## Open checks

Read `collab.py`, `forkroom.py`, `server.py` directly; ask whether the author wants a pluggable transport; check the 2 open issues.
