# 05. P2P stack

Mixed sourcing: mostly aggregator/summary-based. Licenses and 2026 release cadence were not primary-verified.

## Requirements

Signed per-author log, append-only, mergeable, topic-based discovery, NAT traversal, runs on Windows desktops, Node/TypeScript friendly, no central host.

## Candidates

| Option | Fit | Concerns |
|---|---|---|
| **Hyperswarm + Hypercore** (MIT; Hypercore ~2.9k stars, active) | Topic hash discovery, hole punching, blind-relay fallback, signed append-only logs, sparse replication | Built for Bare/Pear runtime; Node on Windows unverified. Single-writer logs can fork (equivocation) unless detected. |
| + **Autobase** (~158 stars) | Multi-writer linearized view, writer admission | `apply` must be deterministic; view reorders undo/redo. Start without it. |
| **Iroh** (1.0 reported ~June 2026, unverified) | Strong hole punching, stability commitment | Rust, no official Node binding, no topic discovery; status of gossip/docs/blobs post-1.0 unclear. Good sidecar fallback. |
| libp2p / Helia / OrbitDB | Mature protocols | Shipyard (IPFS maintainers) wound down 2026-09-30 per one source; two 2026 js-libp2p gossipsub DoS CVEs. Avoid as foundation. |
| Radicle | Per-peer namespaces, signed refs, COB CRDTs, threshold canonical state | Docs warn transport encryption removed over a severe vulnerability; weak Windows support (low-reliability source). Copy ideas, not the stack. |
| Secure Scuttlebutt | Identity = key, signed feeds, gossip | Legacy in JS; full-feed sync; hash chains cannot stop an author forking (Meyer). |
| Automerge / Yjs | Good for editable projections and notes | Not an evidentiary ledger; char-level merges are wrong for typed records. |
| p2panda, Willow/Earthstar, Keyhive | Interesting designs | Pre-production. |
| Git over a transport (BinSync-style) | Familiar, auditable | Weak live claiming and discovery. |

## Recommendation (synthesis, not validated)

- Hyperswarm for discovery on `HMAC(room_secret, sha256 || protocol)`; the raw hash as topic would reveal what people analyze.
- One Hypercore per author; each node materializes its own view by a deterministic rule; defer Autobase.
- Treat any CRDT (Automerge) as a view/projection, never the source of truth.
- Admission by invite or allowlisted author keys (open topics offer no Sybil resistance).
- Keep the protocol transport-agnostic so an Iroh sidecar or git bridge can replace the transport.
- Task assignment: rendezvous hashing of (function, peer) for preferred sets plus short signed leases gossiped; duplicates are fine and provide verification signal. Beware peers grinding IDs to win assignments.

## First experiments

1. Hyperswarm + Hypercore prototype on Windows with Node: discovery, replication, reconnect.
2. Equivocation handling: detect and quarantine a forking author.
3. Relay and bootstrap costs/availability (unverified).
