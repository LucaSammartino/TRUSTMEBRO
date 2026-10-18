# 06. Verification, trust and security

## Hashes versus truth (the qBittorrent question)

BitTorrent knows the correct piece hash in advance. For annotations nobody does, so hashes only give integrity and authorship. Correctness needs separate mechanisms. Use Merkle verification for the **baseline** (reproducibility), signatures for **provenance**, and the ladder below for **truth**.

## Verification ladder (strongest first)

1. Exact byte/object match: recompile with pinned toolchain, objdiff (matching-decomp model).
2. Execution equivalence: run candidate and original on inputs; differential fuzzing is the strongest check found.
3. Static structural proof: CFG/dataflow agreement, struct layout fits observed access offsets, type sizes consistent, no contradiction with baseline.
4. Independent cross-tool or cross-agent agreement.
5. Single-model confidence.
6. Unsupported free text.

Rules: receiving peers should re-run cheap deterministic checks locally and never accept a remote attestation in place of them. Keep claim and evidence separate; do not collapse to one confidence number (agents game scalar metrics).

## Subjective claims (names, comments)

No oracle exists. Keep all signed claims (Alice says X, Bob says Y); each peer's local policy chooses what to show or import. Quorum raises visibility, not truth. Options: demand-adaptive redundancy (BOINC-style: 1 check for mechanical claims, more peers for disputed ones), reputation by survival of claims (WikiTrust idea), hidden canary functions (strip names of known library functions locally and score a new peer's agent; Gemini's idea), publish **rejected-hypothesis** events to save quota.

Rejected as over-engineered for now: Multi-Krum clustering of name embeddings; continuous fine-tuning from the ledger.

## Sybil resistance

Keys are free; signatures prove authorship, not independence. Objective claims: re-verify locally, so fake votes do not matter. Subjective claims: invite-only swarms with inviter reputation at stake, per-binary namespaces, quotas. Open swarms have no good answer.

## Prompt injection (top risk)

Peer annotations and strings inside the target are both hostile input to the local agent. Research (2026) shows binary-embedded strings already attack RE agents; MCP security guidance says tool descriptions and annotations are untrusted. No existing MCP RE server defends against it; decompdecomp passes notes as plain text.

Controls:
- Typed data, never prompt fragments. Strict regex for identifiers (e.g. `^[A-Za-z_][A-Za-z0-9_]{0,63}$`), length caps, field allowlists.
- Free-text comments from peers excluded from autonomous passes or wrapped in untrusted-data delimiters.
- Capability separation: reader/proposer agents get no shell, network or arbitrary file write; the sync daemon runs outside the agent sandbox and never exposes generic RE commands to peers. Pipeline: receive, schema-validate, size/rate check, quarantine, verify signature, local evidence check, materialize by policy. Never "peer says rename, so call MCP rename".
- Sandbox: read-only target mount, network denied by default, narrow local proxy for model calls.

## Privacy leakage

Strip paths, usernames, hostnames, provider IDs. Reject outgoing comments that copy long strings from the binary (check against local .rodata). Allowlist outgoing fields, not blocklist. Topic derived from secret. Even a target hash reveals what someone owns.

## Reproducibility as a trust input

"Peer B verified it" means nothing if B ran a different pipeline. Every attestation carries runtime image digest, tool versions, baseline root. See `04`.

## Supply-chain

Modified compiler/analyzer could forge "verified". Require known approved profiles for high-value verification.
