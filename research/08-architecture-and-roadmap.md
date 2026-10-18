# 08. Architecture and roadmap (proposed)

All of this is synthesis from the research, not a validated design.

## Layers

| Layer | Piece | Status |
|---|---|---|
| Runtime | rea-agent-docker, pinned by image digest | Exists (small project) |
| Analysis | rea (+ Ghidra default) | Exists |
| Agent bridge | rea MCP / GhidraMCP / ReVa, localhost only, sandboxed | Exists |
| Evidence/plan format | REA-Reconstruction-Companion ideas | Exists |
| Annotation payloads | declib artifacts | Exists |
| Event envelope, anchors, evidence, retractions | Ours | To build |
| Baseline manifest + Merkle check | Ours | To build |
| Transport and storage | Hyperswarm + Hypercore (or alternative) | Integrate |
| Local trust engine and validators | Ours | To build |
| Work claiming / leases | Borrow from decompdecomp ideas | To build |

## Swarm manifest

Swarm ID = hash of: target sha256, runtime image digest, rea and backend versions, language/loader, analyzer options, canonical-export schema version, baseline Merkle root, protocol version, share level. Discovery topic = HMAC(room_secret, swarm ID).

## Node data flow

peer event -> schema check -> size/rate limit -> quarantine -> signature -> local evidence check -> policy -> materialized view -> (optional) apply to local Ghidra via declib. Local agent reads only the materialized, validated view.

## Build order

1. **Reproducibility experiment**: same binary (Lua 5.4, built unstripped and stripped) through the pinned image on 2+ machines/OSes; diff canonical exports; measure anchor stability across compilers. Riskiest unknown.
2. **Schema and envelope**: event JSON schema, signing, anchor spec, validators; single-node log.
3. **Local loop**: enumerate functions, task, rea + agent, verify against ground truth (Lua symbols), accept. Gives a score for agent quality.
4. **Transport prototype**: Hyperswarm + Hypercore on Windows, 2-3 nodes, equivocation handling.
5. **Claims and redundancy**: leases, rendezvous assignment, adaptive redundancy.
6. **Trust and security hardening**: injection controls, sandbox, privacy filters, reputation.
7. Interop: BinSync bridge (export/import declib TOML), decompdecomp ideas.

## Pilot target

Lua 5.4 interpreter (MIT, ~30k LOC C). Ground truth from an unstripped build lets you score names/types recovered. Alternatives: cJSON (smaller), SQLite shell (larger).

## Ranked risks

| # | Risk | Mitigation |
|---|---|---|
| 1 | Prompt injection via peer annotations or target strings | Typed data, regex identifiers, capability separation, sandbox |
| 2 | Hallucinated annotations accepted as facts | Evidence ladder, provenance, local re-verification |
| 3 | Non-reproducible baselines across peers | Pinned digest, Merkle diff, per-function exclusion |
| 4 | Legal: EULAs, onward-sharing limits, no takedown path | Metadata-only, configurable schema, counsel, blocklist, permitted targets |
| 5 | Function identity drift (tiny functions, build differences) | Tiered anchors, constraints, separate cross-build edges |
| 6 | Sybil / malicious peers | Invite-only swarms, local verification, reputation |
| 7 | Hyperswarm on Windows/Node unproven; ecosystem churn | Early prototype; transport-agnostic protocol; Iroh sidecar fallback |
| 8 | Privacy leaks (paths, strings, target hash) | Allowlist, string-copy filter, secret-derived topic |
| 9 | Cost and quota abuse | Per-node budgets, claim rate limits |
| 10 | Docker weight on Windows (8 GB images, WSL2) | Document minimum setup; native Ghidra option with pinned versions |

## Open questions

- Do different Ghidra versions agree enough for peers to share anchors, or is one pinned image mandatory?
- Is metadata-only enough value for contributors, or do they need to share reconstructed code (changes the legal profile)?
- Closed or open swarms? Open ones lack Sybil resistance.
- Where do human analysts fit alongside agents?
- Should this fork or extend decompdecomp or BinSync instead of starting fresh? (Leaning: build the envelope/anchors/transport layer fresh, reuse declib payloads, borrow decompdecomp logic.)
- Cost of agent analysis per binary (no data found).
