# P2P collaborative decompilation: research pack

Date: 2026-10-18. Status: research phase, nothing built yet.

Goal: a tool each person runs locally (own binary copy, own AI agent and quota, rea as the analysis layer) that coordinates with peers over the internet by exchanging only metadata (names, types, comments, evidence), never binaries or code.

## Bottom line

1. No project combines all of: local-only targets, metadata-only exchange, bring-your-own-agent, signed provenance, serverless P2P, local re-verification. The pieces exist; the integration does not. (Four independent research passes agree: ours, Codex, Gemini, Consensus. Absence of evidence, not proof.)
2. Closest project: **decompdecomp** (MIT, alpha). It is hub-and-spoke (one host verifies everything) and it shares matched C source, so it is *not* metadata-only P2P. Useful as a reference and as a source of claims/lease/header-versioning logic. See `02`.
3. Annotation schema: reuse **declib** artifact types (BSD-2). Add what it lacks: signed event envelope, stable function anchors, evidence, confidence, retractions, negative evidence. See `03`.
4. Function identity is the unsolved core. Address-only keys break; analyzer-dependent hashes (BSim) drift across Ghidra versions. Recommended: exact-target anchor from our own masked-bytes hash + RVA + size, cross-build fingerprints kept as separate edges. See `04`.
5. Transport: Hyperswarm + Hypercore (one signed log per author) is the best fit on paper; libp2p/IPFS stack is under a maintenance cloud; Radicle has a documented security warning. Windows/Node viability is untested. See `05`.
6. Hashes prove integrity and authorship, not correctness. Correctness comes from a verification ladder (exact byte match > execution > structure > agreement > single model). See `06`.
7. Prompt injection through peer annotations is the top security risk and no existing tool defends against it. See `06`.
8. Legal: metadata-only, bring-your-own-copy is the established pattern; it is not a blanket safe harbor; EULA bans are the main US risk. Get counsel before targeting commercial software. See `07`.

## Files

| File | Contents |
|---|---|
| `01-landscape-and-gaps.md` | Existing tools by category, what is missing |
| `02-decompdecomp.md` | Deep look at the closest project |
| `03-schema-binsync-declib-rebrew.md` | Annotation data model, sync semantics, what to add |
| `04-function-anchors-and-baseline.md` | Stable identity, reproducibility, Merkle baseline |
| `05-p2p-stack.md` | Transport/storage candidates and recommendation |
| `06-verification-trust-security.md` | Verification ladder, reputation, Sybil, injection, privacy |
| `07-legal.md` | Legal context and project-structure implications |
| `08-architecture-and-roadmap.md` | Proposed architecture, build order, risks, open questions |
| `09-sources-and-reliability.md` | Where each claim came from and how much to trust it |

Raw material (earlier reports, and the Codex, Gemini and Consensus deep-research outputs, plus raw subagent notes) was kept local and is **not included in this repository**; the files below are the distilled result. References to `reports/` or `research_notes/` inside these files point to those local-only folders.
