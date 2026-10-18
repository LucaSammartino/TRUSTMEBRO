# 01. Landscape and gaps

## Collaborative RE tools

| Tool | Model | Notes |
|---|---|---|
| Ghidra Server | Central server, check-in/out, merge at check-in | Stores full program DB centrally; version lockstep. Not binary-less. |
| IDA Teams | Commercial; 2026 versions use Git remotes with semantic 3-way merge | Good model for conflict categories (rename vs comment vs type). Proprietary. |
| Binary Ninja Enterprise | Commercial server, snapshot push/pull/merge | Pluggable conflict resolver. |
| **BinSync** (BSD-2, ~750 stars) | Git; branch per user; TOML artifacts; IDA, Binja, angr, Ghidra 12+ | Best schema/adapter base. Address-keyed, unsigned. |
| collabREate, YaCo, IDArling, revsync | Older IDA-era sync plugins | Dormant. revsync tracked per-block analyst attention (idea for work-avoidance). |
| Lumina (Hex-Rays) | Hash-indexed metadata server; sends masked-code digests, returns names | Closest precedent for "metadata by hash without code". Central, and the request also sends license, hostname, paths. |
| RevEng.AI | SaaS, uploads binaries, ML function matching | Violates the privacy boundary. |
| decomp.me | Central web scratchpad for matching C | Function-scoped sharing is a good micro-task model. |
| Matching-decomp projects (SM64, OoT, pret...) | Git + user-supplied ROM checked by hash + objdiff | Strongest precedent for objective verification and legal structure. |
| permuter@home | Volunteer CPU; any result verified in ms | Asymmetric verification pattern. |
| **decompdecomp** (MIT, alpha) | Local agents, host-run "rooms" | Closest project overall. See `02`. |

## AI / agent layer

- MCP bridges exist for every major tool: GhidraMCP (~11k stars), ReVa (Ghidra, transactional edits), ida-pro-mcp (~13k), Binary Ninja MCP, r2mcp, rea (multi-backend). None shares annotations between users.
- Agent workbenches: rebrew (BinSync sync + compiler loop), Mizuchi (m2c + Claude + permuter + objdiff, picks next function), DAILA (decompiler-agnostic AI plugin on declib), decomp-goal-harness (small matching goals with local verifier).
- Research models: LLM4Decompile, SK2Decompile, DIRTY, SymLM, GenNm, ReSym, Agent4Decompile. Reported numbers come from authors; many seen only through summaries.
- Key lesson: compile success is not correctness. One 2026 paper reports refinement raising build rate 75% to 90% while behavior-matched rate fell 74% to 62%. Another reports 99-100% compile but 32-42% re-executability. LLMs invent plausible fields and types.

## Gaps nobody has filled (as far as we found)

1. A P2P protocol whose objects are only non-binary semantic facts.
2. A cross-tool function identity scheme that survives analyzer differences.
3. An evidence schema for AI-generated annotations (model, prompt profile, evidence, verifier result, peer rechecks).
4. Defense against prompt injection arriving via synced annotations.
5. A reproducibility profile shared across Ghidra/IDA/Binja/Rizin.
6. Coordinator-free work claiming with leases (decompdecomp has leases but a host).
7. Sybil-resistant reputation for subjective names (objective claims can be re-verified locally instead).

## Environment pinning

`alexmi256/rea-agent-docker` (MIT, 3 stars): Ubuntu 24.04, rea-agents 6.5.0, Node 24, Ghidra 12.1.4 + JDK 21, Hopper demo, many helpers; GHCR images (~8 GB); linux/amd64 only. Pins are version numbers, not digests; its own verification numbers are internally inconsistent. Good basis for a pinned-by-digest runtime.

`ShadowSwaps/REA-Reconstruction-Companion` (MIT, 74 stars): agent skill on top of rea; evidence packets with hashes and a read-only `--verify`; separates observations/inferences/unknowns; checkpoint/resume. Reuse the evidence-packet and provenance ideas.
