# 04. Function anchors and the reproducible baseline

Source: subagent research (about 16 tool calls). Cited facts and inferences are separated below. No published collision/false-positive rates were found for any scheme.

## How existing systems fingerprint functions

| System | Mechanism | Notes |
|---|---|---|
| Lumina | MD5 over per-basic-block "cleaned" code; relocatable/address bytes and nops masked via processor `calcrel` hook (Synacktiv: matches FLIRT) | The request also sends license key, hostname, paths, input file MD5. |
| Ghidra FID | Full and specific hashes over operand-masked instruction bytes; relocation ranges and large scalars replaced by placeholder; short functions get no hash | Conflict: one source says specific hash includes callee hashes, another small scalars. Unresolved (`FidHashQuad` not read). |
| Ghidra BSim | Decompiler normalized SSA P-code, Weisfeiler-Lehman style relabeling; sorted multiset of 32-bit hashes, TF-IDF cosine | Quarkslab calls "LSH" loose. Depends on decompiler major.minor; incompatible DBs need re-ingest. |
| BinDiff | Layered matchers (raw-byte hash, prime signature, MD index, call graph...) | Pairwise, not an ID. |
| Binary Ninja WARP | UUIDv5 over function's basic-block GUIDs after zeroing relocatable instructions, dropping nops; optional caller/callee constraints | Only the GUID goes over the network. |
| SigKit / Rizin zignatures | Signature libraries | SigKit no longer developed; Rizin docs not verified (found radare2's). |

## Determinism evidence

- Crussell (BAR 2025): 30 Ghidra versions over 3,751 Windows binaries. Function-level similarity dropped as low as 6% between adjacent versions while basic-block similarity stayed ~96%. One file hit 0% because the Decompiler Parameter ID analyzer timed out and produced an empty artifact. (Table extraction partly garbled; check the PDF.)
- Ghidra issue #4332: non-deterministic decompiled-C export on MIPS. #3899: changing image base changes decompiler output. Resolution status not checked.
- Implication: function boundaries and decompiler-derived features are not stable across versions; raw bytes and basic blocks are far more stable.

## Recommended design (our inference)

**Exact tier** (same binary): `sha256(image) + RVA + size + masked_bytes_hash`.
- Masking spec is ours, published and versioned (mask relocations, absolute addresses, nops), with a per-basic-block second hash.
- Tiny functions: no hash-only anchor; require caller/callee constraints.
- Does not depend on the decompiler, so it survives Ghidra upgrades better than BSim.

**Cross-build tier**: BSim / WARP-style GUID / BinDiff-style fingerprints stored as separate equivalence edges, never as identity. Each edge carries tool version and settings hash. Do not share raw BSim vectors.

**Baseline check at join**:
1. Export canonical facts sorted by RVA (function entries/sizes, basic blocks, xrefs) with a header: analyzer and decompiler versions, option set, completeness flag so timeouts are visible.
2. Domain-separated Merkle tree, sub-roots for functions and xrefs.
3. Peers compare roots; on mismatch walk the tree and mark only differing functions unverified. Divergent regions get re-analyzed or excluded.
4. Pin the runtime by image digest (see rea-agent-docker) to make matches the common case.

## Privacy

Masked-byte hashes and feature vectors may let someone who holds the same binary confirm what you analyze. No source analyzed whether they can be inverted; our privacy reasoning is inference only. Mitigate by deriving the swarm topic from a shared secret and only exchanging with admitted peers.

## Open questions

- Collision and false-positive rates on real binaries (needs an experiment on Lua with several compilers).
- Whether peers using different Ghidra versions still agree on function boundaries enough to share anchors.
- Prior art for Merkle commitments of analysis exports: none found.
