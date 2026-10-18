# 09. Sources and reliability

> The raw reports and notes listed below were kept local and are not part of this repository.

## Source passes

| Pass | Where | Method | Reliability notes |
|---|---|---|---|
| Our first deep research (5 topics) | `../reports/P2P collaborative decompilation prior art.md`, `../research_notes/P2P collaborative decompilation prior art/` | Subagents, mostly search-result summaries | Shallow; many licenses and dates unverified; missed decompdecomp |
| Codex deep research | `../reports/Codex-deep-research-report.md` | External; inline citations | Most structured; found decompdecomp; some claims unverified by us |
| Gemini deep research | `../reports/GEMINI - ...docx` | External; ~140 numbered sources | Strong on BinSync/declib, rebrew, Lumina, BSim; some over-engineered ideas; star counts differ from Codex |
| Consensus | `../reports/Consensuapp-...pdf` | Academic search, 100 papers | Good paper citations; confirms no end-to-end system; little new architecture |
| Step 1: decompdecomp | `../research_notes/step_findings/decompdecomp.md` | Page/raw fetches via summarizer | "Verified" = summarizer read it; some files not read |
| Step 2: BinSync/declib/rebrew | `../research_notes/step_findings/binsync_declib_rebrew.md` | Shallow clones, code read, not run | Best-grounded pass |
| Step 3: function anchors | `../research_notes/step_findings/function_anchors.md` | Web research; some PDFs garbled | Design is inference; no collision-rate data |

## Known conflicts and weak spots

- Ghidra stars: ~55k (Gemini) vs ~90k (Codex). Not important, but shows number drift.
- decompdecomp stars: ~4 (Codex) vs 93 (step 1). Repo is changing fast.
- rea star/fork counts in one note (~317k) are implausible; ignore.
- Radicle: Gemini recommends it as base; Codex cites its docs warning about removed transport encryption.
- FID specific hash contents: conflicting sources.
- Iroh 1.0 date and IPFS Shipyard wind-down (2026-09-30) come from third-party notes.
- Benchmark papers (SRE-Bench, CrackMeBench, attack papers) were seen only via summaries.
- EU contract-override rule comes from model knowledge; verify.
- No data found on: Ghidra run-to-run nondeterminism on identical setup, per-binary agent cost, Hyperswarm on Windows/Node, annotation-metadata legal precedent, anchor collision rates.

## Cheapest ways to close the gaps

1. Run the Lua reproducibility experiment (anchors, baseline, determinism).
2. Prototype Hyperswarm/Hypercore on Windows.
3. Read decompdecomp `collab.py`, `server.py` and tool prompts directly.
4. Ask counsel about onward-sharing and EULA questions.
