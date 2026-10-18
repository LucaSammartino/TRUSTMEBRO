# 07. Legal context

Research only, not legal advice. Several points are unverified (flagged). Get counsel before targeting commercial software.

## US

- 17 USC 1201(f): interoperability exception is narrow (sole purpose, independently created program, information not readily available, no otherwise infringing acts); sharing allowed only for interoperability.
- 1201(j) security testing; 2024 triennial rule renewed existing exemptions (current text not retrieved); next cycle 2027.
- Sega v. Accolade, Sony v. Connectix: intermediate copying for analysis can be fair use. Google v. Oracle: fair use on its facts. No ruling on publishing a decompilation.
- EULA bans on reverse engineering have been enforced: Davidson v. Jung (8th Cir. 2005), Bowers v. Baystate (Fed. Cir. 2003). Main US risk for the tool's users.

## EU / UK

- Directive 2009/24/EC Art. 5(3) study/test rights; Art. 6 decompilation for interoperability with limits on onward use; contract cannot override (Art. 8; from model knowledge, verify against the CJEU judgment).
- UK s.50B similar, but a limit on passing information to people who do not need it could cut against peer sharing (flag for counsel).

## Project structure precedents

- SM64, OoT, pret decomps: ship reconstructed source only; user supplies own copy checked by hash. Enforcement found targeted binaries, asset-bearing ports and circumvention tools (Yuzu: $2.4M settlement), not source-only decomps.
- decompdecomp tells users not to publish generated code and notes many decomp communities reject AI contributions. decomp.wtf was archived amid community opposition.
- Several projects omit a root LICENSE for derived src/asm and license only tooling.

## Tool-provider exposure

Betamax/Grokster-style reasoning favors tools with substantial non-infringing uses, no inducement, no circumvention. youtube-dl reinstated after an EFF letter; Yuzu shows the risk with encryption circumvention. A metadata-only exchange with no bytes, disassembly or key handling sits far from the Yuzu theory (our inference, not a legal conclusion).

## Design implications

- Never replicate binaries, assets, raw disassembly, auto-decompiled or generated source.
- Make the allowed annotation schema configurable per project/jurisdiction; do not assume metadata is always safe (large symbol sets, confidential strings, contractual limits).
- No takedown path in pure P2P: consider an opt-in blocklist keyed by binary hash.
- Sharing-level labels (TLP-style) and contribution-based access from malware-sharing communities are governance models to borrow.
- Notice that users must be authorized to analyze their target.
- Default to open-source or explicitly permitted pilot targets.

## Gaps

No case or takedown found on symbol maps/annotation metadata (shallow search). Not covered: Ghidra-specific legal history, DeCSS/Reimerdes, CFAA policy, other jurisdictions, current terms of VirusTotal/abuse.ch.
