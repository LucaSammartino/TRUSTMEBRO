# 03. Annotation schema: BinSync, declib, rebrew

Source: subagent read shallow clones of binsync v5.15.4 (cd38076e), declib v4.5.0 (07a2ce87), rebrew (0b13d6a2). Code was read, not run.

## declib artifacts (verified in source)

Types: Function, FunctionHeader, FunctionArgument, StackVariable, Comment, GlobalVariable, Struct, StructMember, Enum, Typedef, Patch, Segment. Every one has `last_change` and `scope`. Keys are an integer address or a name; TOML writes ints as `0x...`. Equality ignores `last_change`. No author field, no signature, no per-artifact schema version.

## BinSync repo layout (per user branch `binsync/<user>`)

```
metadata.toml            # user, version (= binsync package version)
functions/<%08x>.toml
structs/<name>.toml
comments.toml patches.toml global_vars.toml enums.toml typedefs.toml segments.toml
```

`binsync/__root__` root commit carries the binary hash (MD5, per rebrew docs).

## Sync semantics

- A user only commits to their own branch; commit identity is a self-asserted `<user>@binsync.local`, unsigned.
- Pull = `git fetch --all` plus refresh of each local branch from its own remote. Peers are never git-merged into yours; their data is merged per artifact into your branch (`merge_artifacts`) at levels OVERWRITE, NON_CONFLICTING (default; fills only fields that are None locally, so disagreeing values are silently dropped), MERGE (GUI dialog only for function-name conflicts).
- Push sends `__root__` and own branch; no retry/conflict logic. No tombstones. `last_push_*` is in-memory only.
- Schema evolution is ad hoc (`__setstate__` backports; stored version is not checked).
- Probable bug (not run): patch loading references `patch.offset` while `Patch` has `addr`.

## Ghidra / headless

Ghidra 12.0+ via PyGhidra. README says "early stage" though its own support table contradicts that. declib runs headless: `DecompilerInterface.discover(force_decompiler="ghidra", headless=True)` with `GHIDRA_INSTALL_DIR`; there is an agent-oriented `decompiler` CLI (load, list_functions, decompile, rename, xrefs, `--json`) and a bundled agent skill. Limits: no artifact-watch hooks, struct registration caveats, symbol lookup breaks above ~50k symbols.

## rebrew

- `rebrew binsync init|push|pull|summary|diff|overlay|export|import`; writes as one BinSync user, pulls peers into temp worktrees.
- Three-way reconcile against a local baseline sidecar; conflicts reported not merged; remote deletions surfaced as `deletion_required`, never auto-applied.
- Provenance: per-row `UPDATED_BY`/`UPDATED_AT` (closed list of 19 tool tags); per-field `origins` (tool, user, snapshot hash, value_hash, binary identity); `verification` table (status, writer, input_hash, measured_at); `status_history` up to 10,000 events/function.
- `rebrew prove` (angr + Z3) can set `PROVEN` for near-matches; no stored proof artifact seen. Evidence taxonomy: EXACT, RELOC, PROVEN.
- Identity: `MODULE.0xVA` plus optional source anchors. No signing.

## Reuse vs add

Reuse as-is: declib payload schemas and TOML/JSON serialization; rebrew's three-way reconcile rules and evidence taxonomy.

Add for a P2P signed log:

| Missing | Why |
|---|---|
| Event envelope: content hash, author public key, signature, per-author sequence/parents, event schema version | Authenticity, ordering, evolution |
| sha256 binary identity (MD5 is weak) | Swarm identity |
| Stable anchors beyond address (see `04`) | Cross-peer agreement |
| Explicit retract events | No tombstones today |
| Structured evidence by hash, confidence, model/prompt profile | AI claims need provenance |
| Negative evidence ("rejected hypothesis") | Saves peers' quota |
| Keep all signed conflicting claims; resolve at read time | NON_CONFLICTING drops disagreement silently |
| Identifier/length validation | Injection defense (see `06`) |

## Sketch of an event

```json
{
  "schema": "re-annotation/1",
  "swarm": "<hash of manifest>",
  "target": {"sha256": "...", "baseline_root": "..."},
  "anchor": {"rva": "0x1230", "section": ".text", "size": 372, "masked_hash": "..."},
  "claim": {"kind": "function_name", "value": "parse_packet"},
  "evidence": [{"kind": "xref|string|exact_match|exec", "digest": "..."}],
  "provenance": {"agent": "...", "model": "...", "prompt_profile": "sha256:...", "rea": "x.y.z", "runtime": "image@sha256:..."},
  "confidence_class": "model_only|corroborated|verified",
  "parents": ["event-hash"],
  "author": "ed25519:...", "seq": 42, "signature": "..."
}
```

This is our design inference, not an existing format.
