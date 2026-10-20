# Corvus integration report

Added optional Corvus v2.4.0 support. Existing projects without a provider continue to use rea/Ghidra. New managed projects can use `corvus-dotnet`; native games keep their existing reader, with optional Il2Cpp known names and native build name carry-over.

No Corvus binary was downloaded, installed or run. No real rea/Ghidra analysis was run. Tests used injected runners, fake executables, tiny hand-built headers and dummy archives. No program files or game code were sent anywhere. Changes are confined to `rea-pool/`; package dependencies, the top-level README and git history were not changed. Nothing was committed.

The request mentioned an `-o` file without providing its path. This report uses the announced default, `rea-pool/CORVUS-REPORT.md`.

## Files changed

| File | Change |
|---|---|
| `requirements.json` | Pins Corvus 2.4.0 and the six supplied asset names/SHA-256 values. Adds no global runtime requirement. |
| `setup.sh` | Offers the optional reader, honors `--yes`, `--no-corvus` and check-only, verifies before extraction, installs into the existing tools folder, upgrades old copies, saves PATH/Ghidra settings, and only warns on optional failures. |
| `setup.ps1` | Equivalent optional download, fingerprint check, upgrade and environment setup; adds `-NoCorvus` / `-no-corvus`. Does not register MCP clients. |
| `src/corvus.ts` | Finds the executable without starting it; detects CLR headers and nearby Unity metadata; uses the existing safe process helpers with offline mode; validates JSON envelopes, batch steps, pages, method tokens, C#/IL code, calls and Il2Cpp names. Includes injected runners for tests. |
| `src/import-names.ts` | Checks exported trusted names against the old file fingerprint, seeds the old build's local Corvus annotations, previews conservative native migration, and validates every accepted new address/name. |
| `src/types.ts` | Adds optional project provider/version and `known.source = "corvus"`. |
| `src/exec.ts` | Adds optional per-process environment settings to the existing synchronous/asynchronous helpers. Existing calls retain their process options and Windows checks. |
| `src/check.ts` | Allows Corvus version probes and requires the pinned version only for managed Corvus projects; gives the setup command when it is missing or wrong. |
| `src/prepare.ts` | Reuses JSONL/meta caches for managed methods in a separate provider/version directory; keeps native cache paths unchanged. Can record/read Ghidra's actual image base for Il2Cpp names. |
| `ghidra/DumpAll.java` | With an optional second output argument only, records the actual Ghidra image base. The original one-argument dump behavior remains intact. |
| `src/agent.ts` | Routes managed inspection to Corvus/cache; imports checked Il2Cpp names only into untouched tasks; keeps existing analysis/review flows and labels evidence with the correct reader. |
| `src/leader.ts` | Selects and pins the managed provider for new projects; lists method tasks; supports managed graphs, optional Il2Cpp names during graph/prepare, skip flags, and `import-names <results.json> <old-file> <new-file> --data <new-folder>`. Prevents Ghidra apply from treating method tokens as native addresses. |
| `src/cli.ts` | Persists the project's reader on join, checks managed workers before preparing, and routes worker/manual commands consistently. Managed `pool next` keeps stdout valid JSON. |
| `src/mcp.ts` | Passes the saved reader to inspection and uses the correct evidence label. |
| `src/server.ts` | Preserves managed projects' exclusion of C-style detail-note kinds when loading state. Native rules retain their existing behavior. |
| `README.md` | Adds “Games: Unity, .NET and more (Corvus)”, installation/skip options, target support, export behavior, native migration examples, limitations and upstream links. |
| `skill/SKILL.md` | Explains managed tokens/C#/IL and tells workers to omit native C-style detail notes. |
| `test/corvus.test.ts` | Covers tiny PE/ELF/Mach-O/APK-like inputs, managed selection/fallback, paged/error parsing, sync/async inspection, provider caches, name safety, native migration and rebased Il2Cpp metadata. |
| `test/corvus-setup.test.ts` | Checks all pins and exercises the actual optional Bash/PowerShell installer functions with stub downloads/extraction: fingerprint mismatch, failed download/unpack, skips, unattended install and shell upgrade behavior. |
| `test/corvus-wiring.test.ts` | Runs leader/worker flows against a fake Corvus: managed task creation, join, prepare, JSON task output, submit, version failures, native graph/prepare name import, optional failure/fallback and skip flags. |
| `CORVUS-REPORT.md` | This report. |

## Verification

Ran the project's existing test command, `npm test` in `rea-pool` (invoked as `npm --prefix rea-pool test`), with unrestricted local execution. Runtime: Node v26.0.0, which satisfies the project's Node >=24 requirement. Final test summary, verbatim:

```text
ℹ tests 139
ℹ suites 0
ℹ pass 138
ℹ fail 0
ℹ cancelled 0
ℹ skipped 1
ℹ todo 0
ℹ duration_ms 3782.869583
```

The skipped test is the existing “Windows refuses characters a shell would act on” test, which only applies on Windows. All 13 added tests passed on this machine, including the PowerShell installer mocks under `pwsh`.

Additional checks passed:

- `node --check` on all 45 TypeScript files in `src/` and `test/`; the two files changed during the final defensive-parsing pass were checked again.
- `bash -n rea-pool/setup.sh`.
- PowerShell's parser on `setup.ps1`, plus the mocked installer tests.
- `git diff --check`.

`package.json` has no TypeScript typecheck script or configured compiler. `node --check` checks syntax, not static types; no compiler or dependency was installed to invent a new check.

## UNVERIFIED

These contracts were researched in the upstream docs and, where useful, v2.4.0 source. They have only been simulated here and need an owner-approved real run:

1. **CLI framing and version output.** `batch - --load <file> --json --max-output 20000 --no-index --stop-on-error` accepts a JSON array on stdin, emits one JSON object per step with one-based `step`, and provides the documented `tool/isError/structured/error` envelope. `--version` includes the expected semantic version. Unexpected output fails with a plain error; optional native metadata import warns and continues.
2. **Managed listing and code.** `search_symbols query=* kind=method assembly=<absolute path>` yields unique method tokens with `kind`, `label`, `assembly`, and paged `items/offset/total/hasMore/nextOffset`. `decompile_member` returns `language=csharp|il`, `code`, character offsets and total length. Actual pagination, compiler-generated/abstract/protected methods and IL fallback need real fixtures. Partial or inconsistent pages are rejected.
3. **Managed calls and assembly identity.** `get_call_tree direction=callees depth=1` returns method tokens; an omitted assembly means the root assembly, and `get_assembly_info.id` matches explicit assembly identifiers. Calls to other assemblies/native code are intentionally excluded from this single-assembly project's task graph. Real Unity Mono, ReadyToRun and ordinary .NET outputs have not been compared.
4. **Il2Cpp loading/export.** Loading the selected native binary discovers its matching nearby metadata and pins the selected Android ABI. `export_il2cpp_symbols formats=json baseName=pool` creates `pool_script.json` containing `ScriptMethod` rows with numeric RVA `Address` and text `Name`. This shape was checked in source, not against a real game's export. Encrypted/unusual metadata, generics sharing code and additional layouts may be refused or omitted.
5. **Ghidra address metadata.** The optional Java output has not been compiled or run inside Ghidra. New Il2Cpp preparation should record its actual image base; older ELF caches without that metadata skip name import until `leader prepare <file> --force`. PE preferred-base and cached ELF rebasing are covered with synthetic headers/data only.
6. **Native migration.** Real `rename_native` outcomes and `migrate_native_names` report rows (`oldAddress/newAddress/value/action/source/tier/confidence`) have not been observed. The implementation accepts only checked trusted names, preview action `would_set`, tiers 1–2 and score >=0.95; empirical mapping correctness and performance remain unknown. Old annotations are persisted in Corvus' local cache; original binaries and the new build's Corvus annotations are not rewritten by this preview workflow. Unrelated or unexpected migration rows can reject the import.
7. **Release packaging and platforms.** The six supplied fingerprints are pinned and tested for exact equality, but no release archive was downloaded or inspected. The installers expect a root-level `corvus` / `corvus.exe` with its packaged companion files. Real downloads, archive layout, signing/quarantine, Linux/macOS architectures, Windows PATH persistence and Windows PowerShell 5.1 still need checking. PowerShell mocks ran on this macOS host, not a clean Windows installation.
8. **Native workers and scale.** Corvus' first-use Ghidra worker build, JDK compatibility, native database reuse, large-game resource use and multi-machine operation have not been exercised. Existing native analysis tests and mocked cache paths passed; no real rea/Ghidra analysis was performed.

## Deliberate limits

APK/DEX container task scheduling, managed build migration via `update_to_new_build`/`find_counterpart`, and applying names back to .NET assemblies are documented TODOs. Corvus itself offers those capabilities; this pool integration does not claim to implement them. Native PE/ELF/Mach-O analysis continues through rea/Ghidra. Automatic Il2Cpp known-name detection is limited to `GameAssembly.dll` and `libil2cpp.so` with recognized nearby metadata.

Upstream references: [tools](https://github.com/Albasha0x0/Corvus/blob/v2.4.0/docs/tools.md), [CLI](https://github.com/Albasha0x0/Corvus/blob/v2.4.0/docs/cli.md), [features](https://github.com/Albasha0x0/Corvus/blob/main/docs/features.md), [installation](https://github.com/Albasha0x0/Corvus/blob/main/docs/installation.md), [configuration](https://github.com/Albasha0x0/Corvus/blob/main/docs/configuration.md), [engine databases](https://github.com/Albasha0x0/Corvus/blob/main/docs/engine-databases.md).
