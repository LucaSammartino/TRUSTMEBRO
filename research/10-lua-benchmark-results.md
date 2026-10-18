# 10. Lua benchmark: how well does an AI name functions it can't see names for?

Date: 2026-10-18. Target: `lua54.dll` (Lua 5.4.8, Windows x64, from LuaBinaries). Analysis: rea 6.7.0 + Ghidra 12.1.4, Java 21.

## Method

1. rea listed 844 named internal functions (CRT/startup code excluded).
2. 30 picked at random (fixed seed 42); 1 dropped (ambiguous prompt), **29 tested**.
3. Each function was decompiled by rea/Ghidra. **Every** function name in the code, including called functions, was replaced by `FUN_<address>` (text inside string literals left alone).
4. Each prompt went to a separate Claude helper that saw only that one prompt and returned a name, a one-line summary and a confidence.
5. A separate judge graded name+summary against the real name with a fixed rubric (exact / right / partial / wrong). All 29 grades were reviewed by hand and looked fair.

The AI step used Claude helpers inside the coding session, not the `claude` command line (its login was expired).

## Results

| Grade | Count | Share |
|---|---|---|
| Exact (same name, ignoring prefix) | 10 | 34% |
| Right (same purpose, different words) | 7 | 24% |
| **Exact + right** | **17** | **59%** |
| Partial | 7 | 24% |
| Wrong | 5 | 17% |

### The AI's own confidence is a strong signal

| Stated confidence | Functions | Exact or right |
|---|---|---|
| high | 10 | 10 (100%) |
| medium | 6 | 5 (83%) |
| low | 13 | 1 (8%) |

Implication for the pool: treat confidence as a gate. High-confidence notes could be accepted by default; low-confidence ones should be shown as unverified suggestions only.

### Where it failed

Mostly tiny wrappers and generic internals where the code itself does not reveal purpose: `lua_rawset` (a thin wrapper), `luaX_newstring`, `rethook`, `luaK_indexed`, `luaL_newstate`, `luaB_coresume`. It also described mechanics instead of purpose for `lua_type` and `lua_isstring`, and called `LeaveCriticalSection` a generic "critical section thunk" (real name: leaves the section).

## Caveats (read before quoting the number)

- Lua is open source and almost certainly in the model's training data. Many "exact" answers (e.g. `lua_math_type`, `luaB_getmetatable`) may be recall, not reasoning. Expect lower accuracy on unfamiliar software.
- 29 samples: roughly +/- 9 percentage points of uncertainty.
- One program, one model, one prompt.
- Strings in the code stayed visible (error messages often reveal purpose), which is realistic but helps.
- The judge is also an AI (checked by hand, but not independently verified).
- Exact name matching undervalues correct-but-differently-worded answers; the "right" grade covers that.

## Files

`rea-pool/examples/bench-prepare.ts` (builds the benchmark), `rea-agent.ts` (agent, supports `REA_POOL_NAME_MAP`), `dump-ai.ts`. Raw data: `C:\tools\work\bench\` (prompts, answers, truth, grades).
