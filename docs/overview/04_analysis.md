## 04. Static Code Analysis — Discovery, Naming, CFG, Xrefs, Symbols, Tech Scan

This chapter covers DisasmStudio's *static* analysis layer: the set of `Core/` modules
that turn a freshly-loaded image into something navigable — function boundaries, a
control-flow graph, a whole-program cross-reference index, symbol names (from PDBs,
exports, and heuristic guessing), and a capability ("tech") scan. All of these are
**engine-agnostic** (they drive the disassembler through the `IDisassembler` interface,
so either Zydis or Capstone can back them) and, with the exception of `SymbolResolver`
(which talks to DbgHelp), they are **pure logic with no ImGui/Win32 dependency** so they
can be unit-tested in the sandbox. The Binary View tab (`src/Tabs/BinaryViewTab.cpp`)
orchestrates them and surfaces their results.

A recurring design rule throughout: **real, verifiable facts** (exports, PDB symbols,
relocations, imports) take priority, **heuristic guesses** are always clearly labelled as
best-effort, and a **user rename always wins** over everything.

### Function discovery — `FunctionAnalyzer`

`src/Core/FunctionAnalyzer.{h,cpp}` finds where functions start. Its public surface includes
`analyze(bin, dis, arch, maxFunctions = 50000, maxInstrPerFunc = 4000)` for the exact
architecture selected by the load/background pipeline, returning a
vector of `DiscoveredFunction { address, size, name, isExport }` sorted by address, plus a
human-readable `lastSummary()` string. It combines five independent seed sources and then
expands them by recursive descent:

1. **Entry point** — if `bin.entryPoint()` is non-zero, `imageBase() + entryPoint` is the
   first seed.
2. **Explicit raw root** — a raw image deliberately retains `entryRVA_ = 0`, but its
   analyst-selected mapping base is an authoritative function seed. Validity is explicit,
   so a raw image mapped at VA 0 is seeded correctly rather than lost to a truthiness test.
3. **PE code exports** (`collectExports`) — consumes the bounds-checked
   `BinaryFile::exports()` model rather than reparsing PE tables. Only mapped local code
   targets become function seeds; forwarders, exported data, and unmapped targets remain
   visible in the Exports panel but are not functions. Aliases collapse to one seed per VA,
   a real export name wins over an ordinal label, and an ordinal-only code export is named
   `#N` instead of being presented as a heuristic `sub_`.
4. **PE32+ exception ranges** (`pdataRanges`) — linker-emitted x64
   `RUNTIME_FUNCTION` begin addresses are authoritative seeds, and their `[begin,end)`
   extents provide stronger size hints than the ordinary gap estimate.
5. **Prologue heuristic scan** (`prologueScan`) — a byte sweep over every executable
   section looking for common x64 prologues (`55 48 8B/89 …`, `48 83 EC …`, home-slot
   stores) or x86 frame prologues (`55 8B EC` / `55 89 E5`). The exact selected `Arch`
   gates these byte-pattern scans; ARM/ARM64/MIPS/PPC/RISC-V raw bytes never receive x86
   prologue guesses. Each match is best-effort and seeds a candidate start.

The seeds then drive a **recursive-descent** pass. A worklist disassembles up to an
8 KiB window per seed (capped at `maxInstrPerFunc` instructions); every direct `CALL` whose
`branchTarget` maps into the image is pushed as a new function start (deduped via a
`visited` set), and scanning of a body stops at the first `isRet` so size estimates stay
tight. A key ordering trick: the **high-confidence seeds** (entry/raw root + code exports + x64
`.pdata`, which are `seeds[0..exportSeeds)`) are inserted into the `starts` set *first*, so the heuristic
prologue flood can never crowd them out when the `maxFunctions` cap is hit.

For a raw load, the synthetic executable `.raw` section spans the complete blob, so the
same worker-owned decoder and background jobs produce strings, discovered functions, and
full-program rows. Recursive calls feed the call graph, while the normal section sweep feeds
the whole-program xref index; these are not separate reduced raw-only views. The executable
section also participates in `RuntimeScan`: a high-entropy blob can receive the existing
clearly low-confidence `High-entropy section .raw` finding, which is evidence only and not a
packer-name classification.

**Size estimation** is gap-based: with starts sorted, each function's size is the distance
to the next start, clamped to `0x4000` bytes; the last function uses the remaining mapped
bytes. This is an estimate (it doesn't follow actual flow), which is why downstream consumers
treat the size as a *window hint* rather than a hard boundary. The two caps
(`maxFunctions`, `maxInstrPerFunc`) exist purely for responsiveness on large images, and the
summary string reports the high-confidence seed, `.pdata`, and total-seed counts plus the
decoder engine. Names are `sub_<HEXADDR>` for anything not matched to an authoritative
name.

### Heuristic name guessing — `FunctionNamer`

Discovery only assigns a *real* name when there's hard evidence (an export or a PDB symbol);
everything else is `sub_<addr>`. `src/Core/FunctionNamer.{h,cpp}` is the **name guesser**
that does what a human RE does on a first pass: it reads each anonymous body and proposes a
meaningful name. It is split into two layers so the interesting part is pure and testable:

- **`GuessFromEvidence(const FuncEvidence&)`** — PURE synthesis: takes a small, engine-free
  `FuncEvidence` struct (instruction/call counts, the de-duped list of called API names, a
  few referenced string literals, and the thunk/entry/ret-only/ret-zero flags) and returns a
  `GuessedName { name, reason, guessed }`. Decision order (first match wins):
  1. **Entry point or explicit raw image base** → `start`, with the reason distinguishing
     a real image entry point from an analyst-selected raw root.
  2. **Thunk/wrapper** whose first real instruction is an unconditional `jmp` to a known
     import → `j_<API>` ("tail-jumps to …").
  3. **Trivial stubs** → `nullsub` (returns immediately, no calls) or `ret_zero` (zeroes the
     accumulator then returns).
  4. **Semantic verb from the called-API set** via `semanticName()` — a large ordered table
     mapping API combinations to a verb. It is ordered **most-specific first** so the
     strongest RE signal wins: e.g. `WriteProcessMemory` + (`VirtualAllocEx` |
     `CreateRemoteThread` | `NtCreateThreadEx` | `QueueUserAPC`) → `inject_code`; lone
     `CreateRemoteThread`/`NtCreateThreadEx` → `inject_thread`; `ReadFile`/`fread` →
     `read_file`; `RegOpenKey`/`RegQueryValue` → `read_registry`; `CryptEncrypt`/`BCryptEncrypt`
     → `encrypt_data`; `send`/`recv` → `net_send`/`net_recv`/`net_transfer`;
     `CreateProcess`/`ShellExecute` → `launch_process`; and a long tail of generic helpers
     (`copy_memory`, `format_string`, `allocate_buffer`, …). Matching is done on
     normalized (lowercased, leading-underscore-stripped) names, with a `has()` substring
     test for forgiving matches and an `eq()` exact test (trailing `A`/`W` tolerated) for
     short, ambiguous names like `send`/`connect`/`bind` so they can't accidentally match
     `SendMessage` or `InternetConnect`.
  5. **Thin single-API wrapper** — exactly one notable API, `callCount <= 2`,
     `instrCount <= 24` → the API snake-cased via `ToSnakeIdentifier` (e.g. `CreateFileW` →
     `create_file`), reason "wrapper around …".
  6. **Distinctive embedded identifier** — `identifierString()` picks the most "name-like"
     referenced string literal (a bare C identifier 4–40 chars, scored to prefer
     camelCase/snake_case symbols and reject dictionary noise), e.g. an embedded
     `__FUNCTION__` or class name → used directly as the function name.

  When nothing is confident, `guessed = false` and the caller keeps `sub_<addr>`.

- **`FunctionNamer::name(...)`** — the disassembler-driven pass that *collects* the evidence.
  It runs in two phases. **Pass 1** decodes every function's body (bounded windows: the
  estimated size, else 2 KiB, hard-capped at 8 KiB / 512 instructions) and detects thunks —
  skipping `endbr64`/`endbr32`/`nop` prologue padding — so that a `call` *to* a thunk later
  resolves to the thunk's API. **Pass 2** walks each body counting calls, resolving each
  call/jmp target to an import name (directly via the caller-supplied `importNameFor`, or
  through an IAT memory slot found by `instrDataRef`), folding calls-to-thunks into their
  API, flagging self-recursion, collecting up to 8 referenced strings via the
  caller-supplied `stringRefFor`, and detecting `ret_only`/`ret_zero` shapes (accumulator
  zeroing recognized as `xor eax,eax` / `mov eax,0` / `rax` variants). Compiler/runtime
  noise APIs (`__security_check_cookie`, `__GSHandlerCheck`, `_RTC_*`, CFG guard helpers,
  …) are filtered by `isNoiseApi` so they never become the basis of a name. Finally it calls
  `GuessFromEvidence` and **de-duplicates**: the first taker keeps the bare name, later
  collisions get `_1`, `_2`, … (existing real names are pre-seeded into the `used` set so a
  guess never shadows an export/PDB/user name).

**How guesses flow to the user.** In `BinaryViewTab::guessFunctionNames`, every guess is
written straight into `Func::name` so it propagates through `symbolFor` everywhere — the
listing, the decompiler, call-site labels, the status bar. The function is flagged
`Func::guessed`, and the basis string is stored in `guessReason_` for tooltips. In the
Functions side panel a guessed name is **tinted amber** (`theme::col::warn()`) with a
tooltip `"guessed name - <reason>"` (only when no annotation/user name overrides it,
`guessShown = f.guessed && dn.empty()`). Crucially, guesses are **recomputed on every
analyze and never persisted**; user renames are saved separately and resolved at higher
priority, so the guesser can never corrupt saved analysis.

### Control-flow graph — `CFG`

`src/Core/CFG.{h,cpp}` builds a per-function `ControlFlowGraph` of `BasicBlock`s.
`BuildCFG(code, size, va, dis, maxInsns = 2000, resolveTable = {})` works in four steps:
(1) **linear decode** of the window via `decodeOne` until `maxInsns`/size; (2) **jump-table
resolution** — for each indirect unconditional `jmp` with a `[...]` memory operand (no
direct `branchTarget`), the optional `JumpTableResolver` callback is asked for the case
target VAs, keeping only those that land on a decoded instruction boundary; (3) **leaders**
— the function start, every branch target, every fallthrough after a block-ender, and every
switch case become block leaders; (4) **blocks + edges** — blocks span `[leader, nextLeader)`
up to a terminator, and edges are linked from each terminator: fallthrough for straight-line
code, branch-target + fallthrough for conditionals, branch-target only for unconditional
`jmp`, no successors for returns, and for a resolved switch every `caseTarget` becomes a
successor (block flagged `isSwitch`, `caseTargets` populated, no fallthrough). A
block-ender is `isBranch && !isCall` (calls return, so they don't end a block); returns are
detected via the decoder's `isRet` flag *and* x86 mnemonic fallbacks, so non-x86 returns
(`blr`, `jr $ra`, `bx lr`) are tagged `isReturn` and don't get a spurious fallthrough edge.
The Binary View tab supplies the jump-table callback (`resolveJumpTable`, lambda `jt`) and
reuses `BuildCFG` for the on-screen **Graph** view, the **Pseudocode** decompiler pipeline,
and the live (debugged) CFG.

### Cross-references — `XrefIndex` and `instrDataRef`

`src/Core/XrefIndex.{h,cpp}` is a whole-program `target -> sources` map.
`BuildXrefInto(idx, data, size, base, dis)` does a single `decodeOne` sweep of a code
region and, for each instruction, records two kinds of edge: a relative branch/call records
its `branchTarget`, and a memory operand records the data address it references (computed by
`instrDataRef`, skipping the case where it equals the branch target). `FinalizeXrefIndex`
sorts and de-dups each source list. This turns the old O(n)-per-query search into an O(1)
`sources(target)` lookup and powers the inline **Xrefs panel** ("who references this
function/address?"). The tab rebuilds it lazily (`buildXrefIndex`), cached by a content
signature (image hash ^ patch count ^ function count ^ arch ^ engine) so it only rebuilds
when code or analysis actually changes.

`src/Tabs/DataRef.h`'s **`instrDataRef(const Instruction&)`** is the shared helper that
extracts the data address an instruction references. It parses *only* the text inside the
first `[...]` of the operand string, so a stored immediate like `mov [rbp-4], 0x140002000`
is never mistaken for a reference. It handles both decoder conventions: Capstone keeps
`rip` symbolic (`[rip + 0x..]` → `next_ip + disp`), while Zydis resolves to an absolute
`[0x..]` (optionally with a `fs:`/`ds:` segment prefix). Register-based memory
(`[rbp-4]`, `[rax*8+disp]`) is dynamic and returns 0. This one pure function is reused by
`FunctionNamer` (IAT/string resolution) and `XrefIndex` (data edges), and is unit-tested in
isolation.

There is also an **on-demand modal xref search** (`startXrefSearch`, the "Find references"
context-menu items and the `X` key on the cursor). Unlike the cached index, this sweeps the
*currently relevant* code — the live debuggee's committed executable regions when attached
(masking the debugger's `0xCC` breakpoints, capped at 64 MiB and 3000 hits, decoded at the
debuggee's bitness), otherwise the loaded image's executable sections — and lists clickable
hits with a decoded mnemonic and the enclosing `symbolFor` name.

### Symbols — `SymbolResolver` and the resolution chain

`src/Core/SymbolResolver.{h,cpp}` is a thin DbgHelp wrapper. `useLive(hProcess)` binds to a
running debuggee, `useBinary(path, imageBase)` opens a static file session (using a fake
process handle `0x1`), and `ensureModule(base, size, path)` registers a live module so its
symbols can load. `resolve(addr, name, disp)` returns an **undecorated** symbol name plus
displacement; `addressOf(name, addr)` is the reverse lookup used by the "go to name" box. It
is configured for graceful, non-interactive operation: `SYMOPT_UNDNAME |
SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS`, **no symbol server**
(local PDBs + exports only — no flaky network), and PDBs load lazily on first query.
`resolve` returning `false` is the normal degraded path, letting callers fall back to their
own naming.

The tab's **`symbolFor(ctx, addr)`** ties everything together as a priority chain (with a
per-session cache hard-reset at 100k entries and dropped when attach ↔ static changes):
**(1) user rename** for the exact address (always wins) → **(2) IAT import name** →
**(3) live mode**: DbgHelp PDB/export name (`module.symbol[+off]`), then the app's own PE
export parser, then `module+0xOFF` → **(4) static mode**: DbgHelp on the file, then the
analyzed-functions fallback (`funcContaining`, which includes the `FunctionNamer` guesses)
as `name[+off]`. This is why a guessed verb name shows up consistently across the whole UI.

### Capability detection — `TechScan`

`src/Core/TechScan.{h,cpp}`'s `ScanCapabilities(bin)` returns a confidence-sorted list of
`Capability { name, category, confidence, address, detail }` from three real evidence
sources, and returns an **empty list for a clean binary (no fabricated results)**:

1. **Imported-API grouping** — `kApiRules` defines technique groups (anti-debug, network,
   crypto, injection, dynamic-API resolution, process spawn) as lowercase substrings matched
   against import names (so `A`/`W`/`Ex`/`Nt`/`Zw` variants hit). Confidence scales with the
   number of distinct matching imports (`base + 0.07 * (hits-1)`, capped at 0.96); the detail
   lists the actual imports and the address is a representative IAT slot.
2. **Packer/protector section names** — `kPackers` matches signature sections (`UPX0/1/2`,
   `.vmp0/1`, `.themida`, `.aspack`, `.enigma1/2`, `.mpress1/2`, NsPack, Petite, …) →
   "<name> packer" at 0.80 confidence with an "image may be packed/protected" note.
3. **Distinctive byte patterns** — masked byte-pattern search over `bin.bytes()` for a direct
   syscall stub (`mov r10,rcx; mov eax,imm32; syscall`, "ntdll-less syscall", evasion 0.78),
   the AES Rijndael S-box (0.90), SHA-256 H0/H1 init constants (0.85), and MD5 A/B init
   constants (0.80). The pattern matcher guards `mask.size() >= pat.size()` to avoid the
   `vector<bool>` indexing UB of a mis-sized rule.

The **Binary Tech tab** (`src/Tabs/BinaryTechTab.cpp`) renders this: a "Run Tech Scan"
button, a category filter, a left list (name / category / colour-coded confidence — green
>85%, amber >65%, salmon below) and a right detail pane showing the evidence and a small
disassembly or hex preview at the representative address, with "View in disassembly" /
double-click routing to the Binary View via `ctx.gotoAddress`. Confidence colours and the
explicit "no notable capabilities detected" empty state make the heuristic nature legible.

#### Limitations & notes

- Function discovery is best-effort: prologue patterns are limited to **x86/x64** and are
  enabled only for the exact selected architecture; sizes are
  **gap estimates** (not flow-accurate), and the analyze/per-function caps trade completeness
  for responsiveness on huge images.
- All `FunctionNamer` output is **heuristic and labelled** (amber tint + reason tooltip),
  **recomputed each analyze, and never persisted** — exports, PDB symbols, and user renames
  always take priority.
- CFG jump-table recovery only resolves indirect jumps the supplied resolver can read and
  whose targets land on decoded instruction boundaries; unresolved indirect control flow is
  simply not edged.
- `instrDataRef` resolves only static, non-register memory references; register-relative and
  computed addresses are intentionally reported as none.
- `SymbolResolver` uses **local PDBs + exports only** (no symbol server); rich names appear
  only when a `.pdb` is present beside the file or cached on the system.
- `TechScan` is signature/heuristic detection (imports, section names, fixed byte patterns):
  it can miss obfuscated capabilities and is not a substitute for dynamic analysis; it
  deliberately reports nothing for a trivial binary rather than inventing findings.
