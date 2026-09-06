## 04. Static Code Analysis — Discovery, Naming, CFG, Xrefs, Symbols, Tech Scan

This chapter covers DisasmStudio's *static* analysis layer: the set of `Core/` modules
that turn a freshly-loaded image into something navigable — function boundaries, a
control-flow graph, a whole-program cross-reference index, symbol names (from PDBs,
PE/ELF symbols, and heuristic guessing), and a capability ("tech") scan. All of these are
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
human-readable `lastSummary()` string. It combines six independent seed sources and then
expands them by recursive descent:

1. **Entry point** — `bin.hasEntryPoint()` gates `bin.entryPointVA()`, so structured and
   explicitly selected raw entries use the same authoritative root. The separate validity
   bit makes VA/RVA 0 a real entry rather than a false “missing” value.
2. **Legacy raw fallback** — only a raw image with no explicit entry seeds its first
   executable `.raw` byte (normally the mapping base). An edited or recovered firmware entry
   therefore replaces, rather than competes with, the historical fallback.
3. **Mapped PE/ELF function symbols** (`collectExports`) — consumes the bounds-checked
   `BinaryFile::exports()` model rather than reparsing PE tables. Only mapped local code
   targets become function seeds; forwarders, exported data, and unmapped targets remain
   visible in the Exports / Symbols panel but are not functions. ELF function and GNU IFUNC
   symbols participate, with non-zero valid symbol sizes retained as exact range hints. Aliases collapse to one seed per VA,
   a real export name wins over an ordinal label, and an ordinal-only code export is named
   `#N` instead of being presented as a heuristic `sub_`.
4. **Named analysis landmarks** — each validated `AnalysisLandmark` is an authoritative
   seed and symbol. Open as Raw converts only detector landmarks with `code == true`, keeping
   stable reset/boot/PCI-entry names and evidence; structural `_FVH`, PCIR, image-header,
   descriptor, and BIOS-region landmarks are not fabricated functions.
5. **PE32+ exception ranges** (`pdataRanges`) — linker-emitted x64
   `RUNTIME_FUNCTION` begin addresses are authoritative seeds, and their `[begin,end)`
   extents provide authoritative ownership hints.
6. **Architecture-specific prologue scan** (`prologueScan`) — a byte sweep over every executable
   section looking for common x64 prologues (`55 48 8B/89 …`, `48 83 EC …`, home-slot
   stores), x86 frame prologues (`55 8B EC` / `55 89 E5`), A32/Thumb frame pushes, and A64
   frame setup including PACIASP-prefixed functions. The exact selected `Arch` gates every
   pattern; `Arch::X86_16` and unrelated ISAs never receive x86 or ARM guesses. Before ARM
   prologue seeding, a bounded literal-reference pass records true PC-relative A32/Thumb/A64
   literal spans (not ordinary base-register loads). A candidate inside one is rejected.

The seeds then drive a **recursive-descent** pass. A worklist disassembles up to an
8 KiB window per seed (capped at `maxInstrPerFunc` instructions); every direct `CALL` whose
`branchTarget` maps into executable backed bytes and is outside a known literal span is
pushed as a new function start (deduped via a
`visited` set), and scanning of a body stops at the first `isRet` so size estimates stay
tight. Thumb low-bit targets are canonicalized. A `BLX` edge that changes between the fixed
A32 and Thumb decoder modes is reported but not followed through the wrong decoder. A key
ordering trick: the **high-confidence seeds** (entry/raw fallback + symbols +
named landmarks + x64 `.pdata`, which are `seeds[0..exportSeeds)`) are inserted into the
`starts` set *first*, so the heuristic prologue flood can never crowd them out when the
`maxFunctions` cap is hit.

For a raw load, the synthetic executable `.raw` section spans the complete blob, so the
same worker-owned decoder and background jobs produce strings, discovered functions, and
full-program rows. The selected entry and named roots are validated against the mapping
before load. `Arch::X86_16` uses either real-mode backend for recursive calls, CFG, and xrefs,
without enabling x86-32/x64 prologue or ABI assumptions. Recursive calls feed the call graph,
while the normal section sweep feeds
the whole-program xref index; these are not separate reduced raw-only views. The executable
section also participates in `RuntimeScan`: a high-entropy blob can receive the existing
clearly low-confidence `High-entropy section .raw` finding, which is evidence only and not a
packer-name classification.

**Function ownership** first honors a valid non-zero ELF symbol or x64 `.pdata` range,
then performs a bounded second recursive pass from every complete start. It assigns reached
basic-block chunks without crossing another trusted entry, distinguishes calls from tail
branches, owns architectural delay slots, and can retain non-contiguous `FunctionChunk`
ranges. The legacy `address`/`size` pair remains as a compatible envelope; consumers that
need exact membership use chunks. Budget-limited results set `ownershipTruncated`, and
authoritative exit-family evidence can propagate `noreturn`. Names are `sub_<HEXADDR>` for
anything not matched to an authoritative name.

### Recursive code/data classification — `CodeDataClassifier`

`src/Core/CodeDataClassifier.{h,cpp}` runs after initial function discovery on the
background worker with its own decoder. It recursively traverses exact decoded successors
from authoritative function starts; undecodable gaps are never searched by bytewise
resynchronization. The pass combines that reached-code proof with bounded scanner strings,
instruction data references, A32/Thumb/A64 PC-relative literals, indirect-branch
absolute/RVA/relative jump tables, aligned vtable/code-pointer runs, relocation-backed
callback pointers, decoder-confirmed `endbr32`/`endbr64` entries, and ISA-specific padding.

Strong indirect entries are returned as `CodeDataFunctionSeed` records with their evidence.
`AnalysisJobs::AnalyzeFunctionsNamed` supplies novel seeds to one additional bounded
`FunctionAnalyzer` run, then rebuilds the map from the expanded function set. This fixed
point recovers callback/vtable/CET-only functions without repeatedly analyzing a hostile
image or promoting every plausible pointer to a function.

The output is a sorted, non-overlapping partition of every mapped executable byte.
`CodeDataSpan` distinguishes `Code`, `String`, `LiteralPool`, `JumpTable`, `PointerTable`,
`Padding`, `Data`, and `Unknown`, and carries an element width, confidence, and concrete
evidence. `Unknown` is deliberate: bytes remain lazily inspectable as possible code when
the analyzer cannot prove either side. Instruction, block, table-entry, pointer-scan,
function-seed, and claim limits plus cancellation make the pass finite. Each
production map is stamped with `BinaryFile::imageRevision()` so a patch or reload cannot
apply stale boundaries to a newer image.

### Heuristic name guessing — `FunctionNamer`

Discovery only assigns a *real* name when there's hard evidence (an export or a PDB symbol);
everything else is `sub_<addr>`. `src/Core/FunctionNamer.{h,cpp}` is the **name guesser**
that does what a human RE does on a first pass: it reads each anonymous body and proposes a
meaningful name. It is split into two layers so the interesting part is pure and testable:

- **`GuessFromEvidence(const FuncEvidence&)`** — PURE synthesis: takes a small, engine-free
  `FuncEvidence` struct (instruction/call counts, the de-duped list of called API names, a
  few referenced string literals, and the thunk/entry/ret-only/ret-zero flags) and returns a
  `GuessedName { name, reason, guessed }`. Decision order (first match wins):
  1. **Entry point or legacy raw fallback** → `start`; firmware landmark names are already
     authoritative and therefore never pass through this guesser.
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
resolution** — for an indirect x86 `jmp` with a `[...]` memory operand or a Thumb `TBB`/`TBH`,
the optional `JumpTableResolver` callback is asked for the case target VAs. The Thumb path
uses a nearby `CMP` bound, the architectural aligned `PC+4` table base, halfword-scaled
destinations, and overflow-checked arithmetic. Only targets landing on decoded instruction
boundaries survive; (3) **leaders**
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

`Core/Demangle` makes undecoration consistent beyond PDB-backed DbgHelp results. MSVC
spellings use `UnDecorateSymbolName` while holding the same process-global
`DbgHelpMutex`; GCC/Clang/ELF spellings use a bounded in-tree Itanium ABI parser with
nested names, templates/substitutions, operators, constructors/destructors, qualifiers,
literals, special names, and clone/version suffixes. A capped thread-safe cache serves
the render and analysis threads. Compact qualified labels feed discovery, listings,
xrefs, decompilation, source export, and Cortex; Imports/Exports show the full signature
and can filter/copy either it or the exact raw linker spelling. Raw names remain
authoritative for reverse lookup, forwarders, DLL invocation, scans, and reconstruction.

The tab's **`symbolFor(ctx, addr)`** ties everything together as a priority chain (with a
per-session cache hard-reset at 100k entries and dropped when attach ↔ static changes):
**(1) user rename** for the exact address (always wins) → **(2) IAT import name** →
**(3) live mode**: DbgHelp PDB/export name (`module.symbol[+off]`), then the app's own PE
export parser, then `module+0xOFF` → **(4) static mode**: DbgHelp on the file, then the
analyzed-functions fallback (`funcContaining`, which includes the `FunctionNamer` guesses)
as `name[+off]`. This is why a guessed verb name shows up consistently across the whole UI.

`Core/ApiDatabase.h` complements names with a deliberately bounded, offline Windows API
knowledge set. It supplies parameter names/prototype shapes for high-value file, memory,
process, registry, socket, UI, and wait APIs, plus symbolic access masks, page protections,
allocation types, creation dispositions, registry rights, and socket enums. `FuncAnnotate`
applies it only after a call target is resolved and an argument value is recovered, and its
evidence names the database; unknown APIs/values stay numeric instead of being guessed.

### Capability detection — `TechScan`

`src/Core/TechScan.{h,cpp}`'s `ScanCapabilities(bin)` returns a confidence-sorted list of
`Capability { name, category, confidence, address, detail }` from three real evidence
sources, and returns an **empty list for a clean binary (no fabricated results)**:

1. **Imported-API grouping** — most technique groups use bounded normalized import-name rules.
   Network evidence is stricter: `Core/NetworkApiCatalog` requires an exact normalized DLL+API
   pair for Winsock, DNS, WinHTTP, WinINet, or URLMon, so similarly named UI/IPC APIs such as
   `USER32!SendMessageW` and `KERNEL32!ConnectNamedPipe` do not become network capability hits.
   Confidence scales with distinct matching imports; detail retains the exact evidence and a
   representative IAT slot.
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

### Automatic crackme network triage

`src/Core/CrackmeTriage.{h,cpp}` is the bounded offline pass behind Binary View's **Triage**
workspace. It scans ASCII and UTF-16LE across the complete file byte stream—including unmapped
and overlay bytes—extracts endpoints, routes, reply markers, authentication/license/validation
artifacts, and combines them with exact catalogued network imports. Independent validity bits
preserve both a legitimate mapped VA of zero and a file-only offset of zero.

The correlation layer consumes function ownership, xrefs, typed API-call observations, decision
evidence, and at most a depth-2 bounded call neighborhood. It publishes immutable endpoint trails
using the analyst-facing stages **Endpoint → Connect → Request → Reply → Decision**, with per-stage
evidence, confidence, honesty labels, completeness/truncation fields, and exact source locations.
Low-level DNS resolve/write/read stages contribute to those higher-level trail stages rather than
being exposed as the workflow. The load-time `AnalysisService` runs `K_CrackmeTriage` after its
declared function/xref/call-graph dependencies, and the document cache adopts the report only for
the current image revision and analysis epoch.

`NetworkApiCatalog` also carries an exact documented return contract for every recognized API:
return type, success rule, failure sentinel, asynchronous-pending semantics, EOF meaning, and
typed output parameters such as payload buffers, byte counts, headers, and handles. Candidate-only
`FuncAnnotate` preserves the first bounded local use of the ABI return register (ignored, checked,
branching, stored, propagated, consumed, or returned) plus exact call/use/decision/target VAs.
These are separate evidence layers: a `WinHttpReadData` BOOL check proves API-status handling, not
that the bytes in its output buffer were parsed or accepted. Copied values and output-buffer flow
beyond the bounded first use remain explicitly unproven.

The result is evidence ranking, not runtime proof. Static proximity and a bounded call graph can
miss encoded/dynamic endpoints, deeper dispatch, or transformed arguments. **Automatic static
triage does not run this target or contact detected endpoints.**

### Automatic Authorization Trail

`Core/AuthorizationTrail` turns the existing network, persistence, xref, call-graph, CFG, and
`FuncAnnotate` facts into one bounded, immutable authorization report. The `AnalysisService`
adapter considers small x86/x64 functions only when return analysis yields a typed boolean-like
contract. It then counts retained callsites, unique callers, proven branch consumers, unique
branching callers, and guarded operations separately. Those counts drive a deterministic rank;
they are investigation priority, not proof that the highest-fan-out function grants access. A
candidate is not labelled global or secondary when the relevant caller/control-flow scope is
incomplete.

Each retained use records the exact callsite and decoded continuation, AL/EAX/RAX result width,
first local return use, comparison, conditional branch, and—only when the `test`/`cmp` + `jcc`
shape and boolean contract agree—the true and false destinations. This is the evidence behind the
annotation that the return selects logical true/false paths. The UI uses authorization
permitted/locked wording only after separate authorization-source linkage is proved; a nearby branch
or a semantic function name cannot produce that statement by itself. Selecting a stage, predicate,
use, or source retains direct code/xref navigation so string evidence such as an activation route
can be followed through its containing function to the decision instead of being treated as a
standalone clue.

Field flow uses exact identity rather than a displacement search. `FuncAnnotate` publishes
formal-parameter-rooted accesses and `Core/AuthorizationFieldAlias` keys a stable field by the
proved object root set, signed displacement, and width. Roots merge across functions only through
an exact direct-call target and exact unchanged argument binding. Adjusted interior pointers,
ambiguous/cyclic/conflicting bindings, inexact accesses, missing widths, and equal displacements
on unrelated objects remain rejected or separate. The trail can therefore show where a field such
as `[object+0x138]` is written, read, and used by a predicate without implying that every `+0x138`
operand is the same state.

Secondary-gate detection is likewise control-flow constrained. A downstream predicate is labelled
secondary only when it is reached on the upstream predicate's proved permitted arm and its own
result is required for a retained operation. When a global predicate reaches branding/UI paths but
one or more protected operations still require a secondary predicate, the report emits the explicit
“global gate alone is not sufficient” warning and links both gates and the affected operations.

The presentation orders evidence as **Input → Format validation → Remote request → Entitlement
parsing → Crypto verification → State persistence → Global predicate → Feature predicate →
Protected operation**. This is a conceptual stage inventory, not a claim that every displayed row
belongs to one connected input-to-operation path: each stage is independently evidenced, and only
explicit data/control-flow identities establish an edge. Stages are allowed to be absent; the report
never fills a gap merely because the surrounding stages exist. `VerificationApiCatalog` recognizes only exact DLL/symbol contracts
for selected Windows CNG/CryptoAPI/trust and known OpenSSL/libsodium verifier functions. Import or
call presence means a crypto capability; “signature verified” requires reply-data lineage into the
documented verifier argument plus its result controlling a branch.

Four conclusions remain independent: **locally valid format**, **server accepted**, **signature
verified**, and **feature permitted**. Each is `unknown`, `candidate`, or `supported` from its own
evidence; transport success is not server acceptance, verifier presence is not a successful
verification, and a cosmetic “Pro” state is not permission for a protected operation.
`feature permitted` reaches supported only when an authorization-linked Global/Secondary predicate's
exact branch-exclusive guard controls the exact protected operation; a co-located operation or
unlinked predicate guard remains a candidate. Machine binding, an embedded expected key, and private
signing material are additional scoped facts.
Negative conclusions fail closed: “no embedded expected key” requires the complete retained
local-input equality-comparison scope, while “no private signing material” is limited to a complete
visible-string search for the recognized private-key marker. If those scopes are incomplete the
answer stays unknown. In particular, an endpoint and public verification material cannot be used
to recover or manufacture a real server-signed key.

`Core/AuthorizationPatchAdvisor` is deliberately separate from detection and produces **inert**
advice only. Its narrow eligible shape is an x86/x64 centralized boolean function replaced by
`mov eax,0/1; ret` (preserving a proved x86 `ret imm16` pop when applicable). It requires an
executable destination, complete public-entry and return-style coverage, a supported result width,
authorization-state linkage, no alternate interior entry, complete side-effect analysis, and
sufficient proof confidence. Unknowns are refusals. String/heap cleanup, other side effects,
stack-cookie/security epilogues, non-executable targets, and HTTP-transport-only candidates are
explicit hard refusals. The byte plans include the exact original and replacement span but do not
modify the image, project, or debuggee; applying one remains a separate analyst action.

### Focused raw-firmware analysis verification

`functionanalyzer_test` proves non-base explicit entries, atomic named-landmark validation,
stable firmware names, and a legitimate entry VA 0 all become roots. The pure
`firmware_sniffer_test` covers detector bounds/confidence/mappings/jump chains and
code-vs-structural landmarks; `xref_arch_test` links both native backends and proves their
x86-16 rel16 targets feed `XrefIndex` identically.

#### Limitations & notes

- Function discovery is best-effort: prologue patterns are limited to **x86-32/x64** (not x86-16) and are
  enabled only for the exact selected architecture. Boundaries use bounded recursive basic-block
  ownership with explicit non-contiguous chunks, trusted-entry barriers, tail exits, delay slots,
  and noreturn propagation; `ownershipTruncated` makes a budget-limited result explicit.
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
- Authorization Trail is bounded and x86/x64-only at its typed predicate/data-flow layer. Indirect
  dispatch, unproved wrapper arguments, custom crypto, encoded state, and truncated CFG/call-graph
  scopes remain missing or explicitly partial; fan-out rank is never an authorization verdict.
