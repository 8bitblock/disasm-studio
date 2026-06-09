## 07. The Binary View Workspace (Centerpiece)

The **Binary View** tab is the heart of DisasmStudio: it is where static analysis and live debugging meet. Everything else in the app (Projects, Sig Scanner, Memory Tools, Tech, Diff) ultimately routes the user here to "go look at this address." It lives in `src/Tabs/BinaryViewTab.{h,cpp}` — a single ~5000-line class (`ds::BinaryViewTab`) that owns six switchable **main views**, a three-tab **side panel**, thirteen **lower sub-tabs**, a **debug toolbar**, and a stack of modal popups. This chapter walks through every one of them and the machinery underneath.

The class implements `ITab`; `render(AppContext&)` is the per-frame entry point. `AppContext` carries the shared `binary` (`BinaryFile`), `debug` (`Debugger`), `disasm` (`IDisassembler`), and `project` (`ProjectState`). The tab keeps its own editing state (comments, renames, bookmarks, breakpoints, the navigation history, caches) and mirrors annotations to/from `ctx.project` each frame.

### Top control row & main-view selector

The header row offers a **goto box** (`##goto`, accepts `0x...` hex or a symbol name — hex is parsed, otherwise `lookupSymbol` resolves the name), **Back/Forward** buttons (`<` / `>`, disabled when history is exhausted), a **Goto sym** button (opens the symbol picker), a **Find text** button (opens the disassembly text search), and the radio-button **view selector**: Assembly (0), Pseudocode (1), Hex (2), Graph CFG (3), Call Graph (5), and Live Assembly (4, enabled only while attached). `mainView_` holds the selection; `render()` dispatches to `renderAssembly` / `renderPseudocode` / `renderHex` / `renderGraph` / `renderLiveAssembly` / `renderCallGraph`. The layout below is a left **main-view child**, a right **side panel** (`sideW = 320`), and a **lower-tabs child** (`lowerH = 200`).

### Main view: Assembly (full-program listing)

`renderAssembly` is the dispatcher; by default `asmFullProgram_` is true, so `renderAssemblyFull` shows **the entire program** as one scrollable listing. The key trick (`buildFullListing`) is to **linear-sweep every executable section once** and cache only a row index — `std::vector<ListRow>` where each `ListRow` is `{addr, divider}` — rather than holding decoded instructions. Function starts (from `functions_`) emit a `divider` row that renders as a `sub_<addr>:` (or symbol) header (`renderAsmFuncHeader`). The sweep is capped at `kCap = 800000` instructions to stay responsive on huge images; the header shows `"(capped)"` when hit. The listing signature mixes the content hash, function count, arch, and engine, so it rebuilds only when one of those changes; a **Rebuild listing** button forces it.

Rendering uses an `ImGuiListClipper` over `listRows_`, re-decoding each *visible* row on the fly with `ctx.disasm->decodeOne` — so memory stays small even at 800k instructions. Undecodable bytes fall back to a synthetic `db 0x..` row. Each instruction row (`renderAsmRow`) has five columns: a **breakpoint gutter** (`*` toggles a SW breakpoint), a **flow gutter** (records geometry for branch arrows), the **address** (prefixed `> ` at RIP, tinted green at RIP / magenta at a HW breakpoint), the **raw bytes**, and the **instruction** (mnemonic color-coded: blue calls, amber branches). The RIP row and the selected/cursor row get a slow sinusoidal pulse (`slowPulse`).

**Branch arrows** (`drawAsmArrows`, toggled by "Arrows"/`showJumpArrows_`) are painted into the flow gutter *after* the table using a foreground draw list. Per-row Y centers are collected during render into `asmFlow_`; the renderer assigns each branch to a horizontal **lane** (greedy non-overlap, up to 7 lanes in the 36px gutter), colors backward jumps amber, forward blue, and the cursor's own arrows green, and draws stub triangles for targets that scrolled off-screen.

A non-default **windowed** mode (`renderAssemblyWindow`) shows ~256 instructions around the cursor. To avoid garbage "context" rows above the focus, `alignBinaryStart` trial-decodes from a few bytes back and prefers a *known* analyzed function boundary (`anchor`) before falling back to the earliest offset that lands exactly on the target — important on variable-length x86.

### Inline annotations (the "explain it to me" layer)

Three header toggles enrich each row, all best-effort:

- **Str** (`showStringComments_`): if the instruction references data (`instrDataRef` — RIP-relative or absolute memory operand), the row shows either the resolved import (`importMap_` → `dll.func`, plus a one-line **API purpose** from `apiPurpose`, e.g. *"allocate memory (often RWX)"*), or the **string literal** at that address (`resolveString`, ASCII/UTF-16).
- **Explain** (`showHints_`): a plain-language gloss of what the instruction *does* (`instrGloss`) — `mov` → `dst = src`, `sub rsp, X` → `alloc X of stack`, `test x,x` → `is x zero?`, conditional jumps → `if >= (signed) -> jump`, `rep movs` → `string/block operation`, `syscall` → `kernel system call`. Suppressed if a string/API comment already explains the line.
- A built-in **anti-analysis flag**: `rdtsc`, `cpuid`, `sidt`, `in`/`out`, `int 0x2d`, etc. get a red `; anti-analysis?` note.

User **comments** (`comments_`, green) render after these. All three are clearly secondary text; the heuristic ones are not persisted.

### Main view: Pseudocode (decompiler)

`renderPseudocode` decompiles the **whole function enclosing the cursor** (found via `funcContaining`, a binary search over the lazily-sorted `funcIndex_`). It builds a CFG (`BuildCFG`, with `resolveJumpTable` recovering switch tables), runs the structured `Decompile` pass (dominator/post-dominator structuring → if/else + while/do-while, goto fallback), and feeds it `nameFor` (= `symbolFor`), `dataRefFor` (= `dataRefToken`, resolving constants to quoted strings / import names / globals), and a heuristic `signature` (`guessSignature`). The output is cached by `decompVA_` and prefixed with a banner noting the signature is heuristic with no full type recovery. It is shown read-only (selectable/copyable). A **Refresh** button invalidates the cache.

### Main view: Hex, Graph (CFG), Call Graph

**Hex** (`renderHex`) is a simple read-only 16-byte-per-row dump (offset, hex, ASCII) starting at the cursor, capped at 64 rows.

**Graph / CFG** (`renderGraph`) builds the cursor function's CFG and lays out blocks in a column-per-depth grid with cubic-Bezier edges (green = taken, grey = fallthrough, blue = jump), a colored legend, the RIP block glowing green, and the cursor block outlined. It is **interactive**: drag empty space to pan, drag a block to move it (offsets stored in `cfgDrag_`, "Reset layout" clears them), and double-click a block to re-root the graph there. Each instruction line is formatted like the listing (`+offset mnem ops -> name ; "string"`).

**Call Graph** (`renderCallGraph`) shows, in three columns, the **callers**, the current function, and the **callees** around the cursor function. Edges come from `buildCallGraph`, which sweeps each function once and records direct `call`s whose target is another known function (cached by content-hash + function count). Clicking any node navigates there.

### Main view: Live Assembly (the debugger view)

`renderLiveAssembly` is the live counterpart, available only while attached. It draws a **status pill** (RUNNING/PAUSED/ATTACHED with a colored dot), PID/TID, and the **debug toolbar** — **Continue/Pause** (F5), **Into** (F11), **Over** (F10), **Out** (Shift+F11), all wired to `ctx.debug`. A second header row adds Back/Forward, a **Follow RIP** checkbox, a **Sync** button (jump to and re-follow RIP), a live **goto box**, **Search** (Ctrl+F → live memory search), a **Disasm/Pseudo** mode switch, and display toggles (Regs box, Arrows, reg Hints, Str, Names).

The listing itself (`renderLiveListing`) reads the on-screen window straight from process memory (`readMemoryMasked`, which masks the debugger's own `0xCC` breakpoint bytes so real instructions show), decodes with `liveDecoder` (a decoder matched to the **debuggee's bitness**, so a 32-bit WOW64 target under an x64 host decodes correctly), and **caches** the decode + address index (`liveIdxOf_`) + divider set. The cache signature folds in the window start, RIP (catches stepping and self-modifying code), `liveGen_` (bumped on any live write/patch/re-analyze/detach), the function count, and the PID — so it is rebuilt only when something actually changed, not every frame (this was a deliberate fix for runaway working-set growth while attached). Dividers come from in-window call targets, analyzed functions (ASLR-shifted), and the containing module's parsed **exports** (`parseExports`).

Extra live-only annotations on the RIP row: **register hints** (`regHints`, e.g. `rax=0x..`), and for a conditional branch a flag-evaluated verdict — `-> will jump` / `-> falls through` (`evalCondBranch`). Branch arrows, hover-token highlighting, string comments (with one pointer-hop dereference for `char*` slots), and user comments all work as in the static view. Keyboard: **Enter** follows the cursor's target, **Backspace** navigates back.

A **register box** (`renderRegisterBox`, right side, toggle "Regs") shows GP registers (e-names for 32-bit targets), changed values tinted, decoded flags, and a 12-slot stack preview. Every register and stack value is **clickable to follow** and right-click-to-copy, and while paused each is annotated by `describePointer` (does it point at a string? a symbol? a `char*`?) — memoized per stop via a hash of the whole register snapshot so the symbol lookups don't re-run every frame.

The live **Pseudocode** mode (`renderLivePseudocode`) runs the same structured `Decompile` pipeline over the live function, decoded at the debuggee's bitness.

### Symbol resolution & name overrides (`symbolFor`)

`symbolFor` is the single resolver used *everywhere* a name appears. Its precedence is deliberate: (1) a **user rename** (`names_`) for the exact address always wins; (2) an **IAT slot** resolves to its import (`importMap_`); then, when attached, (3) DbgHelp/PDB names, (4) the in-house export-table parser, (5) `module+0x..`; or, statically, DbgHelp on the file then the **analyzed-function** fallback (`name+0x..`). Results are cached in `symCache_` (bounded at 100k, cleared on context change). Because guessed function names live in `Func::name`, they flow through `symbolFor` too — but `names_` overrides them.

### The side panel: Bookmarks / Functions / Strings + byte search

At the top sits a **Byte Pattern Search** box (hex, no wildcards) with a **Live (process memory)** toggle; hits list below and into the **Results** lower tab, click-to-navigate (live hits open the live view).

- **Bookmarks**: add "+ here", click to go, right-click to rename/remove; persisted as file VAs.
- **Functions**: **Analyze** runs `FunctionAnalyzer` (entry/exports/call-targets/prologues) into `functions_`; a **Guess** toggle runs `FunctionNamer` (`guessFunctionNames`) to heuristically name anonymous `sub_` functions (`read_file`, `j_CreateFileW`, `start`, …). Guessed names render in **amber** (when no user rename overrides) with a tooltip giving the *basis* for the guess (`guessReason_`). The list is filtered into `fnVisible_` and clipper-rendered. Guesses are recomputed each analyze and never persisted.
- **Strings** (`scanStrings`): ASCII/UTF-8 + UTF-16LE runs (≥4 chars), file-mode or **Live** (scans loaded module images so addresses stay stable across rescans; auto-flips to Live + scans once on first attach). Click to navigate, right-click → **Find references (where used)**.

### Lower sub-tabs

`renderLowerTabs` hosts thirteen tabs: **Breakpoints** (software 0xCC with editable conditions, including a "pending" list for not-yet-armed ones, plus hardware DR0–DR3); **Registers** (full register + 24-slot stack view, double-click to **edit** values into the debuggee while paused, pointer annotations); **Watch** (pinned expressions — registers, `[mem]`, constants — evaluated each stop via the shared `EvalExpression`/`Cond.h` evaluator, persisted in `ctx.project.watches`); **Threads** (list, set-active, follow RIP, freeze/thaw); **Call Stack** (heuristic walk in `computeCallStack` — scans the stack for qwords landing just past a `call`); **Stack** (annotated live dump, RBP slot and frame boundaries highlighted, each value resolved to a symbol/string with a "follow" button); **Functions** (table of analyzed functions + a debuggee **modules** list while attached); **Xrefs**; **Notes** (free-text, persisted); **Results** (byte-search hits); **Patches**; **Imports** (IAT VA / module / function, filterable, right-click → find call sites); and **Hotkeys** (a complete printed cheat-sheet).

### Cross-references

Two complementary paths. **Targeted xref search** (`startXrefSearch`, triggered by the `X` key or a right-click "Find references…") sweeps executable code (file sections, or the debuggee's exec regions when attached) with `decodeOne` and `instrRefsAddr` (matches branch/call targets, memory data refs, *and* absolute immediates — the latter catches x86-32 `push offset str`), capped at 3000 hits, results shown in a popup. The **Xrefs lower tab** (`renderXrefsTab`) instead uses a precomputed whole-program `XrefIndex` (`buildXrefIndex`, cached by a content signature) for *instant* "who references the cursor / its enclosing function" lookups with no per-query sweep.

### Navigation & history

`navigateTo` moves the cursor and pushes a `NavEntry{va, live}` onto `navHist_`, dropping any forward branch. Crucially each entry remembers whether it was a **live** (runtime VA) or **static** (file VA) location, so `navBack`/`navForward` restore the correct *view* and never feed a runtime VA into a file-VA view. `gotoStatic` is the entry used by side-panel lists: it records history and, in the live view, shifts the file VA to the runtime VA. History is driven from the toolbar `<`/`>`, **mouse back/forward buttons**, and **Alt+Left/Alt+Right**. Per-instruction keys on the assembly views: **Enter** (follow target), **;** (comment), **N** (rename), **B** (breakpoint), **X** (xrefs), **J/K** (next/prev instruction, Shift = ×16), **P** (patch). Double-click an address or click the `; 0xADDR` target text to follow. Ctrl+G opens the **Goto Symbol** picker (`renderGotoPopup`, fuzzy-filtered over `symbolIndex_`, with a DbgHelp fallback); Ctrl+Shift+F opens the **disassembly text search** (`startTextSearch`, matching mnemonic+operands).

### Live↔file VA translation under ASLR

When attached, the process loads the main module at a base that differs from the file's preferred `imageBase`. `liveMainBase` discovers that base (matching the loaded file's name, falling back to the lowest-base module), and `fileVAtoLive` / `liveVAtoFile` shift addresses by that delta. This is why file-keyed data (analyzed functions, comments, renames, bookmarks, patches) lines up with live instruction addresses, and why annotations created in the live view are stored under the *file* VA. All three helpers are no-ops when not attached or the base is unknown.

### Patching (hex + Keystone assembly)

The **Patch popup** (`renderPatchPopup`) supports two modes: **Assembly** (Keystone via `Assemble`, at the target's own bitness — x64, x86, ARM, ARM64 only) with a live byte preview, and **Hex bytes** with a disassembly preview and a "NOP fill" helper. `applyPatchBytes` is the workhorse: it optionally **NOP-pads** a short encoding up to the original instruction length, captures the *exact* original bytes (read from the live process when attached, else the file image) so a revert is precise, records a `PjPatch` keyed by the **file VA** (`patchKeyFor` translates a runtime VA back), writes the bytes into the debuggee when attached *and* into the in-memory image so the static disassembly reflects them, and invalidates all the relevant caches (`listBuilt_`, pseudocode, decompiler, `functionsDirty_`, `liveGen_`). One-click **NOP out** is available on rows and over multi-line selections. The **Patches** tab lists every patch (original vs patched bytes) with per-row **revert**; `File ▸ Save Binary As…` later splices them to disk.

### Selection & batch actions

The static and live listings support **multi-line selection** (`selVAs_`): plain click = single, Shift+click = range from the anchor, Ctrl+click = toggle one line. When a selected row is right-clicked, a batch menu appears (`asmSelectionMenu` / `liveSelectionMenu`): create a **signature** (`buildSignature`, optionally wildcarding call/jmp displacements so it survives recompilation) routed to the Sig Scanner, copy bytes / C-array / instructions, **NOP out**, **region-patch** (assemble over the whole span), add breakpoints, bookmark, or (live) scan the selected bytes in process memory.

### Analysis export

`exportAnalysis` (File ▸ Export Analysis) gathers renames, comments, bookmarks, notes, and **decompiles every user-named function** (capped at 300) via `decompileFunctionText`, then renders Markdown + HTML reports (`Report.h`) through the app's save dialog.

### Caching strategy (performance)

Responsiveness is engineered throughout: the full listing caches a **row index** (not decoded instructions) and clipper-renders; the live decode is cached by a change-signature; `funcIndex_`, the xref index, the call graph, the symbol index, pseudocode, and the decompiler are all memoized by content/function signatures; `describePointer` is memoized per stop; side lists are filtered into index vectors and clipper-rendered; and the per-frame `saveProjectState` deep-copies the (potentially huge) comment/name maps only when `projectDirty_` is set. On **detach**, the live caches are released once via the `wasAttached_` edge detector.

#### Limitations & notes

- The full listing is **capped at 800k instructions** and is a linear sweep of executable sections — overlapping/obfuscated code may render `db` filler rows rather than the analyst's intended decode.
- The **call-stack walk** is explicitly heuristic (scans for qwords following a `call`); frames beyond frame 0 are best-effort and the UI says so.
- Guessed function names, the inferred `guessSignature`, the instruction gloss, and the API-purpose strings are all **heuristic** and labelled as such (amber tint, "guessed name" tooltips, "signature is heuristic" banner).
- **Keystone** assembly patching covers only x86/x64/ARM/ARM64; other arches can be disassembled (Capstone) but not assembled.
- Conditional-branch evaluation, register hints, and the live string/pointer dereferences are **x86/x64 only** — consistent with the Win32 debugger, which never targets other arches.
- Live string scanning and the various sweeps are **byte-capped** (256 MB strings/value search, 64 MB code search) and **hit-capped** for responsiveness; results may be truncated with a status note.
- The naive live "Pseudo" line translator (`pseudoLine`/`buildPseudo`) is separate from the structured decompiler used by the Pseudocode views; the structured pipeline is the primary one.
