## 07. The Binary View Workspace (Centerpiece)

The **Binary View** tab is the heart of DisasmStudio: it is where static analysis and live debugging meet. Everything else in the app (Projects, Sig Scanner, Memory Tools, Tech, Diff) ultimately routes the user here to "go look at this address." It lives in `src/Tabs/BinaryViewTab.{h,cpp}` — a single ~5000-line class (`ds::BinaryViewTab`) that owns six switchable **main views**, a five-tab **side panel**, thirteen **lower sub-tabs**, a **debug toolbar**, and a stack of modal popups. This chapter walks through every one of them and the machinery underneath.

The class implements `ITab`; `render(AppContext&)` is the per-frame entry point. `AppContext` carries the shared `binary` (`BinaryFile`), `debug` (`Debugger`), `disasm` (`IDisassembler`), and `project` (`ProjectState`). The tab keeps its own editing state (comments, renames, bookmarks, breakpoints, the navigation history, caches) and mirrors annotations to/from `ctx.project` each frame.

### Top control row & main-view selector

The header row offers a **goto box** (`##goto`, accepts `0x...` hex or a symbol name — hex is parsed, otherwise `lookupSymbol` resolves the name), **Back/Forward** buttons (`<` / `>`, disabled when history is exhausted), a **Goto sym** button (opens the symbol picker), a **Find text** button (opens the disassembly text search), and the radio-button **view selector**: Assembly (0), Pseudocode (1), Hex (2), Graph CFG (3), Call Graph (5), and Live Assembly (4, enabled only while attached to a supported x86/x64 target). `mainView_` holds the selection; `render()` dispatches to `renderAssembly` / `renderPseudocode` / `renderHex` / `renderGraph` / `renderLiveAssembly` / `renderCallGraph`. The x86-register/ABI decompiler and synthesis actions are explicitly unavailable on x86-16, A32, Thumb, A64, and the other static-only architectures; their Assembly, Hex, Graph, Call Graph, symbols, and patch views remain usable. The layout below is a left **main-view child**, a right **side panel** (`sideW = 320`), and a **lower-tabs child** (`lowerH = 200`).

### Main view: Assembly (full-program listing)

`renderAssembly` is the dispatcher; by default `asmFullProgram_` is true, so
`renderAssemblyFull` shows the selected image regions as one scrollable listing. The
render thread never performs the full sweep. `buildFullListing` queues a `K_Listing`
job, and `AnalysisJobs::BuildListingRows` returns only a compact region plan: fixed
4 KiB executable `CodePage` descriptors for code/unknown spans, typed directives for
classified executable data islands, region headers, recognized strings, 16-byte
data directives, and explicit `DataTruncated` tail rows. The job performs **zero
instruction decodes** and has no instruction-count cap. Function dividers and unnamed
branch/xref `loc_` labels are added when an individual code page is materialized.

The immutable `CodeDataMap` divides executable storage into code, string, literal-pool,
jump-table, code-pointer-table, padding, data, and honest unknown spans. Positive data
spans render inline as clipped `db`/`dw`/`dd`/`dq` rows with semantic colors, ASCII,
resolved pointer symbols, click navigation, and confidence/evidence tooltips. They also
split the page stream into independent `codeRegion` values: variable-width continuation
checkpoints and page lookahead cannot decode across an embedded data island. A map stamped
for another image revision is ignored.

The **Sections** side tab controls that linear view. Every loader section has separate
visible and folded state, and PE files add a modeled **PE Header** region backed by the
mapped header bytes at the image base. **Code defaults** show and unfold executable
sections while hiding/folding non-executable sections and the PE header. These choices
affect only the linear listing — they do not suppress discovered functions, xrefs, or
other analysis. An unfolded non-executable region preserves recognized string rows and
renders the remaining bytes as 16-byte `db`/ASCII directives. Directive generation is
capped at exactly **1 MiB per data region** and **4 MiB total across the listing**; an
omitted tail is always represented by a truncation row rather than silently disappearing.

Each request carries a `shared_ptr<const ListingLayout>` and a `listingRevision`
independent of the image-analysis epoch. A visibility/fold change, manual **Rebuild
listing**, or manual **Define Function** advances the revision immediately. The worker
plans against that immutable snapshot, and the UI rejects an older result before
atomically adopting `listRows_`; a late job therefore cannot restore an old checkbox
choice. A 64-bit Fenwick index maps each descriptor's estimated or exact row weight to
the clipper's virtual rows. Only visible, goto, cursor-step, or trace-requested pages are
decoded, and a 96-page LRU bounds retained instructions. Exact page weights replace
estimates without losing the top visible address. Variable-width decoders use bounded
lookahead plus propagated page-prefix checkpoints, so an instruction crossing a page
boundary owns its continuation bytes exactly once. Exact predecessor preparation is
strictly capped at 64 KiB. A farther random jump renders immediately from a constant-work
local alignment estimate (15-byte x86 window; halfword-aligned 4-byte Thumb/RISC-V
window; page-front decode for JVM), marks every address with `~`, and invalidates/reconciles
the page if a trusted exact checkpoint becomes available. A page intentionally remains
provisional when no checkpoint is within the 64 KiB bound. A provisional `~` row cannot
seed trace sites or derived analysis automatically. Breakpoint and Patch are explicit analyst
actions: either accepts only the selected displayed instruction start, marks it `!`, and does
not promote the page or authorize trace. The full-program and windowed views use the same
boundary policy. Function definitions, derived signatures, jump-table recovery, and persistent
branch labels still require decoder proof or separate analyst authority. Undecodable bytes use
the architecture's natural resync width.

Each instruction row (`renderAsmRow`) has six columns: a **breakpoint gutter** (`*`
toggles a SW breakpoint), a **flow gutter** (records geometry for branch arrows), the
address, raw bytes, syntax-coloured instruction text, and comments. Assembly and Live
Assembly share DPI-scaled column defaults. Drag separators to resize columns; the
table-header menu can hide Bytes and Comments. The existing ImGui settings retain
these choices, while the navigation/action columns remain visible. RIP, cursor, branch-target, and
navigation-arrival highlights use their distinct theme-derived glow semantics.

Trace coverage is a fifth, lower-priority row state. The app toolbar's **Trace**
button starts or stops the bounded one-shot block plan and **Clear Trace** removes the
collected display state. Discovery walks the lazy executable-page descriptors at
most 1,024 decoded instructions per frame, reports progress, and can be cancelled
before planting. Starting and every planning slice require an exact matching x86/x64
path/module/bitness identity; each file VA is translated with checked arithmetic and
the plan is cancelled before planting if any mapping proof fails. Runtime hits are
translated back through that same matched module. Candidate targets are admitted only when an exact page decode proves the
instruction start; provisional pages are skipped. An executed instruction/block
uses `theme::col::good()` (green) only when a stronger RIP, cursor, branch-target,
multi-selection, or navigation-arrival state does not own the row. Coverage remains
visible after Stop until Clear Trace or a new session/image invalidates it.

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

**Graph / CFG** (`renderGraph`) builds the cursor function's CFG and lays out blocks in a column-per-depth grid with cubic-Bezier edges (green = taken, grey = fallthrough, blue = jump), a colored legend, the RIP block glowing green, executed trace blocks tinted green, and the cursor block outlined. It is **interactive**: drag empty space to pan, drag a block to move it (offsets stored in `cfgDrag_`, "Reset layout" clears them), and double-click a block to re-root the graph there. Each instruction line is formatted like the listing (`+offset mnem ops -> name ; "string"`).

**Call Graph** (`renderCallGraph`) shows, in three columns, the **callers**, the current function, and the **callees** around the cursor function. Edges come from `buildCallGraph`, which sweeps each function once and records direct `call`s whose target is another known function (cached by content-hash + function count). Clicking any node navigates there.

### Main view: Live Assembly (the debugger view)

`renderLiveAssembly` is the live counterpart, available only while attached. It draws a **status pill** (RUNNING/PAUSED/ATTACHED with a colored dot), PID/TID, and the **debug toolbar** — **Continue/Pause** (F5), **Into** (F11), **Over** (F10), **Out** (Shift+F11), all wired to `ctx.debug`. A second header row adds Back/Forward, a **Follow RIP** checkbox, a **Sync** button (jump to and re-follow RIP), a live **goto box**, **Search** (Ctrl+F → live memory search), a **Disasm/Pseudo** mode switch, and display toggles (Regs box, Arrows, reg Hints, Str, Names).

The listing itself (`renderLiveListing`) reads the on-screen window straight from process memory (`readMemoryMasked`, which masks the debugger's own `0xCC` breakpoint bytes so real instructions show), decodes with `liveDecoder` (a decoder matched to the **debuggee's bitness**, so a 32-bit WOW64 target under an x64 host decodes correctly), and **caches** the decode + address index (`liveIdxOf_`) + divider set. The cache signature folds in the window start, RIP (catches stepping and self-modifying code), `liveGen_` (bumped on any live write/patch/re-analyze/detach), the function count, and the PID — so it is rebuilt only when something actually changed, not every frame (this was a deliberate fix for runaway working-set growth while attached). Dividers come from in-window call targets, analyzed functions (ASLR-shifted), and the containing module's parsed **exports** (`parseExports`).

Extra live-only annotations on the RIP row: **register hints** (`regHints`, e.g. `rax=0x..`), and for a conditional branch a flag-evaluated verdict — `-> will jump` / `-> falls through` (`evalCondBranch`). Branch arrows, hover-token highlighting, string comments (with one pointer-hop dereference for `char*` slots), user comments, and green trace-coverage rows all work as in the static view. Keyboard: **Enter** follows the cursor's target, **Backspace** navigates back.

A **register box** (`renderRegisterBox`, right side, toggle "Regs") shows GP registers (e-names for 32-bit targets), changed values tinted, decoded flags, and a 12-slot stack preview. Every register and stack value is **clickable to follow** and right-click-to-copy, and while paused each is annotated by `describePointer` (does it point at a string? a symbol? a `char*`?) — memoized per stop via a hash of the whole register snapshot so the symbol lookups don't re-run every frame.

The live **Pseudocode** mode (`renderLivePseudocode`) runs the same structured `Decompile` pipeline over the live function, decoded at the debuggee's bitness.

### Symbol resolution & name overrides (`symbolFor`)

`symbolFor` is the single resolver used *everywhere* a name appears. Its precedence is deliberate: (1) a **user rename** (`names_`) for the exact address always wins; (2) an **IAT slot** resolves to its import (`importMap_`); then, when attached, (3) DbgHelp/PDB names, (4) the in-house export-table parser, (5) `module+0x..`; or, statically, DbgHelp on the file then the **analyzed-function** fallback (`name+0x..`). Results are cached in `symCache_` (bounded at 100k, cleared on context change). Because guessed function names live in `Func::name`, they flow through `symbolFor` too — but `names_` overrides them.

### The side panel: Bookmarks / Functions / Strings / Sections / Exports + byte search

At the top sits a **Byte Pattern Search** box (hex, no wildcards) with a **Live (process memory)** toggle; hits list below and into the **Results** lower tab, click-to-navigate (live hits open the live view).

- **Bookmarks**: add "+ here", click to go, right-click to rename/remove; persisted as file VAs.
- **Functions**: **Analyze** runs `FunctionAnalyzer` (entry, PE/ELF symbols, call targets, architecture-specific prologues, ARM literal exclusion) into `functions_`; a **Guess** toggle runs `FunctionNamer` (`guessFunctionNames`) to heuristically name anonymous `sub_` functions (`read_file`, `j_CreateFileW`, `start`, …). Guessed names render in **amber** (when no user rename overrides) with a tooltip giving the *basis* for the guess (`guessReason_`). The list is filtered into `fnVisible_` and clipper-rendered. Guesses are recomputed each analyze and never persisted.
- **Strings** (`scanStrings`): ASCII/UTF-8 + UTF-16LE runs (≥4 chars), file-mode or **Live** (scans loaded module images so addresses stay stable across rescans; auto-flips to Live + scans once on first attach). Click to navigate, right-click → **Find references (where used)**.
- **Sections**: listing-only visibility/fold controls for the PE header and every loader
  section. States reconcile by stable `(RVA, name)` identity and are persisted only after
  the analyst explicitly changes or resets the layout.

- **Exports / Symbols**: a filterable view over `BinaryFile::exports()`. PE rows preserve aliases, ordinal-only entries, forwarders, and local code/data targets. ELF rows show `.dynsym`/`.symtab` provenance, kind, binding, visibility, and size. MSVC and Itanium C++ spellings display as full signatures and match filters in either raw or readable form; tooltips/context actions retain the exact linker spelling. Mapped targets navigate to the appropriate code/Hex location; PE forwarders and unmapped evidence remain copyable.

### Lower sub-tabs

`renderLowerTabs` hosts the debugger/analysis panels: **Breakpoints** (software 0xCC with editable conditions, including a "pending" list for not-yet-armed ones, plus hardware DR0–DR3); **Registers** (full register + 24-slot stack view, pointer annotations, and paused double-click editing: hex replaces the raw value, while UTF-8/byte or `L"..."` UTF-16LE text is written to a bounded non-executable target allocation and its pointer placed in a data GPR; the compact Live Assembly register menu opens and focuses this editor); **Watch** (pinned expressions — registers, `[mem]`, constants — evaluated each stop via the shared `EvalExpression`/`Cond.h` evaluator, persisted in `ctx.project.watches`); **Threads** (list, set-active, follow RIP, freeze/thaw); **Call Stack**; **Stack**; **Functions** and live modules; **Xrefs**; **Notes**; **Results**; **Patches**; **Imports**; **Resources**; **Exports / Symbols**; **Annotations**; **Java**; **PDB**; **Address Inspector**; **Triage**; and **Hotkeys**. Panels whose evidence is unavailable stay explicit and inert rather than fabricating data.

**Triage** replaces the old Game tab name without removing its runtime/game-context content. Its
Start Here / Network Trail / Authorization / Strings / Functions / Runtime subtabs provide a guided route from
static endpoint and persistent-state discovery into the existing evidence and optional live observation. Network Trail
renders the report's exact five stages—Endpoint, Connect, Request, Reply, Decision—plus artifacts,
confidence/honesty, completeness, function correlations, and a return-flow table with documented
API success/failure/output contracts, bounded static handling, and separate call/use/decision/target
navigation. Read-status branches remain distinct from reply-content validation. Mapped rows navigate to
Assembly; file-only and overlay sources switch to Hex at `literalFileOffset`. Authorization exposes
every exact cataloged file, registry, INI, Credential Manager, and DPAPI operation in a filterable
clipper table, including operations that cannot be linked to a gate. Exact completed allow-path writes
can link to a startup-reachable read of the same durable identity and the downstream launch gate;
relative/computed/truncated identities remain unlinked. JSON/XML/YAML/TOML labels are filename-extension
hints only and never claim a parsed field or accepted value. The persistent notice states that static
triage does not run the target, contact endpoints, or touch referenced files or registry keys. Open
Live Observation routes to Communications but does not start probes automatically. The routed watch
retains the originating document/image identity and cannot start against an unrelated attached process;
arbitrary-process observation remains an explicit Communications choice.

The same Authorization subtab now adds the **Authorization Trail** above those durable-state
details. Its **Ordered authorization evidence** table sorts independently evidenced
input/format/request/entitlement/verifier/state/gate/operation rows by conceptual stage; it does not
claim that those rows form one connected path. Each location links back to Assembly or Hex and
exposes xrefs where an exact address is available. A ranked predicate table separates unique callers, branch consumers, and guarded
operations; selecting a predicate expands its exact call → return-use → branch → true/false path
and the field lineages that feed it. Rank is explicitly described as an investigation lead. The
large warning above the table identifies proved downstream secondary gates so a branding/global
gate is not presented as sufficient when protected operations remain guarded elsewhere.

The conclusion block deliberately does not collapse “activation” into one boolean. **Locally valid
format**, **server accepted**, **signature verified**, and **feature permitted** each carry their own
unknown/candidate/supported status and evidence. Extra rows scope machine binding, an embedded
expected key, and private signing material. A complete negative scope can support “not found”; an
incomplete scan stays unknown. Endpoint, transport, or verifier presence alone never implies a
recoverable real key, and the UI says that a server-signed entitlement cannot be manufactured
without the private signing material.

For a retained branch-consuming call, **Break after call** starts the checked live experiment
described in chapter 6. The panel displays the observed AL/EAX/RAX contract, offers temporary
**Force true**, **Force false**, and **Restore** only at the same identity-bound pause, and clears the
authority when execution resumes. Safe static patch suggestions are a separate, inert block: an
eligible centralized predicate shows exact original/replacement byte plans, while ineligible
functions show every refusal (for example cleanup, stack-cookie, incomplete entry coverage,
non-executable destination, side effects, or transport-only behavior) instead of an unsafe button.

### Cross-references

**X**, instruction menus, and Overview reference actions pin their target in the
nonmodal **Xrefs** lower panel. Results remain visible while following sources, with
a retained source selection and address/function filter. **Follow cursor** returns
to the cursor/enclosing-function lookup. FILE requests reuse or request the document's
worker-built index; LIVE requests use the bounded, session-owned process-memory
scanner. Explicit requests show up to 3,000 hits and retain partial-coverage labels.

The FILE index scans file-backed executable Code/Unknown ranges, excluding classified
strings, tables, padding, and other data islands without decoding across their edges.
Hidden/folded sections still participate. Bulk, standalone xref, and Cortex analysis
share range planning and analyst overrides. Results carry image, full decoder,
override, and classification identities; stale results are rejected before adoption.
Pinned results retire on image/analysis changes or LIVE session/module replacement.

### Navigation & history

Binary View uses its document's `DocumentNavigation`, with bounded Back/Forward
stacks and explicit representation plus FILE VA, FILE offset, or LIVE VA locations.
Selection updates the current anchor without adding history; an explicit jump pushes
that anchor, so even the first Follow can return to its selected source. Back/Forward
restores the previous view and selection, including VA zero and unmapped Hex offsets.
New jumps discard Forward. Documents retain independent histories; debugger/session
or module-list changes retire LIVE locations while preserving FILE history.

Use toolbar arrows, mouse back/forward, or **Alt+Left/Right** for history. Assembly
keys retain **Enter** (follow), **B** (breakpoint), **X** (references), **J/K** (next/previous,
Shift = 16), and **P** (patch). **;** and **N**, plus contextual menus, share comment and
rename actions across source-backed code views. Synthetic pseudocode rows have no
annotation target. Bookmark actions use the same document-owned address records.

The command band, **Ctrl+G**, and **Ctrl+K** use the same strict numeric grammar:
`file:`/`va:`/`live:`, hexadecimal `0x`/`h`, decimal `0d`, and digit-leading bare hex.
Hex's offset field explicitly selects file offsets. Malformed/overflow inputs keep the
selection and show an error. A pending symbol lookup completes after one submission,
and cancels if its document, image, selection, or debugger owner changes.

Context menus and Address Inspector offer explicit same-address FILE/LIVE handoffs.
They use exact module mapping checks, with reasons when unavailable. **Run to selected
instruction** is available from static instruction menus and Ctrl+K only for an
eligible paused session; dispatch revalidates the captured source and debugger identity.
Ordinary view switches continue to preserve independent static/live cursors.

`Ctrl+K` opens the broader **Investigation** omnibox. `BinaryViewTab` gathers an immutable,
generation-stamped snapshot in bounded render slices; `InvestigationService` builds and ranks it
on its joined worker. Commands, exact FILE/LIVE addresses (including zero), functions, strings,
imports, comments, resources, byte/text hits, xrefs, live modules, typed **Network Trail** findings,
and recent queries share one result model. A trail record carries mapped-VA and file-offset validity
independently; this keeps mapped VA zero distinct from a file-only/overlay source and permits an
exact Hex jump even when no VA exists. Network Trail search evidence also includes bounded expected-
return and static-use summaries. New generations and requests supersede old work, and a result
navigates only when its document/debug-session identity still matches. The **Address Inspector** uses the same
explicit identity discipline to show file offset/RVA/static VA/runtime module+offset, mapping
confidence, xrefs, analyst type/region overrides, and ordered patch coverage.

Authorization Trail locations use the same projection and show **static VA, RVA, file offset, and
current runtime VA together**. Each component has independent validity: a mapped VA of zero remains
valid, a virtual-only byte can lack a file offset, and runtime stays visibly unavailable unless the
attached x86/x64 module identity and range match exactly. Navigation and live mutation never use a
display-only guessed ASLR mapping.

### Live↔file VA translation under ASLR

When attached, the process can load a module at a base that differs from the file's preferred `imageBase`. `liveMainBase` supplies a best-effort display mapping (name match, then lowest-base fallback), and `fileVAtoLive` / `liveVAtoFile` use it to line up non-mutating annotations and navigation. That heuristic never authorizes a debuggee mutation. Static breakpoints, run-to-cursor, trace, hardware breakpoints, and static-to-live patch writes instead go through `AppContext::debuggerRuntimeImage` / `debuggerStaticRuntimeVA`, which require matching x86/x64 bitness plus an exact normalized path for disk images (or an unambiguous module identity for a captured live image), a valid module range, and checked address arithmetic. Without that proof, breakpoints remain pending and patches remain file/project-only. Live Assembly actions use their explicit runtime addresses independently.

### Patching (hex + Keystone assembly)

The preview retains original bytes captured when opened and shows the effective
replacement, including architecture-correct NOP padding. Copy, displayed counts,
and Apply use that same replacement. The destination set and FILE/LIVE mapping are
visible. Completion stays reviewable in the dialog and Patches status: recorded-only,
disabled-set, complete LIVE, and incomplete LIVE outcomes are distinct. Failures keep
the draft open. LIVE edits through this persisted patch workflow require an exact
FILE mapping; a coincidentally equal numeric address is never mapping authority.

The **Patch popup** (`renderPatchPopup`) supports two modes: **Assembly** (Keystone via `Assemble`, for x64, x86, A32, Thumb/Thumb-2, and A64) with a live byte preview, and **Hex bytes** with a disassembly preview and a "NOP fill" helper. NOP fill is architecture-aware: x86 uses `90`, A32 uses `mov r0,r0`, Thumb uses `00 BF`, and A64 uses `1F 20 03 D5`; a fixed-width ISA rejects a span that would split an instruction. `applyPatchBytes` optionally pads a short encoding, captures pristine file bytes for exact revert/save behavior, records a `PjPatch` keyed by file VA, updates the in-memory image, and invalidates derived caches. A static patch is also written into the debuggee only when the exact matcher above proves and checks its runtime translation; otherwise it remains file/project-only. A patch made from Live Assembly reads and writes the explicit runtime address and is translated back to a file key only when a mapping is available. One-click **NOP out** is available on exact static rows and on live rows. The **Patches** tab lists every patch (original vs patched bytes) with per-row **revert**; `File ▸ Save Binary As…` later splices them to disk.

Patches still live in one global vector whose order is the exact later-wins application order, but
each record can now belong to a stable named **patch set**. The Patches tab creates and renames sets,
chooses the enabled destination set for new edits, toggles a set, reassigns its members, reverts all
records in one set, and deletes empty sets. Pre-v4 records belong to the implicit **Ungrouped** set.
Changing a selection reconstructs and validates the pristine image before publishing the new
bytes; it is refused if membership is invalid, saved original bytes disagree, mapping changed, or
two enabled named sets request different bytes over the same span. A failed transition does not
partially change the file image, live target, or project selection.

**Compare selections** is non-mutating. It can compare Current selection, Baseline (no sets),
Ungrouped only, or one named set at a time and reports exact differing-byte counts and clipped spans
with file offsets and left/right bytes. This supports experiments such as “Global gate only” and
“Global + feature gates” without conflating them; enabling, disabling, comparing, and reverting one
named set leaves other set membership and the persisted global patch order intact.

### Selection & batch actions

The static and live listings support **multi-line selection** (`selVAs_`): plain click = single, Shift+click = range from the anchor, Ctrl+click = toggle one line. When a selected row is right-clicked, a batch menu appears (`asmSelectionMenu` / `liveSelectionMenu`): create a **signature** (`buildSignature`, optionally wildcarding call/jmp displacements so it survives recompilation) routed to the Sig Scanner, copy bytes / C-array / instructions, **NOP out**, **region-patch** (assemble over the whole span), add breakpoints, bookmark, or (live) scan the selected bytes in process memory.

### Source export (ASM / C)

**File ▸ Save ASM…** and **File ▸ Save C…** route to Binary View and open the
`Save ASM / Save C` modal. File-menu entry defaults to **Whole program**, while also
showing the analyzed function under the cursor when one exists. The two Functions
lists add **Save function as ASM… / C…** context actions that open the same modal with
that exact function preselected. The scope is therefore explicit: whole analyzed image
or one current function, including a function rooted at VA zero.

C export adds a second choice. **Readable pseudocode** preserves the decompiler's
display-oriented output and is deliberately *not* promised to compile.
**Self-contained compilable C** emits portable C11 scaffolding, sanitized symbols,
external-call stubs, and explicit fallbacks for operations the decompiler cannot model.
C export is x86/x64-only: **x86-16 is deliberately excluded**, so real-mode firmware
uses ASM export. C remains disabled on every unsupported architecture and until background
function discovery has produced the Functions list. Default names are `<binary-stem>.asm` / `<binary-stem>.c`; function scope appends the function
name, and readable C appends `_readable` before `.c`.

`startCodeExport` snapshots the discovered/guessed functions, imports, analyst renames
(the authoritative final name layer), and comments into a `CodeExportRequest`, records
the current image revision, asks `selectCodeExportPath` for the destination, then queues
`AppContext::codeExport`. That dedicated one-job worker constructs its **own decoder**;
it is independent of both `ctx.disasm` and the `AnalysisService` worker. The modal polls
`CodeExportProgress`, showing the named phase, a byte or function progress bar, the
current function VA while decompiling, and **Cancel export**. A completed or cancelled
job reports its final status and byte count in the same modal; cancellation leaves the
chosen destination unchanged. The service streams to a uniquely named sibling temporary
file; only a completed export is committed, with an existing destination first moved to a
short-lived backup so a failed replacement can roll back. Success and cancellation both
remove their temporary/backup artifacts.

### Analysis-report export

This remains a separate workflow: `exportAnalysis` (File ▸ Export Analysis) gathers
renames, comments, bookmarks, notes, and **decompiles every user-named function**
(capped at 300) via `decompileFunctionText`, then renders Markdown + HTML reports
(`Report.h`) through the app's save dialog.

### Caching strategy (performance)

Responsiveness is engineered throughout: the full listing keeps a 64-bit virtual **row index** plus a bounded 96-page decoded LRU and clipper-renders; the live decode is cached by a change-signature; `funcIndex_`, the xref index, the call graph, the symbol index, pseudocode, and the decompiler are all memoized by content/function signatures; `describePointer` is memoized per stop; side lists are filtered into index vectors and clipper-rendered; and the per-frame `saveProjectState` deep-copies the (potentially huge) comment/name maps only when `projectDirty_` is set. On **detach**, the live caches are released once via the `wasAttached_` edge detector.

#### Limitations & notes

- The full listing has **no global instruction cap**. Optional data directives are
  separately capped at **1 MiB per data region** and **4 MiB total**, with visible
  truncation rows; overlapping/obfuscated code may still render `db` filler rows rather
  than the analyst's intended decode.
- The **call-stack walk** is explicitly heuristic (scans for qwords following a `call`); frames beyond frame 0 are best-effort and the UI says so.
- Guessed function names, the inferred `guessSignature`, the instruction gloss, and the API-purpose strings are all **heuristic** and labelled as such (amber tint, "guessed name" tooltips, "signature is heuristic" banner).
- **Keystone** assembly patching covers only x86/x64/A32/Thumb/A64; other arches can be disassembled (Capstone) but not assembled.
- Conditional-branch evaluation, register hints, and the live string/pointer dereferences are **x86/x64 only** — consistent with the Win32 debugger, which never targets other arches.
- Live string scanning and the various sweeps are **byte-capped** (256 MB strings/value search, 64 MB code search) and **hit-capped** for responsiveness; results may be truncated with a status note.
- The naive live "Pseudo" line translator (`pseudoLine`/`buildPseudo`) is separate from the structured decompiler used by the Pseudocode views; the structured pipeline is the primary one.
