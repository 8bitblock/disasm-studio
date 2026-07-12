# DisasmStudio — project memory

> Persistent context for this project. What we're building, why, where things are,
> and the conventions to respect. Read this first in any new session.

## What this is

**DisasmStudio** is a fast, GPU-accelerated **reverse-engineering workbench / disassembler**
written in **C++20** with **Dear ImGui + DirectX 11** on **Win32**. Think "x64dbg / IDA-lite":
static analysis *and* a real live debugger in one tool. The UI is a fixed, browser-style
**single window with a top tab strip** (no docking, by design).

## Goal — what we're trying to accomplish

Build a genuinely usable RE workbench (not a mockup): accurate multi-architecture
disassembly, control-flow + a lightweight decompiler, function/string/import/xref
analysis, a real Win32 debugger, memory tools, signature scanning, binary diffing,
capability ("tech") detection, persistent per-binary analysis, and binary patching —
all navigable and fast.

**Standing constraints (from the project spec):**
- **Must be fast** and **3D/GPU-accelerated** (hardware D3D11 device; clipper-rendered lists).
- AMD-V (SVM) hypervisor backend source lives in `driver/` (`HvDbg.c`, `HvSvm.c`,
  `HvAsm.asm`, `HvDbg.h`), with the user-mode protocol/client under `src/Hv`.
  Packaging, signing, loading, and runtime validation of the kernel driver remain outside
  the normal app target.
- **No scripting/plugin API** — the user explicitly does not want this. Do not add it.

## Required tabs (the spec) and their status

- **Projects** — recent targets (real, backed by a recents index); open/reopen; shows saved-analysis summary.
- **Communications** — native process list + attach (real, Toolhelp32 + Win32 debug API), module list, **live per-process TCP/UDP connections** (real, IP Helper API), a **system-wide connection monitor with history** (all processes, IPv4+IPv6 TCP/UDP, retains closed connections with first/last-seen + active/closed state; filter / selected-process-only / auto-refresh), and the **Java debug (JDWP) console** — attach to a **running** JVM with no prelaunch flag (HotSpot dynamic-attach injection), or connect to a listening agent by host:port; browse classes/methods, live bytecode listing with breakpoints/steps.
- **Sig Scanner** — byte-pattern scan with `??` wildcards (real); Results / Current Scan / **Sig Health** (real match-count scoring) / All Functions. Results click-to-navigate.
- **Binary View** — the main view. Assembly (full-program listing w/ function dividers), Pseudocode (decompiler, **clickable lines sync to the listing** via per-line VA map), **Hex (full-file editor: clipper-rendered, byte/ascii editing routed through the patch system, selection+copy, goto-file-offset)**, Graph (CFG), Call Graph, Live Assembly. Side panel: Bookmarks / Functions / Strings + byte-pattern search. Lower tabs: Breakpoints (w/ **hit counts**) / Registers / Threads / Call Stack / Functions / Watch / Notes / Results / Patches / Imports / Hotkeys. Debug toolbar: Continue / Step Into / Step Over / Step Out.
- **Memory Tools** — scanner (exact/bigger/smaller/changed/…), viewer/editor, region browser, address table w/ freeze (real).
- **Binary Diff** — load two binaries, synced hex panes with per-byte diff highlight (real).
- **Binary Tech** — **real** capability scan (imports/sections/byte-patterns), select to view code.

## Implemented features (status)

Working / real:
- Disassembly via **Zydis (x86/x64)** + **Capstone**; arches: x86, x64, ARM, ARM64, **MIPS/MIPS64, PowerPC/PPC64, RISC-V 32/64**, and **JVM bytecode** (hand-rolled `Disasm/JvmDisassembler`: every opcode incl. wide/tableswitch/lookupswitch, constant-pool symbolication via `Instruction::comment`, switch cases via `Instruction::extraTargets`). Non-x86 routes to Capstone automatically; `Arch::JVM` routes to the JVM backend.
- Loaders: **PE32/PE32+, ELF (32/64), Mach-O (thin 32/64)**, **Java .class** (0xCAFEBABE → per-method executable sections, real method names, exact sizes), and **Open as Raw…** (flat blob at chosen base+arch). A raw load owns one complete executable `.raw` section; its selected base is an explicit function root (including VA 0), while the exact selected `Arch` gates architecture-specific discovery. Structured formats auto-select from the header (`BinaryFile::machine()`).
- **JVM debugging over JDWP** (`Core/Jdwp` pure protocol + `Core/JdwpClient` socket thread): attach to `-agentlib:jdwp` JVMs, suspend/resume, breakpoints at (class, method, bci), step into/over/out, threads + frames, live `Method::Bytecodes` fetch disassembled with constant-pool symbolication from `ReferenceType::ConstantPool`. UI lives in the Communications tab.
- **Full-program assembly listing** with `sub_`/symbol dividers, clipper-rendered (cap 800k insns), auto-loaded functions + strings (ASCII/UTF-8 + UTF-16LE).
- **Lightweight decompiler** (`Core/Decompiler`): dominators + post-dominators + natural-loop detection → structured if/else + while/do-while, goto fallback; per-line operand lifter; heuristic inferred signature. Output language selectable in the Pseudocode view: **pseudo-C or Python** (`DecompileToPython`, a pure display-side transform).
- **Function discovery** (entry/exports/calls/prologue), **CFG**, **call graph**, **xrefs**, switch/jump-table recovery, anti-analysis instruction flags.
- **Heuristic function naming** (`Core/FunctionNamer`): anonymous `sub_` functions are *guessed* a meaningful name from evidence — thunks → `j_<API>`, entry → `start`, empty/zero stubs → `nullsub`/`ret_zero`, recognized API call sets → semantic verbs (`read_file`, `net_send`, `inject_thread`, `read_registry`, `encrypt_data`, …), single-API wrappers → snake-cased API, distinctive embedded identifier strings → that name. Guesses flow through `symbolFor` (so the listing/decompiler header/call sites all use them), are tinted amber + reason-tooltipped in the Functions lists, are de-duped, toggled by **Guess**, and never persisted (user renames still win). Pure `GuessFromEvidence` is unit-tested.
- **Imports + relocations** (PE): IAT resolved to `DLL.func`, shown inline + Imports tab.
- **Per-function annotation engine** (`Core/FuncAnnotate`, x86/x64): heuristic prologue/epilogue notes,
  calling convention + arguments (Win64 reg-use evidence; x86 `ret imm` stdcall / ecx thiscall), stack-frame
  layout + locals (`var_`/`arg_` slots with read/write counts), register lifetimes, per-call
  return-value-checked analysis, plain-language branch meaning ("jumps to 0x.. if eax < 0x10 (signed)",
  strcmp results phrased as match/differ), loop detection with in-loop pattern scans (XOR-decode /
  checksum / byte-compare), switch / indirect-call / virtual-call (vtable-slot shape) / vtable-store /
  this-pointer hints, call-argument sniffing (string literals resolved), and function-level API-set
  patterns (input reading, string compare, file/network/timer/callback/message-pump). **Honesty rule:**
  every `FnNote` carries confidence + evidence + analyzer name and the UI renders them as guesses.
  UI: a "Notes" toolbar toggle renders notes inline (suppresses the gloss on those rows, tooltip = kind +
  confidence + evidence), the function divider shows a summary one-liner, and the **Annotations** lower tab
  is the full report (convention/frame/lifetimes + clickable note list + evidence panel + user override via
  comment). Cached in an 8-entry LRU keyed by function start (`annotationsFor`); ONLY the cursor's function
  builds eagerly — the per-row path is cache-hit-only so scrolling never builds CFGs.
- **Java bytecode annotation engine** (`Core/JvmAnnotate`, Arch::JVM): per-instruction plain-language stack
  effects ("pushes the String constant onto the operand stack", "calls static method, consumes 2 argument
  slot(s)"), operand-stack depth before/after each opcode (abstract interpretation over the bytecode CFG,
  seeded at bci 0 + exception handlers; flags irregular/obfuscated stacks), branch meaning ("branches if the
  top int is zero"), the method's call edges / field accesses / String constants, API-category findings
  (System.exit, Scanner/console input, file I/O, networking, reflection, class loading, native/JNI, crypto,
  ProcessBuilder/exec, threading, UI), and a **password/serial/license check-method** verdict (name +
  boolean-return + String.equals/compareTo + hash/exit evidence). Same confidence+evidence honesty contract.
  UI: inline stack-effect/branch annotations in the listing (Explain/Notes toggle), a method-summary divider
  one-liner, and a dedicated **Java** lower tab — the analysis chain (Native EXE → runtime launcher →
  embedded JAR → Main-Class → main() → check methods), a clickable operand-stack trace, the per-method
  findings/calls/fields/strings, and a filterable **constant-pool viewer**. Cached in an LRU keyed by method
  code offset (`jvmAnnotationsFor`), cache-hit-only per row.
- **Inline annotations** in the listing: strings, API names + **one-line API purpose**, and a per-instruction **plain-language gloss** ("Explain" toggle) describing what each instruction does.
- **User comments + symbol renames** (override resolution everywhere); **bookmarks**; **breakpoints + conditions**.
- **Project persistence**: JSON sidecar keyed by binary content hash in `%APPDATA%/DisasmStudio/projects/<hash>.json`, saved on close/exit/switch, reloaded on open. Hand-rolled JSON (`Core/Json`); addresses stored as hex strings (exact 64-bit round-trip).
- **Patch to file**: accumulate patches, **File ▸ Save Binary As…** splices via `BinaryFile::vaToOffset`.
- **Real Win32 debugger** (`Core/Debugger`): attach/detach, SW + HW breakpoints, conditional breakpoints, step into/over/out, registers/threads/call-stack, read/write memory, live assembly view.
- **Navigation**: unified back/forward history (`navigateTo`/`navBack`/`navForward`), double-click / click-target to follow, goto box + symbol picker, mouse back/fwd + Alt+←/→, per-instruction keys (Enter follow, `;` comment, `N` rename, `B` breakpoint, `X` xrefs).

Heuristic / best-effort (clearly labelled in UI): decompiler output, inferred signatures, deobfuscation/anti-analysis flags, tech-scan confidence.

Out of scope / not done: scripting-plugin API (excluded), FLIRT-style library recognition, IPv6 connection tables, driver packaging/signing/loading/runtime validation.

## Architecture / key files

```
src/App.{h,cpp}         Shell: menu, debug toolbar, tabs; AppContext (shared state: binary,
                        debug, disasm, project, requestedGotoVA, gotoAddress()).
src/main.cpp            Win32 + DX11 host (hardware device), render loop.
src/Core/
  BinaryFile.*          Loader: PE/ELF/Mach-O/raw; VA<->file both ways; contentHash; imports/relocs; machine().
  Debugger.*            Real Win32 debugger (own thread, lock-guarded snapshot); StackWalk64 call-stack unwind.
  CFG.*                 Basic blocks + edges.
  Decompiler.* / DataFlow.*  Structuring pass -> pseudo-C + data-flow pre-pass (inter-block const/copy prop,
                        x86 cdecl/stdcall + Win64 arg detection -> emitted function header, x86-gated via
                        DecompileOptions::x86). Testable, no UI deps.
  AnalysisService.* / AnalysisJobs.*  Background worker (off the render thread) running the pure load-time
                        passes (string scan / function discovery+naming / listing). Owned by AppContext::analysis.
  SigMatch.*            Masked Boyer-Moore-Horspool byte-pattern search (?? wildcards); used by Sig Scanner + TechScan.
  JvmClass.*            Java .class parser: constant pool (describeCp), methods + Code attrs (FILE offsets),
                        LineNumberTable, descriptor pretty-printer. Pure, bounded, unit-tested.
  Jdwp.* / JdwpClient.* JDWP wire protocol (pure encode/decode, unit-tested) + the Winsock client thread
                        (reader pump, parked replies, event handling). ctx.jdwp in AppContext.
  MemCompare.h          Signed/unsigned numeric compare for the memory scanner (header-only, testable).
  DbgHelpLock.h         Process-global lock serializing all DbgHelp use (SymbolResolver vs Debugger::unwindStack).
  FunctionNamer.*       Heuristic naming of anonymous sub_ functions (testable, no UI deps).
  FuncAnnotate.*        Per-function annotation engine (testable, no UI deps): prologue/epilogue, calling
                        convention + args, stack frame/locals, register lifetimes, return-value-checked,
                        plain-language branch meaning, loops + XOR-decode/checksum/byte-compare patterns,
                        switch/indirect/virtual-call + vtable/this-ptr hints, call-arg sniffing, API-set
                        patterns. Every FnNote carries confidence + evidence + analyzer name.
  ApiInfo.h             ApiPurpose(): one-line API behavior map (header-only), shared by the listing's
                        inline comments and FuncAnnotate.
  JvmAnnotate.*         Java bytecode annotation engine (testable, no UI deps): per-opcode stack-effect
                        gloss + slot delta, operand-stack depth via abstract interpretation over the
                        bytecode CFG, branch meaning, call/field/string extraction, API-category findings
                        (System.exit/input/file/network/reflection/class-load/native-JNI/crypto/exec),
                        and a password/serial/license check-method verdict. Confidence + evidence per finding.
  Project.* / Json.*    Per-binary analysis persistence (JSON sidecar) + tiny JSON lib.
  TechScan.*            Capability detection from imports/sections/byte-patterns (multi-hit; testable).
  FunctionAnalyzer.* / SymbolResolver.* / Cond.* / ProcessManager.* / StepLogic.h
src/Disasm/             IDisassembler + Zydis/Capstone/JVM backends, factory, Keystone assembler.
src/Tabs/               One file per tab (BinaryViewTab is the big one, ~3300 lines).
```

## Build

- **Visual Studio 2022**, **x64**, open `DisasmStudio.sln`.
- **vcpkg manifest mode** (`vcpkg.json`): imgui[dx11/win32/docking], zydis, capstone, keystone.
- **Static build** (so the app needs no VC++ Redistributable): the `.vcxproj` sets
  `<VcpkgTriplet>x64-windows-static</VcpkgTriplet>` and the static CRT
  (`RuntimeLibrary` = `MultiThreaded`/`MultiThreadedDebug`). Deps + CRT link *into* the exe, so the
  output is a **single self-contained `DisasmStudio.exe`** — no Zydis/capstone/keystone DLLs beside it,
  no redist needed. (Switching the triplet makes the first build recompile all deps from source.)
  Only non-OS dependency: `d3dcompiler_47.dll` (ImGui DX11 backend), present on Windows 10/11.
- Links: d3d11, dxgi, d3dcompiler, dwmapi, psapi, **iphlpapi, ws2_32**.
- **App icon** embedded via `src/app.rc` (`src/app.ico`, set on the window in `main.cpp`); regenerate with
  `gen_app_icon.ps1`.
- Output: `build/x64/<Config>/DisasmStudio.exe`.

## Conventions & gotchas (respect these)

- **ELF/Mach-O** keep `imageBase_ = 0` and store the absolute VM address in `Section::virtualAddress`,
  so the shared `ptrFromVA`/`vaToOffset` (rva = va - imageBase) math works uniformly with PE.
- **Raw layout is a real analysis image, not a sectionless fallback.** `initializeRawLayout` creates one
  executable/readable `.raw` section spanning every byte, leaves `entryRVA_ = 0` (no fabricated header EP),
  and `FunctionAnalyzer` separately seeds the selected base even at VA 0. The selected `Arch` must be passed
  to background function discovery so x86/x64 prologue patterns never run on other architectures. Raw loads
  use the normal full listing, xrefs, call graph, and background jobs. Reject a mapping when its final VA would
  overflow `uint64_t`; do not leave partial image state.
- **Keystone** (the patch assembler) supports only x86/x64/ARM/ARM64 — it returns a clear
  "unsupported" for other arches (disasm via Capstone is broader than assembly support).
- **Java .class loads use an identity mapping** (imageBase 0, every section's
  virtualAddress == rawOffset), so VA == file offset == what `JvmDisassembler` needs for its
  tableswitch/lookupswitch padding math (pad is relative to the METHOD CODE START — the bci —
  not the instruction address). The parsed `JvmClassFile` lives in `BinaryFile::javaClass()`
  (shared_ptr); `AttachJvmClass(dis, cf)` (declared in JvmDisassembler.h, safe no-op on other
  backends) wires it into the UI decoder (`rebuildDisassembler`) and the worker decoder
  (`AnalysisService::runJob`). FunctionAnalyzer seeds JVM functions straight from the method
  table (exact names/sizes; no x86 heuristics).
- **`Instruction` has two decoder-annotation channels**: `comment` (resolved constant-pool
  text, rendered as a `; ...` inline comment in static/live listings + CFG blocks) and
  `extraTargets` (in-encoding switch case targets; CFG links them as switch successors and
  the listing offers "Follow switch case"). x86/ARM backends leave both empty. CFG also
  treats `goto`/`goto_w` as unconditional.
- **JdwpClient threading**: public requests run on the caller (UI) thread and block on parked
  replies (short timeout); the reader thread pumps the socket and handles events, issuing its
  own follow-up RPCs through a nested pump (`readerRequest`), never the caller-side wait.
  `attach()` acts as the reader until the thread starts. Live bytecode symbolication uses
  `ParseConstantPoolOnly` over the `ReferenceType::ConstantPool` reply (cp-only JvmClassFile,
  set `ok = true` manually).
- New cross-tab "go to an address": set `AppContext::gotoAddress(va)` (Binary View consumes `requestedGotoVA`).
- Annotations (comments/renames/bookmarks/breakpoints/patches/notes/cursor) live in `ctx.project`
  and are mirrored to/from `BinaryViewTab` each frame; the App flushes the sidecar on close/exit.
- **`ctx.project.patches` order = application order — load-bearing.** Overlapping patches resolve
  later-wins; `applyPatchBytes` captures each patch's `orig` as PRISTINE bytes via
  `SubstitutePristine` (Core/Project.h), `revertPatchAt` re-applies surviving overlappers in order,
  and `buildPatchedImage` (App.cpp) splices in the same order. Never re-sort the patch list.
- **Decompiler output carries a per-line source map**: `DecompileWithMap` returns
  `DecompResult{text, lineVA}` (instruction VA per line in the legacy lift, block start in the deep
  data-flow path, 0 = synthetic). `Decompile()` is its `.text` forward — output must stay
  byte-identical; `decompiler_linemap_test` enforces the parallel-vectors invariant.
- Keep it dependency-light: JSON and the decompiler/tech-scan are hand-rolled (no new vcpkg deps added for them).
- **Background analysis** (`AppContext::analysis`): heavy load-time passes (function discovery + naming, string
  scan) run on a worker thread, not the render thread. Invariants: the worker builds its **own** decoder (never
  `ctx.disasm`); every load/patch does `analysis.bumpEpoch()` + `requestBulk(...)` and `render()` applies a result
  only if `epoch` still matches (stale dropped); `App.cpp` calls `analysis.cancelAndWaitIdle()` **before**
  `binary.load/loadRaw/clear` (those realloc the image bytes the worker reads). Listing/xref/decompile stay
  on their existing service/lazy paths. Raw images use this same pipeline through their synthetic executable
  section; do not special-case them back to a reduced windowed-disassembly path.
- **DbgHelp is process-global single-threaded.** Both the UI (`SymbolResolver`) and the debug thread
  (`Debugger::unwindStack`) call it on the same handle, so every DbgHelp call takes `DbgHelpMutex()`
  (`Core/DbgHelpLock.h`). Add that lock around any new `Sym*`/`StackWalk64` call.
- **Theming**: never hardcode RGBA for semantic UI colors — route through `theme::col::*`
  (`accent/good/warn/bad/muted/call/branch/jump/selection/menubar/windowBg`) so all 8 palettes
  (incl. Light) stay correct. Guessed function names render in `theme::col::warn()` (amber).
- **Listing row highlights are glows, with distinct semantics** (static + live):
  RIP = `good` (green), cursor (what the user clicked) = `accent`, the cursor instruction's
  **branch target** = `jump` (violet; per-frame `hlJumpVA_`), plus a ~1s white-hot
  navigation-arrival flash (`navFlashVA_`, set in navigateTo/navBack/navForward). Each row
  keeps a flat RowBg fill (under the text) and pushes halo/outline/left-bar geometry into
  `rowGlow_`; `drawRowGlows` paints it after EndTable on the FOREGROUND draw list (same
  late-draw pattern as the branch arrows — an in-row rect would clip to the cell), glows
  under, arrows on top. Operand tokens are syntax-colored in `renderHoverTokens`
  (registers = `call`, immediates = `warn`, punctuation = `muted`).
- **Pseudocode language selector**: the Pseudocode view renders pseudo-C or **Python**
  (`pseudoLang_`). The worker (K_Decompile) and the LRU always hold pseudo-C;
  `DecompileToPython` (Core/Decompiler) is a **pure display-side text transform** that
  preserves the per-line VA map (braces dropped, decls dropped, for-step re-materialized
  at body end, switch→match with +1 indent inside, case-breaks dropped), applied via
  `applyDecompLang`. Never make the worker emit Python — language switches must stay
  instant and the C path byte-identical (`decompiler_python_test` covers the transform).
- **HiDPI**: `main.cpp` handles `WM_DPICHANGED`, applies Windows' suggested rectangle immediately, and queues
  only the latest DPI for a safe between-frame rebuild: invalidate DX11 font objects → clear/reload the atlas
  at `size*dpi` → `SetUiScale` + absolute `ApplyTheme` metrics (preserving palette/density) → recreate the DX11
  font texture. A creation failure remains queued, suppresses invalid rendering, and retries at a bounded rate.
  Rasterized border/separator widths are rounded to whole physical pixels. New fixed layout sizes should use
  `theme::UiScale()`; never scale the previous ImGui style cumulatively or touch ImGui/DX resources in WndProc.

## Verification approach (important)

- **Pure-logic Core modules are unit-tested** by compiling them with `g++` in a Linux sandbox and
  running small harnesses: JSON round-trip (incl. 64-bit address precision), Project save/load,
  PE/ELF/Mach-O parsing + `vaToOffset`↔`offsetToVA` inverse, the decompiler on synthetic CFGs
  (`decompiler_switch_test`, `decompiler_fixes_test`, `dataflow_decomp_test`, the per-line
  VA map `decompiler_linemap_test`, and the C->Python translation `decompiler_python_test`),
  TechScan detection
  (`techscan_multi_test`), the sig matcher (`sigmatch_test`), memory-compare (`memcompare_test`),
  conditions incl. the signed `s<`/`s<=`/`s>`/`s>=` operators (`cond_eval_test`, `cond_compiled_test`),
  overlapping-patch pristine-orig bookkeeping (`patch_pristine_test`), the background analysis
  mechanics (`analysis_service_test`), the per-function annotation engine (`funcannotate_test`:
  convention/frame/branch/loop/pattern/call notes + the confidence-and-evidence contract),
  the arch enum/helpers, the instruction-gloss/API mapping,
  the Java class parser (`jvmclass_test`), the JVM bytecode decoder + CFG integration
  (`jvmdisasm_test`), the JavaClass loader + JVM function seeding (`jvmload_test`), and the
  JDWP wire protocol (`jdwp_test`).
  Keep adding to these when touching Core logic. `tests\run_core_tests.bat` builds + runs the
  cl-compatible set in one go.
- On Windows (where there is **no g++**), the same `tests/*.cpp` compile+run with **MSVC `cl`** in a
  VS dev shell (`vswhere` → `Enter-VsDevShell` → `cl /std:c++20 /I src tests\<t>.cpp src\Core\<deps>.cpp`,
  `/Fo` must end in a backslash for multi-source) — the fast Core verification loop without the ~20-40 min
  full app build. ImGui/Win32 TUs still need the `DisasmStudio.sln` build.
- The **ImGui / Win32 / Capstone-facing code cannot be compiled in the sandbox** (no Windows SDK /
  ImGui / Capstone / Keystone there), so those edits are **review-verified** — always build
  `DisasmStudio.sln` (x64) on Windows to confirm and report errors.
- Sandbox quirk: the bash file-mount sometimes serves a **stale/torn copy of a just-edited file**
  (e.g. a header truncated mid-line). That's the mount, not the real file — the Read/Edit/Grep
  tools operate on the true Windows files. Work around it by testing the actual logic via a small
  standalone copy if needed.
