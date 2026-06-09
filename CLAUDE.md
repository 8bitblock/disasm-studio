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
- **Communications** — native process list + attach (real, Toolhelp32 + Win32 debug API), module list, and **live per-process TCP/UDP connections** (real, IP Helper API).
- **Sig Scanner** — byte-pattern scan with `??` wildcards (real); Results / Current Scan / **Sig Health** (real match-count scoring) / All Functions. Results click-to-navigate.
- **Binary View** — the main view. Assembly (full-program listing w/ function dividers), Pseudocode (decompiler), Hex, Graph (CFG), Call Graph, Live Assembly. Side panel: Bookmarks / Functions / Strings + byte-pattern search. Lower tabs: Breakpoints / Registers / Threads / Call Stack / Functions / Notes / Results / Patches / Imports / Hotkeys. Debug toolbar: Continue / Step Into / Step Over / Step Out.
- **Memory Tools** — scanner (exact/bigger/smaller/changed/…), viewer/editor, region browser, address table w/ freeze (real).
- **Binary Diff** — load two binaries, synced hex panes with per-byte diff highlight (real).
- **Binary Tech** — **real** capability scan (imports/sections/byte-patterns), select to view code.

## Implemented features (status)

Working / real:
- Disassembly via **Zydis (x86/x64)** + **Capstone**; arches: x86, x64, ARM, ARM64, **MIPS/MIPS64, PowerPC/PPC64, RISC-V 32/64**. Non-x86 routes to Capstone automatically.
- Loaders: **PE32/PE32+, ELF (32/64), Mach-O (thin 32/64)**, and **Open as Raw…** (flat blob at chosen base+arch). Arch auto-selected from the header (`BinaryFile::machine()`).
- **Full-program assembly listing** with `sub_`/symbol dividers, clipper-rendered (cap 800k insns), auto-loaded functions + strings (ASCII/UTF-8 + UTF-16LE).
- **Lightweight decompiler** (`Core/Decompiler`): dominators + post-dominators + natural-loop detection → structured if/else + while/do-while, goto fallback; per-line operand lifter; heuristic inferred signature.
- **Function discovery** (entry/exports/calls/prologue), **CFG**, **call graph**, **xrefs**, switch/jump-table recovery, anti-analysis instruction flags.
- **Heuristic function naming** (`Core/FunctionNamer`): anonymous `sub_` functions are *guessed* a meaningful name from evidence — thunks → `j_<API>`, entry → `start`, empty/zero stubs → `nullsub`/`ret_zero`, recognized API call sets → semantic verbs (`read_file`, `net_send`, `inject_thread`, `read_registry`, `encrypt_data`, …), single-API wrappers → snake-cased API, distinctive embedded identifier strings → that name. Guesses flow through `symbolFor` (so the listing/decompiler header/call sites all use them), are tinted amber + reason-tooltipped in the Functions lists, are de-duped, toggled by **Guess**, and never persisted (user renames still win). Pure `GuessFromEvidence` is unit-tested.
- **Imports + relocations** (PE): IAT resolved to `DLL.func`, shown inline + Imports tab.
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
  MemCompare.h          Signed/unsigned numeric compare for the memory scanner (header-only, testable).
  DbgHelpLock.h         Process-global lock serializing all DbgHelp use (SymbolResolver vs Debugger::unwindStack).
  FunctionNamer.*       Heuristic naming of anonymous sub_ functions (testable, no UI deps).
  Project.* / Json.*    Per-binary analysis persistence (JSON sidecar) + tiny JSON lib.
  TechScan.*            Capability detection from imports/sections/byte-patterns (multi-hit; testable).
  FunctionAnalyzer.* / SymbolResolver.* / Cond.* / ProcessManager.* / StepLogic.h
src/Disasm/             IDisassembler + Zydis/Capstone backends, factory, Keystone assembler.
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
- **Keystone** (the patch assembler) supports only x86/x64/ARM/ARM64 — it returns a clear
  "unsupported" for other arches (disasm via Capstone is broader than assembly support).
- New cross-tab "go to an address": set `AppContext::gotoAddress(va)` (Binary View consumes `requestedGotoVA`).
- Annotations (comments/renames/bookmarks/breakpoints/patches/notes/cursor) live in `ctx.project`
  and are mirrored to/from `BinaryViewTab` each frame; the App flushes the sidecar on close/exit.
- Keep it dependency-light: JSON and the decompiler/tech-scan are hand-rolled (no new vcpkg deps added for them).
- **Background analysis** (`AppContext::analysis`): heavy load-time passes (function discovery + naming, string
  scan) run on a worker thread, not the render thread. Invariants: the worker builds its **own** decoder (never
  `ctx.disasm`); every load/patch does `analysis.bumpEpoch()` + `requestBulk(...)` and `render()` applies a result
  only if `epoch` still matches (stale dropped); `App.cpp` calls `analysis.cancelAndWaitIdle()` **before**
  `binary.load/loadRaw/clear` (those realloc the image bytes the worker reads). Listing/xref/decompile stay
  lazy-synchronous for now (the documented A2 follow-up threads those too).
- **DbgHelp is process-global single-threaded.** Both the UI (`SymbolResolver`) and the debug thread
  (`Debugger::unwindStack`) call it on the same handle, so every DbgHelp call takes `DbgHelpMutex()`
  (`Core/DbgHelpLock.h`). Add that lock around any new `Sym*`/`StackWalk64` call.
- **Theming**: never hardcode RGBA for semantic UI colors — route through `theme::col::*`
  (`accent/good/warn/bad/muted/call/branch/selection/menubar/windowBg`) so all 8 palettes
  (incl. Light) stay correct. Guessed function names render in `theme::col::warn()` (amber).
- **HiDPI**: `main.cpp` enables per-monitor DPI awareness, loads fonts at `size*dpi`, and calls
  `theme::SetUiScale(dpi)`; `applyMetrics()` multiplies every pixel metric by that scale, so the
  layout stays crisp and survives live theme switches. New fixed pixel sizes should multiply by
  `theme::UiScale()`.

## Verification approach (important)

- **Pure-logic Core modules are unit-tested** by compiling them with `g++` in a Linux sandbox and
  running small harnesses: JSON round-trip (incl. 64-bit address precision), Project save/load,
  PE/ELF/Mach-O parsing + `vaToOffset`↔`offsetToVA` inverse, the decompiler on synthetic CFGs
  (`decompiler_switch_test`, `decompiler_fixes_test`, `dataflow_decomp_test`), TechScan detection
  (`techscan_multi_test`), the sig matcher (`sigmatch_test`), memory-compare (`memcompare_test`),
  conditions (`cond_eval_test`, `cond_compiled_test`), the background analysis mechanics
  (`analysis_service_test`), the arch enum/helpers, and the instruction-gloss/API mapping. Keep
  adding to these when touching Core logic.
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
