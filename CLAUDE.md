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
- **No scripting/plugin API** — the user explicitly does not want this. Do not add it.

## Required tabs (the spec) and their status

- **Projects** — recent targets (real, backed by a recents index); open/reopen; shows saved-analysis summary.
- **Communications** — native process list + attach (real, Toolhelp32 + Win32 debug API), module list, **live per-process IPv4+IPv6 TCP/UDP connections** (real, IP Helper API; family/protocol/text filters, scope IDs, auto-refresh, partial-table errors), a **system-wide connection monitor with history** (all processes, IPv4+IPv6 TCP/UDP, retains closed connections with first/last-seen + active/closed state; filter / selected-process-only / auto-refresh), and the **Java debug (JDWP) console** — attach to a **running** JVM with no prelaunch flag (HotSpot dynamic-attach injection), or connect to a listening agent by host:port; browse classes/methods, live bytecode listing with breakpoints/steps.
- **Sig Scanner** — byte-pattern scan with `??` wildcards (real); Results / Current Scan / **Sig Health** (real match-count scoring) / All Functions. Results click-to-navigate.
- **Binary View** — the main view. Assembly (full-program listing w/ function dividers), Pseudocode (decompiler, **clickable lines sync to the listing** via per-line VA map), **Hex (full-file editor: clipper-rendered, byte/ascii editing routed through the patch system, selection+copy, goto-file-offset)**, Graph (CFG), Call Graph, Live Assembly. Side panel: Bookmarks / Functions / Strings + byte-pattern search. Lower tabs: Breakpoints (w/ **hit counts**) / Registers / Threads / Call Stack / Functions / Watch / Notes / Results / Patches / Imports / **Resources** / Hotkeys. Debug toolbar: Continue / Step Into / Step Over / Step Out / **Trace**.
- **Memory Tools** — scanner (exact/bigger/smaller/changed/…), viewer/editor, region browser, address table w/ freeze (real).
- **Binary Diff** — flat/section-aware byte comparison plus opt-in **semantic function diff** (symbols, normalized instruction semantics, CFG shape, call neighborhoods, edit hunks, and explicit-only metadata transfer), all on a cancellable path-owning worker.
- **Binary Tech** — **real** capability scan (imports/sections/byte-patterns), select to view code.

## Implemented features (status)

Working / real:
- Disassembly via **Zydis (x86-16 real mode/x86/x64)** + **Capstone**; arches: x86-16, x86, x64, **ARM/A32, Thumb/Thumb-2, ARM64/A64**, **MIPS/MIPS64, PowerPC/PPC64, RISC-V 32/64**, and **JVM bytecode** (hand-rolled `Disasm/JvmDisassembler`: every opcode incl. wide/tableswitch/lookupswitch, constant-pool symbolication via `Instruction::comment`, switch cases via `Instruction::extraTargets`). Both native engines decode `Arch::X86_16` with real-mode defaults; Thumb uses `CS_MODE_THUMB`; non-x86 routes to Capstone automatically; `Arch::JVM` routes to the JVM backend.
- Loaders: **PE32/PE32+, ELF (32/64), Mach-O (thin + universal/fat32/fat64, either byte order)**, **Java .class** (0xCAFEBABE → per-method executable sections, real method names, exact sizes), and **Open as Raw…** (flat blob at editable base + entry + arch). ELF `.dynsym`/`.symtab`, REL/RELA, PLT/GOT, `DT_NEEDED`, GNU versions, and init/fini records use bounded validity-bearing models; `ET_REL` alloc sections receive checked synthetic analysis VAs. Mach-O models symbols, classic dyld bindings/export trie, function starts, initializers, and deterministic slice selection while preserving outer-file offsets. A raw load owns one complete executable `.raw` section; an explicit entry is authoritative even at VA 0, and named firmware landmarks can seed additional roots. Structured formats auto-select from the header (`BinaryFile::machine()`).
- **Firmware sniffing / boot-entry recovery** (`Core/FirmwareSniffer`): bounded, dependency-free detection of legacy BIOS images, PI `_FVH` volumes, PCI/EFI option ROMs (`55 AA` + PCIR), and Intel Flash Descriptors. Results retain per-record confidence/evidence, conservative x86-16/x86/x64 hints, bounded A32/Thumb/A64 motif hints, recommended top-of-4-GiB or standalone-ROM mappings, resolved short/near/far x86 boot-jump chains, and named structural/code landmarks. Open as Raw presents detected defaults but keeps base, entry, architecture, and landmark seeding editable.
- **JVM debugging over JDWP** (`Core/Jdwp` pure protocol + `Core/JdwpClient` socket thread): attach to `-agentlib:jdwp` JVMs, suspend/resume, breakpoints at (class, method, bci), step into/over/out, threads + frames, live `Method::Bytecodes` fetch disassembled with constant-pool symbolication from `ReferenceType::ConstantPool`. UI lives in the Communications tab.
- **Full-program assembly listing** with `sub_`/symbol dividers and auto-loaded functions + strings (ASCII/UTF-8 + UTF-16LE). There is no global instruction cap: a 64-bit virtual row index and bounded code-page LRU decode only visible or explicitly requested 4 KiB pages. Variable-width x86/JVM/Thumb/RISC-V boundaries propagate exact checkpoints; a far random jump instead paints immediately from a constant-work provisional alignment (`~`), never grants trace/breakpoint/patch authority, and reconciles when a bounded exact predecessor result arrives.
- **Recursive whole-image code/data classification** (`Core/CodeDataClassifier`): bounded recursive traversal from trusted roots plus referenced strings/literals, ARM-family literal references, absolute/RVA/relative jump tables, aligned code-pointer/vtable runs, relocation-backed callbacks, CET landing pads, and ISA-aware padding. Strong indirect-only entries feed one bounded `FunctionAnalyzer` rerun. Every executable byte is partitioned as code/string/literal/jump-table/pointer-table/padding/data/unknown with confidence+evidence; Binary View splits lazy decode regions at data islands and renders them as typed `db`/`dw`/`dd`/`dq` directives with symbols and evidence tooltips.
- **Lightweight decompiler** (`Core/Decompiler`): dominators + post-dominators + natural-loop detection → structured if/else + while/do-while, goto fallback; per-line operand lifter; heuristic inferred signature. Output language selectable in the Pseudocode view: **pseudo-C or Python** (`DecompileToPython`, a pure display-side transform).
- **Save ASM / Save C source export** (`Core/CodeExport`): File-menu workflow for the whole analyzed program or the function under the cursor. ASM is a named/commented listing for every decoder; x86/x64 C can be the decompiler's readable pseudo-C or a normalized, self-contained compilable C11 translation unit. A dedicated worker owns an independent decoder, streams output off the render thread, exposes phase/current/total/bytes-written progress, and supports cancellation.
- **Function discovery** (entry/PE+ELF symbols/calls/x86+A32+Thumb+A64 prologues), bounded ARM literal-pool exclusion, **CFG**, **call graph**, **xrefs**, x86 switch recovery + Thumb TBB/TBH recovery, anti-analysis instruction flags.
- **Semantic binary diff** (`Core/SemanticDiff*` + Binary Diff tab): deterministic bounded function matching by authoritative symbols, relocation-insensitive typed-instruction hashes, CFG structure, and matched call neighborhoods; added/removed functions, evidence/confidence, instruction edit hunks, and side-by-side instruction review. File loading, parsing, hashing, and analysis stay on the diff worker. Name/comment/prototype/bookmark proposals are inert until individually selected, and apply only when the target content hash is the active static project.
- **Heuristic function naming** (`Core/FunctionNamer`): anonymous `sub_` functions are *guessed* a meaningful name from evidence — thunks → `j_<API>`, entry → `start`, empty/zero stubs → `nullsub`/`ret_zero`, recognized API call sets → semantic verbs (`read_file`, `net_send`, `inject_thread`, `read_registry`, `encrypt_data`, …), single-API wrappers → snake-cased API, distinctive embedded identifier strings → that name. Guesses flow through `symbolFor` (so the listing/decompiler header/call sites all use them), are tinted amber + reason-tooltipped in the Functions lists, are de-duped, toggled by **Guess**, and never persisted (user renames still win). Pure `GuessFromEvidence` is unit-tested.
- **Symbols/imports + relocations**: PE IAT/exports/relocations plus bounded ELF `.dynsym`/`.symtab` defined and undefined symbols. A shared bounded C++ demangler uses DbgHelp for MSVC names and an in-tree Itanium parser for GCC/Clang names; compact names flow through analysis/listings/decompilation while Imports/Exports show full signatures and preserve raw linker names. `Core/SymbolService` is the sole asynchronous UI-symbol owner for static/live targets; lightweight listing lookups and rich source/prototype/type/local inspection never run DbgHelp on the render thread. Symbol-server fetching is disabled by default and requires an explicit cache + server opt-in in **View -> Symbol Settings**. The GUI exposes filterable **Exports / Symbols**, **PDB / Symbols**, and Imports panels; mapped ELF functions/IFUNCs seed analysis with exact size hints.
- **PE resource browser** (`BinaryFile::parseResources` + `Core/ResourceDecode`): bounded parse of data
  directory [2] into a Type→Name→Language `Resource` model (`resources()`); a **Resources** lower tab
  renders the tree with decoded previews (manifest/HTML text, `RT_VERSION` version info, `RT_STRING`
  tables), a hex fallback, click-to-Hex navigation, verbatim save, and reconstructed **.bmp/.ico** export.
  Pure parser + decoders are unit-tested (`binaryfile_resources_test`, `resourcedecode_test`).
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
- **Project persistence**: version-3 JSON sidecars keyed by binary content hash in `%APPDATA%/DisasmStudio/projects/<hash>.json`, debounced off the render thread and synchronously committed before close/exit/switch. Writes use a flushed sibling temporary file, atomic replace, and `.bak` recovery; failures remain visibly dirty and block target replacement. Addresses are hex strings for exact 64-bit round-trips. Version 3 persists the exact raw mapping plus authoritative function/code/data/type overrides; versions 1–2 remain readable.
- **Multi-document workspace** (`DocumentContext` + `BinaryViewHostTab`): the fixed single window has a top strip for up to eight static/live-image documents. Each stable document owns its binary/project/decoder/analysis/export services and retained Binary View/navigation state. Opens, activations, and closes commit only after the frame releases tab references; save failure preserves the outgoing owner, close joins all borrowers, and closing the last tab installs a fresh scratch. Debugger/JDWP/Prism and epoch-gated live-module analysis remain app-global.
- **Patch to file**: accumulate patches, **File ▸ Save Binary As…** splices via `BinaryFile::vaToOffset`.
- **Real Win32 debugger** (`Core/Debugger`): attach/detach, SW + HW breakpoints, conditional breakpoints, step into/over/out, registers/threads/call-stack, read/write memory, live assembly view.
- **Execution trace / coverage** (`Core/TraceCoverage` + debugger integration): from a paused session, incrementally plan and plant up to 65,536 invisible one-shot basic-block breakpoints; expose progress, cancel/stop, and Clear Trace; preserve user/temp-breakpoint priority at colliding addresses; and render executed code green in the static listing, Live Assembly, and CFG.
- **Debug-a-DLL** (`Core/DllDebugPlan` + hosted debugger launch): validate a PE DLL and its callable non-forwarded code exports, select a bitness-matched trusted `System32`/`SysWOW64` `rundll32.exe` or a validated custom host, build correctly quoted typed arguments, plant optional DllMain/export stops after `LOAD_DLL`, retarget RVAs to the actual ASLR base, and hand the mapped DLL to the normal live-module analysis path.
- **Navigation / investigation**: unified back/forward history (`navigateTo`/`navBack`/`navForward`), double-click / click-target to follow, mouse back/fwd + Alt+←/→, and per-instruction keys (Enter follow, `;` comment, `N` rename, `B` breakpoint, `X` xrefs). **Ctrl+K** is the asynchronous unified investigation omnibox across commands, exact FILE/LIVE addresses, functions, strings, imports, comments, resources, byte/text hits, xrefs, live modules, and recent queries. Its sliced snapshot collector and worker service are generation-safe and bounded. The lower **Address Inspector** shows file offset/RVA/static VA/runtime module+offset, mapping confidence/evidence, xrefs, classification/type/overrides, and ordered patch state with explicit VA-zero validity.

Heuristic / best-effort (clearly labelled in UI): decompiler output, inferred signatures, deobfuscation/anti-analysis flags, tech-scan confidence.

Out of scope / not done: scripting-plugin API (excluded), FLIRT-style library recognition, kernel-mode/hypervisor backends.

## Architecture / key files

```
src/App.{h,cpp}         Shell: menu, debug toolbar, tabs; AppContext (shared state: binary,
                        debug, disasm, project, requestedGotoVA, gotoAddress()).
src/main.cpp            Win32 + DX11 host (hardware device), render loop.
src/Core/
  BinaryFile.*          Loader: PE/ELF/Mach-O/raw; VA<->file both ways; explicit raw entry + named analysis
                        landmarks; contentHash; imports/relocs; machine(); exports() (PE EAT) + resources().
  FirmwareSniffer.*     Pure bounded BIOS/UEFI/PCI-ROM/Intel-descriptor detector; evidence/confidence,
                        mapping/CPU hints, reset/boot-jump recovery, and code-vs-structural landmarks.
  ResourceDecode.*      Pure PE resource-payload decoders (no ImGui/Win32/BinaryFile dep): RT_* type names,
                        UTF-16->UTF-8, VS_VERSIONINFO, RT_STRING tables, DIB describe, .bmp/.ico reconstruct.
  Debugger.*            Real Win32 debugger (own thread, lock-guarded snapshot); StackWalk64 call-stack unwind.
  TraceCoverage.*       Thread-safe generational trace state: bounded one-shot site lifecycle, hit counters,
                        progress/cancel/clear snapshots; debugger owns the actual invisible int3 breakpoints.
  DllDebugPlan.*        Pure PE-DLL inspection, callable-export selection, bitness/host and Windows argv
                        planning, breakpoint RVA plan, and LOAD_DLL/ASLR retargeting.
  CFG.*                 Basic blocks + edges.
  Decompiler.* / DataFlow.*  Structuring pass -> pseudo-C + data-flow pre-pass (inter-block const/copy prop,
                        x86 cdecl/stdcall + Win64 arg detection -> emitted function header, x86-gated via
                        DecompileOptions::x86; per-call argument recovery -> inlined call args, gated by
                        DecompileOptions::callArgs). Testable, no UI deps.
  CodeExport.*          Pure streaming ASM/C generator + independent one-job background export service;
                        whole-program/current-function scopes and readable/self-contained compilable C modes.
  CodeDataClassifier.*  Pure bounded global executable-byte classifier; indirect function-seed feedback,
                        typed data spans, confidence/evidence, complete partitions, and cancellation.
  AnalysisService.* / AnalysisJobs.*  Background worker (off the render thread) running the pure load-time
                        passes (string scan / function discovery+naming + code/data classification / listing).
                        The current document owns it; multi-document contexts use one worker apiece.
  DocumentContext.*     Static-document lifetime owner + eight-document manager: binary/project/decoder/workers,
                        FILE/LIVE navigation, staged replacement, save-failure transition barriers, and joined close.
  Tabs/BinaryViewHostTab.*  Per-DocumentId retained Binary View owner; image-generation-scoped UI state,
                        active-only rendering, safe transition mirroring, and host-monotone investigation snapshots.
  AtomicFile.* / Preferences.*  Shared flushed atomic small-file store plus strict bounded prefs codec/recovery.
  SemanticDiff* / SemanticTransfer.*  Pure bounded semantic matching + BinaryFile adapter and identity-checked,
                        explicit-only analyst-metadata transfer. BinaryDiffTab owns path loading and orchestration.
  SigMatch.*            Masked Boyer-Moore-Horspool byte-pattern search (?? wildcards); used by Sig Scanner + TechScan.
  JvmClass.*            Java .class parser: constant pool (describeCp), methods + Code attrs (FILE offsets),
                        LineNumberTable, descriptor pretty-printer. Pure, bounded, unit-tested.
  Jdwp.* / JdwpClient.* JDWP wire protocol (pure encode/decode, unit-tested) + the Winsock client thread
                        (reader pump, parked replies, event handling). ctx.jdwp in AppContext.
  MemCompare.h          Signed/unsigned numeric compare for the memory scanner (header-only, testable).
  DbgHelpLock.h         Process-global lock serializing the independent SymbolService and debugger DbgHelp sessions.
  SymbolResolver.* / SymbolService.*  Bounded DbgHelp adapter plus sole joined async UI-symbol owner; optional
                        cache-backed symbol-server access is off by default; rich source/type/local records are bounded.
  InvestigationIndex.* / InvestigationService.*  Pure typed FILE/LIVE omnibox index plus one-worker, latest-wins,
                        generation-safe build/search orchestration with structured failures and overload counters.
  AddressInspector.*   Pure validity-bearing FILE/LIVE address projection over immutable analysis/debug snapshots.
  Demangle.*            Bounded cached MSVC/Itanium/C symbol demangling; raw linker spellings remain authoritative.
  NetworkEndpoint.*     Canonical IPv4/IPv6 endpoint formatting with RFC5952 compression and numeric scope IDs.
  FunctionNamer.*       Heuristic naming of anonymous sub_ functions (testable, no UI deps).
  FuncAnnotate.*        Per-function annotation engine (testable, no UI deps): prologue/epilogue, calling
                        convention + args, stack frame/locals, register lifetimes, return-value-checked,
                        plain-language branch meaning, loops + XOR-decode/checksum/byte-compare patterns,
                        switch/indirect/virtual-call + vtable/this-ptr hints, call-arg sniffing, API-set
                        patterns. Every FnNote carries confidence + evidence + analyzer name.
  ApiInfo.h             ApiPurpose(): one-line API behavior map (header-only), shared by the listing's
                        inline comments and FuncAnnotate.
  ApiDatabase.h         Bounded Windows API prototypes/parameter names plus symbolic access, allocation,
                        page-protection, file/registry/socket/message constants used by call annotations.
  JvmAnnotate.*         Java bytecode annotation engine (testable, no UI deps): per-opcode stack-effect
                        gloss + slot delta, operand-stack depth via abstract interpretation over the
                        bytecode CFG, branch meaning, call/field/string extraction, API-category findings
                        (System.exit/input/file/network/reflection/class-load/native-JNI/crypto/exec),
                        and a password/serial/license check-method verdict. Confidence + evidence per finding.
  Project.* / Json.*    Per-binary analysis persistence (JSON sidecar) + tiny JSON lib.
  TechScan.*            Capability detection from imports/sections/byte-patterns (multi-hit; testable).
  Cortex.*              RE-brain (additions.md #3): PURE reasoning layer over the other analyzers' output
                        (TechScan caps + AlgoScan matches + FunctionNamer guesses + FuncAnnotate per-function
                        summaries/patterns via CortexInput::funcInfo + imports/strings) -> plain-English
                        headline/verdict, merged per-category behaviours (confidence+evidence), per-function
                        briefs (prefer the FuncAnnotate summary/patterns; carry calling convention) + a ranked
                        highlights list, and a deterministic keyword-routed AskCortex() "chat with the binary"
                        (incl. per-function lookup: "what does sub_401500 / 0x.. do?"). RenderCortexMarkdown for
                        export. No model dependency — the LLM-backend seam is AskCortex()/the verdict text.
                        Testable (cortex_test); CortexTab drives it (builds the FuncAnnotations, bounded to 200).
  Prism.* / PrismSampler.*  Prism 2 explanatory profiler. Prism.* is the PURE aggregation+explanation
                        layer: symbolized stack samples -> self/inclusive hot-function table, thread-state
                        breakdown (running/waiting/lock-contention/allocation/io/gpu via top-frame keyword
                        classification), PER-THREAD breakdown (each thread's dominant state + hottest leaf),
                        PER-MODULE self-time, an over-time timeline (30 buckets by PrismSample::timeMs; empty
                        when untimed), bounded deterministic flame layout, hot call paths, collection-quality/
                        lost-event evidence, and a "where the time goes / what to fix" verdict (prism_test).
                        PrismSampler owns a preferred real-time ETW kernel collector (profile/image/thread/
                        context-switch-derived wait/I/O evidence) and an explicitly labelled suspend-and-walk
                        fallback with native x64 + WOW64 StackWalk64 contexts. A separate aggregation worker
                        publishes immutable reports; PrismTab only draws them, supports timeline selection and
                        one-click exact-static-or-live navigation. ETW may require elevation/profile privilege;
                        Automatic mode records the failure and falls back rather than hiding it.
  FunctionAnalyzer.* / SymbolResolver.* / Cond.* / ProcessManager.* / StepLogic.h
src/Disasm/             IDisassembler + Zydis/Capstone/JVM backends (incl. x86-16 real mode), factory,
                        Keystone assembler.
src/Tabs/               One file per tab (BinaryViewTab is the big one, ~3300 lines).
```

## Build

- **Visual Studio 2022**, **x64**, open `DisasmStudio.sln`.
- **vcpkg manifest mode** (`vcpkg.json`): imgui[dx11/win32/docking], zydis, capstone, keystone. The
  Capstone dependency explicitly enables `x86`, `arm`, `arm64`, `mips`, `ppc`, and `riscv`; keep those
  manifest features aligned with `Arch` rather than relying on a port's changing defaults.
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
- **ELF `ET_REL` is the exception to literal section addresses.** Multiple `SHF_ALLOC` sections commonly have
  `sh_addr == 0`; `parseELF` assigns them checked, alignment-aware, non-overlapping synthetic analysis VAs and
  resolves defined symbols against those same bases. `SHT_NOBITS` has a virtual range but no backing bytes.
- **Raw layout is a real analysis image, not a sectionless fallback.** `initializeRawLayout` creates one
  executable/readable `.raw` section spanning every byte and initially leaves `entryRVA_ = 0` with
  `rawEntryExplicit_ = false` (no fabricated header EP). The Open-as-Raw staging path then validates the
  editable entry with `setRawEntryPointVA` and the detector/user roots with `setAnalysisLandmarks` before
  replacing the current image. Use `hasEntryPoint()` + `entryPointVA()` when consuming entries: an explicitly
  selected RVA/VA 0 is valid. `FunctionAnalyzer` seeds that entry plus every bounded named landmark; only a
  legacy raw image with no explicit entry falls back to the mapped base. The exact selected `Arch` must reach
  the worker: `Arch::X86_16` is a real-mode decoder but receives no x86-32/x64 prologue/ABI assumptions, and
  `Arch::THUMB` remains a distinct fixed decoder mode from A32. Raw
  loads use the normal listing, xrefs, call graph, and background jobs. Reject a mapping when its final VA
  would overflow `uint64_t`; invalid entry/landmark replacement is atomic and must not disturb current state.
- **Firmware detection is evidence, not certainty.** `SniffFirmware` validates declared extents/checksums/
  metadata, caps records and signature work, and marks partial findings with confidence plus explanatory
  evidence. The interactive probe skips files over 512 MiB; the Core scanner otherwise uses bounded head/tail
  windows while fixed reset/descriptor checks still run. Never promote a structural landmark (`code == false`)
  to a function root, treat ARM-mode motif detection as a conservative hint rather than proof, and keep the
  base/entry/architecture controls editable after applying detected defaults.
- **Keystone** (the patch assembler) supports only x86/x64/A32/Thumb/A64 — it returns a clear
  "unsupported" for other arches (disasm via Capstone is broader than assembly support).
- **Resource-directory offsets are relative to the resource base RVA, NOT RVAs** — every
  `IMAGE_RESOURCE_DIRECTORY`/string/subdirectory offset in `parseResources` is added to `resourceRVA_`
  before `ptrFromRVA`; only the leaf `IMAGE_RESOURCE_DATA_ENTRY.OffsetToData` is a real RVA. The walk is
  bounded by a visited-entry cap + a depth cap so a self-referential subdirectory can't spin. Each
  `Resource` carries `va = imageBase_ + dataRVA` (for Hex navigation) and a `fileOffset` (for reading
  bytes). The `Core/ResourceDecode` decoders take a raw (bytes, size) span and stay ImGui/Win32-free.
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
- **JdwpClient threading**: one connection thread exclusively owns every Winsock call and
  processes attach, detach, and public RPC commands from a bounded-wait command queue. UI
  callers never close or access the socket; detach/dispose cancels queued requests and the
  owner performs shutdown. Event-driven follow-up RPCs use the owner's nested pump without
  deadlocking the queue. Live bytecode symbolication uses
  `ParseConstantPoolOnly` over the `ReferenceType::ConstantPool` reply (cp-only JvmClassFile,
  set `ok = true` manually).
- New cross-tab "go to an address": set `AppContext::gotoAddress(va)` (Binary View consumes `requestedGotoVA`).
- Annotations (comments/renames/bookmarks/breakpoints/patches/notes/cursor/analyst overrides) live in
  `ctx.project` and are mirrored to/from `BinaryViewTab`; mutations mark a revision dirty, the App
  debounces an atomic background save, and close/switch synchronously verifies the final commit.
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
  scan) run on a worker thread, not the render thread. `K_Listing` is intentionally decoder-free: it emits
  immutable layout rows plus 4 KiB code-page descriptors, while the GUI materializes visible pages into a
  bounded LRU and indexes their estimated/exact row weights with `ListingVirtualIndex`. Far variable-width pages
  must not be decoded linearly from the section front: exact prefix work is capped at 64 KiB. Farther x86 pages use
  a <=15-byte/<=120-call local estimate, Thumb and compressed RISC-V use aligned <=4-byte candidates, and JVM uses
  a provisional page-front decode. These rows cannot seed trace sites, breakpoints, patches, or persistent branch
  labels; they may remain provisional when no trusted checkpoint is within the cap, and reconcile if one arrives.
  Deterministic pass results are retained in a bounded, thread-safe in-memory LRU. Cache keys include the
  pristine content hash, an order-sensitive patch digest, exact architecture and effective decoder, analysis
  schema, name-guess setting, authoritative override digest, and pass-specific immutable inputs. Lookup,
  hashing of large snapshots, result cloning, and eviction all happen on analysis workers; cancellation and
  epoch checks still gate every published cache hit.
  Invariants: passes that
  decode build their **own** decoder (never
  `ctx.disasm`); every load/patch does `analysis.bumpEpoch()` + `requestBulk(...)` and `render()` applies a result
  only if `epoch` still matches (stale dropped); `App.cpp` calls `analysis.cancelAndWaitIdle()` **before**
  `binary.load/loadRaw/clear` (those realloc the image bytes the worker reads). Listing/xref/decompile stay
  on their existing service/lazy paths. Raw images use this same pipeline through their synthetic executable
  section; do not special-case them back to a reduced windowed-disassembly path.
- **Code/data map lifetime and listing boundaries are load-bearing.** Production maps are stamped with
  `BinaryFile::imageRevision()` and must be rejected for a different revision. Code/unknown spans retain lazy
  `CodePage` behavior; positively classified data spans split `codeRegion`, so exact/provisional variable-width
  checkpoints and decode lookahead never cross a data island. Preserve `Unknown` when evidence is insufficient.
- **Background code export** (`AppContext::codeExport`) is a separate one-job service, not an
  `AnalysisService` task. It owns its decoder and reads a borrowed `BinaryFile`; call
  `codeExport.cancelAndWaitIdle()` before any load, close, patch, or other image mutation/reallocation.
  The image revision is a stale-work guard, not a replacement for that lifetime rule.
- **DbgHelp is process-global single-threaded.** The `SymbolService` worker owns the UI's static/live resolver
  (using a duplicated process handle), while the debugger thread owns its independent local-only unwind session.
  Every `Sym*`/`StackWalk64` call in either session takes `DbgHelpMutex()` (`Core/DbgHelpLock.h`); the render thread
  only enqueues symbol requests and polls immutable results.
- **Theming**: never hardcode RGBA for semantic UI colors — route through `theme::col::*`
  (`accent/good/warn/bad/muted/call/branch/jump/selection/menubar/windowBg`, plus the panel-chrome
  tokens `panel/panelHeader/line/lineSoft`) so all 9 palettes stay correct — incl. Light and the
  default **Paper** (warm paper/ink/amber, from `disassembler-wireframes.html`). Guessed function
  names render in `theme::col::warn()` (amber).
- **Wireframe chrome kit** (`Ui/Widgets.h`, modeled on `disassembler-wireframes.html`): build new
  chrome from `ui::ToolButton` (30px square bordered icon button), `ui::ToolbarDivider`,
  `ui::Pill` / `ui::StatePill` (bordered mono chips), `ui::TabStrip` (accent-underline tab strip),
  and `ui::StatusDivider` — don't hand-roll. The app toolbar (App.cpp; its height comes from
  `ToolbarHeight()`, which renderMainWindow must keep using for its top offset), the menubar
  file tab (close routes through `App::closeBinary()`), the mono status bar, and the Binary View
  view-switcher tab strip are all built from this kit.
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
  at body end, switch→match with +1 indent inside, case-breaks dropped, and
  `true/false/NULL/nullptr`→`True/False/None`), applied via `applyDecompLang`. Never make
  the worker emit Python — language switches must stay instant and the C path byte-identical
  (`decompiler_python_test` covers the transform).
- **Decompiler engine upgrade passes** (`Core/Decompiler.cpp`, deep data-flow path, gated by
  `DecompileOptions` flags `prettyNames`/`foldTemps`/`conditionGloss`, default on) run after
  structuring/for-loop reconstruction and **must keep the `lineVA` parallel-vectors invariant**:
  `prettyNamesPass` renames loop-counter temps to `i/j/k` (whole-word token rewrite, no line
  change); `foldTempsPass` coalesces/inlines genuinely single-use intra-block temps and **erases
  the dead line AND its `lineVA` entry in lockstep** (never across calls/stores/multi-use);
  `conditionGlossPass` appends an additive `/* var OP literal */` gloss to simple relational
  `if`s (skips literals that don't fit signed-64 so the decimal can't print wrong-signed).
  `DecompileWithMap`'s signature is unchanged and both the Pseudocode and Decompiler views get
  the upgraded output. Covered by `decompiler_tempname_test` / `decompiler_folder_test` (+ the
  linemap/fixes/dataflow golden tests).
- **Call-argument recovery** (`Core/DataFlow.cpp`, deep path, gated by `DecompileOptions::callArgs`,
  default on) renders each call's arguments inline — `printf("hello", a1)` instead of `printf()`.
  Win64: a CONTIGUOUS run of the integer arg registers (rcx, rdx, r8, r9) that still hold a
  propagated value at the call site (volatile regs are cleared after every call, so a value here
  was set for this call); stops at the first unset register so a stale higher reg can't fabricate a
  gap arg. x86 cdecl/stdcall: the values pushed since the last call / frame setup (`mov ebp,esp` /
  `sub esp` / `add esp` reset the pending-push group), consumed reversed (last push = arg1). Each
  arg's reads are unioned into the call's reads, so **a string/value marshalled into an argument is
  no longer dead-code-eliminated** — this is what makes string literals appear at the point they're
  passed (the marshalling `mov`/`lea` then folds away, leaving just the call). Heuristic (no callee
  prototypes), so it can over/under-count; flip `callArgs` off for the legacy bare-`callee()` form.
  Covered by `dataflow_decomp_test` (tests 16–20: Win64 string arg, multi-arg, contiguity guard,
  x86 push chain, kill switch).
- **Binary View layout is fixed wireframe (`.wf-body.va`), not a dockspace** — `render()` lays
  out LEFT list column (`leftColW_`, default 218) / CENTER code-view panel / GRAPH column
  (`graphColW_`, 400; `graphView_` 0=CFG 1=Call Graph) / RIGHT rail (`rightRailW_`, 250;
  Registers/Stack) / BOTTOM dock (`bottomDockH_`; `renderLowerTabs`) using `BeginChild` +
  `ds::ui::VSplitter` + a local horizontal splitter. Widths scale by `theme::UiScale()` once
  (`layoutScaled_`); **View ▸ Reset Layout restores all of them (incl. `decompSplitW_`)** instead
  of rebuilding a dock node. Each panel header is a `ui::TabStrip` ending in decorative
  `.wf-win-btns` dots. The center view switcher = `mainView_` (0=Assembly, 1=Pseudocode,
  2=Hex, 4=Live, **6=Decompiler**); legacy 3/5 are normalized into `graphView_` at frame entry.
- **Decompiler view** (`renderDecompiler`, `mainView_==6`) reuses the SAME decompile request +
  LRU + `decompVA_/decompLines_/decompLineVA_/decompPending_` flow as the Pseudocode view (no
  double-request, instant switch), and shows two `VSplitter` panes (`decompSplitW_`): upgraded
  pseudocode (clickable lines → `navigateTo(decompLineVA_[i])` when nonzero) beside a compact,
  freshly-`decodeOne`-decoded asm pane of the same function, cross-highlighted via `decompHoverVA_`
  (deliberately NOT the big glow/arrow listing, to keep that foreground-draw pattern isolated).
- **HiDPI**: `main.cpp` handles `WM_DPICHANGED`, applies Windows' suggested rectangle immediately, and queues
  only the latest DPI for a safe between-frame rebuild: invalidate DX11 font objects → clear/reload the atlas
  at `size*dpi` → `SetUiScale` + absolute `ApplyTheme` metrics (preserving palette/density) → recreate the DX11
  font texture. A creation failure remains queued, suppresses invalid rendering, and retries at a bounded rate.
  Rasterized border/separator widths are rounded to whole physical pixels. New fixed layout sizes should use
  `theme::UiScale()`; never scale the previous ImGui style cumulatively or touch ImGui/DX resources in WndProc.

## Verification approach (important)

- **Pure-logic Core modules are unit-tested** by compiling them with `g++` in a Linux sandbox and
  running small harnesses: JSON round-trip (incl. 64-bit address precision), Project save/load,
  PE/ELF/Mach-O parsing + `vaToOffset`↔`offsetToVA` inverse, ELF32/64 dynamic/static symbols and `ET_REL`
  synthetic layouts (`elf_symbols_test`), the PE resource directory parser
  (`binaryfile_resources_test`) and its payload decoders (`resourcedecode_test`), the decompiler on synthetic CFGs
  (`decompiler_switch_test`, `decompiler_fixes_test`, `dataflow_decomp_test`, the per-line
  VA map `decompiler_linemap_test`, and the C->Python translation `decompiler_python_test`),
  TechScan detection
  (`techscan_multi_test`), the sig matcher (`sigmatch_test`), memory-compare (`memcompare_test`),
  conditions incl. the signed `s<`/`s<=`/`s>`/`s>=` operators (`cond_eval_test`, `cond_compiled_test`),
  overlapping-patch pristine-orig bookkeeping (`patch_pristine_test`), the background analysis
  mechanics (`analysis_service_test`), global code/data partitioning and indirect-only function recovery
  (`codedata_classifier_test`), lazy listing layout/virtual-row/cross-page behavior
  (`listing_layout_test`, `listing_virtual_index_test`), streaming/background source export (`code_export_test`: whole/per-function
  ASM, readable/compilable C, generated-C compiler invocation, in-flight cancel + temp cleanup), the per-function annotation engine (`funcannotate_test`:
  convention/frame/branch/loop/pattern/call notes + the confidence-and-evidence contract),
  firmware formats/mappings/jump recovery and hostile bounds (`firmware_sniffer_test`), explicit raw-entry +
  named-landmark discovery including VA 0 plus ARM prologues/literal exclusion (`functionanalyzer_test`),
  the arch enum/helpers, ISA-correct NOP fill, Thumb TBB/TBH arithmetic, real Zydis/Capstone x86-16 and
  Capstone Thumb width/target behavior (`xref_arch_test`), the instruction-gloss/API mapping,
  trace coverage lifecycle/generation/priority state (`trace_coverage_test`), PE-DLL inspection, host/argument
  planning and LOAD_DLL ASLR retargeting (`dll_debug_plan_test`),
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

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
