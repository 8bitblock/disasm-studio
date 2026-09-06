# DisasmStudio — Project Overview, Purpose & Architecture

> **DisasmStudio is a fast, GPU-accelerated reverse-engineering workbench for Windows: a static disassembler *and* a real live debugger in one self-contained application.** It loads PE/ELF/Mach-O, Java class, and raw binaries across twelve native CPU modes plus JVM bytecode, including x86-16 real mode and Thumb/Thumb-2, disassembles them, recovers functions and control flow, **guesses meaningful names for unknown functions**, decompiles them into readable pseudo-C, lets you debug a running process down to the instruction, scan and edit memory, diff binaries, detect capabilities, patch bytes, and persist all of your analysis — inside one polished, themeable, single-window UI. Think "x64dbg meets a lite IDA," built in C++20 on Dear ImGui + Direct3D 11.

**Audience for this document:** an engineer or technical evaluator who has never seen the codebase and wants to understand, completely, what DisasmStudio *is*, *what it is for*, *everything it can do*, and *how it is built*. Every chapter is grounded in the actual source; nothing here is aspirational unless explicitly labelled "roadmap" or "out of scope."

**How to read it:** this front section states the purpose, the full capability catalogue, the intended users, and the design principles. Chapters 1–12 are deep technical tours of each subsystem. Chapter 13 is an appendix with a source-coverage map, an honest list of which outputs are heuristic, the explicit non-goals, and a forward roadmap.

---

## What DisasmStudio Is (Purpose & Vision)

DisasmStudio exists to **make an unfamiliar binary understandable, quickly**. Reverse engineering is the act of recovering meaning from compiled code that ships without source, symbols, or documentation — malware, vulnerable software, undocumented file formats, DRM, firmware. The work is slow because the analyst has to rebuild, by hand, everything the compiler threw away: where functions begin and end, what they do, what the data means, how control flows, and how the program behaves when it actually runs. DisasmStudio's purpose is to **automate as much of that reconstruction as possible and present it in one fast, navigable workspace**, so the human can spend their attention on the parts that need judgment.

It is built around a deliberate philosophy:

- **Be a real tool, not a mockup.** Every headline feature is backed by working code: accurate multi-architecture disassembly, an actual control-flow-and-data-flow decompiler, a genuine Win32 debugger that attaches to and single-steps live processes, real PE/ELF/Mach-O parsing, real network/process inspection, real binary patching that writes back to disk.
- **Static *and* dynamic in one place.** Most tools make you choose between reading code (a disassembler) and running it (a debugger). DisasmStudio unifies both: the same addresses, names, comments, and breakpoints carry across the static listing and the live debuggee, with automatic translation for ASLR.
- **Recover *meaning*, not just bytes.** A raw disassembly is a wall of `sub_140001000` and `mov rax, [rcx+8]`. DisasmStudio layers understanding on top: it **guesses function names** from behaviour (`read_file`, `net_send`, `inject_thread`, `j_CreateFileW`), inlines the strings and API calls each instruction touches, writes a plain-language gloss of what each instruction does, and decompiles whole functions into structured pseudo-C with named locals and inferred signatures.
- **Organize authorization evidence honestly.** The bounded Authorization Trail presents input/format evidence, request and entitlement handling, exact verifier and persistent-field lineage, ranked global/secondary predicates, and protected operations in conceptual stage order. Independently evidenced stages are not presented as one connected path; exact edges are claimed only where data/control-flow proof exists. It keeps local format validity, server acceptance, signature verification, and feature permission as separate conclusions instead of turning a nearby “Pro” string or successful API call into a verdict.
- **Be fast and stay fast.** The UI is GPU-accelerated (hardware Direct3D 11), and every large list (instructions, functions, strings, hex) is clipper-rendered and aggressively cached. The assembly view has no fixed instruction cap: multi-million-instruction images use a virtual row index and decode only visible 4 KiB code pages into a bounded cache.
- **Be self-contained and dependency-light.** The whole product compiles to a *single* statically-linked `DisasmStudio.exe` that needs no installer, no runtime redistributable, and no DLLs beside it. Where a dependency would add weight or risk, the project hand-rolls a focused replacement (its own JSON library, its own decompiler, its own capability scanner).
- **Keep the analyst in control.** There is, by deliberate design, **no scripting or plugin API** — the surface area is the curated, hand-built workbench, not an extension platform. Heuristic results are always *labelled* as heuristic (and colour-coded), and any guess the tool makes can be overridden by a one-keystroke rename that then propagates everywhere.

In short: **DisasmStudio is the workbench an analyst opens to go from "here is an unknown executable" to "I understand what this program does" as fast as possible** — reading it, naming it, decompiling it, running it, poking its memory, comparing it, and writing down what they learn.

---

## What DisasmStudio Can Do — The Capability Catalogue

DisasmStudio is one self-contained Windows executable that can do **all** of the following. (Items are numbered continuously so the breadth is concrete; grouped by what you are trying to accomplish.)

### Load, decode & explore any binary
1. **Load PE32 and PE32+** (32- and 64-bit Windows executables and DLLs).
2. **Load ELF32 and ELF64** (Linux/Unix binaries), synthesizing sections from program headers for stripped images.
3. **Load thin Mach-O** (32- and 64-bit macOS binaries).
4. **Open arbitrary bytes as a flat "raw" blob** at a chosen base address (shellcode, firmware, memory dumps) with a chosen architecture.
5. **Auto-detect the file format** from its magic bytes and **auto-select the CPU architecture** from the header.
6. **Disassemble twelve native CPU modes plus JVM bytecode:** x86-16, x86, x64, A32, Thumb/Thumb-2, A64, MIPS, MIPS64, PowerPC, PPC64, RISC-V 32, and RISC-V 64.
7. **Use the right engine automatically:** Zydis for the x86-family fast path, Capstone for every other native architecture, and the JVM backend for bytecode, behind one engine-neutral interface.
8. **Render a full-program assembly listing** with function dividers and no global instruction cap; a virtual row index materializes only requested 4 KiB code pages into a bounded cache.
9. **Never get stuck on undecodable bytes** — they fall back to data pseudo-ops with an ISA-aligned stride so the listing always advances without destroying ARM/Thumb alignment.
10. **Translate freely between virtual addresses and file offsets**, uniformly across all formats.

### Discover & understand code
11. **Discover function boundaries** from the entry point, PE export table, and an x86/x64 prologue scan, then follow direct calls recursively.
12. **Build a per-function control-flow graph** (basic blocks + edges) and view it as an interactive graph.
13. **Recover `switch`/`case` jump tables** and their selector expressions.
14. **Build a whole-program cross-reference index** (every target → who references it) for instant "find references."
15. **Search references on demand**, in the file *or* in a live debuggee's memory.
16. **Resolve symbols** from PDBs and export tables via DbgHelp, in both static and live sessions.
17. **Go to any symbol by name** (reverse name→address lookup).
18. **Build a caller/callee call graph** around any function.

### Guess function names (the headline feature)
19. **Heuristically name anonymous `sub_` functions** so the listing and decompiler read in plain language.
20. **Name thunks/wrappers** that tail-jump to an import as `j_<API>` (e.g. `j_CreateFileW`).
21. **Name the program entry point `start`,** and trivial stubs `nullsub` / `ret_zero`.
22. **Infer semantic names from the set of APIs a function calls** — e.g. `read_file`, `write_registry`, `net_send`, `inject_thread`, `encrypt_data`, `launch_process`, `resolve_imports`, across ~40 categories.
23. **Snake-case a single-API wrapper** to a readable name (a one-call helper around `GetTickCount` becomes `get_tick_count`).
24. **Derive a name from a distinctive embedded identifier string** the function references.
25. **Explain every guess** via a hover tooltip ("calls CreateFileW, ReadFile"), **colour guesses amber** so they read as heuristic, **de-duplicate** colliding names, and let you **toggle guessing on/off**.
26. **Propagate guessed (and user-given) names everywhere** — listing, function dividers, call sites, call graph, xrefs, and the decompiler header — while a **user rename always wins** and is saved.

### Decompile to readable pseudo-C
27. **Decompile any function to structured pseudo-C** using dominator/post-dominator analysis.
28. **Recover `if`/`else`, `while`/`do-while`, and `for` loops**, with labelled-`goto` fallback for irreducible flow.
29. **Render conditional branches as real relational expressions** derived from the preceding `cmp`/`test`.
30. **Name and type locals and arguments** (`a1..aN`, `int`/`__int64`/`void*`) via a data-flow pass.
31. **Propagate constants and copies and eliminate dead assignments** for cleaner output.
32. **Recover return expressions** and **inline string literals, imports, and globals** into the code.
33. **Splice the guessed name and inferred signature into the function header**, so output reads like real C.

### Read what the code *means*
34. **Inline string references** next to the instructions that use them (ASCII/UTF-8 and UTF-16LE).
35. **Inline imported-API names and a one-line description of each API's purpose.**
36. **Toggle a per-instruction plain-language "Explain" gloss** describing what each instruction does.
37. **Add your own comments** at any address, shown inline.

### Debug a live process
38. **Attach to a running process, launch an executable, or debug a validated PE DLL** through a bitness-matched trusted `rundll32.exe` or custom host; DllMain/export breakpoint RVAs are retargeted on the DLL's actual ASLR load event.
39. **Break at the real program entry point**, not the loader stub.
40. **Set software (`int3`) breakpoints** that auto-restore, step, and re-arm.
41. **Set conditional breakpoints** with a register/memory comparison expression.
42. **Set hardware breakpoints (DR0–DR3):** execute / write / read-write, sized 1/2/4/8 bytes.
43. **Step Into, Step Over, Step Out, and Run-to-Cursor.**
44. **View and edit registers** while paused.
45. **Read, write, and view debuggee memory**, with breakpoint bytes masked out.
46. **Enumerate committed memory regions** with R/W/X flags.
47. **List and freeze/thaw threads** and pick the active thread.
48. **Walk the call stack** (clearly labelled heuristic) and inspect the raw stack with symbol/string annotations.
49. **Debug 32-bit (WOW64) targets** via the WOW64 context.
50. **Pin watch expressions** that re-evaluate at every stop.
51. **See a live-updating disassembly and pseudocode** that follow RIP, collect bounded one-shot basic-block execution coverage, and run a checked **Break after call** authorization experiment that observes AL/EAX/RAX and temporarily forces/restores only that stopped return register.

### Inspect & manipulate memory
52. **Scan process memory beyond the basic Cheat Engine workflow** — passive or debugger-backed targets; signed/unsigned integers, floats, AOB `??`, and UTF-8/UTF-16; exact/not-equal/ordered/between/changed/unchanged/increased/decreased/delta/unknown scans with exact-count paging and region/range/alignment filters.
53. **Inspect and edit a 256-byte live hex/ASCII selection**, browse searchable memory regions, follow pointers, and jump directly from Live RIP.
54. **Find bounded pointer chains** with module-relative roots, and save/load JSON address tables with inert-on-load rows plus identity-checked constant/minimum/maximum freeze policies.

### Search, scan & compare
55. **Byte-pattern (signature) scanning with `??` wildcards**, against the file or live memory.
56. **Score a signature's "health"** (no match / unique / multiple) so you know if it's specific enough.
57. **Search disassembly text** (mnemonics/operands) and **byte patterns**, click-to-navigate.
58. **Diff two binaries** in synchronized hex panes with per-byte difference highlighting.

### Detect capabilities & triage
59. **Run a capability/"tech" scan and automatic Authorization Trail**: rank boolean predicates by proven consumer fan-out, follow exact call-return/field/guard relationships where available, present other stages as independent evidence, and keep every conclusion evidence-graded and independently navigable.
60. **Enumerate running processes and their modules** natively.
61. **View live per-process TCP/UDP (IPv4) connection tables.**

### Patch binaries
62. **Patch bytes by hex or by typing assembly** (Keystone-assembled for x86/x64/A32/Thumb/A64), with ISA-correct NOP-padding of short encodings and inert, fail-closed advice for narrowly proved centralized boolean predicates.
63. **Patch live debuggee memory** or the static image.
64. **Revert an individual patch or organize patches into named experiment sets**, enable/disable or revert a set independently, and compare Baseline/Current/single-set selections without mutation.
65. **Save a patched copy of the binary to disk** (patches spliced back through the file offsets).

### Annotate, persist & report
66. **Comment, rename, and bookmark** any address.
67. **Auto-save all analysis per binary** — comments, renames, bookmarks, breakpoints + conditions, version-4 named patch sets and membership, notes, watches, and last cursor.
68. **Key analysis to the binary's content hash**, so it follows the bytes even if the file is moved or renamed.
69. **Reopen recent targets** from a Projects dashboard with a saved-analysis summary.
70. **Export a full analysis report** to Markdown or HTML (named, decompiled functions, comments, bookmarks, metadata).
71. **Save assembly or C source** for the whole analyzed program or the function under the cursor; assembly follows every active decoder, while x86/x64 C can be readable pseudo-C or a self-contained compilable C11 translation unit, generated on a cancellable background worker with progress.

### Navigate & work efficiently
72. **Unified back/forward navigation history** (aware of static vs live locations), goto-by-address, and a symbol picker.
73. **Mouse back/forward, `Alt`+←/→, and per-instruction keys** (`Enter` follow, `;` comment, `N` rename, `B` breakpoint, `X` xrefs, `J`/`K` step).
74. **Branch arrows** drawn in a flow gutter in the listing.
75. **Eight built-in colour themes** (Midnight, Slate, Light, Monokai, Solarized Dark, Dracula, Nord, Matrix), switchable live and remembered across sessions.
76. **A fixed, browser-style single-window UI** with a top tab strip — no fiddly docking to manage.

### Engineering qualities
77. **Ships as one statically-linked, self-contained `.exe`** — no installer, no redistributable, no side-by-side DLLs (only the OS's `d3dcompiler_47.dll`).
78. **GPU-accelerated, vsync-capped rendering** with occlusion-aware frame skipping.
79. **A testable Core** — the pure logic (loaders, firmware sniffing/jump recovery, listing-region planning, decompiler, data-flow, function namer, xrefs, JSON, conditions, step logic, trace-coverage state, DLL launch planning, tech-scan, source export) is decoupled from the UI and unit-tested off-target.
80. **Dependency-light by design** — hand-rolled JSON, decompiler, and capability scanner; only Zydis/Capstone/Keystone/ImGui as third-party libraries.

### Advanced / experimental

---

## Who It's For & Typical Workflows

DisasmStudio is built for anyone who needs to understand a binary they did not write:

- **Malware analysts & incident responders.** Open a sample, let the capability scan and function-name guesser triage it ("this calls `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` → `inject_code`"), read the decompiled droppers, attach to detonate it under the debugger, watch its network connections, and export a report — without leaving the app.
- **Vulnerability researchers.** Navigate the disassembly and call graph, decompile the parsers, set conditional and hardware breakpoints on interesting memory, scan and watch values as the program runs, and patch to test hypotheses.
- **CTF players & crackme solvers.** Find the check function by name guess or string xref, decompile it, patch the jump, and save the cracked binary.
- **Firmware & shellcode analysts.** Open raw blobs at the right base/arch and disassemble non-x86 ISAs (ARM/MIPS/PPC/RISC-V).
- **Students & the curious.** Use the per-instruction "Explain" gloss and readable pseudocode to learn how compiled code actually works.

A typical first-pass workflow: **Open** the target (or review the detected mapping/entry for raw firmware) → DisasmStudio auto-analyzes (functions, strings, imports, **guessed names**) → choose the visible/folded listing regions in **Sections** → skim the **Functions** list and **Binary Tech** capabilities → **decompile** the interesting functions → **comment/rename** as understanding grows (auto-saved) → **attach/launch** or **Debug DLL…** to confirm behaviour dynamically, optionally collecting execution coverage → **patch** and/or export a report, whole-program/current-function assembly, or readable/compilable C from the **File** menu.

---

## Design Principles & Constraints

These are the standing rules the codebase holds itself to (see CLAUDE.md and Chapters 1, 10, 12):

- **Fast and GPU-accelerated.** Hardware D3D11 device; clipper-rendered lists; pervasive caching.
- **Single self-contained executable.** `x64-windows-static` triplet + static CRT → one `DisasmStudio.exe`, no redist.
- **Single-window, browser-style tabs, no docking.** A fixed, predictable layout by deliberate choice.
- **No scripting / plugin API.** The product is the curated workbench, not an extension platform — this is an explicit non-goal.
- **Dependency-light.** Hand-rolled where a library would add weight or risk (JSON, decompiler, tech-scan).
- **Heuristics are labelled.** Guessed names, inferred signatures, decompiler output, anti-analysis flags, and tech-scan results are always presented as best-effort and are user-overridable.
- **Testable core, review-verified UI.** Logic lives in `src/Core` and is unit-tested; the ImGui/Win32/engine-facing code is review-verified, built, and smoke-run.

---

## How This Document Is Organized

| # | Chapter | In one line |
|---|---------|-------------|
| 1 | Architecture & Application Shell | The Win32 + D3D11 host, render loop, app shell, fixed tab strip, AppContext, cross-tab plumbing. |
| 2 | Disassembly Engines & Assembler | Decoding bytes to instructions (Zydis/Capstone) and encoding patches (Keystone) behind one interface. |
| 3 | Binary Loading & Formats | Loading PE/ELF/Mach-O/raw, arch detection, uniform VA↔offset math, in-memory patching. |
| 4 | Static Code Analysis | Function discovery, **name guessing**, CFG, xrefs, symbols, and capability detection. |
| 5 | Decompiler & Data-Flow | Dominator-based structuring + a data-flow pass producing readable pseudo-C. |
| 6 | The Live Win32 Debugger | Threaded event loop, breakpoints, stepping, conditions, WOW64, and the debugging UI. |
| 7 | The Binary View Workspace | The centerpiece: six main views, side panel, lower sub-tabs, navigation, annotations, patching, and source export. |
| 8 | The Other Workbench Tabs | Projects, Communications, Sig Scanner, Memory Tools, Binary Diff, Binary Tech. |
| 9 | Persistence, Projects & Reporting | Hash-keyed JSON sidecars, recents, ASM/C source export, and Markdown/HTML reports. |
| 10 | UI, Theming & Fonts | Eight palette-derived themes, semantic colour accents, and the font system. |
| 12 | Build, Testing & Verification | One static self-contained exe, and how the Core logic is unit-tested off-target. |
| 13 | Appendix | Source-coverage map, heuristic-output honesty, explicit non-goals, and roadmap. |

---
## 01. Architecture & Application Shell

DisasmStudio is a single-process, immediate-mode desktop application. There is no
web server, no embedded scripting runtime, and (by explicit design) no plugin API.
Everything runs in one Win32 process that owns a hardware Direct3D 11 device, drives
a Dear ImGui UI at the display refresh rate, and hangs all functional surfaces off a
fixed, browser-style top tab strip. This chapter covers the lowest two layers of the
stack: the **Win32 + D3D11 host** (`src/main.cpp`) and the **application shell**
(`src/App.h`, `src/App.cpp`, `src/Tabs/ITab.h`, `src/resource.h`, `src/app.rc`).

### The Win32 + Direct3D 11 host (`main.cpp`)

The program entry point is `wWinMain`. It is a Unicode `WinMain`, so the binary is a
GUI subsystem app (no console). `CommandLineToArgvW` reads an optional first target
argument and converts it to the UTF-8 path representation used by the loader; after
UI initialization that path is opened through the same `loadBinaryPath` flow as the
File menu. The rest of the flow is the canonical Dear ImGui
`example_win32_directx11` skeleton, adapted for this project:

1. **Register the window class** (`WNDCLASSEXW` with class name `DisasmStudioWnd`,
   `CS_CLASSDC`, `WndProc`). The class is given the embedded application icon: the
   large icon (`hIcon`) for alt-tab/taskbar and a separately sized small icon
   (`hIconSm`, sized via `GetSystemMetrics(SM_CXSMICON/SM_CYSMICON)`) for the
   window caption. Both come from resource `IDI_APPICON` via `LoadImageW` (see the
   icon section below).
2. **Create the top-level window** (`CreateWindowW`, `WS_OVERLAPPEDWINDOW`, initial
   1600×960) and **create the D3D11 device** (`CreateDeviceD3D`). On device-creation
   failure the code cleans up and returns `1` — there is no software-only ImGui
   fallback path.
3. The window is then shown **maximized** (`SW_SHOWMAXIMIZED`), matching the "fixed
   single full-window" UX intent.
4. **ImGui setup**: create the context; enable keyboard navigation, platform viewports,
   docking support, and `DpiEnableScaleViewports`; and point `io.IniFilename` at the
   durable `%APPDATA%\DisasmStudio\imgui.ini`. The app-owned workbench geometry remains
   explicit, while ImGui can preserve platform-window state and logical DPI geometry.
5. **Backends**: `ImGui_ImplWin32_Init(hwnd)` and `ImGui_ImplDX11_Init(device, ctx)`.
6. **Fonts** (`src/Ui/Fonts.h` globals `ds::ui::gUiFont` / `ds::ui::gMonoFont`): the
   host prefers crisp Windows system fonts — `segoeui.ttf` at `17px*dpi` for the
   proportional UI font and `consola.ttf` (or `cour.ttf`) at `16px*dpi` for the monospace
   code/hex font — checking each file exists first and falling back to the ImGui
   built-in font. The monospace handle may be null, in which case `PushMono()`
   callers fall back to the default font. This is why disassembly/hex views stay
   aligned: they explicitly push the monospace face.

`CreateDeviceD3D` builds a `DXGI_SWAP_CHAIN_DESC` with **two back buffers**,
`DXGI_FORMAT_R8G8B8A8_UNORM`, a 60 Hz refresh descriptor, and
`DXGI_SWAP_EFFECT_DISCARD`. It calls `D3D11CreateDeviceAndSwapChain` first with
`D3D_DRIVER_TYPE_HARDWARE` (the project's "must be GPU-accelerated" requirement), and
only if that returns `DXGI_ERROR_UNSUPPORTED` does it retry with
`D3D_DRIVER_TYPE_WARP` (Microsoft's software rasterizer) as a graceful degrade.
Feature levels requested are 11.0 then 10.0. `D3D11_CREATE_DEVICE_DEBUG` is added only
in `_DEBUG` builds. The render-target view is created from back-buffer 0 in
`CreateRenderTarget`.

**The render loop** is a classic `PeekMessage` pump:

- Drain all pending Win32 messages (`PeekMessage`/`TranslateMessage`/`DispatchMessage`);
  `WM_QUIT` ends the loop.
- **Deferred DPI rebuild**: after message draining and before a new ImGui frame, consume
  only the latest queued DPI, invalidate the old DX11 font objects, rebuild the atlas,
  rederive absolute theme metrics, and recreate the font texture. Failed creation remains
  queued and is retried without rendering against a missing texture.
- **Occlusion skip**: if the swapchain was occluded last frame and a
  `Present(0, DXGI_PRESENT_TEST)` still reports `DXGI_STATUS_OCCLUDED` (e.g. window
  minimized/covered), it `Sleep(10)`s and continues without rendering — saving GPU
  while hidden.
- **Deferred resize**: `WM_SIZE` only stashes the new width/height in
  `g_ResizeWidth/Height`; the loop performs the actual `ResizeBuffers` +
  `CreateRenderTarget`. If `ResizeBuffers` fails (device removed/reset), the RTV is
  left null and the frame is skipped rather than binding a dead target.
- **Frame**: `ImGui_ImplDX11_NewFrame` → `ImGui_ImplWin32_NewFrame` → `ImGui::NewFrame`
  → `app.render()` → (exit check) → `ImGui::Render`. If the RTV is valid it is bound
  and cleared to a near-black color `(0.07, 0.08, 0.10)` (pre-multiplied by alpha),
  then `ImGui_ImplDX11_RenderDrawData` draws the UI.
- **Present** with `Present(1, 0)` — vsync **on** — and the occluded flag is updated
  from the result. Vsync caps the frame rate to the display, keeping the app smooth
  without spinning the GPU.

`WndProc` first forwards every message to `ImGui_ImplWin32_WndProcHandler` so ImGui
receives input. It then handles `WM_SIZE` (ignoring `SIZE_MINIMIZED`), suppresses the
ALT application menu (`WM_SYSCOMMAND` / `SC_KEYMENU` returns 0 so ALT-key chords like
`Alt+←/→` are free for navigation), and posts quit on `WM_DESTROY`. For
`WM_DPICHANGED`, it applies Windows' suggested rectangle and stores only the latest DPI;
font/style/DX11 resource mutation remains outside `WndProc` at the between-frame boundary.

#### Embedded application icon (`app.rc`, `resource.h`)

`src/resource.h` defines exactly one identifier: `IDI_APPICON = 101`. The comment
notes it is intentionally the lowest-numbered icon resource so Windows Explorer uses
it as the executable's shell icon. `src/app.rc` declares
`IDI_APPICON ICON "app.ico"` (a multi-resolution `.ico`, regenerated by
`gen_app_icon.ps1`) plus a `VS_VERSION_INFO` block (file/product version `1.0.0.0`,
company/product `DisasmStudio`, `OriginalFilename DisasmStudio.exe`). The icon is thus
embedded into the EXE and loaded at startup for window, taskbar, and alt-tab use.

### The application shell: `App` and `AppContext`

`ds::App` is the top-level controller, instantiated once on the stack in `wWinMain`.
Its constructor (`App()`):

- `loadPrefs()` reads `%APPDATA%/DisasmStudio/prefs.ini` (bounded theme/density,
  opt-in symbol policy/cache, and recent-investigation settings) and
  `theme::ApplyTheme(theme_)` restyles ImGui.
- `ctx_.rebuildDisassembler()` builds the initial disassembler.
- It constructs the fixed top-level workbench tabs and stores them as
  `std::vector<std::unique_ptr<ITab>>`: Projects, Communications, Connections,
  Sig Scanner, Binary View, Memory Tools, Binary Diff, Binary Tech, Cortex, and Prism.
  This vector *is* the top tab-strip order.

The destructor (`~App()`) calls `ctx_.saveProject()` so analysis is flushed when the
window closes (Alt+F4 / WM_DESTROY path).

#### `AppContext` — the single shared-state struct

`AppContext` is passed **by reference** to every tab's `render` each frame; it is the
app's shared blackboard. Key members:

- `BinaryFile binary` — the loaded target (PE/ELF/Mach-O/raw); see chapter on loaders.
- `Debugger debug` — the live Win32 debugger (own thread, lock-guarded snapshot).
- `CodeExportService codeExport` — a dedicated one-job source-export worker. It builds
  an independent decoder and streams ASM/C without borrowing the UI decoder or occupying
  the load-time analysis worker.
- `Engine engine` (default `Zydis`), `Arch arch` (default `X64`),
  `std::unique_ptr<IDisassembler> disasm` — the active decode engine. Note the
  Debugger owns its **own** decoder and is *not* wired to the UI's `disasm`.
- `ProjectState project` — the per-binary analysis sidecar (comments, renames,
  bookmarks, breakpoints, patches, notes, cursor, and raw mapping identity), persisted as
  versioned JSON keyed by content hash.
- **Cross-tab request flags**: `requestedTab` (name of a tab to switch to next
  frame), `requestedLiveAssembly`, `requestedExportAnalysis`, `requestedCodeExport`
  plus `requestedCodeExportFormat`, `requestedDebugDll`, the trace toggle/clear/cancel
  flags, `binaryJustLoaded`, and `pendingSignature`
  (Binary View → Sig Scanner pattern handoff).
- **Go-to plumbing**: `requestedGotoVA` + `hasGotoRequest` (the bool distinguishes
  "go to VA 0" from "no request"). The helper `gotoAddress(va)` sets both and forces
  `requestedTab = "Binary View"` — this is the single canonical way any tab asks the
  app to focus an address.
- **Cursor mirroring**: `cursorVA`, `hasCursor`, `cursorFuncName` (enclosing function),
  and `runtimeCursorVA` (ASLR-translated address for "Run to Cursor"). Binary View's
  real cursor is private; it copies it here each frame so the status bar and debug
  toolbar can read it without reaching into the tab.

`AppContext` also owns the high-level commands shared across tabs:
`rebuildDisassembler()` (`disasm = MakeDisassembler(engine, arch)`), `openBinaryDialog()`
(Win32 `commdlg` open), `loadBinaryPath()`, `loadRawPath()`, `saveProject()`,
`exportAnalysisFile()`, `selectCodeExportPath()`, `openLiveAssemblyView()`, and the private
`loadProjectForBinary()`.

Direct launch eligibility deliberately distinguishes PE executables from DLLs:
`binaryLaunchable()` excludes `IMAGE_FILE_DLL`, while `binaryDllDebuggable()` requires
a file-backed x86/x64 PE DLL. The latter routes to the App-owned Debug DLL modal and
the validated hosted-launch plan instead of ever passing a DLL to `CreateProcessW`.

#### Binary loading & project lifecycle

`loadBinaryPath(path)` is the spine of opening a file:
1. `saveProject()` first — persist the **outgoing** target's analysis before swapping.
2. Drain both image readers: `codeExport.cancelAndWaitIdle()` cancels any source export,
   then `analysis.cancelAndWaitIdle()` drains load-time analysis before bytes are replaced.
3. `binary.load(path)`; on failure return false.
4. `arch = archFromMachine(binary.machine(), binary.is64Bit())` — the architecture is
   auto-selected from the file header (the `archFromMachine` switch maps every
   `MachineArch` to an `Arch`, defaulting to x64/x86 by bitness).
5. `rebuildDisassembler()`, then `loadProjectForBinary()` to restore the sidecar.
6. `binaryJustLoaded = true` so Binary View re-homes to the entry point and re-analyzes.

The export request holds a borrowed `BinaryFile*`, so that first drain is a lifetime
requirement, not just a stale-result optimization. `expectedImageRevision` rejects work
whose image revision changed at safe checkpoints, but never substitutes for joining the
worker before load, close, patch, or another mutation that may reallocate image storage.

`loadProjectForBinary(applySavedArchEngine=true)` resets `project`, hashes the binary
(`binary.contentHash()`), and `LoadProject(h, loaded)`. If a saved sidecar exists and
`applySavedArchEngine` is true, the **saved engine/arch are reapplied** (via
`ArchFromName`/`EngineFromName` + `rebuildDisassembler`) so a binary reopens exactly as
last analyzed. For a raw candidate, a valid saved base, explicit entry, and named landmark
set are re-staged before VA-keyed annotations are restored; corrupt saved mapping metadata
is ignored rather than shifting annotations or making the file unopenable. It then stamps
fresh metadata (hash, path, arch/engine names, display name, `lastOpenedUnix`).

`loadRawPath(path, base, arch)` is the "Open as Raw" path: it calls `binary.loadRaw`,
sets the user-chosen arch, and calls `loadProjectForBinary(false)` so the **dialog's
arch choice wins** over any saved value.

`saveProject()` is a no-op unless a binary is loaded with a non-zero hash; it refreshes
the persisted arch/engine (so an Engine-menu change since load is captured) and calls
`SaveProject(project)`.

### Per-frame rendering: `App::render()`

Called exactly once per loop iteration, `render()` draws the shell top-to-bottom:
`renderMenuBar()` → `renderDebugToolbar()` → `renderMainWindow()` → `renderStatusBar()`
→ `renderRawLoadPopup()` → `renderDllDebugPopup()` → `renderSaveResultPopup()`, plus the optional ImGui demo and
About windows. The three full-width bars are positioned manually against
`ImGui::GetMainViewport()` work area: a debug toolbar pinned to the top, the tab window
filling the middle, and a status bar pinned to the bottom. All three are flagged
`NoTitleBar | NoResize | NoMove | NoSavedSettings | NoDocking` (the main window adds
`NoBringToFrontOnFocus | NoNavFocus`) and pushed to `WindowRounding = 0` so they read
as fixed chrome, not floating panels.

#### Menu bar (`renderMenuBar`)

A standard `BeginMainMenuBar`:

- **File**: *Open Binary…* (Ctrl+O, `openFileDialog`), *Open as Raw…*
  (`openRawFileDialog`), *Debug DLL…* (only for a validated file-backed x86/x64 PE
  DLL), *Save Binary As…* (enabled only when loaded; splices
  accumulated patches — see below), *Export Analysis…* (sets
  `requestedExportAnalysis` + switches to Binary View, which produces the report),
  *Close Binary* (flush, `binary.clear()`, `project.reset()`), and *Exit* (flush +
  `exit_=true`). Disabled items carry hover tooltips (`AllowWhenDisabled`).
- **Engine**: Zydis / Capstone toggle and an Architecture submenu (x86, x64, ARM,
  ARM64, MIPS, MIPS64, PowerPC, PowerPC64, RISC-V 32, RISC-V 64). For non-x86 arches
  Zydis is disabled (it decodes x86/x64 only) and the check marks reflect the
  **effective** engine (`disasm->engine()`), so the menu never disagrees with what is
  actually decoding. Any change calls `rebuildDisassembler()`.
- **View**: Theme submenu (iterates `theme::ThemeId` up to `Count`, applies + persists
  via `savePrefs()`) and an *ImGui Demo* toggle.
- **Help**: *Keyboard Shortcuts* (F1, a grouped global/debugger/navigation/view
  reference) and *About* (version, feature overview, and runtime stack).
- A right-aligned status string (`Engine: … | <format or "no binary">`) is laid out by
  measuring text width and `SameLine`-offsetting from the window width.

#### Debug toolbar (`renderDebugToolbar`)

A full-width borderless window at the top. It reads a `DbgSnapshot` from the Debugger
and branches on attach state. When detached: an executable shows **Launch & Debug**
(calls `debug.launchAndAttach`), while a DLL opens **Debug DLL…** instead; successful
launches open the live assembly view and failures become toasts. Otherwise it shows a hint to attach via the
Communications tab. When attached it shows **Detach**, **Continue/Pause** (label and
color flip with run state), **Step Into / Step Over / Step Out / Run to Cursor** (the
stepping buttons disabled unless paused), plus **Trace / Clear Trace**. Trace is
startable only while paused with an analyzed image, remains stoppable during discovery
or planting, and forwards its request to Binary View's incremental block planner. A live status line shows PID, bitness,
state, RIP/EIP, RSP/ESP, and the last debug event. Keyboard shortcuts are bound here
(only when ImGui is not capturing text input): **F5** continue/pause, **F11** step
into, **Shift+F11** step out, **F10** step over, **Ctrl+F9** run to cursor (using
`runtimeCursorVA`). A `cbutton` lambda gives each button a base color plus auto
hover/active tints and an optional tooltip.

#### Main window & the tab strip (`renderMainWindow`)

This realizes the "browser-style single window, no docking" design. One fixed
full-size child window holds an `ImGui::BeginTabBar` (`Reorderable | FittingPolicyScroll`).
It iterates `tabs_` and, for each, checks whether `ctx_.requestedTab == tab->name()`;
if so it passes `ImGuiTabItemFlags_SetSelected` (programmatic tab switch) and clears
the request. The selected tab's content is rendered inside a padded child
(`##tabcontent`) via `tab->render(ctx_)`. There is no docking, no tear-off, no floating
windows — tabs always live in the same place.

#### Status bar (`renderStatusBar`)

A bottom bar with a hand-drawn colored **state dot** (drawn with
`AddCircleFilled` so it needs no font glyph) reflecting debug state (muted/green/amber/red
→ detached/running/paused/bad), the state word, PID/RIP when attached, the engine name,
the arch name, the loaded file's base name + format, and — when `hasCursor` — the cursor
VA and enclosing function name. It reads everything from `ctx_`; the cursor info is the
mirrored copy Binary View writes each frame.

#### Modal popups

`renderRawLoadPopup` is the "Open as Raw" modal: it shows the chosen file, a base-address
hex input (accepts `0x`-prefixed or bare hex via `sscanf("%llx")`), and
x86-16/x86/x64/A32/Thumb/A64 radio buttons, then calls `loadRawPath` and switches to Binary View. The chosen architecture
is retained as the exact worker/discovery architecture; the loader creates the complete
executable `.raw` section and rejects a base+length range that would overflow. `renderSaveResultPopup`
shows the result message from *Save Binary As…*.

`renderDllDebugPopup` inspects the current image with `InspectDllForDebug`, offers a
callable export and user arguments, selects the bitness-matched trusted system
`rundll32.exe` or a browsed/bitness-checked custom host, and lets the analyst arm
DllMain and/or export stops. It displays planning warnings/errors before enabling
launch, then calls `Debugger::launchAndAttachDll` with the Windows-quoted plan.

#### Save Binary As — patch splicing

`saveBinaryAs()` opens a save dialog and calls the free function `buildPatchedImage`,
which copies `binary.bytes()` and, for each accumulated `PjPatch`, resolves its VA to a
file offset with `BinaryFile::vaToOffset`; patches that don't map or run past the buffer
are skipped and counted. The result is written to disk and the modal reports
"Wrote N bytes with M patch(es) applied[, K unmapped/skipped]". This is how
user edits become a real on-disk modified binary.

### The `ITab` contract & tab dispatch

`src/Tabs/ITab.h` defines a minimal interface: a virtual destructor,
`const char* name() const`, and `void render(AppContext& ctx)`. Each concrete tab
(`ProjectsTab`, etc.) is a `final` class deriving from `ITab`, returning its display
name and rendering itself given the shared context. The App owns the tabs as
`unique_ptr`s and dispatches them polymorphically inside the tab bar each frame. The
name string is doubly load-bearing: it is both the tab label *and* the key used by
`requestedTab` for cross-tab navigation — so `gotoAddress`, `openLiveAssemblyView`,
and the File-menu commands all coordinate purely through these string names plus the
boolean request flags on `AppContext`.

### Data flow & frame contract (summary)

Each frame: tabs read `ctx_` to render and write request flags / mirror state back
into it; the App consumes those flags (e.g. clears `requestedTab` when it switches a
tab, Binary View consumes `requestedGotoVA`/`binaryJustLoaded`/`requestedExportAnalysis`
and writes back `cursorVA`/`hasCursor`/`runtimeCursorVA`). Because everything is
immediate-mode and single-threaded on the UI side, this "set a flag this frame, consume
it next frame" handshake is the entire inter-tab messaging system — there are no
signals, callbacks, or event queues. Background concurrency lives in the `Debugger` and
the epoch-guarded `AnalysisService`; the latter runs the same selected-architecture
function/string/listing pipeline for structured and raw images.

#### Limitations & notes

- **App-owned workbench layout**: the bars/panels are explicitly positioned rather than
  exposed as a user dockspace; ImGui's platform/layout state still persists in its ini file.
- **No plugin/scripting API**: excluded by project spec; the shell offers no extension
  point — tabs are compiled in.
- ImGui platform viewports and DPI geometry scaling are enabled, while the workbench's
  browser-style panel arrangement remains an explicit app layout rather than a user dockspace.
- **Hardware-first, WARP fallback**: if no D3D11 hardware device is available the app
  silently falls back to the WARP software rasterizer; if even that fails, startup aborts.
- `Open as Raw` exposes **x86-16/x86/x64/A32/Thumb/A64** directly. The Engine menu offers
  more architectures (MIPS/PPC/RISC-V); raw blobs of those architectures
  would need the Engine-menu arch switch after loading.
- The base-address parser in the raw popup tolerant-parses hex and does not reason about
  overlap with another real image; `BinaryFile` still rejects a flat range whose final VA
  would overflow.
- Cross-tab state is a per-frame flag handshake, not a robust event bus; it works
  because the whole UI is single-threaded immediate mode, but it means requests are
  effectively "fire on the next frame" and one-shot.
## 02. Disassembly Engines & Assembler

This chapter covers the lowest layer of DisasmStudio's analysis stack: the code that turns raw bytes into decoded instructions, and the inverse path that turns typed assembly text back into bytes for patching. Everything above it — the function analyzer, CFG builder, call-graph, decompiler, xref engine, and the entire Binary View listing — consumes the small, engine-neutral data type defined here. The design goal is simple but load-bearing: **the rest of the app must never know or care whether a given instruction was decoded by Zydis or Capstone.** All of the source for this subsystem lives under `src/Disasm/`.

### The engine-agnostic interface (`IDisassembler.h`)

The contract is a pure virtual class, `ds::IDisassembler` (in `src/Disasm/IDisassembler.h`). It exposes only four methods:

- `Engine engine() const` and `const char* engineName() const` — identity, used for display and per-project persistence.
- `std::vector<Instruction> disassemble(const uint8_t* data, size_t size, uint64_t virtualAddress, size_t maxInstructions = 0)` — bulk-decode a buffer starting at a virtual address, stopping after `maxInstructions` (0 = "until the buffer is exhausted").
- `bool decodeOne(const uint8_t* data, size_t size, uint64_t virtualAddress, Instruction& out)` — decode exactly one instruction, returning `false` on a decode error.

The UI and Core always hold an `IDisassembler*` (or `std::unique_ptr<IDisassembler>`) and never `#include` a concrete backend. That keeps Zydis/Capstone headers out of the rest of the build and means a binary's engine can be swapped at runtime without touching call sites.

#### The `Instruction` model

The single struct every consumer sees is `ds::Instruction`, deliberately minimal and render-ready:

| Field | Type | Meaning |
|---|---|---|
| `address` | `uint64_t` | virtual address of the instruction |
| `length` | `uint32_t` | size in bytes |
| `bytes` | `std::string` | hex byte string, e.g. `"48 89 5C 24 08"` |
| `mnemonic` | `std::string` | e.g. `"mov"` |
| `operands` | `std::string` | e.g. `"rbx, [rsp+0x8]"` |
| `isBranch` | `bool` | any jmp/jcc/call/ret-family instruction |
| `isCall` | `bool` | call instruction |
| `isRet` | `bool` | ret/retf/iret family (returns from a call frame) |
| `isRepString` | `bool` | carries a REP/REPE/REPNE prefix (`rep movs/stos/cmps/scas/…`) |
| `branchTarget` | `uint64_t` | resolved absolute target if statically known, else 0 |

Two design choices are worth calling out. First, the text fields (`bytes`, `mnemonic`, `operands`) are already **formatted as strings** rather than carrying structured operand data — the UI renders them directly, and higher layers that need structure (e.g. the decompiler's operand lifter) re-parse the text. This keeps the struct cheap to copy and the interface trivial. Second, the four boolean flags plus `branchTarget` are the *only* semantic signals the CFG, call-graph, xref, function-discovery, and goto-navigation subsystems get. Getting these right across every architecture is therefore critical, and both backends go out of their way to normalise them (see below).

#### The `Arch` and `Engine` enums and helpers

`enum class Arch { X86_16, X86, X64, ARM, THUMB, ARM64, MIPS, MIPS64, PPC, PPC64, RISCV32, RISCV64, JVM }` enumerates every supported architecture and decoder mode; `enum class Engine { Zydis, Capstone }` the two native backends. A32 and Thumb remain distinct fixed modes, and explicit capability helpers gate x86-only decompilation/debugging versus x86/x64/A32/Thumb/A64 assembly. Several free helpers in the same header glue this to the rest of the app:

- `ArchIsX86(Arch a)` — `true` only for `X86`/`X64`. This single predicate drives backend routing (the factory) *and* assembler capability checks.
- `ArchName(Arch)` / `ArchFromName(const char*, Arch&)` — a name↔enum pair (e.g. `"RISC-V 32"` ↔ `RISCV32`). The inverse exists specifically so the chosen architecture can be saved into the per-binary JSON sidecar and restored exactly on reopen.
- `EngineNameOf(Engine)` / `EngineFromName(const char*, Engine&)` — the same round-trip for the engine choice.

The architecture is normally auto-selected from the loaded image header (`BinaryFile::machine()`), and non-x86 images route to Capstone automatically.

### The Zydis backend (x86/x64 only)

`ds::ZydisDisassembler` (`src/Disasm/ZydisDisassembler.{h,cpp}`) is the fast path for the common case. It is intentionally header-light: the Zydis types live behind an opaque `struct ZyState` (a `ZydisDecoder` + `ZydisFormatter`) held via `unique_ptr`, so `ZydisDisassembler.h` doesn't drag the Zydis headers into every translation unit that decodes.

The decoder and formatter depend only on the architecture, so they are **built once in the constructor and reused for every instruction** — a deliberate amortisation that matters when decoding very large listings. The constructor maps `Arch::X86` → `ZYDIS_MACHINE_MODE_LEGACY_32` + `ZYDIS_STACK_WIDTH_32` and everything else → `ZYDIS_MACHINE_MODE_LONG_64` + `ZYDIS_STACK_WIDTH_64`, and initialises the formatter to Intel syntax (`ZYDIS_FORMATTER_STYLE_INTEL`).

`decodeOne` calls `ZydisDecoderDecodeFull`, then formats into a 256-byte stack buffer with `ZydisFormatterFormatInstruction`. A subtle but important detail: the mnemonic is taken from Zydis *metadata* (`ZydisMnemonicGetString(insn.mnemonic)`), **not** by splitting the formatted string on the first space. The formatted text prefixes legacy-prefix tokens (`rep`, `lock`, `bnd`, …), so a naive first-space split would treat the prefix as the mnemonic (`"rep movsb"` → `"rep"`). The code finds the real mnemonic inside the formatted string and slices the remainder as `operands`, falling back to a first-space split only if the mnemonic string is unavailable.

Semantic flags come from Zydis's instruction category metadata:
- `isCall` ← `ZYDIS_CATEGORY_CALL`, `isRet` ← `ZYDIS_CATEGORY_RET`.
- `isBranch` ← call OR ret OR `COND_BR` OR `UNCOND_BR`.
- `isRepString` ← the `HAS_REP | HAS_REPE | HAS_REPNE` attribute bits. This flag exists so the debugger's step-over/step-out logic treats a `rep`-prefixed string op as one unit instead of single-stepping each iteration.
- `branchTarget` ← for each visible operand that is a *relative* immediate, `ZydisCalcAbsoluteAddress` resolves it to an absolute VA.

### The Capstone backend (everything else)

`ds::CapstoneDisassembler` (`src/Disasm/CapstoneDisassembler.{h,cpp}`) covers ARM, ARM64, MIPS/MIPS64, PPC/PPC64, RISC-V 32/64 — and can also handle x86/x64 if explicitly requested. `open()` maps `Arch` to Capstone's `cs_arch`/`cs_mode` pairs, enables full detail (`CS_OPT_DETAIL`), and pre-allocates **one reusable `cs_insn` scratch buffer via `cs_malloc`** so the decode loop uses `cs_disasm_iter` without a per-instruction malloc/free. The handle and scratch are stored as opaque `uintptr_t`/`void*` to keep the header clean.

One real-world correctness fix is baked in: every loadable image in this tool is little-endian (the ELF loader requires `ei_data==1`, Mach-O requires the LE magic, PE is LE), so PPC/PPC64 are opened with `CS_MODE_LITTLE_ENDIAN` rather than the old big-endian default, which had mis-decoded every loadable PPC binary (notably ppc64le ELF).

Because Capstone's generic groups don't cover every architecture's idioms, the backend does extra normalisation in `fillInstruction`:

- **Flags from groups:** `CS_GRP_CALL` → `isCall`+`isBranch`; `CS_GRP_RET` → `isRet`; `CS_GRP_JUMP`/`CS_GRP_RET`/`CS_GRP_BRANCH_RELATIVE` → `isBranch`.
- **Return detection by mnemonic** (`arch != X86/X64`): Capstone's generic `CS_GRP_RET` does not fire for several non-x86 returns, so they are detected textually — MIPS `jr $ra`, PPC `blr`/`blrl`/`bclr`, ARM `bx lr` / `pop {…pc}` / `ldm…{…pc}` / `mov pc, lr`, RISC-V `ret` / `jr ra` / `jalr zero, ra`. This is what keeps CFG block boundaries and step-out classification correct under Capstone for every architecture.
- **`branchTarget`** is read from the first immediate operand in the arch-specific detail union (`cs_x86`/`cs_arm64`/`cs_arm`/`cs_mips`/`cs_ppc`/`cs_riscv`) via `branchTargetFor`. Capstone resolves relative branches to absolute addresses for every architecture, so this yields the same `branchTarget` the Zydis path produces for x86 — and extends it to A32/Thumb/A64/MIPS/PPC/RISC-V, which is exactly what CFG, xref, call-graph, and goto navigation depend on.
- **`isRepString`** is computed only for x86/x64 via `isRepStringInsn`, which checks both the group-1 prefix byte (`cs_x86.prefix[0]`) *and* a `"rep"`-prefixed mnemonic, then requires a real string-op base (`movs/stos/cmps/scas/lods/ins/outs`) to avoid mis-flagging SSE instructions that carry a mandatory `0xF2`/`0xF3`.

### `decodeOne` vs `disassemble`, and never-stall decoding

`decodeOne` is the surgical path: one instruction from a buffer, `false` on failure. The debugger's live assembly, step logic, and lazy 4 KiB listing-page materializer use it. `disassemble` remains the caller-bounded bulk path for analysis and export work.

Both backends share a **resync-on-error** strategy so malformed input never stalls the stream. x86 emits a one-byte synthetic `db`; fixed-width/halfword-aligned ARM-family modes consume an architecture-aligned fallback unit so one invalid word cannot shift every subsequent decode off its legal boundary. The lazy listing uses the same rule. Bulk `disassemble` calls still honour their caller-provided `maxInstructions`; the virtual full-program listing instead bounds work per requested page and has no global instruction-count cap.

### Backend selection (`DisassemblerFactory`)

`ds::MakeDisassembler(Engine engine, Arch arch)` (`src/Disasm/DisassemblerFactory.cpp`) is the only place a concrete backend is constructed. Its routing rule is blunt and safe:

```
if (!ArchIsX86(arch)) return CapstoneDisassembler(arch);   // forced
switch (engine) { Zydis -> ZydisDisassembler; Capstone -> CapstoneDisassembler; }
```

For any non-x86 architecture the requested engine is **ignored** and Capstone is forced — because Zydis can only decode x86/x64, and silently routing, say, ARM bytes through it would mis-decode them as x64. For x86/x64 the user/project preference (Zydis or Capstone) is honoured. This is why x86/x64 is the only place "which engine" is even a meaningful choice.

### The Keystone assembler (patching)

`ds::Assemble(Arch arch, const std::string& text, uint64_t address)` (`src/Disasm/Assembler.{h,cpp}`) is the inverse path — a thin wrapper over Keystone used by Binary View's live "Patch" feature (type `mov rax, 1`, get bytes). It returns an `AsmResult { bool ok; std::vector<uint8_t> bytes; size_t count; std::string error; }`: the encoded bytes, the number of statements encoded, and a human-readable error when `ok` is false. It accepts one or more instructions separated by `;` or newline, uses Intel syntax, and resolves relative operands against the supplied `address` (so a `jmp`/`call` patch lands correctly at its in-memory location).

The crucial asymmetry: **the assembler supports only x86/x64/A32/Thumb/A64.** Keystone has no enabled encoder for MIPS/PPC/RISC-V here, so unsupported architectures return immediately with a clear error rather than being mis-encoded. NOP fill is also ISA-aware: A32, Thumb, and A64 use their architectural fixed-width encodings and reject spans that split an instruction. Keystone init failures and assembly errors are surfaced as readable strings, and the engine handle and encoded buffer are freed on every exit path. Disassembly coverage remains broader than assembly coverage.

### Performance characteristics

- Zydis and Capstone both build their decoder/formatter (and Capstone its scratch `cs_insn`) **once per instance**, so the hot decode loop allocates nothing per instruction.
- The `Instruction` struct is small and string-based; bulk `disassemble` returns a `std::vector<Instruction>` sized to the work.
- Resync-on-error keeps worst-case decoding linear in bytes even on data-heavy regions.

#### Limitations & notes

- **Engine choice only matters for x86/x64.** All other architectures are forced to Capstone by the factory; the requested `Engine` is ignored for them.
- **Assembly is narrower than disassembly.** Keystone here supports only x86/x64/A32/Thumb/A64; patching any other arch fails with a clear "unsupported" message — by design, not a bug.
- **Operands are formatted strings, not structured data.** Consumers needing operand structure re-parse the text; the model carries no per-operand type/size information.
- **`branchTarget` is best-effort and static.** It is non-zero only when the target is a statically resolvable relative/immediate (register-indirect, memory-indirect, and computed jumps resolve to 0). Indirect control flow is handled by higher layers (e.g. jump-table recovery), not here.
- **PPC is decoded little-endian** to match every loadable image; big-endian PPC images are out of scope of the loaders, so this is consistent rather than a restriction in practice.
- Undecodable bytes surface as synthetic `db 0xNN` pseudo-instructions; these are real entries in the listing, not silent gaps.
## 03. Binary Loading & Formats

Everything in DisasmStudio starts with a file becoming a `BinaryFile`. This one class
(`src/Core/BinaryFile.h`, `src/Core/BinaryFile.cpp`) is the single source of truth for
*what the bytes are*: which executable format, which CPU architecture, where the image is
based, where it starts executing, how its sections map between file offsets and virtual
addresses, what it imports/exports, and a stable content hash that keys all persisted
analysis. It uses only the C++ standard library (including `<filesystem>` for durable
Unicode paths), so it can be unit-tested standalone with no Windows/ImGui/Capstone
dependencies.

### Supported formats and detection

`load(path)` slurps the whole file into a single `std::vector<uint8_t> data_` in one read
(seek-to-end to size it, then one `read`), then sniffs the format by magic bytes:

- **`MZ`** at offset 0 → attempt `parsePE()` (PE32 / PE32+).
- **`\x7FELF`** at offset 0 → attempt `parseELF()` (ELF32 / ELF64, little-endian only).
- **`0xFEEDFACE` / `0xFEEDFACF`** little-endian at offset 0 → attempt `parseMachO()` (thin
  Mach-O 32 / 64).
- **`0xCAFEBABE`** → attempt `parseJavaClass()` (method-code sections backed by the parsed
  Java class model).
- Anything else → `BinFormat::Raw`.

The key robustness convention: if a recognized magic is present but the structured parse
*fails*, the format silently degrades to `BinFormat::Raw` rather than refusing the file
(`if (!parsePE()) format_ = BinFormat::Raw;`). A truncated or malformed
PE/ELF/Mach-O/Java class still loads through the same complete raw-image model described
below. `load()` only returns `false` for I/O failures (missing file, empty file, short read)
or an unrepresentable flat address range, never merely for a parse mismatch. Successful file and raw loads retain a canonical
absolute UTF-8 path, so recents/debug launch remain valid after working-directory changes.

`loadRaw(path, base)` is the explicit **Open as Raw…** path: no header parsing at all, the
caller supplies the load `base`, `format_ = Raw`, and `entryRVA_ = 0` (there is no
fabricated header entry point). `initializeRawLayout` creates one executable/readable code
section named `.raw`, with virtual/file offset zero and both sizes covering the complete
blob. Function discovery treats the analyst-selected base as an explicit root even when it
is VA 0; the separately selected `Arch` is passed to the worker decoder and gates
architecture-specific discovery. Consequently raw images use the normal background string/
function/listing jobs and the same full-program listing, xrefs, call graph, navigation, and
patch mapping as structured images. This is the route for shellcode, firmware dumps, and
decrypted blobs. A load is rejected, without leaving partial state, if `base + size - 1`
would overflow `uint64_t`; a mapping ending exactly at `UINT64_MAX` remains valid.

`BinFormat` (`Unknown, PE32, PE32Plus, ELF, MachO, JavaClass, Raw`) and `formatName()`
give the UI a width-only format label like `"PE32+"` or `"Mach-O"`; the parsed machine architecture is displayed separately.

### Machine / architecture recovery

`MachineArch` (`X86, X64, ARM, ARM64, MIPS, MIPS64, PPC, PPC64, RISCV, RISCV64, JVM, Unknown`)
is recovered from the *format header*, not inferred from the 32/64-bit class. This matters
because an ARM64 ELF and an x64 ELF are both 64-bit — only the `e_machine` field
distinguishes them, and `machine()` is what lets the UI auto-select Zydis for x86/x64 and
route everything else to Capstone instead of wrongly defaulting to x86.

- **PE** reads the COFF `Machine` field: `0x014C`→X86, `0x8664`→X64, A32
  (`0x01C0`)→ARM, Thumb/ARMNT (`0x01C2/01C4`)→THUMB, `0xAA64`→ARM64, MIPS variants, PowerPC (`0x01F0/01F1`), and
  RISC-V (`0x5032`→RV32, `0x5064`→RV64).
- **ELF** reads `e_machine` at offset 18, mapping EM_386/EM_X86_64/EM_ARM/EM_AARCH64,
  EM_MIPS (64-bit-aware → MIPS64), EM_PPC/EM_PPC64, and EM_RISCV (→ RISCV64 when 64-bit).
  Unknown machines fall back to X64/X86 by `ei_class`.
- **Mach-O** reads `cputype`, mapping x86/x86_64/ARM/ARM64/PPC/PPC64, with the same
  64-vs-32 fallback.

ELF rejects big-endian outright (`ei_data != 1` → parse fails → degrades to Raw); this is a
stated limitation, not a bug.

### imageBase, entryPoint, and the imageBase_=0 convention

`imageBase()` and `entryPoint()` (the latter actually returns `entryRVA_`) describe where
the image loads and where it starts. The crucial design decision, called out in
`CLAUDE.md` and enforced here:

- **PE** keeps `imageBase_` as the real preferred load base (read from the optional header:
  8 bytes for PE32+, 4 for PE32) and stores **RVAs** in `Section::virtualAddress`.
- **ELF and Mach-O** keep `imageBase_ = 0` and store the **absolute** VM address in
  `Section::virtualAddress` (ELF `sh_addr`; Mach-O section `addr`).

Because every translation routine computes `rva = (va >= imageBase_) ? va - imageBase_ :
va`, setting `imageBase_ = 0` for ELF/Mach-O makes "rva == absolute va" — so the *same*
section-walk code handles all three formats uniformly. There is no per-format branch in the
hot translation path beyond the `Raw` special-case.

`entryRVA_` is the PE `AddressOfEntryPoint`, the ELF `e_entry`, or — for Mach-O — computed
from `LC_MAIN`'s `entryoff` (a *file* offset) translated through the `__TEXT` segment
(`textVmaddr + (entryFileoff - textFileoff)`), falling back to the first executable
section's VA when no `LC_MAIN` is present.

### Sections and the executable flag

Each `Section` carries `name`, `virtualAddress`, `virtualSize`, `rawOffset`, `rawSize`,
`characteristics`, and an `executable` bool. The parsers normalize the "is this code?"
decision per format:

- **PE**: `executable = characteristics & IMAGE_SCN_MEM_EXECUTE (0x20000000)`.
- **ELF**: `SHF_EXECINSTR (0x4)`. Non-allocated `.symtab`/`.strtab` sections are retained
  only in the bounded private header model needed for symbol parsing and are not mapped.
  `.bss` (`SHT_NOBITS`) keeps `rawSize = 0` so it is recognized as virtual-only padding.
- **Mach-O**: a section is executable if its segment is exec, or the section flags carry
  `S_ATTR_PURE_INSTRUCTIONS (0x80000000)` / `S_ATTR_SOME_INSTRUCTIONS (0x400)`, or the
  section is literally named `__text`.
- **Raw**: one synthetic `.raw` section spans every file byte and carries code/execute/read
  characteristics. It is deliberately complete so section-driven analysis does not need a
  separate raw-only path.

`firstCodeSection()` returns the first executable section, or — if none is flagged — the
first section, or `nullptr`. This is the default disassembly target when a binary opens.

A notable ELF resilience feature: if the section header table is missing or implausible
(`!e_shoff || !e_shnum || e_shnum > 4096`, i.e. a fully stripped binary), `parseELF()`
falls back to the **program header table** and synthesizes one `Section` per `PT_LOAD`
segment (using `p_vaddr/p_memsz/p_offset/p_filesz`, `PF_X` for executability) so the image
still maps and disassembles.

### VA ↔ file-offset translation

Four routines form the addressing core, and every other subsystem (disassembler, hex view,
string scanner, patcher, decompiler) goes through them:

- **`ptrFromVA(va, availOut)`** — VA → live pointer into `data_`, plus how many contiguous
  bytes are available. For `Raw`, it is just `data() + (va - base)`. For mapped formats it
  walks `sections_`, finds the containing section via *overflow-safe containment*
  (`rva >= s.virtualAddress && rva - s.virtualAddress < s.virtualSize` — the subtraction
  form avoids `base + size` wrapping on 64-bit ELF/Mach-O), returns `nullptr` if the VA
  falls in virtual padding (`delta >= rawSize`), and clamps both the returned base and the
  reported span to the bytes actually present so a malformed `rawOffset/rawSize` past EOF
  cannot over-read.
- **`ptrFromRVA(rva, availOut)`** — thin wrapper: `ptrFromVA(imageBase_ + rva, ...)`.
- **`offsetToVA(fileOffset, vaOut)`** — file index → VA. Used when something scans `data_`
  directly (strings, byte-pattern search) so reported hits line up with the disassembly
  instead of being mistaken for RVAs. It finds the section whose raw range contains the
  offset; for **PE only**, offsets before the first section's raw data are treated as
  headers mapping 1:1 (`offset == RVA`). For ELF/Mach-O an uncovered offset has no VA.
- **`vaToOffset(va, offOut)`** — the inverse, VA → file index, returning `false` for
  virtual-only padding or out-of-file VAs. This is what makes **patch-to-file** possible
  (see chapter on patching): a patch's VA must resolve to a concrete byte in a copy of the
  original file.

These routines are genuine inverses on backed bytes, which is exactly the property the Core
unit tests assert (round-tripping `vaToOffset`↔`offsetToVA`). The whole defensive style
here — the `rd<T>()` helper splits its bounds check into two halves
(`off <= size && sizeof(T) <= size - off`) precisely so a hostile `e_lfanew`/`e_shoff` near
`SIZE_MAX` cannot wrap the bound and trigger a wild `memcpy` — reflects that this code
parses untrusted, possibly adversarial binaries.

### contentHash — the persistence key

`contentHash()` is a 64-bit **FNV-1a** over the entire file, with the length mixed in at
the end so two blobs differing only by trailing zero padding still hash differently. It is
computed lazily on first call and **cached** (`hash_`, `hashValid_`). The caching is not
just an optimization — it is correctness: the hash is taken from the *pristine* file before
any in-memory patch, so it remains stable as the persistence key. Every saved-analysis
sidecar (`%APPDATA%/DisasmStudio/projects/<hash>.json`: comments, renames, bookmarks,
breakpoints, patches, notes) is keyed by this value, so a patched binary does not split its
analysis across two files. `clear()` resets `hashValid_` so the next loaded file recomputes.

### PE exports, imports, and base relocations

For PE, `parsePE()` reads only data-directory slots that fit both
`NumberOfRvaAndSizes` and the declared `SizeOfOptionalHeader`, so a truncated optional
header cannot alias the section table. It also preserves the COFF
`fileCharacteristics()` value; `isDll()` tests `IMAGE_FILE_DLL`, which prevents the App
from treating a DLL as a directly launchable executable and feeds the validated hosted
DLL-debug workflow. It records export
(`exportDirRVA/Size`), import, and base-relocation directory locations. After sections are
parsed (imports need them for RVA translation):

- **`parseExports()`** builds the shared `BinaryFile::Export` model from the complete EAT:
  named aliases, ordinal-only rows, forwarders, local code/data targets, and malformed or
  unmapped targets. RVA/name/ordinal walks are bounds-checked and hostile inputs are capped
  by row, stored-string, and aggregate string-scan budgets. The PE header span declared by
  `SizeOfHeaders` (clamped before the earliest raw section) maps 1:1, so a valid
  header-resident export directory is supported without treating the virtual gap before the
  first section as file-backed data.
- **`parseImports()`** walks `IMAGE_IMPORT_DESCRIPTOR`s, resolving each IAT slot to a
  `{ iatVA, dll, name }` `Import`. It handles bound imports (OFT may be 0, falls back to
  the IAT RVA) and ordinal imports (`#NN` when the high bit is set). `iatVA = imageBase_ +
  iatRVA + k*ptrSize` is the actual slot address, which lets the UI annotate `call [iat]`
  sites inline as `DLL.func` and populate the Imports tab. Hard caps (descriptor scan to
  64 KB, 50 000 thunks per DLL, 100 000 total imports) bound pathological inputs.
- **`parseDelayImports()`** walks data directory 13 as bounded
  `IMAGE_DELAYLOAD_DESCRIPTOR` records. Both modern RVA-based descriptors and legacy
  VA-based fields are resolved without narrowing. The immutable `delayImports()` model
  preserves descriptor attributes/timestamp, module/IAT/INT/bound/unload addresses, DLL
  name, ordinal/name symbols, termination/truncation state, and exact IAT slot VAs. Delay
  symbols are also appended to the normalized `imports()` model with `delayed == true`.
- **`parseTlsDirectory()`** decodes the PE32/PE32+ TLS directory (data directory 9), whose
  members are VAs rather than RVAs. `peTls()` exposes the raw-data/index/callback-table
  addresses, zero-fill/characteristics, validation state, and an ordered, image-backed,
  null-terminated callback list capped at 4,096 entries.
- **`parseDebugDirectory()`** retains bounded generic `IMAGE_DEBUG_DIRECTORY` rows and
  decodes CodeView **RSDS** payloads into GUID bytes/printable GUID, age, and a bounded PDB
  path. Payloads may be backed by `AddressOfRawData` or, for disk images only,
  `PointerToRawData`; mapped images never reinterpret a raw-file pointer. No path parser
  trusts an unbounded NUL terminator.
- **`parseLoadConfig()`** reads only the prefix proven by all three of the structure's
  declared `Size`, the directory size, and mapped bytes. `peLoadConfig()` exposes the
  dependent-load flags plus presence/mapping state for the security cookie, SafeSEH table,
  Guard CF check/dispatch pointers, Guard CF function table/count, and Guard flags for both
  PE32 and PE32+ layouts.
- **`parseRuntimeFunctions()`** materializes x64 `RUNTIME_FUNCTION` rows and bounded
  `UNWIND_INFO` prefixes: range VAs, version/flags, prologue size, frame register/offset,
  exact raw unwind-code slots, exception handlers, CHAININFO, and indirect parent records.
  The existing `pdataRanges()` compatibility API continues to omit continuation records
  when seeding function discovery and retains its current-image parsing behavior.
- **`parseRelocs()`** walks `IMAGE_BASE_RELOCATION` blocks into `(VA, type)` pairs (type =
  `IMAGE_REL_BASED_*`), skipping ABSOLUTE (type 0) padding entries, capped at 200 000.
- **`parseResources()`** walks the resource directory (data directory [2]) — the three-level
  `IMAGE_RESOURCE_DIRECTORY` tree Type → Name/ID → Language — into a flat `BinaryFile::Resource`
  list (`resources()`). Each leaf records its type/name (numeric id or decoded UTF-8 string), language
  id, data RVA/size/code page, `va = imageBase_ + dataRVA`, and backing `fileOffset`. Directory
  offsets are relative to the resource base RVA (only the leaf data entry carries a real RVA); a
  visited-entry cap plus a depth cap keep a self-referential or absurd tree from spinning. The
  payload decoders (RT_* names, version info, string tables, `.bmp`/`.ico` reconstruction) live in
  the pure `Core/ResourceDecode` module and drive the Binary View's Resources tab.

ELF32/64 `.dynsym` and `.symtab` records are parsed through their linked string tables into
the same normalized symbol/import models, including kind, binding, visibility, size,
defined/undefined state, and table provenance. Dynamic rows win duplicate precedence and
mapped function/IFUNC symbols seed analysis. `ET_REL` alloc sections receive checked,
alignment-aware non-overlapping synthetic VAs so zero-address object-file sections and their
section-relative symbols remain distinct. Class-aware REL/RELA records retain symbol/type/
signed-addend data and explicit mapped-target validity; conventional PLT/GOT sections expose
bounded slots, `DT_NEEDED` entries expose dependencies, GNU version definitions/requirements
are associated with dynamic symbols, and direct/array initializers retain distinct slot/target
validity (including VA zero). Sectionless `PT_DYNAMIC` recovery remains out of scope.

Mach-O thin and universal containers retain bounded selected-slice metadata, symbols, dyld
binding/export-trie records, function starts, and initializer records. Slice/load-command/
link-edit walks are range-checked and expose explicit validity/truncation.

### writeImage — in-memory patching that preserves identity

`writeImage(va, data, n)` maps the VA to a file offset via `vaToOffset` and overwrites up
to `n` bytes of the in-memory `data_`, returning the count written (0 if the VA is not
backed by on-disk bytes). After it runs, `bytes()` and `ptrFromVA()` return the patched
view, so the disassembly immediately reflects an applied (or reverted) patch. Two things it
**deliberately does not do**: it does not touch `contentHash()` (cached from the pristine
file, so saved analysis stays under one key) and it does not write the file on disk. Writing
to disk is a separate, explicit action (**File ▸ Save Binary As…**) that splices patches
into a copy via `vaToOffset`. This separation keeps "preview a patch" cheap and reversible
while keeping the original artifact untouched.

### User-facing surface

`BinaryFile` has no UI of its own; it is pure model. Its outputs drive the chrome:
`formatName()` and `machine()` populate the title/status, `firstCodeSection()` sets the
initial cursor, `imports()` feeds the Imports tab and inline IAT annotations, and
`exports()` feeds the unified Exports / Symbols panel and PE/ELF function discovery. The addressing routines back
every navigation, hex pane, and string/byte search. The file-opening routes are an optional
startup argument (`DisasmStudio.exe <path>`), **File ▸ Open** (both auto-detect via `load`),
and **Open as Raw…** (`loadRaw` with a chosen base + arch).

#### Limitations & notes

- ELF is **little-endian only**; big-endian ELF degrades to Raw.
- A universal Mach-O opens one deterministic supported slice at a time and exposes all
  inspected slice descriptors; it does not merge architectures into one analysis image.
  Chained fixups and Objective-C/Swift metadata remain separate work.
- PE imports/exports/resources/relocations, TLS, delay imports, CodeView RSDS,
  security load configuration, and x64 unwind metadata are parsed. ELF section-table
  symbols, REL/RELA, PLT/GOT ranges, dynamic dependencies, versions, and initializer arrays
  are parsed; Mach-O symbols, bindings, export trie, function starts, initializers, and
  universal containers are modeled. Sectionless ELF `PT_DYNAMIC` recovery remains out of
  scope.
- Inferred fallbacks (machine defaulting by bit-class for unknown `e_machine`/`cputype`,
  Mach-O entry derived from `__TEXT`, ELF program-header fallback for stripped binaries) are
  best-effort but unlabeled at this layer — they are internal robustness, not surfaced as
  "heuristic" to the user the way the decompiler/tech-scan output is.
- A failed structured parse becomes `Raw` rather than an error, by design.
- Explicit raw mappings whose final byte would wrap the 64-bit VA space are rejected.
- The whole file is held in one contiguous `data_` buffer; loading is O(file size) memory,
  which is fine for typical executables but is the limiting factor for very large images.
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
3. **Mapped PE/ELF function symbols** (`collectExports`) — consumes the bounds-checked
   `BinaryFile::exports()` model rather than reparsing PE tables. Only mapped local code
   targets become function seeds; forwarders, exported data, and unmapped targets remain
   visible in the Exports panel but are not functions. Aliases collapse to one seed per VA,
   a real export name wins over an ordinal label, and an ordinal-only code export is named
   `#N` instead of being presented as a heuristic `sub_`.
4. **PE32+ exception ranges** (`pdataRanges`) — linker-emitted x64
   `RUNTIME_FUNCTION` begin addresses are authoritative seeds, and their `[begin,end)`
   extents provide authoritative ownership hints.
5. **Prologue heuristic scan** (`prologueScan`) — a byte sweep over every executable
   section looking for common x64 prologues (`55 48 8B/89 …`, `48 83 EC …`, home-slot
   stores), x86 frame prologues (`55 8B EC` / `55 89 E5`), or architecture-specific
   A32/Thumb/A64 frame setup (including PACIASP). The exact selected `Arch` gates every
   pattern. Bounded true PC-relative ARM literal spans suppress false prologue and recursive
   call roots; ordinary base-register loads are not literals. Each match remains best-effort.

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

**Function ownership** first honors valid ELF symbol and x64 `.pdata` extents, then uses
bounded recursive basic-block ownership with trusted-entry barriers, calls versus tail
branches, architectural delay slots, explicit non-contiguous chunks, and noreturn evidence.
The legacy `address`/`size` pair is the compatible envelope; exact membership uses chunks,
and `ownershipTruncated` discloses a budget-limited result. Names are `sub_<HEXADDR>` for
anything not matched to an authoritative name.

### Recursive code/data classification — `CodeDataClassifier`

`src/Core/CodeDataClassifier.{h,cpp}` runs after initial function discovery on the background
worker with an independent decoder. Exact recursive control-flow reachability is combined with
bounded strings and literals, ARM-family literal references, absolute/RVA/relative jump tables,
aligned vtable/code-pointer runs, relocation-backed callbacks, CET landing pads, and ISA-aware
padding. Strong indirect entries feed one bounded `FunctionAnalyzer` rerun, recovering functions
that have no direct-call, export, symbol, unwind, or recognizable-prologue evidence.

The result partitions every mapped executable byte into code, string, literal pool, jump table,
pointer table, padding, data, or deliberately unknown spans. Every positive span carries width,
confidence, and evidence. Explicit instruction/block/table/scan/claim limits and cancellation keep
the pass finite, and the production map is stamped with `BinaryFile::imageRevision()` so patches or
reloads cannot reuse stale boundaries.

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

`src/Core/SymbolResolver.{h,cpp}` is the bounded DbgHelp adapter and
`src/Core/SymbolService.{h,cpp}` is the sole joined owner used by the UI. Static sessions use
unique DbgHelp keys; live sessions receive a duplicated debugger process handle plus an explicit
debug-session generation. Every process-global DbgHelp option/load/query is serialized by the
shared mutex, while debugger unwind has an independent local-only session. Ordinary listing
lookups are non-blocking cache reads; PDB loading, optional source/type/local queries, and all
network-capable work run on the symbol worker. A configured cache is supported and symbol-server
access is **disabled by default**. Enabling it is explicit, search paths are validated, requests
and returned records are capped, and stale generations cannot publish into a replacement target.
`resolve` returning `false` remains the normal degraded path, letting callers fall back to their
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

### Automatic Authorization Trail

`Core/AuthorizationTrail` and the bounded `AnalysisService` adapter collect existing input,
network, persistent-state, xref, call-graph, CFG, and `FuncAnnotate` facts into a conceptually ordered
**Input → Format → Remote request → Entitlement parsing → Crypto verification → State
persistence → Global predicate → Feature predicate → Protected operation** report. Small
x86/x64 boolean-returning functions are ranked by unique callers, proven branch consumers,
and guarded operations. Every retained call use carries the exact continuation, AL/EAX/RAX
width, comparison/branch, and proved true/false destinations; rank is an investigation lead,
not evidence that a function grants access. Stage rows are independently evidenced and are not
claimed to form one connected path unless explicit data/control-flow identities connect them.

`Core/AuthorizationFieldAlias` keys fields by proved object root + displacement + width and
merges roots between functions only through exact unchanged direct-call argument bindings.
Displacement-only, adjusted, ambiguous, cyclic, incomplete, and width-conflicting rows remain
separate or rejected. A downstream predicate becomes secondary only when it lies on the proved
permitted arm and its result is required for a retained operation; this drives the explicit
warning when changing a global/branding predicate cannot authorize every protected path.

The conclusions **locally valid format**, **server accepted**, **signature verified**, and
**feature permitted** are independent unknown/candidate/supported facts. Exact verifier import
or call presence is capability only; signature verification additionally requires reply-data
lineage into a documented verifier argument and its result controlling a branch.
`feature permitted` additionally requires an authorization-linked Global/Secondary predicate's
exact branch-exclusive guard over the exact protected operation; a matching operation location or
unlinked predicate guard is insufficient. “No embedded expected key” and “no private signing
material” are emitted only for explicitly complete,
narrow search scopes. Otherwise they stay unknown, and the tool does not claim a real signed key
can be recovered from an endpoint or public verification material.

`Core/AuthorizationPatchAdvisor` produces inert x86/x64 `mov eax,0/1; ret` advice only for a
proved centralized predicate with complete entry/return/side-effect coverage, executable bytes,
a supported ABI, no alternate entry, and sufficient confidence. It refuses string/heap cleanup,
other side effects, stack-cookie/security epilogues, non-executable targets, and transport-only
changes. The advisor never mutates the image, project, or process.

#### Limitations & notes

- Function discovery is best-effort: prologue patterns are limited to **x86/x64** and are
  enabled only for the exact selected architecture; bounded reachability may set
  `ownershipTruncated` when the per-function cap trades completeness for responsiveness.
- All `FunctionNamer` output is **heuristic and labelled** (amber tint + reason tooltip),
  **recomputed each analyze, and never persisted** — exports, PDB symbols, and user renames
  always take priority.
- CFG jump-table recovery only resolves indirect jumps the supplied resolver can read and
  whose targets land on decoded instruction boundaries; unresolved indirect control flow is
  simply not edged.
- `instrDataRef` resolves only static, non-register memory references; register-relative and
  computed addresses are intentionally reported as none.
- Symbol-server access is opt-in and asynchronous. Even after cancellation, shutdown may need to
  wait for one in-progress DbgHelp/symsrv call because that API has no safe force-cancel contract;
  the UI never owns or closes its underlying session.
- `TechScan` is signature/heuristic detection (imports, section names, fixed byte patterns):
  it can miss obfuscated capabilities and is not a substitute for dynamic analysis; it
  deliberately reports nothing for a trivial binary rather than inventing findings.
## 05. Decompiler & Data-Flow

DisasmStudio ships a **lightweight, in-house decompiler**: given a function's
control-flow graph, it recovers C-like control structures (`if/else`,
`while`/`do-while`, `for`, `switch`), lifts each instruction to a readable
statement, and — when enabled — runs a **data-flow pre-pass** that names locals,
propagates copies and constants, eliminates dead assignments, infers types, and
recovers return expressions. The result reads much closer to real C than a raw
instruction-by-instruction transliteration. This is deliberately *not* a
full-blown decompiler (no SSA, no global type lattice, no inter-procedural type
recovery) — it is a "good enough to read" structurer, and every heuristic edge is
labelled as such in the UI.

The subsystem lives in two pure-logic, UI-free Core modules (so they are
unit-testable in the sandbox):

- `src/Core/Decompiler.{h,cpp}` — the **structurer** plus the legacy per-instruction operand lifter.
- `src/Core/DataFlow.{h,cpp}` — the optional **data-flow pre-pass** (`AnalyzeDataFlow`).

The single public entry point is `ds::Decompile(const ControlFlowGraph&, const DecompileOptions&)`.

### Inputs and options — `DecompileOptions`

`Decompile` consumes a `ControlFlowGraph` (basic blocks + edges from
`src/Core/CFG.h`, built by `BuildCFG`) and a small option bundle
(`Decompiler.h`):

- `nameFor(uint64_t va)` — resolve a call/jump-target VA to a display name
  (e.g. `kernel32.CreateFileW`, a user rename, or `""` to fall back to
  `sub_<addr>`). The UI binds this to `BinaryViewTab::symbolFor`.
- `dataRefFor(uint64_t addr)` — resolve a constant data address to a display
  token: a quoted, escaped C-string literal, an import/global name, etc. The UI
  binds this to `BinaryViewTab::dataRefToken`, which checks the IAT/import map,
  user renames/symbols, and finally attempts to read a printable ASCII/UTF string
  at the address.
- `signature` — an optional inferred `"<rettype> (args)"` header (e.g.
  `"__int64 (a1, a2)"`). When present, the function name is spliced in at the
  `(`; otherwise the header falls back to `__int64 <name>()`.
- `deepDataFlow` (default **true**) — the **A/B kill-switch**. With it on,
  `Decompile` runs `AnalyzeDataFlow` and emits named/propagated/DCE'd statements;
  with it off (or if the data-flow pass returns `ok == false`), it falls back to
  the legacy per-instruction string lift. No instruction is ever lost in either
  mode.

The guessed name + inferred signature are what make the output read like a real
function: a header such as `__int64 sub_140001000(a1, a2)` over a body of named
locals and inlined string literals, rather than a wall of register mnemonics.

### The structurer (`Decompiler.cpp`)

#### Building the per-block model

`Structurer::build` walks the CFG once and, per block, computes:

- **Body statements** — from the data-flow pass when active (`df_.blockStmts[i]`),
  otherwise from `liftStmt` over every non-terminator instruction. A trailing
  `call` is treated as a normal statement, not a terminator, so it stays in the
  body.
- **Terminator kind** (`Term::{Return, Uncond, Cond, Fall, External, Switch}`) and
  its operands: true/false successor indices for conditionals, the unconditional
  jump target, the fallthrough block, switch case targets, or an `extTarget` VA
  when a branch leaves the analyzed window (rendered later as a `goto loc_<addr>`
  "tail" call).
- **Flag state** (`FlagState`) feeding the terminator, so a `Jcc` can be rendered
  as a real relational condition.
- **Forward adjacency** (`succ`) for the dominator analysis.

#### Dominators and post-dominators (Cooper/Harvey/Kennedy)

`computeIdom` implements the classic **Cooper, Harvey & Kennedy iterative
dominator algorithm**: an iterative DFS produces a postorder numbering, then the
immediate-dominator array is refined to a fixpoint over the reverse-postorder,
using the two-finger `intersect` walk up the dom-tree. Unreachable nodes stay
`-1`. `dominates(a, b)` is then a simple walk up `idom[]`.

**Post-dominators** are computed by running the same algorithm on the *reversed*
graph augmented with a virtual exit node (index `N`): every return / external /
sink block is linked to it. The resulting `ipdom[]` gives each block's immediate
post-dominator — i.e. the **join point** where an `if/else` reconverges, which is
the linchpin of structuring.

#### Natural-loop detection

`detectLoops` finds **back-edges** `u→v` (an edge whose head `v` dominates its
tail `u`), marks `v` a loop header, and grows the natural-loop body by walking
predecessors from `u` back to `v`. Multiple latches into the same header are
merged (OR'd) into one body set. Each header's **loop follow** is the
lowest-address block that an in-loop edge exits to — the post-loop continuation.

#### Emission: two passes, structured output

Emission runs **twice**. Pass 1 (`collecting = true`) discovers which blocks need
labels (i.e. are `goto` targets); pass 2 emits the text with those labels in
place. The `emitted` counter guards against pathological blow-up (truncates past
100,000 emitted blocks).

`emitFrom`/`emitTerminator` are a recursive structuring driver:

- **`Cond`** — renders `if (cond) { ... }` (and `else { ... }`) bounded by the
  post-dominator join `ipdom[n]`. Empty arms are detected and the condition is
  inverted to avoid an empty `then`. When there is no common join before exit, the
  then-arm is bounded by the else's entry so it can't run away and swallow the
  rest of the function. Branches whose targets exit (return/continue/break/goto)
  collapse to a single `if (cond) <jump>;` line.
- **`Switch`** — the recovered jump table becomes `switch (selector) { case N: ...
  break; }`. Cases run to the switch's post-dominator join; when no join exists,
  the case body is bounded by the next distinct case entry (otherwise `case 0`
  would swallow every later case and the tail). `switchVar` recovers the selector
  expression from the `jmp [base + reg*N]` form by finding the register scaled by
  8/4/2; failing that it emits `switch_index`.
- **Loops** (`emitLoop`) — emitted as **pre-tested** `while (cond) { ... }` when
  the header itself is a side-effect-free 2-way test with exactly one arm leaving
  the loop (the condition is negated as needed and the loop's real exit arm is
  used as the break target). Otherwise it falls back to `while (1) { ... }` with
  the exit handled inside via break/goto — the general form for `do-while` and
  multi-exit loops.
- **`continue` / `break` vs labelled `goto`** — `goTo` scans the loop stack
  innermost-first. Because C `continue`/`break` bind only to the innermost loop, a
  transfer to the innermost header/follow becomes `continue;`/`break;`, but a
  transfer to an *enclosing* loop's header/follow becomes a labelled `goto … /*
  continue outer */`. Any jump to an already-emitted block also becomes a labelled
  `goto`. This is exactly how production decompilers fall back on **irreducible
  control flow**: structure where possible, labelled gotos where not.

#### for-loop reconstruction (post-pass, data-flow mode only)

`reconstructForLoops` is a **purely textual, conservative** post-pass run only
when `deepDataFlow` is active. It rewrites a `while (COND) { …; i++; }` into
`for (; COND; i++) { … }` when: the last top-level body line is a recognized step
(`i++`, `i--`, `i += k`, `i -= k`), `i` appears as a word in `COND`, and the body
contains **no** `continue` or `goto` (which would skip the step in a `while` but
always run it in a `for`). Anything not matching the exact shape stays a `while` —
so the rewrite can never change semantics. (The data-flow pass also carries a
`DfForLoop` triple structure for header blocks, but the shipped emitter uses this
textual reconstruction.)

#### The legacy operand lifter (`liftStmt`)

When data-flow is off, `liftStmt` turns one instruction into a C-ish statement:

- `mov`/`movzx`/`movsx`/`movabs`/SSE moves → `A = B;`; `lea` → `A = &(addr);`.
- Arithmetic/logic → compound assignment (`+= -= &= |= ^= <<= >>=`); `xor x,x`
  special-cased to `x = 0;`. `inc`/`dec` → `++`/`--`; `neg`/`not` → `-`/`~`.
- `rol`/`ror` → `_rotl`/`_rotr` (single-operand form rotates by 1); `bswap`,
  `xchg`→`swap(...)`.
- `mul`/`imul`/`div`/`idiv` model the implicit accumulator pair, picking
  `rdx:rax`/`edx:eax`/`dx:ax`/`ah:al` from the operand width via `accPair`;
  3-operand `imul dst,src,imm` → `dst = src * imm`.
- `cmp`/`test` produce no statement — they set `FlagState` for the next branch.
- `setcc`/`cmovcc` render against the pending flag state via `condString` (e.g.
  `dst = (a < b);`, `if (a == b) dst = src;`).
- Anything unmodelled is preserved verbatim as `__asm { … };` so no instruction is
  silently dropped.
- `[mem]` is rewritten to `*(mem)` (`cOperand`) so memory reads look like C
  dereferences.

#### Condition rendering (`condString` / `condOp`)

`condOp` maps a `Jcc` mnemonic to a C operator and its negation (handling both
signed and unsigned families, e.g. `jg/jnle/ja/jnbe → >`). `condString` then
renders the taken condition against the `FlagState`: after `cmp a,b` it emits
`a <op> b`; after `test x,x` it emits `x <op> 0`; after `test x,y` it emits
`(x & y) <op> 0`; after an arithmetic op it tests the result against 0. `js`/`jns`
are special-cased to a signed `< 0` / `>= 0` (cast to `int64_t`). Unmodelled
branches (`jp`, `jo`, `loop`, `jcxz`, …) degrade to an exposed `<mnem>_cc`
predicate rather than a wrong comparison.

### The data-flow pre-pass (`DataFlow.cpp`)

`AnalyzeDataFlow` is the upgrade that makes the output read like C. It returns a
`DataFlowResult` consumed directly by the structurer (per-block statement lists,
terminator flags, inferred declarations, return expressions, for-loop triples).
If anything goes wrong it returns `ok == false` and the structurer silently falls
back to the legacy lift.

#### Typed operand model

Each Intel-syntax operand is parsed (`parseOperand`) into a typed `Operand`
(`Reg`/`Imm`/`Mem`/`Sym`), stripping size keywords (`byte/word/dword/qword/xmmword
ptr`) and `fs:`/`gs:` segment overrides. Registers are canonicalized to a 16-entry
index via `regTable()` so all sub-registers alias one location (`eax`/`ax`/`al`
all map to `RAX`), tracking width (8/4/2/1) and the `ah/bh/ch/dh` high-byte case.
Memory operands (`parseMem`) are decomposed into base/index*scale/disp with
rip-relative and disp-only flags. `[rbp/rsp ± disp]` slots with no index become
**tracked stack locations** (`stackLoc`), the basis for named locals.

#### Naming, propagation, and the value environment

Each block is lifted in isolation by `liftBlock`, maintaining an `Env` of
location→`Val` (an expression plus the variable names it reads and the locations
it depends on). Reading a tracked location returns its cached, propagated
expression — this is **intra-block constant/copy propagation**. Writes
(`emitDef`) record a new `Val`; `killDep`/`killMemory`/`killStackSlots`
invalidate cached values when their inputs change, a memory store happens, or a
`call` clobbers volatile registers and may alias a passed `&local`. Names come
from `nameOf`: arguments get `a1..aN`, register temporaries `v1, v2, …`, stack
slots `local_0, local_1, …`.

Width matters for correctness: a 32-bit write zero-extends, so it is a full
definition (propagatable); an 8/16-bit write is a read-modify-write rendered with
`LOBYTE`/`LOWORD`/`BYTE1` so the surviving upper bits aren't lost. Calls assign
`rax` and clobber the Win64 volatile set.

#### Argument detection

`detectArgs` scans the prologue linearly until the first `ret` and flags Win64
argument registers (`rcx, rdx, r8, r9`) that are **read before being written**
(self-zeroing `xor x,x`/`sub x,x` don't count as reads; registers inside memory
operands always count). Args are contiguous, so if a later register is an arg the
earlier ones are named too. This mirrors the UI's `guessSignature` so the arg
count matches the emitted header.

#### Dead-assignment elimination (live-variable analysis)

`eliminateDead` runs a standard **iterative backward live-variable analysis** over
the whole CFG (gen/kill per block, `liveOut = ∪ liveIn(succ)`, seeded at returns
with the variables a return reads). A backward sweep then deletes any non-side-
effecting assignment whose destination is dead, and — crucially — strips the
dead *result* of a `call` (turning `v3 = foo();` into `foo();`) while keeping the
call itself. Stores and calls (`side == true`) are never removed.

#### Type inference, return recovery, declarations

Types are inferred heuristically: a name used as a memory base is a `void *`
(`ptr_`); otherwise width ≤ 4 ⇒ `int`, else `__int64`. Only locals/temps
(`local_*`, `v<digit>*`) get declarations, emitted in first-appearance order at
the top of the function body. **Return-value recovery**: if `rax` is ever
assigned, each `return` reports `rax`'s value — the inlined propagated expression
when known (`return v3 + 1;`), else the variable name (`return v3;`); otherwise a
bare `return;`. The static Pseudocode view prefixes the result with
`// signature is heuristic (no full type recovery)`.

### User-facing surface

The decompiler appears in the **Binary View** tab as the **Pseudocode** main-view
radio (`mainView_ == 1`, `renderPseudocode`), alongside Assembly / Hex / Graph /
Call Graph / Live Assembly. It also drives the **Live Assembly → Pseudocode**
panel (`renderLivePseudocode`) for the running debuggee, which reads memory
masked for `0xCC` breakpoints and decodes with the debuggee-bitness decoder.

- The static view shows a `Refresh` button and explanatory disabled text
  ("if/else + while recovery via dominator analysis; goto fallback for irreducible
  flow"), then a read-only multiline box so the output can be selected and copied;
  the live view adds `Copy`.
- It decompiles the **function enclosing the cursor** (via `funcContaining`), not
  just the window under it, capped at a sensible window (`fnSize + 16`, ≤ 16 KB,
  else 4 KB). Results are cached per function start (`decompVA_` / `pseudoVA_`) and
  invalidated when the function changes, on rename, or on relevant edits.
- The view participates in the broader analysis: `nameFor`/`dataRefFor` pull in
  user renames, imports, and string literals, so renaming a function in the
  listing immediately improves the pseudocode (`decompVA_ = 0` invalidation).

### Performance characteristics

All passes are near-linear in instruction count for typical functions: dominators
iterate to a fixpoint over RPO, liveness to a fixpoint over blocks, and the
structurer emits each block roughly once (label-discovery + emit = two passes).
CFG construction is capped (`maxInsns = 2000`) and the structurer truncates past
100,000 emitted blocks. Output is cached per function, so scrolling the cursor
within a function is free. There is no whole-program decompile pass at idle; the
exported "Report" path decompiles the analyst's named functions on demand with a
cap to keep large rename sets fast.

#### Limitations & notes

- **Not a full decompiler.** No SSA, no global/inter-procedural type recovery, no
  cross-block value propagation (propagation is intra-block only), no stack-frame
  reconstruction beyond `[rbp/rsp ± disp]` slot naming. Output is explicitly
  labelled heuristic.
- **Argument/signature/return guesses are best-effort** and **x86/x64-only**
  (`guessSignature` returns `""` for other arches; `detectArgs` assumes the Win64
  ABI). The SysV path exists only in the UI's `guessSignature` arg-count estimate.
- High-half results of `mul`/`div`, the FPU/SSE/vector domain, and the stack
  (`push`/`pop`) are not modelled; unmodelled instructions are preserved verbatim
  as `__asm { … };` so nothing is dropped, but they read as opaque.
- Irreducible flow falls back to **labelled `goto`s** by design; deeply
  unstructured functions will contain `loc_<addr>:` labels rather than clean
  nesting.
- `for`-loop reconstruction is a conservative textual rewrite that only fires on an
  exact, jump-free shape; everything else stays a `while`.
- The data-flow pass is gated by `deepDataFlow` (default on); turning it off, or
  any internal failure, transparently yields the simpler register-level lift.
## 06. The Live Win32 Debugger

DisasmStudio is not only a static disassembler — it embeds a **real Win32 user-mode
debugger** that drives a live target process: attach or launch, set software and
hardware breakpoints (with conditions), single-step in three modes, read and write
the debuggee's registers and memory, walk threads and the call stack, and view live
disassembly that tracks the program counter. This chapter covers the engine
(`src/Core/Debugger.{h,cpp}`), the pure stepping-decision logic
(`src/Core/StepLogic.h`), the conditional-breakpoint evaluator
(`src/Core/Cond.{h,cpp}`), and the process/connection backends
(`src/Core/ProcessManager.{h,cpp}` plus the IP Helper code in the Communications
tab). Everything described here is **x86/x64 only**; non-x86 architectures are
disassembled statically but cannot be debugged live.

### Threading model — why a dedicated debug thread

The Win32 debug API has a hard constraint: **the same thread that called
`DebugActiveProcess` (or `CreateProcess` with a `DEBUG_*` flag) must service every
`WaitForDebugEvent`/`ContinueDebugEvent`**. The UI, of course, runs on the render
thread. `Debugger` therefore owns one dedicated worker thread (`thread_`, started in
`attach`/`launchAndAttach`) that runs `threadMain` — the create/attach, the debug-event
pump, all breakpoint byte-patching, and all context reads/writes happen there.

The UI thread never blocks on the debuggee. Instead it:

- **Posts commands** (`cont`, `stepInto`, `stepOver`, `stepOut`, `pause`, `runToCursor`,
  `detach`) by setting `pending_` under `mtx_` and signalling `cmdCv_`. The debug
  thread blocks in `waitForCommand()` while the target is paused.
- **Reads a lock-guarded snapshot** via `snapshot()`, which copies `state_`, `regs_`,
  the breakpoint lists, the thread list, the active TID and the `is32` flag into a
  plain `DbgSnapshot` value under `mtx_`. The UI calls this every frame and renders
  from the copy, so there is no shared mutable state to race on.

Two mutexes guard the shared surface. `mtx_` protects the command/snapshot state and
the breakpoint tables. A second mutex, `hProcMtx_`, serializes UI-thread use of the
process **HANDLE** (`pause`, `readMemory`, `writeMemory`, `regions`) against the debug
thread closing that handle at teardown — closing the classic load-then-use TOCTOU
window where the UI could call `ReadProcessMemory` on a handle the debug thread just
closed. Pending breakpoint changes are queued into `pendingBpAdds_/Rems_/Conds_`
(and `pendingHwAdds_/Rems_`) from the UI and folded into the live process by
`applyPendingBps()` only when the debuggee is stopped at an event — the one safe
moment to patch its memory.

Startup is synchronous from the caller's view: `attach`/`launchAndAttach` spin up the
thread, then wait on `cmdCv_` until `startupDone_` is set, returning the
`startupErr_` string on failure (e.g. *"DebugActiveProcess failed … run as
Administrator / match bitness."*).

### Attaching and launching

`attach(pid, err)` calls `DebugActiveProcess(pid)` on the debug thread.
`launchAndAttach(exePath, err, breakAtEntry=true)` converts the UTF-8 path to UTF-16
and calls `CreateProcessW` with `DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE` —
again on the debug thread, because the creator must be the event pump. Both paths
call `DebugSetProcessKillOnExit(FALSE)` so that detaching (or DisasmStudio crashing)
leaves the target alive.

**Break-at-entry** is a deliberate refinement over the default loader behaviour. A
freshly created process raises an initial system breakpoint inside ntdll's loader,
not at the user's code. When `breakAtEntry` is set, the engine instead computes the
real entry point from the mapped image: on `CREATE_PROCESS_DEBUG_EVENT` it reads the
PE header out of the debuggee (`AddressOfEntryPoint` at `e_lfanew + 24 + 16`, valid
for both PE32 and PE32+), falling back to `lpStartAddress` only if that read fails
(the field is unreliable for packed/managed images). It then arms a one-shot
breakpoint (`TempKind::EntryPoint`) and continues, landing the user on the first
instruction of *their* code rather than in the loader.

### Debugging a DLL through a real host

A PE DLL cannot be passed directly to `CreateProcessW`. **Debug DLL…** therefore
uses the pure `Core/DllDebugPlan` layer before starting a session. `InspectDllForDebug`
requires a valid PE image with the COFF DLL characteristic, determines PE32/PE32+
bitness, records DllMain's RVA when its entry is executable, and offers only local,
non-forwarded exports whose RVAs map to file-backed executable sections. Forwarders,
data exports, malformed targets, and non-DLL PEs remain visible elsewhere in the UI
but cannot be selected as launch callbacks.

The default host is the trusted Windows `rundll32.exe` matching the DLL: native
`System32` for a 64-bit DLL, or `SysWOW64` for a 32-bit DLL on 64-bit Windows. A
custom host is also supported, with an enforced bitness match when its PE bitness is
known. The launch request stores typed argument slots (literal, DLL path, export
invocation, and zero-or-more user arguments); `BuildWindowsCommandLine` applies the
Microsoft/CRT quoting rules so spaces, empty arguments, embedded quotes, and trailing
backslashes retain their exact argv boundaries. The system-host route also warns that
an executable export RVA cannot prove the callback has rundll32's required ABI.

`Debugger::launchAndAttachDll` passes the validated host as `lpApplicationName` and
the already quoted mutable command line separately. Requested DllMain/export stops
remain RVAs while the loader runs. When the exact target appears in
`LOAD_DLL_DEBUG_EVENT`, `RetargetDllDebugLaunchPlan` matches its normalized full path
(falling back to a leaf name only when the event supplied no directory), adds the
actual ASLR base, and plants invisible one-shot target breakpoints. `DbgSnapshot`
publishes the matched path/base/size, active/last target label, and any planting error.
On a target hit the App copies that mapped module through `loadLiveModule`, so the
normal Binary View, symbols, listing, and analysis follow the DLL rather than the
rundll32/custom-host image.

### Software breakpoints — the int3 dance

A software breakpoint overwrites the first byte of an instruction with `0xCC`
(`int3`). The engine stores, per address, the original byte and the optional
condition string in `bps_` (`va -> {orig, cond}`). Arming/disarming is byte-level
patching via `writeByteRPM`, which temporarily flips the page to
`PAGE_EXECUTE_READWRITE`, writes, restores protection and `FlushInstructionCache`s.

Hitting a breakpoint requires the full **restore + single-step + re-arm** sequence,
handled in `handleUserBp`: cancel any in-flight step, restore the original byte
(`disarmBreakpoint`), back RIP up over the consumed `int3` byte (`ctxSetRip`), then
evaluate the condition. If the condition holds (or is empty) the engine parks on the
breakpoint and surfaces to the UI; if it is false, it single-steps the original
instruction with the trap flag, silently re-arms the `0xCC`, and free-runs — so a
false condition never visibly stops the program.

`applyPendingBps()` is careful about pre-existing `int3` bytes: if the byte at a
new breakpoint address is already `0xCC`, it preserves it as the saved original
(it could be a genuine `int3` in the program or another debugger's), rather than
fabricating a `0x90` NOP that would corrupt the code when the breakpoint is later
removed. On teardown the loop restores every saved breakpoint byte.

### Hardware breakpoints — DR0–DR3

Up to four hardware breakpoints are supported, one per debug register, tracked in
`hwSlots_[4]`. `addHardwareBreakpoint(va, kind, size)` rejects duplicates and returns
`false` when all four slots (including pending adds) are taken. `HwKind` selects the
trigger: `Execute` (RWn=00, length forced to 1), `Write` (RWn=01) or `ReadWrite`
(RWn=11); `size` maps to the LENn field (1/2/4/8 bytes). `applyHwToThread` builds DR7
from the slot table and programs DR0–DR3 + DR7 on each thread, and new threads inherit
the active set on `CREATE_THREAD_DEBUG_EVENT`.

A subtle WOW64 gotcha is documented and handled in code: debug registers set through
the 32-bit `WOW64_CONTEXT` are **not reliably armed by the kernel**, so the engine
always programs DRs (and reads/clears DR6) through the **native 64-bit `CONTEXT`** with
`CONTEXT_DEBUG_REGISTERS`, even for WOW64 targets — the DR7 layout is identical and
32-bit addresses zero-extend cleanly. When a fault-class execute breakpoint stops the
thread, RIP is still on the trapping instruction; the engine sets `EFLAGS.RF`
(`setResumeFlag`) so the CPU runs that one instruction without re-trapping, after
which the hardware clears RF and the breakpoint stays live.

### Stepping — pure decisions in StepLogic

The hard-to-test core of any debugger is the *decision* of what to do when stepping.
DisasmStudio factors those decisions into `StepLogic.h` as pure, side-effect-free
functions over `InsnKind` (`Normal`/`Call`/`Ret`/`RepString`), so they can be
unit-tested off-target with no Windows/Zydis/process dependency (`tests/step_logic_test.cpp`).

- **Step Into** sets the trap flag (`EFLAGS.TF`) and stops after exactly one
  instruction — following calls into the callee, branches to their target.
- **Step Over** (`DecideStepOver`): a normal instruction single-steps; a `call` or a
  REP-string op instead gets a **temporary breakpoint placed after it** so the whole
  call/repeat runs without tracing in.
- **Step Out** (`DecideStepOut`) single-steps the frame, stepping *over* every call so
  the trace never descends; the first `ret` it lands on therefore belongs to the
  current frame, making step-out O(instructions in this frame). It is guarded against
  ret-tricks: `stepOutFinishing` only pauses if RSP rose above `stepOutAnchorRsp`
  (the RSP captured when step-out began), so a `push`/`ret` gadget or deeper recursion
  keeps stepping rather than stopping in the wrong frame. A `kStepOutCap` of 500,000
  iterations bounds runaway traces and is surfaced as *"step out (capped)"*.

`DecideOnBpResume` composes both ideas: when the user issues a step *while parked on a
breakpoint*, the engine must restore the byte, execute the original instruction, re-arm
the `0xCC`, and only then realize the command — choosing between a trap-flag single-step
or a temp-breakpoint-after based on whether the underlying instruction is a call/rep.
**Run to cursor** (`runToCursor` / `TempKind::RunTo`) is implemented as a one-shot
temp breakpoint at the target followed by a normal continue.

### Execution trace / coverage

Trace is bounded coverage sampling built from one-shot basic-block breakpoints, not
instruction-by-instruction trap-flag tracing. From a paused session the Binary View
walks the analyzed functions/CFGs in chunks, maps preferred addresses to the live
module, de-duplicates block starts, and caps a trace plan at **65,536** sites. The
toolbar exposes planning/planting progress; planning can be cancelled without
blocking the render thread. `Debugger::startTraceCoverage` hands the completed plan to
the debug-event thread, which owns all process-memory patching.

`Core/TraceCoverage` is the Win32-free, mutex-protected state machine. Each `begin`
creates a generation, sorts/de-duplicates/caps sites, and reports requested, planned,
armed, hit, skipped, and retired totals through `TraceCoverageSnapshot`. Active-state
and generation checks make stale planting callbacks harmless after Stop, detach, or
a new target. The debugger keeps the trace `int3` table separate from user software
breakpoints and masks both tables in `readMemoryMasked`, so live disassembly still
decodes pristine bytes.

When a trace site fires, the engine restores its original byte, backs RIP up, records
the block-start/instruction hit, retires the site permanently, and executes the real
instruction once under TF before free-running. A collision never changes the
semantics of a user breakpoint or a temporary entry/step/run/JVM stop: the explicit
operation owns the byte and still contributes coverage when reached. **Stop Trace**
removes outstanding internal breakpoints but preserves collected hits; **Clear Trace**
removes the coverage data. The UI translates the runtime hits back to analysis VAs
and renders executed code with the semantic green `theme::col::good()` treatment in
the static Assembly listing, Live Assembly, and CFG.

`decodeAt` measures instruction length and classifies call/ret/rep using the debug
thread's **own private disassembler instances** (`ownDis_` for x64, `ownDis32_` for
WOW64 x86) — separate from the UI's engine, because Capstone/Zydis handles are not
concurrency-safe across threads. It masks out the engine's own `0xCC` bytes before
decoding so it classifies the real instruction, not an `int3`.

A notable correctness detail in the single-step handler is **thread binding**: the
engine records `stepTid` whenever it arms a step, and a single-step `#DB` from any
*other* thread (the whole process resumes on `ContinueDebugEvent`) is treated as a
stray — its trap flag is cleared and execution continues, without consuming the
stepped thread's pending state. Unlike a "freeze all other threads" scheme this can't
deadlock a thread waiting on a peer's lock.

### Registers, threads, memory and regions

While paused, `setRegisters` / `setRegister(name, value)` patch general-purpose
registers using a get-modify-set so unmodeled state (segment, FP, debug registers) is
preserved. `setActiveThread(tid)` re-points the snapshot's register view at another
thread (only valid at a stop, where contexts are stable). Threads can be individually
**frozen and thawed** with `suspendThread`/`resumeThread` (tracked in `suspended_`,
exactly +1 suspend count each), and all frozen threads are auto-thawed on detach.

`readMemory`/`writeMemory` proxy `ReadProcessMemory`/`WriteProcessMemory` (writes flip
page protection and flush the i-cache). `readMemoryMasked` is the variant used for all
**live disassembly and string scanning**: it substitutes the engine's own `0xCC`
breakpoint bytes back to their saved originals so the live view decodes real
instructions instead of `int3`. `regions()` walks the address space with
`VirtualQueryEx`, returning committed, non-guard, non-no-access `MemRegion`s with
parsed read/write/exec flags.

### WOW64 / 32-bit targets

The engine transparently debugs 32-bit (WOW64) processes. `IsWow64Process` (checked
once on `CREATE_PROCESS_DEBUG_EVENT`) sets `isWow64_`, after which the arch-aware
`ctxReadFull`/`ctxWriteFull`/`ctxReadRip`/`ctxSetRip` use `Wow64Get/SetThreadContext`
and the `WOW64_CONTEXT` register set, zero-extending the 32-bit registers into the low
halves of the shared `Registers` struct (`Eip→rip`, `Esp→rsp`, …; `r8`–`r15` stay 0)
so the rest of the engine and the UI stay arch-agnostic. WOW64 also reports 32-bit
`int3`/single-step under WX86 status codes (`0x4000001F` / `0x4000001E`) rather than
the usual `EXCEPTION_BREAKPOINT`/`EXCEPTION_SINGLE_STEP`, and a WOW64 target raises
**multiple loader breakpoints** during startup (the x64 ntdll one, then the wow64
ntdll one); a `loaderPhase` flag swallows the extras so the process is not killed by
an unhandled exception.

### Conditional breakpoints (Cond)

`Cond.{h,cpp}` is a tiny, dependency-free expression evaluator. The grammar is
`operand OP operand`, where `OP` is one of `== != <= >= < >` and each operand is a
number (decimal or `0x…`, via `strtoull` base 0), a **register** (case-insensitive;
both 64-bit and 32-bit names — `rax`/`eax`, `rip`/`eip`, etc. — alias the same field),
or a **memory dereference** `[addr]` with an optional `+`/`-` displacement
(`[rsp+8]`, `[rax-4]`). Registers and memory are resolved through caller-supplied
callbacks (`CondContext::reg`/`mem`), keeping the evaluator decoupled from Win32 and
unit-testable. `evalConditionFor` wires these to the stopped thread's context and a
pointer-width memory read (4 bytes for WOW64, 8 otherwise, so a `[addr]` deref in a
32-bit target doesn't pull adjacent bytes into the high dword).

A deliberate design choice: an **empty expression is true** (unconditional
breakpoint), and a *parse error or unknown register also defaults to true* (`onError`
= true) — a malformed condition behaves like an unconditional stop, so the user
notices the broken condition rather than silently never stopping.
`EvalExpression` exposes the same operand evaluator for watch-style single-value
expressions.

### ProcessManager and live connections

`ProcessManager` is the lightweight native backend for the Communications and Memory
tabs (separate from the full `Debugger`). `enumerate()` snapshots all processes via
Toolhelp32 (`CreateToolhelp32Snapshot`/`Process32W`), best-effort opening each with
`PROCESS_QUERY_LIMITED_INFORMATION` to record bitness (`IsWow64Process`) and whether
it was openable. `modules(pid)` lists loaded modules (name/path/base/size) via a
Toolhelp32 module snapshot (`TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32`). It can also
`attach`/`readMemory` and `pumpDebugEvent` passively (a 0 ms `WaitForDebugEvent` that
auto-continues), carefully closing every handle the debug API hands back to avoid
per-event leaks.

**Live TCP/UDP connections** are gathered by owned tab workers using the IP Helper API:
`GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)` and
`GetExtendedUdpTable(UDP_TABLE_OWNER_PID)` for both `AF_INET` and `AF_INET6`, filtered
to the selected PID, with TCP states rendered to readable names (`ESTABLISHED`,
`LISTEN`, …). Each table has bounded allocation/retries and reports partial failures
without hiding successful families. IPv6 endpoints preserve numeric scope IDs. The
selected-process worker is latest-PID-wins; the system-wide history worker owns its
process-name/ESTATS work and publishes a bounded snapshot. Epochs reject stale results,
so no whole-table enumeration, sorting, or history merge runs on the render thread.

### Checked authorization return experiments

Authorization Trail's explicit **Break after call** action uses the exact decoded call
continuation and requires a matching x86/x64 PID, debugger generation, module incarnation,
thread, executable committed byte, and checked ASLR range before queuing a one-shot stop. At
that exact pause the debugger re-reads RIP and validity-bearing AL/EAX/RAX aliases. Temporary
**Force true/false** and **Restore** operations are accumulator-register writes only: the
debugger rechecks identity, RIP, and the expected masked value immediately before writing,
reads the context back, and attempts rollback if verification fails. No predicate/file code
bytes are changed by return forcing. Resume, RIP/thread change, detach, or module replacement
invalidates the captured value, and one observed return never upgrades the independent static
server/signature/feature conclusions by itself.

### How the UI consumes the snapshot

The Binary View tab renders entirely from `ctx.debug.snapshot()` each frame. A debug
toolbar (in both `App.cpp` and the Live Assembly view) shows a coloured state pill
(RUNNING / PAUSED / ATTACHED / TERMINATED), PID/TID, RIP/RSP (labelled EIP/ESP for
32-bit targets) and the last event string, plus Continue/Pause, Step Into, Step Over,
Step Out, Run to Cursor and Detach buttons. Keyboard shortcuts (active when no text
field is focused): **F5** Continue/Pause, **F11** Step Into, **Shift+F11** Step Out,
**F10** Step Over, **Ctrl+F9** Run to Cursor. Per-instruction context menus add/remove
software and hardware breakpoints and run-to-cursor; the **Live Assembly** view follows
RIP, masks breakpoint bytes, and highlights the current instruction and changed
registers between stops. Lower panels render Breakpoints, Registers (editable),
Threads (with follow/freeze), and the Call Stack.

The **call stack** (`computeCallStack`) is a **heuristic stack walk**, clearly labelled
as such in the UI (*"Heuristic walk for TID … N frame(s)"*). It scans up to 2048 stack
slots (4- or 8-byte slots by bitness) from RSP, and treats a value as a return address
only if it points into an executable committed region *and* the bytes immediately
before it decode as a `call` whose length ends exactly at that address. It is
recomputed only when the stop signature (RIP/RSP/TID/state) changes, to avoid
re-walking every frame.

### Adaptive unpack workflow

**Debug -> Adaptive Unpack** combines restored ESP/RSP, transfers into changed pages,
newly executable protection, timed entropy settling, run-free timeout, and analyst-selected
evidence through the bounded, Win32-free `Core/UnpackEngine`. OEP candidates expose their
score and evidence; the same telemetry produces a bounded heuristic hot-RIP, exact back-edge,
high-fan-in, and exception-handler report for VM-like dispatchers.

Fresh targets may be assigned before resume to a disclosed one-process, kill-on-close Windows
Job. It constrains children/lifetime but does not claim filesystem or network virtualization.
The sampler reads readable regions with debugger breakpoints masked and remembers changed and
executable pages. `Core/PeUnpack` then converts mapped PE32/PE32+ bytes to aligned disk sections,
restores valid ILT thunks or reconstructs imports in `.dsimp` from exact live export matches,
transactionally normalizes HIGHLOW/DIR64 relocations, and repairs or clears OEP, security-cookie,
Guard CF, signature, bound-import, and checksum metadata. Uncertain relocation tables fall back
to the captured runtime base; any failure retains a raw mapping and detailed report. Tests are
`unpack_engine_test` and `pe_unpack_test`.

### Static packed-PE recovery

**Debug -> Static Packed-PE Recovery** handles samples whose compressed payload can be
recovered without execution. `Core/StaticUnpack` validates and maps the disk PE, then looks
for an exact VMProtect-style `PACKER_INFO` plan: the ordered destination RVAs must match all
virtual-only non-BSS sections, the preceding record must resolve to valid five-byte LZMA1
properties, and every source and destination receives a finite validated extent. A bounded,
dependency-free LZMA1 decoder enforces hard input, exact-output, dictionary, candidate, block,
probability-model, allocation, and cancellation limits. Automatic mode prefers that evidence-rich plan and can
fall back to an independently valid finite LZMA-alone container; either strategy can be forced.

The operation runs on an owned/path-backed worker, verifies the exact source size/hash before
decoding, publishes phase/block/byte progress, and never blocks the render thread. In-memory
patches must be saved and reopened first. Recovered blocks form a mapped image which can pass through the shared
transactional `PeUnpack` reconstruction. The UI retains and saves three distinct provenances:
the reconstructed disk PE, decompressed mapped image, and raw/failure artifact. Per-block status,
confidence, evidence, issues, and a full report remain visible. OEP trust is reported separately:
a validated manual OEP (resolved against a nested PE's own preferred base) or a header entry inside
a completed recovered executable destination block is marked runnable; executable-section plausibility or a structurally valid nested PE alone is not
enough. An unchanged loader entry is saved under an analysis-only filename and can still be loaded
into ordinary analysis. Encrypted or version-mutated metadata and genuinely virtualized
code are reported honestly and handed to the live Adaptive Unpack workflow rather than guessed.
`static_unpack_test` covers PE32/PE32+, descriptor recovery, decoding, bounds, fallback,
cancellation, reconstruction, and worker result handoff.

### Passive process dump

The Communications process picker has a **Dump** action, mirrored by **Debug -> Passive Process
Dump**. For an existing PID, `Core/PassiveDump` uses query/read access only unless the analyst
opts into a brief final `NtSuspendProcess`/`NtResumeProcess` window. It never calls
`DebugActiveProcess`, injects code, patches bytes, or writes target memory. A launch-and-watch
source safely requotes analyst arguments, accepts an explicit working directory, and uses ordinary
`CreateProcess` without debug flags: the target is created suspended, assigned to a mandatory one-process kill-on-close Job, and resumed only after containment
succeeds. Cancelling or closing the modal cannot strand an owned launch without a visible stop
control.

Immediate, manual, and automatic timing are available. Automatic timing compares bounded page
fingerprints and Shannon entropy until both stabilize (or the declared timeout expires). The
final capture records validity and protection per page and refuses PE reconstruction if a
required file-backed page is missing. Unreadable discardable pages may be supplied from the
on-disk module only after strict header/layout identity checks; the original remote bytes and
validity mask remain separate and backfilled bytes never become import evidence. A 2 GiB aggregate
peak estimate reserves capture, transactional reconstruction, and export-map storage before work.
With final suspension, the module list and remote EATs are snapshotted before resume, then local
captured IAT/data bytes are matched exactly; without it, coherence is explicitly best-effort.
`PeUnpack` performs import, OEP, relocation, section, and metadata repair, but the original header
entry remains analysis-only. Runnable classification requires a manual OEP validated on an exactly
captured executable page and zero disk-backfilled pages; backfill downgrades the artifact without
mislabeling a validated OEP as unverified. The modal provides progress, cancellation, raw fallback, warnings, reports,
provenance-aware filenames/save labels, load handoff, and explicit
contained-launch termination. `passive_dump_test` covers the settle policy, a real read-only
self-snapshot and PE rebuild, pure memory/OEP policy, plus an opt-in contained-launch smoke test.

### Hide Debugger / anti-anti-debug

**Debug -> Hide Debugger / Anti-Anti-Debug** configures a session-atomic policy before attach or
launch; every option is off by default. `Core/AntiDebug` owns pure decisions, first-pristine
bookkeeping, debug-register masking, bounded warnings, and a production-seeded correlated clock.
The debug loop performs reversible PEB `BeingDebugged`/`NtGlobalFlag` writes and changes heap flags
only after OS heap-list provenance, region bounds, and a legacy NT-heap signature validate while
preserving unrelated policy bits. Detach
attempts conditional best-effort restoration only where the value still equals DisasmStudio's
concealed value, so a legitimate target-side change is never overwritten.

Target-local entry `int3` traps use bounded exports from the exact canonical, matching-machine
System32/SysWOW64 `ntdll.dll` and are admitted only on executable `MEM_IMAGE` pages owned by that
mapping. CET shadow-stack/IP validation disables synthetic-return hooks. The traps mediate selected `NtQueryInformationProcess`,
`NtQuerySystemInformation`, `NtQueryInformationThread`, `NtSetInformationThread`, invalid
`NtClose`, `NtGetContextThread`, `NtSetContextThread`, `NtQueryPerformanceCounter`, and
`NtQuerySystemTime` calls with exact buffer rules and proven self/same-process handles. Context reads
hide DR0-DR7; context writes omit target-supplied debug-register changes and reapply debugger-owned
hardware breakpoints. RDTSC/RDTSCP discovery follows decode-valid control flow recursively only from
the PE entry, fully validated x64 unwind roots, and trusted ntdll roots, with 50k/image and 250k/session
budgets. QPC, system time, and TSC share live-machine seeds and actual resumed-run intervals while
excluding debugger-paused time. Per-thread/same-address leases safely re-arm concurrent pass-throughs.
Internal traps carry an owner image, retire without writes on unload, are masked from live reads,
share sites safely with user breakpoints, and are conditionally restored. Live budget/clock/restore
counters, a 32-entry deduplicating warning cap, and the capability report make the boundary explicit: direct syscalls,
`KUSER_SHARED_DATA`, generated/self-modifying timing sites, kernel observers, the one-instruction
pass-through re-arm window, and instruction-perfect multicore time require the optional Hv
backend for transparent guarantees. `anti_debug_test` covers policy decisions, pristine restore,
DR masking, range gates, concurrent re-arm state, and synthetic clocks; event-loop integration is
Windows solution-build verified.

#### Limitations & notes

- **x86/x64 only.** The live debugger does not support A32/Thumb/A64/MIPS/PPC/RISC-V
  targets even though those decode statically; the step decoders are Zydis x64/x86.
- Connection tables cover IPv4 and IPv6 TCP/UDP; visibility still depends on OS access rights.
- The **call stack is heuristic** (return-address scanning, not unwind-info based) and
  is labelled as such; it can miss or invent frames in optimized/FPO code.
- Up to **four hardware breakpoints** total (DR0–DR3), the hardware limit.
- Attaching/launching may require **Administrator rights and matching bitness**;
  failures surface the `GetLastError` code in the UI.
- Conditional breakpoints support a **single binary comparison** only (no `&&`/`||`,
  arithmetic, or function calls); a malformed condition deliberately falls back to an
  unconditional stop so the user notices.
- `DebugSetProcessKillOnExit(FALSE)` means the target keeps running after detach by
  design; user-frozen threads are auto-thawed on detach.
## 07. The Binary View Workspace (Centerpiece)

The **Binary View** tab is the heart of DisasmStudio: it is where static analysis and live debugging meet. Everything else in the app (Projects, Sig Scanner, Memory Tools, Tech, Diff) ultimately routes the user here to "go look at this address." It lives in `src/Tabs/BinaryViewTab.{h,cpp}` — a single ~5000-line class (`ds::BinaryViewTab`) that owns six switchable **main views**, a four-tab **side panel**, thirteen **lower sub-tabs**, a **debug toolbar**, and a stack of modal popups. This chapter walks through every one of them and the machinery underneath.

The class implements `ITab`; `render(AppContext&)` is the per-frame entry point. `AppContext` carries the shared `binary` (`BinaryFile`), `debug` (`Debugger`), `disasm` (`IDisassembler`), and `project` (`ProjectState`). The tab keeps its own editing state (comments, renames, bookmarks, breakpoints, the navigation history, caches) and mirrors annotations to/from `ctx.project` each frame.

### Top control row & main-view selector

The header row offers a **goto box** (`##goto`, accepts `0x...` hex or a symbol name — hex is parsed, otherwise `lookupSymbol` resolves the name), **Back/Forward** buttons (`<` / `>`, disabled when history is exhausted), a **Goto sym** button (opens the symbol picker), a **Find text** button (opens the disassembly text search), and the radio-button **view selector**: Assembly (0), Pseudocode (1), Hex (2), Graph CFG (3), Call Graph (5), and Live Assembly (4, enabled only while attached). `mainView_` holds the selection; `render()` dispatches to `renderAssembly` / `renderPseudocode` / `renderHex` / `renderGraph` / `renderLiveAssembly` / `renderCallGraph`. The layout below is a left **main-view child**, a right **side panel** (`sideW = 320`), and a **lower-tabs child** (`lowerH = 200`).

### Main view: Assembly (full-program listing)

`renderAssembly` is the dispatcher; by default `asmFullProgram_` is true, so `renderAssemblyFull` shows the selected image regions as one scrollable listing. `buildFullListing` queues a `K_Listing` job whose worker performs no instruction decoding and has no instruction cap: it returns fixed 4 KiB executable `CodePage` descriptors for code/unknown spans plus region headers, strings, bounded data directives, and explicit truncated-tail rows. Classified executable data islands render as symbol-aware `db`/`dw`/`dd`/`dq` rows with evidence tooltips and split independent lazy `codeRegion` checkpoints, so page lookahead cannot decode across them. Function dividers and unresolved branch/xref `loc_` labels are materialized with each decoded page.

Rendering uses a 64-bit Fenwick index to map each descriptor's estimated or exact weight into virtual clipper rows. It decodes only pages requested by the visible viewport, goto, cursor stepping, or incremental trace planning, and retains them in a bounded 96-page LRU. The top visible address is restored when exact weights replace estimates. Bounded lookahead and propagated continuation checkpoints prevent variable-width x86/JVM/Thumb/RISC-V instructions that cross 4 KiB boundaries from being decoded twice. Exact predecessor work is capped at 64 KiB; farther random pages paint immediately from a constant-work local estimate, show `~` provisional addresses, and reconcile when exact checkpoints arrive. Provisional rows are excluded from trace and derived function/signature/jump-table authority and cannot publish persistent branch labels automatically. An explicit Breakpoint/Patch action accepts only its selected displayed instruction start as analyst authority (`!`), never the page or a trace seed; full-program and windowed assembly share that policy. Undecodable bytes fall back using the architecture's natural resynchronization width. Each actionable instruction row (`renderAsmRow`) retains the normal breakpoint, flow, address, bytes, syntax, annotation, navigation, and glow interactions.

Trace coverage adds a lower-priority row state. The app toolbar's **Trace** button
starts or stops the bounded one-shot block plan and **Clear Trace** removes collected
display state. Discovery walks lazy code-page descriptors at most 1,024 decoded
instructions per frame, admits only exact decoded instruction starts, reports progress,
and can be cancelled before planting. Trace start and every planning slice require an
exact matching x86/x64 path/module/bitness identity; every site uses checked file-to-runtime
translation and any failed proof cancels before planting. Executed instructions use the semantic green
`theme::col::good()` treatment only when a stronger RIP/cursor/target state does not
own the row, and remain visible after Stop until Clear Trace.

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

### The side panel: Bookmarks / Functions / Strings / Exports + byte search

At the top sits a **Byte Pattern Search** box (hex, no wildcards) with a **Live (process memory)** toggle; hits list below and into the **Results** lower tab, click-to-navigate (live hits open the live view).

- **Bookmarks**: add "+ here", click to go, right-click to rename/remove; persisted as file VAs.
- **Functions**: **Analyze** runs `FunctionAnalyzer` (entry/exports/call-targets/prologues) into `functions_`; a **Guess** toggle runs `FunctionNamer` (`guessFunctionNames`) to heuristically name anonymous `sub_` functions (`read_file`, `j_CreateFileW`, `start`, …). Guessed names render in **amber** (when no user rename overrides) with a tooltip giving the *basis* for the guess (`guessReason_`). The list is filtered into `fnVisible_` and clipper-rendered. Guesses are recomputed each analyze and never persisted.
- **Strings** (`scanStrings`): ASCII/UTF-8 + UTF-16LE runs (≥4 chars), file-mode or **Live** (scans loaded module images so addresses stay stable across rescans; auto-flips to Live + scans once on first attach). Click to navigate, right-click → **Find references (where used)**.

- **Exports**: a filterable view over `BinaryFile::exports()`, the bounded PE export-address-table model. It preserves aliases, ordinal-only entries, forwarders, and local code/data targets; local targets navigate to the appropriate code/Hex location, while forwarder targets remain copyable evidence.

### Lower sub-tabs

`renderLowerTabs` hosts debugger and analysis panels including **Breakpoints**, **Registers**,
**Watch**, **Threads**, **Call Stack**, **Stack**, **Functions**, **Xrefs**, **Notes**,
**Results**, **Patches**, **Imports**, **Resources**, **Exports / Symbols**, **Annotations**,
**Java**, **PDB**, **Address Inspector**, **Triage**, and **Hotkeys**. Panels whose evidence is not
available stay explicit and inert rather than inventing data.

The Triage **Authorization Trail** joins the existing string, xref, network, persistence,
function, and runtime views. It renders the ordered input-to-protected-operation stages, ranked
predicate fan-out, exact call/return branch consumers, object-root + displacement + width field
lineages, and proved secondary gates. Selecting evidence navigates to Assembly/Hex and xrefs. Its
four primary conclusions—locally valid format, server accepted, signature verified, feature
permitted—remain independent unknown/candidate/supported facts, with explicit completeness and
negative-search scope. A prominent warning identifies protected operations still behind secondary
gates when a global predicate reaches only branding or UI paths.

Each selected authorization location projects **static VA, RVA, file offset, and current runtime
VA** together, with validity retained independently. Runtime is unavailable rather than guessed
unless the active x86/x64 module identity and range match exactly. Eligible branch-consuming calls
also expose the identity-bound Break-after-call / AL-EAX-RAX force-and-restore experiment; inert
static patch advice lists all safety refusals instead of silently proposing a cleanup, cookie,
non-executable, side-effecting, or transport-only edit.

### Cross-references

Two complementary paths. **Targeted xref search** (`startXrefSearch`, triggered by the `X` key or a right-click "Find references…") sweeps executable code (file sections, or the debuggee's exec regions when attached) with `decodeOne` and `instrRefsAddr` (matches branch/call targets, memory data refs, *and* absolute immediates — the latter catches x86-32 `push offset str`), capped at 3000 hits, results shown in a popup. The **Xrefs lower tab** (`renderXrefsTab`) instead uses a precomputed whole-program `XrefIndex` (`buildXrefIndex`, cached by a content signature) for *instant* "who references the cursor / its enclosing function" lookups with no per-query sweep.

### Navigation & history

`navigateTo` moves the cursor and pushes a `NavEntry{va, live}` onto `navHist_`, dropping any forward branch. Crucially each entry remembers whether it was a **live** (runtime VA) or **static** (file VA) location, so `navBack`/`navForward` restore the correct *view* and never feed a runtime VA into a file-VA view. `gotoStatic` is the entry used by side-panel lists: it records history and, in the live view, shifts the file VA to the runtime VA. History is driven from the toolbar `<`/`>`, **mouse back/forward buttons**, and **Alt+Left/Alt+Right**. Per-instruction keys on the assembly views: **Enter** (follow target), **;** (comment), **N** (rename), **B** (breakpoint), **X** (xrefs), **J/K** (next/prev instruction, Shift = ×16), **P** (patch). Double-click an address or click the `; 0xADDR` target text to follow. Ctrl+G opens the focused **Goto Symbol** picker; Ctrl+Shift+F opens disassembly text search.

`Ctrl+K` opens the unified **Investigation** omnibox. Binary View gathers an immutable,
generation-stamped snapshot in bounded render slices; `InvestigationService` builds/ranks it on
one joined worker. Commands, exact FILE/LIVE addresses (including zero), functions, strings,
imports, comments, resources, byte/text hits, xrefs, live modules, and recent queries share a
typed result model. Superseded generations cannot publish or navigate. The lower **Address
Inspector** applies the same explicit FILE/LIVE discipline while showing file offset, RVA,
static VA, runtime module+offset, mapping confidence/evidence, xrefs, classification/type,
analyst overrides, and ordered overlapping-patch state.

### Live↔file VA translation under ASLR

When attached, the process loads the main module at a base that differs from the file's preferred `imageBase`. `liveMainBase` discovers that base (matching the loaded file's name, falling back to the lowest-base module), and `fileVAtoLive` / `liveVAtoFile` shift addresses by that delta. This is why file-keyed data (analyzed functions, comments, renames, bookmarks, patches) lines up with live instruction addresses, and why annotations created in the live view are stored under the *file* VA. All three helpers are no-ops when not attached or the base is unknown.

### Patching (hex + Keystone assembly)

The **Patch popup** (`renderPatchPopup`) supports two modes: **Assembly** (Keystone via `Assemble` for x64, x86, A32, Thumb, and A64) with a live byte preview, and **Hex bytes** with a disassembly preview and an architecture-correct "NOP fill" helper. `applyPatchBytes` captures pristine original bytes, records an ordered `PjPatch` keyed by file VA, updates live/static memory as applicable, and invalidates the affected analysis/listing caches. One-click **NOP out** is available on rows and over multi-line selections. The **Patches** tab lists every patch with per-row revert; `File ▸ Save Binary As…` later splices them to disk.

Every patch can belong to a stable named experiment set while the one global patch vector remains
the authoritative later-wins order. The Patches tab creates/renames sets, selects the destination
for new edits, toggles them through checked pristine-image reconstruction, reassigns or reverts
members, deletes empty sets, and compares Current/Baseline/Ungrouped/single-set selections without
mutation. Invalid membership, original-byte disagreement, changed mappings, and conflicting enabled
overlaps fail closed; a rejected transition publishes no partial image, live write, or project state.

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
C export is x86/x64-only and remains disabled on other architectures and until background
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

- The full listing has **no global instruction cap**. It decodes only requested 4 KiB pages and never linearly sweeps an executable span for display. A far variable-width page may remain visibly provisional when no trusted checkpoint lies within the 64 KiB exact-preparation bound. Breakpoint/Patch can explicitly accept one displayed start, but no page-wide or trace authority is inferred. Overlapping/obfuscated code can still render `db` filler rows rather than the analyst's intended alternate decode.
- The **call-stack walk** is explicitly heuristic (scans for qwords following a `call`); frames beyond frame 0 are best-effort and the UI says so.
- Guessed function names, the inferred `guessSignature`, the instruction gloss, and the API-purpose strings are all **heuristic** and labelled as such (amber tint, "guessed name" tooltips, "signature is heuristic" banner).
- **Keystone** assembly patching covers only x86/x64/A32/Thumb/A64; other arches can be disassembled (Capstone) but not assembled.
- Conditional-branch evaluation, register hints, and the live string/pointer dereferences are **x86/x64 only** — consistent with the Win32 debugger, which never targets other arches.
- Live string scanning and the various sweeps are **byte-capped** (256 MB strings/value search, 64 MB code search) and **hit-capped** for responsiveness; results may be truncated with a status note.
- The naive live "Pseudo" line translator (`pseudoLine`/`buildPseudo`) is separate from the structured decompiler used by the Pseudocode views; the structured pipeline is the primary one.
## 08. The Other Workbench Tabs

DisasmStudio is a browser-style single window with a top tab strip. Chapter 07 covered the **Binary View** — the analysis centerpiece. This chapter documents the other six top-level tabs that surround it: **Projects**, **Communications**, **Sig Scanner**, **Memory Tools**, **Binary Diff**, and **Binary Tech**. Each is implemented as an `ITab` subclass with a `name()` and a `render(AppContext&)` method (one file per tab under `src/Tabs/`), and each leans on the shared `AppContext` for cross-tab state: the loaded `BinaryFile` (`ctx.binary`), the live `Debugger` (`ctx.debug`), the active disassembler (`ctx.disasm`), the persisted `ProjectState` (`ctx.project`), and the cross-tab navigation helpers `ctx.gotoAddress(va)` and `ctx.requestedTab`.

A recurring design choice across all of them: the tabs are thin, immediate-mode UI shells over reusable, testable Core logic. The Projects tab is just a view over `LoadRecents()`; Binary Tech is a view over `ScanCapabilities()`; the scanners and process tools are views over `ProcessManager`/`Debugger`. None of these tabs invent data — where a result is heuristic or unavailable, the UI says so in dimmed text.

---

### Projects tab

**File:** `src/Tabs/ProjectsTab.h/.cpp`. Backed by the on-disk recents index.

The Projects tab is the landing/dashboard view. It is *real* — not a mock list — because it reads the same JSON recents index that `SaveProject()` upserts every time a binary is analyzed. `ProjectsTab::refresh()` simply calls `LoadRecents()` (from `Core/Project`) into a `std::vector<RecentEntry>`. Each `RecentEntry` carries `hash`, `path`, `name`, `arch`, `status`, and `lastOpenedUnix`. The index lives alongside the per-binary sidecars under `%APPDATA%/DisasmStudio/projects/`.

**Auto-refresh.** The tab caches the last-seen project hash in `lastSeenHash_`. On first paint, and whenever `ctx.project.hash` changes (i.e. a different binary became the active project), it re-reads the index. So opening or saving a target makes it appear in the recents list without a manual refresh.

**Layout.** A two-pane split. Top toolbar: **Open Binary…** (calls `ctx.openBinaryDialog()`, and on success switches to the Binary View via `ctx.requestedTab`), **Refresh**, and a hint pointing at *File ▸ Open as Raw…* for shellcode/firmware. Any open error is shown in red.

The **left pane** is a three-column table (Name / Arch / Opened) listing the recents. Interactions:
- Single click selects a row (`selected_`).
- Double-click opens it (`ctx.loadBinaryPath(r.path)`, then jump to Binary View; failure stores an `openError_`).
- Right-click context menu: **Open**, **Copy path** (to the clipboard), **Remove from list** (calls `RemoveRecent(hash)` and refreshes). Timestamps are formatted by a small `whenStr()` helper using `localtime_s`.

The **right pane** shows two detail blocks. *Selected* echoes the highlighted recent's name, path, arch, content hash (printed as `%016llX`), and last-opened time, with an **Open this project** button. *Loaded Binary* describes the currently open binary — path, `formatName()`, image base, entry point (`imageBase + entryPoint`), section count — followed by a *Saved analysis* summary pulled straight from `ctx.project`: counts of comments, renames, bookmarks, breakpoints, and patches. A **Save project now** button forces a synchronous commit; the normal path is a short debounced autosave plus a verified final commit on close/exit/switch.

**Why this design.** The recents index gives the tool a memory of past targets keyed by *content hash*, not path — so a binary moved or copied still resolves to the same analysis sidecar. The summary block makes the dashboard a quick "what have I done to this file" glance.

---

### Communications tab

**File:** `src/Tabs/CommunicationsTab.h/.cpp`. Native-process backend: processes, modules, and live connections.

This tab is the live-system side of the tool. Its main `render()` splits the area: a 55%-width left child for the process list, and a right child stacking **Modules** above **Connections**.

**Process list (`renderProcesses`).** Enumeration is real, via `ProcessManager::enumerate()` (Toolhelp32). Results are sorted by name for stable ordering. A subtle correctness detail: the selection follows the **PID**, not the row index — on re-enumerate the code records the previously selected PID and re-locates it, so its modules/connections never get listed against the wrong process after a re-sort. A name filter box (`filter_`) narrows the table. Each row shows PID, name, Arch (`is64 ? "x64" : "x86"`, WOW64-aware best-effort), an **Access** column (green "ok" / red "denied" from `ProcessInfo::canOpen`), and an **Attach**/**Detach** action. Attach calls `ctx.debug.attach(pid, err)` (the real Win32 debug API, `DebugActiveProcess`). On success: if no file is loaded, it points `ctx.arch` at the debuggee's bitness and calls `ctx.rebuildDisassembler()` so generic decode paths are correct, then `ctx.openLiveAssemblyView()`. A green "| debugging PID N" badge appears when a session is live.

**Modules (`renderModules`).** For the selected process, lazily fetches `pm_.modules(pid)` (Toolhelp32 module snapshot), caching per PID. Columns: Module / Base / Size (KB). If empty, it tells the user this usually means a bitness or rights mismatch and suggests running as Administrator.

**Connections (`renderConnections`).** Live per-process IPv4+IPv6 TCP/UDP endpoints, real, via the IP Helper API. An owned latest-PID-wins worker queries the four owner-PID tables (`AF_INET`/`AF_INET6` × TCP/UDP) through bounded size/fetch/retry and allocation caps, then filters on `dwOwningPid`; epochs prevent a late result from replacing the newly selected process. One failed table produces an honest partial-refresh warning without suppressing successful rows. `Core/NetworkEndpoint` formats canonical bracketed IPv6 endpoints with numeric scope IDs and IPv4-mapped addresses. The pane separates local/remote, protocol, family, and TCP state, auto-refreshes once per second, and offers IPv4/IPv6/TCP/UDP plus text filters. Whole-table queries and result sorting never run in `render()`.


---

### Sig Scanner tab

**File:** `src/Tabs/SigScannerTab.h/.cpp`. Byte-pattern scanning with `??` wildcards.

The top bar holds a pattern input (defaulting to `48 89 5C 24 ?? 57 48 83 EC 20`), a **Scan** button, a **Live** checkbox, a signature-name box, **Save Sig**, and a progress bar. Below is a four-way sub-tab bar.

**Pattern parsing.** `parsePattern()` converts a string like `"48 89 ?? 24"` into a `bytes` vector plus a parallel `mask` of bools. Whitespace is skipped; a `?` (single or `??`) pushes a wildcard (mask=false); a hex pair is parsed with `sscanf("%x")`. A malformed pattern returns false (and is reported as health "malformed", count `-1`).

**Scan (`scan`).** Two modes:
- **File mode** (default): linear search over `ctx.binary.bytes()`; each file-offset hit is mapped back to a VA with `BinaryFile::offsetToVA` (the same mapping strings/byte-search use) so results are clickable. Capped at 4096 results.
- **Live mode**: walks the attached process's committed regions (`ctx.debug.regions()`), reading in 1 MB chunks with a `(pattern-1)`-byte **overlap** so a match straddling two chunks is never dropped. It skips non-readable/non-`MEM_COMMIT` regions, enforces a 512 MB byte budget and a 4096-result cap to stay responsive, and labels each hit with the module it falls in (resolved against `ProcessManager::modules`, defaulting to "live"). Works whether the target is paused or running.

**Sub-tabs.**
- **Results** — table of Address / Signature / Module. Clicking an address calls `ctx.gotoAddress()` (navigates the Binary View). A caption notes whether results came from "(live process memory)" or "(file on disk)".
- **Current Scan** — shows the active pattern, total bytes loaded, and the progress bar (mainly useful for the chunked live scan).
- **Sig Health** — a saved-signature scorecard. `refreshHealth()` re-counts each signature against the loaded binary via `countMatches()` (capped at 100k for speed), and `healthFromCount()` maps the count to a label: `malformed` (−1) / `none` (0) / `unique` (1) / `multiple` (>1), color-coded green/amber/red. This is the real, match-count-based "is my signature still good" check that makes saved patterns trustworthy across rebuilds. Three starter signatures ship pre-populated.
- **All Functions** — runs `FunctionAnalyzer::analyze(ctx.binary, *ctx.disasm)` (recursive-descent + prologue + export sweep) and lists Address / Name / Size with a name filter; the analyzer's `lastSummary()` is shown. Clicking a row navigates to it.

**Cross-tab handoff.** If the Binary View's right-click "create signature" sets `ctx.pendingSignature`, this tab loads it into the pattern box and scans immediately on next paint.

---

### Memory Tools tab

**Files:** `src/Tabs/MemoryToolsTab.*`, `src/Core/ProcessMemorySession.*`, `src/Core/MemoryScan.*`, `src/Core/MemoryPointer.*`, and `src/Core/MemoryTable.*`. Memory Tools can reuse the exact active debugger session or open a **passive process-memory session** by PID. Passive open never calls `DebugActiveProcess` or consumes debug events and can retain a read-only session when Windows denies write rights. Both paths bind operations to PID plus session generation; passive identities also retain process creation time to reject PID reuse.

**Value scanner.** The typed codec supports signed and unsigned 8/16/32/64-bit integers, `float`, `double`, AOB byte arrays with `??` wildcards, and validated UTF-8/UTF-16LE text with optional terminators. Numeric input supports decimal and raw-width hexadecimal. Predicates are **Exact, Not equal, Greater/Less than value, Between, Changed, Unchanged, Increased, Decreased, Increased by, Decreased by, and Unknown initial**, with optional float tolerance.

- A cancellable first scan selects committed/readable memory by private/image/mapped kind, writable/executable state, explicit address range, alignment, and byte-admission bound.
- `MemoryScanSnapshot` owns previous bytes per chunk and a compact candidate bitmap. Chunk lookahead preserves cross-boundary values; next scans re-read/refine whole retained chunks instead of making one `ReadProcessMemory` call per candidate.
- Candidate counts are exact for the admitted readable scope. Results are enumerated by stable ordinal pages, eliminating the old 1,000-row display and 2-million-hit storage truncations without materializing every address.

**Hex viewer/editor and regions.** The live inspector is a 256-byte hex/ASCII window with history, byte selection, copy, byte-array paste/edit, changed-byte highlighting, and pointer-follow actions. The cached searchable region browser shows base/end/size, protection, allocation type, and module, and can route a range into either the viewer or scanner. The debug toolbar and Ctrl+K command **Inspect Live RIP in Memory Tools** carry the current PID/session generation and RIP directly to the inspector.

**Pointer scan.** A cancellable worker performs deterministic 32- or 64-bit backlink discovery across an admitted region snapshot. Depth, positive offset, result/frontier/read/comparison, and cancellation limits are explicit. Stable module-relative roots and short chains rank first; a result can be resolved against the identity-bound reader or added as a relocatable module-plus-offset pointer record.

**Address table and freeze.** Records support absolute or module-relative bases, pointer offsets, all scanner value types, grouping/description, hexadecimal display, and per-row protection authority. A strict bounded **JSON table** is saved separately from the project sidecar. Loading always clears runtime `enabled` and `freezeActive` flags—even if an untrusted file sets them—so opening a table never starts target reads or writes. Resolution prefers exact normalized module paths and rejects ambiguous basename matches.

A dedicated worker applies **Constant, Minimum, or Maximum** freeze policies independently of tab rendering, always against the current process identity. Debugger writes are session-checked and batched. Passive writes capture original bytes, apply and verify the change, restore temporary page protection, and attempt verified rollback after a post-write failure. Normal authority permits only already-writable, non-executable committed data; a row must explicitly allow protection changes for read-only or executable pages, and guard/no-access spans remain denied.

---

### Binary Diff tab

**File:** `src/Tabs/BinaryDiffTab.h/.cpp`. Compare two binaries with synchronized hex panes.

Before a diff exists, `renderLoadZone()` draws a centered "drop zone" — two cards (LEFT / RIGHT) each with a **Load…** button, plus a **Compute Diff** button enabled once two paths and their stable Win32 identities have been captured. The render thread never loads or parses either binary.

`computeDiff()` enqueues work on a persistent cancellable worker. The job contains only paths and stable Win32 file identities; the worker reloads owned `BinaryFile` objects, verifies identity before and after work, scans bytes once, counts every mismatch, keeps bounded samples, and coalesces navigable change regions. Optional section-aware mode aligns sections by name then RVA. After computing, a compact toolbar lets you swap either side or **Recompute** without leaving the view.

The diff view is two equal bordered panes rendered by `renderPane()`, each a clipper-driven (`ImGuiListClipper`) 16-byte-per-row hex+ASCII dump. A byte is highlighted **red** when it differs from the other file (or lies past the other's end); matching bytes are muted. **Synchronized scrolling:** only the hovered ("master") pane shows a scrollbar and drives `scrollY_`; the follower is positioned with `SetScrollY` to match. Hovering either pane hands it the master role, so scrolling either side keeps both aligned. Flat mode is exact by file offset; section-aware mode is better for changed layouts.

**Semantic mode.** Opting in builds immutable function models on the same worker and matches unique authoritative names first, then relocation-normalized typed-instruction hashes, canonical CFG structure, and already-matched call neighborhoods. The UI separates matched/added/removed functions, shows confidence and concrete evidence, lists instruction edit hunks, and presents a synchronized two-column instruction review. Persisted names, comments, prototypes, and bookmarks become proposals only: every checkbox starts clear, the user must explicitly select and apply each proposal, and application is rejected unless the destination image hash equals both the active binary and project identity.

---

### Binary Tech tab

**File:** `src/Tabs/BinaryTechTab.h/.cpp`. Real capability/technique detection.

**Run Tech Scan** calls `ScanCapabilities(ctx.binary)` from `Core/TechScan` — pure, unit-testable logic that detects capabilities three ways: **imported-API grouping** (anti-debug / network / crypto / injection / dynamic-API / spawn), **packer section-name signatures**, and **distinctive byte patterns** (direct-syscall stub, AES S-box, SHA-256 constants). Each `Capability` carries `name`, `category`, a `confidence` (0..1), a representative `address` (an IAT slot or pattern hit, or 0), and a human-readable `detail` listing the evidence. Results are sorted by descending confidence, and the scan returns an **empty list for a clean binary** — no fabricated findings.

**Layout.** A category filter box and a count caption, then a two-pane split. The **left** table lists Capability / Cat / Conf, where confidence is color-coded (green >85%, amber >65%, red below). Selecting a row populates the **right** detail pane: name, category, confidence, address, a **View in disassembly** button, and the wrapped `detail` evidence. Below that is an inline preview: if the capability's address lands in an executable section (`vaIsExecutable`), it disassembles ~10 instructions there with `ctx.disasm`; otherwise it shows a 64-byte hex dump and suggests using *Find references* in the Binary View. Double-clicking a capability (or the button) calls `ctx.gotoAddress(c.address)` to jump to the code.

**What is real vs heuristic.** The detection is real (it reads actual imports, section names, and byte patterns), but the `confidence` percentage is a heuristic score, and the categorization is best-effort — the UI presents it as such (a percentage, not a verdict).

---

#### Limitations & notes

- **Communications connections cover IPv4 and IPv6 TCP/UDP.** Module/connection visibility still depends on having matching bitness and sufficient rights (often requires Administrator); individual table failures are shown as partial refreshes.
- **Live scans are bounded** for responsiveness: the Sig Scanner caps at 512 MB scanned / 4096 results with chunk overlap. Memory Tools uses configurable byte/work admission bounds, keeps every candidate in the admitted readable chunks, reports the exact count, and pages display rows without a hit cap.
- **Memory Tools needs a live process, but not a debugger attach.** It can open a passive memory session or reuse the current debugger session. Windows rights, target exit, identity changes, and unreadable regions are surfaced explicitly. Binary Diff needs two file inputs and keeps flat, section-aware, and semantic work cancellable.
- **Memory tables are durable JSON artifacts, not project-sidecar state.** Loaded rows are deliberately disabled and unfrozen until the analyst enables them for the current target.
- **Binary Tech `confidence` is a heuristic score**; the detected evidence (imports/sections/patterns) is real, and a clean binary yields an empty list rather than invented capabilities.
## 09. Persistence, Projects & Reporting

This chapter covers everything that survives a restart: the per-binary analysis
state DisasmStudio persists, the JSON sidecar format and its hand-rolled JSON
library, the recents index that backs the **Projects** tab, when state is saved
and reloaded, and the **Export Analysis** report generator (Markdown / HTML). The
guiding design idea is simple: a binary's content hash is the identity key, so the
analyst's annotations follow the *bytes*, not the file path — rename a file, move
it, copy it, and your comments, renames, bookmarks, breakpoints, named patch sets and notes
come right back. There is no notion of a manually-saved `.dsproj` file the user
juggles; persistence is implicit and automatic.

Key files: `src/Core/Project.h`, `src/Core/Project.cpp` (state model + sidecar
I/O + recents), `src/Core/PatchSet.h` and `src/Core/PatchedImage.h` (bounded
selection, pristine reconstruction, and comparison), `src/Core/Json.h`, `src/Core/Json.cpp` (the tiny JSON lib),
`src/Core/Report.h`, `src/Core/Report.cpp` (report formatters). Wiring lives in
`src/App.cpp` (`AppContext::loadProjectForBinary`, `saveProject`,
`exportAnalysisFile`), `src/Tabs/BinaryViewTab.cpp` (`loadProjectState`,
`saveProjectState`, `exportAnalysis`), and `src/Tabs/ProjectsTab.cpp` (the UI).

### What gets persisted: `ProjectState`

`ds::ProjectState` (in `Project.h`) is the single struct holding everything
worth saving for one binary. It splits into identity/metadata and the analysis
annotations themselves.

Identity / metadata:
- `hash` — the binary's 64-bit content hash; this is the sidecar's filename key
  (`0` means "no project").
- `binaryPath`, `arch` (`"x86"`/`"x64"`/`"ARM"`/`"ARM64"`/…), `engine`
  (`"Zydis"`/`"Capstone"`), `name` (display name, defaults to the file name),
  `status` (defaults to `"analyzed"`), and `lastOpenedUnix` (a Unix timestamp).
- Raw-layout identity: the exact image base, an explicit-entry bit plus entry VA (including
  VA 0), and bounded named landmarks/evidence. A raw blob has no header from which these can
  be reconstructed on a recent-project reopen.

Analysis annotations (the part actually worth persisting):
- `comments` — `unordered_map<uint64_t,string>`, address → user comment.
- `names` — `unordered_map<uint64_t,string>`, address → user rename/symbol.
- `bookmarks` — `vector<PjBookmark>` (`{address, label}`).
- `breakpoints` — `vector<uint64_t>` of addresses.
- `bpConditions` — `unordered_map<uint64_t,string>`, address → condition
  expression, kept 1:1 with `breakpoints`.
- `patches` — `vector<PjPatch>`, each holding `{address, orig, bytes, patchSetId}` where
  `orig` and `bytes` are the original and replacement byte vectors. Their vector
  order is application order and is preserved because overlapping patches are later-wins.
- `patchSets` — presentation records `{id, name, enabled}`. Zero is the implicit
  backward-compatible **Ungrouped** set; named ids are stable project-local identities rather
  than vector indices.
- `functionOverrides` and `dataOverrides` — authoritative analyst decisions for
  define/undefine, exact function extents, noreturn/convention/prototype/mode, and
  bounded code/data/string/pointer-table/jump-table spans with optional types.
- `lastCursor` — the last cursor VA, so reopening returns you where you were.
- `notes` — free-form text from the Notes tab.
- `watches` — the watch-panel expressions.

Two helpers shape the save policy. `reset()` clears the struct to defaults
(called when switching targets), and `hasContent()` returns true only if there is
real analysis present (any comment, name, bookmark, breakpoint, patch or patch set, note,
watch, analyst override, valid cursor, or saved raw mapping). Crucially, ordinary open metadata alone is not "content" —
a freshly-opened binary with only an auto-stamped open time is considered empty.
This gate prevents `%APPDATA%` from filling with junk sidecars for binaries the
user merely glanced at (see save policy below).

### The JSON sidecar and where it lives

`ProjectsDir()` resolves the base directory: on Windows it is
`%APPDATA%\DisasmStudio\projects`, otherwise `$HOME/.disasmstudio/projects`
(with sensible relative fallbacks if the env vars are missing). It is overridable
via the `DS_PROJECTS_DIR` environment variable — used by the unit tests so they
can read/write to a sandbox directory without touching the real profile.

`ProjectPathForHash(hash)` creates the directory if needed and returns
`<dir>/<HASH>.json`, where the hash is formatted as a fixed 16-digit uppercase hex
string (`%016llX.json`). One file per binary, named purely by content. The
recents index is a sibling file, `index.json`, in the same directory.

The content hash itself comes from `BinaryFile::contentHash()` (in
`BinaryFile.cpp`): a 64-bit **FNV-1a** over the raw file bytes, mixing the length
in at the end so two blobs differing only in trailing zero padding still hash
differently. The value is computed once and cached (`hashValid_`) from the
*pristine* file at load time. This is a deliberate, load-bearing detail: when the
user applies patches, `BinaryFile::writeImage` rewrites the in-memory image but
`contentHash()` is intentionally left untouched. If patching changed the hash, the
sidecar key would move out from under a live project and the patches would orphan
their own annotations. Keeping the hash pinned to the original bytes means the
project key is stable across patch/revert cycles within a session.

### Serialization: addresses as hex strings (and why)

`SerializeProject` / `DeserializeProject` (split out from filesystem I/O so they
are unit-testable with no disk) convert `ProjectState` to and from a JSON object.
The serialized document carries `version: 4`, the metadata fields, an optional
`rawMapping` object, annotations, named patch sets, ordered patches, and analyst overrides. Maps
are sorted by address for stable output, but the patch vector is deliberately
not sorted because its order defines overlap precedence. Versions 1–3 remain
readable; legacy patches have no membership field and load into Ungrouped. New saves include an
explicit hex-string set id for every patch.

The single most important serialization decision: **every address is stored as a
hex string, not a JSON number.** The reasons:

- JSON has only one numeric type, and this codebase's JSON lib stores numbers as
  `double` (see below). A `double` has 53 bits of mantissa, so a 64-bit address
  above 2^53 cannot round-trip without precision loss. A high virtual address
  (common with PIE/ASLR images and 64-bit code) would silently corrupt.
- Storing `"0x1400123456"` as a string and parsing it back with `strtoull`
  guarantees an exact 64-bit round-trip. The project round-trip test specifically
  checks an address like `0x1400123456` for `lastCursor`.

Helpers enforce this: `hexU64` formats `0x%llX`; `parseU64` strips an optional
`0x`/`0X` prefix and parses base-16 with `strtoull`, returning `0` on no-digits or
overflow (it never fabricates a value). Patch byte vectors are stored as
space-separated hex pairs via `bytesToHex` / `hexToBytes`.

Deserialization is defensive — a corrupt or hand-edited sidecar must not be able
to drive bad behaviour:
- Breakpoints are de-duplicated on load so the `breakpoints` vector and the
  `bpConditions` map stay 1:1 (a duplicate address would break that invariant).
- `hexToBytes` requires *full* two-hex-digit bytes and stops on a lone trailing
  nibble rather than fabricating a wrong byte.
- Patches are validated before the file-splicer is ever allowed to trust them:
  `bytes` must be non-empty, `orig` and `bytes` must be the same length, and the
  size is capped at 1 MiB. Named set ids/names and memberships must be bounded and
  unique, overlapping records must agree about pristine bytes, and enabled sets may not
  request conflicting replacement bytes. A malformed version-4 patch or invalid set plan
  rejects the sidecar rather than publishing a partial selection — this
  matters because saved patches are re-applied to the in-memory image on reopen
  and can be spliced into a written-out binary via **Save Binary As…**.
- Override counts, text, ranges, duplicates, overflow, and data-span overlap are
  validated before they can influence analysis; explicit validity fields keep VA 0 legal.

### The hand-rolled JSON library (`Json.*`)

`src/Core/Json.{h,cpp}` is a tiny, dependency-free JSON value + parser +
serializer — "just enough" to back persistence, deliberately added so no new
vcpkg dependency was needed. `ds::json::Value` is a tagged union over
`Null/Bool/Num/Str/Arr/Obj`; numbers are `double`; objects are an
**insertion-ordered** `vector<pair<string,Value>>` (so emitted key order is
predictable, not hash-randomized). Construction helpers (`Value::Obj()`,
`Value::Arr()`, `Value::Str()`, `Value::Int()`, …), `set`/`find`/`push`, and typed
getters (`getStr`, `getInt`, `getBool` with defaults) make the (de)serializers
terse.

`Dump(value, pretty)` pretty-prints with two-space indentation by default,
escapes strings (including control chars as `\uXXXX`), and prints whole numbers
without a decimal point. The parser is a small recursive-descent `Parser` that is
hardened against hostile input: it caps nesting at `kMaxDepth = 200` to avoid
stack overflow, rejects trailing garbage after the root value, validates number
tokens (rejecting `"1e"`, `"."`, `"--5"`), correctly decodes `\u` escapes
including UTF-16 surrogate pairs into UTF-8, and rejects lone/invalid surrogates.
Because it stores numbers as `double`, the Project layer's hex-string-for-address
convention isn't a stylistic choice — it's what makes 64-bit fidelity possible at
all on top of this library.

### When state is saved and reloaded

Loading (`AppContext::loadProjectForBinary` in `App.cpp`): on opening a binary it
`reset()`s the project, computes the content hash, and calls `LoadProject(hash)`.
If a sidecar exists it is restored. On the normal open path, a raw candidate is first
re-staged at the saved base with the saved explicit entry and named landmarks, then the
saved arch/engine is applied. This prevents every VA-keyed annotation from shifting on a
recent raw reopen. Invalid saved raw metadata is ignored safely. On the interactive
**Open as Raw…** path, the dialog's explicit mapping and architecture win. It then stamps fresh metadata
(hash, path, arch, engine, name, `lastOpenedUnix`). A bounded firmware rescan recreates
the evidence report on an ordinary raw reopen without changing the saved mapping.

The Binary View tab then mirrors `ctx.project` into its live editing state via
`loadProjectState` (comments, names, bookmarks, breakpoints + conditions, notes,
watches, named patch sets, and `lastCursor` → cursor). If a debugger is already attached, saved
breakpoints (with conditions) arm only after exact x86/x64 path/module/bitness matching;
otherwise they remain pending. The enabled patch-set selection is reconstructed from checked
pristine bytes and written into the in-memory image so the disassembly reflects it across sessions — and
because the hash was cached from the pristine file, those writes don't change the
sidecar key.

Mutations mark a project revision dirty. After a short debounce, the App snapshots
the state and commits it on a background task, keeping serialization and filesystem
work off the render thread. It also verifies a synchronous final commit at every
destructive boundary:
- **Window close / Alt+F4 / Exit** — `App` calls `ctx_.saveProject()` on
  shutdown.
- **File ▸ Close Binary** — flush, then unload and `reset()`.
- **Switching targets** — `loadBinaryPath` / `loadRawPath` call `saveProject()`
  for the *outgoing* binary before loading the new one.
- **Projects tab "Save project now"** button — an explicit manual flush.

Binary View mirrors live state into `ctx.project`, and mutation sites call
`markProjectDirty()`. In-flight and saved revisions are tracked separately, so an
edit made during a save remains dirty. Failure remains visible, retains in-memory
state, and is retried without allowing close/switch to discard the project.

`SaveProject` itself enforces the empty-project policy: if `hasContent()` is
false it records the open in the recents index but writes **no** sidecar (and
leaves any pre-existing sidecar from a prior, content-bearing session untouched);
otherwise it writes the sidecar and upserts recents.

### The recents index and the Projects tab

`index.json` is a flat array of `RecentEntry` (`hash`, `path`, `name`, `arch`,
`status`, `lastOpenedUnix`). `upsertRecent` removes any existing entry for the
same hash, inserts the new one at the front (most-recent-first), and trims the
list to **50** entries. `LoadRecents` tolerates either a bare array or an object
with a `"projects"` array, skipping malformed entries. `RemoveRecent(hash)` drops
an entry and reports whether anything changed.

The **Projects** tab (`ProjectsTab.cpp`) is this index made visible. It re-reads
`index.json` on first paint and whenever the active project hash changes, so a
newly opened target shows up without a manual refresh. The layout is a left list
(Name / Arch / Opened, with human-readable local timestamps via `whenStr`) and a
right details pane. Interactions: **Open Binary…** and **Refresh** buttons;
double-click or right-click ▸ **Open** to reopen (which calls
`ctx.loadBinaryPath` and switches to Binary View); right-click ▸ **Copy path** /
**Remove from list**. The details pane shows the selected entry's metadata and,
for the currently loaded binary, a live "Saved analysis" summary (counts of
comments, renames, bookmarks, breakpoints, patches) plus the **Save project now**
button and a reminder about debounced autosave and final close/exit commits.

### Save ASM / Save C (source export)

Source export is intentionally separate from the persisted project and the analysis
report below. **File ▸ Save ASM… / Save C…** exports either every analyzed function/
executable range or one selected function. ASM preserves resolved names and analyst
comments. On x86/x64, C has two contracts: `CodeExportCStyle::Readable` keeps the decompiler's
display pseudo-C, while `CodeExportCStyle::Compilable` produces a self-contained portable
C11 translation unit with normalized identifiers, declarations/stubs, and explicit
fallbacks where the lightweight decompiler cannot express an operation faithfully.

`Core/CodeExport` keeps generation independent of ImGui and Win32. The pure
`GenerateCodeExport(request, decoder, out, cancel, progress)` function streams into an
arbitrary `std::ostream`; `CodeExportService` wraps it in a dedicated one-job thread and
opens the path chosen by `AppContext::selectCodeExportPath`. A request snapshots the
engine/architecture, scope, function table, import/discovered/user name layers, comments,
source name, destination, and expected image revision. The worker creates its own decoder
through the injected factory, so a long whole-program export neither touches `ctx.disasm`
nor occupies the load-time `AnalysisService` worker.

Progress is structured (`Preparing`, `Assembly`, `Decompiling`, `Finalizing`) rather than
a spinner-only flag: assembly reports bytes, C reports functions and the current function
VA, and both expose bytes written. `cancel()` is non-blocking for the render thread;
`cancelAndWaitIdle()` is the stronger lifetime barrier used before loading, closing,
patching, or reverting the borrowed `BinaryFile`. The source files are write-out artifacts
only; their paths/options are not stored in the project sidecar and there is no import path.
The service writes a same-directory temporary file and commits it only after generation and
flush succeed; an existing destination is protected by a rollback backup during replacement,
and failure/cancellation cleans the staged artifacts without changing that destination.

### Export Analysis (Markdown / HTML report)

`Report.{h,cpp}` are pure formatters (no ImGui/Win32, hence sandbox-testable) that
turn analysis into a shareable document. `RenderReportMarkdown` and
`RenderReportHtml` consume a `ReportInput` containing the title (binary file name),
content hash (hex), arch, engine, function and string counts, and lists of
`renames`, `comments`, `bookmarks`, `notes`, plus a vector of `ReportFunction`
(`address`, `name`, inferred `signature`, decompiled `pseudocode`).

`BinaryViewTab::exportAnalysis` (triggered by **File ▸ Export Analysis…**, which
sets `requestedExportAnalysis` and routes to Binary View) assembles the input: it
takes the renames, comments and bookmarks (each sorted by address), the notes, and
the function/string counts. It then decompiles **only the analyst's user-named
functions** — for each it computes the heuristic `guessSignature` and the
structured `decompileFunctionText` — capped at 300 functions to keep a large
rename set fast (any beyond the cap are counted and reported as omitted). The
report deliberately scopes to *named* functions because those are the ones the
analyst cared about, keeping the document focused rather than dumping the entire
program.

Both renderers emit a metadata table (hash/arch/engine/function count/string
count), then sections for **Renamed symbols**, **Comments**, **Bookmarks**
(each as an address-keyed table, with `_none_` when empty), a **Notes** block,
and a **Decompiled functions** section with each function's name, address,
inferred signature (clearly italicized as heuristic) and pseudo-C body. The HTML
variant is a self-contained dark-themed page (inline `<style>`, no external
assets) and HTML-escapes all user text via `esc`; the Markdown variant fences
code/pseudocode and back-ticks addresses.

`AppContext::exportAnalysisFile` drives a Win32 **Save As** dialog seeded with
`<binary>_analysis.md`, offering Markdown and HTML filters. The chosen extension
decides the body: a case-insensitive `.htm`/`.html` suffix writes the HTML render,
anything else writes Markdown. On success it reports the byte count and path; a
cancelled dialog produces no popup.

#### Limitations & notes

- **Heuristic content is labelled.** The report's function signatures come from
  `guessSignature` (inferred, no full type recovery) and bodies from the
  lightweight decompiler; these are best-effort and the signature lines are
  presented in italics. The exported decompilation inherits all of the
  decompiler's structuring limitations.
- **Reports are export-only.** They are write-out artifacts; there is no import
  path, and they are not part of the persisted project state.
- **Sidecars and recents are crash-recoverable filesystem transactions.** Saves
  use a same-directory unique temporary file, `FlushFileBuffers`, and atomic
  replacement while retaining the previous good file as `.bak`; load falls back
  to it if the primary is corrupt. Failures stay visibly dirty and block a close
  or target switch from silently discarding in-memory work.
- **The empty-project policy is intentional.** Opening a binary and doing nothing
  writes no sidecar; only real annotations create one. The first content-bearing
  save is what materializes `<hash>.json`.
- **Recents are capped at 50** and keyed by hash, so two copies of the same bytes
  collapse to one entry; conversely, an analyzed file that is later modified gets
  a *new* hash and therefore a fresh, separate project.
- New sidecars use version 4; versions 1–3 remain readable and legacy patches load into
  the implicit Ungrouped set before the next save records explicit membership.
- **The JSON lib is minimal by design** — `double`-backed numbers (hence the
  hex-string address convention), no comments, no streaming; it exists solely to
  back persistence without adding a dependency.
## 10. UI, Theming & Fonts

DisasmStudio renders its entire interface through **Dear ImGui** on a hardware **Direct3D 11** device. Two small, self-contained support modules give that interface a consistent identity: `src/Ui/Theme.{h,cpp}` defines the colour and metrics system (nine built-in palettes plus a set of semantic colour accessors), and `src/Ui/Fonts.{h,cpp}` manages the proportional/monospace font pair. This chapter covers both, plus the wider ImGui usage philosophy and the visual design language they enforce.

### Why a centralized theme module

ImGui's style is a single mutable global (`ImGui::GetStyle()`): one array of ~50 named colours plus dozens of scalar metrics (rounding, padding, spacing). Left to individual tabs, syntax-style colouring (call vs. branch instructions, "running" vs. "paused" debug state, breakpoint red) would be hard-coded literals scattered across the codebase, and they would not follow a theme switch. The `ds::theme` namespace solves this two ways:

1. **`ApplyTheme(id)`** derives the *entire* ImGui style from a tiny `Palette` of core colours, so every theme stays internally consistent and a switch restyles the whole UI in one call.
2. **`ds::theme::col::*`** accessors resolve semantic colours against the *current* theme, so any widget that needs an accent, "good/warn/bad" status colour, or call/branch tint reads it from one place and automatically recolours when the theme changes.

### The `Palette` and the nine themes

A theme is *not* a full ImGui colour array. It is a compact `Palette` struct (in the anonymous namespace of `Theme.cpp`) holding only the seed colours:

- **Backgrounds:** `bg0` (window), `bg1` (frame), `bg2` (hovered), `bg3` (active), plus `child`, `popup`, `menubar`.
- **Text/chrome:** `text`, `muted`, `border`.
- **Semantic accents:** `accent`, `good`, `warn`, `bad`, `call`, `branch`.
- **`light`** — a boolean flag that flips a couple of derivation decisions (see below).

`PaletteFor(ThemeId)` is a single `switch` that returns the seed colours for each of the eight built-ins enumerated in `ThemeId` (`Theme.h`):

| Theme | Character |
|---|---|
| **Midnight** (default) | deep blue dark, blue accent |
| **Slate** | neutral grey dark, teal accent |
| **Light** | bright/paper light theme (the only `light=true` palette) |
| **Monokai** | warm olive dark, lime/pink |
| **Solarized Dark** | classic Solarized base03 cyan-teal |
| **Dracula** | purple/pink dark |
| **Nord** | cold blue-grey |
| **Matrix** | near-black background, phosphor-green text |
| **Paper** (default) | warm paper/ink with an amber accent |

The `Count` sentinel is kept last so the menu and the prefs loader can iterate or range-check the set generically. The default `switch` case also falls through to Midnight, so an out-of-range id never produces an undefined palette.

### Deriving the full style: `applyColors()`

`applyColors(const Palette&)` is where the small palette becomes the ~50-entry ImGui colour table. Rather than spelling out every state colour, it *blends* them from the seeds using two helpers:

- `V(r,g,b,a)` — a terse `ImVec4` constructor.
- `mix(a, b, t)` — component-wise linear interpolation (`a + (b-a)*t`).

The key idea is that interactive states are computed as accent blends over the base, so hover/active feedback is uniform across every widget type:

- Buttons: base `mix(bg1, accent, 0.14)`, hovered `mix(bg1, accent, 0.50)`, active = pure `accent`.
- Headers, tabs, separators, resize grips, scrollbar grabs all follow the same "more accent on stronger interaction" gradient, ending at full `accent` (or `accDim`, the accent at 0.40 alpha) for the active state.
- `CheckMark`, `SliderGrab`, `NavHighlight`, `ScrollbarGrabActive` are all the raw accent, tying focus and selection visuals to the theme's identity colour.
- `TextSelectedBg` and several hover states reuse `accDim` so text selection reads as a translucent accent wash.

The `light` flag tunes two derivations that would otherwise look wrong on a bright background: `ScrollbarBg` darkens by only 0.04 toward black on light themes (vs. 0.20 on dark), and `TableRowBgAlt` uses a faint *black* overlay (`0,0,0,0.030`) on light vs. a faint *white* overlay (`1,1,1,0.025`) on dark. `TableRowBg` itself is fully transparent so zebra striping comes purely from the alt row. `BorderShadow` is zeroed (flat, no drop shadow). This is the entire reason a single `applyColors()` can serve both a paper-white theme and a black Matrix theme without per-theme special cases beyond that one boolean.

### Layout metrics: `applyMetrics()`

`applyMetrics()` derives geometry from fixed baseline values multiplied by the current
per-monitor UI scale; spacing/padding also include the selected density factor. It assigns
absolute results rather than scaling the previous style, so repeated monitor transitions
cannot accumulate error and the same metrics apply to all palettes. Highlights:

- **Rounding:** windows/children 6px, frames/popups 5px, scrollbars 9px, grabs 4px, tabs 6px — a soft, modern, slightly rounded look.
- **Borders:** a 1px baseline on windows/children/popups; **0px on frames and tabs** (frames rely on fill contrast, not outlines). Rasterized border and separator widths are rounded to whole physical pixels at fractional Windows scales such as 125% and 150%.
- **Spacing/padding:** `WindowPadding (12,12)`, `FramePadding (10,6)`, `CellPadding (8,5)`, `ItemSpacing (10,8)`, `IndentSpacing 20`, `ScrollbarSize 14`, `GrabMinSize 12` — generous touch targets and breathing room.
- `WindowTitleAlign` left-aligned, `WindowMenuButtonPosition = ImGuiDir_None` (no collapse caret), `SeparatorTextBorderSize 2` for stronger section rules.

`ApplyTheme(id)` clamps the id, stores `g_theme`/`g_pal`, then calls `applyMetrics()` followed by `applyColors(g_pal)`. The no-argument `ApplyTheme()` re-applies the current palette and density after `SetUiScale()` during a DPI transition; it does not reset either preference. `g_theme`/`g_pal` are initialized before the first frame, so the `col::*` accessors are always valid.

### Semantic colour accessors: `ds::theme::col`

The `col` namespace exposes eight functions that simply return fields of the *current* resolved palette `g_pal`:

- `accent()` — primary accent (titles, links, selected symbols).
- `good()` — green: debugger "running", OK status.
- `warn()` — amber: debugger "paused", "multiple", and now **heuristic guessed names**.
- `bad()` — red: `ret`, errors, breakpoints, launch failures.
- `muted()` — dim text (addresses in dividers, "detached").
- `call()` — call-instruction tint (also reused for resolved branch-target symbols).
- `branch()` — branch-instruction tint.
- `selection()` — multi-line selection highlight; note it returns the accent forced to **alpha 1.0** (callers then apply their own low alpha, e.g. ~0.26, when filling a row background).

These are consumed throughout the tabs. Examples grounded in `BinaryViewTab.cpp`: the status bar's state dot picks `muted/good/warn/bad` from the debug snapshot; resolved call targets render in `col::call()`; the title card renders in `col::accent()`; multi-line row selection fills with `col::selection()` at reduced alpha.

#### Amber for guessed names (heuristic labelling)

The function side panel distinguishes three name sources. A **user rename** renders in `col::accent()`; a name discovered as a real symbol renders normally; and a **heuristic guess** from `FunctionNamer` (e.g. a function calling `CreateFileW`+`ReadFile` becoming `read_file`, an import stub becoming `j_<API>`, the entry point becoming `start`) is tinted **amber via `col::warn()`** and shown only when no user rename overrides it (`guessShown = f.guessed && dn.empty()`). Hovering such an entry shows a tooltip reading `"guessed name - <reason>"`, where the reason comes from `guessReason_[address]`. This is the project's standard pattern: heuristic output is visually distinguished (amber) and self-labels as best-effort in a tooltip, never presented as ground truth. These guesses are recomputed on each analyze and are never persisted; user renames always win and are saved separately.

### Fonts: `ds::ui`

`Fonts.h` declares two global `ImFont*` handles and a push/pop pair:

- `gUiFont` — proportional UI face. Loaded in `main.cpp` from `C:\Windows\Fonts\segoeui.ttf` at a **17px × DPI-scale** size, falling back to ImGui's built-in font at the same scaled size if Segoe UI is absent.
- `gMonoFont` — monospace face for code/hex. Loaded from `consola.ttf` (Consolas) at a **16px × DPI-scale** size, falling back to `cour.ttf` (Courier New), or left **null** if neither exists.
- `PushMono()` / `PopMono()` — wrap `ImGui::PushFont`/`PopFont`. `PushMono()` is null-safe: if `gMonoFont` is null it pushes the current font instead, so the stack stays balanced and `PopMono()` is always valid regardless of which fonts loaded.

The monospace face is what makes the disassembly listing, hex view, and live assembly align into clean columns — addresses, raw bytes, mnemonics, and operands all share a fixed advance width. Code views bracket their tables with `ui::PushMono()` / `ui::PopMono()` (e.g. the full-program listing and the focused assembly view in `BinaryViewTab.cpp`); the rest of the chrome uses the proportional `gUiFont`. The complete atlas is built at startup and rebuilt only when the main window changes DPI, so there is no per-frame font cost. `WM_DPICHANGED` applies Windows' suggested rectangle immediately but queues resource work: between frames, only the latest queued DPI invalidates the old DX11 objects, clears/reloads the atlas, reapplies absolute theme metrics, and creates the replacement font texture. Creation failure leaves the DPI uncommitted, suppresses rendering with the missing texture, and retries at a bounded cadence while messages continue to pump.

### ImGui usage philosophy & visual design language

Several deliberate choices in `main.cpp` and the theme module define the app's "feel":

- **Fixed browser-style shell.** The workbench's core panel arrangement is app-owned rather than a user dockspace. ImGui platform viewports remain enabled for platform-window/DPI bookkeeping, and `DpiEnableScaleViewports` preserves logical geometry across monitor changes.
- **Hardware-accelerated.** ImGui draws via `ImGui_ImplDX11` on a real D3D11 device; large lists are clipper-rendered, and the uncapped full-program listing decodes only requested 4 KiB code pages into a bounded LRU.
- **Live per-monitor DPI.** The Win32 host is per-monitor aware, ImGui preserves logical viewport geometry, and fonts are re-atlased at the destination monitor's native scale rather than bitmap-stretched.
- **Bounded user preferences.** Theme/density, opt-in symbol settings, and at most 32 encoded
  Investigation queries live in `%APPDATA%\DisasmStudio\prefs.ini`; authoritative per-binary
  analysis remains in its atomic sidecar. A DPI rebuild reuses the active visual values.
- **One source of truth for colour.** Because every status, syntax, and accent colour resolves through `col::*` against `g_pal`, switching themes live recolours debug indicators, instruction tints, selection highlights, and guessed-name amber uniformly — no tab carries its own literals for these.

`ThemeName(id)` provides the human label for the menu (e.g. `SolarizedDark` → "Solarized Dark"), returning "?" for an unknown id.

#### Limitations & notes

- **Automatic DPI, no manual font slider.** The 17px UI / 16px mono values are 96-DPI baselines and scale automatically per monitor; there is no user font-size slider.
- **Windows font paths are hard-coded.** Font loading probes `C:\Windows\Fonts\…` directly; if those faces are missing the UI falls back to ImGui's default and the monospace handle may be null (still safe via `PushMono`). No font fallback for non-Latin glyph ranges is configured (default ASCII range only).
- **No custom themes.** The nine palettes are built-in and not user-editable; there is no theme editor, import/export, or per-colour override. Adding a theme means extending `ThemeId`, `PaletteFor`, and `ThemeName`.
- **Visual prefs only.** The prefs file stores the theme and density; it is separate from binary-analysis sidecars and ImGui's layout file.
- The `light` flag tunes only scrollbar/alt-row derivations; all other colours come straight from the palette seeds, so a new light theme must pick legible `text`/`accent` seeds itself.
## 12. Build, Testing & Verification

DisasmStudio is a single Visual Studio C++20 project that produces one self-contained executable, paired with a deliberately unusual verification strategy: the parts that *can* be compiled and run without Windows GUI/SDK dependencies are covered by a suite of small, focused off-target unit tests, while the parts that *cannot* (the ImGui / Win32 / Zydis / Capstone-facing code) are review-verified and exercised by building the solution and smoke-running the app. This chapter documents both halves precisely.

### 12.1 How the project is built

#### Toolchain and project shape

The build is driven by **Visual Studio 2022 / MSBuild**, x64 only. There is a single solution (`DisasmStudio.sln`) and a single project (`DisasmStudio.vcxproj`). Key facts straight from the `.vcxproj`:

- **Configurations:** `Debug|x64` and `Release|x64`. The project is *x64-only* by design — `build.ps1`'s `-Platform` parameter is `[ValidateSet('x64')]`, so any other value is rejected before MSBuild runs.
- **Toolset / SDK:** `PlatformToolset` is `v143` (the Visual Studio 2022 toolset) and `WindowsTargetPlatformVersion` is `10.0` (latest installed Windows 10/11 SDK). The repository overlay binds vcpkg to the active MSBuild instance and its exact `v143` minor via `VCPKG_VISUAL_STUDIO_PATH` and `VCPKG_PLATFORM_TOOLSET_VERSION`, so a newer side-by-side Visual Studio cannot supply ABI-incompatible C++ libraries.
- **Language standard:** `LanguageStandard` = `stdcpp20` with `ConformanceMode` (`/permissive-`) on. `MultiProcessorCompilation` is enabled for parallel `/MP` builds.
- **Include path:** `$(ProjectDir)src` is added so headers resolve as `Core/...`, `Disasm/...`, `Tabs/...` etc. — the same include rooting the unit tests rely on (`/I src`).
- **Preprocessor defines (all configs):** `UNICODE;_UNICODE;NOMINMAX;WIN32_LEAN_AND_MEAN;_CRT_SECURE_NO_WARNINGS`. `NOMINMAX` matters because the codebase uses `std::min`/`std::max` freely; `WIN32_LEAN_AND_MEAN` keeps the Win32 headers (used heavily by `Debugger`, `ProcessManager`, the IP Helper paths) lean. Debug adds `_DEBUG`; Release adds `NDEBUG`.
- **Output paths:** binaries land in `build\$(Platform)\$(Configuration)\` and intermediates in `build\int\$(Platform)\$(Configuration)\`. The Release exe is `build\x64\Release\DisasmStudio.exe`.
- **Release optimization:** `WholeProgramOptimization` (LTCG), `/O2` (`MaxSpeed`), `FunctionLevelLinking`, `IntrinsicFunctions`, plus linker `EnableCOMDATFolding` and `OptimizeReferences` to strip dead code. Debug is `/Od` (`Disabled`).
- **Subsystem:** `Windows` (a GUI app, entry via `wWinMain` in `main.cpp`). An optional first command-line argument opens that target immediately; `CommandLineToArgvW` preserves quoted/Unicode paths.
- **Resources:** `src\app.rc` (compiled by the resource compiler) embeds `src\app.ico`, giving the window/taskbar/Explorer icon. The icon is regenerated with `gen_app_icon.ps1`.

The full source membership is enumerated in the `.vcxproj` `ItemGroup`s: `main.cpp`, `App.cpp`, the UI helpers (`Ui/Theme`, `Ui/Fonts`), the entire `Core/` set (`BinaryFile`, `ProcessManager`, `FunctionAnalyzer`, `FunctionNamer`, `Debugger`, `SymbolResolver`, `CFG`, `Cond`, `Json`, `Project`, `Decompiler`, `DataFlow`, `TechScan`, `XrefIndex`, `Report`), the `Disasm/` backends (`ZydisDisassembler`, `CapstoneDisassembler`, `DisassemblerFactory`, `Assembler`), every tab in `Tabs/`.

#### Dependencies via vcpkg manifest mode

Dependencies are declared in `vcpkg.json` (manifest mode), enabled in the project via `<VcpkgEnableManifest>true</VcpkgEnableManifest>` and `<VcpkgEnabled>true</VcpkgEnabled>`. The manifest pins exactly four dependencies:

- **`imgui`** with features `dx11-binding`, `win32-binding`, and `docking-experimental` — the GUI layer (Dear ImGui), its DirectX 11 renderer backend, its Win32 platform backend, and the docking branch.
- **`zydis`** — the primary x86/x64 disassembler.
- **`capstone`** — the multi-architecture disassembler (A32/Thumb/A64, MIPS/MIPS64, PowerPC/PPC64, RISC-V), routed to automatically for non-x86 images.
- **`keystone`** — the assembler behind the Patch feature (x86/x64/A32/Thumb/A64 only; it reports "unsupported" for other arches).

The first build downloads and compiles all four from source; subsequent builds are incremental because vcpkg caches the built artifacts (in this checkout they already exist under `vcpkg_installed/`). The active `VSInstallDir`/`VCToolsVersion`, overlay triplet, selected `v143` marker, and a generated toolchain-identity file participate in manifest-stamp invalidation, so changing the instance, minor, or overlay causes dependency reevaluation. `build.ps1` is the canonical command-line/CI entry point: it restricts `vswhere` to VS 2022, forces one exact `v143` minor through MSBuild and vcpkg, and supports explicit `-VisualStudioPath`/`-VcpkgRoot` values without hardcoded machine paths. Direct vcpkg use has the same VS 2022 discovery fallback. No new vcpkg dependency was added for JSON, the decompiler, or tech-scan — those are hand-rolled on purpose (see §12.4).

#### Static, self-contained single-exe output

The most consequential build decision lives in two settings working together:

1. `<VcpkgTriplet>x64-windows-static</VcpkgTriplet>` — vcpkg builds ImGui/Zydis/Capstone/Keystone as **static libraries**.
2. `RuntimeLibrary` = `MultiThreadedDebug` (`/MTd`) in Debug and `MultiThreaded` (`/MT`) in Release — the app links the **static C/C++ runtime**.

Together these link all four dependencies *and* the CRT directly into the executable. The result is a **single self-contained `DisasmStudio.exe`**: there is no `Zydis.dll`/`capstone.dll`/`keystone.dll` beside it, and crucially **no Visual C++ Redistributable** is required on the target machine. The only non-OS runtime dependency is `d3dcompiler_47.dll` (ImGui's DX11 backend compiles its shaders at runtime), which ships with Windows 10/11. The trade-off is a one-time cost: changing the triplet forces vcpkg to recompile every dependency from source, and the static-CRT choice must stay consistent across the app and any test that links the same Core `.cpp` files (the test recipes use `/MT` for exactly this reason).

#### Link libraries

The project links the Windows system import libraries it needs, declared in `<AdditionalDependencies>`: `d3d11.lib`, `dxgi.lib`, `d3dcompiler.lib` (the GPU renderer), `dwmapi.lib` (DWM/window composition), `psapi.lib` (process/module queries), `iphlpapi.lib` + `ws2_32.lib` (the IP Helper live-connections feature in the Communications tab), and `advapi32.lib`.

#### build.ps1 — the scripted build

`build.ps1` is a thin, CI-friendly wrapper over MSBuild that needs **no Developer Command Prompt**. Its logic:

- Resolves the solution path relative to the script and errors out if it is missing.
- Selects a complete VS 2022 C++ instance via **`vswhere.exe -version [17.0,18.0)`**, or accepts `-VisualStudioPath`/`VCPKG_VISUAL_STUDIO_PATH` for explicit side-by-side selection. It resolves MSBuild from that same root rather than using a floating `PATH` entry.
- Reads and validates the selected instance's exact default `v143` minor, passes it as `VCToolsVersion`, and exports the same VS root/minor to vcpkg so dependencies and the app use one compiler ABI.
- Parameters: `-Configuration` (`Release` default, or `Debug`), `-Platform` (`x64` only), `-VisualStudioPath`, `-VcpkgRoot`, `-Rebuild` (MSBuild `/t:Rebuild`), `-Clean` (`/t:Clean`, no build), and `-Verbosity` (`minimal` default).
- Invokes MSBuild with `/m` (parallel), `/nologo`, and the chosen target, then **returns MSBuild's exit code** so it composes in scripts/CI. On success it prints the resolved exe path (`build\x64\Release\DisasmStudio.exe`); on failure it prints `Build FAILED (MSBuild exit code N)`.

A practical note from the project's own build workflow: a benign `'pwsh.exe' is not recognized` line can appear from a post-build step — it is harmless, and "Build succeeded" is the authoritative signal.

### 12.2 The verification philosophy

The codebase is split, for verification purposes, into two zones:

- **Pure-logic Core modules** — no ImGui, no Win32 GUI, and (where possible) no live disassembler. These are unit-tested off-target.
- **GUI / OS / engine-facing code** — `main.cpp`, `App.cpp`, every `Tabs/*` file, the ImGui rendering, and the parts of the debugger that need a live Win32 debug loop. These cannot be unit-compiled in a plain sandbox, so they are **review-verified** and validated by **building the `.sln` and smoke-running** the exe.

Originally the pure-logic tests were intended to compile with `g++` in a Linux sandbox (as CLAUDE.md still describes). In the actual Windows environment there is no g++/clang, so they are compiled and run with **MSVC `cl`** inside a VS Dev Shell. Each test file's header comment carries its exact `cl /std:c++20 /EHsc /I src ...` build line listing the minimal set of `.cpp` files it needs, so any single test can be rebuilt and rerun in isolation. `tests\run_core_tests.bat` owns the current manifest and can run the full MSVC-compatible set or one named test. It respects explicit `VCPKG_VISUAL_STUDIO_PATH` selection or constrains `vswhere` to a complete VS 2022 C++ instance, so tests cannot drift to a newer side-by-side compiler; the live `wow64_debug_test` self-skips when no 32-bit target is available.

### 12.3 The off-target unit tests (`tests/`)

Each test is a standalone `main()` using a tiny `CHECK(cond)` macro that counts failures and returns non-zero if any fail, so they are trivially CI-gateable. Several replay canned instruction streams through a `MockDisassembler`/`StubDis` that implements `IDisassembler::decodeOne` from a lookup table — this lets CFG/decompiler/xref logic be exercised without a real decoder. Two tests deliberately *do* link the real Zydis to prove arch-correct decoding.

- **`binaryfile_macho_test.cpp`** — builds a byte-accurate thin 32-bit Mach-O in memory, writes it to a temp file, loads it via `BinaryFile`, and asserts format/machine/bitness, that the single `__text` section parses, and that `vaToOffset`/`offsetToVA` are correct inverses (`0x1000↔0x100`, `0x1050→0x150`). It specifically pins a fixed bug where 32-bit segment fields (`initprot`/`nsects`) were read at the wrong offsets (`lc+48/52` vs `lc+44/48`), which previously yielded zero sections.
- **`binaryfile_pe_metadata_test.cpp`** — builds a synthetic PE32+ containing TLS callbacks, named/ordinal delay imports, RSDS GUID/age/PDB data, security-relevant load-config fields, and ordinary/chained/indirect x64 unwind records. It also pins truncated structures, impossible payload extents, unbacked pointers, maximal declared directory sizes, and bounded unterminated PDB paths.
- **`binaryfile_elf_metadata_test.cpp`** — builds synthetic ELF64 shared and ELF32
  relocatable images containing REL/RELA, PLT/GOT slots, `DT_NEEDED`, GNU version
  definitions/requirements/index associations, and init/fini arrays. It pins ET_REL
  synthetic targets, valid VA zero, signed addends, and independent malformed/truncated
  table reporting.
- **`decompiler_switch_test.cpp`** — drives `BuildCFG` + `Decompile` over a classic `cmp`/`jbe`/`jmp [table]` switch dispatch using a `JumpTableResolver` callback. Asserts the dispatch block is flagged `isSwitch` with the three resolved `caseTargets` and one successor per case, that *without* a resolver it stays a plain `jmp` (not a switch), and that the decompiler emits real `switch (rax) { case 0: ... break; }` rather than a bare `goto loc_0;`.
- **`dataflow_decomp_test.cpp`** — the most comprehensive decompiler test (14 scenarios). It validates the data-flow pre-pass (`Core/DataFlow.cpp`) wired into `Decompiler`: copy/constant propagation and dead-assignment elimination (`mov rax,rcx; mov rbx,[rax+8]; mov rax,rbx; ret` → `*(a1 + 8)` with all raw register names gone), argument naming (`rcx→a1`, `rdx→a2`), `xor eax,eax → return 0`, `for`-loop reconstruction from a counting `while`+increment, return-value recovery, `mul`/`div` modeled as `*`/`/`/`%` (not `__asm`), string/IAT resolution through a `dataRefFor` callback (`lea rax,[addr] → return "hello"`, `call [iat] → kernel32.Foo()`), partial-register soundness (`mov al,0` rendered as `LOBYTE(...)`, not a full zero), `movzx` width via `(unsigned __int8)`, alias-aware invalidation of a tracked stack slot, and the **legacy fallback** (`deepDataFlow = false` keeps the raw `rax = rcx;` lift).
- **`function_namer_test.cpp`** — tests the *pure* part of the heuristic function namer: `ToSnakeIdentifier` (`CreateFileW → create_file`, strips `W`/`A` suffix and leading `_`) and `GuessFromEvidence` over a `FuncEvidence` struct. Covers priority ordering (entry → `start`, thunk → `j_CreateFileW`, ret-only → `nullsub`, ret-zero → `ret_zero`), semantic names from API sets (`read_file`, `write_file`, `inject_code`, `net_send`/`net_recv`, `socket_setup`, `check_debugger`, …), the guard that `SendMessageW` is *not* a network send, single-API thin-wrapper detection (small function only), string-derived identifiers, and the "no evidence → no guess" case. These outputs are explicitly *heuristic* and the namer marks them with a `guessed` flag the UI uses to label them.
- **`analysis_cache_test.cpp`** — verifies ordered overlapping-patch identity, decoder/schema/override invalidation, effective-backend normalization, typed lookup, and true LRU eviction. `analysis_service_test.cpp` additionally proves worker-level hit/miss behavior and a miss when only the ordered-patch digest changes.
- **Authorization Trail regression group** — `verification_api_catalog_test.cpp`, `authorization_trail_test.cpp`, `authorization_field_alias_test.cpp`, `authorization_patch_advisor_test.cpp`, and `authorization_experiment_test.cpp` pin exact catalog matching, deterministic fan-out/secondary-gate/conclusion rules, conservative field-root binding, fail-closed patch advice, and PID/session/module/thread/RIP-bound register-only force/restore behavior.
- **`xref_arch_test.cpp`** — links the **real Zydis** decoder. It confirms `BuildXrefInto`/`FinalizeXrefIndex` recover relative call targets and data references correctly in **both x86 and x64** modes, including the subtle case where identical bytes (`8B 05 ...`) mean RIP-relative in x64 but absolute (`moffs`) in x86 — proving the xref sweep follows the decoder's arch.
- **`xref_report_test.cpp`** — two pure modules. The `XrefIndex` half (a `StubDis` toy encoding) checks that two callers of one target are recorded **sorted and de-duplicated**, that a data ref resolves to the right source, that unreferenced targets return `nullptr`, that `edgeCount()` is correct, and that `FinalizeXrefIndex` is **idempotent**. The `Report` half checks `RenderReportMarkdown` and `RenderReportHtml` produce the expected structure and — importantly — that `<` is left raw in Markdown but **HTML-escaped** to `&lt;` in HTML output.
- **`project_roundtrip_test.cpp` / `patch_set_test.cpp`** — round-trip a fully populated version-4 project including stable named-set ids and per-patch membership, retain version-1–3 compatibility and exact 64-bit strings, and pin bounded selection/overlap validation, pristine composition, and non-mutating Baseline/current/single-set comparisons.
- **`cond_eval_test.cpp`** — tests the conditional-breakpoint / watch expression evaluator (`Core/Cond.cpp`): `EvalExpression` for single operands (registers, hex/decimal literals, memory derefs `[rax]`, base+disp `[rsp+8]` / `[rsp + 0x8]`, and failures for unknown registers/garbage) and `EvalCondition` for two-operand comparisons (`==`, `!=`, `<`), including empty-string meaning "unconditional → true".
- **`step_logic_test.cpp`** — the only test the comment still shows building with `g++`, because `Core/StepLogic.h` is pure header-only logic. It pins the debugger's *decision tables* (`ClassifyInsn`, `DecideStepOver`, `DecideStepOut`, `DecideOnBpResume`) and then runs a **synthetic CPU + stack simulator** that drives stepping using *only* those decisions, proving step-out and step-over land on the correct instruction across nested calls and recursion (e.g. step-out unwinds exactly one frame). This is how the live debugger's trickiest behavior is verified without a debuggee.
- **`trace_coverage_test.cpp`** — drives the pure `TraceCoverage` state machine through de-duplication/capping, generational replacement, arm/hit/stop/clear/reset, stale-callback rejection, deterministic snapshots, and saturated counters without Win32 or a process.
- **`dll_debug_plan_test.cpp`** — constructs synthetic PE32/PE32+ DLLs and pins DLL/bitness/entry/export validation, callable-export filtering, trusted System32/SysWOW64 and custom-host selection, Microsoft-compatible argv quoting, requested breakpoint RVAs, and exact-path `LOAD_DLL` ASLR retargeting.
- **`static_unpack_test.cpp`** — builds synthetic PE32/PE32+ packed layouts and validates exact `PACKER_INFO` recovery, bounded LZMA1 and LZMA-alone decoding, stale-plan fallback, manual/stored blocks, hard caps, cancellation, disk reconstruction, raw/mapped artifacts, and background-service result handoff.
- **`passive_dump_test.cpp`** — pins page fingerprints, entropy/change comparison, coverage-loss rejection, settle/manual/timeout decisions, and on Windows performs a real query/read-only self-snapshot plus PE rebuild. An opt-in launch smoke verifies CREATE_SUSPENDED -> one-process Job -> ResumeThread with no debug flags.
- **`anti_debug_test.cpp`** — exercises the all-off policy, exact ntdll information-class decisions, invalid-handle gating, PEB/heap normalizers, first-pristine compare-before-restore behavior, DR masking, monotonic QPC/system-time/RDTSC values, saturation, and the explicit user-mode-versus-Hv capability report.
- **`memory_scan_test.cpp`** — covers strict signed/unsigned integer and float codecs, AOB wildcards, UTF-8/UTF-16LE, every absolute and previous-value predicate, alignment, boundary lookahead, chunk refinement, exact candidate counts, and stable ordinal paging.
- **`memory_pointer_test.cpp`** — pins deterministic 32/64-bit backlink discovery, depth/offset/alignment/canonical-address/cycle/work bounds, cancellation, de-duplication, and root-to-target pointer-chain resolution.
- **`memory_table_test.cpp`** — verifies exact-path and unique-name module-relative resolution, ambiguous-module rejection, pointer offsets, constant/minimum/maximum freeze decisions, bounded JSON round-trips, and the invariant that loaded rows are disabled and unfrozen.
- **`process_memory_session_test.cpp`** — tests pure write-authority decisions and identity matching, then on Windows exercises passive self-open/read/region enumeration plus verified transactional writes without debugger attachment.
- **`instr_dataref_test.cpp`** — header-only (no `.cpp` deps), tests `instrDataRef()` (`Tabs/DataRef.h`): extracting the static data address an instruction references (absolute `[0x...]`, IAT `call/jmp qword ptr [0x...]`, segment-prefixed `fs:[...]`, Capstone `[rip ± disp]` resolved to absolute) while correctly returning 0 for register-relative memory, stored immediates, bare immediates, and relative branch targets.
- **`wow64_debug_test.cpp`** — a **live end-to-end** test (links the real Debugger + Zydis). It launches a 32-bit process (`SysWOW64\cmd.exe` by default) under the debugger with break-at-entry, asserts it is detected as 32-bit (`is32`), that EIP/ESP are sub-4 GB, exercises the local-loopback Server Watch lifecycle, and then terminates the child. The default local manifest run reports this `LIVE_TEST` as an explicit skip, but GitHub Actions selects it directly with `DS_REQUIRE_LIVE_DEBUG_TESTS=1`; an unavailable target, privilege failure, or fixture skip is therefore a CI failure rather than a silent pass. This exercises `Debugger.cpp`'s WOW64 path without contacting an external server.

Two helper scripts round out the workflow: **`run_namer_test.ps1`** enters a VS Dev Shell and compiles+runs the namer test end-to-end (a template for the `cl`-based recipe), and **`smoke_run.ps1`** launches the built Release exe, waits 5 seconds, and reports whether it stayed alive — the canonical "did the GUI start" check for the code that can't be unit-tested. Tests that link the static Zydis/Capstone libs reference them under the (doubled) path `vcpkg_installed\x64-windows-static\x64-windows-static\{include, lib}`.

### 12.4 Dependency-light philosophy

A recurring design rule is to **add no new third-party dependency** for things the project can reasonably own. Consequently the JSON layer (`Core/Json`), the structuring decompiler (`Core/Decompiler` + `Core/DataFlow`), and the capability/tech scan (`Core/TechScan`) are all hand-rolled. The payoff is twofold: the dependency set stays at exactly four vcpkg packages (so the static single-exe stays small and the first-build cost stays bounded), and these modules have **no GUI/OS coupling**, which is precisely what makes them unit-testable off-target. The verification strategy and the dependency philosophy reinforce each other.

### 12.5 Tracking fixes — FIXES.txt

`FIXES.txt` is the project's adversarial-audit log. It catalogues issues by severity (HIGH/MEDIUM/LOW) with file:line citations and root-cause notes — loader integer-overflow/OOB hardening in `BinaryFile` `rd<T>`, debug-handle leaks in `ProcessManager::pumpDebugEvent`, the `setActiveThread` `Paused` guard, the 0xCC-original-byte preservation fix, TOCTOU races guarded by a new `hProcMtx_`, the WOW64 context handling, decompiler join-block overruns, and more. Each line records whether it is done or **consciously deferred with rationale** (e.g. CFG branch-target leaders that land mid-instruction are still dropped — a re-decode feature, not a one-liner — and a cosmetic legacy-decompiler placeholder left to avoid churning the golden-string tests). It also lists the paths an audit reviewed and found clean (the Zydis/Capstone/Keystone decode paths, the hand-rolled JSON parser, `SymbolResolver`, `DataFlow`, the dominator core, the Hv client). It is the human-readable companion to the automated tests — covering exactly the GUI/OS-facing code the unit tests can't reach.

#### Limitations & notes

- **No automated GUI/integration harness.** The ImGui/Win32/Tabs layer is verified by review + `.sln` build + `smoke_run.ps1` (a 5-second liveness check). Deeper interactive paths (live assembly view, Stack/Xrefs tabs, run-to-cursor, and export dialogs) still require manual GUI use. The startup target argument supports deterministic file loading, but it is not a general UI-automation interface.
- **The unit tests are not auto-run by the build.** The solution build produces the app only. Run `tests\run_core_tests.bat` separately to compile and execute the complete MSVC-compatible Core regression set (one isolated `cl` invocation per harness); pass a test stem such as `binaryfile_exports_test` to run only that declaration.
- **Off-target reality vs. docs.** CLAUDE.md describes the tests as g++-on-Linux; in the real Windows environment they are built with MSVC `cl` in a VS Dev Shell (only the header-only `step_logic_test` is g++-portable as documented). A noted sandbox quirk is that a mounted copy of a just-edited file can be stale/torn — the real Windows files are authoritative.
- **First-build cost.** The `x64-windows-static` triplet recompiles all four vcpkg deps from source on a clean tree; this is a one-time cost traded for a redist-free single exe.
- **x64-only, static-CRT-only.** There is no 32-bit (Win32) app configuration; the static CRT choice must match across the app and any test linking the same Core sources (hence `/MT` in the engine-linking test recipes).
- **`wow64_debug_test` is environment-dependent.** It needs a 32-bit target present and adequate privileges; otherwise it self-skips rather than fail. Attaching to protected or cross-bitness processes generally needs Administrator and a matching architecture.
## 13. Appendix — Source Map, Limitations, Non-Goals & Roadmap

This appendix closes the overview. It (1) maps every significant source file to the
chapter that documents it (and flags anything not covered), (2) collects the parts of
the tool whose output is **heuristic / best-effort** and explains how the UI labels
them, (3) restates the **explicit non-goals** from the project spec, and (4) sketches a
realistic **roadmap** that stays inside the current architecture and does not contradict
those non-goals.

### Source coverage map

Chapter numbers refer to files `01_*.md` … `13_*.md` in this directory. There is no
chapter 11: the AMD-V (SVM) hypervisor backend, its kernel driver, and the Communications
tab's user-mode client panel have been removed from the project.

| Source file / dir | Documented in chapter | Notes |
|---|---|---|
| `src/App.h`, `src/App.cpp` | 1 | Application shell, AppContext, menu/toolbar/tab strip |
| `src/main.cpp` | 1 | Win32 + D3D11 hardware host, render loop |
| `src/Tabs/ITab.h` | 1 | Tab interface |
| `src/resource.h`, `src/app.rc`, `src/app.ico` | 1 (also 12) | Embedded icon / version resource |
| `gen_app_icon.ps1` | 12 (also 1) | Icon regeneration script |
| `src/Disasm/IDisassembler.h` | 2 | Engine-agnostic interface |
| `src/Disasm/ZydisDisassembler.{h,cpp}` | 2 | Zydis x86/x64 backend |
| `src/Disasm/CapstoneDisassembler.{h,cpp}` | 2 | Multi-arch backend |
| `src/Disasm/DisassemblerFactory.{h,cpp}` | 2 | Engine/arch selection |
| `src/Disasm/Assembler.{h,cpp}` | 2 | Keystone assembler (patch path) |
| `src/Core/BinaryFile.{h,cpp}` | 3 | PE/ELF/Mach-O/raw loader, VA↔file, hash, imports/relocs |
| `src/Core/FunctionAnalyzer.{h,cpp}` | 4 | Function discovery |
| `src/Core/FunctionNamer.{h,cpp}` | 4 | Heuristic GUESSED function names |
| `src/Core/CFG.{h,cpp}` | 4 | Basic blocks + edges |
| `src/Core/XrefIndex.{h,cpp}` | 4 | Cross-reference index |
| `src/Core/SymbolResolver.{h,cpp}` | 4 | Name resolution / override precedence |
| `src/Core/Demangle.{h,cpp}` | 4 | Bounded cached MSVC/Itanium/C symbol presentation |
| `src/Core/TechScan.{h,cpp}` | 4 | Capability / tech detection |
| `src/Core/AuthorizationTrail.{h,cpp}` | 4 (also 7) | Ranked predicates, stages, secondary gates, independent conclusions |
| `src/Core/AuthorizationFieldAlias.{h,cpp}` | 4 | Exact interprocedural object-field identity correlation |
| `src/Core/VerificationApiCatalog.{h,cpp}` | 4 | Exact DLL/symbol signature-verifier contracts |
| `src/Core/AuthorizationPatchAdvisor.{h,cpp}` | 4 (also 7) | Inert, fail-closed centralized-boolean patch advice |
| `src/Tabs/DataRef.h` | 4 | `instrDataRef` shared static-ref helper |
| `src/Core/Decompiler.{h,cpp}` | 5 | Structuring pass → pseudo-C |
| `src/Core/DataFlow.{h,cpp}` | 5 | Data-flow support for the decompiler |
| `src/Core/CodeExport.{h,cpp}` | 7 (also 9) | Streaming ASM/C generator + dedicated background export service |
| `src/Core/Debugger.{h,cpp}` | 6 | Real Win32 debugger |
| `src/Core/AuthorizationExperiment.{h,cpp}` | 6 (also 7) | Identity-bound register-only return experiment state |
| `src/Core/TraceCoverage.{h,cpp}` | 6 (also 7) | Bounded/generational one-shot block coverage state |
| `src/Core/DllDebugPlan.{h,cpp}` | 6 (also 3) | PE-DLL/export validation, host argv planning, LOAD_DLL ASLR retargeting |
| `src/Core/ProcessManager.{h,cpp}` | 6 | Toolhelp32 process/module enumeration |
| `src/Core/ProcessMemorySession.{h,cpp}` | 8 | Passive identity-bound memory access and verified write transactions |
| `src/Core/MemoryScan.{h,cpp}` | 8 | Typed scan predicates, chunk snapshots, bitmap paging |
| `src/Core/MemoryPointer.{h,cpp}` | 8 | Bounded pointer-chain discovery and resolution |
| `src/Core/MemoryTable.{h,cpp}` | 8 | Module-relative records, freeze policy, strict JSON codec |
| `src/Core/StepLogic.h` | 6 | Pure, unit-tested stepping decisions |
| `src/Core/Cond.{h,cpp}` | 6 | Conditional-breakpoint evaluator |
| `src/Tabs/BinaryViewTab.{h,cpp}` | 7 | The Binary View centerpiece |
| `src/Tabs/ProjectsTab.{h,cpp}` | 8 | Recents / project management |
| `src/Tabs/CommunicationsTab.{h,cpp}` | 8 | Processes, modules, connections, JDWP console |
| `src/Core/NetworkEndpoint.{h,cpp}` | 8 | Canonical scope-aware IPv4/IPv6 formatting |
| `src/Tabs/SigScannerTab.{h,cpp}` | 8 | Signature scanner |
| `src/Tabs/MemoryToolsTab.{h,cpp}` | 8 | Passive/debugger scanner, hex editor, regions, pointers, JSON table |
| `src/Tabs/BinaryDiffTab.{h,cpp}` | 8 | Two-binary byte diff |
| `src/Tabs/BinaryTechTab.{h,cpp}` | 8 | Tech-scan UI |
| `src/Core/Project.{h,cpp}` | 9 | Version-4 per-binary JSON sidecar persistence |
| `src/Core/PatchSet.h`, `src/Core/PatchedImage.h` | 7 (also 9) | Named-set validation, pristine composition, and comparison |
| `src/Core/Json.{h,cpp}` | 9 | Hand-rolled JSON |
| `src/Core/Report.{h,cpp}` | 9 | Report/export generation |
| `src/Ui/Theme.{h,cpp}` | 10 | Color theme / styling |
| `src/Ui/Fonts.{h,cpp}` | 10 | Font loading |
| `DisasmStudio.vcxproj`, `DisasmStudio.sln` | 12 | Project/solution |
| `vcpkg.json` | 12 | Dependency manifest |
| `build.ps1` | 12 | Build driver script |
| `README.md`, `FIXES.txt` | 12 | Docs / audit log |
| `tests/*.cpp` (manifested Core and live regression tests) | 12 | Built by `tests\run_core_tests.bat`; key tests enumerated and described |

Auxiliary scripts not in any chapter plan: `tests/smoke_run.ps1` is referenced by
chapter 12 (a ~5-second GUI liveness check); `tests/run_namer_test.ps1` (the
function-namer test runner) is **not explicitly named** in any chapter, though the
test it drives (`function_namer_test.cpp`) is documented in chapter 12. These are minor.

**Verdict:** Every source file in `src/`, `tests/`, and the build/config root is covered by
a chapter.

### Heuristic / best-effort areas

Several outputs are explicitly **inferred, not authoritative**. The tool labels each as
heuristic in the UI rather than presenting it as ground truth. A clean or unusual binary
should be expected to produce few or no hits, and none of these should be trusted as
proof.

- **Decompiler / pseudocode output (ch. 5).** The Pseudocode view is produced by an
  in-house structuring pass (dominators / post-dominators / natural-loop detection →
  `if/else` and `while`/`do-while`, with a labelled-`goto` fallback for irreducible
  flow). It is **not** a full data-flow decompiler — there is no type recovery — so the
  output is structured-but-approximate. The view is presented as decompiled pseudo-C,
  is cached per function, and re-runs on **Refresh**.
- **Inferred function signatures (ch. 5).** The decompiler prepends a heuristic
  signature (argument count guessed from calling-convention register reads;
  `__int64`/`void` return guessed) and labels it as inferred/heuristic in the output.
- **Guessed function names (ch. 4, `FunctionNamer`).** Functions without an
  export/PDB/user name get an auto-generated, behavior-derived label. These are
  **guesses** and are visibly distinguished from real symbol names; a user **rename**
  (persisted in the project sidecar) always overrides them everywhere a name resolves.
  Address-only fallbacks render as `sub_<addr>`.
- **Deobfuscation / anti-analysis flags (ch. 4/7).** Timing / privileged / anti-debug
  instructions (`rdtsc`, `cpuid`, `int 0x2d`, `in`/`out`, direct syscall stubs, …) are
  flagged **inline** in the listing as best-effort hints — a flag means "this
  instruction is *associated with* anti-analysis," not "this binary is malicious."
- **Tech-scan confidence (ch. 4, `TechScan`).** Capability detection (imported-API
  grouping, packer/protector section-name signatures, distinctive byte patterns such as
  AES S-box / SHA-256 / MD5 constants) reports **confidence/grouping**, not certainty.
  Results are never fabricated: each hit links to a real address with a live
  disasm/hex preview, and a clean binary shows few or none.
- **Signature health (ch. 8, Sig Scanner).** Saved signatures are scored live against
  the loaded image as *none / unique / multiple* with an actual match count — a derived
  quality measure, not a hardcoded verdict.
- **Per-instruction "Explain" gloss (ch. 7).** The plain-language one-liner per
  instruction and the one-line API purpose are descriptive aids, toggleable, and not a
  formal semantic model.

### Explicit non-goals

These are deliberate scope decisions from the project spec. They are **not** "TODO"
items — they are intentionally excluded, and the roadmap below does not propose
reversing any of them.

- **No scripting / plugin / automation API.** The user explicitly does not want a
  scripting or plugin surface. It must not be added. The application is a single
  self-contained GUI tool. The optional startup path only opens a target; it is not a
  scripting, plugin, or headless automation surface.
- **No FLIRT-style library recognition.** Signature-based identification of statically
  linked library functions (IDA-FLIRT style) is not implemented.
- **No kernel-mode or hypervisor backend.** DisasmStudio is a pure user-mode
  application. It does not ship, load, or talk to a kernel driver, and it makes no
  hardware-assisted (AMD-V/SVM, VT-x) introspection claims. Anything that would require
  ring-0 or ring-(-1) authority — hiding kernel debug objects, virtualizing
  KUSER_SHARED_DATA, trapping RDTSC in generated code — is explicitly out of scope, and
  the anti-debug capability report says so.

### Roadmap / plausible future enhancements

Forward-looking and grounded in the current architecture. None of these requires a
scripting API or contradicts the non-goals above.

- **Decompiler depth.** Incremental data-flow improvements on the existing
  `DataFlow`/`Decompiler` core: light type/width recovery, better condition rendering,
  and retiring the legacy non-data-flow `hi:lo`/`flags == 0` placeholder paths noted in
  `FIXES.txt`. Stay within the "structured per-binary output, no fixed template" design.
- **CFG fidelity on obfuscated code.** Address the deferred limitation
  (`CFG.cpp` drops branch-target leaders that land mid-instruction) via
  overlapping-instruction re-decode at unaligned targets — a real feature with
  regression risk to normal-code CFGs, hence deferred but tractable.
- **Loader breadth.** Additional formats / fat (universal) Mach-O, deeper PE/ELF
  relocation and symbol-version handling, and UI presentation of the now-parsed PE TLS,
  delay-import, CodeView, load-config, and unwind models — all extensions of
  `BinaryFile` with no new heavy dependency.
- **Debugger robustness.** Mitigations around the documented edges: re-entrant hits
  during stepped-over calls whose own address holds a software breakpoint, the Step Out
  500k-instruction safety cap, and callees that rewrite their return address.
- **Architecture coverage for assembly.** Keystone currently assembles only
  x86/x64/A32/Thumb/A64 (disassembly via Capstone is broader). Extending patch-time
  assembly to more arches, where Keystone supports it, would close the disasm/asm gap.
- **Reporting / export.** Save ASM/C already covers whole-program and per-function
  source export; a future extension can still enrich `Core/Report` with more structured
  function/string/import/xref formats for offline review.
- **Performance and persistence.** Continue clipper-driven rendering work for very large
  images and incremental/streamed analysis caching in the project sidecar, keeping the
  "must be fast, GPU-accelerated" constraint central.
