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
4. **Open arbitrary bytes as a flat "raw" blob** with an editable base, entry point, and architecture. A bounded, evidence-scored firmware probe can recognize legacy BIOS, PI/UEFI firmware volumes, PCI option ROMs, and Intel Flash Descriptor images, or conservatively suggest A32/Thumb/A64 from coherent instruction motifs; every mapping/mode/entry suggestion remains under analyst control.
5. **Auto-detect the file format** from its magic bytes and **auto-select the CPU architecture** from the header.
6. **Disassemble twelve native CPU modes plus JVM bytecode:** x86-16 real mode, x86, x64, A32, Thumb/Thumb-2, A64, MIPS, MIPS64, PowerPC, PPC64, RISC-V 32, and RISC-V 64.
7. **Use the right engine automatically:** Zydis for the x86-family fast path, Capstone for every other native architecture (including `CS_MODE_THUMB`), and the JVM backend for bytecode, behind one engine-neutral interface.
8. **Render a configurable full-program assembly listing** with function dividers plus optional PE-header and data-section rows. A worker builds immutable 4 KiB code-page descriptors without decoding; the virtual clipper materializes only requested pages and has no global instruction cap.
9. **Never get stuck on undecodable bytes** — they fall back to data pseudo-ops with an ISA-aligned stride so the listing always advances without destroying ARM/Thumb alignment.
10. **Translate freely between virtual addresses and file offsets**, uniformly across all formats.

### Discover & understand code
11. **Discover function boundaries** from the structured/raw entry, firmware landmarks, PE and ELF symbols, architecture-gated x86/A32/Thumb/A64 prologues, exact ELF size hints, and bounded ARM literal-pool exclusion, then follow safe direct calls recursively.
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
52. **Scan process memory like Cheat Engine** — exact / bigger / smaller / changed / unchanged / unknown-initial value scans.
53. **Edit memory in a viewer/editor** with write-through to the live process.
54. **Browse memory regions** and **maintain an address table with per-entry freeze.**

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
67. **Auto-save all analysis per binary** — comments, renames, bookmarks, breakpoints + conditions, version-4 named patch sets and membership, notes, watches, last cursor, and explicit PE-header/section listing visibility and fold choices keyed by stable `(RVA, name)` identities.
68. **Key analysis to the binary's content hash**, so it follows the bytes even if the file is moved or renamed.
69. **Reopen recent targets** from a Projects dashboard with a saved-analysis summary.
70. **Export a full analysis report** to Markdown or HTML (named, decompiled functions, comments, bookmarks, metadata).
71. **Save assembly or C source** for the whole analyzed program or the function under the cursor; assembly follows every active decoder, while C export is limited to x86/x64 (x86-16 is explicitly excluded) and can be readable pseudo-C or a self-contained compilable C11 translation unit, generated on a cancellable background worker with progress.

### Navigate & work efficiently
72. **Unified back/forward navigation history** (aware of static vs live locations), goto-by-address, and a symbol picker.
73. **Mouse back/forward, `Alt`+←/→, and per-instruction keys** (`Enter` follow, `;` comment, `N` rename, `B` breakpoint, `X` xrefs, `J`/`K` step).
74. **Branch arrows** drawn in a flow gutter in the listing.
75. **Eight built-in colour themes** (Midnight, Slate, Light, Monokai, Solarized Dark, Dracula, Nord, Matrix), switchable live and remembered across sessions.
76. **A fixed, browser-style single-window UI** with a top tab strip — no fiddly docking to manage.

### Engineering qualities
77. **Ships as one statically-linked, self-contained `.exe`** — no installer, no redistributable, no side-by-side DLLs (only the OS's `d3dcompiler_47.dll`).
78. **GPU-accelerated, vsync-capped rendering** with occlusion-aware frame skipping.
79. **A testable Core** — the pure logic (loaders and ELF symbols, firmware/ARM-mode sniffing, lazy listing planning/indexing, decompiler, data-flow, function discovery/naming, xrefs, JSON, conditions, step logic, trace-coverage state, DLL launch planning, tech-scan, source export) is decoupled from the UI and unit-tested off-target.
80. **Dependency-light by design** — hand-rolled JSON, decompiler, and capability scanner; only Zydis/Capstone/Keystone/ImGui as third-party libraries.

### Advanced / experimental

---

## Who It's For & Typical Workflows

DisasmStudio is built for anyone who needs to understand a binary they did not write:

- **Malware analysts & incident responders.** Open a sample, let the capability scan and function-name guesser triage it ("this calls `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` → `inject_code`"), read the decompiled droppers, attach to detonate it under the debugger, watch its network connections, and export a report — without leaving the app.
- **Vulnerability researchers.** Navigate the disassembly and call graph, decompile the parsers, set conditional and hardware breakpoints on interesting memory, scan and watch values as the program runs, and patch to test hypotheses.
- **CTF players & crackme solvers.** Find the check function by name guess or string xref, decompile it, patch the jump, and save the cracked binary.
- **Firmware & shellcode analysts.** Let the bounded firmware probe suggest a real-mode/32-bit/64-bit mapping and boot entry, review its evidence, edit any value, optionally seed reset/boot/EFI-image landmarks, or manually map non-x86 blobs (ARM/MIPS/PPC/RISC-V).
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
- **Heuristics are labelled.** Guessed names, inferred signatures, decompiler output, anti-analysis flags, tech-scan results, and firmware kind/mapping/entry recommendations are presented as evidence-backed best-effort output and remain user-overridable.
- **Testable core, review-verified UI.** Logic lives in `src/Core` and is unit-tested; the ImGui/Win32/engine-facing code is review-verified, built, and smoke-run.

---

## How This Document Is Organized

| # | Chapter | In one line |
|---|---------|-------------|
| 1 | Architecture & Application Shell | The Win32 + D3D11 host, render loop, app shell, fixed tab strip, AppContext, raw-firmware workflow, and cross-tab plumbing. |
| 2 | Disassembly Engines & Assembler | Decoding bytes to instructions (Zydis/Capstone) and encoding patches (Keystone) behind one interface. |
| 3 | Binary Loading & Formats | Loading PE/ELF/Mach-O/raw, arch detection, uniform VA↔offset math, in-memory patching. |
| 4 | Static Code Analysis | Function discovery, **name guessing**, CFG, xrefs, symbols, and capability detection. |
| 5 | Decompiler & Data-Flow | Dominator-based structuring + a data-flow pass producing readable pseudo-C. |
| 6 | The Live Win32 Debugger | Threaded event loop, breakpoints, stepping, conditions, WOW64, and the debugging UI. |
| 7 | The Binary View Workspace | The centerpiece: six main views, section/header listing controls, side panel, lower sub-tabs, navigation, annotations, patching, and source export. |
| 8 | The Other Workbench Tabs | Projects, Communications, Sig Scanner, Memory Tools, Binary Diff, Binary Tech. |
| 9 | Persistence, Projects & Reporting | Hash-keyed JSON sidecars, recents, ASM/C source export, and Markdown/HTML reports. |
| 10 | UI, Theming & Fonts | Eight palette-derived themes, semantic colour accents, and the font system. |
| 12 | Build, Testing & Verification | One static self-contained exe, and how the Core logic is unit-tested off-target. |
| 13 | Appendix | Source-coverage map, heuristic-output honesty, explicit non-goals, and roadmap. |

---
