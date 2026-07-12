# Requested Features Not Fully Present

Last updated: 2026-07-12
Audit baseline: `b8724e7` (then updated to account for completed work in this tree)

This file contains only requested features that are absent or not implemented to the described level. `Missing` means no working implementation was found. `Partial` means related functionality exists, but one or more material parts of the requested feature do not.

The findings come from the current source and tests, not from names in documentation alone.

## Missing

### 1. Firmware sniffing and boot-entry recovery

There is no BIOS/UEFI/PCI option-ROM detector, reset-vector mapping, 16-bit real-mode decoder, boot-jump resolver, Intel Flash Descriptor or `_FVH` corroboration, editable detected entry point, or firmware-landmark seeding/naming.

Evidence:

- `Arch` has no x86-16 mode: `src/Disasm/IDisassembler.h:36`.
- the raw-load popup in `src/App.cpp` accepts only a base plus x86/x64/ARM/ARM64.
- `BinaryFile::loadRaw` in `src/Core/BinaryFile.cpp` always sets `entryRVA_ = 0`.
- source searches found no reset-vector, option-ROM, `_FVH`, or flash-descriptor implementation.

### 2. Optional PE sections and header in the linear listing

There is no Sections panel, PE-header row source, per-section "load into listing" toggle, folding of `.rsrc`/`.data`/`.rdata`/`.reloc`/`.pdata`, or project-persisted section visibility. Executable sections are always swept; non-executable sections contribute only recognized string rows.

Evidence: the Binary View's static-list construction in `src/Tabs/BinaryViewTab.cpp`, `src/Core/AnalysisJobs.cpp:307-342`, and the absence of section-visibility state in `src/Core/Project.h:47-73`.

### 3. PE resource browser

There is no resource-directory model/parser, type/name/language tree, manifest/version/string-table decoding, bitmap/icon preview, raw-resource save, or resource-to-address navigation.

Evidence: `BinaryFile::parsePE` does not consume resource directory index 2, and no Resources tab or resource-browser implementation exists.

### 4. Save ASM / Save C export workflow

There is no whole-program or per-function `.asm`/`.c` export, readable-versus-compilable C choice, self-contained compilable-C preamble, background export job, or export progress UI.

The existing feature is a different Markdown/HTML analysis report and does not satisfy this request. Evidence: `AppContext::exportAnalysisFile` and the report workflow in `src/Tabs/BinaryViewTab.cpp`.

### 5. Execution trace / coverage

There is no trace toggle, executed-block/instruction store, one-shot basic-block breakpoint planting, green execution coverage, background planting/removal, or Clear Trace command.

Evidence: the debugger command set has no trace operation (`src/Core/Debugger.h:256`), `App::renderDebugToolbar` has no trace controls, and source searches found no execution-coverage implementation.

### 6. Debug-a-DLL workflow

There is no DLL host dialog, bitness-matched `rundll32.exe` or custom-host launch, argument/export picker, DllMain/export breakpoint, or retargeting to the loaded DLL.

Currently every PE is treated as directly launchable and is passed to `CreateProcessW`, including DLLs: the launch path in `src/App.h`, `src/Core/Debugger.cpp:95-110`, and `src/Core/Debugger.cpp:1100-1108`.

### 7. Generic unpacker

There is no Unpack action/dialog; OEP discovery; ESP/NX/manual/run-free strategy; process-image dump; IAT reconstruction; section cleanup; entry/cookie/CFG/relocation repair; sandbox; failure dump; timed entropy probes; or VM-loop/handler trace report.

Only detection fragments exist: packer section-name rules in `src/Core/TechScan.cpp:106-136` and generic entropy findings in `src/Core/RuntimeScan.cpp:341-387`.

### 8. Static VMProtect output unpack

There is no `PACKER_INFO` parser, block-descriptor recovery, LZMA decoder, static decompression/reconstruction strategy, automatic strategy selection, or decompressed-image handoff.

VMProtect is currently recognized only through section-name detection such as `.vmp0`/`.vmp1`: `src/Core/TechScan.cpp:108-111`.

### 9. Non-invasive process dump

There is no passive Dump Process action, read-only snapshot-to-clean-PE pipeline, IAT rebuild, optional `NtSuspendProcess`, launch-and-watch mode, settle detector, or entropy-based auto-timing.

The existing `AppContext::loadLiveModule` path requires an invasive debugger session and only loads copied bytes into the analyzer. `ProcessManager::attach` uses `DebugActiveProcess`: `src/Core/ProcessManager.cpp:71-89`.

### 10. Anti-anti-debug / Hide Debugger layer

There is no PEB/heap normalization, concealment hooks for the requested ntdll calls, invalid-handle handling, debug-register masking/preservation, synthetic clock, or RDTSC/RDTSCP interception/emulation.

Current anti-debug support detects and annotates suspicious imports/instructions only: `src/Core/TechScan.cpp:48-50` and `src/Core/FuncAnnotate.cpp:962-1003`.

## Partial

### 11. ELF symbols are not integrated into Exports or function analysis

The completed Exports side panel now provides a full bounded PE export-address-table view, including aliases, ordinal-only entries, forwarders, and code/data targets. ELF `.dynsym` and `.symtab` entries are still skipped rather than exposed as exports/imports or used as analysis symbols.

Evidence: `src/Core/BinaryFile.cpp` skips non-loaded ELF symbol/string-table sections during section modeling, and `BinaryFile::exports()` is populated by the PE export-directory parser only.

### 12. ARM / Thumb / AArch64 raw-firmware workflow

A32 and A64 Capstone decoding exist, but these requested parts do not:

- Thumb/Thumb-2 architecture selection or `CS_MODE_THUMB`;
- byte-frequency ARM-versus-Thumb sniffing and dialog preselection;
- an editable entry point for raw images;
- ARM prologue discovery and code-versus-literal-pool classification;
- ARM table-branch resolution;
- explicit disabling of x86-only decompiler/debugger/export actions for ARM images.

Evidence: `src/Disasm/IDisassembler.h:36`, `src/Disasm/CapstoneDisassembler.cpp:94-112`, the raw-load popup in `src/App.cpp`, and the x86-only prologue gate in `FunctionAnalyzer::prologueScan`. Pseudocode/Decompiler remain enabled for all loaded architectures in the Binary View's main-view selector.

### 13. Multi-million-instruction, on-screen-only linear listing

ImGui clipper rendering, visible-row decode caching, syntax coloring, string/API comments, and a branch-arrow gutter exist. The requested scale/virtualization model does not:

- the background indexer first decodes every executable byte to build row addresses;
- a hard 800,000-instruction cap omits the rest of larger images;
- unresolved intra-function targets are not consistently materialized as persistent `loc_` listing labels.

Evidence: `src/Core/AnalysisJobs.cpp:281-342`, the cap at `src/Core/AnalysisService.cpp:233-245`, and the visible-row clipping/cache path in `BinaryViewTab::renderAssembly`.

### 14. Recursive code/data classification

Function discovery does use the entry, PE exports, x64 `.pdata`, direct calls, and limited x86 prologues. It does not build the requested code map or classify executable-section padding, jump tables, literals, and embedded strings as data.

Missing pieces include data code-pointer/vtable/callback seeds, `endbr64`-aware gap scanning, indirect-only function recovery from those seeds, ARM literal-pool separation, and `db`/`dd`/`dq` rendering for non-code spans inside executable sections. The current listing linearly disassembles all executable bytes.

Evidence: `FunctionAnalyzer::analyze`, the Binary View's static-list construction, and `src/Core/AnalysisJobs.cpp:307-342`.

### 15. Graph interaction and synchronization

Block cards, colored ordinary edges, pan, block dragging, cursor/RIP block highlighting, and re-rooting exist. The requested graph still lacks:

- Ctrl+wheel zoom and fit-to-view;
- per-instruction hit targets and exact instruction-to-instruction two-way sync;
- a distinct switch-case edge style.

One invisible hit target currently covers each whole block and double-click selects the block start; instruction text is draw-list text. Evidence: the block hit-target, dragging, and edge-rendering paths in `BinaryViewTab::renderGraph`.

### 16. Multi-level IL decompiler

The current lazy background decompiler, LRU, structured pseudo-C/Python output, data-flow improvements, goto fallback, and source navigation are real. There are no separate Low IL, Medium IL, or High IL artifacts/views and no Low/Medium/High/Pseudo-C selector; both decompiler views consume the same final structured result.

Source synchronization on the deep path is block-granular rather than exact-instruction-granular, and double-clicking a call line does not resolve/follow the callee.

Evidence: the Pseudocode/Decompiler selectors, shared-result description, and click handling in `src/Tabs/BinaryViewTab.cpp`, plus mapping granularity at `src/Core/Decompiler.h:77-80`.

### 17. Whole-address-space Hex view

The Hex editor is virtualized and editable, with selection/copy, goto-file-offset, and patch highlighting. It covers `binary.bytes()` (file-backed bytes), not the whole mapped virtual address space, so virtual-only/BSS tails and sparse address gaps cannot be displayed.

Evidence: `BinaryViewTab::renderHex`, which derives its extent from `binary.bytes()`.

### 18. Jump-table recovery

CFG switch edges and a basic resolver exist, but the resolver only handles a scaled memory-form `jmp [...]`, extracts a hex literal, and reads absolute 4/8-byte pointers until an invalid target.

It does not use a preceding `cmp` bound, recover MSVC/GCC relative/RVA tables, handle `mov [table]; add; jmp reg`, or emit the requested `; switch (N cases)` listing annotation.

Evidence: `BinaryViewTab::resolveJumpTable` and `src/Core/CFG.cpp:114-121`.

### 19. Patching workflow

Assembly/raw-hex patching, NOP fill/padding, the in-memory overlay, manual revert, Hex integration, and Save Binary As exist. These requested parts do not:

- Ctrl+Z or a stepwise patch undo history;
- enforcement that a replacement stays within whole selected instructions (a longer encoding may overwrite following bytes after only a warning);
- changed-region-only decode and linear-index splicing.

Edits instead mark functions dirty and rebuild all code-derived indexes in the background. Evidence: the patch/apply flows and manual-revert path in `src/Tabs/BinaryViewTab.cpp`.

### 20. Windows API prototype and symbolic-argument awareness

The app has a one-line API-purpose map and limited best-effort argument sniffing. It does not have the requested prototype database, parameter names/types, x64 stack-argument recovery at `[rsp+0x20+...]`, or symbolic decoding for access masks, share modes, `PAGE_*`, `MEM_*`, creation dispositions, and file flags/attributes.

Graph cards also do not show the requested prototype/argument annotations.

Evidence: `src/Core/ApiInfo.h`, backward scans in `src/Core/FuncAnnotate.cpp:635-687`, the explicit "no callee prototypes" limitation in `src/Core/Decompiler.h:65-74`, and the assembly/graph annotation formatting in `src/Tabs/BinaryViewTab.cpp`.

### 21. C++ demangling throughout

DbgHelp is configured with `SYMOPT_UNDNAME`, which can provide some MSVC/PDB undecoration. There is no built-in Itanium demangler or shared demangling pass, and parsed PE import/export names are displayed/copied raw rather than demangled consistently across functions, imports, exports, and labels.

Evidence: `src/Core/SymbolResolver.cpp:29-41`, `FunctionAnalyzer::collectExports`, and the raw-name rendering in the Exports/Imports views.

### 22. Manual `.dsproj` projects

Automatic hash-keyed JSON sidecars and a recents index persist real annotations. The requested Save Project/Open Project `.dsproj` workflow, versioned user-chosen project file, binary reference/load options, section choices, and broader current-view state are absent.

Raw recents are especially incomplete: reopening uses normal `loadBinaryPath`, so the originally chosen raw base is not restored; only saved architecture/engine can be reapplied.

Evidence: `src/Core/Project.cpp:294-396`, `src/Core/Project.h:47-73`, and `AppContext::loadBinaryPath` / `loadRawPath`.

### 23. Full requested live-debugger surface

The core Win32 debugger, launch/attach, live memory disassembly, stepping, run-to-cursor, SW/HW breakpoints, registers/stack/call stack/modules, detach cleanup, and WOW64 path exist. The requested version still lacks:

- process-picker window title and image-path fields;
- a separate Stop/terminate action and Continue-to-return command;
- the requested F7/F8 shortcut mapping (current mapping is F11/F10/Shift+F11, and Ctrl+F9 is Run to Cursor);
- full C-like conditions with arithmetic/logical operators, typed dereferences, flags, and complete sub-register semantics;
- exact-N and at-or-after-N hit policies plus breakpoint enable/disable state;
- conditions/hit policies for hardware breakpoints;
- a general bottom Memory Dump pane (the general viewer is in the separate Memory Tools tab).

Evidence: `src/Core/ProcessManager.h:12-19`, command set at `src/Core/Debugger.h:256`, shortcuts in `App::renderDebugToolbar`, condition grammar at `src/Core/Cond.h:4-13`, register handling at `src/Core/Debugger.cpp:947-958`, hit policy at `src/Core/Debugger.cpp:1305-1315`, and `BinaryViewTab::renderLowerTabs`.
