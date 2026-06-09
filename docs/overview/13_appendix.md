## 13. Appendix — Source Map, Limitations, Non-Goals & Roadmap

This appendix closes the overview. It (1) maps every significant source file to the
chapter that documents it (and flags anything not covered), (2) collects the parts of
the tool whose output is **heuristic / best-effort** and explains how the UI labels
them, (3) restates the **explicit non-goals** from the project spec, and (4) sketches a
realistic **roadmap** that stays inside the current architecture and does not contradict
those non-goals.

### Source coverage map

Chapter numbers refer to files `01_*.md` … `13_*.md` in this directory. **Chapter 11 —
"Hypervisor (AMD-V/SVM) Backend & Kernel Driver"** is present and documents the entire
AMD-V/SVM subsystem at an architectural level: the `src/Hv/*` user-mode protocol/client/loader
and the `driver/*` kernel source, with the explicit caveat that driver
packaging/signing/loading/runtime-validation are out of scope (see the non-goals below). The
Communications tab's AMD-V *panel* (a UI surface) is additionally described in chapter 8.

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
| `src/Core/TechScan.{h,cpp}` | 4 | Capability / tech detection |
| `src/Tabs/DataRef.h` | 4 | `instrDataRef` shared static-ref helper |
| `src/Core/Decompiler.{h,cpp}` | 5 | Structuring pass → pseudo-C |
| `src/Core/DataFlow.{h,cpp}` | 5 | Data-flow support for the decompiler |
| `src/Core/Debugger.{h,cpp}` | 6 | Real Win32 debugger |
| `src/Core/ProcessManager.{h,cpp}` | 6 | Toolhelp32 process/module enumeration |
| `src/Core/StepLogic.h` | 6 | Pure, unit-tested stepping decisions |
| `src/Core/Cond.{h,cpp}` | 6 | Conditional-breakpoint evaluator |
| `src/Tabs/BinaryViewTab.{h,cpp}` | 7 | The Binary View centerpiece |
| `src/Tabs/ProjectsTab.{h,cpp}` | 8 | Recents / project management |
| `src/Tabs/CommunicationsTab.{h,cpp}` | 8 | Processes, connections, AMD-V panel |
| `src/Tabs/SigScannerTab.{h,cpp}` | 8 | Signature scanner |
| `src/Tabs/MemoryToolsTab.{h,cpp}` | 8 | Memory scanner/editor/table |
| `src/Tabs/BinaryDiffTab.{h,cpp}` | 8 | Two-binary byte diff |
| `src/Tabs/BinaryTechTab.{h,cpp}` | 8 | Tech-scan UI |
| `src/Core/Project.{h,cpp}` | 9 | Per-binary JSON sidecar persistence |
| `src/Core/Json.{h,cpp}` | 9 | Hand-rolled JSON |
| `src/Core/Report.{h,cpp}` | 9 | Report/export generation |
| `src/Ui/Theme.{h,cpp}` | 10 | Color theme / styling |
| `src/Ui/Fonts.{h,cpp}` | 10 | Font loading |
| `src/Hv/HvDbgProtocol.h` | 11 | Shared user/kernel IOCTL + ABI contract |
| `src/Hv/HvDbgClient.{h,cpp}` | 11 (also 8) | `\\.\HvDbg` user-mode client (Communications panel in ch. 8) |
| `src/Hv/HvDbgLoader.{h,cpp}` | 11 | SCM-based driver load/unload helper |
| `driver/HvDbg.h` | 11 | Shared kernel-side definitions |
| `driver/HvDbg.c` | 11 | Driver entry, device object, IOCTL dispatch |
| `driver/HvSvm.c` | 11 | SVM core (virtualize/devirtualize) |
| `driver/HvAsm.asm` | 11 | Asm ↔ C entry/guest-state glue |
| `load-driver.ps1` | 11 | Developer driver-load script |
| `DisasmStudio.vcxproj`, `DisasmStudio.sln` | 12 | Project/solution |
| `vcpkg.json` | 12 | Dependency manifest |
| `build.ps1` | 12 | Build driver script |
| `README.md`, `FIXES.txt` | 12 | Docs / audit log |
| `tests/*.cpp` (11 off-target unit tests) | 12 | All enumerated and described |

Auxiliary scripts not in any chapter plan: `tests/smoke_run.ps1` is referenced by
chapter 12 (a ~5-second GUI liveness check); `tests/run_namer_test.ps1` (the
function-namer test runner) is **not explicitly named** in any chapter, though the
test it drives (`function_namer_test.cpp`) is documented in chapter 12. These are minor.

**Verdict:** Every source file in `src/`, `driver/`, `tests/`, and the build/config root is
covered by a chapter. The AMD-V/SVM subsystem is documented at an architectural level in
chapter 11 — deliberately *not* at an operational driver-loading level, per the non-goals.

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
  self-contained tool, driven entirely through its UI (and `wWinMain` ignores argv, so
  there is no CLI to auto-load a target).
- **No FLIRT-style library recognition.** Signature-based identification of statically
  linked library functions (IDA-FLIRT style) is not implemented.
- **No IPv6 connection tables.** The Communications tab enumerates per-process **IPv4**
  TCP/UDP endpoints (via the IP Helper API filtered by owning PID). There is no IPv6
  table walk.
- **Kernel-driver packaging / signing / loading / runtime validation are outside the
  normal app target.** The AMD-V (SVM) hypervisor lives as **reviewable source** under
  `driver/` (`HvDbg.c`, `HvSvm.c`, `HvAsm.asm`, `HvDbg.h`) plus the `\\.\HvDbg`
  user-mode protocol/client under `src/Hv/`. The shipping `DisasmStudio` solution builds
  **only the user-mode app** — it does not produce a signed, installable, loaded, or
  runtime-validated driver package. The VMRUN / #VMEXIT paths in the driver are
  consequently **review-verified, not runtime-verified** (as the driver source itself
  notes), and the Communications AMD-V panel is a client surface that refuses VMRUN
  IOCTLs on an ABI mismatch.

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
- **Loader breadth.** Additional formats / fat (universal) Mach-O, richer PE metadata
  (TLS callbacks, exception/unwind data, debug directory / PDB path), and deeper
  relocation handling — all extensions of `BinaryFile` with no new heavy dependency.
- **Debugger robustness.** Mitigations around the documented edges: re-entrant hits
  during stepped-over calls whose own address holds a software breakpoint, the Step Out
  500k-instruction safety cap, and callees that rewrite their return address. Possible
  IPv6 connection enumeration would relax a current non-goal — to be treated as an
  explicit scope change, not an assumed default.
- **Architecture coverage for assembly.** Keystone currently assembles only
  x86/x64/ARM/ARM64 (disassembly via Capstone is broader). Extending patch-time
  assembly to more arches, where Keystone supports it, would close the disasm/asm gap.
- **Reporting / export.** Build out `Core/Report` export formats (e.g. richer
  structured exports of functions/strings/imports/xrefs) for offline review.
- **Performance and persistence.** Continue clipper-driven rendering work for very large
  images and incremental/streamed analysis caching in the project sidecar, keeping the
  "must be fast, GPU-accelerated" constraint central.
