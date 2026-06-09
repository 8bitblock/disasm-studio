## 12. Build, Testing & Verification

DisasmStudio is a single Visual Studio C++20 project that produces one self-contained executable, paired with a deliberately unusual verification strategy: the parts that *can* be compiled and run without Windows GUI/SDK dependencies are covered by a suite of small, focused off-target unit tests, while the parts that *cannot* (the ImGui / Win32 / Zydis / Capstone-facing code) are review-verified and exercised by building the solution and smoke-running the app. This chapter documents both halves precisely.

### 12.1 How the project is built

#### Toolchain and project shape

The build is driven by **Visual Studio 2022 / MSBuild**, x64 only. There is a single solution (`DisasmStudio.sln`) and a single project (`DisasmStudio.vcxproj`). Key facts straight from the `.vcxproj`:

- **Configurations:** `Debug|x64` and `Release|x64`. The project is *x64-only* by design — `build.ps1`'s `-Platform` parameter is `[ValidateSet('x64')]`, so any other value is rejected before MSBuild runs.
- **Toolset / SDK:** `PlatformToolset` is `v145` and `WindowsTargetPlatformVersion` is `10.0` (latest installed Windows 10/11 SDK).
- **Language standard:** `LanguageStandard` = `stdcpp20` with `ConformanceMode` (`/permissive-`) on. `MultiProcessorCompilation` is enabled for parallel `/MP` builds.
- **Include path:** `$(ProjectDir)src` is added so headers resolve as `Core/...`, `Disasm/...`, `Tabs/...` etc. — the same include rooting the unit tests rely on (`/I src`).
- **Preprocessor defines (all configs):** `UNICODE;_UNICODE;NOMINMAX;WIN32_LEAN_AND_MEAN;_CRT_SECURE_NO_WARNINGS`. `NOMINMAX` matters because the codebase uses `std::min`/`std::max` freely; `WIN32_LEAN_AND_MEAN` keeps the Win32 headers (used heavily by `Debugger`, `ProcessManager`, the IP Helper paths) lean. Debug adds `_DEBUG`; Release adds `NDEBUG`.
- **Output paths:** binaries land in `build\$(Platform)\$(Configuration)\` and intermediates in `build\int\$(Platform)\$(Configuration)\`. The Release exe is `build\x64\Release\DisasmStudio.exe`.
- **Release optimization:** `WholeProgramOptimization` (LTCG), `/O2` (`MaxSpeed`), `FunctionLevelLinking`, `IntrinsicFunctions`, plus linker `EnableCOMDATFolding` and `OptimizeReferences` to strip dead code. Debug is `/Od` (`Disabled`).
- **Subsystem:** `Windows` (a GUI app, entry via `wWinMain` in `main.cpp` — note that argv is ignored, so there is no CLI to auto-open a binary).
- **Resources:** `src\app.rc` (compiled by the resource compiler) embeds `src\app.ico`, giving the window/taskbar/Explorer icon. The icon is regenerated with `gen_app_icon.ps1`.

The full source membership is enumerated in the `.vcxproj` `ItemGroup`s: `main.cpp`, `App.cpp`, the UI helpers (`Ui/Theme`, `Ui/Fonts`), the entire `Core/` set (`BinaryFile`, `ProcessManager`, `FunctionAnalyzer`, `FunctionNamer`, `Debugger`, `SymbolResolver`, `CFG`, `Cond`, `Json`, `Project`, `Decompiler`, `DataFlow`, `TechScan`, `XrefIndex`, `Report`), the `Disasm/` backends (`ZydisDisassembler`, `CapstoneDisassembler`, `DisassemblerFactory`, `Assembler`), every tab in `Tabs/`, and the hypervisor user-mode client `Hv/HvDbgClient` + `Hv/HvDbgLoader`. The kernel driver under `driver/` is *not* part of this project — it is reviewable source only (packaging/signing/loading are out of scope).

#### Dependencies via vcpkg manifest mode

Dependencies are declared in `vcpkg.json` (manifest mode), enabled in the project via `<VcpkgEnableManifest>true</VcpkgEnableManifest>` and `<VcpkgEnabled>true</VcpkgEnabled>`. The manifest pins exactly four dependencies:

- **`imgui`** with features `dx11-binding`, `win32-binding`, and `docking-experimental` — the GUI layer (Dear ImGui), its DirectX 11 renderer backend, its Win32 platform backend, and the docking branch.
- **`zydis`** — the primary x86/x64 disassembler.
- **`capstone`** — the multi-architecture disassembler (ARM/ARM64, MIPS/MIPS64, PowerPC/PPC64, RISC-V), routed to automatically for non-x86 images.
- **`keystone`** — the assembler behind the Patch feature (x86/x64/ARM/ARM64 only; it reports "unsupported" for other arches).

The first build downloads and compiles all four from source; subsequent builds are incremental because vcpkg caches the built artifacts (in this checkout they already exist under `vcpkg_installed/`). No new vcpkg dependency was added for JSON, the decompiler, or tech-scan — those are hand-rolled on purpose (see §12.4).

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
- Locates MSBuild via **`vswhere.exe`** (`-latest -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe'`), so it works regardless of the exact VS install path. Missing vswhere or MSBuild yields a clear "install the C++ workload" error.
- Parameters: `-Configuration` (`Release` default, or `Debug`), `-Platform` (`x64` only), `-Rebuild` (MSBuild `/t:Rebuild`), `-Clean` (`/t:Clean`, no build), and `-Verbosity` (`minimal` default).
- Invokes `msbuild` with `/m` (parallel), `/nologo`, and the chosen target, then **returns MSBuild's exit code** so it composes in scripts/CI. On success it prints the resolved exe path (`build\x64\Release\DisasmStudio.exe`); on failure it prints `Build FAILED (MSBuild exit code N)`.

A practical note from the project's own build workflow: a benign `'pwsh.exe' is not recognized` line can appear from a post-build step — it is harmless, and "Build succeeded" is the authoritative signal.

### 12.2 The verification philosophy

The codebase is split, for verification purposes, into two zones:

- **Pure-logic Core modules** — no ImGui, no Win32 GUI, and (where possible) no live disassembler. These are unit-tested off-target.
- **GUI / OS / engine-facing code** — `main.cpp`, `App.cpp`, every `Tabs/*` file, the ImGui rendering, and the parts of the debugger that need a live Win32 debug loop. These cannot be unit-compiled in a plain sandbox, so they are **review-verified** and validated by **building the `.sln` and smoke-running** the exe.

Originally the pure-logic tests were intended to compile with `g++` in a Linux sandbox (as CLAUDE.md still describes). In the actual Windows environment there is no g++/clang, so they are compiled and run with **MSVC `cl`** inside a VS Dev Shell (entered programmatically via `Enter-VsDevShell` from `Microsoft.VisualStudio.DevShell.dll`). Each test file's header comment carries its exact `cl /std:c++20 /EHsc /I src ...` build line listing the minimal set of `.cpp` files it needs, so any single test can be rebuilt and rerun in isolation. All **eleven** `tests/*.cpp` pass (the `FIXES.txt` "10/10" stamp predates the live `wow64_debug_test`, which self-skips when no 32-bit target is available).

### 12.3 The off-target unit tests (`tests/`)

Each test is a standalone `main()` using a tiny `CHECK(cond)` macro that counts failures and returns non-zero if any fail, so they are trivially CI-gateable. Several replay canned instruction streams through a `MockDisassembler`/`StubDis` that implements `IDisassembler::decodeOne` from a lookup table — this lets CFG/decompiler/xref logic be exercised without a real decoder. Two tests deliberately *do* link the real Zydis to prove arch-correct decoding.

- **`binaryfile_macho_test.cpp`** — builds a byte-accurate thin 32-bit Mach-O in memory, writes it to a temp file, loads it via `BinaryFile`, and asserts format/machine/bitness, that the single `__text` section parses, and that `vaToOffset`/`offsetToVA` are correct inverses (`0x1000↔0x100`, `0x1050→0x150`). It specifically pins a fixed bug where 32-bit segment fields (`initprot`/`nsects`) were read at the wrong offsets (`lc+48/52` vs `lc+44/48`), which previously yielded zero sections.
- **`decompiler_switch_test.cpp`** — drives `BuildCFG` + `Decompile` over a classic `cmp`/`jbe`/`jmp [table]` switch dispatch using a `JumpTableResolver` callback. Asserts the dispatch block is flagged `isSwitch` with the three resolved `caseTargets` and one successor per case, that *without* a resolver it stays a plain `jmp` (not a switch), and that the decompiler emits real `switch (rax) { case 0: ... break; }` rather than a bare `goto loc_0;`.
- **`dataflow_decomp_test.cpp`** — the most comprehensive decompiler test (14 scenarios). It validates the data-flow pre-pass (`Core/DataFlow.cpp`) wired into `Decompiler`: copy/constant propagation and dead-assignment elimination (`mov rax,rcx; mov rbx,[rax+8]; mov rax,rbx; ret` → `*(a1 + 8)` with all raw register names gone), argument naming (`rcx→a1`, `rdx→a2`), `xor eax,eax → return 0`, `for`-loop reconstruction from a counting `while`+increment, return-value recovery, `mul`/`div` modeled as `*`/`/`/`%` (not `__asm`), string/IAT resolution through a `dataRefFor` callback (`lea rax,[addr] → return "hello"`, `call [iat] → kernel32.Foo()`), partial-register soundness (`mov al,0` rendered as `LOBYTE(...)`, not a full zero), `movzx` width via `(unsigned __int8)`, alias-aware invalidation of a tracked stack slot, and the **legacy fallback** (`deepDataFlow = false` keeps the raw `rax = rcx;` lift).
- **`function_namer_test.cpp`** — tests the *pure* part of the heuristic function namer: `ToSnakeIdentifier` (`CreateFileW → create_file`, strips `W`/`A` suffix and leading `_`) and `GuessFromEvidence` over a `FuncEvidence` struct. Covers priority ordering (entry → `start`, thunk → `j_CreateFileW`, ret-only → `nullsub`, ret-zero → `ret_zero`), semantic names from API sets (`read_file`, `write_file`, `inject_code`, `net_send`/`net_recv`, `socket_setup`, `check_debugger`, …), the guard that `SendMessageW` is *not* a network send, single-API thin-wrapper detection (small function only), string-derived identifiers, and the "no evidence → no guess" case. These outputs are explicitly *heuristic* and the namer marks them with a `guessed` flag the UI uses to label them.
- **`xref_arch_test.cpp`** — links the **real Zydis** decoder. It confirms `BuildXrefInto`/`FinalizeXrefIndex` recover relative call targets and data references correctly in **both x86 and x64** modes, including the subtle case where identical bytes (`8B 05 ...`) mean RIP-relative in x64 but absolute (`moffs`) in x86 — proving the xref sweep follows the decoder's arch.
- **`xref_report_test.cpp`** — two pure modules. The `XrefIndex` half (a `StubDis` toy encoding) checks that two callers of one target are recorded **sorted and de-duplicated**, that a data ref resolves to the right source, that unreferenced targets return `nullptr`, that `edgeCount()` is correct, and that `FinalizeXrefIndex` is **idempotent**. The `Report` half checks `RenderReportMarkdown` and `RenderReportHtml` produce the expected structure and — importantly — that `<` is left raw in Markdown but **HTML-escaped** to `&lt;` in HTML output.
- **`project_roundtrip_test.cpp`** — serializes a fully-populated `ProjectState` (hash, paths, per-project engine/arch, comments, renames, bookmarks, breakpoints + conditions, patches, watches, notes, last cursor) and deserializes it, asserting an exact round-trip. It specifically exercises **64-bit precision** (`hash = 0xDEADBEEFCAFEF00D`, addresses like `0x1400123456`) because the JSON stores addresses as hex strings for exact round-trip; round-trips every `Arch` through `ArchName`/`ArchFromName`; and verifies the `hasContent()` guard (metadata alone is not "content"; a single comment or watch is).
- **`cond_eval_test.cpp`** — tests the conditional-breakpoint / watch expression evaluator (`Core/Cond.cpp`): `EvalExpression` for single operands (registers, hex/decimal literals, memory derefs `[rax]`, base+disp `[rsp+8]` / `[rsp + 0x8]`, and failures for unknown registers/garbage) and `EvalCondition` for two-operand comparisons (`==`, `!=`, `<`), including empty-string meaning "unconditional → true".
- **`step_logic_test.cpp`** — the only test the comment still shows building with `g++`, because `Core/StepLogic.h` is pure header-only logic. It pins the debugger's *decision tables* (`ClassifyInsn`, `DecideStepOver`, `DecideStepOut`, `DecideOnBpResume`) and then runs a **synthetic CPU + stack simulator** that drives stepping using *only* those decisions, proving step-out and step-over land on the correct instruction across nested calls and recursion (e.g. step-out unwinds exactly one frame). This is how the live debugger's trickiest behavior is verified without a debuggee.
- **`instr_dataref_test.cpp`** — header-only (no `.cpp` deps), tests `instrDataRef()` (`Tabs/DataRef.h`): extracting the static data address an instruction references (absolute `[0x...]`, IAT `call/jmp qword ptr [0x...]`, segment-prefixed `fs:[...]`, Capstone `[rip ± disp]` resolved to absolute) while correctly returning 0 for register-relative memory, stored immediates, bare immediates, and relative branch targets.
- **`wow64_debug_test.cpp`** — a **live end-to-end** test (links the real Debugger + Zydis). It launches a 32-bit process (`SysWOW64\cmd.exe` by default) under the debugger with break-at-entry, asserts it is detected as 32-bit (`is32`), that EIP/ESP are sub-4 GB, and that a single step advances EIP while staying 32-bit, then terminates the child. It **gracefully SKIPs** (exit 0) if no 32-bit target exists or launch fails, so it is safe in CI. This is the one test that genuinely exercises `Debugger.cpp`'s WOW64 path on Windows.

Two helper scripts round out the workflow: **`run_namer_test.ps1`** enters a VS Dev Shell and compiles+runs the namer test end-to-end (a template for the `cl`-based recipe), and **`smoke_run.ps1`** launches the built Release exe, waits 5 seconds, and reports whether it stayed alive — the canonical "did the GUI start" check for the code that can't be unit-tested. Tests that link the static Zydis/Capstone libs reference them under the (doubled) path `vcpkg_installed\x64-windows-static\x64-windows-static\{include, lib}`.

### 12.4 Dependency-light philosophy

A recurring design rule is to **add no new third-party dependency** for things the project can reasonably own. Consequently the JSON layer (`Core/Json`), the structuring decompiler (`Core/Decompiler` + `Core/DataFlow`), and the capability/tech scan (`Core/TechScan`) are all hand-rolled. The payoff is twofold: the dependency set stays at exactly four vcpkg packages (so the static single-exe stays small and the first-build cost stays bounded), and these modules have **no GUI/OS coupling**, which is precisely what makes them unit-testable off-target. The verification strategy and the dependency philosophy reinforce each other.

### 12.5 Tracking fixes — FIXES.txt

`FIXES.txt` is the project's adversarial-audit log. It catalogues issues by severity (HIGH/MEDIUM/LOW) with file:line citations and root-cause notes — loader integer-overflow/OOB hardening in `BinaryFile` `rd<T>`, debug-handle leaks in `ProcessManager::pumpDebugEvent`, the `setActiveThread` `Paused` guard, the 0xCC-original-byte preservation fix, TOCTOU races guarded by a new `hProcMtx_`, the WOW64 context handling, decompiler join-block overruns, and more. Each line records whether it is done or **consciously deferred with rationale** (e.g. CFG branch-target leaders that land mid-instruction are still dropped — a re-decode feature, not a one-liner — and a cosmetic legacy-decompiler placeholder left to avoid churning the golden-string tests). It also lists the paths an audit reviewed and found clean (the Zydis/Capstone/Keystone decode paths, the hand-rolled JSON parser, `SymbolResolver`, `DataFlow`, the dominator core, the Hv client). It is the human-readable companion to the automated tests — covering exactly the GUI/OS-facing code the unit tests can't reach.

#### Limitations & notes

- **No automated GUI/integration harness.** The ImGui/Win32/Tabs layer is verified by review + `.sln` build + `smoke_run.ps1` (a 5-second liveness check). Deeper interactive paths (live assembly view, Stack/Xrefs tabs, run-to-cursor, the export dialog) require manual GUI use; there is no CLI to auto-load a binary (`wWinMain` ignores argv).
- **The unit tests are not auto-run by the build.** `build.ps1` builds only the app; the `tests/*.cpp` are compiled and run separately (one `cl` invocation each) and are not wired into MSBuild or a test runner. There is no single "run all tests" command in-repo.
- **Off-target reality vs. docs.** CLAUDE.md describes the tests as g++-on-Linux; in the real Windows environment they are built with MSVC `cl` in a VS Dev Shell (only the header-only `step_logic_test` is g++-portable as documented). A noted sandbox quirk is that a mounted copy of a just-edited file can be stale/torn — the real Windows files are authoritative.
- **First-build cost.** The `x64-windows-static` triplet recompiles all four vcpkg deps from source on a clean tree; this is a one-time cost traded for a redist-free single exe.
- **x64-only, static-CRT-only.** There is no 32-bit (Win32) app configuration; the static CRT choice must match across the app and any test linking the same Core sources (hence `/MT` in the engine-linking test recipes).
- **`wow64_debug_test` is environment-dependent.** It needs a 32-bit target present and adequate privileges; otherwise it self-skips rather than fail. Attaching to protected or cross-bitness processes generally needs Administrator and a matching architecture.
