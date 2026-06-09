# DisasmStudio

A fast, GPU-accelerated reverse-engineering workbench built with **Dear ImGui** and **DirectX 11** in C++20. This is the first-pass scaffold: every tab and the debug-control toolbar are laid out and wired to shared state, with a working PE loader, byte-pattern scanner, string extractor, and a real disassembly engine behind an abstraction layer (Zydis + Capstone, switchable at runtime).

## Layout

```
DisasmStudio.sln            Visual Studio 2022 solution (x64)
DisasmStudio.vcxproj        Project (manifest-mode vcpkg enabled)
vcpkg.json                  Dependencies: imgui[dx11/win32/docking], zydis, capstone, keystone
src/
  main.cpp                  Win32 + DX11 host, ImGui render loop (fixed single-window UI)
  App.{h,cpp}               Shell: menu bar, debug toolbar, dockspace, tab hosting
  Core/
    BinaryFile.{h,cpp}      Loader: PE32/PE32+, ELF(32/64), Mach-O, raw; VA<->file (both ways), hash, exports
    Debugger.{h,cpp}        Real Win32 debugger: debug-event loop, breakpoints, step into/over/out
    ProcessManager.{h,cpp}  Toolhelp32 process/module enumeration
    FunctionAnalyzer.{h,cpp} Function discovery (entry/exports/calls/prologues)
    CFG.{h,cpp}             Control-flow graph (basic blocks + edges)
    Cond.{h,cpp}            Conditional-breakpoint expression evaluator
    Decompiler.{h,cpp}      Structuring pass (dominators/loops) -> pseudo-C for the Pseudocode view
    Project.{h,cpp}         Per-binary analysis persistence (JSON sidecar keyed by content hash)
    Json.{h,cpp}            Tiny dependency-free JSON parser/serializer backing Project
    TechScan.{h,cpp}        Capability detection (imports/sections/byte patterns) for the Binary Tech tab
  Disasm/
    IDisassembler.h         Engine-agnostic disassembly interface
    ZydisDisassembler.*     Zydis backend
    CapstoneDisassembler.*  Capstone backend
    DisassemblerFactory.*   Builds the chosen engine for the chosen arch
  Tabs/
    ProjectsTab            Manage targets / recent projects
    CommunicationsTab      Native process list + connections/channels
    SigScannerTab          Pattern scan: Results / Current Scan / Sig Health / All Functions
    BinaryViewTab          Assembly + Pseudocode + Hex, side panel (Bookmarks/Functions/
                           Strings), byte-pattern search, lower tabs (Breakpoints/Notes/
                           Results/Hotkeys)
    MemoryToolsTab         Scanner (+ scan options), Viewer/Editor, tree Browser, Address Table
    BinaryDiffTab          Load two binaries, compute and review byte differences
    BinaryTechTab          Run a tech scan; select detected capabilities to view code
```

## Build

### Prerequisites
- **Visual Studio 2022** with the "Desktop development with C++" workload (MSVC v143, Windows 10/11 SDK).
- **vcpkg** (https://github.com/microsoft/vcpkg). One-time setup:
  ```
  git clone https://github.com/microsoft/vcpkg
  .\vcpkg\bootstrap-vcpkg.bat
  .\vcpkg\vcpkg integrate install
  ```

The project uses **vcpkg manifest mode** (`vcpkg.json`), so the first build automatically downloads and builds ImGui (with the DX11 + Win32 + docking backends), Zydis, Capstone, and Keystone (the assembler behind the Patch feature). No manual library setup needed. The persistence and decompiler subsystems are dependency-free (hand-rolled JSON, in-house structuring), so they add nothing to the dependency set.

### Compile
Open `DisasmStudio.sln`, pick **x64 / Debug** (or Release), and build (F7). The binary lands in `build\x64\<Config>\DisasmStudio.exe`.

If the ImGui backend headers (`imgui_impl_dx11.h`, `imgui_impl_win32.h`) aren't found, confirm the `dx11-binding` and `win32-binding` features installed: `vcpkg install` from the project root reads `vcpkg.json`.

### Distribution (self-contained exe)
The project builds against the **`x64-windows-static`** vcpkg triplet with the **static CRT** (`/MT`, `/MTd`),
so ImGui/Zydis/Capstone/Keystone and the C/C++ runtime are linked *into* the exe. The result is a
**single self-contained `DisasmStudio.exe`** — no `Zydis.dll`/`capstone.dll`/`keystone.dll` beside it and
**no Visual C++ Redistributable** required on the target. The only non-OS dependency is
`d3dcompiler_47.dll` (ImGui's DX11 backend compiles its shaders at runtime), which ships with Windows 10/11.

The app icon (window/taskbar + Explorer) is embedded via `src/app.rc` (`src/app.ico`). To regenerate the
multi-resolution icon, run `powershell -ExecutionPolicy Bypass -File gen_app_icon.ps1`.

## Using it
- **File > Open Binary** loads an `.exe/.dll/.sys/.bin` (PE/ELF/Mach-O auto-detected); **Open as Raw…** maps a flat blob at a chosen base + arch; **Save Binary As…** writes a patched copy. The Projects tab lists recent targets (double-click to reopen) and shows parsed format, image base, entry point, sections, and the saved-analysis summary.
- **Engine** menu switches between Zydis and Capstone and the target architecture at runtime — the Binary View re-disassembles immediately.
- The top **debug toolbar** drives Continue / Step Into / Step Over / Step Out (also F5 / F11 / F10 / Shift+F11).
- The UI is a fixed, browser-style single window: a top tab strip switches between the Projects / Communications / Sig Scanner / Binary View / Memory Tools / Binary Diff / Binary Tech tabs, with the debug toolbar pinned above and a status bar below (no docking / tear-off windows, by design).
- Most result lists (Sig Scanner matches, Binary Tech capabilities, Imports, functions, strings) are click-to-navigate: selecting an address jumps the Binary View to it.

## What's real vs. stubbed
**Working now:**
- PE parsing, VA↔file translation, live disassembly (both engines).
- Byte-pattern signature scanning with `??` wildcards, ASCII string extraction, byte search, binary diffing.
- **Live process enumeration** (Toolhelp32) and **a real Win32 debugger** (`Debugger`): attach/detach via the debug API, software breakpoints (0xCC with the restore→single-step→re-arm dance), **Step Into** (EFLAGS trap flag), **Step Over** (temp breakpoint after a `call` or a `rep`-prefixed string op, single-step otherwise), **Step Out** (single-steps the current frame while *stepping over* every call, then stops on that frame's own `ret` — it never traces into callees, so it stays fast), register capture via `Get/SetThreadContext`, and `ReadProcessMemory`. Continue / Step Into / Step Over / Step Out all resume correctly even when issued while the thread is parked *exactly* on a software breakpoint: the engine restores + steps the original instruction, re-arms the 0xCC, and only then carries out the requested command. The per-instruction stepping decisions live in a pure, unit-tested header (`Core/StepLogic.h`; see `tests/step_logic_test.cpp`). The toolbar drives it; the debug loop runs on its own thread and the UI reads a lock-guarded snapshot.
- **Hardware breakpoints** (DR0–DR3): up to four debug-register breakpoints with full DR7 condition/length encoding, programmed onto every thread (including newly created ones) and DR6-based hit detection. Right-click an address in the assembly view to toggle one; managed in the Breakpoints panel.
- **Conditional breakpoints**: any software breakpoint can carry a condition expression (e.g. `rax == 0x10`, `rcx > 100`, `[rsp+8] != 0`) evaluated on the debug thread at hit time — the debuggee only stops when it's true, otherwise it silently re-arms and continues. Evaluator lives in `Cond.{h,cpp}` (registers, memory derefs with displacement, `== != < > <= >=`).
- **Run to cursor**: right-click any instruction → *Run to cursor* sets a one-shot temp breakpoint and continues.
- **Thread list + context switching** (Binary View → Threads lower tab): every debuggee thread with its RIP; select one to point the register/stack views at it, or *follow* to also move the disassembly cursor.
- **Registers + stack panel** (Binary View → Registers lower tab): full GPR/RIP/RSP/RFLAGS dump plus a live stack read through `Debugger::readMemory`, for the active thread.
- **Live Assembly view** (Binary View → *Live Assembly*): disassembles the *debuggee's* memory at RIP in real time. Inline execution controls (Continue/Pause, Step Into/Over/Out) and a state pill mean you can drive the debugger without leaving the listing. A **register/flags strip** shows all GPRs + decoded EFLAGS (ZF/CF/SF/OF/PF/AF/DF) and **amber-highlights any register that changed since the previous stop**. **Jump arrows** are drawn in a left flow gutter (lane-packed, colored for forward/backward/active, with off-window stubs). The line at RIP gets **inline register-value hints** parsed from its operands (e.g. `; rcx=0x.. rdx=0x..`). Following RIP **back-aligns the window** so the current instruction shows with leading context and **auto-scrolls** to stay centered. Branch targets are clickable (and double-click-to-follow) with **back/forward cursor history**, a goto box, a right-click menu (run-to-cursor, SW/HW breakpoints, copy address/bytes/instruction), and per-view toggles for the strip, arrows, and hints.
- **Real memory scanner** (Memory Tools): first/next scan over committed regions (`VirtualQueryEx` + `ReadProcessMemory`) for byte/word/dword/qword/float/double, with exact/bigger/smaller/changed/unchanged/unknown scan types; live viewer/editor, a region browser, and an address table with **write-through editing and value freezing** via `Debugger::writeMemory`.
- **Automatic function discovery** (`FunctionAnalyzer`): entry point + PE export table seeds, recursive-descent call following, and a prologue heuristic sweep.
- **Control-flow graph** (`CFG` + the "Graph (CFG)" mode in Binary View): basic-block partitioning, branch/fallthrough edges, an `ImDrawList` canvas with the live RIP block highlighted.
- **Lightweight decompiler** (`Decompiler` + the "Pseudocode" mode): a real in-house structuring pass over the CFG — iterative dominators + immediate post-dominators, natural-loop detection, and recursive emission that recovers `if/else` and `while/do-while`, with a labelled-`goto` fallback for irreducible flow. Instructions are lifted to C-like statements (with `cmp`/`test`→relational conditions and call-target name resolution). Cached per function; **Refresh** re-runs it. Not a data-flow decompiler (no type recovery), but per-binary structured output instead of a fixed template.
- **Project persistence** (`Project` + `Json`): comments, symbol renames, bookmarks, breakpoints (+ conditions), byte patches, the last cursor, and notes are saved as a JSON sidecar **keyed by the binary's content hash** (`%APPDATA%\DisasmStudio\projects\<hash>.json`) and reloaded automatically on open. Saved on Close / Exit / target-switch. A recents index backs the **Projects tab** (double-click to reopen). JSON is hand-rolled (no new dependency); addresses persist as hex strings so 64-bit values round-trip exactly.
- **User comments + symbol renaming**: right-click any instruction → *Set comment…* / *Rename symbol…*. Renames win over export/PDB/heuristic names everywhere they resolve (listing targets, function headers/lists, xrefs, call stack, goto-by-name); comments render inline in the listing. Both persist via the project sidecar.
- **Patch to file**: the Patch popup (asm via Keystone, or raw hex) now *accumulates* patches into the project; **File ▸ Save Binary As…** splices them into a copy of the image on disk via the new `BinaryFile::vaToOffset`. Patches are listed in the Binary View → *Patches* lower tab (revert/remove), still write live when attached, and survive a restart.
- **Multi-format loader**: PE32/PE32+, **ELF (32/64)**, **Mach-O (thin 32/64)** header parsing, plus **File ▸ Open as Raw…** to map a flat code blob (shellcode/firmware) at a chosen base + arch. The CPU is read from the header (`machine()`), so ELF/Mach-O ARM images route to Capstone automatically.
- **Full-program assembly listing** (Binary View → *Assembly*, "Full program" on by default): a linear sweep of every executable section with `sub_`/symbol **function dividers**, rendered through an `ImGuiListClipper` so even multi-MB images stay smooth (re-decoded per visible row; capped at 800k instructions). Strings and functions **load automatically** on open (no manual scan); the string scanner detects ASCII/UTF-8 **and UTF-16LE**.
- **More architectures** (via Capstone): x86/x64, ARM/ARM64, **MIPS/MIPS64, PowerPC/PowerPC64, RISC-V 32/64**. The loader's `machine()` auto-selects the arch from PE/ELF/Mach-O headers; the Engine menu lets you override. (The Keystone-backed patch assembler remains x86/ARM only and says so.)
- **Imports & relocations** (PE): the IAT is resolved to `DLL.function` and shown inline at call sites (`call [iat]  ; kernel32.CreateFileW`), in `symbolFor`, and in a dedicated **Imports** lower tab; base relocations are parsed and counted. (`BinaryFile::imports()` / `relocations()`.)
- **Call graph** (Binary View → *Call Graph*): cached caller/callee edges between discovered functions, navigable around the current function.
- **Switch/jump-table recovery**: right-click an indirect `jmp [reg*n + table]` → *Resolve jump table* reads the table entries (bounded by the section) and lists the case targets.
- **Best-effort type & deobfuscation hints**: the decompiler prepends a heuristic **inferred signature** (arg count from calling-convention register reads, `__int64`/`void` return); timing/privileged/anti-debug instructions (`rdtsc`, `cpuid`, `int 0x2d`, `in`/`out`, …) are flagged inline. Clearly labelled as heuristic.
- **Binary Tech capability scan** (`Core/TechScan`): a real scan over the loaded image — imported-API grouping (anti-debug / network / crypto / injection / dynamic-API / process-spawn), packer/protector section-name signatures (UPX, VMProtect, Themida, ASPack, …), and distinctive byte patterns (direct syscall stub, AES S-box, SHA-256 / MD5 constants). Each hit links to its address with a live disasm/hex preview. (No fabricated results — a clean binary shows few or none.)
- **Signature health**: saved signatures are scored against the loaded binary (none / unique / multiple, with a match count), not hardcoded.
- **Live connections** (Communications): per-process IPv4 TCP/UDP endpoints via the IP Helper API (`GetExtendedTcpTable`/`UdpTable` filtered by owning PID), with TCP state.

**Still stubbed / out of scope:**
- The AMD-V (SVM) hypervisor driver source exists under `driver/`, and the Communications tab has a `\\.\HvDbg` user-mode client. Packaging, signing, loading, and runtime validation of that kernel driver are still outside the normal app build.
- Connection enumeration is IPv4-only (no IPv6 table walk yet). Scripting/plugin automation is intentionally not included.

**Known limitations to be aware of in the debugger:** Step Out single-steps the *current* frame (stepping over calls), so it is bounded by that frame's executed instructions — a pathological in-frame loop that runs past the 500k-instruction safety cap pauses early with a "step out (capped)" status. Hitting a user breakpoint mid-step cancels the in-progress step (you stop on the breakpoint). When you step *over* (or step *out* past) a `call` whose own address holds a software breakpoint, that breakpoint is briefly un-armed while the call runs, so a re-entrant hit *during* the skipped call is not caught. Step Out relies on the executed `ret`/tail-`jmp` actually returning to the call site; a callee that rewrites its own return address (some ROP/obfuscation) won't trip the return breakpoint. The memory scanner caps the scan at 512 MB / 2M results per pass to stay responsive. Attaching to protected or cross-bitness processes needs Administrator and matching architecture.

## On the performance / hypervisor requirements
The renderer is genuinely GPU-accelerated: it creates a **hardware** D3D11 device (falling back to WARP only if no GPU is available), double-buffered with vsync, and skips rendering when occluded. ImGui draws in retained-immediate mode and stays well within frame budget.

The **AMD hypervisor** request is a larger, separate subsystem: an AMD-V (SVM) based VMM for stealthy debugging / EPT-style memory shadowing means a kernel driver and ring-(-1) code, which lives outside this user-mode UI process. This tree now includes the reviewable driver source in `driver/` plus the `\\.\HvDbg` user-mode protocol/client in `src/Hv`; the normal `DisasmStudio` solution still builds only the user-mode app, not a signed/installable driver package.
