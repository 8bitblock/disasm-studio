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
instruction-by-instruction trap-flag tracing. From a paused session whose analyzed
image has an exact matching x86/x64 module and bitness, Binary View walks the lazy
executable-page map in chunks, admits only instruction starts proven by exact (not
provisional) page decodes, maps checked file VAs to the matched live module,
de-duplicates block starts, and caps a trace plan at **65,536** sites. The
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

The paused register editor also accepts text. Because a register cannot contain an
arbitrary string, `RegisterEdit.h` encodes a bounded NUL-terminated UTF-8/byte string
(or UTF-16LE with `L"..."`), and `setRegisterToBufferForSession` allocates
`PAGE_READWRITE` target memory, verifies the write, then places that address in the
selected data GPR. PID, session generation, and active TID must all still match;
WOW64 addresses must fit in 32 bits. Allocation, direct write/readback, context write,
and snapshot publication form one paused transaction and never make the text page
executable. Failed transactions free their allocation. A successful mapping becomes
target-owned across a live detach so any pointer retained by the program stays valid;
process termination reclaims it. This is a current-stop override, not a register
freeze: the program may write the register again after it resumes.

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

**Live TCP/UDP connections** are gathered by the Communications tab
on owned background workers using the IP Helper API:
`GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)` and
`GetExtendedUdpTable(UDP_TABLE_OWNER_PID)` for both `AF_INET` and `AF_INET6`, filtered
to the selected PID, with TCP states rendered to readable names (`ESTABLISHED`,
`LISTEN`, …). Each table has bounded allocation/retries and reports partial failures
without hiding successful families. IPv6 endpoints preserve numeric scope IDs.

### Guided live Server Watch

Static crackme findings can hand off to Communications' **Server Watch**, but observation begins
only after the analyst explicitly presses **Start Server Watch**. `Core/NetworkObservation.h`
defines the bounded, Win32-free event/coverage contract; `Debugger` owns the live probes and ABI
translation. Supported entry/return paths cover catalogued DNS, Winsock, WinHTTP, WinINet, and
URLMon APIs for native x64 and WOW64 targets. Events retain stage, direction, endpoint/hostname,
HTTP method/object, validity-bearing raw result, ABI width, requested/transferred-byte validity,
bounded payload, and runtime continuation address. The shared exact API catalog lets the UI render
the documented expected success/failure/output contract beside the interpreted observed outcome;
a successful read operation is explicitly not presented as server/license acceptance.
Live-PE file offsets are **Observed projections** derived from the target's in-memory PE headers;
the backing-file identity and extent are explicitly unproven.

The UI exposes start/stop, text/hex payload display, continuation navigation, expected-vs-observed
return details, and optional file logging;
starting a log also starts observation rather than silently enabling only a legacy socket tap.
Coverage reports available/armed/skipped probes, shared user breakpoints, drops, retained payload,
and limitations. The capture is best-effort: overlapped completions are marked partial, custom TLS
payloads can remain opaque, and direct syscalls, unsupported transports, generated stubs, or kernel
traffic are not claimed. Server Watch is an observation aid, not containment or a network sandbox.

### Checked authorization return experiments

The Authorization Trail's **Break after call** action is a deliberately narrow dynamic check, not
an automatic crack or a permanent patch. A retained predicate use supplies the exact decoded
instruction immediately after its call. `Core/AuthorizationExperiment` translates that static
continuation through the exact active module identity, and `Debugger::runToCursorForSession`
accepts the one-shot stop only for the captured PID, debugger generation, active thread, executable
committed byte, idle command slot, and a continuation that does not conflict with another
debugger-owned breakpoint. A guessed main-module delta is never sufficient authority.

At the matching pause, `readPausedRegistersForSession` re-reads the real thread context and exposes
RIP plus validity-bearing AL, EAX, and RAX views. The experiment records the result width consumed
by the static branch and captures the original accumulator once. **Force true** and **Force false**
produce register-only proposals: immediately before committing, the debugger rechecks the exact
PID/session/thread, RIP, and masked expected accumulator; after `SetThreadContext` it reads the
context back. A failed verification attempts transactional restoration. **Restore** writes the
captured accumulator back through the same checks. The predicate's code bytes and the analyzed
file are not changed by return forcing.

The captured return is meaningful only for one stopped call instance. Continuing execution,
changing the active thread or RIP, detaching/reattaching, or unloading/replacing the module makes
the plan stale and invalidates force/restore controls. Unrelated breakpoints can stop first without
being misreported as the predicate continuation. This keeps live observation separate from the
static conclusions: an observed return for one run does not prove server acceptance, signature
verification, or feature permission on every path.

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

Static-view debugger actions use file VAs and are deliberately stricter than Live
Assembly. They require an exact path/module/bitness match plus checked ASLR translation
before arming a software/hardware breakpoint, running to the cursor, planting trace
sites, or writing/reverting live bytes. Without that proof, breakpoints stay pending and
patches affect only the project/in-memory file image; an unrelated attached process is
never used as a heuristic destination.

The **call stack** (`computeCallStack`) is a **heuristic stack walk**, clearly labelled
as such in the UI (*"Heuristic walk for TID … N frame(s)"*). It scans up to 2048 stack
slots (4- or 8-byte slots by bitness) from RSP, and treats a value as a return address
only if it points into an executable committed region *and* the bytes immediately
before it decode as a `call` whose length ends exactly at that address. It is
recomputed only when the stop signature (RIP/RSP/TID/state) changes, to avoid
re-walking every frame.

### Adaptive unpack workflow

**Debug -> Adaptive Unpack** is a live PE32/PE32+ unpack workflow rather than a blind
memory dump. `Core/UnpackEngine` is a Win32-free, bounded state machine that combines
restored ESP/RSP, transfers into changed pages, newly executable protection, timed entropy
settling, run-free timeout, and analyst-selected evidence. Candidates are de-duplicated and
shown with confidence plus the exact evidence that produced the score. The same sample
stream builds a bounded heuristic report of hot RIPs, exact repeated back-edges, high-fan-in
destinations, and exception-handler entries so VM-like dispatch behavior remains inspectable
even when no clean OEP is found.

A new launch can be assigned—before its primary thread resumes—to a one-process Windows Job
with `JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. The dialog calls
this *containment* and explicitly notes that it does not virtualize filesystem or network
access. The sampler briefly suspends a bounded set of live threads for RIP/RSP capture, reads
the module by readable `VirtualQueryEx` regions with debugger breakpoint bytes masked, remembers
changed/executable pages, and caps both periodic probes and final image capture. Per-page
readability is tracked separately: unreadable holes cannot look like zero-filled writes, and a
partial final capture is retained only as a raw failure artifact rather than labelled runnable.

`Core/PeUnpack` performs the deterministic mapped-image reconstruction. It emits aligned disk
sections, clears stale COFF per-section tables, repairs the OEP/owner-section flags, copies a
valid original ILT over the loader-resolved IAT or creates `.dsimp` descriptors/ILT/name data
from exact live export matches, and transactionally undoes PE32 HIGHLOW / PE32+ DIR64 ASLR
relocations. If normalization is not trustworthy it retains the runtime base rather than
publishing a half-relocated file. Load-config security-cookie and Guard CF pointers are
rebased when they point into the captured image or cleared conservatively; invalid signature,
bound-import, and checksum state is removed. Reconstruction failures retain the raw mapping,
and every save writes a side report with repair issues, OEP evidence, entropy window, and
VM-loop/handler telemetry. Successful output can be loaded directly into the normal analyzer.

`unpack_engine_test` covers strategy scoring, bounds/caps, entropy settling, manual OEPs, and
VM-loop false-positive controls. `pe_unpack_test` covers PE32+ layout, OEP and section repair,
intact and reconstructed imports, ASLR/load-config repair, malformed-relocation fallback, and
raw failure artifacts.

### Static packed-PE recovery

**Debug -> Static Packed-PE Recovery** uses the owned-input `Core/StaticUnpack` worker to
recover packed payloads without executing them. The high-confidence strategy requires an exact
VMProtect-style `PACKER_INFO` destination sequence for all virtual-only non-BSS sections and a
valid shared LZMA1-properties record; every compressed source and destination has a finite bound.
The in-tree LZMA1 decoder has hard input/exact-output/dictionary/candidate/block/allocation limits
and cancellation. Its path-backed worker verifies the exact source size/hash before decoding;
in-memory patches must be saved and reopened first.
Automatic mode can independently validate a bounded LZMA-alone fallback, while either strategy
can be forced. Recovered mappings feed through `PeUnpack`; reconstructed disk, mapped, and raw
artifacts, per-block evidence, and reports remain separately saveable. The result carries explicit
OEP trust: validated entries are labelled runnable (using a nested PE's own preferred base), while
an unchanged packer/loader entry is visibly analysis-only but may still be loaded for inspection.
Encrypted/mutated metadata and virtualized code are reported for live Adaptive
Unpack instead of guessed. `static_unpack_test` covers PE32/PE32+, bounds, decoding, fallback,
cancellation, reconstruction, and service handoff.

### Passive process dump

The Communications process list and **Debug -> Passive Process Dump** use `Core/PassiveDump`.
Existing targets are queried/read without debugger attach, injection, patches, or target writes;
an optional short `NtSuspendProcess` window can make the final capture coherent. Fresh launch/watch
safely requotes arguments, accepts a working directory, uses no debug flags, and requires pre-resume
one-process kill-on-close Job containment. Immediate,
manual, or page-change+entropy-settle timing is available. Page validity/protection provenance is
kept exact; PE reconstruction refuses missing required pages, with identity-checked disk backfill
limited to unreadable discardable pages and excluded from import evidence. Aggregate peak-memory
admission runs before image-sized work. Under final suspension, remote module/export metadata is
snapshotted before resume and then matched against local captured IAT bytes; otherwise coherence is
reported best-effort. `PeUnpack` repairs the PE, but its unchanged header entry remains analysis-only.
Runnable classification requires an analyst OEP validated on an exactly captured executable page
and zero disk-backfilled pages; backfill downgrades the artifact without making that OEP unverified. Progress,
cancellation, raw fallback, reports, provenance-aware save/load, and explicit owned-process
termination are integrated. `passive_dump_test` includes pure settle/memory/OEP policy, a real
read-only self-snapshot/rebuild, and an opt-in contained-launch smoke.

### Hide Debugger / anti-anti-debug

The pre-session **Hide Debugger** policy defaults entirely off. It reversibly normalizes PEB and
OS-heap-list-proven, region-bounded legacy-heap fields while preserving unrelated heap policy bits.
Target-local entry traps use bounded exports from canonical matching-machine System32/SysWOW64
`ntdll.dll` and are admitted only on executable image-owned pages. CET shadow-stack/IP validation
disables synthetic-return hooks. The remaining traps mediate
selected process/system/thread queries, thread-hide requests, invalid `NtClose`, exact self/same-
process contexts/debug registers, QPC, and system time with native buffer rules. RDTSC/RDTSCP
discovery recursively follows decode-valid control flow only from the PE entry, fully validated x64 unwind
roots, and trusted ntdll roots, bounded to 50k instructions/image and 250k/session. Live-seeded QPC,
system time, and TSC share actual resumed-run intervals while excluding debugger-paused time.
Per-thread/same-address leases safely re-arm concurrent pass-throughs. First-pristine/compare-before-restore rules avoid overwriting target changes; restoration is
best-effort, owner-image traps retire without writes on unload, trap bytes are masked from debugger
reads, and user breakpoints can share sites. Live budget/clock/restore counters and a 32-entry deduplicating
warning cap are shown. The capability report explicitly does not claim direct-syscall, `KUSER_SHARED_DATA`,
generated/self-modifying timing-site, kernel-observer, re-arm-window, or instruction-perfect
multicore guarantees; those require the optional Hv backend. `anti_debug_test` covers the pure
policy/state/clock/range/re-arm layer and the event-loop integration is solution-build verified.

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
- Authorization return experiments require an exact x86/x64 image/session/thread match and a
  proved call continuation. They change only the stopped accumulator and become stale on resume;
  they do not emulate server responses or bypass downstream secondary gates automatically.
- `DebugSetProcessKillOnExit(FALSE)` means the target keeps running after detach by
  design; user-frozen threads are auto-thawed on detach.
