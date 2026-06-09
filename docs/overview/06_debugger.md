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

**Live TCP/UDP connections** are gathered by the Communications tab
(`src/Tabs/CommunicationsTab.cpp::refreshConnections`) using the IP Helper API:
`GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)` and
`GetExtendedUdpTable(UDP_TABLE_OWNER_PID)`, filtered to the selected PID, with TCP
states rendered to readable names (`ESTABLISHED`, `LISTEN`, …). This is **IPv4 only**
— IPv6 connection tables are explicitly out of scope per the project spec.

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

#### Limitations & notes

- **x86/x64 only.** The live debugger does not support ARM/ARM64/MIPS/PPC/RISC-V
  targets even though those decode statically; the step decoders are Zydis x64/x86.
- **IPv4 only** for the connection tables; IPv6 is out of scope.
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
