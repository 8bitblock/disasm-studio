#pragma once
//
// Debugger.h
// A real Win32 user-mode debugger. Owns the debug session for one process and
// runs the debug-event loop on a dedicated thread (Windows requires the same
// thread that called DebugActiveProcess to service WaitForDebugEvent). The UI
// thread posts commands (continue/step/...) and reads a thread-safe snapshot.
//
// Implements:
//   - attach / detach via the Win32 debug API
//   - software breakpoints (0xCC) with the restore + single-step + re-arm dance
//   - step into  (trap flag, EFLAGS.TF)
//   - step over  (temporary breakpoint after a CALL, else single-step)
//   - step out   (call-depth-counting single-step until the matching RET)
//   - register capture via Get/SetThreadContext
//   - process memory reads for disassembly
//
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "Cond.h"   // CondProgram (pre-compiled breakpoint conditions)
#include "AntiDebug.h"
#include "AuthorizationWatch.h"
#include "AttachImagePolicy.h"
#include "DebugTargetIdentity.h"
#include "DllDebugPlan.h"
#include "NetworkObservation.h"
#include "TraceCoverage.h"
#include "GameMakerSession.h"

namespace ds {

class IDisassembler;

enum class DbgState { Detached, Running, Paused, Terminated };

// Lifecycle work has its own state: Starting/Stopping never grant authority to
// read or modify a target. DbgState continues to describe the actual session.
enum class DbgLifecycleState { Detached, Starting, Attached, Paused, Stopping, Failed };
enum class DbgLifecycleCommand { None, Attach, Detach };
struct DbgLifecycleSnapshot {
    DbgLifecycleState state = DbgLifecycleState::Detached;
    DbgLifecycleCommand command = DbgLifecycleCommand::None;
    uint64_t requestId = 0;
    uint32_t requestedPid = 0;
    DebugTargetIdentity target{}; // exact successful completion owner
    bool busy = false;
    bool completed = false;
    bool succeeded = false;
    bool cancelled = false;
    std::string error;
};

struct NetCaptureLogStatus {
    bool enabled = false;
    bool opening = false;
    bool draining = false;
    size_t queuedRecords = 0;
    size_t queuedBytes = 0;
    uint64_t droppedRecords = 0;
    std::string error;
};

struct Registers {
    uint64_t rip = 0, rsp = 0, rbp = 0, rflags = 0;
    uint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0, rsi = 0, rdi = 0;
    uint64_t r8 = 0, r9 = 0, r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, r15 = 0;
};

// Stable register evidence from one exact user-visible debugger stop.  EAX and
// AL are derived while the same lock protects the whole RAX value, preventing a
// UI adapter from accidentally combining aliases from different stops.
struct PausedRegisterSnapshot {
    DebugTargetIdentity target{};
    uint32_t             tid = 0;
    bool                 is32 = false;
    Registers            regs;
    uint32_t             eax = 0;
    uint8_t              al = 0;
};

enum class HwKind { Execute, Write, ReadWrite };

struct MemRegion {
    uint64_t base = 0, size = 0;
    uint64_t allocationBase = 0;
    uint32_t protect = 0, state = 0, type = 0;
    bool     read = false, write = false, exec = false;
};

// One independently verified live-memory mutation.  Batch submission is used
// by Memory Tools' freeze scheduler so scattered address-table rows share one
// debugger wake-up while retaining per-row success/failure results.
struct MemoryWriteSpan {
    uint64_t address = 0;
    std::vector<uint8_t> bytes;
    // False limits the transaction to already-writable, non-executable pages.
    // True permits a temporary page-protection change; executable writes still
    // require a user-visible debugger pause.
    bool allowProtectionChange = false;
};

struct ThreadInfo {
    uint32_t tid = 0;
    uint64_t rip = 0;
    bool     suspended = false;   // user-frozen via suspendThread()
};

struct SwBreakpointInfo {
    uint64_t    address = 0;
    std::string condition;   // empty = unconditional
    uint32_t    hits  = 0;   // every time the 0xCC fired (incl. condition-false passes)
    uint32_t    stops = 0;   // hits where the condition held and we parked
    uint32_t    everyN = 0;  // 0/1 = stop on every (condition-true) hit; N = every Nth
    bool        armed = true; // false on install/re-arm failure or while stepped off a held breakpoint
    std::string error;        // asynchronous install/re-arm failure, when present
};

// One loaded module of the debuggee, tracked live from LOAD_DLL/UNLOAD_DLL
// debug events (the Communications tab's Toolhelp list is a one-shot snapshot;
// this one follows dynamic loads/unloads during the session).
struct DbgModule {
    std::string name;        // file name (e.g. "jvm.dll")
    std::string path;        // full path when resolvable (may be empty)
    uint64_t    base = 0;
    uint64_t    size = 0;    // SizeOfImage read from the mapped header (0 if unreadable)
    AttachedFileIdentity fileIdentity; // exact CREATE_PROCESS/LOAD_DLL backing file
    uint64_t    loadGeneration = 0; // mapping incarnation within session
};

struct HwBreakpointInfo {
    uint64_t address = 0;
    HwKind   kind    = HwKind::Execute;
    uint8_t  size    = 1;    // 1/2/4/8 bytes (forced to 1 for Execute)
};

// One unwound call-stack frame, produced by the real DbgHelp StackWalk64 walk of
// the stopped debuggee (see Debugger::unwindStack). pc is the frame's instruction
// pointer; frameSp/stackPtr are AddrFrame/AddrStack from the walk; name is a
// best-effort DbgHelp symbol (the UI may re-resolve it through its own namer).
struct CallStackFrame {
    uint64_t    pc = 0;
    uint64_t    frameSp = 0;   // STACKFRAME64::AddrFrame  (frame base, ~rbp)
    uint64_t    stackPtr = 0;  // STACKFRAME64::AddrStack  (stack pointer at the frame)
    std::string name;          // best-effort symbol (may be empty)
};

// Typed lifecycle for the narrow, identity-checked RunTo used by an
// Authorization Trail return experiment.  requestToken is supplied by the
// experiment owner and is opaque to the debugger; revision is debugger-owned
// and increases on every published transition.  Ordinary RunTo commands do
// not create or modify this record.
enum class CheckedRunToState : uint8_t {
    None = 0,
    Pending,
    Armed,
    Failed,
    Hit,
    Cancelled,
};

struct CheckedRunToSnapshot {
    CheckedRunToState state = CheckedRunToState::None;
    uint64_t revision = 0;
    uint64_t requestToken = 0;
    DebugTargetIdentity target{};
    uint32_t tid = 0;
    uint64_t address = 0;
    std::string error;
};

namespace debugger_detail {
struct LifecycleTestAccess; // target-free deterministic worker/lifetime regression fixture

// Pure reconciliation model for abandoning a temporary software breakpoint.
// A failed byte transition may release metadata only when another persistent
// breakpoint owner accepts responsibility, the byte is proved not to be an
// INT3, or its mapping is proved gone.  Unknown/remaining INT3 state keeps the
// temporary owner live so cleanup can be retried or the trap can be consumed.
enum class TempBreakpointByteState : uint8_t {
    Unknown = 0,
    Int3,
    Other,
    Unmapped,
};

enum class TempBreakpointCleanupDisposition : uint8_t {
    Release = 0,
    Retain,
};

TempBreakpointCleanupDisposition ClassifyTempBreakpointCleanup(
    bool persistentOwner,
    bool transitionSucceeded,
    TempBreakpointByteState byteState) noexcept;

} // namespace debugger_detail

struct DbgSnapshot {
    DbgState                 state = DbgState::Detached;
    uint32_t                 pid = 0, tid = 0;     // tid = active/displayed thread
    uint64_t                 sessionGeneration = 0; // changes on every successful attach/launch
    Registers                regs;
    std::string              lastEvent = "idle";
    std::vector<SwBreakpointInfo> breakpoints;     // software (0xCC), with conditions
    std::vector<HwBreakpointInfo> hwBreakpoints;   // DR0-DR3 (address + kind + size)
    std::vector<ThreadInfo>  threads;
    std::vector<CallStackFrame> frames;             // real StackWalk64 unwind of the active thread
    std::vector<DbgModule>   modules;               // live module list (LOAD/UNLOAD_DLL events)
    std::vector<std::string> debugOutput;           // OutputDebugString capture (bounded ring)
    uint32_t                 activeTid = 0;
    bool                     is32 = false;          // target is a 32-bit (WOW64) process
    // JVM awareness (Java EXEs): set once a jvm.dll/j9vm.dll loads in the debuggee.
    bool                     jvmLoaded = false;
    std::string              jvmPath;               // path of the loaded VM module
    uint64_t                 jvmExceptionsPassed = 0; // JVM-internal AVs passed through silently
    uint64_t                 exceptionSequence = 0;   // increments for each non-break/step exception
    uint32_t                 exceptionCode = 0;
    uint64_t                 exceptionAddress = 0;
    bool                     exceptionFirstChance = false;
    // Hosted-DLL launch state. The path/base identify the exact ASLR-loaded
    // module so the App can replace its preferred-base image with live memory.
    bool                     dllHostedLaunch = false;
    bool                     dllTargetMatched = false;
    std::string              dllTargetPath;
    uint64_t                 dllTargetBase = 0;
    uint64_t                 dllTargetSize = 0;
    std::string              dllTargetLabel;  // armed targets or most recent target hit
    std::string              dllTargetError;  // planting/retargeting failure, if any
    CheckedRunToSnapshot     checkedRunTo;    // Authorization Trail one-shot lifecycle
    bool                     containedJob = false; // kill-on-close, one-process unpack containment
    AntiDebugSessionStats    antiDebug;       // opt-in concealment coverage/telemetry
    bool                     attached() const { return state != DbgState::Detached; }
};

class Debugger {
    friend struct debugger_detail::LifecycleTestAccess;
public:
    Debugger();
    ~Debugger();

    bool attach(uint32_t pid, std::string& err);

    // UI lifecycle commands are bounded to one outstanding operation. Zero
    // means rejected (busy, stale identity, or invalid input). No join, Win32
    // attach, or cleanup executes on the caller. Poll completion by requestId.
    uint64_t requestAttach(uint32_t pid);
    uint64_t requestDetach(DebugTargetIdentity expected = {});
    bool cancelLifecycle(uint64_t requestId);
    DbgLifecycleSnapshot lifecycleSnapshot();

    // Launch a new process under the debugger (CreateProcess with DEBUG flags) and
    // begin a debug session. With breakAtEntry, the session pauses at the program's
    // entry point (a one-shot breakpoint past the loader breakpoint) so you can
    // debug from the first instruction. exePath is a UTF-8 filesystem path.
    bool launchAndAttach(const std::string& exePath, std::string& err,
                         bool breakAtEntry = true, bool containedJob = false,
                         const AuthorizationWatchPlan* authorizationPlan = nullptr,
                         AuthorizationWatchOptions authorizationOptions = {},
                         bool prelaunchNetworkObservation = false);

    // Launch a validated bitness-compatible DLL host. lpApplicationName comes
    // from plan.executable while the already Windows-quoted argv is passed as
    // the mutable lpCommandLine. Requested DllMain/export breakpoints are
    // retargeted from RVAs when the exact DLL appears in LOAD_DLL.
    bool launchAndAttachDll(const DllDebugLaunchPlan& plan, std::string& err);

    void detach();
    bool detachForSession(DebugTargetIdentity expected);

    // Execution control (posted to the debug thread; return immediately).
    void cont();
    void stepInto();
    void stepOver();
    void stepOut();
    void pause();   // best-effort async break
    bool continueForSession(DebugTargetIdentity expected);
    bool stepIntoForSession(DebugTargetIdentity expected);
    bool stepOverForSession(DebugTargetIdentity expected);
    bool stepOutForSession(DebugTargetIdentity expected);
    bool pauseForSession(DebugTargetIdentity expected);
    void runToCursor(uint64_t va);   // one-shot temp breakpoint, then continue

    // Checked counterpart for a live authorization experiment.  The request is
    // accepted only for the exact paused PID/session/thread, an executable
    // committed continuation byte, an idle command slot, and no conflicting
    // debugger-owned breakpoint at that address.  requestToken must be the
    // caller's non-zero monotonically changing experiment generation. Success
    // means the validated one-shot request was queued; DbgSnapshot publishes
    // its exact asynchronous Pending/Armed/Failed/Hit/Cancelled lifecycle.
    bool runToCursorForSession(DebugTargetIdentity expected,
                               uint32_t expectedTid,
                               uint64_t runtimeContinuation,
                               uint64_t requestToken,
                               std::string* error = nullptr);
    bool runToCursorForSession(DebugTargetIdentity expected, uint64_t va);

    // Execution coverage. The supplied basic-block starts are planted as an
    // invisible, bounded set of one-shot internal software breakpoints by the
    // debug-event thread. Calls return immediately; snapshots are thread-safe.
    void startTraceCoverage(const std::vector<uint64_t>& basicBlockStarts,
                            size_t maxSites = 65536);
    bool startTraceCoverageForSession(DebugTargetIdentity expected,
                                      const std::vector<uint64_t>& basicBlockStarts,
                                      size_t maxSites = 65536);
    void stopTraceCoverage();
    bool stopTraceCoverageForSession(DebugTargetIdentity expected);
    void clearTraceCoverage();
    bool clearTraceCoverageForSession(DebugTargetIdentity expected);
    TraceCoverageSnapshot traceCoverageSnapshot() const;

    // ---- authorization / remembered-access observation --------------------
    // Plans use main-image RVAs and are bound atomically to a PID + debugger
    // session generation. Attached starts reject stale identities. The optional
    // launch plan is prepared before CreateProcess and planted at the
    // CREATE_PROCESS_DEBUG_EVENT, before TLS callbacks or the PE entry execute.
    bool startAuthorizationWatch(
        const AuthorizationWatchPlan& plan, DebugTargetIdentity expected,
        const AuthorizationWatchOptions& options = {}, std::string* error = nullptr);
    void stopAuthorizationWatch();
    void clearAuthorizationWatch();
    AuthorizationWatchSnapshot authorizationWatchSnapshot();

    // Pick which thread the snapshot's registers/stack follow (while paused).
    void setActiveThread(uint32_t tid);
    bool setActiveThreadForSession(DebugTargetIdentity expected, uint32_t tid);

    // Write the active thread's general-purpose registers (valid only while
    // Paused). Get-modify-Set preserves the unmodeled context (segment/FP/debug).
    // Returns false if not paused / no active thread. `setRegister` patches one
    // GP register by lowercase name (e.g. "rax", "rip", "rflags").
    bool setRegisters(const Registers& r);
    bool setRegister(const std::string& name, uint64_t value);
    // Identity-atomic register edit for UI state captured from one debugger
    // frame. PID/generation validation, paused-state validation, thread-handle
    // selection, context write, and snapshot publication share one mtx_ lock.
    // The editor supplies both optional guards; they reject a draft after an
    // active-thread or paused-RIP change, including a valid RIP of zero.
    bool setRegisterForSession(uint32_t expectedPid,
                               uint64_t expectedSessionGeneration,
                               const std::string& name, uint64_t value,
                               uint32_t expectedTid = 0,
                               const uint64_t* expectedRip = nullptr);

    // Capture RIP/RAX and its EAX/AL aliases only while the exact target and
    // active thread remain paused.  This is intentionally narrower than the
    // general snapshot(): a successful result is suitable as one observation
    // for AuthorizationExperiment without inferring validity from zero values.
    bool readPausedRegistersForSession(DebugTargetIdentity expected,
                                       uint32_t expectedTid,
                                       PausedRegisterSnapshot& out,
                                       std::string* error = nullptr);

    // Transactional accumulator edit for a live authorization experiment.
    // Before writing, re-read the real paused context and require both RIP and
    // the masked prior accumulator value to match the inert write proposal.
    // The write is read back and returned as one coherent alias snapshot.  A
    // failed verification attempts to restore the complete original context;
    // when a final context can still be read, `observed` is populated even on
    // false so the caller can retain recovery for a mutation that stuck.
    bool setAccumulatorForSessionVerified(
        DebugTargetIdentity expected,
        uint32_t expectedTid,
        uint64_t expectedRip,
        uint64_t expectedAccumulator,
        uint64_t accumulatorCompareMask,
        uint64_t value,
        PausedRegisterSnapshot& observed,
        std::string* error = nullptr);
    // Allocate a non-executable target buffer, copy `bytes`, and point one data
    // GPR at it. The complete operation is valid only for the exact paused
    // PID/session/thread captured by the register editor. Successful buffers
    // become target-owned: a live detach deliberately leaves them mapped because
    // the debuggee may have retained the pointer; process termination reclaims
    // them, and explicit freeRemote/freeAllRemote remains available while paused.
    // A supplied expectedRip is checked before target allocation or mutation.
    bool setRegisterToBufferForSession(uint32_t expectedPid,
                                       uint64_t expectedSessionGeneration,
                                       uint32_t expectedTid,
                                       const std::string& name,
                                       const std::vector<uint8_t>& bytes,
                                       uint64_t& remoteAddress,
                                       std::string* error = nullptr,
                                       const uint64_t* expectedRip = nullptr);

    // Freeze / thaw a single thread (Suspend/ResumeThread). Frozen threads stay
    // stopped across continues until thawed; all are auto-thawed on detach.
    void suspendThread(uint32_t tid);
    void resumeThread(uint32_t tid);
    bool suspendThreadForSession(DebugTargetIdentity expected, uint32_t tid);
    bool resumeThreadForSession(DebugTargetIdentity expected, uint32_t tid);
    bool isThreadSuspended(uint32_t tid);

    // Software breakpoint management (thread-safe). An optional condition
    // expression (see Cond.h) is evaluated on hit; the debuggee only stops if
    // it is true (or empty).
    bool addBreakpoint(uint64_t va, const std::string& condition = "");
    bool removeBreakpoint(uint64_t va);
    bool addBreakpointForSession(DebugTargetIdentity expected, uint64_t va,
                                 const std::string& condition = "");
    bool removeBreakpointForSession(DebugTargetIdentity expected, uint64_t va);
    bool hasBreakpoint(uint64_t va);
    // Returns false without queuing any change when `condition` is malformed or
    // names a register the breakpoint evaluator cannot resolve. Empty remains a
    // valid unconditional condition.
    bool setBreakpointCondition(uint64_t va, const std::string& condition);
    bool setBreakpointConditionForSession(DebugTargetIdentity expected, uint64_t va,
                                          const std::string& condition);
    // Break only on every Nth (condition-true) hit; 0/1 = every hit. Evaluated
    // next to the condition in the int3 handler; persisted with the breakpoint.
    void setBreakpointEveryN(uint64_t va, uint32_t n);
    bool setBreakpointEveryNForSession(DebugTargetIdentity expected, uint64_t va,
                                       uint32_t n);

    // ---- JVM-aware debugging (Java EXEs) ----
    // Arm a one-shot break on jvm.dll!JNI_CreateJavaVM when the VM module loads.
    // Must be set BEFORE the JVM loads (i.e. before launch) to take effect.
    void setBreakOnJvmInit(bool on)     { breakOnJvmInit_ = on; }
    bool breakOnJvmInit() const         { return breakOnJvmInit_.load(); }

    // ---- first-chance exception filter ----
    // Default off: first-chance exceptions pass straight to the debuggee (the
    // JVM-internal ones are additionally counted, not shown). When enabled (or
    // for codes on the whitelist), the debugger pauses on first chance instead.
    void setBreakOnFirstChance(bool on) { breakOnFirstChance_ = on; }
    bool breakOnFirstChanceEnabled() const { return breakOnFirstChance_.load(); }
    void addFirstChanceCode(uint32_t code);
    void removeFirstChanceCode(uint32_t code);
    std::vector<uint32_t> firstChanceCodes();

    // Clear the captured OutputDebugString ring (Debug Output tab's Clear).
    void clearDebugOutput();

    // ---- guided live network observation -----------------------------------
    // Internal probes follow Winsock resolution/connect/send/recv plus bounded
    // WinHTTP/WinINet handle lineage. They are not exposed as user breakpoints;
    // an analyst breakpoint at the same address retains visible-stop priority.
    // Events and coverage are tagged with the debugger session generation.
    void startNetworkObservation();
    void stopNetworkObservation();
    NetworkObservation networkObservationSnapshot();
    NetworkProbeCoverage networkProbeCoverage();
    void clearNetworkObservation();

    // Compatibility toggle name retained for the existing Connections tab.
    void enableNetTap(bool on);
    bool netTapEnabled() const { return networkObservationWant_.load(); }
    // Accept an asynchronous open request. Check netCaptureLogStatus() for
    // completion/errors; all file operations are owned by the bounded writer.
    bool setNetCaptureLogFile(const std::string& utf8Path, bool append, std::string* err = nullptr);
    void closeNetCaptureLogFile();
    NetCaptureLogStatus netCaptureLogStatus();
    bool netCaptureLogEnabled();
    std::string netCaptureLogPath();

    // Hardware breakpoint management (DR0-DR3; up to 4). Execute kind uses a
    // 1-byte length. Returns false if all 4 slots are in use (on add).
    bool addHardwareBreakpoint(uint64_t va, HwKind kind = HwKind::Execute, uint8_t size = 1);
    bool removeHardwareBreakpoint(uint64_t va);
    bool addHardwareBreakpointForSession(DebugTargetIdentity expected, uint64_t va,
                                         HwKind kind = HwKind::Execute, uint8_t size = 1);
    bool removeHardwareBreakpointForSession(DebugTargetIdentity expected, uint64_t va);
    bool hasHardwareBreakpoint(uint64_t va);

    // ---- opt-in anti-anti-debug policy ----
    // Configuration is intentionally session-atomic: set it while detached, then
    // attach/launch.  Every field defaults off.  Detach restores pristine memory
    // fields and trap bytes.  The capability report explicitly separates what the
    // Win32 event loop can cover from guarantees that require the Hv backend.
    bool setAntiDebugPolicy(const AntiDebugPolicy& policy, std::string* error = nullptr);
    AntiDebugPolicy antiDebugPolicy();
    AntiDebugCapabilityReport antiDebugCapabilityReport();

    // Read / write debuggee memory (valid while attached).
    size_t readMemory(uint64_t va, void* out, size_t n);
    // Identity-checked counterpart for addresses owned by a scan/table from a
    // captured target. The handle remains selected and locked through the read.
    size_t readMemoryForSession(uint32_t expectedPid,
                                uint64_t expectedSessionGeneration,
                                uint64_t va, void* out, size_t n);
    // Like readMemory but substitutes our own 0xCC software-breakpoint bytes back to
    // the saved originals (mirrors decodeAt), so the live view / analysis decode the
    // real instructions instead of int3. Use this for any live disassembly/string read.
    size_t readMemoryMasked(uint64_t va, void* out, size_t n);
    // Same breakpoint-masked read, but fail closed if PID/session changes at
    // either the remote read or mask-application boundary.
    size_t readMemoryMaskedForSession(uint32_t expectedPid,
                                      uint64_t expectedSessionGeneration,
                                      uint64_t va, void* out, size_t n);
    size_t writeMemory(uint64_t va, const void* in, size_t n);
    // Writes only when the currently published process handle still belongs to
    // the caller's exact debugger session. Identity selection, validation, and
    // WriteProcessMemory are one hProcMtx_ critical section, closing the
    // snapshot-check / detach / reattach race for target-owned UI state.
    size_t writeMemoryForSession(uint32_t expectedPid,
                                 uint64_t expectedSessionGeneration,
                                 uint64_t va, const void* in, size_t n,
                                 bool allowProtectionChange = true);
    // Queue a bounded set under one target-identity observation and wake the
    // running debuggee only once. Each span still uses the normal transactional
    // read/write/verify/rollback and breakpoint-byte preservation path. The
    // returned vector mirrors `writes`; each element is bytes committed or 0.
    std::vector<size_t> writeMemoryBatchForSession(
        uint32_t expectedPid, uint64_t expectedSessionGeneration,
        const std::vector<MemoryWriteSpan>& writes);

    // Briefly suspend live threads to sample their contexts while the debuggee is
    // running. The singular form samples the active/display thread first; the
    // plural form returns a bounded active-first set. Paused sessions return their
    // already-coherent active-thread snapshot.
    bool sampleExecutionContext(Registers& out);
    std::vector<Registers> sampleExecutionContexts(size_t maxThreads = 32);

    // Snapshot of committed memory regions (VirtualQueryEx walk).
    std::vector<MemRegion> regions();
    // Identity-checked counterpart for scan jobs whose region map belongs to a
    // captured debugger session. Selection, identity validation, and the
    // VirtualQueryEx walk share hProcMtx_, so a detach/reattach cannot relabel a
    // new target's address space with an old scan generation.
    std::vector<MemRegion> regionsForSession(uint32_t expectedPid,
                                             uint64_t expectedSessionGeneration);
    // Focused live-module snapshot for long-lived memory-table resolution.
    // Unlike a render-frame snapshot, callers can refresh it on a background
    // freeze tick and fail closed after detach/reattach.
    std::vector<DbgModule> modulesForSession(uint32_t expectedPid,
                                             uint64_t expectedSessionGeneration);

    // Allocate executable (RWX) memory in the debuggee for F2 live hot-patch detours
    // when no on-image code cave fits. These explicit mutations require Paused;
    // tracked regions are also released by stopped-session detach cleanup.
    uint64_t allocRemote(size_t n);
    void     freeRemote(uint64_t addr);
    void     freeAllRemote();

    // Whole-process state snapshot / restore for F3 in-emulator path re-seeding: capture
    // the active thread's registers + committed readable regions (each up to perRegionCap
    // bytes), then restore them to rewind the process to that point. restore only while
    // Paused. Best-effort (skips unreadable pages); writeMemory handles RO->RW toggling.
    struct MemSnapshot {
        Registers regs;
        struct Block { uint64_t base = 0; std::vector<uint8_t> bytes; };
        std::vector<Block> blocks;
    };
    bool takeSnapshot(MemSnapshot& out, size_t perRegionCap = (1u << 20));
    bool restoreSnapshot(const MemSnapshot& snap);

    // A transient borrowed debuggee HANDLE, or null. Callers that retain or use
    // it outside one atomic observation must use duplicateProcessHandleForSession(); the
    // debug thread may otherwise close and the OS may recycle the raw value.
    void* processHandle() const { return hProcessShared_.load(); }
    // Returns an owned DuplicateHandle copy only when the currently published
    // process still belongs to `expected`, or null otherwise. Identity checking
    // and duplication share hProcMtx_, so a frame snapshot cannot accidentally
    // acquire a reattached target's handle and label it with the old generation.
    // The caller closes the returned handle.
    void* duplicateProcessHandleForSession(DebugTargetIdentity expected);
    uint64_t processCreationTimeForSession(DebugTargetIdentity expected);

    DbgSnapshot snapshot();

    // Built-in GML connection. File verification/extraction runs on a worker;
    // bootstrap, hooks, stop authentication and writes belong to the event loop.
    bool connectGameMaker(std::shared_ptr<const GameMakerArchive> archive,
        const std::string& archivePath, uint64_t archiveHash,
        const std::vector<GmlSavedBreakpoint>& breakpoints, std::string& error);
    GameMakerSessionSnapshot gameMakerSnapshot();
    bool setGameMakerBreakpoints(uint64_t archiveHash,
        const std::vector<GmlSavedBreakpoint>& breakpoints, std::string& error);
    bool gameMakerCommand(GmlControlCommand command, GmlPauseIdentity expected,
        std::string& error);
    bool editGameMakerNumeric(GmlPauseIdentity expected, uint64_t snapshotRevision, uint32_t slotIndex,
        std::string value, std::string& error);
    bool inspectGameMakerInstance(GmlPauseIdentity expected, uint32_t objectIndex,
        uint64_t instanceId, std::string& error);
    void disconnectGameMaker();

private:
    enum class Cmd {
        None,
        ServiceWrites, // wake the paused debug thread without resuming its held event
        GmlResume,
        Continue,
        StepInto,
        StepOver,
        StepOut,
        RunTo,
        Detach,
    };

    struct CommandEnvelope {
        Cmd      command = Cmd::None;
        uint64_t argument = 0;
        uint64_t epoch = 0;
        // Non-zero only for an exact-thread checked run-to request. Ordinary
        // execution controls continue to resolve the currently displayed
        // thread when the debug thread consumes them.
        uint32_t ownerTid = 0;
        // Non-zero only for the Authorization Trail checked RunTo API. It is
        // copied into the temp-breakpoint owner and its typed snapshot status.
        uint64_t checkedRunToToken = 0;
    };

    // UI-originated target writes are immutable, epoch-tagged jobs. Only the
    // debug-event thread performs Read/WriteProcessMemory, while it owns a
    // stopped debug event. The per-request condition variable gives callers a
    // bounded synchronous API without exposing a borrowed process HANDLE.
    struct MemoryWriteRequest {
        uint64_t epoch = 0;
        DebugTargetIdentity identity{};
        DbgState submittedState = DbgState::Detached;
        uint64_t address = 0;
        std::vector<uint8_t> bytes;
        bool allowProtectionChange = true;

        std::mutex completionMtx;
        std::condition_variable completionCv;
        bool cancelRequested = false;
        bool done = false;
        size_t result = 0;
    };

    void   threadEntry(uint32_t pid, bool launch, std::wstring applicationPath,
                       std::wstring commandLine, bool breakAtEntry,
                       std::optional<DllDebugLaunchPlan> dllPlan,
                       bool containedJob, uint64_t controlEpoch) noexcept;
    void   threadMain(uint32_t pid, bool launch, std::wstring applicationPath,
                      std::wstring commandLine, bool breakAtEntry,
                      std::optional<DllDebugLaunchPlan> dllPlan,
                      bool containedJob, uint64_t controlEpoch);
    void   emergencyThreadCleanup(const std::string& reason) noexcept;
    uint64_t beginSessionControl();
    bool   waitForStartup(std::string& err);
    void   lifecycleWorkerLoop();
    void   captureContext(uint32_t tid);
    void   applyContext(uint32_t tid);
    CommandEnvelope waitForCommand(uint64_t controlEpoch); // blocks until an epoch-valid UI command
    void   postCommand(Cmd c, uint64_t argument = 0);
    bool   postCommandForSession(Cmd c, uint64_t argument,
                                 DebugTargetIdentity expected);
    void   requestTraceSyncBreak(DebugTargetIdentity expected = {});
    void   refreshThreadList();           // debug thread: rebuild thread list + rips
    void   unwindStack(uint32_t tid);     // debug thread: DbgHelp StackWalk64 -> frames_
    bool   evalConditionFor(uint64_t addr, uint32_t tid); // debug thread

    bool   writeByte(uint64_t va, uint8_t b, uint8_t* prev);
    size_t writeMemoryOwned(std::optional<DebugTargetIdentity> expected,
                            uint64_t va, const void* in, size_t n,
                            bool allowProtectionChange = true);
    void   servicePendingWrites(uint64_t controlEpoch); // debug-event thread only
    void   performMemoryWrite(const std::shared_ptr<MemoryWriteRequest>& request,
                              uint64_t controlEpoch);    // completes request
    void   cancelPendingWritesLocked();                  // caller owns mtx_
    void   serviceGameMaker(bool eventHeld); // event owner; never waits for a target thread
    bool   acceptGameMakerException(uint32_t code, bool firstChance, uint32_t tid,
        uint32_t parameterCount, const uint64_t* parameters);
    bool   resumeGameMakerOwned(GmlControlCommand command);
    void   invalidateGameMakerPause();
    void   cleanupGameMakerOwned(bool alive);
    bool   gameMakerOwnsRangeLocked(uint64_t address, uint64_t size) const;
    bool   gameMakerBreakpointConflictLocked(uint64_t address, uint64_t size) const;
    void   transitionCheckedRunToLocked(CheckedRunToState state,
                                        std::string error = {});
    void   cancelCheckedRunToLocked(std::string error);
    bool   armBreakpoint(uint64_t va);
    bool   disarmBreakpoint(uint64_t va);
    bool   disarmAuthorizationBreakpoint(uint64_t va);
    bool   rearmAuthorizationBreakpoint(uint64_t va);
    bool   disarmAuthorizationReturn(uint64_t va);
    bool   rearmAuthorizationReturn(uint64_t va);
    bool   setTrapFlag(uint32_t tid, bool on);
    void   setResumeFlag(uint32_t tid);   // EFLAGS.RF, to step past a fault-class hw exec bp

    // Arch-aware thread-context access: native x64 CONTEXT for 64-bit targets, or
    // WOW64_CONTEXT (Wow64Get/SetThreadContext) for 32-bit (WOW64) targets. The
    // 32-bit registers are zero-extended into the low halves of the Registers fields
    // (Eip->rip, Esp->rsp, ..., Edi->rdi; r8-r15 stay 0), so the rest of the engine
    // and the UI keep working unchanged. hThread is a raw HANDLE.
    bool     ctxReadFull(void* hThread, Registers& out);
    bool     ctxWriteFull(void* hThread, const Registers& r);   // get-modify-set
    uint64_t ctxReadRip(void* hThread);
    void     ctxSetRip(void* hThread, uint64_t rip);

    // Decode just enough about the instruction at `va` to drive stepping
    // (length + call/ret/rep classification). Reads debuggee memory.
    struct StepDecode { uint32_t length = 1; bool isCall = false; bool isRet = false; bool isRepString = false; };
    StepDecode decodeAt(uint64_t va);

    // Hardware-breakpoint helpers (debug thread).
    bool   applyHwToThread(void* hThread);
    bool   applyHwAllThreads();
    bool   readDr6Clear(uint32_t tid, uint64_t& dr6);

    enum class AntiTrapKind : uint8_t {
        QueryProcess, QuerySystem, QueryThread, SetThread, CloseHandle,
        GetContext, SetContext, QueryPerformanceCounter, QuerySystemTime,
        Rdtsc, Rdtscp,
    };
    struct AntiTrap {
        uint8_t orig = 0;
        AntiTrapKind kind = AntiTrapKind::QueryProcess;
        uint8_t instructionLength = 1;
        uint64_t ownerImageBase = 0;
        uint64_t ownerImageSize = 0;
    };
    bool   installAntiTrap(uint64_t va, AntiTrapKind kind, uint8_t instructionLength,
                           uint64_t ownerImageBase, uint64_t ownerImageSize);
    bool   handleAntiTrap(uint64_t va, uint32_t tid);
    bool   normalizeAntiDebugEnvironment(bool deferHeapUnavailableWarning = false);
    bool   verifyAntiDebugSyntheticReturns();
    void   armAntiDebugForImage(uint64_t base, uint64_t size, bool mainImage,
                                const std::string& moduleName,
                                const std::string& modulePath,
                                bool modulePathTrusted);
    void   restoreAntiDebugState(bool targetAlive);
    void   retireAntiDebugImage(uint64_t imageBase);
    void   addAntiDebugWarning(std::string warning);
    uint64_t resolveMappedExport(uint64_t moduleBase, uint64_t moduleSize,
                                 const char* name);
    void   rebuildAntiTrapAddrs_() noexcept;

    // Private disassembler used only by the debug thread (instruction length /
    // call detection for step-over/out). Owning its own instance avoids sharing
    // the UI's engine across threads - Capstone's handle is not concurrency-safe.
    std::unique_ptr<IDisassembler> ownDis_;     // x64 length/flow decoder (native targets)
    std::unique_ptr<IDisassembler> ownDis32_;   // x86 length/flow decoder (WOW64 targets)
    std::atomic<bool>  isWow64_{false};         // target is a 32-bit (WOW64) process

    std::thread        thread_;
    // Serializes every synchronous lifecycle API and ownership of thread_. The
    // async worker uses those same APIs; nested detach during attach is valid.
    std::recursive_mutex lifecycleOwnerMtx_;
    std::mutex lifecycleMtx_;
    std::condition_variable lifecycleCv_;
    std::thread lifecycleThread_;
    DbgLifecycleSnapshot lifecycle_{};
    DebugTargetIdentity lifecycleExpected_{};
    uint64_t nextLifecycleRequest_ = 0;
    bool lifecycleQueued_ = false;
    bool lifecycleShutdown_ = false;
    std::atomic<bool> lifecycleCancel_{false};
    std::atomic<bool> lifecycleAttaching_{false};
    std::atomic<bool>  quit_{false};
    std::atomic<bool>  startupOk_{false};
    std::atomic<bool>  startupDone_{false};
    std::atomic<bool>  breakRequested_{false};   // UI pressed Pause -> break into user code
    std::atomic<bool>  traceSyncBreakRequested_{false}; // coalesced target-mutation DebugBreakProcess wake-up
    std::string        startupErr_;
    bool               initialProcessEventReady_ = false; // mtx_: bitness/main module published

    // Shared state (guarded by mtx_).
    std::mutex                       mtx_;
    std::condition_variable          cmdCv_;
    CommandEnvelope                  pendingCommand_{};
    uint64_t                         controlEpoch_ = 0; // invalidates commands/mutations at each session boundary
    std::deque<std::shared_ptr<MemoryWriteRequest>> pendingWrites_;
    std::shared_ptr<MemoryWriteRequest> activeWrite_;
    size_t                           pendingWriteBytes_ = 0;
    DbgState                         state_   = DbgState::Detached;
    uint32_t                         pid_ = 0, tid_ = 0;
    uint64_t                         sessionGeneration_ = 0;
    uint32_t                         activeTid_ = 0;
    Registers                        regs_;
    std::string                      lastEvent_ = "idle";
    std::shared_ptr<GameMakerSession> gmlSession_; // native fields used only on event thread
    GameMakerSessionSnapshot          gmlSnapshot_; // mtx_ protects publications and requests
    uint64_t                         gmlGeneration_ = 0;
    std::vector<std::pair<uint64_t, uint64_t>> gmlOwnedRanges_;
    CheckedRunToSnapshot             checkedRunTo_{};
    uint64_t                         checkedRunToRevision_ = 0;
    bool                             containedJob_ = false;
    std::vector<ThreadInfo>          threadList_;        // guarded snapshot for UI
    std::vector<std::pair<uint32_t, void*>> threadHandles_; // guarded tid -> HANDLE
    std::vector<CallStackFrame>      frames_;            // guarded: last StackWalk64 unwind
    std::unordered_set<uint32_t>     suspended_;         // user-frozen tids (guarded by mtx_)

    struct SwBp { uint8_t orig = 0; std::string cond; CondProgram prog;
                  uint32_t hits = 0, stops = 0;         // counters mutate under mtx_ (snapshot reads)
                  uint32_t everyN = 0;                  // stop on every Nth hit (0/1 = every)
                  bool     ownsByte = true;             // false when an anti-debug trap owns the shared int3
                  bool     armed = true;
                  std::string error; };
    std::unordered_map<uint64_t, SwBp> bps_;            // va -> {original byte, condition, compiled}
    // Bounded, oldest-first diagnostics only: failed installations never own a
    // byte, enter bpAddrs_, mask a read, or take priority over internal hooks.
    // Guarded by mtx_; exposed through the existing armed/error snapshot fields.
    static constexpr size_t kMaxFailedBreakpointInstalls = 4096;
    std::deque<SwBreakpointInfo> failedBpInstalls_;
    void clearBreakpointInstallFailureLocked(uint64_t va);
    // Maintained sorted vector of breakpoint addresses, mirroring bps_'s key set,
    // so readMemoryMasked can fix up its 0xCC bytes in O(log n) per read (binary
    // search of the read range) instead of scanning the whole map per byte. Kept in
    // sync wherever bps_ is mutated (debug thread) and snapshotted under mtx_.
    std::vector<uint64_t>            bpAddrs_;
    void   rebuildBpAddrs_();                            // refill bpAddrs_ from bps_ (under mtx_)
    struct PendingBp { uint64_t va; std::string cond; };
    std::vector<PendingBp>           pendingBpAdds_;
    std::vector<uint64_t>            pendingBpRems_;
    std::vector<PendingBp>           pendingBpConds_;    // condition updates
    std::vector<std::pair<uint64_t, uint32_t>> pendingBpEveryN_; // every-Nth-hit updates
    std::optional<uint64_t>         pausedUserBpAddr_; // physically restored while parked in the UI
    std::optional<uint64_t>         runtimeTempBpAddr_; // rejects live writes that would stale temp ownership

    // ---- invisible one-shot execution coverage breakpoints ----
    TraceCoverage                    traceCoverage_;
    struct TraceBp { uint8_t orig = 0; uint64_t generation = 0; };
    std::unordered_map<uint64_t, TraceBp> traceBps_;      // guarded by mtx_, not UI-visible bps_
    std::vector<uint64_t>            traceBpAddrs_;       // sorted mirror for readMemoryMasked
    bool                             pendingTraceStart_ = false;
    bool                             pendingTraceStop_ = false;

    // ---- repeatable authorization-watch probes ----------------------------
    AuthorizationWatch               authorizationWatch_;
    struct AuthorizationBp {
        uint8_t orig = 0;
        uint64_t generation = 0;
        CodeByteSignature signature;
        bool ownsByte = true;
        bool armed = true;
    };
    std::unordered_map<uint64_t, AuthorizationBp> authorizationBps_;
    std::vector<uint64_t>            authorizationBpAddrs_;
    struct AuthorizationReturnBp {
        uint8_t orig = 0;
        bool ownsByte = true;
        bool armed = true;
        bool sharedWithUserBreakpoint = false;
    };
    std::unordered_map<uint64_t, AuthorizationReturnBp> authorizationReturnBps_;
    std::vector<uint64_t>            authorizationReturnBpAddrs_;
    AuthorizationWatchReturnTracker  authorizationPendingReturns_; // debug thread only
    size_t                           authorizationPendingReturnCount_ = 0;
    uint64_t                         authorizationPendingReturnsDropped_ = 0;
    bool                             pendingAuthorizationStart_ = false;
    bool                             pendingAuthorizationStop_ = false;

    // ---- hosted-DLL one-shot target breakpoints ----
    // A target can share an existing user/temp byte. ownsByte records which
    // mechanism must restore the byte, preventing double-restores and stale 0xCC.
    struct DllTargetBp {
        uint8_t orig = 0;
        bool ownsByte = false;
        std::vector<std::string> labels;
    };
    std::unordered_map<uint64_t, DllTargetBp> dllTargetBps_; // guarded by mtx_
    std::vector<uint64_t>            dllTargetBpAddrs_;       // sorted mirror for masked reads
    bool                             dllHostedLaunch_ = false;
    bool                             dllTargetMatched_ = false;
    std::string                      dllTargetPath_;
    uint64_t                         dllTargetBase_ = 0;
    uint64_t                         dllTargetSize_ = 0;
    std::string                      dllTargetLabel_;
    std::string                      dllTargetError_;

    // ---- guided network observation (internal, never UI-visible breakpoints) -
    std::atomic<bool> networkObservationWant_{false};
    bool              netTapArmed_ = false;
    struct NetworkProbeBp {
        uint8_t orig = 0;
        NetworkProbeApi api = NetworkProbeApi::Unknown;
        uint64_t moduleBase = 0;
        bool ownsByte = true;
        bool armed = true;
    };
    struct NetworkReturnBp {
        uint8_t orig = 0;
        bool ownsByte = true;
        bool armed = true;
    };
    struct NetworkPendingFrame {
        uint64_t returnAddress = 0; // required by NetworkReturnTracker
        NetworkProbeApi api = NetworkProbeApi::Unknown;
        uint64_t caller = 0;
        uint64_t handle = 0;
        uint64_t parent = 0;
        uint64_t buffer = 0;
        uint64_t buffers = 0;
        uint64_t countOrLength = 0;
        uint64_t requestedLength = 0; // input/body bytes before the 64-KiB evidence cap
        bool requestedLengthValid = false;
        uint64_t transferredPtr = 0;
        uint64_t addressPtr = 0;
        uint64_t addressLengthPtr = 0;
        std::array<uint64_t, 9> args{};
        uint16_t port = 0;
        bool portValid = false;
        bool wide = false;
        bool async = false;
        bool payloadTruncated = false;
        std::string hostname;
        std::string ip;
        std::string endpoint;
        std::string method;
        std::string path;
        std::string object;
        std::string detail;
        std::vector<uint8_t> payload;
    };
    std::unordered_map<uint64_t, NetworkProbeBp> networkProbeBps_;
    std::vector<uint64_t> networkProbeBpAddrs_;
    std::unordered_map<uint64_t, NetworkReturnBp> networkReturnBps_;
    std::vector<uint64_t> networkReturnBpAddrs_;
    NetworkReturnTracker<NetworkPendingFrame> networkPendingReturns_;
    NetworkHandleLineage networkHandleLineage_;
    std::deque<NetworkObservationEvent> networkEvents_;
    NetworkProbeCoverage networkCoverage_;
    uint64_t networkEventSequence_ = 0;
    uint64_t networkPendingPayloadBytes_ = 0; // charged against the shared 32-MiB cap
    void   armNetTap();
    void   disarmNetTap();
    void   retireNetworkModule(uint64_t base, uint64_t size);
    void   netTapCapture(uint64_t addr, uint32_t tid, NetworkProbeApi api);
    bool   netTapOnReturn(uint64_t addr, uint32_t tid,
                          bool* transitionFailed = nullptr); // true when shared site still needs re-arm
    bool   disarmNetworkProbe(uint64_t addr);
    bool   rearmNetworkProbe(uint64_t addr);
    bool   rearmNetworkReturn(uint64_t addr);
    void   decorateNetworkEvent(NetworkObservationEvent& event);
    void   pushNetworkEvent(NetworkObservationEvent&& event);
    void   writeNetworkObservationLog(const NetworkObservationEvent& event);
    void   networkLogWorkerLoop();
    struct NetLogWork {
        enum class Kind { Open, Record, Close } kind = Kind::Record;
        std::string path;
        bool append = false;
        uint64_t generation = 0;
        uint64_t timestamp = 0; // UTC FILETIME captured at observation time
        size_t bytes = 0;
        NetworkObservationEvent event;
    };
    static constexpr size_t kNetLogQueueRecords = 256;
    static constexpr size_t kNetLogQueueBytes = 4 * 1024 * 1024;
    static constexpr size_t kNetLogQueueControls = 16;
    std::mutex                       netLogMtx_;
    std::condition_variable          netLogCv_;
    std::thread                      netLogThread_;
    std::deque<NetLogWork>            netLogQueue_;
    NetCaptureLogStatus              netLogStatus_;
    size_t                           netLogQueuedControls_ = 0;
    uint64_t                         netLogGeneration_ = 0;
    bool                             netLogShutdown_ = false;
    std::string                      netLogPath_;

    // ---- live module list (LOAD_DLL/UNLOAD_DLL), guarded by mtx_ ----
    std::vector<DbgModule>           dbgModules_;

    // ---- JVM awareness (published for the snapshot; jvm base/size live on the
    //      debug thread inside threadMain). Guarded by mtx_ unless atomic. ----
    std::atomic<bool>                breakOnJvmInit_{false};
    bool                             jvmLoaded_ = false;
    std::string                      jvmPath_;
    uint64_t                         jvmExceptionsPassed_ = 0;
    uint64_t                         exceptionSequence_ = 0;
    uint32_t                         exceptionCode_ = 0;
    uint64_t                         exceptionAddress_ = 0;
    bool                             exceptionFirstChance_ = false;

    // ---- first-chance exception filter (whitelist guarded by mtx_) ----
    std::atomic<bool>                breakOnFirstChance_{false};
    std::unordered_set<uint32_t>     fcWhitelist_;

    // ---- OutputDebugString capture (bounded ring, guarded by mtx_) ----
    std::deque<std::string>          dbgOutput_;

    // Hardware breakpoints: up to 4 slots (DR0-DR3).
    struct HwSlot { bool used = false; uint64_t addr = 0; HwKind kind = HwKind::Execute; uint8_t size = 1; };
    HwSlot                           hwSlots_[4];
    std::vector<HwSlot>              pendingHwAdds_;
    std::vector<uint64_t>            pendingHwRems_;

    // Hide-Debugger configuration (configured while detached) and per-session
    // runtime. antiTraps_/antiTrapAddrs_/stats are guarded by mtx_ because live
    // disassembly and snapshot() read them from the UI thread.
    AntiDebugPolicy                 antiDebugPolicy_{};
    AntiDebugPolicy                 activeAntiDebugPolicy_{}; // debug-thread session copy
    AntiDebugSessionStats           antiDebugStats_{};
    PristinePatchSet                antiDebugPatches_;
    SyntheticClock                  antiDebugClock_{};
    std::unordered_map<uint64_t, AntiTrap> antiTraps_;
    std::vector<uint64_t>            antiTrapAddrs_;
    size_t                           antiDebugRdtscBudgetRemaining_ = 0; // debug-thread only
    bool                             antiDebugCallHooksAllowed_ = true; // false when CET/unknown mitigation makes synthetic RET unsafe

    // Debug-thread-local handles (only touched on the debug thread).
    void*  hProcess_ = nullptr;                         // HANDLE
    bool   dbgHelpSessionInited_ = false;                // debug-thread-owned unwind session
    std::unordered_map<uint32_t, void*> threads_;       // tid -> HANDLE

    // Process handle shared with the UI thread for async-break (pause()).
    std::atomic<void*> hProcessShared_{nullptr};
    // Serializes use of hProcess_/hProcessShared_ by the UI thread
    // (pause/readMemory/writeMemory/regions) against the debug thread closing it at
    // teardown, closing the load-then-use TOCTOU window.
    std::mutex hProcMtx_;

    // VAs of VirtualAllocEx regions created by the debugger. Executable F2
    // detours are freed during a stopped detach; successful register text
    // buffers are filtered out because a live target may retain their pointer.
    // All local tracking is cleared at the session boundary. Guarded by hProcMtx_.
    std::vector<uint64_t> remoteAllocs_;
    // PAGE_READWRITE allocations created by setRegisterToBufferForSession.  This
    // subset bounds repeated text-pointer edits without constraining F2 detours.
    std::unordered_set<uint64_t> remoteRegisterBuffers_;
    // Identity of hProcessShared_. Published and cleared in the same
    // hProcMtx_ critical section as that handle. Never infer this from a later
    // snapshot: a detach/reattach can occur between the two observations.
    DebugTargetIdentity hProcessIdentity_{};
};

} // namespace ds
