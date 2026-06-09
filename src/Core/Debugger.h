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
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "Cond.h"   // CondProgram (pre-compiled breakpoint conditions)

namespace ds {

class IDisassembler;

enum class DbgState { Detached, Running, Paused, Terminated };

struct Registers {
    uint64_t rip = 0, rsp = 0, rbp = 0, rflags = 0;
    uint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0, rsi = 0, rdi = 0;
    uint64_t r8 = 0, r9 = 0, r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, r15 = 0;
};

enum class HwKind { Execute, Write, ReadWrite };

struct MemRegion {
    uint64_t base = 0, size = 0;
    uint32_t protect = 0, state = 0, type = 0;
    bool     read = false, write = false, exec = false;
};

struct ThreadInfo {
    uint32_t tid = 0;
    uint64_t rip = 0;
    bool     suspended = false;   // user-frozen via suspendThread()
};

struct SwBreakpointInfo {
    uint64_t    address = 0;
    std::string condition;   // empty = unconditional
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

struct DbgSnapshot {
    DbgState                 state = DbgState::Detached;
    uint32_t                 pid = 0, tid = 0;     // tid = active/displayed thread
    Registers                regs;
    std::string              lastEvent = "idle";
    std::vector<SwBreakpointInfo> breakpoints;     // software (0xCC), with conditions
    std::vector<HwBreakpointInfo> hwBreakpoints;   // DR0-DR3 (address + kind + size)
    std::vector<ThreadInfo>  threads;
    std::vector<CallStackFrame> frames;             // real StackWalk64 unwind of the active thread
    uint32_t                 activeTid = 0;
    bool                     is32 = false;          // target is a 32-bit (WOW64) process
    bool                     attached() const { return state != DbgState::Detached; }
};

class Debugger {
public:
    Debugger();
    ~Debugger();

    bool attach(uint32_t pid, std::string& err);

    // Launch a new process under the debugger (CreateProcess with DEBUG flags) and
    // begin a debug session. With breakAtEntry, the session pauses at the program's
    // entry point (a one-shot breakpoint past the loader breakpoint) so you can
    // debug from the first instruction. exePath is a UTF-8 filesystem path.
    bool launchAndAttach(const std::string& exePath, std::string& err, bool breakAtEntry = true);

    void detach();

    // Execution control (posted to the debug thread; return immediately).
    void cont();
    void stepInto();
    void stepOver();
    void stepOut();
    void pause();   // best-effort async break
    void runToCursor(uint64_t va);   // one-shot temp breakpoint, then continue

    // Pick which thread the snapshot's registers/stack follow (while paused).
    void setActiveThread(uint32_t tid);

    // Write the active thread's general-purpose registers (valid only while
    // Paused). Get-modify-Set preserves the unmodeled context (segment/FP/debug).
    // Returns false if not paused / no active thread. `setRegister` patches one
    // GP register by lowercase name (e.g. "rax", "rip", "rflags").
    bool setRegisters(const Registers& r);
    bool setRegister(const std::string& name, uint64_t value);

    // Freeze / thaw a single thread (Suspend/ResumeThread). Frozen threads stay
    // stopped across continues until thawed; all are auto-thawed on detach.
    void suspendThread(uint32_t tid);
    void resumeThread(uint32_t tid);
    bool isThreadSuspended(uint32_t tid);

    // Software breakpoint management (thread-safe). An optional condition
    // expression (see Cond.h) is evaluated on hit; the debuggee only stops if
    // it is true (or empty).
    bool addBreakpoint(uint64_t va, const std::string& condition = "");
    bool removeBreakpoint(uint64_t va);
    bool hasBreakpoint(uint64_t va);
    void setBreakpointCondition(uint64_t va, const std::string& condition);

    // Hardware breakpoint management (DR0-DR3; up to 4). Execute kind uses a
    // 1-byte length. Returns false if all 4 slots are in use (on add).
    bool addHardwareBreakpoint(uint64_t va, HwKind kind = HwKind::Execute, uint8_t size = 1);
    bool removeHardwareBreakpoint(uint64_t va);
    bool hasHardwareBreakpoint(uint64_t va);

    // Read / write debuggee memory (valid while attached).
    size_t readMemory(uint64_t va, void* out, size_t n);
    // Like readMemory but substitutes our own 0xCC software-breakpoint bytes back to
    // the saved originals (mirrors decodeAt), so the live view / analysis decode the
    // real instructions instead of int3. Use this for any live disassembly/string read.
    size_t readMemoryMasked(uint64_t va, void* out, size_t n);
    size_t writeMemory(uint64_t va, const void* in, size_t n);

    // Snapshot of committed memory regions (VirtualQueryEx walk).
    std::vector<MemRegion> regions();

    // Allocate executable (RWX) memory in the debuggee for F2 live hot-patch detours
    // when no on-image code cave fits. Returns the base VA, or 0 on failure. Tracked
    // and released on detach (also via freeRemote). Thread-safe (hProcMtx_).
    uint64_t allocRemote(size_t n);
    void     freeRemote(uint64_t addr);
    void     freeAllRemote();   // release every tracked allocation (called on detach)

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

    // The debuggee process HANDLE (for DbgHelp symbol resolution), or null.
    void* processHandle() const { return hProcessShared_.load(); }

    DbgSnapshot snapshot();

private:
    enum class Cmd { None, Continue, StepInto, StepOver, StepOut, RunTo, Detach };

    void   threadMain(uint32_t pid, bool launch, std::wstring launchPath, bool breakAtEntry);
    void   captureContext(uint32_t tid);
    void   applyContext(uint32_t tid);
    Cmd    waitForCommand();              // blocks debug thread until UI posts
    void   postCommand(Cmd c);
    void   refreshThreadList();           // debug thread: rebuild thread list + rips
    void   unwindStack(uint32_t tid);     // debug thread: DbgHelp StackWalk64 -> frames_
    bool   evalConditionFor(uint64_t addr, uint32_t tid); // debug thread

    bool   writeByte(uint64_t va, uint8_t b, uint8_t* prev);
    void   armBreakpoint(uint64_t va);
    void   disarmBreakpoint(uint64_t va);
    void   setTrapFlag(uint32_t tid, bool on);
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
    void   applyHwToThread(void* hThread);
    void   applyHwAllThreads();
    bool   readDr6Clear(uint32_t tid, uint64_t& dr6);

    // Private disassembler used only by the debug thread (instruction length /
    // call detection for step-over/out). Owning its own instance avoids sharing
    // the UI's engine across threads - Capstone's handle is not concurrency-safe.
    std::unique_ptr<IDisassembler> ownDis_;     // x64 length/flow decoder (native targets)
    std::unique_ptr<IDisassembler> ownDis32_;   // x86 length/flow decoder (WOW64 targets)
    std::atomic<bool>  isWow64_{false};         // target is a 32-bit (WOW64) process

    std::thread        thread_;
    std::atomic<bool>  quit_{false};
    std::atomic<bool>  startupOk_{false};
    std::atomic<bool>  startupDone_{false};
    std::atomic<bool>  breakRequested_{false};   // UI pressed Pause -> break into user code
    std::string        startupErr_;

    // Shared state (guarded by mtx_).
    std::mutex                       mtx_;
    std::condition_variable          cmdCv_;
    Cmd                              pending_ = Cmd::None;
    uint64_t                         cmdArg_  = 0;       // e.g. run-to-cursor target
    DbgState                         state_   = DbgState::Detached;
    uint32_t                         pid_ = 0, tid_ = 0;
    uint32_t                         activeTid_ = 0;
    Registers                        regs_;
    std::string                      lastEvent_ = "idle";
    std::vector<ThreadInfo>          threadList_;        // guarded snapshot for UI
    std::vector<std::pair<uint32_t, void*>> threadHandles_; // guarded tid -> HANDLE
    std::vector<CallStackFrame>      frames_;            // guarded: last StackWalk64 unwind
    std::unordered_set<uint32_t>     suspended_;         // user-frozen tids (guarded by mtx_)

    struct SwBp { uint8_t orig = 0; std::string cond; CondProgram prog; };
    std::unordered_map<uint64_t, SwBp> bps_;            // va -> {original byte, condition, compiled}
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

    // Hardware breakpoints: up to 4 slots (DR0-DR3).
    struct HwSlot { bool used = false; uint64_t addr = 0; HwKind kind = HwKind::Execute; uint8_t size = 1; };
    HwSlot                           hwSlots_[4];
    std::vector<HwSlot>              pendingHwAdds_;
    std::vector<uint64_t>            pendingHwRems_;

    // Debug-thread-local handles (only touched on the debug thread).
    void*  hProcess_ = nullptr;                         // HANDLE
    std::unordered_map<uint32_t, void*> threads_;       // tid -> HANDLE

    // Process handle shared with the UI thread for async-break (pause()).
    std::atomic<void*> hProcessShared_{nullptr};
    // Serializes use of hProcess_/hProcessShared_ by the UI thread
    // (pause/readMemory/writeMemory/regions) against the debug thread closing it at
    // teardown, closing the load-then-use TOCTOU window.
    std::mutex hProcMtx_;

    // VAs of VirtualAllocEx regions created via allocRemote (F2 detours); freed on
    // detach. Guarded by hProcMtx_.
    std::vector<uint64_t> remoteAllocs_;
};

} // namespace ds
