#include "PrismSampler.h"
#include "DbgHelpLock.h"

#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>

#include <array>
#include <cstdio>
#include <exception>

#pragma comment(lib, "dbghelp.lib")

namespace ds {

namespace {

// A sampled thread must always be resumed, including if symbol/vector allocation
// throws while its stack is being copied. Resume before taking the samples mutex so
// a large UI snapshot never prolongs the target's suspension.
struct SuspendedThread {
    HANDLE handle = nullptr;
    bool suspended = false;

    ~SuspendedThread() { resumeAndClose(); }

    void resumeAndClose() {
        if (handle && suspended) ResumeThread(handle);
        if (handle) CloseHandle(handle);
        handle = nullptr;
        suspended = false;
    }
};

// Resolve an instruction pointer to "module!function" (caller MUST hold DbgHelpMutex).
void symbolize(HANDLE hProc, uint64_t pc, std::string& out) {
    std::string mod, fn;

    IMAGEHLP_MODULE64 mi{};
    mi.SizeOfStruct = sizeof(mi);
    if (SymGetModuleInfo64(hProc, pc, &mi) && mi.ModuleName[0]) mod = mi.ModuleName;

    ULONG64 buf[(sizeof(SYMBOL_INFO) + 256 + sizeof(ULONG64) - 1) / sizeof(ULONG64)] = { 0 };
    SYMBOL_INFO* si = reinterpret_cast<SYMBOL_INFO*>(buf);
    si->SizeOfStruct = sizeof(SYMBOL_INFO);
    si->MaxNameLen   = 255;
    DWORD64 disp = 0;
    if (SymFromAddr(hProc, pc, &disp, si) && si->NameLen)
        fn.assign(si->Name, si->NameLen < si->MaxNameLen ? si->NameLen : si->MaxNameLen);

    char addr[24];
    std::snprintf(addr, sizeof(addr), "0x%llX", (unsigned long long)pc);
    if (!mod.empty() && !fn.empty()) out = mod + "!" + fn;
    else if (!mod.empty())           out = mod + "!" + addr;
    else if (!fn.empty())            out = fn;
    else                             out = addr;
}

} // namespace

PrismSampler::~PrismSampler() { stop(); }

bool PrismSampler::start(uint32_t pid, std::string& err) {
    if (running_.load()) { err = "sampler already running"; return false; }

    // A worker that stopped by itself (target exit / sample cap) is still joinable.
    // Reap it before assigning a new std::thread; assigning over a joinable thread
    // calls std::terminate.
    if (thread_.joinable()) stop();

    {
        std::lock_guard<std::mutex> lk(mtx_);
        error_.clear();
    }

    // Suspending another thread in this process while it owns DbgHelpMutex (or the
    // samples mutex) can deadlock the sampler before it gets a chance to resume it.
    if (pid == GetCurrentProcessId()) {
        err = "profiling DisasmStudio itself is disabled (self-sampling can deadlock while threads are suspended)";
        return false;
    }

    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE, FALSE, pid);
    if (!h) { err = "OpenProcess failed (elevation / architecture mismatch?)"; return false; }

    // x64 walk only for now: reject 32-bit (WOW64) targets rather than mis-walk them.
    BOOL wow = FALSE;
    if (IsWow64Process(h, &wow) && wow) {
        CloseHandle(h);
        err = "32-bit (WOW64) targets are not supported yet — x64 processes only";
        return false;
    }

    // A successfully validated new target starts a fresh rolling window. Keep the
    // old deque movable so even the rare std::thread construction failure can put
    // the previous report back without a deep copy.
    std::deque<PrismSample> previousSamples;
    const uint32_t previousPid = pid_;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        previousSamples.swap(samples_);
    }
    generation_.fetch_add(1, std::memory_order_release);
    lastCycles_.clear();

    hProc_ = h;
    pid_   = pid;
    stop_.store(false);
    running_.store(true);
    try {
        thread_ = std::thread([this] { run(); });
    } catch (const std::exception& e) {
        running_.store(false);
        CloseHandle(h);
        hProc_ = nullptr;
        pid_ = previousPid;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            samples_.swap(previousSamples);
        }
        generation_.fetch_add(1, std::memory_order_release);
        err = std::string("failed to start sampler thread: ") + e.what();
        return false;
    }
    return true;
}

void PrismSampler::stop() {
    stop_.store(true);
    if (thread_.joinable()) thread_.join();
    if (hProc_) { CloseHandle((HANDLE)hProc_); hProc_ = nullptr; }
    running_.store(false);
}

std::vector<PrismSample> PrismSampler::snapshot() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return { samples_.begin(), samples_.end() };
}

size_t PrismSampler::sampleCount() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return samples_.size();
}

void PrismSampler::clearSamples() {
    std::lock_guard<std::mutex> lk(mtx_);
    samples_.clear();
    generation_.fetch_add(1, std::memory_order_release);
}

std::string PrismSampler::lastError() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return error_;
}

void PrismSampler::run() {
    HANDLE hProc = (HANDLE)hProc_;
    bool symbolsReady = false;
    DWORD symbolError = ERROR_SUCCESS;
    {
        std::lock_guard<std::recursive_mutex> lk(DbgHelpMutex());
        SymSetOptions(SymGetOptions() | SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME);
        symbolsReady = SymInitialize(hProc, nullptr, TRUE) != FALSE; // invade target modules
        if (!symbolsReady) symbolError = GetLastError();
    }
    if (!symbolsReady) {
        char msg[96];
        std::snprintf(msg, sizeof(msg), "DbgHelp symbol initialization failed (Win32 error %lu)",
                      (unsigned long)symbolError);
        {
            std::lock_guard<std::mutex> lk(mtx_);
            error_ = msg;
        }
        running_.store(false);
        return;
    }

    uint64_t nextModuleRefresh = 0;
    while (!stop_.load()) {
        if (WaitForSingleObject(hProc, 0) == WAIT_OBJECT_0) break; // target exited
        const uint64_t now = GetTickCount64();
        if (now >= nextModuleRefresh) {
            std::lock_guard<std::recursive_mutex> lk(DbgHelpMutex());
            SymRefreshModuleList(hProc); // refresh modules and x64 unwind tables
            nextModuleRefresh = now + 1000;
        }
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te{};
            te.dwSize = sizeof(te);
            if (Thread32First(snap, &te)) {
                do {
                    if (te.th32OwnerProcessID == pid_) sampleThread(hProc, te.th32ThreadID);
                } while (!stop_.load() && Thread32Next(snap, &te));
            }
            CloseHandle(snap);
        }
        Sleep(1);   // ~coarse tick (no timeBeginPeriod) — light overhead
    }

    if (symbolsReady) {
        std::lock_guard<std::recursive_mutex> lk(DbgHelpMutex());
        SymCleanup(hProc);
    }
    running_.store(false);
}

void PrismSampler::sampleThread(void* hProcV, uint32_t tid) {
    HANDLE hProc = (HANDLE)hProcV;
    // Never suspend our own sampler/render threads if the user points Prism at us.
    if (pid_ == GetCurrentProcessId() && tid == GetCurrentThreadId()) return;

    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME,
                                FALSE, tid);
    if (!hThread) return;
    SuspendedThread held{ hThread, false };

    PrismSample s;
    s.threadId = tid;
    s.timeMs   = GetTickCount64();   // over-time timeline uses this

    ULONG64 cyclesNow = 0;
    if (QueryThreadCycleTime(hThread, &cyclesNow)) {
        auto [it, inserted] = lastCycles_.emplace(tid, (uint64_t)cyclesNow);
        if (!inserted) {
            if ((uint64_t)cyclesNow >= it->second) s.cpuCycles = (uint64_t)cyclesNow - it->second;
            it->second = (uint64_t)cyclesNow;
        }
    }

    // Wait for DbgHelp before suspending the target. Keep only fixed-size PCs while
    // suspended, resume immediately after the walk, then symbolize (which may load
    // PDBs) with the target running again.
    std::array<uint64_t, 64> pcs{};
    size_t pcCount = 0;
    {
        std::lock_guard<std::recursive_mutex> lk(DbgHelpMutex());
        if (SuspendThread(hThread) == (DWORD)-1) return;
        held.suspended = true;

        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_FULL;
        if (GetThreadContext(hThread, &ctx)) {
            STACKFRAME64 sf{};
            sf.AddrPC.Offset    = ctx.Rip; sf.AddrPC.Mode    = AddrModeFlat;
            sf.AddrFrame.Offset = ctx.Rbp; sf.AddrFrame.Mode = AddrModeFlat;
            sf.AddrStack.Offset = ctx.Rsp; sf.AddrStack.Mode = AddrModeFlat;

            // The captured RIP is the actual leaf even when the first unwind fails.
            if (ctx.Rip) pcs[pcCount++] = ctx.Rip;
            for (size_t n = 0; n + 1 < pcs.size(); ++n) {
                if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, hProc, hThread, &sf, &ctx,
                                 /*ReadMemory*/ nullptr,
                                 SymFunctionTableAccess64, SymGetModuleBase64, nullptr))
                    break;
                uint64_t pc = sf.AddrPC.Offset;
                if (!pc) break;
                if (!pcCount || pc != pcs[pcCount - 1]) pcs[pcCount++] = pc;
                if (n > 0 && sf.AddrReturn.Offset == sf.AddrPC.Offset && !sf.AddrFrame.Offset) break;
                if (pcCount >= pcs.size()) break;
            }
        }

        held.resumeAndClose();
        s.frames.reserve(pcCount);
        for (size_t i = 0; i < pcCount; ++i) {
            PrismFrame f;
            f.address = pcs[i];
            symbolize(hProc, pcs[i], f.symbol);
            s.frames.push_back(std::move(f));
        }
    }

    if (!s.frames.empty()) {
        std::lock_guard<std::mutex> lk(mtx_);
        if (samples_.size() >= kMaxSamples) samples_.pop_front();
        samples_.push_back(std::move(s));
        generation_.fetch_add(1, std::memory_order_release);
    }
}

} // namespace ds
