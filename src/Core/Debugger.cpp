#include "Debugger.h"
#include "NetworkApiCatalog.h"
#include "Cond.h"
#include "DbgHelpLock.h"      // serialize DbgHelp against the UI thread's SymbolResolver
#include "ExcName.h"          // semantic exception-code names for lastEvent_
#include "JvmAware.h"         // JVM module detection / JNI_CreateJavaVM resolution
#include "RegisterEdit.h"     // text-pointer register edit policy / byte cap
#include "StepLogic.h"
#include "../Disasm/IDisassembler.h"
#include "../Disasm/ZydisDisassembler.h"

#include <windows.h>
#include <dbghelp.h>          // StackWalk64 + Sym* callbacks for real call-stack unwinding
#include <tlhelp32.h>         // authoritative target heap-list provenance

#include <algorithm>          // std::sort / std::lower_bound (breakpoint-address cache)
#include <cctype>
#include <chrono>
#include <cwctype>
#include <cstdio>
#include <cstring>
#include <exception>
#include <iterator>
#include <limits>
#include <intrin.h>

#pragma comment(lib, "dbghelp.lib")

namespace ds {

static constexpr uint32_t TRAP_FLAG = 0x100;
static constexpr size_t   kStepOutCap = 500000; // safety cap for depth stepping
static constexpr size_t   kMaxDbgModules = 2048;   // live-module list bound
static constexpr size_t   kDbgOutputCap  = 1000;   // OutputDebugString ring bound
static constexpr size_t   kDbgOutputLine = 8192;   // per-message read cap (bytes)
static constexpr size_t   kAntiDebugRdtscSessionBudget = 250000;
static constexpr size_t   kAntiDebugRdtscPerImageBudget = 50000;
static constexpr uint64_t kAntiDebugMaxRunIntervalSeconds = 24ull * 60 * 60;
static constexpr auto     kDebuggerStartupTimeout = std::chrono::seconds(30);
static constexpr auto     kMemoryWriteTimeout = std::chrono::seconds(10);
static constexpr size_t   kMaxMemoryWriteBytes = 16u * 1024u * 1024u;
static constexpr size_t   kMaxPendingMemoryWriteBytes = 32u * 1024u * 1024u;
static constexpr size_t   kMaxPendingMemoryWrites = 64;
static constexpr size_t   kMaxRemoteRegisterBuffers = 256;

static bool readByteRPM(HANDLE h, uint64_t va, uint8_t& b);
static bool writeByteRPM(HANDLE h, uint64_t va, uint8_t b);
static bool replaceByteIfEqual(HANDLE h, uint64_t va, uint8_t expected, uint8_t replacement);
static bool readRemoteExact(HANDLE h, uint64_t va, void* out, size_t size);

static AttachedFileIdentity attachedFileIdentity(HANDLE file) {
    AttachedFileIdentity identity;
    if (!file || file == INVALID_HANDLE_VALUE) return identity;
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(file, &info)) return identity;
    identity.valid = true;
    identity.volumeSerial = info.dwVolumeSerialNumber;
    identity.fileIndex = (static_cast<uint64_t>(info.nFileIndexHigh) << 32) |
                         info.nFileIndexLow;
    identity.fileSize = (static_cast<uint64_t>(info.nFileSizeHigh) << 32) |
                        info.nFileSizeLow;
    identity.lastWriteTime =
        (static_cast<uint64_t>(info.ftLastWriteTime.dwHighDateTime) << 32) |
        info.ftLastWriteTime.dwLowDateTime;
    return identity;
}

static std::wstring widenUtf8(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n > 0 ? n : 0, L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), n);
    return w;
}

// lpApplicationName removes executable-search ambiguity, but the debuggee still
// receives argv[0] from lpCommandLine. Keep that token intact when the path has
// spaces. A Windows filesystem path cannot contain a quote, so this is sufficient
// for the single argv[0] token used by the normal executable-launch path.
static std::wstring quotedArgv0(const std::wstring& path) {
    if (path.empty()) return {};
    return L"\"" + path + L"\"";
}

// Use the executable's directory as the normal launch working directory when it
// names a real directory. This avoids inheriting DisasmStudio's own cwd without
// changing hosted-DLL plans, whose pre-built command line may intentionally rely
// on the caller's environment.
static std::wstring executableDirectory(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"/\\");
    if (slash == std::wstring::npos) return {};

    std::wstring directory = slash == 0 ? path.substr(0, 1)
                                         : path.substr(0, slash);
    // Preserve the separator for drive roots, including extended paths such as
    // \\?\C:\app.exe; bare "C:" has drive-relative semantics on Windows.
    if (!directory.empty() && directory.back() == L':') directory.push_back(path[slash]);

    const DWORD attrs = GetFileAttributesW(directory.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_DIRECTORY)) return {};
    return directory;
}

static std::wstring normalizedWindowsPath(const std::string& utf8Path) {
    std::wstring path = widenUtf8(utf8Path);
    if (path.empty()) return {};
    std::vector<wchar_t> full(32768, L'\0');
    const DWORD n = GetFullPathNameW(path.c_str(), static_cast<DWORD>(full.size()),
                                     full.data(), nullptr);
    if (n > 0 && n < full.size()) path.assign(full.data(), n);
    if (path.rfind(L"\\\\?\\", 0) == 0) path.erase(0, 4);
    std::replace(path.begin(), path.end(), L'/', L'\\');
    std::transform(path.begin(), path.end(), path.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(std::towlower(c));
    });
    return path;
}

static bool sameWindowsPath(const std::string& a, const std::string& b) {
    const std::wstring left = normalizedWindowsPath(a);
    const std::wstring right = normalizedWindowsPath(b);
    return !left.empty() && !right.empty() && left == right;
}

static bool isTrustedSystemNtdllPath(const std::string& utf8Path, bool wow64Target) {
    if (utf8Path.empty()) return false;
    wchar_t systemDir[1024]{};
    UINT count = wow64Target
               ? GetSystemWow64DirectoryW(systemDir, static_cast<UINT>(std::size(systemDir)))
               : GetSystemDirectoryW(systemDir, static_cast<UINT>(std::size(systemDir)));
    if (!count || count >= std::size(systemDir)) return false;
    std::wstring expected(systemDir, count);
    if (!expected.empty() && expected.back() != L'\\' && expected.back() != L'/') expected.push_back(L'\\');
    expected += L"ntdll.dll";
    std::wstring actual = widenUtf8(utf8Path);
    if (actual.rfind(L"\\\\?\\", 0) == 0) actual.erase(0, 4);
    auto normalize = [](std::wstring& value) {
        std::replace(value.begin(), value.end(), L'/', L'\\');
        std::transform(value.begin(), value.end(), value.begin(),
                       [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    };
    normalize(actual);
    normalize(expected);
    return actual == expected;
}

static SyntheticClockConfig productionSyntheticClockConfig() {
    SyntheticClockConfig config;
    LARGE_INTEGER qpc{}, frequency{};
    if (QueryPerformanceCounter(&qpc)) config.qpcStart = static_cast<uint64_t>(qpc.QuadPart);
    if (QueryPerformanceFrequency(&frequency) && frequency.QuadPart > 0)
        config.qpcFrequency = static_cast<uint64_t>(frequency.QuadPart);
    // The run-interval accountant supplies real elapsed time. Keep only a small
    // monotonic call-cost here so tight query loops are not inflated by 100 us
    // per interception.
    config.qpcQuantum = (std::max)(uint64_t{1}, config.qpcFrequency / 1000000u); // ~1 us

    FILETIME fileTime{};
    GetSystemTimeAsFileTime(&fileTime);
    config.systemTimeStart100ns = (uint64_t{fileTime.dwHighDateTime} << 32) |
                                  fileTime.dwLowDateTime;
    config.tscStart = __rdtsc();
    config.rdtscpAux = GetCurrentProcessorNumber();

    uint64_t tscFrequency = 0;
    int cpu[4]{};
    __cpuid(cpu, 0);
    const int maxLeaf = cpu[0];
    if (maxLeaf >= 0x15) {
        __cpuid(cpu, 0x15);
        const uint32_t denominator = static_cast<uint32_t>(cpu[0]);
        const uint32_t numerator = static_cast<uint32_t>(cpu[1]);
        const uint32_t crystalHz = static_cast<uint32_t>(cpu[2]);
        if (denominator && numerator && crystalHz)
            tscFrequency = (uint64_t{crystalHz} * numerator) / denominator;
    }
    if (!tscFrequency && maxLeaf >= 0x16) {
        __cpuid(cpu, 0x16);
        const uint32_t baseMHz = static_cast<uint32_t>(cpu[0]);
        if (baseMHz) tscFrequency = uint64_t{baseMHz} * 1000000u;
    }
    if (!tscFrequency) tscFrequency = 3000000000ULL; // disclosed best-effort fallback
    const long double tscStep = static_cast<long double>(config.qpcQuantum) *
                                static_cast<long double>(tscFrequency) /
                                static_cast<long double>(config.qpcFrequency);
    config.tscQuantum = tscStep >= static_cast<long double>(UINT64_MAX)
                      ? UINT64_MAX
                      : (std::max)(uint64_t{1}, static_cast<uint64_t>(tscStep));
    return config;
}

static void writePrintablePayload(std::FILE* f, const std::vector<uint8_t>& bytes) {
    for (uint8_t b : bytes) {
        if (b == '\r' || b == '\n' || b == '\t') std::fputc((int)b, f);
        else if (b >= 0x20 && b < 0x7F)          std::fputc((int)b, f);
        else                                     std::fputc('.', f);
    }
    if (bytes.empty() || bytes.back() != '\n') std::fputc('\n', f);
}

static void writeHexPayload(std::FILE* f, const std::vector<uint8_t>& bytes) {
    for (size_t off = 0; off < bytes.size(); off += 16) {
        std::fprintf(f, "%08zX  ", off);
        char ascii[17] = {};
        for (size_t i = 0; i < 16; ++i) {
            if (off + i < bytes.size()) {
                uint8_t b = bytes[off + i];
                std::fprintf(f, "%02X ", b);
                ascii[i] = (b >= 0x20 && b < 0x7F) ? (char)b : '.';
            } else {
                std::fputs("   ", f);
                ascii[i] = ' ';
            }
            if (i == 7) std::fputc(' ', f);
        }
        ascii[16] = '\0';
        std::fprintf(f, " %s\n", ascii);
    }
}

// In a 32-bit (WOW64) target, int3 / single-step in the 32-bit code are reported as
// these WX86 status codes, not the usual EXCEPTION_BREAKPOINT / EXCEPTION_SINGLE_STEP.
static constexpr uint32_t kStatusWx86Breakpoint = 0x4000001FUL;
static constexpr uint32_t kStatusWx86SingleStep = 0x4000001EUL;

// The debugger handles both native 64-bit and 32-bit (WOW64) targets: it reads the
// x64 CONTEXT or the WOW64_CONTEXT as appropriate (see isWow64_ / the ctx* helpers).
// Two private step decoders measure instruction lengths and spot calls - x64 for
// native targets, x86 for WOW64 - independent of whichever engine the UI is showing.
Debugger::Debugger()
    : ownDis_(std::make_unique<ZydisDisassembler>(Arch::X64)),
      ownDis32_(std::make_unique<ZydisDisassembler>(Arch::X86)) {
    lifecycleThread_ = std::thread([this] { lifecycleWorkerLoop(); });
    try {
        netLogThread_ = std::thread([this] { networkLogWorkerLoop(); });
    } catch (...) {
        { std::lock_guard lock(lifecycleMtx_); lifecycleShutdown_ = true; }
        lifecycleCv_.notify_one();
        lifecycleThread_.join();
        throw;
    }
}
Debugger::~Debugger() {
    {
        std::lock_guard lock(lifecycleMtx_);
        lifecycleShutdown_ = true;
        lifecycleQueued_ = false;
        lifecycleCancel_.store(true);
    }
    lifecycleCv_.notify_all();
    cmdCv_.notify_all();
    if (lifecycleThread_.joinable()) lifecycleThread_.join();
    detach();
    { std::lock_guard lock(netLogMtx_); netLogShutdown_ = true; }
    netLogCv_.notify_one();
    if (netLogThread_.joinable()) netLogThread_.join();
}

uint64_t Debugger::requestAttach(uint32_t pid) {
    if (!pid) return 0;
    std::lock_guard lock(lifecycleMtx_);
    if (lifecycleShutdown_ || lifecycle_.busy) return 0;
    lifecycle_ = {};
    lifecycle_.requestId = ++nextLifecycleRequest_;
    if (!lifecycle_.requestId) lifecycle_.requestId = ++nextLifecycleRequest_;
    lifecycle_.requestedPid = pid;
    lifecycle_.command = DbgLifecycleCommand::Attach;
    lifecycle_.state = DbgLifecycleState::Starting;
    lifecycle_.busy = true;
    lifecycleExpected_ = {};
    lifecycleCancel_.store(false);
    lifecycleQueued_ = true;
    lifecycleCv_.notify_one();
    return lifecycle_.requestId;
}

uint64_t Debugger::requestDetach(DebugTargetIdentity expected) {
    std::lock_guard lock(lifecycleMtx_);
    if (lifecycleShutdown_ || lifecycle_.busy) return 0;
    if (expected.valid()) {
        std::lock_guard sessionLock(mtx_);
        if (state_ == DbgState::Detached ||
            !DebugTargetIdentityMatches({pid_, sessionGeneration_}, expected))
            return 0;
    }
    lifecycle_ = {};
    lifecycle_.requestId = ++nextLifecycleRequest_;
    if (!lifecycle_.requestId) lifecycle_.requestId = ++nextLifecycleRequest_;
    lifecycle_.command = DbgLifecycleCommand::Detach;
    lifecycle_.state = DbgLifecycleState::Stopping;
    lifecycle_.busy = true;
    lifecycleExpected_ = expected;
    lifecycleCancel_.store(false);
    lifecycleQueued_ = true;
    lifecycleCv_.notify_one();
    return lifecycle_.requestId;
}

bool Debugger::cancelLifecycle(uint64_t requestId) {
    std::lock_guard lock(lifecycleMtx_);
    // Detach cleanup must finish restoring target-owned state; cancellation is
    // only meaningful while starting an attachment.
    if (!requestId || requestId != lifecycle_.requestId || !lifecycle_.busy ||
        lifecycle_.command != DbgLifecycleCommand::Attach) return false;
    lifecycleCancel_.store(true);
    lifecycle_.state = DbgLifecycleState::Stopping;
    cmdCv_.notify_all();
    return true;
}

DbgLifecycleSnapshot Debugger::lifecycleSnapshot() {
    std::lock_guard lock(lifecycleMtx_);
    auto result = lifecycle_;
    if (!result.busy) {
        std::lock_guard sessionLock(mtx_);
        if (state_ == DbgState::Paused) result.state = DbgLifecycleState::Paused;
        else if (state_ == DbgState::Running) result.state = DbgLifecycleState::Attached;
        else if (result.state != DbgLifecycleState::Failed) result.state = DbgLifecycleState::Detached;
    }
    return result;
}

void Debugger::lifecycleWorkerLoop() {
    for (;;) {
        DbgLifecycleSnapshot request;
        DebugTargetIdentity expected;
        {
            std::unique_lock lock(lifecycleMtx_);
            lifecycleCv_.wait(lock, [this] { return lifecycleShutdown_ || lifecycleQueued_; });
            if (lifecycleShutdown_) return;
            request = lifecycle_;
            expected = lifecycleExpected_;
            lifecycleQueued_ = false;
        }
        bool succeeded = false;
        std::string error;
        DebugTargetIdentity target;
        std::lock_guard ownerLock(lifecycleOwnerMtx_);
        try {
            if (request.command == DbgLifecycleCommand::Attach) {
                lifecycleAttaching_.store(true);
                const bool attemptedAttach = !lifecycleCancel_.load();
                if (attemptedAttach) succeeded = attach(request.requestedPid, error);
                // Cancellation also covers the race after Win32 succeeded but
                // before completion publication. Only the owner performs cleanup.
                if (lifecycleCancel_.load()) {
                    // A queued request cancelled before it acquires ownership
                    // never tears down an existing unrelated attachment.
                    if (attemptedAttach) detach();
                    succeeded = false;
                    error = "attachment cancelled";
                }
                if (succeeded) {
                    std::lock_guard sessionLock(mtx_);
                    target = {pid_, sessionGeneration_};
                }
                lifecycleAttaching_.store(false);
            } else {
                succeeded = expected.valid() ? detachForSession(expected) : (detach(), true);
                if (!succeeded) error = "the debugger session changed before detach";
            }
        } catch (const std::exception& e) {
            error = std::string("debugger lifecycle failed: ") + e.what();
            lifecycleAttaching_.store(false);
        } catch (...) {
            error = "debugger lifecycle failed";
            lifecycleAttaching_.store(false);
        }
        std::unique_lock lock(lifecycleMtx_);
        if (succeeded && request.command == DbgLifecycleCommand::Attach &&
            lifecycleCancel_.load()) {
            // Commit and cancellation share this lock. Keep the operation busy
            // while cleanup runs, but release it so UI polling never waits on IO.
            lock.unlock();
            detach();
            succeeded = false;
            target = {};
            error = "attachment cancelled";
            lock.lock();
        }
        lifecycle_.busy = false;
        lifecycle_.completed = true;
        lifecycle_.succeeded = succeeded;
        lifecycle_.cancelled = lifecycleCancel_.load() &&
            request.command == DbgLifecycleCommand::Attach;
        lifecycle_.error = std::move(error);
        lifecycle_.target = target;
        lifecycle_.state = succeeded ? (request.command == DbgLifecycleCommand::Attach
            ? DbgLifecycleState::Attached : DbgLifecycleState::Detached)
            : lifecycle_.cancelled ? DbgLifecycleState::Detached : DbgLifecycleState::Failed;
    }
}

// ---- UI-thread API ----------------------------------------------------------

void Debugger::cancelPendingWritesLocked() {
    for (const auto& request : pendingWrites_) {
        {
            std::lock_guard<std::mutex> completionLock(request->completionMtx);
            request->cancelRequested = true;
            request->result = 0;
            request->done = true;
        }
        request->completionCv.notify_all();
    }
    pendingWrites_.clear();
    pendingWriteBytes_ = 0;

    // An active request is already owned by the debug thread. Mark it for a
    // verified rollback; that thread publishes completion after the target is
    // back in its pre-request state (or surfaces a restoration failure).
    if (activeWrite_) {
        std::lock_guard<std::mutex> completionLock(activeWrite_->completionMtx);
        activeWrite_->cancelRequested = true;
    }
}

void Debugger::transitionCheckedRunToLocked(CheckedRunToState state,
                                             std::string error) {
    if (++checkedRunToRevision_ == 0) ++checkedRunToRevision_;
    checkedRunTo_.state = state;
    checkedRunTo_.revision = checkedRunToRevision_;
    checkedRunTo_.error = std::move(error);
}

void Debugger::cancelCheckedRunToLocked(std::string error) {
    if (checkedRunTo_.state != CheckedRunToState::Pending &&
        checkedRunTo_.state != CheckedRunToState::Armed)
        return;
    if (error.empty()) error = "the checked RunTo request was abandoned";
    transitionCheckedRunToLocked(CheckedRunToState::Cancelled,
                                 std::move(error));
}

uint64_t Debugger::beginSessionControl() {
    std::lock_guard<std::mutex> lk(mtx_);
    cancelCheckedRunToLocked(
        "the debugger session changed before the checked RunTo request fired");
    ++controlEpoch_;
    if (!controlEpoch_) ++controlEpoch_;
    pendingCommand_ = {};
    gmlSession_.reset();
    gmlSnapshot_ = {};
    gmlOwnedRanges_.clear();
    cancelPendingWritesLocked();
    activeWrite_.reset();
    pendingBpAdds_.clear();
    failedBpInstalls_.clear();
    pendingBpRems_.clear();
    pendingBpConds_.clear();
    pendingBpEveryN_.clear();
    pendingHwAdds_.clear();
    pendingHwRems_.clear();
    pausedUserBpAddr_.reset();
    runtimeTempBpAddr_.reset();
    startupErr_.clear();
    quit_ = false;
    startupOk_ = false;
    startupDone_ = false;
    initialProcessEventReady_ = false;
    breakRequested_ = false;
    traceSyncBreakRequested_ = false;
    return controlEpoch_;
}

bool Debugger::waitForStartup(std::string& err) {
    bool timedOut = false;
    bool cancelled = false;
    {
        std::unique_lock<std::mutex> lk(mtx_);
        if (!cmdCv_.wait_for(lk, kDebuggerStartupTimeout,
                             [this] { return (startupDone_.load() &&
                                 (!startupOk_.load() || !lifecycleAttaching_.load() ||
                                  initialProcessEventReady_ || state_ == DbgState::Terminated)) ||
                                 (lifecycleAttaching_.load() && lifecycleCancel_.load()); })) {
            timedOut = true;
            startupErr_ = "debugger startup timed out after 30 seconds";
        }
        cancelled = lifecycleAttaching_.load() && lifecycleCancel_.load();
        if (!timedOut && !cancelled && lifecycleAttaching_.load() &&
            startupOk_.load() && !initialProcessEventReady_) {
            startupOk_ = false;
            startupErr_ = "the target ended before debugger initialization completed";
        }
        if (timedOut || cancelled) {
            if (cancelled) startupErr_ = "attachment cancelled";
            startupOk_ = false;
            startupDone_ = true;
            quit_ = true;
            pendingCommand_ = { Cmd::Detach, 0, controlEpoch_ };
        }
        err = startupErr_;
        if (!timedOut && !cancelled && startupOk_) return true;
    }

    cmdCv_.notify_all();
    if ((timedOut || cancelled) && thread_.joinable()) {
        // All startup operations are synchronous Win32 calls. Ask Windows to
        // cancel any cancellable call and wake a target that was attached just
        // before the timeout so the worker can reach its cleanup boundary.
        CancelSynchronousIo(thread_.native_handle());
        requestTraceSyncBreak();
    }
    if (thread_.joinable()) thread_.join();
    return false;
}

bool Debugger::attach(uint32_t pid, std::string& err) {
    std::unique_lock ownerLock(lifecycleOwnerMtx_, std::try_to_lock);
    if (!ownerLock.owns_lock()) { err = "debugger lifecycle is busy"; return false; }
    {
        std::lock_guard lock(lifecycleMtx_);
        if (lifecycle_.busy && std::this_thread::get_id() != lifecycleThread_.get_id()) {
            err = "debugger lifecycle is busy";
            return false;
        }
    }
    detach();
    const uint64_t controlEpoch = beginSessionControl();
    try {
        thread_ = std::thread([this, pid, controlEpoch] {
            threadEntry(pid, /*launch=*/false, std::wstring(), std::wstring(),
                        /*breakAtEntry=*/false, std::nullopt, /*containedJob=*/false,
                        controlEpoch);
        });
    } catch (const std::exception& e) {
        err = std::string("could not start debugger worker: ") + e.what();
        return false;
    }
    return waitForStartup(err);
}

bool Debugger::launchAndAttach(const std::string& exePath, std::string& err,
                               bool breakAtEntry, bool containedJob,
                               const AuthorizationWatchPlan* authorizationPlan,
                               AuthorizationWatchOptions authorizationOptions,
                               bool prelaunchNetworkObservation) {
    std::unique_lock ownerLock(lifecycleOwnerMtx_, std::try_to_lock);
    if (!ownerLock.owns_lock()) { err = "debugger lifecycle is busy"; return false; }
    {
        std::lock_guard lock(lifecycleMtx_);
        if (lifecycle_.busy) { err = "debugger lifecycle is busy"; return false; }
    }
    // UTF-8 path -> UTF-16 for CreateProcessW.
    std::wstring wpath;
    if (!exePath.empty()) {
        int n = MultiByteToWideChar(CP_UTF8, 0, exePath.c_str(), (int)exePath.size(), nullptr, 0);
        wpath.resize(n > 0 ? n : 0);
        if (n > 0) MultiByteToWideChar(CP_UTF8, 0, exePath.c_str(), (int)exePath.size(), wpath.data(), n);
    }
    if (wpath.empty()) { err = "no binary path to launch"; return false; }
    if (authorizationPlan) {
        if (authorizationPlan->sites.empty()) {
            err = "authorization watch plan has no sites";
            return false;
        }
        if (!authorizationPlan->imagePath.empty() &&
            !sameWindowsPath(authorizationPlan->imagePath, exePath)) {
            err = "authorization watch plan belongs to a different executable";
            return false;
        }
        if (!CompleteAuthorizationWatchSourceEvidence(
                authorizationPlan->launchSource)) {
            err = "authorization watch plan has no complete retained source-file evidence";
            return false;
        }
    }

    // Invalid authorization evidence must not tear down an unrelated live
    // debugger session. Once every launch input is complete, establish the new
    // session and retain the plan before the worker can receive CREATE_PROCESS.
    detach();
    const uint64_t controlEpoch = beginSessionControl();
    if (authorizationPlan) {
        authorizationWatch_.prepare(*authorizationPlan, authorizationOptions);
        std::lock_guard<std::mutex> lk(mtx_);
        pendingAuthorizationStop_ = false;
        pendingAuthorizationStart_ = true;
    }
    // Publish the optional Server Watch request before the worker starts. Its
    // first CREATE_PROCESS/LOAD_DLL events can then arm every available module
    // export before that event is continued into startup code.
    networkObservationWant_.store(prelaunchNetworkObservation);
    const std::wstring commandLine = quotedArgv0(wpath);
    try {
        thread_ = std::thread([this, wpath, commandLine, breakAtEntry, containedJob, controlEpoch] {
            threadEntry(0, /*launch=*/true, wpath, commandLine, breakAtEntry, std::nullopt,
                        containedJob, controlEpoch);
        });
    } catch (const std::exception& e) {
        networkObservationWant_.store(false);
        authorizationWatch_.reset();
        { std::lock_guard<std::mutex> lk(mtx_);
          pendingAuthorizationStart_ = pendingAuthorizationStop_ = false; }
        err = std::string("could not start debugger worker: ") + e.what();
        return false;
    }
    const bool started = waitForStartup(err);
    if (!started) {
        networkObservationWant_.store(false);
        if (authorizationPlan) {
            authorizationWatch_.reset();
            std::lock_guard<std::mutex> lk(mtx_);
            pendingAuthorizationStart_ = pendingAuthorizationStop_ = false;
        }
    }
    return started;
}

bool Debugger::launchAndAttachDll(const DllDebugLaunchPlan& plan, std::string& err) {
    std::unique_lock ownerLock(lifecycleOwnerMtx_, std::try_to_lock);
    if (!ownerLock.owns_lock()) { err = "debugger lifecycle is busy"; return false; }
    {
        std::lock_guard lock(lifecycleMtx_);
        if (lifecycle_.busy) { err = "debugger lifecycle is busy"; return false; }
    }
    detach();
    if (!plan.valid) {
        err = plan.errors.empty() ? "invalid DLL debug launch plan" : plan.errors.front();
        return false;
    }
    const std::wstring applicationPath = widenUtf8(plan.executable);
    const std::wstring commandLine = widenUtf8(plan.commandLine);
    if (applicationPath.empty() || commandLine.empty()) {
        err = "DLL debug plan has no executable or command line";
        return false;
    }

    const uint64_t controlEpoch = beginSessionControl();
    try {
        thread_ = std::thread([this, applicationPath, commandLine, plan, controlEpoch] {
            threadEntry(0, /*launch=*/true, applicationPath, commandLine,
                        /*breakAtEntry=*/false, plan, /*containedJob=*/false,
                        controlEpoch);
        });
    } catch (const std::exception& e) {
        err = std::string("could not start debugger worker: ") + e.what();
        return false;
    }
    return waitForStartup(err);
}

void Debugger::detach() {
    std::lock_guard ownerLock(lifecycleOwnerMtx_);
    // Observation is session-scoped. Never carry an old opt-in into a later
    // attach, even when detach is called while no worker is running.
    networkObservationWant_.store(false);
    {
        std::lock_guard<std::mutex> lk(mtx_);
        cancelPendingWritesLocked();
        cancelCheckedRunToLocked(
            "the debugger detached before the checked RunTo request fired");
    }
    if (!thread_.joinable()) {
        traceCoverage_.reset();
        authorizationWatch_.reset();
        closeNetCaptureLogFile();
    } else {
        // If the process is running, acquire a real debug event before teardown.
        // threadMain keeps that event outstanding while it restores debugger-owned
        // bytes and DR state, so cleanup never races executing target threads.
        requestTraceSyncBreak();
        quit_ = true;
        postCommand(Cmd::Detach);
        thread_.join();
        closeNetCaptureLogFile();
    }
    std::lock_guard<std::mutex> lk(mtx_);
    ++controlEpoch_;                 // invalidate every command from the old owner
    if (!controlEpoch_) ++controlEpoch_;
    pendingCommand_ = {};
    cancelPendingWritesLocked();
    activeWrite_.reset();
    state_ = DbgState::Detached;
    bps_.clear();
    failedBpInstalls_.clear();
    bpAddrs_.clear();
    pendingBpAdds_.clear();
    pendingBpRems_.clear();
    pendingBpConds_.clear();
    pendingBpEveryN_.clear();
    pendingHwAdds_.clear();
    pendingHwRems_.clear();
    pausedUserBpAddr_.reset();
    runtimeTempBpAddr_.reset();
    traceBps_.clear();
    traceBpAddrs_.clear();
    pendingTraceStart_ = pendingTraceStop_ = false;
    traceCoverage_.reset();
    authorizationBps_.clear();
    authorizationBpAddrs_.clear();
    authorizationReturnBps_.clear();
    authorizationReturnBpAddrs_.clear();
    authorizationPendingReturns_.clear();
    authorizationPendingReturnCount_ = 0;
    authorizationPendingReturnsDropped_ = 0;
    pendingAuthorizationStart_ = pendingAuthorizationStop_ = false;
    authorizationWatch_.reset();
    dllTargetBps_.clear();
    dllTargetBpAddrs_.clear();
    dllHostedLaunch_ = false;
    dllTargetMatched_ = false;
    dllTargetPath_.clear();
    dllTargetBase_ = dllTargetSize_ = 0;
    dllTargetLabel_.clear();
    dllTargetError_.clear();
    networkProbeBps_.clear();
    networkProbeBpAddrs_.clear();
    networkReturnBps_.clear();
    networkReturnBpAddrs_.clear();
    networkPendingReturns_.clear();
    networkHandleLineage_.clear();
    networkEvents_.clear();
    networkCoverage_ = {};
    networkEventSequence_ = 0;
    networkPendingPayloadBytes_ = 0;
    netTapArmed_ = false;
    threadList_.clear();
    threadHandles_.clear();
    frames_.clear();
    suspended_.clear();
    dbgModules_.clear();
    dbgOutput_.clear();
    jvmLoaded_ = false;
    jvmPath_.clear();
    jvmExceptionsPassed_ = 0;
    exceptionSequence_ = 0;
    exceptionCode_ = 0;
    exceptionAddress_ = 0;
    exceptionFirstChance_ = false;
    activeTid_ = 0;
    containedJob_ = false;
    isWow64_.store(false);
}

bool Debugger::detachForSession(DebugTargetIdentity expected) {
    std::unique_lock ownerLock(lifecycleOwnerMtx_, std::try_to_lock);
    if (!ownerLock.owns_lock()) return false;
    if (!expected.valid()) return false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (state_ == DbgState::Detached ||
            !DebugTargetIdentityMatches({ pid_, sessionGeneration_ }, expected))
            return false;
    }
    // UI lifecycle calls are serialized. The identity check prevents a retained
    // control (for example Ctrl+K) from detaching a later session.
    detach();
    return true;
}

void Debugger::postCommand(Cmd c, uint64_t argument) {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (c != Cmd::Detach && state_ != DbgState::Paused) return;
        if (pendingCommand_.checkedRunToToken)
            cancelCheckedRunToLocked(
                "another execution command replaced the pending checked RunTo request");
        pendingCommand_ = { c, argument, controlEpoch_ };
    }
    cmdCv_.notify_all();
}

bool Debugger::postCommandForSession(Cmd c, uint64_t argument,
                                     DebugTargetIdentity expected) {
    if (!expected.valid()) return false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (state_ != DbgState::Paused ||
            !DebugTargetIdentityMatches({ pid_, sessionGeneration_ }, expected))
            return false;
        if (pendingCommand_.checkedRunToToken)
            cancelCheckedRunToLocked(
                "another execution command replaced the pending checked RunTo request");
        pendingCommand_ = { c, argument, controlEpoch_ };
    }
    cmdCv_.notify_all();
    return true;
}

void Debugger::cont()     { postCommand(Cmd::Continue);  }
void Debugger::stepInto() { postCommand(Cmd::StepInto);  }
void Debugger::stepOver() { postCommand(Cmd::StepOver);  }
void Debugger::stepOut()  { postCommand(Cmd::StepOut);   }
bool Debugger::continueForSession(DebugTargetIdentity expected) {
    return postCommandForSession(Cmd::Continue, 0, expected);
}
bool Debugger::stepIntoForSession(DebugTargetIdentity expected) {
    return postCommandForSession(Cmd::StepInto, 0, expected);
}
bool Debugger::stepOverForSession(DebugTargetIdentity expected) {
    return postCommandForSession(Cmd::StepOver, 0, expected);
}
bool Debugger::stepOutForSession(DebugTargetIdentity expected) {
    return postCommandForSession(Cmd::StepOut, 0, expected);
}

void Debugger::runToCursor(uint64_t va) {
    postCommand(Cmd::RunTo, va);
}

bool Debugger::runToCursorForSession(DebugTargetIdentity expected,
                                     uint32_t expectedTid,
                                     uint64_t runtimeContinuation,
                                     uint64_t requestToken,
                                     std::string* error) {
    if (error) error->clear();
    auto fail = [&](const char* message) {
        if (error) *error = message;
        return false;
    };
    if (!expected.valid()) return fail("the captured debugger target is invalid");
    if (!expectedTid) return fail("the captured debugger thread is invalid");
    if (!runtimeContinuation)
        return fail("the runtime call continuation is invalid");
    if (!requestToken)
        return fail("the checked RunTo request token is invalid");

    // Lock order intentionally matches the register-buffer transaction:
    // debugger state first, then the independently lifetime-guarded process
    // handle.  The user-visible pause keeps the queried page and byte stable.
    std::unique_lock<std::mutex> stateLock(mtx_);
    if (!DebugTargetIdentityMatches({ pid_, sessionGeneration_ }, expected))
        return fail("the debugger target or session changed");
    if (state_ != DbgState::Paused)
        return fail("the debugger is no longer paused");
    if (activeTid_ != expectedTid)
        return fail("the active debugger thread changed");
    if (std::none_of(threadHandles_.begin(), threadHandles_.end(),
                     [expectedTid](const auto& entry) {
                         return entry.first == expectedTid && entry.second;
                     }))
        return fail("the active debugger thread handle is unavailable");
    if (isWow64_.load() && runtimeContinuation > UINT32_MAX)
        return fail("the runtime continuation does not fit the 32-bit target");
    if (pendingCommand_.command != Cmd::None)
        return fail("another debugger execution command is already queued");
    if (runtimeTempBpAddr_)
        return fail("another one-shot debugger breakpoint is already active");
    if (pausedUserBpAddr_ && *pausedUserBpAddr_ == runtimeContinuation)
        return fail("the continuation is the breakpoint currently being stepped off");

    const bool pendingUserBreakpoint = std::any_of(
        pendingBpAdds_.begin(), pendingBpAdds_.end(),
        [runtimeContinuation](const PendingBp& value) {
            return value.va == runtimeContinuation;
        });
    const bool sharesAntiTrap = antiTraps_.count(runtimeContinuation) != 0;
    if (bps_.count(runtimeContinuation) ||
        traceBps_.count(runtimeContinuation) ||
        dllTargetBps_.count(runtimeContinuation) ||
        networkProbeBps_.count(runtimeContinuation) ||
        networkReturnBps_.count(runtimeContinuation) ||
        authorizationBps_.count(runtimeContinuation) ||
        authorizationReturnBps_.count(runtimeContinuation) ||
        pendingUserBreakpoint)
        return fail("the continuation is already owned by another debugger breakpoint");

    std::lock_guard<std::mutex> processLock(hProcMtx_);
    HANDLE process = static_cast<HANDLE>(hProcessShared_.load());
    if (!process || !DebugTargetIdentityMatches(hProcessIdentity_, expected))
        return fail("the debugger process handle no longer belongs to this session");

    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQueryEx(process,
                       reinterpret_cast<LPCVOID>(runtimeContinuation),
                       &mbi, sizeof(mbi)) != sizeof(mbi) ||
        mbi.State != MEM_COMMIT ||
        (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
        return fail("the runtime continuation is not committed executable memory");
    const DWORD protection = mbi.Protect & 0xFFu;
    if (protection != PAGE_EXECUTE && protection != PAGE_EXECUTE_READ &&
        protection != PAGE_EXECUTE_READWRITE &&
        protection != PAGE_EXECUTE_WRITECOPY)
        return fail("the runtime continuation is not executable");

    uint8_t byte = 0;
    if (!readByteRPM(process, runtimeContinuation, byte))
        return fail("the runtime continuation byte is unreadable");
    if (byte == 0xCC && !sharesAntiTrap)
        return fail("the runtime continuation already contains an unowned INT3");
    if (byte != 0xCC && sharesAntiTrap)
        return fail("the shared Hide Debugger trap is no longer armed");

    pendingCommand_ = {
        Cmd::RunTo, runtimeContinuation, controlEpoch_, expectedTid,
        requestToken
    };
    checkedRunTo_ = {};
    checkedRunTo_.requestToken = requestToken;
    checkedRunTo_.target = expected;
    checkedRunTo_.tid = expectedTid;
    checkedRunTo_.address = runtimeContinuation;
    transitionCheckedRunToLocked(CheckedRunToState::Pending, {});
    stateLock.unlock();
    cmdCv_.notify_all();
    return true;
}

bool Debugger::runToCursorForSession(DebugTargetIdentity expected, uint64_t va) {
    return postCommandForSession(Cmd::RunTo, va, expected);
}

bool Debugger::sampleExecutionContext(Registers& out) {
    std::vector<Registers> all = sampleExecutionContexts(1);
    if (all.empty()) return false;
    out = all.front();
    return true;
}

std::vector<Registers> Debugger::sampleExecutionContexts(size_t maxThreads) {
    std::vector<Registers> result;
    if (!maxThreads) return result;
    struct Sample { uint32_t tid = 0; HANDLE handle = nullptr; };
    std::vector<Sample> samples;
    DbgState state = DbgState::Detached;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        state = state_;
        if (state == DbgState::Paused) {
            result.push_back(regs_);
            return result;
        }
        uint32_t wanted = activeTid_ ? activeTid_ : tid_;
        // Active/display thread first, followed by every other currently owned
        // debug-event thread. CREATE/EXIT publish this list under the same lock.
        auto duplicateOne = [&](const std::pair<uint32_t, void*>& value) {
            if (samples.size() >= maxThreads || !value.second) return;
            HANDLE copy = nullptr;
            if (DuplicateHandle(GetCurrentProcess(), (HANDLE)value.second, GetCurrentProcess(),
                                &copy, 0, FALSE, DUPLICATE_SAME_ACCESS))
                samples.push_back({ value.first, copy });
        };
        auto active = std::find_if(threadHandles_.begin(), threadHandles_.end(),
            [wanted](const auto& value) { return value.first == wanted; });
        if (active != threadHandles_.end()) duplicateOne(*active);
        for (const auto& value : threadHandles_)
            if (value.first != wanted) duplicateOne(value);
    }
    if (state != DbgState::Running) {
        for (auto& sample : samples) CloseHandle(sample.handle);
        return result;
    }
    for (auto& sample : samples) {
        Registers regs{};
        if (SuspendThread(sample.handle) != static_cast<DWORD>(-1)) {
            if (ctxReadFull(sample.handle, regs)) result.push_back(regs);
            ResumeThread(sample.handle);
        }
        CloseHandle(sample.handle);
    }
    return result;
}

void Debugger::requestTraceSyncBreak(DebugTargetIdentity expected) {
    DbgState state;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (expected.valid() && !DebugTargetIdentityMatches(
                { pid_, sessionGeneration_ }, expected))
            return;
        state = state_;
    }
    if (state == DbgState::Paused) {
        // Queued breakpoint edits can be applied under the held debug event;
        // they must not require an execution command to wake its owner.
        cmdCv_.notify_all();
        return;
    }
    if (state != DbgState::Running) return;
    std::lock_guard<std::mutex> lk(hProcMtx_);
    void* h = hProcessShared_.load();
    if (!h || (expected.valid() &&
               !DebugTargetIdentityMatches(hProcessIdentity_, expected)))
        return;
    if (traceSyncBreakRequested_.exchange(true)) return; // one helper services all queued mutations
    if (!DebugBreakProcess((HANDLE)h)) traceSyncBreakRequested_ = false;
}

void Debugger::startTraceCoverage(const std::vector<uint64_t>& basicBlockStarts,
                                  size_t maxSites) {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (state_ == DbgState::Detached || state_ == DbgState::Terminated) return;
        traceCoverage_.begin(basicBlockStarts, maxSites);
        pendingTraceStop_ = false;
        pendingTraceStart_ = true;
    }
    requestTraceSyncBreak();
}

bool Debugger::startTraceCoverageForSession(
    DebugTargetIdentity expected,
    const std::vector<uint64_t>& basicBlockStarts,
    size_t maxSites) {
    if (!expected.valid()) return false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if ((state_ != DbgState::Running && state_ != DbgState::Paused) ||
            !DebugTargetIdentityMatches({ pid_, sessionGeneration_ }, expected))
            return false;
        traceCoverage_.begin(basicBlockStarts, maxSites);
        pendingTraceStop_ = false;
        pendingTraceStart_ = true;
    }
    requestTraceSyncBreak(expected);
    return true;
}

void Debugger::stopTraceCoverage() {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        traceCoverage_.stop();
        pendingTraceStart_ = false;
        pendingTraceStop_ = true;
    }
    requestTraceSyncBreak();
}

bool Debugger::stopTraceCoverageForSession(DebugTargetIdentity expected) {
    if (!expected.valid()) return false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if ((state_ != DbgState::Running && state_ != DbgState::Paused) ||
            !DebugTargetIdentityMatches({ pid_, sessionGeneration_ }, expected))
            return false;
        traceCoverage_.stop();
        pendingTraceStart_ = false;
        pendingTraceStop_ = true;
    }
    requestTraceSyncBreak(expected);
    return true;
}

void* Debugger::duplicateProcessHandleForSession(DebugTargetIdentity expected) {
    std::lock_guard<std::mutex> lk(hProcMtx_);
    HANDLE source = static_cast<HANDLE>(hProcessShared_.load());
    if (!source || !DebugTargetIdentityMatches(hProcessIdentity_, expected)) return nullptr;
    HANDLE duplicate = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), source, GetCurrentProcess(),
                         &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS))
        return nullptr;
    return duplicate;
}

uint64_t Debugger::processCreationTimeForSession(DebugTargetIdentity expected) {
    if (!expected.valid()) return 0;
    std::lock_guard<std::mutex> lk(hProcMtx_);
    HANDLE process = static_cast<HANDLE>(hProcessShared_.load());
    if (!process || !DebugTargetIdentityMatches(hProcessIdentity_, expected)) return 0;
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) return 0;
    return (uint64_t{ created.dwHighDateTime } << 32) | created.dwLowDateTime;
}

void Debugger::clearTraceCoverage() { traceCoverage_.clearHits(); }

bool Debugger::clearTraceCoverageForSession(DebugTargetIdentity expected) {
    if (!expected.valid()) return false;
    std::lock_guard<std::mutex> lk(mtx_);
    if ((state_ != DbgState::Running && state_ != DbgState::Paused) ||
        !DebugTargetIdentityMatches({ pid_, sessionGeneration_ }, expected))
        return false;
    traceCoverage_.clearHits();
    return true;
}

TraceCoverageSnapshot Debugger::traceCoverageSnapshot() const {
    return traceCoverage_.snapshot();
}

bool Debugger::startAuthorizationWatch(
    const AuthorizationWatchPlan& plan, DebugTargetIdentity expected,
    const AuthorizationWatchOptions& options, std::string* error) {
    if (error) error->clear();
    if (plan.sites.empty()) {
        if (error) *error = "authorization watch plan has no sites";
        return false;
    }

    if (!plan.requireExactModuleIdentity ||
        plan.documentId == 0 || plan.documentImageGeneration == 0) {
        if (error) *error =
            "authorization watch plan has no exact document/module binding";
        return false;
    }

    DbgModule main;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        const DebugTargetIdentity current{ pid_, sessionGeneration_ };
        if (!DebugTargetIdentityMatches(current, expected) ||
            (state_ != DbgState::Running && state_ != DbgState::Paused)) {
            if (error) *error = "debug target changed before Authorization Watch could start";
            return false;
        }
        if (authorizationWatch_.active() || !authorizationBps_.empty() ||
            !authorizationReturnBps_.empty() ||
            pendingAuthorizationStart_ || pendingAuthorizationStop_) {
            if (error) *error =
                "Authorization Watch is already active or still retiring; stop and resume once before restarting";
            return false;
        }
        if (dbgModules_.empty() || !dbgModules_.front().base) {
            if (error) *error = "the attached process main image is not available yet";
            return false;
        }
        main = dbgModules_.front();
    }

    // The App stamps this plan only after its exact document -> live-image
    // validator succeeds. Re-check every module property here so an intervening
    // document switch, detach, or mapping replacement cannot plant stale RVAs.
    const AttachedModuleIdentity actualMain{
        main.base, main.size, main.name, main.path, main.loadGeneration
    };
    if (!ExactAuthorizationWatchModuleMatch(plan.expectedModule, actualMain)) {
        if (error) *error =
            "authorization watch plan does not match the exact attached main-image mapping";
        return false;
    }

    authorizationWatch_.prepare(plan, options);
    {
        std::lock_guard<std::mutex> lk(mtx_);
        const DebugTargetIdentity current{ pid_, sessionGeneration_ };
        if (!DebugTargetIdentityMatches(current, expected) ||
            (state_ != DbgState::Running && state_ != DbgState::Paused)) {
            authorizationWatch_.reset();
            if (error) *error = "debug target changed while Authorization Watch was starting";
            return false;
        }
        pendingAuthorizationStop_ = false;
        pendingAuthorizationStart_ = true;
    }
    requestTraceSyncBreak();
    return true;
}

void Debugger::stopAuthorizationWatch() {
    authorizationWatch_.stop();
    {
        std::lock_guard<std::mutex> lk(mtx_);
        pendingAuthorizationStart_ = false;
        pendingAuthorizationStop_ = true;
    }
    requestTraceSyncBreak();
}

void Debugger::clearAuthorizationWatch() {
    authorizationWatch_.clearEvents();
}

AuthorizationWatchSnapshot Debugger::authorizationWatchSnapshot() {
    AuthorizationWatchSnapshot snapshot = authorizationWatch_.snapshot();
    std::lock_guard<std::mutex> lk(mtx_);
    snapshot.coverage.pendingReturns = authorizationPendingReturnCount_;
    snapshot.coverage.pendingReturnsDropped = authorizationPendingReturnsDropped_;
    for (const auto& [_, site] : authorizationReturnBps_) {
        if (site.armed) ++snapshot.coverage.returnSitesArmed;
        if (site.sharedWithUserBreakpoint)
            ++snapshot.coverage.returnSitesSharedWithUserBreakpoints;
    }
    return snapshot;
}

void Debugger::setActiveThread(uint32_t tid) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (state_ != DbgState::Paused) return;            // thread contexts are only stable at a stop
    void* h = nullptr;
    for (auto& kv : threadHandles_) if (kv.first == tid) { h = kv.second; break; }
    if (!h) return;
    Registers r;
    if (!ctxReadFull(h, r)) return;
    activeTid_ = tid;
    regs_ = r;
    // frames_ was unwound for the thread the debugger stopped on. Switching to a
    // different displayed thread invalidates it; clear it (this is the UI thread, so
    // we can't safely re-run StackWalk64 here, which touches debug-thread-local
    // state) so the call-stack view falls back to the heuristic walk of the new
    // thread's RSP until the next stop re-unwinds.
    if (tid != tid_) frames_.clear();
}

bool Debugger::setActiveThreadForSession(DebugTargetIdentity expected, uint32_t tid) {
    if (!expected.valid()) return false;
    std::lock_guard<std::mutex> lk(mtx_);
    if (state_ != DbgState::Paused ||
        !DebugTargetIdentityMatches({ pid_, sessionGeneration_ }, expected))
        return false;
    void* h = nullptr;
    for (auto& kv : threadHandles_) if (kv.first == tid) { h = kv.second; break; }
    if (!h) return false;
    Registers r;
    if (!ctxReadFull(h, r)) return false;
    activeTid_ = tid;
    regs_ = r;
    if (tid != tid_) frames_.clear();
    return true;
}

bool Debugger::setRegisters(const Registers& r) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (state_ != DbgState::Paused || gmlSnapshot_.stop) return false;
    void* h = nullptr;
    for (auto& kv : threadHandles_) if (kv.first == activeTid_) { h = kv.second; break; }
    if (!h) return false;
    if (!ctxWriteFull(h, r)) return false;             // get-modify-set (preserves seg/FP/debug)
    regs_ = r;                                          // reflect immediately in the next snapshot
    return true;
}

static uint64_t Registers::* registerFieldByName(const std::string& name) {
    uint64_t Registers::* f = nullptr;
    if      (name == "rip") f = &Registers::rip; else if (name == "rsp") f = &Registers::rsp;
    else if (name == "rbp") f = &Registers::rbp; else if (name == "rflags") f = &Registers::rflags;
    else if (name == "rax") f = &Registers::rax; else if (name == "rbx") f = &Registers::rbx;
    else if (name == "rcx") f = &Registers::rcx; else if (name == "rdx") f = &Registers::rdx;
    else if (name == "rsi") f = &Registers::rsi; else if (name == "rdi") f = &Registers::rdi;
    else if (name == "r8")  f = &Registers::r8;  else if (name == "r9")  f = &Registers::r9;
    else if (name == "r10") f = &Registers::r10; else if (name == "r11") f = &Registers::r11;
    else if (name == "r12") f = &Registers::r12; else if (name == "r13") f = &Registers::r13;
    else if (name == "r14") f = &Registers::r14; else if (name == "r15") f = &Registers::r15;
    return f;
}

bool Debugger::setRegister(const std::string& name, uint64_t value) {
    const DbgSnapshot current = snapshot();
    return setRegisterForSession(current.pid, current.sessionGeneration, name, value);
}

bool Debugger::setRegisterForSession(uint32_t expectedPid,
                                     uint64_t expectedSessionGeneration,
                                     const std::string& name, uint64_t value,
                                     uint32_t expectedTid,
                                     const uint64_t* expectedRip) {
    uint64_t Registers::* f = registerFieldByName(name);
    if (!f) return false;
    const DebugTargetIdentity expected{ expectedPid, expectedSessionGeneration };
    std::lock_guard<std::mutex> lk(mtx_);
    const DebugTargetIdentity current{ pid_, sessionGeneration_ };
    if (!DebugTargetIdentityMatches(current, expected) || state_ != DbgState::Paused || gmlSnapshot_.stop)
        return false;
    if (expectedTid && activeTid_ != expectedTid) return false;
    const bool wow64 = isWow64_.load();
    if (!RegisterValueFitsTarget(value, wow64) ||
        (wow64 && (name == "r8" || name == "r9" || name == "r10" ||
                   name == "r11" || name == "r12" || name == "r13" ||
                   name == "r14" || name == "r15")))
        return false;

    void* h = nullptr;
    for (auto& thread : threadHandles_)
        if (thread.first == activeTid_) { h = thread.second; break; }
    if (!h) return false;
    Registers r;
    if (!ctxReadFull(h, r)) return false;
    regs_ = r;
    if (expectedRip && r.rip != *expectedRip) return false;
    r.*f = value;
    if (!ctxWriteFull(h, r)) return false;
    // Publish what the target actually received.  In particular, a WOW64
    // context contains zero-extended DWORDs and must never expose a stale high
    // half in the UI snapshot.
    Registers observed;
    regs_ = ctxReadFull(h, observed) ? observed : r;
    return true;
}

static void publishPausedRegisterSnapshot(PausedRegisterSnapshot& out,
                                          DebugTargetIdentity target,
                                          uint32_t tid,
                                          bool is32,
                                          const Registers& registers) {
    out = {};
    out.target = target;
    out.tid = tid;
    out.is32 = is32;
    out.regs = registers;
    out.eax = static_cast<uint32_t>(registers.rax);
    out.al = static_cast<uint8_t>(registers.rax);
}

bool Debugger::readPausedRegistersForSession(DebugTargetIdentity expected,
                                             uint32_t expectedTid,
                                             PausedRegisterSnapshot& out,
                                             std::string* error) {
    out = {};
    if (error) error->clear();
    auto fail = [&](const char* message) {
        if (error) *error = message;
        return false;
    };
    if (!expected.valid()) return fail("the captured debugger target is invalid");
    if (!expectedTid) return fail("the captured debugger thread is invalid");

    std::lock_guard<std::mutex> stateLock(mtx_);
    if (gmlSnapshot_.stop)
        return fail("native register experiments are unavailable inside a GML helper stop");
    if (!DebugTargetIdentityMatches({ pid_, sessionGeneration_ }, expected))
        return fail("the debugger target or session changed");
    if (state_ != DbgState::Paused)
        return fail("the debugger is no longer paused");
    if (activeTid_ != expectedTid)
        return fail("the active debugger thread changed");

    void* thread = nullptr;
    for (const auto& candidate : threadHandles_)
        if (candidate.first == expectedTid) {
            thread = candidate.second;
            break;
        }
    if (!thread) return fail("the active debugger thread handle is unavailable");

    Registers actual;
    if (!ctxReadFull(thread, actual))
        return fail("could not read the paused thread context");
    regs_ = actual;
    publishPausedRegisterSnapshot(out, expected, expectedTid,
                                  isWow64_.load(), actual);
    return true;
}

bool Debugger::setAccumulatorForSessionVerified(
    DebugTargetIdentity expected,
    uint32_t expectedTid,
    uint64_t expectedRip,
    uint64_t expectedAccumulator,
    uint64_t accumulatorCompareMask,
    uint64_t value,
    PausedRegisterSnapshot& observed,
    std::string* error) {
    observed = {};
    if (error) error->clear();
    auto fail = [&](const char* message) {
        if (error) *error = message;
        return false;
    };
    if (!expected.valid()) return fail("the captured debugger target is invalid");
    if (!expectedTid) return fail("the captured debugger thread is invalid");
    if (!accumulatorCompareMask)
        return fail("the expected accumulator comparison mask is empty");

    std::lock_guard<std::mutex> stateLock(mtx_);
    if (!DebugTargetIdentityMatches({ pid_, sessionGeneration_ }, expected))
        return fail("the debugger target or session changed");
    if (state_ != DbgState::Paused)
        return fail("the debugger is no longer paused");
    if (activeTid_ != expectedTid)
        return fail("the active debugger thread changed");

    const bool wow64 = isWow64_.load();
    if (!RegisterValueFitsTarget(value, wow64))
        return fail("the accumulator value does not fit the target architecture");

    void* thread = nullptr;
    for (const auto& candidate : threadHandles_)
        if (candidate.first == expectedTid) {
            thread = candidate.second;
            break;
        }
    if (!thread) return fail("the active debugger thread handle is unavailable");

    // Read the real context immediately before evaluating the proposal.  The
    // target is stopped at a held debug event, so no instruction can execute
    // between this comparison, the write, and the readback below.
    Registers before;
    if (!ctxReadFull(thread, before))
        return fail("could not read the paused thread context before the write");
    regs_ = before;
    if (before.rip != expectedRip)
        return fail("the paused instruction pointer changed before the write");
    if ((before.rax & accumulatorCompareMask) !=
        (expectedAccumulator & accumulatorCompareMask))
        return fail("the paused accumulator changed before the write");

    Registers requested = before;
    requested.rax = value;
    if (!ctxWriteFull(thread, requested)) {
        Registers current;
        if (ctxReadFull(thread, current)) regs_ = current;
        return fail("could not write the paused accumulator");
    }

    Registers after;
    const bool readBack = ctxReadFull(thread, after);
    const uint64_t architectureMask = wow64 ? UINT64_C(0xffffffff)
                                             : UINT64_MAX;
    const uint64_t normalizedValue = value & architectureMask;
    if (!readBack || after.rip != expectedRip ||
        after.rax != normalizedValue) {
        (void)ctxWriteFull(thread, before);
        Registers finalContext;
        const bool finalRead = ctxReadFull(thread, finalContext);
        const bool rollbackVerified = finalRead &&
            finalContext.rip == before.rip &&
            finalContext.rax == before.rax;
        if (finalRead) {
            regs_ = finalContext;
            // A false result can still carry a coherent final observation. The
            // experiment state machine uses it to retain Restore when the
            // requested write stuck and rollback did not.
            publishPausedRegisterSnapshot(observed, expected, expectedTid,
                                          wow64, finalContext);
        } else if (readBack) {
            regs_ = after;
        } else {
            regs_ = before;
        }
        if (error) {
            *error = rollbackVerified
                ? "the accumulator write did not verify and the original context was restored"
                : "the accumulator write did not verify and restoration of the original context could not be verified";
        }
        return false;
    }

    regs_ = after;
    publishPausedRegisterSnapshot(observed, expected, expectedTid, wow64, after);
    return true;
}

bool Debugger::setRegisterToBufferForSession(
    uint32_t expectedPid, uint64_t expectedSessionGeneration,
    uint32_t expectedTid, const std::string& name,
    const std::vector<uint8_t>& bytes, uint64_t& remoteAddress,
    std::string* error, const uint64_t* expectedRip) {
    remoteAddress = 0;
    if (error) error->clear();
    auto fail = [&](std::string message) {
        if (error) *error = std::move(message);
        return false;
    };

    uint64_t Registers::* field = registerFieldByName(name);
    if (!field) return fail("unknown register");
    if (bytes.empty() || bytes.size() > kRegisterEditMaxBufferBytes)
        return fail("register text buffer must contain 1 to 64 KiB");
    if (bytes.back() != 0)
        return fail("register text buffer is not NUL-terminated");

    const DebugTargetIdentity expected{
        expectedPid, expectedSessionGeneration
    };
    if (!expected.valid() || !expectedTid)
        return fail("the captured debugger target/thread is invalid");

    // Allocate verification storage before taking debugger locks. Allocation,
    // byte publication, readback, context replacement, and snapshot publication
    // then occur as one current-stop transaction: the debug thread cannot move
    // Paused -> Running and freeRemote/freeAllRemote cannot retire this address
    // between the individual mutations.
    std::vector<uint8_t> observedBytes;
    try {
        observedBytes.resize(bytes.size());
    } catch (...) {
        return fail("could not allocate text-write verification storage");
    }

    std::unique_lock<std::mutex> stateLock(mtx_);
    if (gmlSnapshot_.stop)
        return fail("native register text editing is unavailable inside a GML helper stop");
    if (!DebugTargetIdentityMatches({ pid_, sessionGeneration_ }, expected) ||
        state_ != DbgState::Paused || activeTid_ != expectedTid)
        return fail("debugger target, session, or active thread changed");
    const bool wow64 = isWow64_.load();
    if (!RegisterCanHoldTextPointer(name, wow64))
        return fail("text pointers may only be assigned to data registers");

    void* thread = nullptr;
    for (const auto& candidate : threadHandles_)
        if (candidate.first == expectedTid) {
            thread = candidate.second;
            break;
        }
    if (!thread) return fail("active thread handle is no longer available");

    Registers before;
    if (!ctxReadFull(thread, before))
        return fail("could not read the paused thread context");
    regs_ = before;
    if (expectedRip && before.rip != *expectedRip)
        return fail("the paused instruction pointer changed before the write");

    // Lock order matches allocRemote/freeRemote: mtx_ -> hProcMtx_. A fresh
    // PAGE_READWRITE region cannot overlap debugger breakpoints, so it is safe
    // to write it directly while the process-wide debug event remains held.
    // Avoiding the generic patch writer also avoids any transient RWX mapping.
    std::lock_guard<std::mutex> processLock(hProcMtx_);
    HANDLE process = static_cast<HANDLE>(hProcessShared_.load());
    if (!process || !DebugTargetIdentityMatches(hProcessIdentity_, expected))
        return fail("debugger process handle no longer belongs to this session");
    void* memory = VirtualAllocEx(process, nullptr, bytes.size(),
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!memory) return fail("could not allocate text memory in the target");
    const uint64_t allocation = reinterpret_cast<uint64_t>(memory);
    if (wow64 && allocation > UINT32_MAX) {
        VirtualFreeEx(process, memory, 0, MEM_RELEASE);
        return fail("Windows returned a text address that does not fit in EAX");
    }

    // A successful allocation at this exact base proves that any prior mapping
    // there is gone. The target owns successful text buffers and may free one
    // itself, after which VirtualAllocEx can legitimately reuse its address.
    // Retire every stale local occurrence before applying the session bound or
    // recording ownership for this fresh mapping.
    remoteRegisterBuffers_.erase(allocation);
    remoteAllocs_.erase(
        std::remove(remoteAllocs_.begin(), remoteAllocs_.end(), allocation),
        remoteAllocs_.end());
    if (remoteRegisterBuffers_.size() >= kMaxRemoteRegisterBuffers) {
        if (!VirtualFreeEx(process, memory, 0, MEM_RELEASE)) {
            try {
                remoteAllocs_.push_back(allocation);
            } catch (...) {
                // Allocation failure left no safe way to retain bookkeeping.
            }
        }
        return fail("this debugger session reached the 256 text-buffer limit");
    }

    bool vectorTracked = false;
    bool bufferTracked = false;
    try {
        remoteAllocs_.push_back(allocation);
        vectorTracked = true;
        bufferTracked = remoteRegisterBuffers_.insert(allocation).second;
    } catch (...) {
        if (bufferTracked) remoteRegisterBuffers_.erase(allocation);
        if (VirtualFreeEx(process, memory, 0, MEM_RELEASE) && vectorTracked) {
            auto tracked = std::find(remoteAllocs_.begin(), remoteAllocs_.end(),
                                     allocation);
            if (tracked != remoteAllocs_.end()) remoteAllocs_.erase(tracked);
        }
        return fail("could not track the target text allocation");
    }
    if (!bufferTracked) {
        if (VirtualFreeEx(process, memory, 0, MEM_RELEASE)) {
            auto tracked = std::find(remoteAllocs_.begin(), remoteAllocs_.end(),
                                     allocation);
            if (tracked != remoteAllocs_.end()) remoteAllocs_.erase(tracked);
        }
        return fail("target text allocation collided with existing ownership");
    }

    // Failed allocations never become target-owned. If Windows cannot release
    // one immediately, leave it in remoteAllocs_ (but not the successful-buffer
    // subset) so stopped-session cleanup gets another chance.
    auto discardFailedAllocation = [&] {
        remoteRegisterBuffers_.erase(allocation);
        if (!VirtualFreeEx(process, memory, 0, MEM_RELEASE)) return;
        auto tracked = std::find(remoteAllocs_.begin(), remoteAllocs_.end(),
                                 allocation);
        if (tracked != remoteAllocs_.end()) remoteAllocs_.erase(tracked);
    };

    SIZE_T written = 0;
    if (!WriteProcessMemory(process, memory, bytes.data(), bytes.size(), &written) ||
        written != bytes.size()) {
        discardFailedAllocation();
        return fail("could not write the complete text buffer into the target");
    }
    SIZE_T read = 0;
    if (!ReadProcessMemory(process, memory, observedBytes.data(),
                           observedBytes.size(), &read) ||
        read != observedBytes.size() || observedBytes != bytes) {
        discardFailedAllocation();
        return fail("target text readback did not match the requested bytes");
    }

    Registers updated = regs_;
    updated.*field = allocation;
    if (!ctxWriteFull(thread, updated)) {
        discardFailedAllocation();
        return fail("Windows refused the register context write");
    }
    Registers observedContext;
    regs_ = ctxReadFull(thread, observedContext) ? observedContext : updated;
    remoteAddress = allocation;
    return true;
}

void Debugger::suspendThread(uint32_t tid) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (suspended_.count(tid)) return;                 // keep our suspend count at exactly +1
    void* h = nullptr;
    for (auto& kv : threadHandles_) if (kv.first == tid) { h = kv.second; break; }
    if (!h) return;
    if (SuspendThread((HANDLE)h) != (DWORD)-1) suspended_.insert(tid);
}

bool Debugger::suspendThreadForSession(DebugTargetIdentity expected, uint32_t tid) {
    if (!expected.valid()) return false;
    std::lock_guard<std::mutex> lk(mtx_);
    if ((state_ == DbgState::Detached || state_ == DbgState::Terminated) ||
        !DebugTargetIdentityMatches({ pid_, sessionGeneration_ }, expected))
        return false;
    if (suspended_.count(tid)) return true;
    void* h = nullptr;
    for (auto& kv : threadHandles_) if (kv.first == tid) { h = kv.second; break; }
    if (!h) return false;
    if (SuspendThread((HANDLE)h) == (DWORD)-1) return false;
    suspended_.insert(tid);
    return true;
}

void Debugger::resumeThread(uint32_t tid) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (!suspended_.count(tid)) return;
    void* h = nullptr;
    for (auto& kv : threadHandles_) if (kv.first == tid) { h = kv.second; break; }
    // Only forget the thread once it is actually un-suspended (or its handle is
    // already gone). If ResumeThread fails on a live handle, keep the entry so a
    // retry can still thaw it - symmetric with suspendThread's success check.
    if (!h || ResumeThread((HANDLE)h) != (DWORD)-1) suspended_.erase(tid);
}

bool Debugger::resumeThreadForSession(DebugTargetIdentity expected, uint32_t tid) {
    if (!expected.valid()) return false;
    std::lock_guard<std::mutex> lk(mtx_);
    if ((state_ == DbgState::Detached || state_ == DbgState::Terminated) ||
        !DebugTargetIdentityMatches({ pid_, sessionGeneration_ }, expected))
        return false;
    if (!suspended_.count(tid)) return true;
    void* h = nullptr;
    for (auto& kv : threadHandles_) if (kv.first == tid) { h = kv.second; break; }
    if (!h) {
        suspended_.erase(tid);
        return true;
    }
    if (ResumeThread((HANDLE)h) == (DWORD)-1) return false;
    suspended_.erase(tid);
    return true;
}

bool Debugger::isThreadSuspended(uint32_t tid) {
    std::lock_guard<std::mutex> lk(mtx_);
    return suspended_.count(tid) != 0;
}

void Debugger::pause() {
    std::lock_guard<std::mutex> lk(hProcMtx_);   // serialize with the debug thread closing the handle
    void* h = hProcessShared_.load();
    if (h) {
        breakRequested_ = true;               // tell the loop the next stray int3 is our pause
        if (!DebugBreakProcess((HANDLE)h))     // injects an int3 in a helper thread
            breakRequested_ = false;
    }
}

bool Debugger::pauseForSession(DebugTargetIdentity expected) {
    if (!expected.valid()) return false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (state_ != DbgState::Running ||
            !DebugTargetIdentityMatches({ pid_, sessionGeneration_ }, expected))
            return false;
    }
    std::lock_guard<std::mutex> lk(hProcMtx_);
    void* h = hProcessShared_.load();
    if (!h || !DebugTargetIdentityMatches(hProcessIdentity_, expected)) return false;
    breakRequested_ = true;
    if (!DebugBreakProcess((HANDLE)h)) {
        breakRequested_ = false;
        return false;
    }
    return true;
}

bool Debugger::addBreakpoint(uint64_t va, const std::string& condition) {
    if (!ValidateBreakpointCondition(condition)) return false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (state_ == DbgState::Detached || state_ == DbgState::Terminated) return false;
        if (gameMakerOwnsRangeLocked(va,1)) return false;
        // The debug thread drains command kinds separately. Coalesce this
        // address while still queued so remove/re-add preserves the last intent.
        // Keep adds/removals sorted: large ascending listing selections append
        // after logarithmic lookup instead of scanning every prior request.
        const auto removal = std::lower_bound(pendingBpRems_.begin(), pendingBpRems_.end(), va);
        if (removal != pendingBpRems_.end() && *removal == va) pendingBpRems_.erase(removal);
        std::erase_if(pendingBpConds_, [va](const PendingBp& pending) { return pending.va == va; });
        const auto addition = std::lower_bound(pendingBpAdds_.begin(), pendingBpAdds_.end(), va,
            [](const PendingBp& pending, uint64_t address) { return pending.va < address; });
        if (addition != pendingBpAdds_.end() && addition->va == va) addition->cond = condition;
        else pendingBpAdds_.insert(addition, { va, condition });
        clearBreakpointInstallFailureLocked(va); // a fresh request is queued, not the old failure
    }
    requestTraceSyncBreak();
    return true;
}
bool Debugger::addBreakpointForSession(DebugTargetIdentity expected, uint64_t va,
                                       const std::string& condition) {
    if (!expected.valid() || !ValidateBreakpointCondition(condition)) return false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if ((state_ != DbgState::Running && state_ != DbgState::Paused) ||
            !DebugTargetIdentityMatches({ pid_, sessionGeneration_ }, expected))
            return false;
        if (gameMakerOwnsRangeLocked(va,1)) return false;
        const auto removal = std::lower_bound(pendingBpRems_.begin(), pendingBpRems_.end(), va);
        if (removal != pendingBpRems_.end() && *removal == va) pendingBpRems_.erase(removal);
        std::erase_if(pendingBpConds_, [va](const PendingBp& pending) { return pending.va == va; });
        const auto addition = std::lower_bound(pendingBpAdds_.begin(), pendingBpAdds_.end(), va,
            [](const PendingBp& pending, uint64_t address) { return pending.va < address; });
        if (addition != pendingBpAdds_.end() && addition->va == va) addition->cond = condition;
        else pendingBpAdds_.insert(addition, { va, condition });
        clearBreakpointInstallFailureLocked(va);
    }
    requestTraceSyncBreak(expected);
    return true;
}
bool Debugger::removeBreakpoint(uint64_t va) {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (state_ == DbgState::Detached || state_ == DbgState::Terminated) return false;
        const auto addition = std::lower_bound(pendingBpAdds_.begin(), pendingBpAdds_.end(), va,
            [](const PendingBp& pending, uint64_t address) { return pending.va < address; });
        if (addition != pendingBpAdds_.end() && addition->va == va) pendingBpAdds_.erase(addition);
        std::erase_if(pendingBpConds_, [va](const PendingBp& pending) { return pending.va == va; });
        std::erase_if(pendingBpEveryN_, [va](const auto& pending) { return pending.first == va; });
        const auto removal = std::lower_bound(pendingBpRems_.begin(), pendingBpRems_.end(), va);
        if (removal == pendingBpRems_.end() || *removal != va) pendingBpRems_.insert(removal, va);
    }
    requestTraceSyncBreak();
    return true;
}
bool Debugger::removeBreakpointForSession(DebugTargetIdentity expected, uint64_t va) {
    if (!expected.valid()) return false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if ((state_ != DbgState::Running && state_ != DbgState::Paused) ||
            !DebugTargetIdentityMatches({ pid_, sessionGeneration_ }, expected))
            return false;
        const auto addition = std::lower_bound(pendingBpAdds_.begin(), pendingBpAdds_.end(), va,
            [](const PendingBp& pending, uint64_t address) { return pending.va < address; });
        if (addition != pendingBpAdds_.end() && addition->va == va) pendingBpAdds_.erase(addition);
        std::erase_if(pendingBpConds_, [va](const PendingBp& pending) { return pending.va == va; });
        std::erase_if(pendingBpEveryN_, [va](const auto& pending) { return pending.first == va; });
        const auto removal = std::lower_bound(pendingBpRems_.begin(), pendingBpRems_.end(), va);
        if (removal == pendingBpRems_.end() || *removal != va) pendingBpRems_.insert(removal, va);
    }
    requestTraceSyncBreak(expected);
    return true;
}
bool Debugger::hasBreakpoint(uint64_t va) {
    std::lock_guard<std::mutex> lk(mtx_);
    return bps_.count(va) != 0;
}
bool Debugger::setBreakpointCondition(uint64_t va, const std::string& condition) {
    if (!ValidateBreakpointCondition(condition)) return false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (state_ == DbgState::Detached || state_ == DbgState::Terminated) return false;
        pendingBpConds_.push_back({ va, condition });
    }
    requestTraceSyncBreak();
    return true;
}

bool Debugger::setBreakpointConditionForSession(DebugTargetIdentity expected,
                                                uint64_t va,
                                                const std::string& condition) {
    if (!expected.valid() || !ValidateBreakpointCondition(condition)) return false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if ((state_ != DbgState::Running && state_ != DbgState::Paused) ||
            !DebugTargetIdentityMatches({ pid_, sessionGeneration_ }, expected))
            return false;
        pendingBpConds_.push_back({ va, condition });
    }
    requestTraceSyncBreak(expected);
    return true;
}

void Debugger::setBreakpointEveryN(uint64_t va, uint32_t n) {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (state_ == DbgState::Detached || state_ == DbgState::Terminated) return;
        pendingBpEveryN_.push_back({ va, n });
    }
    requestTraceSyncBreak();
}

bool Debugger::setBreakpointEveryNForSession(DebugTargetIdentity expected,
                                             uint64_t va, uint32_t n) {
    if (!expected.valid()) return false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if ((state_ != DbgState::Running && state_ != DbgState::Paused) ||
            !DebugTargetIdentityMatches({ pid_, sessionGeneration_ }, expected))
            return false;
        pendingBpEveryN_.push_back({ va, n });
    }
    requestTraceSyncBreak(expected);
    return true;
}

void Debugger::addFirstChanceCode(uint32_t code) {
    std::lock_guard<std::mutex> lk(mtx_);
    fcWhitelist_.insert(code);
}
void Debugger::removeFirstChanceCode(uint32_t code) {
    std::lock_guard<std::mutex> lk(mtx_);
    fcWhitelist_.erase(code);
}
std::vector<uint32_t> Debugger::firstChanceCodes() {
    std::lock_guard<std::mutex> lk(mtx_);
    return std::vector<uint32_t>(fcWhitelist_.begin(), fcWhitelist_.end());
}

void Debugger::clearDebugOutput() {
    std::lock_guard<std::mutex> lk(mtx_);
    dbgOutput_.clear();
}

// Defined further down (the RPM byte helpers); forward-declared so the net-tap
// methods above their definitions can use them.
static bool readByteRPM(HANDLE h, uint64_t va, uint8_t& b);
static bool writeByteRPM(HANDLE h, uint64_t va, uint8_t b);

// ---- guided network observation (public shell + debug-thread probes) ---------
void Debugger::startNetworkObservation() {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        // A terminated snapshot deliberately retains modules/register history,
        // but it has no live debuggee in which probes can be installed. Keep
        // this Core boundary authoritative even if a UI caller has stale state.
        if (state_ != DbgState::Running && state_ != DbgState::Paused) {
            networkObservationWant_.store(false);
            networkCoverage_.requested = false;
            return;
        }
        networkObservationWant_.store(true);
        networkCoverage_.requested = true;
    }
    requestTraceSyncBreak();
}

void Debugger::stopNetworkObservation() {
    networkObservationWant_.store(false);
    {
        std::lock_guard<std::mutex> lk(mtx_);
        networkCoverage_.requested = false;
    }
    requestTraceSyncBreak();
}

void Debugger::enableNetTap(bool on) {
    if (on) startNetworkObservation();
    else stopNetworkObservation();
}

NetworkObservation Debugger::networkObservationSnapshot() {
    std::lock_guard<std::mutex> lk(mtx_);
    NetworkObservation snapshot;
    snapshot.coverage = networkCoverage_;
    snapshot.events.assign(networkEvents_.begin(), networkEvents_.end());
    return snapshot;
}

NetworkProbeCoverage Debugger::networkProbeCoverage() {
    std::lock_guard<std::mutex> lk(mtx_);
    return networkCoverage_;
}

void Debugger::clearNetworkObservation() {
    std::lock_guard<std::mutex> lk(mtx_);
    networkEvents_.clear();
    networkCoverage_.retainedPayloadBytes = 0;
    networkCoverage_.payloadBytesDropped = 0;
    networkCoverage_.eventsDropped = 0;
}

bool Debugger::setNetCaptureLogFile(const std::string& utf8Path, bool append, std::string* err) {
    if (err) err->clear();
    if (utf8Path.empty() || utf8Path.size() > 32768 || utf8Path.find('\0') != std::string::npos) {
        if (err) *err = "invalid log path";
        return false;
    }
    std::lock_guard lock(netLogMtx_);
    // Reserve an extra control slot for Close, which must always be accepted.
    if (netLogShutdown_ || netLogQueuedControls_ >= kNetLogQueueControls) {
        if (err) *err = "log writer is busy; wait for queued file changes to finish";
        return false;
    }
    NetLogWork work;
    work.kind = NetLogWork::Kind::Open;
    work.path = utf8Path;
    work.append = append;
    work.generation = ++netLogGeneration_;
    netLogQueue_.push_back(std::move(work));
    ++netLogQueuedControls_;
    netLogPath_ = utf8Path;
    netLogStatus_.enabled = true;
    netLogStatus_.opening = true;
    netLogStatus_.draining = false;
    netLogStatus_.error.clear();
    netLogCv_.notify_one();
    return true;
}

void Debugger::closeNetCaptureLogFile() {
    std::lock_guard lock(netLogMtx_);
    if (!netLogStatus_.enabled && !netLogStatus_.opening) return;
    NetLogWork work;
    work.kind = NetLogWork::Kind::Close;
    work.generation = ++netLogGeneration_;
    netLogQueue_.push_back(std::move(work));
    ++netLogQueuedControls_;
    netLogStatus_.enabled = false;
    netLogStatus_.opening = false;
    netLogStatus_.draining = true;
    netLogCv_.notify_one();
}

NetCaptureLogStatus Debugger::netCaptureLogStatus() {
    std::lock_guard lock(netLogMtx_);
    return netLogStatus_;
}

bool Debugger::netCaptureLogEnabled() {
    std::lock_guard lock(netLogMtx_);
    return netLogStatus_.enabled;
}

std::string Debugger::netCaptureLogPath() {
    std::lock_guard lock(netLogMtx_);
    return netLogPath_;
}

static const char* networkApiName(NetworkProbeApi api) {
    const NetworkProbeDescriptor* descriptor = NetworkProbeDescriptorFor(api);
    return descriptor ? descriptor->symbol : "network";
}

static const char* networkStageName(NetworkObservationStage stage) {
    switch (stage) {
        case NetworkObservationStage::NameResolution: return "resolve";
        case NetworkObservationStage::Connect: return "connect";
        case NetworkObservationStage::Request: return "request";
        case NetworkObservationStage::Response: return "response";
        case NetworkObservationStage::Send: return "send";
        case NetworkObservationStage::Receive: return "receive";
        case NetworkObservationStage::HandleClosed: return "close";
        case NetworkObservationStage::Limitation: return "limitation";
        case NetworkObservationStage::ProbeStatus: return "status";
    }
    return "status";
}

static const char* networkDirectionName(NetworkDirection direction) {
    switch (direction) {
        case NetworkDirection::Outbound: return "outbound";
        case NetworkDirection::Inbound: return "inbound";
        case NetworkDirection::None: return "none";
    }
    return "none";
}

void Debugger::pushNetworkEvent(NetworkObservationEvent&& event) {
    event.hostname = BoundNetworkText(std::move(event.hostname));
    event.ip = BoundNetworkText(std::move(event.ip));
    event.endpoint = BoundNetworkText(std::move(event.endpoint));
    event.method = BoundNetworkText(std::move(event.method));
    event.path = BoundNetworkText(std::move(event.path));
    event.object = BoundNetworkText(std::move(event.object));
    event.detail = BoundNetworkText(std::move(event.detail));
    event.runtimeModule = BoundNetworkText(std::move(event.runtimeModule));
    event.mappingEvidence = BoundNetworkText(std::move(event.mappingEvidence));
    if (event.payload.size() > kNetworkObservationPayloadCap) {
        event.payload.resize(kNetworkObservationPayloadCap);
        event.truncated = true;
    }
    std::lock_guard<std::mutex> lk(mtx_);
    if (!event.sessionGeneration) event.sessionGeneration = sessionGeneration_;
    if (!event.pid) event.pid = pid_;
    event.sequence = ++networkEventSequence_;
    auto payloadWouldExceed = [&]() {
        const uint64_t retained = networkPendingPayloadBytes_ +
                                  networkCoverage_.retainedPayloadBytes;
        return retained >= kNetworkObservationRetainedPayloadCap
             ? !event.payload.empty()
             : event.payload.size() > kNetworkObservationRetainedPayloadCap - retained;
    };
    while (!networkEvents_.empty() && payloadWouldExceed()) {
        networkCoverage_.payloadBytesDropped += networkEvents_.front().payload.size();
        networkCoverage_.retainedPayloadBytes -= networkEvents_.front().payload.size();
        networkEvents_.pop_front();
        ++networkCoverage_.eventsDropped;
    }
    if (payloadWouldExceed()) {
        const uint64_t retained = (std::min<uint64_t>)(
            kNetworkObservationRetainedPayloadCap,
            networkPendingPayloadBytes_ + networkCoverage_.retainedPayloadBytes);
        const size_t available = static_cast<size_t>(
            kNetworkObservationRetainedPayloadCap - retained);
        networkCoverage_.payloadBytesDropped += event.payload.size() - available;
        event.payload.resize(available);
        event.truncated = true;
    }
    while (networkEvents_.size() >= kNetworkObservationEventCap) {
        networkCoverage_.retainedPayloadBytes -= networkEvents_.front().payload.size();
        networkCoverage_.payloadBytesDropped += networkEvents_.front().payload.size();
        networkEvents_.pop_front();
        ++networkCoverage_.eventsDropped;
    }
    networkCoverage_.retainedPayloadBytes += event.payload.size();
    networkEvents_.push_back(std::move(event));
}
static void writeNetworkLogRecord(std::FILE* file, const NetworkObservationEvent& event,
                                  uint64_t timestamp) {
    FILETIME utc{static_cast<DWORD>(timestamp), static_cast<DWORD>(timestamp >> 32)}, local{};
    SYSTEMTIME st{};
    FileTimeToLocalFileTime(&utc, &local);
    FileTimeToSystemTime(&local, &st);
    const std::string port = event.portValid ? std::to_string(event.port) : "-";
    const uint32_t eventPid = event.pid;
    std::fprintf(file,
                 "=== %04u-%02u-%02u %02u:%02u:%02u.%03u stage=%s direction=%s api=%s pid=%u tid=%u handle=0x%llX host=%s ip=%s port=%s method=%s path=%s object=%s endpoint=%s detail=%s result=%lld raw_result=0x%llX result_valid=%u pointer_bits=%u requested=%llu requested_valid=%u transferred=%u transferred_valid=%u captured=%zu%s%s%s ===\n",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                 networkStageName(event.stage), networkDirectionName(event.direction),
                 networkApiName(event.api), eventPid, event.tid,
                 (unsigned long long)event.handle, event.hostname.c_str(), event.ip.c_str(),
                 port.c_str(), event.method.c_str(), event.path.c_str(), event.object.c_str(),
                 event.endpoint.c_str(), event.detail.c_str(), (long long)event.result,
                 (unsigned long long)event.rawResult, event.resultValid ? 1u : 0u,
                 static_cast<unsigned>(event.pointerWidthBits),
                 (unsigned long long)event.requestedBytes,
                 event.requestedBytesValid ? 1u : 0u, event.transferred,
                 event.transferredValid ? 1u : 0u,
                 event.payload.size(), event.truncated ? " truncated" : "",
                 event.asyncPartial ? " async-partial" : "",
                 event.payloadOpaque ? " opaque" : "");
    if (!event.payload.empty()) {
        std::fputs("TEXT:\n", file);
        writePrintablePayload(file, event.payload);
        std::fputs("HEX:\n", file);
        writeHexPayload(file, event.payload);
    }
    std::fputc('\n', file);
}

void Debugger::writeNetworkObservationLog(const NetworkObservationEvent& event) {
    std::lock_guard lock(netLogMtx_);
    if (!netLogStatus_.enabled || netLogShutdown_) return;
    if (event.payload.size() > kNetLogQueueBytes - sizeof(NetworkObservationEvent)) {
        ++netLogStatus_.droppedRecords;
        return;
    }
    size_t bytes = sizeof(NetworkObservationEvent) + event.payload.size();
    for (const auto* text : {&event.hostname, &event.ip, &event.endpoint, &event.method,
            &event.path, &event.object, &event.detail, &event.runtimeModule, &event.mappingEvidence}) {
        if (text->size() > kNetLogQueueBytes || bytes > kNetLogQueueBytes - text->size()) {
            ++netLogStatus_.droppedRecords;
            return;
        }
        bytes += text->size();
    }
    if (netLogStatus_.queuedRecords >= kNetLogQueueRecords ||
        bytes > kNetLogQueueBytes - netLogStatus_.queuedBytes) {
        ++netLogStatus_.droppedRecords;
        return;
    }
    NetLogWork work;
    work.event = event;
    work.event.pid = event.pid ? event.pid : pid_; // called only by the debug-event owner
    work.bytes = bytes;
    work.generation = netLogGeneration_;
    FILETIME now{};
    GetSystemTimeAsFileTime(&now);
    work.timestamp = (uint64_t(now.dwHighDateTime) << 32) | now.dwLowDateTime;
    netLogQueue_.push_back(std::move(work));
    ++netLogStatus_.queuedRecords;
    netLogStatus_.queuedBytes += bytes;
    netLogCv_.notify_one();
}

void Debugger::networkLogWorkerLoop() {
    std::FILE* file = nullptr; // accessed/closed exclusively by this worker
    uint64_t openGeneration = 0;
    auto closeFile = [&] {
        if (!file) return;
        SYSTEMTIME st{};
        GetLocalTime(&st);
        std::fprintf(file, "\n# stopped %04u-%02u-%02u %02u:%02u:%02u.%03u local\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        const bool failed = std::ferror(file) != 0;
        const int closed = std::fclose(file);
        file = nullptr;
        if (failed || closed != 0) {
            std::lock_guard lock(netLogMtx_);
            netLogStatus_.error = "network log could not be completely written to storage";
        }
    };
    for (;;) {
        NetLogWork work;
        {
            std::unique_lock lock(netLogMtx_);
            netLogCv_.wait(lock, [this] { return netLogShutdown_ || !netLogQueue_.empty(); });
            if (netLogQueue_.empty() && netLogShutdown_) break;
            work = std::move(netLogQueue_.front());
            netLogQueue_.pop_front();
            if (work.kind == NetLogWork::Kind::Record) {
                --netLogStatus_.queuedRecords;
                netLogStatus_.queuedBytes -= work.bytes;
            } else --netLogQueuedControls_;
        }
        if (work.kind == NetLogWork::Kind::Close) {
            closeFile();
            std::lock_guard lock(netLogMtx_);
            if (work.generation == netLogGeneration_) netLogStatus_.draining = false;
        } else if (work.kind == NetLogWork::Kind::Open) {
            closeFile();
            const auto path = widenUtf8(work.path);
            const bool opened = !path.empty() &&
                _wfopen_s(&file, path.c_str(), work.append ? L"ab" : L"wb") == 0 && file;
            if (opened) {
                openGeneration = work.generation;
                SYSTEMTIME st{};
                GetLocalTime(&st);
                std::fprintf(file,
                    "# DisasmStudio typed network observation log\n"
                    "# started %04u-%02u-%02u %02u:%02u:%02u.%03u local\n"
                    "# bounded asynchronous writer; queue drops are reported in Server Watch\n\n",
                    st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
            }
            std::lock_guard lock(netLogMtx_);
            if (work.generation == netLogGeneration_) {
                netLogStatus_.opening = false;
                netLogStatus_.enabled = opened;
                if (!opened) netLogStatus_.error = "could not open network log file: " + work.path;
            }
        } else if (file && work.generation == openGeneration) {
            writeNetworkLogRecord(file, work.event, work.timestamp);
            // Flushing is exclusively writer-owned. Even a stalled filesystem
            // cannot hold a debug-event/UI mutex or grow the bounded queue.
            if (std::fflush(file) != 0 || std::ferror(file)) {
                closeFile();
                std::lock_guard lock(netLogMtx_);
                if (work.generation == netLogGeneration_) {
                    netLogStatus_.enabled = false;
                    netLogStatus_.error = "network log write failed; logging stopped";
                }
                ++netLogStatus_.droppedRecords;
            }
        } else {
            std::lock_guard lock(netLogMtx_);
            ++netLogStatus_.droppedRecords;
        }
    }
    closeFile();
}

// Resolve exports from the debuggee's exact mapped modules. Probe metadata lives
// outside bps_, so it never appears in the analyst breakpoint list. A user bp can
// share the physical int3 and remains the owner/visible stop.
void Debugger::armNetTap() {
    if (!hProcess_) return;
    std::vector<DbgModule> modules;
    { std::lock_guard<std::mutex> lk(mtx_); modules = dbgModules_; }
    std::unordered_set<std::string> catalogBackedSpecs;
    std::vector<std::string> rejectedSpecs;
    for (const NetworkProbeDescriptor& spec : kNetworkProbeDescriptors) {
        if (!NetworkProbeDescriptorFor(spec.api)) continue;
        const auto catalog = LookupNetworkApi(spec.dll, spec.symbol);
        if (!catalog) {
            rejectedSpecs.push_back(std::string(spec.dll) + "!" + spec.symbol);
            continue;
        }
        catalogBackedSpecs.insert(catalog->dll + "!" + catalog->normalizedName);
    }
    auto targetExecutableImageAddress = [&](const DbgModule& module, uint64_t va) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (::VirtualQueryEx((HANDLE)hProcess_, reinterpret_cast<LPCVOID>(va), &mbi,
                             sizeof(mbi)) != sizeof(mbi) ||
            mbi.State != MEM_COMMIT || mbi.Type != MEM_IMAGE ||
            reinterpret_cast<uint64_t>(mbi.AllocationBase) != module.base ||
            va < module.base || (module.size && va - module.base >= module.size) ||
            (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
            return false;
        switch (mbi.Protect & 0xFFu) {
            case PAGE_EXECUTE:
            case PAGE_EXECUTE_READ:
            case PAGE_EXECUTE_READWRITE:
            case PAGE_EXECUTE_WRITECOPY: return true;
            default: return false;
        }
    };
    uint32_t available = 0, skipped = 0;
    for (const NetworkProbeDescriptor& spec : kNetworkProbeDescriptors) {
        if (!NetworkProbeDescriptorFor(spec.api)) continue;
        // Registration is fail-closed: a typo, wrong DLL, or future ad-hoc row
        // cannot become a live target mutation until it is cataloged exactly.
        if (!LookupNetworkApi(spec.dll, spec.symbol)) continue;
        auto module = std::find_if(modules.begin(), modules.end(), [&](const DbgModule& m) {
            return jvmdetail::baseNameLower(m.name) == spec.dll ||
                   jvmdetail::baseNameLower(m.path) == spec.dll;
        });
        if (module == modules.end() || !module->base || !module->size) continue;
        const uint64_t addr = resolveMappedExport(module->base, module->size, spec.symbol);
        if (!addr || !targetExecutableImageAddress(*module, addr)) continue;
        ++available;
        { std::lock_guard<std::mutex> lk(mtx_);
          if (networkProbeBps_.count(addr)) continue; }

        NetworkProbeBp probe;
        probe.api = spec.api;
        probe.moduleBase = module->base;
        bool conflict = false;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            if (auto user = bps_.find(addr); user != bps_.end() && user->second.armed) {
                probe.orig = user->second.orig;
                probe.ownsByte = false;
            } else if (bps_.count(addr)) {
                conflict = true;
            } else if (traceBps_.count(addr) || dllTargetBps_.count(addr) ||
                       antiTraps_.count(addr) || networkReturnBps_.count(addr) ||
                       authorizationBps_.count(addr) ||
                       authorizationReturnBps_.count(addr) ||
                       (runtimeTempBpAddr_ && *runtimeTempBpAddr_ == addr)) {
                conflict = true;
            }
        }
        if (conflict) { ++skipped; continue; }
        if (probe.ownsByte) {
            if (!readByteRPM((HANDLE)hProcess_, addr, probe.orig) || probe.orig == 0xCC ||
                !replaceByteIfEqual((HANDLE)hProcess_, addr, probe.orig, 0xCC)) {
                ++skipped;
                continue;
            }
        }
        {
            std::lock_guard<std::mutex> lk(mtx_);
            networkProbeBps_[addr] = probe;
            auto at = std::lower_bound(networkProbeBpAddrs_.begin(), networkProbeBpAddrs_.end(), addr);
            networkProbeBpAddrs_.insert(at, addr);
        }
    }
    std::string unsupportedCatalog =
        "Cataloged APIs without a live ABI decoder (not silently observed): ";
    bool hasUnsupportedCatalog = false;
    for (const NetworkApiMatch& api : EnumerateNetworkApis()) {
        if (catalogBackedSpecs.count(api.dll + "!" + api.normalizedName)) continue;
        if (hasUnsupportedCatalog) unsupportedCatalog += ", ";
        unsupportedCatalog += api.dll + "!" + api.canonicalName;
        hasUnsupportedCatalog = true;
    }
    {
        std::lock_guard<std::mutex> lk(mtx_);
        networkCoverage_.sessionGeneration = sessionGeneration_;
        networkCoverage_.pid = pid_;
        networkCoverage_.requested = networkObservationWant_.load();
        networkCoverage_.active = !networkProbeBps_.empty();
        networkCoverage_.wow64 = isWow64_.load();
        networkCoverage_.probesAvailable = available;
        networkCoverage_.probesArmed = static_cast<uint32_t>(networkProbeBps_.size());
        networkCoverage_.probesSkipped = skipped + static_cast<uint32_t>(rejectedSpecs.size());
        networkCoverage_.probesSharedWithUserBreakpoints = 0;
        networkCoverage_.winsock = networkCoverage_.nameResolution = false;
        networkCoverage_.winHttp = networkCoverage_.winInet = networkCoverage_.urlMon = false;
        for (const auto& [ignored, probe] : networkProbeBps_) {
            (void)ignored;
            if (!probe.ownsByte) ++networkCoverage_.probesSharedWithUserBreakpoints;
            if (probe.api >= NetworkProbeApi::ResolveAddrInfoA &&
                probe.api <= NetworkProbeApi::DnsQueryUtf8)
                networkCoverage_.nameResolution = true;
            if ((probe.api >= NetworkProbeApi::ResolveAddrInfoA &&
                 probe.api <= NetworkProbeApi::GetNameInfoW) ||
                (probe.api >= NetworkProbeApi::Connect &&
                 probe.api <= NetworkProbeApi::CloseSocket))
                networkCoverage_.winsock = true;
            if (probe.api >= NetworkProbeApi::WinHttpOpen && probe.api <= NetworkProbeApi::WinHttpCloseHandle)
                networkCoverage_.winHttp = true;
            if (probe.api >= NetworkProbeApi::InternetOpenA && probe.api <= NetworkProbeApi::InternetCloseHandle)
                networkCoverage_.winInet = true;
            if (probe.api >= NetworkProbeApi::UrlDownloadToFileA &&
                probe.api <= NetworkProbeApi::UrlOpenBlockingStreamW)
                networkCoverage_.urlMon = true;
        }
        networkCoverage_.payloads = networkCoverage_.winsock || networkCoverage_.winHttp || networkCoverage_.winInet;
        networkCoverage_.limitations = {
            "Custom TLS stacks and raw Winsock TLS payloads remain opaque encrypted bytes.",
            "Overlapped/asynchronous receive completion can outlive the API return and is reported as partial.",
            "Direct syscalls, custom/inlined network stacks, kernel traffic, and child processes are not observed.",
            "API entry probes briefly restore one instruction under debugger-controlled peer suspension.",
        };
        if (hasUnsupportedCatalog)
            networkCoverage_.limitations.push_back(std::move(unsupportedCatalog));
        if (networkCoverage_.handleStatesDropped)
            networkCoverage_.limitations.push_back(
                "HTTP/socket handle-lineage state exceeded the 4,096-record cap; some descendant metadata is unavailable.");
        if (!rejectedSpecs.empty()) {
            std::string rejected = "Live probe specs rejected by exact network catalog guard: ";
            for (size_t i = 0; i < rejectedSpecs.size(); ++i) {
                if (i) rejected += ", ";
                rejected += rejectedSpecs[i];
            }
            networkCoverage_.limitations.push_back(std::move(rejected));
        }
        netTapArmed_ = !networkProbeBps_.empty();
    }
}

void Debugger::disarmNetTap() {
    if (hProcess_) {
        std::vector<std::pair<uint64_t, NetworkProbeBp>> probes;
        std::vector<std::pair<uint64_t, NetworkReturnBp>> returns;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            probes.assign(networkProbeBps_.begin(), networkProbeBps_.end());
            returns.assign(networkReturnBps_.begin(), networkReturnBps_.end());
            networkProbeBps_.clear(); networkProbeBpAddrs_.clear();
            networkReturnBps_.clear(); networkReturnBpAddrs_.clear();
            networkCoverage_.active = false;
            networkCoverage_.probesArmed = 0;
        }
        for (const auto& [addr, probe] : probes)
            if (probe.ownsByte) (void)replaceByteIfEqual((HANDLE)hProcess_, addr, 0xCC, probe.orig);
        for (const auto& [addr, site] : returns)
            if (site.ownsByte) (void)replaceByteIfEqual((HANDLE)hProcess_, addr, 0xCC, site.orig);
    }
    networkPendingReturns_.clear();
    { std::lock_guard<std::mutex> lk(mtx_); networkPendingPayloadBytes_ = 0; }
    networkHandleLineage_.clear();
    netTapArmed_ = false;
}

void Debugger::retireNetworkModule(uint64_t base, uint64_t size) {
    if (!base) return;
    std::lock_guard<std::mutex> lk(mtx_);
    for (auto it = networkProbeBps_.begin(); it != networkProbeBps_.end(); ) {
        if (it->second.moduleBase == base) it = networkProbeBps_.erase(it);
        else ++it;
    }
    networkProbeBpAddrs_.clear();
    for (const auto& [addr, ignored] : networkProbeBps_) {
        (void)ignored; networkProbeBpAddrs_.push_back(addr);
    }
    std::sort(networkProbeBpAddrs_.begin(), networkProbeBpAddrs_.end());
    if (!size) {
        // With no image extent, address-range retirement would risk deleting
        // unrelated higher mappings. Drop all in-flight returns without writing
        // any possibly reused VA; loaded entry probes will be re-evaluated below.
        networkPendingReturns_.clear();
        networkPendingPayloadBytes_ = 0;
        networkReturnBps_.clear();
    }
    for (auto it = networkReturnBps_.begin(); it != networkReturnBps_.end(); ) {
        if (size && it->first >= base && it->first - base < size) {
            (void)networkPendingReturns_.eraseAddress(it->first,
                [&](const NetworkPendingFrame& frame) {
                    networkPendingPayloadBytes_ -= (std::min<uint64_t>)(
                        networkPendingPayloadBytes_, frame.payload.size());
                });
            it = networkReturnBps_.erase(it);
        } else ++it;
    }
    networkReturnBpAddrs_.clear();
    for (const auto& [addr, ignored] : networkReturnBps_) {
        (void)ignored; networkReturnBpAddrs_.push_back(addr);
    }
    std::sort(networkReturnBpAddrs_.begin(), networkReturnBpAddrs_.end());
    networkCoverage_.probesArmed = static_cast<uint32_t>(networkProbeBps_.size());
    networkCoverage_.active = !networkProbeBps_.empty();
    netTapArmed_ = !networkProbeBps_.empty();
}

bool Debugger::disarmNetworkProbe(uint64_t addr) {
    NetworkProbeBp probe;
    { std::lock_guard<std::mutex> lk(mtx_);
      auto it = networkProbeBps_.find(addr); if (it == networkProbeBps_.end()) return false;
      probe = it->second; it->second.armed = false; }
    return !probe.ownsByte || replaceByteIfEqual((HANDLE)hProcess_, addr, 0xCC, probe.orig);
}

bool Debugger::rearmNetworkProbe(uint64_t addr) {
    NetworkProbeBp probe;
    { std::lock_guard<std::mutex> lk(mtx_);
      auto it = networkProbeBps_.find(addr); if (it == networkProbeBps_.end()) return false;
      probe = it->second; }
    const bool ok = !probe.ownsByte || replaceByteIfEqual((HANDLE)hProcess_, addr, probe.orig, 0xCC);
    if (ok) { std::lock_guard<std::mutex> lk(mtx_); if (auto it = networkProbeBps_.find(addr); it != networkProbeBps_.end()) it->second.armed = true; }
    return ok;
}

bool Debugger::rearmNetworkReturn(uint64_t addr) {
    NetworkReturnBp site;
    { std::lock_guard<std::mutex> lk(mtx_);
      auto it = networkReturnBps_.find(addr); if (it == networkReturnBps_.end()) return false;
      site = it->second; }
    const bool ok = !site.ownsByte || replaceByteIfEqual((HANDLE)hProcess_, addr, site.orig, 0xCC);
    if (ok) {
        std::lock_guard<std::mutex> lk(mtx_);
        if (auto it = networkReturnBps_.find(addr); it != networkReturnBps_.end())
            it->second.armed = true;
    }
    return ok;
}

static std::string readNetworkAnsi(HANDLE process, uint64_t address,
                                   size_t maxChars = kNetworkObservationTextCap,
                                   bool* hitLimit = nullptr) {
    std::string value;
    if (hitLimit) *hitLimit = false;
    if (!address) return value;
    value.reserve(128);
    maxChars = (std::min)(maxChars, kNetworkObservationTextCap);
    bool terminated = false;
    for (size_t i = 0; i < maxChars; ++i) {
        char ch = 0;
        if (!readRemoteExact(process, address + i, &ch, sizeof(ch))) break;
        if (!ch) { terminated = true; break; }
        value.push_back(ch);
    }
    if (hitLimit) *hitLimit = maxChars != 0 && value.size() == maxChars && !terminated;
    return value;
}

static std::string readNetworkWide(HANDLE process, uint64_t address,
                                   size_t maxChars = kNetworkObservationTextCap,
                                   bool* hitLimit = nullptr) {
    std::vector<wchar_t> wide;
    if (hitLimit) *hitLimit = false;
    if (!address) return {};
    wide.reserve(128);
    maxChars = (std::min)(maxChars, kNetworkObservationTextCap);
    bool terminated = false;
    for (size_t i = 0; i < maxChars; ++i) {
        uint16_t unit = 0;
        if (!readRemoteExact(process, address + i * 2u, &unit, sizeof(unit))) break;
        if (!unit) { terminated = true; break; }
        wide.push_back(static_cast<wchar_t>(unit));
    }
    if (hitLimit) *hitLimit = maxChars != 0 && wide.size() == maxChars && !terminated;
    if (wide.empty()) return {};
    const int count = WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
                                          nullptr, 0, nullptr, nullptr);
    if (count <= 0) return {};
    std::string value(static_cast<size_t>(count), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
                        value.data(), count, nullptr, nullptr);
    return BoundNetworkText(std::move(value));
}

static std::vector<uint8_t> readNetworkPayload(HANDLE process, uint64_t address,
                                                uint64_t length) {
    std::vector<uint8_t> payload;
    const size_t take = static_cast<size_t>((std::min<uint64_t>)(
        length, kNetworkObservationPayloadCap));
    if (!address || !take) return payload;
    payload.resize(take);
    SIZE_T got = 0;
    if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address), payload.data(), take, &got) || !got) {
        payload.clear();
        return payload;
    }
    payload.resize(static_cast<size_t>(got));
    return payload;
}

static std::vector<uint8_t> readNetworkWsabufs(HANDLE process, bool wow64,
                                               uint64_t buffers, uint64_t count,
                                               uint64_t byteLimit = UINT64_MAX,
                                               uint64_t* describedBytes = nullptr,
                                               bool* truncated = nullptr,
                                               bool* describedBytesValid = nullptr) {
    std::vector<uint8_t> payload;
    const size_t stride = wow64 ? 8u : 16u;
    const uint64_t originalCount = count;
    count = (std::min<uint64_t>)(count, 16u);
    uint64_t described = 0;
    uint64_t processed = 0;
    bool wasTruncated = originalCount > count;
    for (uint64_t i = 0; i < count; ++i) {
        uint8_t descriptor[16]{};
        if (!readRemoteExact(process, buffers + i * stride, descriptor, stride)) {
            wasTruncated = true;
            break;
        }
        uint32_t length = 0;
        std::memcpy(&length, descriptor, sizeof(length));
        ++processed;
        described = UINT64_MAX - described < length ? UINT64_MAX : described + length;
        uint64_t pointer = 0;
        if (wow64) {
            uint32_t narrow = 0;
            std::memcpy(&narrow, descriptor + 4, sizeof(narrow));
            pointer = narrow;
        } else {
            std::memcpy(&pointer, descriptor + 8, sizeof(pointer));
        }
        const uint64_t available = kNetworkObservationPayloadCap - payload.size();
        const uint64_t take = (std::min<uint64_t>)((std::min<uint64_t>)(length, available), byteLimit);
        if (!take) {
            if (length) wasTruncated = true;
            continue;
        }
        std::vector<uint8_t> part = readNetworkPayload(process, pointer, take);
        payload.insert(payload.end(), part.begin(), part.end());
        if (part.size() < take) { wasTruncated = true; break; }
        if (take < length) wasTruncated = true;
        byteLimit -= take;
    }
    if (processed < count) wasTruncated = true;
    if (payload.size() == kNetworkObservationPayloadCap && described > payload.size())
        wasTruncated = true;
    if (describedBytes) *describedBytes = described;
    if (truncated) *truncated = wasTruncated;
    if (describedBytesValid)
        *describedBytesValid = originalCount <= 16u && processed == originalCount &&
                               described != UINT64_MAX;
    return payload;
}

static bool readInternetBuffer(HANDLE process, bool wow64, uint64_t descriptor,
                               uint64_t& buffer, uint32_t& length,
                               uint64_t* headers = nullptr,
                               uint32_t* headersLength = nullptr) {
    buffer = 0;
    length = 0;
    if (headers) *headers = 0;
    if (headersLength) *headersLength = 0;
    const size_t size = wow64 ? 40u : 56u;
    std::array<uint8_t, 56> bytes{};
    if (!descriptor || !readRemoteExact(process, descriptor, bytes.data(), size)) return false;
    uint32_t structureSize = 0;
    std::memcpy(&structureSize, bytes.data(), sizeof(structureSize));
    if (structureSize < size) return false;
    if (wow64) {
        uint32_t pointer = 0;
        std::memcpy(&pointer, bytes.data() + 20, sizeof(pointer));
        buffer = pointer;
        std::memcpy(&length, bytes.data() + 24, sizeof(length));
        if (headers) {
            std::memcpy(&pointer, bytes.data() + 8, sizeof(pointer));
            *headers = pointer;
        }
        if (headersLength)
            std::memcpy(headersLength, bytes.data() + 12, sizeof(*headersLength));
    } else {
        std::memcpy(&buffer, bytes.data() + 32, sizeof(buffer));
        std::memcpy(&length, bytes.data() + 40, sizeof(length));
        if (headers) std::memcpy(headers, bytes.data() + 16, sizeof(*headers));
        if (headersLength)
            std::memcpy(headersLength, bytes.data() + 24, sizeof(*headersLength));
    }
    return true;
}

static std::string readNetworkHostent(HANDLE process, bool wow64, uint64_t address,
                                      std::string* firstIp = nullptr) {
    if (firstIp) firstIp->clear();
    if (!address) return {};
    const uint64_t typeAt = address + (wow64 ? 8u : 16u);
    const uint64_t lengthAt = typeAt + 2u;
    const uint64_t listAt = address + (wow64 ? 12u : 24u);
    uint16_t family = 0, addressLength = 0;
    if (!readRemoteExact(process, typeAt, &family, sizeof(family)) ||
        !readRemoteExact(process, lengthAt, &addressLength, sizeof(addressLength))) return {};
    const NetworkCallContext pointerContext{wow64, 0, {}};
    const NetworkMemoryReader read = [process](uint64_t at, void* out, size_t size) {
        return readRemoteExact(process, at, out, size);
    };
    uint64_t list = 0;
    if (!ReadNetworkPointer(pointerContext, read, listAt, list)) return {};
    std::string endpoints;
    const uint64_t pointerSize = wow64 ? 4u : 8u;
    for (size_t i = 0; list && i < 8; ++i) {
        uint64_t item = 0;
        if (!ReadNetworkPointer(pointerContext, read, list + i * pointerSize, item) || !item) break;
        std::string one;
        if (family == 2 && addressLength >= 4) {
            uint8_t bytes[4]{};
            if (readRemoteExact(process, item, bytes, sizeof(bytes))) one = FormatIpv4Address(bytes);
        } else if (family == 23 && addressLength >= 16) {
            uint8_t bytes[16]{};
            if (readRemoteExact(process, item, bytes, sizeof(bytes))) one = FormatIpv6Address(bytes);
        }
        if (!one.empty()) {
            if (firstIp && firstIp->empty()) *firstIp = one;
            if (!endpoints.empty()) endpoints += ", ";
            endpoints += one;
        }
    }
    return BoundNetworkText(std::move(endpoints));
}

static std::string readNetworkSockaddr(HANDLE process, uint64_t address, uint64_t length,
                                       std::string* ip = nullptr, uint16_t* port = nullptr,
                                       bool* portValid = nullptr) {
    if (ip) ip->clear();
    if (port) *port = 0;
    if (portValid) *portValid = false;
    const size_t take = static_cast<size_t>((std::min<uint64_t>)(length, 128u));
    if (!address || take < 2) return {};
    std::array<uint8_t, 128> bytes{};
    if (!readRemoteExact(process, address, bytes.data(), take)) return {};
    NetworkEndpointParts parts;
    if (!DecodeNetworkSockaddr(bytes.data(), take, parts)) return {};
    if (ip) *ip = parts.ip;
    if (port) *port = parts.port;
    if (portValid) *portValid = parts.portValid;
    return parts.endpoint;
}

static std::string formatNetworkHostPort(const std::string& host, uint16_t port,
                                         bool portValid) {
    if (host.empty()) return {};
    if (!portValid) return host;
    if (host.find(':') != std::string::npos && host.front() != '[')
        return "[" + host + "]:" + std::to_string(port);
    return host + ":" + std::to_string(port);
}

void Debugger::decorateNetworkEvent(NetworkObservationEvent& event) {
    if (!event.caller || !hProcess_) return;
    DbgModule module;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = std::find_if(dbgModules_.begin(), dbgModules_.end(), [&](const DbgModule& candidate) {
            return candidate.base && candidate.size && event.caller >= candidate.base &&
                   event.caller - candidate.base < candidate.size;
        });
        if (it == dbgModules_.end()) return;
        module = *it;
    }
    event.runtimeModule = module.name.empty() ? module.path : module.name;
    event.runtimeModuleBase = module.base;
    event.runtimeModuleLoadGeneration = module.loadGeneration;

    IMAGE_DOS_HEADER dos{};
    DWORD signature = 0;
    IMAGE_FILE_HEADER file{};
    uint32_t sizeOfHeaders = 0;
    if (!readRemoteExact((HANDLE)hProcess_, module.base, &dos, sizeof(dos)) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 || dos.e_lfanew > 0x100000 ||
        !readRemoteExact((HANDLE)hProcess_, module.base + dos.e_lfanew, &signature, sizeof(signature)) ||
        signature != IMAGE_NT_SIGNATURE ||
        !readRemoteExact((HANDLE)hProcess_, module.base + dos.e_lfanew + 4, &file, sizeof(file)) ||
        !file.NumberOfSections || file.NumberOfSections > 96 || file.SizeOfOptionalHeader < 64 ||
        !readRemoteExact((HANDLE)hProcess_, module.base + dos.e_lfanew + 24 + 60,
                         &sizeOfHeaders, sizeof(sizeOfHeaders)))
        return;

    const uint64_t rva = event.caller - module.base;
    if (rva < sizeOfHeaders) {
        event.fileOffset = rva;
        event.fileOffsetValid = true;
        event.mappingEvidence =
            "observed live PE header projection (backing-file identity/extent not proven)";
        event.evidenceQuality = NetworkEvidenceQuality::Observed;
        return;
    }
    const uint64_t sectionsAt = module.base + dos.e_lfanew + 24 + file.SizeOfOptionalHeader;
    std::vector<IMAGE_SECTION_HEADER> sections(file.NumberOfSections);
    if (!readRemoteExact((HANDLE)hProcess_, sectionsAt, sections.data(),
                         sections.size() * sizeof(IMAGE_SECTION_HEADER)))
        return;
    for (const IMAGE_SECTION_HEADER& section : sections) {
        const uint64_t start = section.VirtualAddress;
        const uint64_t rawSize = section.SizeOfRawData;
        if (!rawSize || rva < start || rva - start >= rawSize) continue;
        const uint64_t delta = rva - start;
        if (section.PointerToRawData > UINT64_MAX - delta) return;
        event.fileOffset = section.PointerToRawData + delta;
        event.fileOffsetValid = true;
        event.mappingEvidence =
            "observed live PE section projection (backing-file identity/extent not proven)";
        event.evidenceQuality = NetworkEvidenceQuality::Observed;
        return;
    }
    event.mappingEvidence = "caller is in a live image range without file-backed raw bytes";
}

// Decode the stopped call in the target ABI, retain nested return state per thread,
// and plant a shared physical return site only when the result/buffer is needed.
void Debugger::netTapCapture(uint64_t /*addr*/, uint32_t tid, NetworkProbeApi api) {
    auto th = threads_.find(tid);
    if (th == threads_.end()) return;
    Registers r;
    if (!ctxReadFull(th->second, r)) return;
    HANDLE hp = (HANDLE)hProcess_;
    const bool wow64 = isWow64_.load();
    const NetworkCallContext context{ wow64, r.rsp, { r.rcx, r.rdx, r.r8, r.r9 } };
    const NetworkMemoryReader read = [hp](uint64_t address, void* out, size_t size) {
        return readRemoteExact(hp, address, out, size);
    };
    NetworkPendingFrame frame;
    frame.api = api;
    frame.wide = api == NetworkProbeApi::ResolveAddrInfoW ||
                 api == NetworkProbeApi::GetAddrInfoExW ||
                 api == NetworkProbeApi::GetNameInfoW ||
                 api == NetworkProbeApi::DnsQueryW ||
                 api == NetworkProbeApi::InternetOpenW ||
                 api == NetworkProbeApi::InternetConnectW ||
                 api == NetworkProbeApi::HttpOpenRequestW ||
                 api == NetworkProbeApi::HttpAddRequestHeadersW ||
                 api == NetworkProbeApi::HttpSendRequestW ||
                 api == NetworkProbeApi::HttpSendRequestExW ||
                 api == NetworkProbeApi::HttpEndRequestW ||
                 api == NetworkProbeApi::InternetOpenUrlW ||
                 api == NetworkProbeApi::InternetReadFileExW ||
                 api == NetworkProbeApi::HttpQueryInfoW ||
                 api == NetworkProbeApi::UrlDownloadToFileW ||
                 api == NetworkProbeApi::UrlDownloadToCacheFileW ||
                 api == NetworkProbeApi::UrlOpenStreamW ||
                 api == NetworkProbeApi::UrlOpenBlockingStreamW;
    (void)ReadNetworkReturnAddress(context, read, frame.returnAddress);
    frame.caller = frame.returnAddress;
    for (size_t i = 0; i < frame.args.size(); ++i)
        (void)ReadNetworkArgument(context, i, read, frame.args[i]);
    // Win64 stack home slots are 64-bit, but the high half is unspecified for
    // DWORD/ULONG/int arguments. Normalize scalar ABI values before any bounds
    // decision; handles, pointers, and callback/context values stay full-width.
    const auto argU32 = [&](size_t index) {
        return static_cast<uint32_t>(frame.args[index]);
    };
    const auto argI32 = [&](size_t index) {
        return static_cast<int32_t>(argU32(index));
    };
    const auto positiveI32Length = [&](size_t index) -> uint32_t {
        const int32_t value = argI32(index);
        return value > 0 ? static_cast<uint32_t>(value) : 0u;
    };
    frame.handle = frame.args[0];
    // Session async mode is inherited by connection/request handles. Capture it
    // at entry so async read/write returns never inspect completion-owned output.
    frame.async = networkHandleLineage_.resolve(frame.handle).async;

    auto queueReturn = [&](NetworkPendingFrame pending) {
        if (!pending.returnAddress) return false;
        const uint64_t returnAddress = pending.returnAddress;
        const bool first = networkPendingReturns_.references(returnAddress) == 0;
        if (first) {
            NetworkReturnBp site;
            bool conflict = false;
            {
                std::lock_guard<std::mutex> lk(mtx_);
                if (auto user = bps_.find(returnAddress);
                    user != bps_.end() && user->second.armed) {
                    site.orig = user->second.orig;
                    site.ownsByte = false;
                } else if (bps_.count(returnAddress)) {
                    conflict = true;
                } else if (networkProbeBps_.count(returnAddress) || traceBps_.count(returnAddress) ||
                           dllTargetBps_.count(returnAddress) || antiTraps_.count(returnAddress) ||
                           authorizationBps_.count(returnAddress) ||
                           authorizationReturnBps_.count(returnAddress) ||
                           (runtimeTempBpAddr_ && *runtimeTempBpAddr_ == returnAddress)) {
                    conflict = true;
                }
            }
            if (conflict || (site.ownsByte &&
                (!readByteRPM(hp, returnAddress, site.orig) || site.orig == 0xCC ||
                 !replaceByteIfEqual(hp, returnAddress, site.orig, 0xCC)))) {
                std::lock_guard<std::mutex> lk(mtx_);
                ++networkCoverage_.pendingReturnsDropped;
                return false;
            }
            {
                std::lock_guard<std::mutex> lk(mtx_);
                networkReturnBps_[returnAddress] = site;
                auto at = std::lower_bound(networkReturnBpAddrs_.begin(), networkReturnBpAddrs_.end(),
                                           returnAddress);
                networkReturnBpAddrs_.insert(at, returnAddress);
            }
        }
        const size_t pendingPayload = pending.payload.size();
        if (pendingPayload) {
            std::lock_guard<std::mutex> lk(mtx_);
            auto wouldExceed = [&]() {
                const uint64_t retained = networkPendingPayloadBytes_ +
                                          networkCoverage_.retainedPayloadBytes;
                return retained >= kNetworkObservationRetainedPayloadCap ||
                       pending.payload.size() >
                           kNetworkObservationRetainedPayloadCap - retained;
            };
            while (!networkEvents_.empty() && wouldExceed()) {
                networkCoverage_.payloadBytesDropped += networkEvents_.front().payload.size();
                networkCoverage_.retainedPayloadBytes -= networkEvents_.front().payload.size();
                networkEvents_.pop_front();
                ++networkCoverage_.eventsDropped;
            }
            const uint64_t retained = (std::min<uint64_t>)(
                kNetworkObservationRetainedPayloadCap,
                networkPendingPayloadBytes_ + networkCoverage_.retainedPayloadBytes);
            const size_t available = static_cast<size_t>(
                kNetworkObservationRetainedPayloadCap - retained);
            if (pending.payload.size() > available) {
                networkCoverage_.payloadBytesDropped += pending.payload.size() - available;
                pending.payload.resize(available);
                pending.payloadTruncated = true;
            }
        }
        const size_t admittedPayload = pending.payload.size();
        if (networkPendingReturns_.push(tid, returnAddress, std::move(pending))) {
            if (admittedPayload) {
                std::lock_guard<std::mutex> lk(mtx_);
                networkPendingPayloadBytes_ += admittedPayload;
            }
            return true;
        }
        if (first) {
            NetworkReturnBp site;
            {
                std::lock_guard<std::mutex> lk(mtx_);
                auto it = networkReturnBps_.find(returnAddress);
                if (it != networkReturnBps_.end()) { site = it->second; networkReturnBps_.erase(it); }
                auto at = std::lower_bound(networkReturnBpAddrs_.begin(), networkReturnBpAddrs_.end(),
                                           returnAddress);
                if (at != networkReturnBpAddrs_.end() && *at == returnAddress)
                    networkReturnBpAddrs_.erase(at);
                ++networkCoverage_.pendingReturnsDropped;
            }
            if (site.ownsByte) (void)replaceByteIfEqual(hp, returnAddress, 0xCC, site.orig);
        } else {
            std::lock_guard<std::mutex> lk(mtx_);
            ++networkCoverage_.pendingReturnsDropped;
        }
        return false;
    };

    switch (api) {
        case NetworkProbeApi::ResolveAddrInfoA:
        case NetworkProbeApi::ResolveAddrInfoW:
            frame.hostname = frame.wide ? readNetworkWide(hp, frame.args[0])
                                        : readNetworkAnsi(hp, frame.args[0]);
            frame.detail = frame.wide ? readNetworkWide(hp, frame.args[1])
                                      : readNetworkAnsi(hp, frame.args[1]);
            frame.buffer = frame.args[3]; // addrinfo**
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::GetAddrInfoExA:
        case NetworkProbeApi::GetAddrInfoExW:
            frame.hostname = frame.wide ? readNetworkWide(hp, frame.args[0])
                                        : readNetworkAnsi(hp, frame.args[0]);
            frame.detail = frame.wide ? readNetworkWide(hp, frame.args[1])
                                      : readNetworkAnsi(hp, frame.args[1]);
            frame.buffer = frame.args[5]; // ADDRINFOEX**
            frame.async = frame.args[7] != 0 || frame.args[8] != 0;
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::GetHostByName:
            frame.hostname = readNetworkAnsi(hp, frame.args[0]);
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::GetNameInfoA:
        case NetworkProbeApi::GetNameInfoW: {
            frame.endpoint = readNetworkSockaddr(hp, frame.args[0], positiveI32Length(1),
                                                 &frame.ip, &frame.port,
                                                 &frame.portValid);
            frame.buffer = frame.args[2];
            frame.countOrLength = argU32(3);
            frame.transferredPtr = frame.args[4]; // service-name buffer
            frame.addressLengthPtr = argU32(5); // service-name character capacity
            (void)queueReturn(std::move(frame));
            return;
        }
        case NetworkProbeApi::DnsQueryA:
        case NetworkProbeApi::DnsQueryW:
        case NetworkProbeApi::DnsQueryUtf8:
            frame.hostname = frame.wide ? readNetworkWide(hp, frame.args[0])
                                        : readNetworkAnsi(hp, frame.args[0]);
            frame.countOrLength = static_cast<uint16_t>(frame.args[1]); // DNS record type
            frame.buffer = frame.args[4];        // DNS_RECORD**
            frame.detail = "DNS record type " +
                           std::to_string(static_cast<uint16_t>(frame.countOrLength));
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::Connect:
        case NetworkProbeApi::WSAConnect:
            frame.endpoint = readNetworkSockaddr(hp, frame.args[1], positiveI32Length(2),
                                                 &frame.ip, &frame.port,
                                                 &frame.portValid);
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::CloseSocket:
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::Send:
        case NetworkProbeApi::SendTo: {
            const int32_t requested = argI32(2);
            frame.requestedLengthValid = requested >= 0;
            frame.requestedLength = requested >= 0 ? static_cast<uint32_t>(requested) : 0u;
            frame.payload = readNetworkPayload(hp, frame.args[1], frame.requestedLength);
            frame.payloadTruncated = frame.payload.size() < frame.requestedLength;
            if (api == NetworkProbeApi::SendTo)
                frame.endpoint = readNetworkSockaddr(hp, frame.args[4], positiveI32Length(5),
                                                     &frame.ip, &frame.port,
                                                     &frame.portValid);
            (void)queueReturn(std::move(frame));
            return;
        }
        case NetworkProbeApi::WSASend:
        case NetworkProbeApi::WSASendTo:
            frame.buffers = frame.args[1];
            frame.countOrLength = argU32(2);
            frame.transferredPtr = frame.args[3];
            frame.payload = readNetworkWsabufs(hp, wow64, frame.buffers,
                                               frame.countOrLength, UINT64_MAX,
                                               &frame.requestedLength,
                                               &frame.payloadTruncated,
                                               &frame.requestedLengthValid);
            if (api == NetworkProbeApi::WSASendTo)
                frame.endpoint = readNetworkSockaddr(hp, frame.args[5], positiveI32Length(6),
                                                     &frame.ip, &frame.port,
                                                     &frame.portValid);
            frame.async = frame.args[NetworkOverlappedArgumentIndex(api)] != 0;
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::Recv:
        case NetworkProbeApi::RecvFrom: {
            frame.buffer = frame.args[1];
            const int32_t requested = argI32(2);
            frame.requestedLengthValid = requested >= 0;
            frame.countOrLength = requested >= 0 ? static_cast<uint32_t>(requested) : 0u;
            frame.requestedLength = frame.countOrLength;
            if (api == NetworkProbeApi::RecvFrom) {
                frame.addressPtr = frame.args[4];
                frame.addressLengthPtr = frame.args[5];
            }
            (void)queueReturn(std::move(frame));
            return;
        }
        case NetworkProbeApi::WSARecv:
        case NetworkProbeApi::WSARecvFrom:
            frame.buffers = frame.args[1];
            frame.countOrLength = argU32(2);
            frame.transferredPtr = frame.args[3];
            (void)readNetworkWsabufs(hp, wow64, frame.buffers,
                                     frame.countOrLength, 0,
                                     &frame.requestedLength, nullptr,
                                     &frame.requestedLengthValid);
            if (api == NetworkProbeApi::WSARecvFrom) {
                frame.addressPtr = frame.args[5];
                frame.addressLengthPtr = frame.args[6];
            }
            frame.async = frame.args[NetworkOverlappedArgumentIndex(api)] != 0;
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::WinHttpOpen:
            frame.handle = 0;
            frame.detail = readNetworkWide(hp, frame.args[0]);
            frame.async = NetworkHttpSessionIsAsync(argU32(4));
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::InternetOpenA:
        case NetworkProbeApi::InternetOpenW:
            frame.handle = 0;
            frame.detail = frame.wide ? readNetworkWide(hp, frame.args[0])
                                      : readNetworkAnsi(hp, frame.args[0]);
            frame.async = NetworkHttpSessionIsAsync(argU32(4));
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::WinHttpConnect:
            frame.hostname = readNetworkWide(hp, frame.args[1]);
            frame.port = static_cast<uint16_t>(frame.args[2]);
            frame.portValid = true; // INTERNET_PORT is a 16-bit value, including valid zero.
            if (NetworkLooksLikeIp(frame.hostname)) frame.ip = frame.hostname;
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::InternetConnectA:
        case NetworkProbeApi::InternetConnectW:
            frame.hostname = frame.wide ? readNetworkWide(hp, frame.args[1])
                                        : readNetworkAnsi(hp, frame.args[1]);
            frame.port = static_cast<uint16_t>(frame.args[2]);
            frame.portValid = true; // INTERNET_PORT is a 16-bit value, including valid zero.
            if (NetworkLooksLikeIp(frame.hostname)) frame.ip = frame.hostname;
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::WinHttpOpenRequest:
        case NetworkProbeApi::HttpOpenRequestA:
        case NetworkProbeApi::HttpOpenRequestW:
            frame.parent = frame.args[0];
            frame.method = api == NetworkProbeApi::WinHttpOpenRequest || frame.wide
                         ? readNetworkWide(hp, frame.args[1]) : readNetworkAnsi(hp, frame.args[1]);
            frame.object = api == NetworkProbeApi::WinHttpOpenRequest || frame.wide
                         ? readNetworkWide(hp, frame.args[2]) : readNetworkAnsi(hp, frame.args[2]);
            frame.path = frame.object;
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::WinHttpAddRequestHeaders:
        case NetworkProbeApi::HttpAddRequestHeadersA:
        case NetworkProbeApi::HttpAddRequestHeadersW: {
            const uint32_t headerChars = static_cast<uint32_t>(frame.args[2]);
            const size_t headerLimit = headerChars == UINT32_MAX
                                     ? kNetworkObservationTextCap : headerChars;
            bool headerHitLimit = false;
            frame.detail = api == NetworkProbeApi::WinHttpAddRequestHeaders || frame.wide
                         ? readNetworkWide(hp, frame.args[1], headerLimit, &headerHitLimit)
                         : readNetworkAnsi(hp, frame.args[1], headerLimit, &headerHitLimit);
            frame.payloadTruncated = (headerChars != UINT32_MAX &&
                                      headerChars > kNetworkObservationTextCap) ||
                                     (headerChars == UINT32_MAX && headerHitLimit);
            (void)queueReturn(std::move(frame));
            return;
        }
        case NetworkProbeApi::InternetOpenUrlA:
        case NetworkProbeApi::InternetOpenUrlW:
            frame.parent = frame.args[0];
            frame.object = frame.wide ? readNetworkWide(hp, frame.args[1])
                                      : readNetworkAnsi(hp, frame.args[1]);
            {
                NetworkUrlParts url;
                if (ParseNetworkUrl(frame.object, url)) {
                    frame.hostname = std::move(url.hostname);
                    frame.ip = std::move(url.ip);
                    frame.port = url.port;
                    frame.portValid = url.portValid;
                    frame.path = std::move(url.path);
                }
            }
            {
                const uint32_t headerChars = static_cast<uint32_t>(frame.args[3]);
                const size_t headerLimit = headerChars == UINT32_MAX
                                         ? kNetworkObservationTextCap : headerChars;
                bool headerHitLimit = false;
                frame.detail = frame.wide
                             ? readNetworkWide(hp, frame.args[2], headerLimit, &headerHitLimit)
                             : readNetworkAnsi(hp, frame.args[2], headerLimit, &headerHitLimit);
                frame.payloadTruncated = (headerChars != UINT32_MAX &&
                                          headerChars > kNetworkObservationTextCap) ||
                                         (headerChars == UINT32_MAX && headerHitLimit);
            }
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::WinHttpSendRequest:
        case NetworkProbeApi::HttpSendRequestA:
        case NetworkProbeApi::HttpSendRequestW: {
            const uint32_t headerChars = static_cast<uint32_t>(frame.args[2]);
            const size_t headerLimit = headerChars == UINT32_MAX
                                     ? kNetworkObservationTextCap : headerChars;
            bool headerHitLimit = false;
            frame.detail = api == NetworkProbeApi::WinHttpSendRequest || frame.wide
                         ? readNetworkWide(hp, frame.args[1], headerLimit, &headerHitLimit)
                         : readNetworkAnsi(hp, frame.args[1], headerLimit, &headerHitLimit);
            // DWORD stack arguments only guarantee their low 32 bits on Win64;
            // do not treat stale upper home-slot bytes as part of the length.
            frame.requestedLength = static_cast<uint32_t>(frame.args[4]);
            frame.requestedLengthValid = true;
            frame.payload = readNetworkPayload(hp, frame.args[3], frame.requestedLength);
            frame.payloadTruncated = frame.payload.size() < frame.requestedLength ||
                                     (headerChars != UINT32_MAX &&
                                      headerChars > kNetworkObservationTextCap) ||
                                     (headerChars == UINT32_MAX && headerHitLimit);
            (void)queueReturn(std::move(frame));
            return;
        }
        case NetworkProbeApi::HttpSendRequestExA:
        case NetworkProbeApi::HttpSendRequestExW: {
            frame.buffers = frame.args[1];
            uint64_t body = 0, headers = 0;
            uint32_t bodyLength = 0, headersLength = 0;
            if (readInternetBuffer(hp, wow64, frame.buffers, body, bodyLength,
                                   &headers, &headersLength)) {
                frame.payload = readNetworkPayload(hp, body, bodyLength);
                frame.requestedLength = bodyLength;
                frame.requestedLengthValid = true;
                frame.payloadTruncated = frame.payload.size() < bodyLength ||
                                         headersLength > kNetworkObservationTextCap;
                frame.detail = frame.wide
                             ? readNetworkWide(hp, headers, headersLength)
                             : readNetworkAnsi(hp, headers, headersLength);
            }
            (void)queueReturn(std::move(frame));
            return;
        }
        case NetworkProbeApi::HttpEndRequestA:
        case NetworkProbeApi::HttpEndRequestW:
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::WinHttpWriteData:
        case NetworkProbeApi::InternetWriteFile:
            frame.requestedLength = argU32(2);
            frame.requestedLengthValid = true;
            frame.payload = readNetworkPayload(hp, frame.args[1], frame.requestedLength);
            frame.payloadTruncated = frame.payload.size() < frame.requestedLength;
            frame.transferredPtr = frame.args[3];
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::WinHttpReceiveResponse:
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::WinHttpReadData:
        case NetworkProbeApi::InternetReadFile:
            frame.buffer = frame.args[1];
            frame.countOrLength = argU32(2);
            frame.requestedLength = frame.countOrLength;
            frame.requestedLengthValid = true;
            frame.transferredPtr = frame.args[3];
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::InternetReadFileExA:
        case NetworkProbeApi::InternetReadFileExW: {
            frame.buffers = frame.args[1];
            frame.async = frame.async || (argU32(2) & 0x1u) != 0; // IRF_ASYNC
            uint64_t requestedBuffer = 0;
            uint32_t requestedLength = 0;
            if (readInternetBuffer(hp, wow64, frame.buffers,
                                   requestedBuffer, requestedLength)) {
                frame.requestedLength = requestedLength;
                frame.requestedLengthValid = true;
            }
            (void)queueReturn(std::move(frame));
            return;
        }
        case NetworkProbeApi::WinHttpQueryHeaders:
            frame.buffer = frame.args[3];
            frame.transferredPtr = frame.args[4];
            if (frame.transferredPtr) {
                uint32_t capacity = 0;
                if (readRemoteExact(hp, frame.transferredPtr, &capacity, sizeof(capacity))) {
                    frame.countOrLength = capacity;
                    frame.requestedLength = capacity;
                    frame.requestedLengthValid = true;
                }
            }
            frame.detail = "query level " + std::to_string(static_cast<uint32_t>(frame.args[1]));
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::HttpQueryInfoA:
        case NetworkProbeApi::HttpQueryInfoW:
            frame.buffer = frame.args[2];
            frame.transferredPtr = frame.args[3];
            if (frame.transferredPtr) {
                uint32_t capacity = 0;
                if (readRemoteExact(hp, frame.transferredPtr, &capacity, sizeof(capacity))) {
                    frame.countOrLength = capacity;
                    frame.requestedLength = capacity;
                    frame.requestedLengthValid = true;
                }
            }
            frame.detail = "query level " + std::to_string(static_cast<uint32_t>(frame.args[1]));
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::WinHttpCloseHandle:
        case NetworkProbeApi::InternetCloseHandle:
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::UrlDownloadToFileA:
        case NetworkProbeApi::UrlDownloadToFileW:
            frame.object = frame.wide ? readNetworkWide(hp, frame.args[1])
                                      : readNetworkAnsi(hp, frame.args[1]);
            {
                NetworkUrlParts url;
                if (ParseNetworkUrl(frame.object, url)) {
                    frame.hostname = std::move(url.hostname); frame.ip = std::move(url.ip);
                    frame.port = url.port; frame.portValid = url.portValid;
                    frame.path = std::move(url.path);
                }
            }
            frame.detail = frame.wide ? readNetworkWide(hp, frame.args[2])
                                      : readNetworkAnsi(hp, frame.args[2]);
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::UrlDownloadToCacheFileA:
        case NetworkProbeApi::UrlDownloadToCacheFileW:
            frame.object = frame.wide ? readNetworkWide(hp, frame.args[1])
                                      : readNetworkAnsi(hp, frame.args[1]);
            {
                NetworkUrlParts url;
                if (ParseNetworkUrl(frame.object, url)) {
                    frame.hostname = std::move(url.hostname); frame.ip = std::move(url.ip);
                    frame.port = url.port; frame.portValid = url.portValid;
                    frame.path = std::move(url.path);
                }
            }
            frame.buffer = frame.args[2];
            frame.countOrLength = argU32(3);
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::UrlOpenStreamA:
        case NetworkProbeApi::UrlOpenStreamW:
            frame.object = frame.wide ? readNetworkWide(hp, frame.args[1])
                                      : readNetworkAnsi(hp, frame.args[1]);
            {
                NetworkUrlParts url;
                if (ParseNetworkUrl(frame.object, url)) {
                    frame.hostname = std::move(url.hostname); frame.ip = std::move(url.ip);
                    frame.port = url.port; frame.portValid = url.portValid;
                    frame.path = std::move(url.path);
                }
            }
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::UrlOpenBlockingStreamA:
        case NetworkProbeApi::UrlOpenBlockingStreamW:
            frame.object = frame.wide ? readNetworkWide(hp, frame.args[1])
                                      : readNetworkAnsi(hp, frame.args[1]);
            {
                NetworkUrlParts url;
                if (ParseNetworkUrl(frame.object, url)) {
                    frame.hostname = std::move(url.hostname); frame.ip = std::move(url.ip);
                    frame.port = url.port; frame.portValid = url.portValid;
                    frame.path = std::move(url.path);
                }
            }
            frame.buffer = frame.args[2]; // IStream**
            (void)queueReturn(std::move(frame));
            return;
        default:
            return;
    }
}

// Restore one shared return instruction, pop exactly the calling thread's top
// frame, publish its typed result, and tell the event loop whether peers still
// reference this site and therefore require it to be re-armed after one TF step.
bool Debugger::netTapOnReturn(uint64_t addr, uint32_t tid, bool* transitionFailed) {
    if (transitionFailed) *transitionFailed = false;
    HANDLE hp = (HANDLE)hProcess_;
    NetworkReturnBp site;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = networkReturnBps_.find(addr);
        if (it == networkReturnBps_.end()) return false;
        site = it->second;
        it->second.armed = false;
    }
    auto th = threads_.find(tid);
    if (site.ownsByte && !replaceByteIfEqual(hp, addr, 0xCC, site.orig)) {
        if (transitionFailed) *transitionFailed = true;
        return false;
    }
    if (th == threads_.end()) return true;
    ctxSetRip(th->second, addr);
    auto finishSite = [&]() {
        const bool shared = networkPendingReturns_.references(addr) != 0;
        if (!shared) {
            std::lock_guard<std::mutex> lk(mtx_);
            networkReturnBps_.erase(addr);
            auto at = std::lower_bound(networkReturnBpAddrs_.begin(),
                                       networkReturnBpAddrs_.end(), addr);
            if (at != networkReturnBpAddrs_.end() && *at == addr)
                networkReturnBpAddrs_.erase(at);
        }
        return shared;
    };
    NetworkPendingFrame frame;
    if (!networkPendingReturns_.pop(tid, addr, frame)) return finishSite();
    if (!frame.payload.empty()) {
        std::lock_guard<std::mutex> lk(mtx_);
        networkPendingPayloadBytes_ -= (std::min<uint64_t>)(
            networkPendingPayloadBytes_, frame.payload.size());
    }
    Registers r;
    if (!ctxReadFull(th->second, r)) return finishSite();
    const bool wow64 = isWow64_.load();
    const int32_t result32 = static_cast<int32_t>(static_cast<uint32_t>(r.rax));
    const uint64_t rawResult = wow64 ? static_cast<uint32_t>(r.rax) : r.rax;
    NetworkObservationEvent event;
    event.tickMs = GetTickCount(); event.tid = tid; event.api = frame.api;
    event.caller = frame.caller; event.handle = frame.handle;
    event.result = result32;
    SetNetworkObservedRawResult(event, r.rax, wow64);
    event.hostname = frame.hostname; event.ip = frame.ip;
    event.port = frame.port; event.portValid = frame.portValid;
    event.endpoint = frame.endpoint; event.method = frame.method;
    event.path = frame.path; event.object = frame.object; event.detail = frame.detail;
    event.requestedBytes = frame.requestedLength;
    event.requestedBytesValid = frame.requestedLengthValid;
    event.asyncPartial = frame.async;
    event.truncated = frame.payloadTruncated;

    auto applyLineage = [&]() {
        const NetworkHandleRecord lineage = networkHandleLineage_.resolve(frame.handle);
        if (event.hostname.empty()) event.hostname = lineage.hostname;
        if (event.ip.empty()) event.ip = lineage.ip;
        if (!event.portValid && lineage.portValid) {
            event.port = lineage.port;
            event.portValid = true;
        }
        if (event.method.empty()) event.method = lineage.method;
        if (event.path.empty()) event.path = lineage.path;
        if (event.object.empty()) event.object = lineage.object;
        if (event.endpoint.empty()) event.endpoint = lineage.endpoint;
        if (event.endpoint.empty()) {
            const std::string& host = !event.ip.empty() ? event.ip : event.hostname;
            event.endpoint = formatNetworkHostPort(host, event.port, event.portValid);
        }
        event.asyncPartial = event.asyncPartial || lineage.async;
    };
    auto readTransferred = [&](uint32_t& transferred) {
        transferred = 0;
        return frame.transferredPtr &&
               readRemoteExact(hp, frame.transferredPtr, &transferred,
                               sizeof(transferred));
    };
    auto captureTransferred = [&]() {
        uint32_t transferred = 0;
        if (!readTransferred(transferred)) return false;
        event.transferred = transferred;
        event.transferredValid = true;
        return true;
    };
    auto putHandleState = [&](uint64_t handle, NetworkHandleRecord record) {
        if (networkHandleLineage_.put(handle, std::move(record))) return true;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            networkCoverage_.handleStatesDropped =
                NetworkHandleStatesDropped(networkHandleLineage_);
            if (networkCoverage_.handleStatesDropped == 1)
                networkCoverage_.limitations.push_back(
                    "HTTP/socket handle-lineage state exceeded the 4,096-record cap; some descendant metadata is unavailable.");
        }
        if (!event.detail.empty()) event.detail += "; ";
        event.detail += "handle-lineage state dropped at bounded capacity";
        return false;
    };
    switch (frame.api) {
        case NetworkProbeApi::ResolveAddrInfoA:
        case NetworkProbeApi::ResolveAddrInfoW: {
            event.stage = NetworkObservationStage::NameResolution;
            event.result = result32;
            if (result32 == 0 && frame.buffer) {
                const NetworkCallContext pointerContext{ isWow64_.load(), 0, {} };
                const NetworkMemoryReader read = [hp](uint64_t address, void* out, size_t size) {
                    return readRemoteExact(hp, address, out, size);
                };
                uint64_t cursor = 0;
                if (ReadNetworkPointer(pointerContext, read, frame.buffer, cursor)) {
                    std::string endpoints;
                    for (size_t i = 0; cursor && i < 8; ++i) {
                        uint32_t addrLen = 0;
                        uint64_t addrPtr = 0, next = 0;
                        const uint64_t addrLenAt = cursor + 16;
                        (void)readRemoteExact(hp, addrLenAt, &addrLen, sizeof(addrLen));
                        const uint64_t addrPtrAt = cursor + (isWow64_.load() ? 24u : 32u);
                        const uint64_t nextAt = cursor + (isWow64_.load() ? 28u : 40u);
                        if (ReadNetworkPointer(pointerContext, read, addrPtrAt, addrPtr)) {
                            std::string oneIp;
                            uint16_t onePort = 0;
                            bool onePortValid = false;
                            const std::string one = readNetworkSockaddr(
                                hp, addrPtr, addrLen, &oneIp, &onePort, &onePortValid);
                            if (!one.empty()) {
                                if (event.ip.empty()) {
                                    event.ip = std::move(oneIp);
                                    event.port = onePort;
                                    event.portValid = onePortValid;
                                }
                                if (!endpoints.empty()) endpoints += ", ";
                                endpoints += one;
                            }
                        }
                        if (!ReadNetworkPointer(pointerContext, read, nextAt, next) || next == cursor) break;
                        cursor = next;
                    }
                    event.endpoint = BoundNetworkText(std::move(endpoints));
                }
            }
            break;
        }
        case NetworkProbeApi::GetAddrInfoExA:
        case NetworkProbeApi::GetAddrInfoExW: {
            event.stage = NetworkObservationStage::NameResolution;
            event.asyncPartial = frame.async;
            if (result32 == 0 && frame.buffer && !frame.async) {
                const bool narrow = isWow64_.load();
                const NetworkCallContext pointerContext{narrow, 0, {}};
                const NetworkMemoryReader read = [hp](uint64_t address, void* out, size_t size) {
                    return readRemoteExact(hp, address, out, size);
                };
                uint64_t cursor = 0;
                if (ReadNetworkPointer(pointerContext, read, frame.buffer, cursor)) {
                    std::string endpoints;
                    for (size_t i = 0; cursor && i < 8; ++i) {
                        uint32_t addrLen = 0;
                        uint64_t addrPtr = 0, next = 0;
                        (void)readRemoteExact(hp, cursor + 16, &addrLen, sizeof(addrLen));
                        const uint64_t addrAt = cursor + (narrow ? 24u : 32u);
                        const uint64_t nextAt = cursor + (narrow ? 40u : 64u);
                        if (ReadNetworkPointer(pointerContext, read, addrAt, addrPtr)) {
                            std::string oneIp;
                            uint16_t onePort = 0;
                            bool onePortValid = false;
                            const std::string one = readNetworkSockaddr(
                                hp, addrPtr, addrLen, &oneIp, &onePort, &onePortValid);
                            if (!one.empty()) {
                                if (event.ip.empty()) {
                                    event.ip = std::move(oneIp);
                                    event.port = onePort;
                                    event.portValid = onePortValid;
                                }
                                if (!endpoints.empty()) endpoints += ", ";
                                endpoints += one;
                            }
                        }
                        if (!ReadNetworkPointer(pointerContext, read, nextAt, next) || next == cursor)
                            break;
                        cursor = next;
                    }
                    event.endpoint = BoundNetworkText(std::move(endpoints));
                }
            }
            break;
        }
        case NetworkProbeApi::GetHostByName:
            event.stage = NetworkObservationStage::NameResolution;
            event.result = static_cast<int64_t>(rawResult);
            if (rawResult)
                event.endpoint = readNetworkHostent(hp, isWow64_.load(), rawResult,
                                                    &event.ip);
            break;
        case NetworkProbeApi::GetNameInfoA:
        case NetworkProbeApi::GetNameInfoW:
            event.stage = NetworkObservationStage::NameResolution;
            if (result32 == 0) {
                bool hostHitLimit = false, serviceHitLimit = false;
                event.hostname = frame.wide
                    ? readNetworkWide(hp, frame.buffer,
                                      static_cast<size_t>((std::min<uint64_t>)(
                                          frame.countOrLength, kNetworkObservationTextCap)),
                                      &hostHitLimit)
                    : readNetworkAnsi(hp, frame.buffer,
                                      static_cast<size_t>((std::min<uint64_t>)(
                                          frame.countOrLength, kNetworkObservationTextCap)),
                                      &hostHitLimit);
                const std::string service = frame.wide
                    ? readNetworkWide(hp, frame.transferredPtr,
                                      static_cast<size_t>((std::min<uint64_t>)(
                                          frame.addressLengthPtr, kNetworkObservationTextCap)),
                                      &serviceHitLimit)
                    : readNetworkAnsi(hp, frame.transferredPtr,
                                      static_cast<size_t>((std::min<uint64_t>)(
                                          frame.addressLengthPtr, kNetworkObservationTextCap)),
                                      &serviceHitLimit);
                event.truncated = event.truncated || hostHitLimit || serviceHitLimit;
                if (!service.empty()) event.detail = "service " + service;
            }
            break;
        case NetworkProbeApi::DnsQueryA:
        case NetworkProbeApi::DnsQueryW:
        case NetworkProbeApi::DnsQueryUtf8:
            event.stage = NetworkObservationStage::NameResolution;
            break;
        case NetworkProbeApi::Connect:
        case NetworkProbeApi::WSAConnect:
            event.stage = NetworkObservationStage::Connect;
            event.direction = NetworkDirection::Outbound;
            event.result = result32;
            if (result32 == 0 && frame.handle) {
                NetworkHandleRecord socket;
                socket.kind = NetworkHandleKind::Socket;
                socket.endpoint = frame.endpoint; socket.ip = frame.ip;
                socket.port = frame.port; socket.portValid = frame.portValid;
                (void)putHandleState(frame.handle, std::move(socket));
            }
            break;
        case NetworkProbeApi::Send:
        case NetworkProbeApi::SendTo:
            event.stage = NetworkObservationStage::Send;
            event.direction = NetworkDirection::Outbound;
            if (result32 >= 0) {
                event.transferred = static_cast<uint32_t>(result32);
                event.transferredValid = true;
            }
            if (result32 > 0) {
                if (event.transferred < frame.payload.size()) frame.payload.resize(event.transferred);
            }
            event.payload = std::move(frame.payload);
            event.truncated = event.truncated || event.transferred > event.payload.size();
            event.payloadOpaque = true; // raw Winsock may contain TLS ciphertext; bytes remain exact
            applyLineage();
            break;
        case NetworkProbeApi::WSASend:
        case NetworkProbeApi::WSASendTo:
            event.stage = NetworkObservationStage::Send;
            event.direction = NetworkDirection::Outbound;
            if (result32 == 0) (void)captureTransferred();
            event.payload = std::move(frame.payload);
            if (event.transferred && event.transferred < event.payload.size()) event.payload.resize(event.transferred);
            event.truncated = event.truncated || event.transferred > event.payload.size();
            event.payloadOpaque = true;
            applyLineage();
            break;
        case NetworkProbeApi::Recv:
        case NetworkProbeApi::RecvFrom:
            event.stage = NetworkObservationStage::Receive;
            event.direction = NetworkDirection::Inbound;
            if (result32 >= 0) {
                event.transferred = static_cast<uint32_t>(result32);
                event.transferredValid = true;
            }
            if (result32 > 0) {
                event.payload = readNetworkPayload(hp, frame.buffer,
                    (std::min<uint64_t>)(event.transferred, frame.countOrLength));
            }
            if (result32 > 0 && frame.addressPtr && frame.addressLengthPtr) {
                int32_t length = 0;
                if (readRemoteExact(hp, frame.addressLengthPtr, &length, sizeof(length)) && length > 0)
                    event.endpoint = readNetworkSockaddr(
                        hp, frame.addressPtr, static_cast<uint32_t>(length),
                        &event.ip, &event.port, &event.portValid);
            }
            event.truncated = event.truncated || event.transferred > event.payload.size();
            event.payloadOpaque = true;
            applyLineage();
            break;
        case NetworkProbeApi::WSARecv:
        case NetworkProbeApi::WSARecvFrom:
            event.stage = NetworkObservationStage::Receive;
            event.direction = NetworkDirection::Inbound;
            if (result32 == 0) {
                (void)captureTransferred();
                event.payload = readNetworkWsabufs(hp, isWow64_.load(), frame.buffers,
                                                   frame.countOrLength, event.transferred);
            }
            if (result32 == 0 && frame.addressPtr && frame.addressLengthPtr) {
                int32_t length = 0;
                if (readRemoteExact(hp, frame.addressLengthPtr, &length, sizeof(length)) && length > 0)
                    event.endpoint = readNetworkSockaddr(
                        hp, frame.addressPtr, static_cast<uint32_t>(length),
                        &event.ip, &event.port, &event.portValid);
            }
            event.truncated = event.truncated || event.transferred > event.payload.size();
            event.payloadOpaque = true;
            applyLineage();
            break;
        case NetworkProbeApi::CloseSocket:
            event.stage = NetworkObservationStage::HandleClosed;
            applyLineage();
            if (result32 == 0) networkHandleLineage_.erase(frame.handle);
            break;
        case NetworkProbeApi::WinHttpOpen:
        case NetworkProbeApi::InternetOpenA:
        case NetworkProbeApi::InternetOpenW:
            event.stage = NetworkObservationStage::ProbeStatus;
            event.result = static_cast<int64_t>(rawResult);
            event.handle = rawResult;
            event.detail = rawResult ? "HTTP session opened" : "HTTP session open failed";
            event.asyncPartial = frame.async;
            if (rawResult) {
                NetworkHandleRecord record;
                record.kind = NetworkHandleKind::Session;
                record.async = frame.async;
                (void)putHandleState(rawResult, std::move(record));
            }
            break;
        case NetworkProbeApi::WinHttpConnect:
        case NetworkProbeApi::InternetConnectA:
        case NetworkProbeApi::InternetConnectW:
            event.stage = NetworkObservationStage::Connect;
            event.result = static_cast<int64_t>(rawResult);
            event.handle = rawResult;
            event.asyncPartial = networkHandleLineage_.resolve(frame.handle).async;
            if (rawResult) {
                NetworkHandleRecord record;
                record.kind = NetworkHandleKind::Connection; record.parent = frame.handle;
                record.hostname = frame.hostname; record.ip = frame.ip;
                record.port = frame.port; record.portValid = frame.portValid;
                (void)putHandleState(rawResult, std::move(record));
                event.endpoint = formatNetworkHostPort(
                    !event.ip.empty() ? event.ip : event.hostname,
                    event.port, event.portValid);
            }
            break;
        case NetworkProbeApi::WinHttpOpenRequest:
        case NetworkProbeApi::HttpOpenRequestA:
        case NetworkProbeApi::HttpOpenRequestW:
        case NetworkProbeApi::InternetOpenUrlA:
        case NetworkProbeApi::InternetOpenUrlW:
            event.stage = NetworkObservationStage::Request;
            event.direction = NetworkDirection::Outbound;
            event.result = static_cast<int64_t>(rawResult);
            event.handle = rawResult;
            if (rawResult) {
                NetworkHandleRecord record;
                record.kind = NetworkHandleKind::Request;
                record.parent = frame.parent ? frame.parent : frame.handle;
                record.hostname = frame.hostname; record.ip = frame.ip;
                record.port = frame.port; record.portValid = frame.portValid;
                record.method = frame.method; record.path = frame.path;
                record.object = frame.object;
                (void)putHandleState(rawResult, std::move(record));
            }
            applyLineage();
            break;
        case NetworkProbeApi::WinHttpAddRequestHeaders:
        case NetworkProbeApi::HttpAddRequestHeadersA:
        case NetworkProbeApi::HttpAddRequestHeadersW:
            event.stage = NetworkObservationStage::Request;
            event.direction = NetworkDirection::Outbound;
            applyLineage();
            break;
        case NetworkProbeApi::WinHttpSendRequest:
        case NetworkProbeApi::HttpSendRequestA:
        case NetworkProbeApi::HttpSendRequestW:
            event.stage = NetworkObservationStage::Request;
            event.direction = NetworkDirection::Outbound;
            event.payload = std::move(frame.payload);
            applyLineage();
            break;
        case NetworkProbeApi::HttpSendRequestExA:
        case NetworkProbeApi::HttpSendRequestExW:
            event.stage = NetworkObservationStage::Request;
            event.direction = NetworkDirection::Outbound;
            event.payload = std::move(frame.payload);
            applyLineage();
            break;
        case NetworkProbeApi::HttpEndRequestA:
        case NetworkProbeApi::HttpEndRequestW:
            event.stage = NetworkObservationStage::Request;
            event.direction = NetworkDirection::Outbound;
            event.detail = "extended request body ended";
            applyLineage();
            break;
        case NetworkProbeApi::WinHttpWriteData:
        case NetworkProbeApi::InternetWriteFile:
            event.stage = NetworkObservationStage::Send;
            event.direction = NetworkDirection::Outbound;
            applyLineage();
            if (result32 != 0 && !event.asyncPartial)
                (void)captureTransferred();
            event.payload = std::move(frame.payload);
            if (result32 != 0 && event.transferred && event.transferred < event.payload.size())
                event.payload.resize(event.transferred);
            event.truncated = event.truncated || event.transferred > event.payload.size();
            break;
        case NetworkProbeApi::WinHttpReceiveResponse:
            event.stage = NetworkObservationStage::Response;
            event.direction = NetworkDirection::Inbound;
            applyLineage();
            break;
        case NetworkProbeApi::WinHttpReadData:
        case NetworkProbeApi::InternetReadFile:
            event.stage = NetworkObservationStage::Receive;
            event.direction = NetworkDirection::Inbound;
            applyLineage();
            if (result32 != 0 && !event.asyncPartial) {
                (void)captureTransferred();
                event.payload = readNetworkPayload(hp, frame.buffer,
                    (std::min<uint64_t>)(event.transferred, frame.countOrLength));
            }
            event.truncated = event.truncated || event.transferred > event.payload.size();
            break;
        case NetworkProbeApi::InternetReadFileExA:
        case NetworkProbeApi::InternetReadFileExW: {
            event.stage = NetworkObservationStage::Receive;
            event.direction = NetworkDirection::Inbound;
            applyLineage();
            uint64_t body = 0;
            uint32_t bodyLength = 0;
            if (result32 != 0 && !event.asyncPartial &&
                readInternetBuffer(hp, isWow64_.load(), frame.buffers, body, bodyLength)) {
                event.transferred = bodyLength;
                event.transferredValid = true;
                event.payload = readNetworkPayload(hp, body, bodyLength);
                event.truncated = event.truncated || bodyLength > event.payload.size();
            }
            break;
        }
        case NetworkProbeApi::WinHttpQueryHeaders:
        case NetworkProbeApi::HttpQueryInfoA:
        case NetworkProbeApi::HttpQueryInfoW:
            event.stage = NetworkObservationStage::Response;
            event.direction = NetworkDirection::Inbound;
            // On failure the size pointer is an updated required length, not a
            // claim that the caller supplied that capacity. Never read beyond
            // the entry-time buffer size (especially ERROR_INSUFFICIENT_BUFFER).
            if (result32 != 0) {
                (void)captureTransferred();
                const uint64_t readable = (std::min<uint64_t>)(
                    event.transferred, frame.countOrLength);
                event.payload = readNetworkPayload(hp, frame.buffer, readable);
                event.truncated = event.transferred > event.payload.size();
            }
            applyLineage();
            break;
        case NetworkProbeApi::UrlDownloadToFileA:
        case NetworkProbeApi::UrlDownloadToFileW:
            event.stage = NetworkObservationStage::Request;
            event.direction = NetworkDirection::Outbound;
            event.object = frame.object;
            event.detail = "destination: " + frame.detail;
            break;
        case NetworkProbeApi::UrlDownloadToCacheFileA:
        case NetworkProbeApi::UrlDownloadToCacheFileW:
            event.stage = NetworkObservationStage::Request;
            event.direction = NetworkDirection::Outbound;
            event.object = frame.object;
            if (result32 == 0)
                event.detail = "cache destination: " +
                    (frame.wide ? readNetworkWide(hp, frame.buffer)
                                : readNetworkAnsi(hp, frame.buffer));
            break;
        case NetworkProbeApi::UrlOpenStreamA:
        case NetworkProbeApi::UrlOpenStreamW:
            event.stage = NetworkObservationStage::Request;
            event.direction = NetworkDirection::Outbound;
            event.object = frame.object;
            event.asyncPartial = true; // callback completion is outside this API return
            break;
        case NetworkProbeApi::UrlOpenBlockingStreamA:
        case NetworkProbeApi::UrlOpenBlockingStreamW: {
            event.stage = NetworkObservationStage::Request;
            event.direction = NetworkDirection::Outbound;
            event.object = frame.object;
            const NetworkCallContext pointerContext{isWow64_.load(), 0, {}};
            const NetworkMemoryReader read = [hp](uint64_t at, void* out, size_t size) {
                return readRemoteExact(hp, at, out, size);
            };
            uint64_t stream = 0;
            if (result32 == 0 && ReadNetworkPointer(pointerContext, read, frame.buffer, stream))
                event.handle = stream;
            break;
        }
        case NetworkProbeApi::WinHttpCloseHandle:
        case NetworkProbeApi::InternetCloseHandle:
            event.stage = NetworkObservationStage::HandleClosed;
            applyLineage();
            if (result32 != 0) networkHandleLineage_.erase(frame.handle);
            break;
        default:
            event.stage = NetworkObservationStage::ProbeStatus;
            break;
    }

    decorateNetworkEvent(event);
    writeNetworkObservationLog(event);
    pushNetworkEvent(std::move(event));

    return finishSite();
}

bool Debugger::addHardwareBreakpoint(uint64_t va, HwKind kind, uint8_t size) {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (state_ == DbgState::Detached || state_ == DbgState::Terminated) return false;
        if (gameMakerOwnsRangeLocked(va,kind==HwKind::Execute ? 1 : size)) return false;
        // A remove followed by an add at the same address is a type/size
        // replacement. The debug thread applies removals before additions, so do
        // not mistake the soon-to-be-freed slot for an already-satisfied add.
        const bool replacing = std::find(pendingHwRems_.begin(), pendingHwRems_.end(), va) !=
                               pendingHwRems_.end();
        for (auto& pending : pendingHwAdds_) {
            if (pending.addr != va) continue;
            pending.kind = kind;
            pending.size = size;
            return true;
        }
        int inUse = 0;
        for (auto& s : hwSlots_) {
            if (!s.used) continue;
            if (s.addr == va) {
                if (!replacing) return true;
                continue;
            }
            ++inUse;
        }
        inUse += (int)pendingHwAdds_.size();
        if (inUse >= 4) return false;
        HwSlot s; s.used = true; s.addr = va; s.kind = kind; s.size = size;
        pendingHwAdds_.push_back(s);
    }
    requestTraceSyncBreak();
    return true;
}
bool Debugger::addHardwareBreakpointForSession(DebugTargetIdentity expected,
                                               uint64_t va, HwKind kind,
                                               uint8_t size) {
    if (!expected.valid()) return false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if ((state_ != DbgState::Running && state_ != DbgState::Paused) ||
            !DebugTargetIdentityMatches({ pid_, sessionGeneration_ }, expected))
            return false;
        if (gameMakerOwnsRangeLocked(va,kind==HwKind::Execute ? 1 : size)) return false;
        const bool replacing = std::find(pendingHwRems_.begin(), pendingHwRems_.end(), va) !=
                               pendingHwRems_.end();
        for (auto& pending : pendingHwAdds_) {
            if (pending.addr != va) continue;
            pending.kind = kind;
            pending.size = size;
            return true;
        }
        int inUse = 0;
        for (auto& s : hwSlots_) {
            if (!s.used) continue;
            if (s.addr == va) {
                if (!replacing) return true;
                continue;
            }
            ++inUse;
        }
        inUse += (int)pendingHwAdds_.size();
        if (inUse >= 4) return false;
        HwSlot s; s.used = true; s.addr = va; s.kind = kind; s.size = size;
        pendingHwAdds_.push_back(s);
    }
    requestTraceSyncBreak(expected);
    return true;
}
bool Debugger::removeHardwareBreakpoint(uint64_t va) {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (state_ == DbgState::Detached || state_ == DbgState::Terminated) return false;
        pendingHwRems_.push_back(va);
    }
    requestTraceSyncBreak();
    return true;
}
bool Debugger::removeHardwareBreakpointForSession(DebugTargetIdentity expected,
                                                  uint64_t va) {
    if (!expected.valid()) return false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if ((state_ != DbgState::Running && state_ != DbgState::Paused) ||
            !DebugTargetIdentityMatches({ pid_, sessionGeneration_ }, expected))
            return false;
        pendingHwRems_.push_back(va);
    }
    requestTraceSyncBreak(expected);
    return true;
}
bool Debugger::hasHardwareBreakpoint(uint64_t va) {
    std::lock_guard<std::mutex> lk(mtx_);
    for (auto& s : hwSlots_) if (s.used && s.addr == va) return true;
    return false;
}

bool Debugger::setAntiDebugPolicy(const AntiDebugPolicy& policy, std::string* error) {
    std::unique_lock ownerLock(lifecycleOwnerMtx_, std::try_to_lock);
    if (!ownerLock.owns_lock()) {
        if (error) *error = "Hide Debugger policy cannot change during debugger lifecycle work";
        return false;
    }
    {
        std::lock_guard lock(lifecycleMtx_);
        if (lifecycle_.busy) {
            if (error) *error = "Hide Debugger policy cannot change during debugger lifecycle work";
            return false;
        }
    }
    std::lock_guard<std::mutex> lk(mtx_);
    if (state_ != DbgState::Detached || thread_.joinable()) {
        if (error) *error = "Hide Debugger policy can only be changed while detached";
        return false;
    }
    antiDebugPolicy_ = policy;
    if (error) error->clear();
    return true;
}

AntiDebugPolicy Debugger::antiDebugPolicy() {
    std::lock_guard<std::mutex> lk(mtx_);
    return antiDebugPolicy_;
}

AntiDebugCapabilityReport Debugger::antiDebugCapabilityReport() {
    return BuildAntiDebugCapabilityReport(antiDebugPolicy());
}

void Debugger::addAntiDebugWarning(std::string warning) {
    std::lock_guard<std::mutex> lk(mtx_);
    AddAntiDebugWarning(antiDebugStats_, std::move(warning));
}

static size_t readProcessMemoryFromHandle(HANDLE h, uint64_t va, void* out, size_t n) {
    SIZE_T got = 0;
    ReadProcessMemory(h, (LPCVOID)va, out, n, &got);
    return (size_t)got;
}

static bool processHandleMatchesIdentity(HANDLE h, DebugTargetIdentity current,
                                         DebugTargetIdentity expected) {
    return h && DebugTargetIdentityMatches(current, expected);
}

size_t Debugger::readMemory(uint64_t va, void* out, size_t n) {
    std::lock_guard<std::mutex> lk(hProcMtx_);   // serialize handle use vs the debug thread's close
    HANDLE h = static_cast<HANDLE>(hProcessShared_.load());
    return h ? readProcessMemoryFromHandle(h, va, out, n) : 0;
}

size_t Debugger::readMemoryForSession(uint32_t expectedPid,
                                      uint64_t expectedSessionGeneration,
                                      uint64_t va, void* out, size_t n) {
    std::lock_guard<std::mutex> lk(hProcMtx_);
    HANDLE h = static_cast<HANDLE>(hProcessShared_.load());
    const DebugTargetIdentity expected{ expectedPid, expectedSessionGeneration };
    if (!processHandleMatchesIdentity(h, hProcessIdentity_, expected)) return 0;
    return readProcessMemoryFromHandle(h, va, out, n);
}

// Refill the sorted breakpoint-address cache from bps_. Caller holds mtx_.
void Debugger::rebuildBpAddrs_() {
    bpAddrs_.clear();
    bpAddrs_.reserve(bps_.size());
    for (auto& kv : bps_) bpAddrs_.push_back(kv.first);
    std::sort(bpAddrs_.begin(), bpAddrs_.end());
}

size_t Debugger::readMemoryMasked(uint64_t va, void* out, size_t n) {
    return readMemoryMaskedForSession(0, 0, va, out, n);
}

size_t Debugger::readMemoryMaskedForSession(
    uint32_t expectedPid, uint64_t expectedSessionGeneration,
    uint64_t va, void* out, size_t n) {
    const DebugTargetIdentity expected{
        expectedPid, expectedSessionGeneration
    };
    size_t got = expected.valid()
        ? readMemoryForSession(expectedPid, expectedSessionGeneration,
                               va, out, n)
        : readMemory(va, out, n);
    if (!got) return got;
    uint8_t* p = static_cast<uint8_t*>(out);
    std::lock_guard<std::mutex> lk(mtx_);           // bps_ / bpAddrs_ are guarded by mtx_
    if (expected.valid() && !DebugTargetIdentityMatches(
            {pid_, sessionGeneration_}, expected))
        return 0;
    if (bpAddrs_.empty() && traceBpAddrs_.empty() && dllTargetBpAddrs_.empty() &&
        antiTrapAddrs_.empty() && networkProbeBpAddrs_.empty() &&
        networkReturnBpAddrs_.empty() && authorizationBpAddrs_.empty() &&
        authorizationReturnBpAddrs_.empty()) return got;
    // Binary-search the maintained sorted address list for only the breakpoints that
    // fall inside [va, va+got): the read range, not the whole bp table, drives the
    // work, so a read with no in-range breakpoints does O(log n) and stops.
    auto lo = std::lower_bound(bpAddrs_.begin(), bpAddrs_.end(), va);
    uint64_t end = va + (uint64_t)got;              // got <= n, no overflow vs a real read
    for (auto it = lo; it != bpAddrs_.end() && *it < end; ++it) {
        auto b = bps_.find(*it);
        // Membership is logical ownership.  Mask unconditionally so an RPM
        // racing the physical disarm/re-arm transition cannot leak a transient
        // 0xCC into scanners, viewers, or table baselines.
        if (b != bps_.end())
            p[(size_t)(*it - va)] = b->second.orig;
    }
    // Trace sites are intentionally absent from the ordinary breakpoint snapshot,
    // but live disassembly must still see their pristine bytes rather than int3.
    auto tlo = std::lower_bound(traceBpAddrs_.begin(), traceBpAddrs_.end(), va);
    for (auto it = tlo; it != traceBpAddrs_.end() && *it < end; ++it) {
        auto b = traceBps_.find(*it);
        if (b != traceBps_.end()) p[(size_t)(*it - va)] = b->second.orig;
    }
    // Hosted-DLL DllMain/export targets are likewise invisible one-shots.
    auto dlo = std::lower_bound(dllTargetBpAddrs_.begin(), dllTargetBpAddrs_.end(), va);
    for (auto it = dlo; it != dllTargetBpAddrs_.end() && *it < end; ++it) {
        auto b = dllTargetBps_.find(*it);
        if (b != dllTargetBps_.end()) p[(size_t)(*it - va)] = b->second.orig;
    }
    // Hide-Debugger hooks and decoded RDTSC sites are persistent internal int3s.
    auto alo = std::lower_bound(antiTrapAddrs_.begin(), antiTrapAddrs_.end(), va);
    for (auto it = alo; it != antiTrapAddrs_.end() && *it < end; ++it) {
        auto b = antiTraps_.find(*it);
        if (b != antiTraps_.end()) p[(size_t)(*it - va)] = b->second.orig;
    }
    auto nplo = std::lower_bound(networkProbeBpAddrs_.begin(), networkProbeBpAddrs_.end(), va);
    for (auto it = nplo; it != networkProbeBpAddrs_.end() && *it < end; ++it) {
        auto b = networkProbeBps_.find(*it);
        if (b != networkProbeBps_.end()) p[(size_t)(*it - va)] = b->second.orig;
    }
    auto nrlo = std::lower_bound(networkReturnBpAddrs_.begin(), networkReturnBpAddrs_.end(), va);
    for (auto it = nrlo; it != networkReturnBpAddrs_.end() && *it < end; ++it) {
        auto b = networkReturnBps_.find(*it);
        if (b != networkReturnBps_.end()) p[(size_t)(*it - va)] = b->second.orig;
    }
    auto awlo = std::lower_bound(authorizationBpAddrs_.begin(),
                                 authorizationBpAddrs_.end(), va);
    for (auto it = awlo; it != authorizationBpAddrs_.end() && *it < end; ++it) {
        auto b = authorizationBps_.find(*it);
        if (b != authorizationBps_.end()) p[(size_t)(*it - va)] = b->second.orig;
    }
    auto arlo = std::lower_bound(authorizationReturnBpAddrs_.begin(),
                                 authorizationReturnBpAddrs_.end(), va);
    for (auto it = arlo; it != authorizationReturnBpAddrs_.end() && *it < end; ++it) {
        auto b = authorizationReturnBps_.find(*it);
        if (b != authorizationReturnBps_.end())
            p[(size_t)(*it - va)] = b->second.orig;
    }
    return got;
}

struct DebugWriteProtectionSpan {
    uint64_t address = 0;
    size_t size = 0;
    DWORD restoreProtect = 0;
    bool needsChange = false;
    bool executable = false;
    bool changed = false;
};

struct DebugWriteProtectionPlan {
    std::vector<DebugWriteProtectionSpan> spans;
    bool executable = false;
    bool needsAuthority = false;
};

static bool buildDebugWriteProtectionPlan(HANDLE process, uint64_t address,
                                          size_t size,
                                          DebugWriteProtectionPlan& output) {
    if (!process || !size || address > UINT64_MAX - static_cast<uint64_t>(size))
        return false;
    DebugWriteProtectionPlan candidate;
    try { candidate.spans.reserve(8); } catch (...) { return false; }
    const uint64_t end = address + static_cast<uint64_t>(size);
    uint64_t cursor = address;
    while (cursor < end) {
        MEMORY_BASIC_INFORMATION info{};
        if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(cursor), &info,
                           sizeof(info)) != sizeof(info))
            return false;
        const uint64_t regionBase = reinterpret_cast<uint64_t>(info.BaseAddress);
        const uint64_t regionSize = static_cast<uint64_t>(info.RegionSize);
        if (!regionSize || regionBase > UINT64_MAX - regionSize ||
            regionBase + regionSize <= cursor || info.State != MEM_COMMIT ||
            (info.Protect & PAGE_GUARD) ||
            (info.Protect & 0xFFu) == PAGE_NOACCESS)
            return false;
        const DWORD base = info.Protect & 0xFFu;
        const bool readable = base == PAGE_READONLY || base == PAGE_READWRITE ||
            base == PAGE_WRITECOPY || base == PAGE_EXECUTE_READ ||
            base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
        const bool writable = base == PAGE_READWRITE || base == PAGE_WRITECOPY ||
            base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
        const bool executable = base == PAGE_EXECUTE || base == PAGE_EXECUTE_READ ||
            base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
        const bool needsChange = !readable || !writable;
        const uint64_t spanEnd = (std::min)(end, regionBase + regionSize);
        try {
            candidate.spans.push_back({ cursor,
                static_cast<size_t>(spanEnd - cursor), 0,
                needsChange, executable, false });
        } catch (...) {
            return false;
        }
        candidate.executable = candidate.executable || executable;
        candidate.needsAuthority = candidate.needsAuthority || executable || needsChange;
        cursor = spanEnd;
    }
    output = std::move(candidate);
    return true;
}

static bool makeDebugWriteSpansWritable(HANDLE process,
                                        DebugWriteProtectionPlan& plan) {
    for (DebugWriteProtectionSpan& span : plan.spans) {
        if (!span.needsChange) continue;
        DWORD previous = 0;
        const DWORD temporary = span.executable ? PAGE_EXECUTE_READWRITE
                                                : PAGE_READWRITE;
        if (!VirtualProtectEx(process, reinterpret_cast<LPVOID>(span.address),
                              span.size, temporary, &previous))
            return false;
        span.restoreProtect = previous;
        span.changed = true;
    }
    return true;
}

static bool restoreDebugWriteProtections(HANDLE process,
                                         DebugWriteProtectionPlan& plan) {
    bool restored = true;
    for (auto it = plan.spans.rbegin(); it != plan.spans.rend(); ++it) {
        if (!it->changed) continue;
        DWORD ignored = 0;
        if (VirtualProtectEx(process, reinterpret_cast<LPVOID>(it->address),
                             it->size, it->restoreProtect, &ignored))
            it->changed = false;
        else
            restored = false;
    }
    return restored;
}

static bool reopenDebugWriteSpans(HANDLE process,
                                  DebugWriteProtectionPlan& plan) {
    bool reopened = true;
    for (DebugWriteProtectionSpan& span : plan.spans) {
        if (!span.needsChange || span.changed) continue;
        DWORD ignored = 0;
        const DWORD temporary = span.executable ? PAGE_EXECUTE_READWRITE
                                                : PAGE_READWRITE;
        if (VirtualProtectEx(process, reinterpret_cast<LPVOID>(span.address),
                             span.size, temporary, &ignored))
            span.changed = true;
        else
            reopened = false;
    }
    return reopened;
}

size_t Debugger::writeMemoryOwned(std::optional<DebugTargetIdentity> expected,
                                  uint64_t va, const void* in, size_t n,
                                  bool allowProtectionChange) {
    if (!in || !n || n > kMaxMemoryWriteBytes ||
        va > UINT64_MAX - static_cast<uint64_t>(n))
        return 0;

    std::shared_ptr<MemoryWriteRequest> request;
    try {
        request = std::make_shared<MemoryWriteRequest>();
        const auto* first = static_cast<const uint8_t*>(in);
        request->bytes.assign(first, first + n); // caller storage need not outlive this call
    } catch (...) {
        return 0;
    }

    bool wakeRunningTarget = false;
    {
        std::lock_guard<std::mutex> stateLock(mtx_);
        if (state_ != DbgState::Paused && state_ != DbgState::Running) return 0;
        const DebugTargetIdentity current{ pid_, sessionGeneration_ };
        if (!current.valid() || (expected && !DebugTargetIdentityMatches(current, *expected)))
            return 0;
        if (pendingWrites_.size() >= kMaxPendingMemoryWrites ||
            n > kMaxPendingMemoryWriteBytes - pendingWriteBytes_)
            return 0;

        request->epoch = controlEpoch_;
        request->identity = current;
        request->submittedState = state_;
        request->address = va;
        request->allowProtectionChange = allowProtectionChange;
        pendingWrites_.push_back(request);
        pendingWriteBytes_ += n;
        wakeRunningTarget = state_ == DbgState::Running;
    }

    // A paused worker is blocked in waitForCommand; a running worker needs an
    // internal DebugBreakProcess event. Both paths ultimately execute the same
    // transaction on the debug-event thread.
    cmdCv_.notify_all();
    if (wakeRunningTarget) requestTraceSyncBreak(request->identity);

    std::unique_lock<std::mutex> completionLock(request->completionMtx);
    if (request->completionCv.wait_for(completionLock, kMemoryWriteTimeout,
                                      [&request] { return request->done; }))
        return request->result;

    // Do not let a stalled target turn a UI write into an unbounded wait. A
    // queued request is removed below; an already-active request observes this
    // flag before commit and verifies rollback while the debug event stays held.
    request->cancelRequested = true;
    completionLock.unlock();

    bool removed = false;
    {
        std::lock_guard<std::mutex> stateLock(mtx_);
        auto it = std::find(pendingWrites_.begin(), pendingWrites_.end(), request);
        if (it != pendingWrites_.end()) {
            pendingWriteBytes_ -= request->bytes.size();
            pendingWrites_.erase(it);
            removed = true;
        }
    }
    if (removed) {
        {
            std::lock_guard<std::mutex> lock(request->completionMtx);
            request->result = 0;
            request->done = true;
        }
        request->completionCv.notify_all();
    }
    return 0;
}

void Debugger::performMemoryWrite(const std::shared_ptr<MemoryWriteRequest>& request,
                                  uint64_t controlEpoch) {
    std::unique_lock<std::mutex> stateLock(mtx_);
    auto finish = [&](size_t result) {
        std::lock_guard<std::mutex> completionLock(request->completionMtx);
        request->result = request->cancelRequested ? 0 : result;
        request->done = true;
    };
    auto cancelled = [&]() {
        std::lock_guard<std::mutex> completionLock(request->completionMtx);
        return request->cancelRequested;
    };

    if (request->epoch != controlEpoch || request->epoch != controlEpoch_ ||
        !DebugTargetIdentityMatches({ pid_, sessionGeneration_ }, request->identity) ||
        !hProcess_ || request->bytes.empty() || cancelled() || gmlSnapshot_.stop) {
        finish(0);
        stateLock.unlock();
        request->completionCv.notify_all();
        return;
    }

    HANDLE h = static_cast<HANDLE>(hProcess_);
    const size_t n = request->bytes.size();
    const uint64_t va = request->address;
    const uint64_t end = va + static_cast<uint64_t>(n);
    DebugWriteProtectionPlan protection;
    if (!buildDebugWriteProtectionPlan(h, va, n, protection) ||
        (protection.needsAuthority && !request->allowProtectionChange)) {
        finish(0);
        stateLock.unlock();
        request->completionCv.notify_all();
        return;
    }
    if (protection.executable && request->submittedState != DbgState::Paused) {
        finish(0); // executable-memory edits require an explicit user-visible pause
        stateLock.unlock();
        request->completionCv.notify_all();
        return;
    }

    // A temp bp's displaced byte is debug-thread-local, and an anti-debug hook
    // may currently be in its one-instruction pass-through lease. Reject those
    // overlaps instead of making either restoration record stale.
    if (gameMakerOwnsRangeLocked(va,n) ||
        (runtimeTempBpAddr_ && *runtimeTempBpAddr_ >= va && *runtimeTempBpAddr_ < end) ||
        std::any_of(antiTraps_.begin(), antiTraps_.end(), [&](const auto& item) {
            return item.first >= va && item.first < end;
        })) {
        finish(0);
        stateLock.unlock();
        request->completionCv.notify_all();
        return;
    }

    std::vector<uint8_t> physical;
    std::vector<uint8_t> before;
    std::vector<uint8_t> verify;
    try {
        physical = request->bytes;
        before.resize(n);
        verify.resize(n);
    } catch (...) {
        finish(0);
        stateLock.unlock();
        request->completionCv.notify_all();
        return;
    }

    auto keepTrap = [&](uint64_t address) {
        if (address >= va && address < end)
            physical[static_cast<size_t>(address - va)] = 0xCC;
    };
    for (const auto& [address, bp] : bps_) {
        const bool parked = pausedUserBpAddr_ && *pausedUserBpAddr_ == address;
        if (address >= va && address < end &&
            request->bytes[static_cast<size_t>(address - va)] == 0xCC) {
            finish(0); // native INT3 cannot live underneath a displaced-byte bp
            stateLock.unlock();
            request->completionCv.notify_all();
            return;
        }
        if (bp.armed && !parked) keepTrap(address);
    }
    for (const auto& [address, bp] : traceBps_) {
        (void)bp;
        if (address >= va && address < end &&
            request->bytes[static_cast<size_t>(address - va)] == 0xCC) {
            finish(0);
            stateLock.unlock();
            request->completionCv.notify_all();
            return;
        }
        keepTrap(address);
    }
    for (const auto& [address, bp] : dllTargetBps_) {
        if (!bp.ownsByte) continue;
        if (address >= va && address < end &&
            request->bytes[static_cast<size_t>(address - va)] == 0xCC) {
            finish(0);
            stateLock.unlock();
            request->completionCv.notify_all();
            return;
        }
        keepTrap(address);
    }
    for (const auto& [address, bp] : networkProbeBps_) {
        if (!bp.ownsByte) continue;
        if (address >= va && address < end &&
            request->bytes[static_cast<size_t>(address - va)] == 0xCC) {
            finish(0);
            stateLock.unlock();
            request->completionCv.notify_all();
            return;
        }
        if (bp.armed) keepTrap(address);
    }
    for (const auto& [address, bp] : networkReturnBps_) {
        if (!bp.ownsByte) continue;
        if (address >= va && address < end &&
            request->bytes[static_cast<size_t>(address - va)] == 0xCC) {
            finish(0);
            stateLock.unlock();
            request->completionCv.notify_all();
            return;
        }
        if (bp.armed) keepTrap(address);
    }
    for (const auto& [address, bp] : authorizationBps_) {
        if (!bp.ownsByte) continue;
        if (address >= va && address < end &&
            request->bytes[static_cast<size_t>(address - va)] == 0xCC) {
            finish(0);
            stateLock.unlock();
            request->completionCv.notify_all();
            return;
        }
        if (bp.armed) keepTrap(address);
    }
    for (const auto& [address, bp] : authorizationReturnBps_) {
        if (!bp.ownsByte) continue;
        if (address >= va && address < end &&
            request->bytes[static_cast<size_t>(address - va)] == 0xCC) {
            finish(0);
            stateLock.unlock();
            request->completionCv.notify_all();
            return;
        }
        if (bp.armed) keepTrap(address);
    }

    if (!makeDebugWriteSpansWritable(h, protection)) {
        if (!restoreDebugWriteProtections(h, protection))
            lastEvent_ = "memory write protection setup failed and restoration was incomplete";
        finish(0);
        stateLock.unlock();
        request->completionCv.notify_all();
        return;
    }

    SIZE_T got = 0;
    if (!ReadProcessMemory(h, (LPCVOID)va, before.data(), n, &got) ||
        got != n || cancelled()) {
        if (!restoreDebugWriteProtections(h, protection))
            lastEvent_ = "memory read failed and page protection restoration was incomplete";
        finish(0);
        stateLock.unlock();
        request->completionCv.notify_all();
        return;
    }

    auto rollback = [&]() {
        SIZE_T putBack = 0;
        if (!WriteProcessMemory(h, reinterpret_cast<LPVOID>(va), before.data(), n,
                                &putBack) || putBack != n)
            return false;
        if (protection.executable &&
            !FlushInstructionCache(h, reinterpret_cast<LPCVOID>(va), n))
            return false;
        SIZE_T restored = 0;
        return ReadProcessMemory(h, reinterpret_cast<LPCVOID>(va), verify.data(), n,
                                 &restored) && restored == n && verify == before;
    };

    SIZE_T put = 0;
    const bool wrote = WriteProcessMemory(h, reinterpret_cast<LPVOID>(va),
                                          physical.data(), n, &put) && put == n;
    const bool flushed = !protection.executable ||
        FlushInstructionCache(h, reinterpret_cast<LPCVOID>(va), n);
    if (!wrote || !flushed) {
        const bool rolledBack = rollback();
        const bool restored = restoreDebugWriteProtections(h, protection);
        if (!rolledBack || !restored)
            lastEvent_ = "memory write failed and rollback/protection restoration was incomplete";
        finish(0);
        stateLock.unlock();
        request->completionCv.notify_all();
        return;
    }
    got = 0;
    if (!ReadProcessMemory(h, (LPCVOID)va, verify.data(), n, &got) || got != n ||
        verify != physical) {
        const bool rolledBack = rollback();
        const bool restored = restoreDebugWriteProtections(h, protection);
        if (!rolledBack || !restored)
            lastEvent_ = "memory write verification and rollback/protection restoration failed";
        finish(0);
        stateLock.unlock();
        request->completionCv.notify_all();
        return;
    }

    {
        // Timeout/cancellation and ownership publication share this final lock:
        // either the caller receives a committed transaction, or the target is
        // verified back at its exact pre-write bytes before completion.
        std::lock_guard<std::mutex> completionLock(request->completionMtx);
        if (request->cancelRequested) {
            const bool rolledBack = rollback();
            const bool restored = restoreDebugWriteProtections(h, protection);
            if (!rolledBack || !restored)
                lastEvent_ = "timed-out memory write rollback/protection restoration was incomplete";
            request->result = 0;
            request->done = true;
        } else if (!restoreDebugWriteProtections(h, protection)) {
            // Some spans may already be restored. Reopen those, put the exact
            // original bytes back, and retry restoration so a failed protection
            // transition never reports a successful mutation.
            const bool reopened = reopenDebugWriteSpans(h, protection);
            const bool rolledBack = reopened && rollback();
            const bool restored = restoreDebugWriteProtections(h, protection);
            if (!reopened || !rolledBack || !restored)
                lastEvent_ = "memory write protection restoration failed and rollback was incomplete";
            else
                lastEvent_ = "memory write was rolled back after a protection restoration failure";
            request->result = 0;
            request->done = true;
        } else {
            for (auto& [address, bp] : bps_)
                if (address >= va && address < end)
                    bp.orig = request->bytes[static_cast<size_t>(address - va)];
            for (auto& [address, bp] : traceBps_)
                if (address >= va && address < end)
                    bp.orig = request->bytes[static_cast<size_t>(address - va)];
            for (auto& [address, bp] : dllTargetBps_)
                if (address >= va && address < end)
                    bp.orig = request->bytes[static_cast<size_t>(address - va)];
            for (auto& [address, bp] : networkProbeBps_)
                if (address >= va && address < end)
                    bp.orig = request->bytes[static_cast<size_t>(address - va)];
            for (auto& [address, bp] : networkReturnBps_)
                if (address >= va && address < end)
                    bp.orig = request->bytes[static_cast<size_t>(address - va)];
            for (auto& [address, bp] : authorizationBps_)
                if (address >= va && address < end)
                    bp.orig = request->bytes[static_cast<size_t>(address - va)];
            for (auto& [address, bp] : authorizationReturnBps_)
                if (address >= va && address < end)
                    bp.orig = request->bytes[static_cast<size_t>(address - va)];
            request->result = n;
            request->done = true;
        }
    }
    stateLock.unlock();
    request->completionCv.notify_all();
}

void Debugger::servicePendingWrites(uint64_t controlEpoch) {
    for (;;) {
        std::shared_ptr<MemoryWriteRequest> request;
        {
            std::lock_guard<std::mutex> stateLock(mtx_);
            if (pendingWrites_.empty()) break;
            request = std::move(pendingWrites_.front());
            pendingWrites_.pop_front();
            pendingWriteBytes_ -= request->bytes.size();
            activeWrite_ = request;
        }

        try {
            performMemoryWrite(request, controlEpoch);
        } catch (...) {
            {
                std::lock_guard<std::mutex> stateLock(mtx_);
                lastEvent_ = "memory write worker failed before commit";
                std::lock_guard<std::mutex> completionLock(request->completionMtx);
                request->result = 0;
                request->done = true;
            }
            request->completionCv.notify_all();
        }

        {
            std::lock_guard<std::mutex> stateLock(mtx_);
            if (activeWrite_ == request) activeWrite_.reset();
        }
    }
}

size_t Debugger::writeMemory(uint64_t va, const void* in, size_t n) {
    return writeMemoryOwned(std::nullopt, va, in, n);
}

size_t Debugger::writeMemoryForSession(uint32_t expectedPid,
                                       uint64_t expectedSessionGeneration,
                                       uint64_t va, const void* in, size_t n,
                                       bool allowProtectionChange) {
    const DebugTargetIdentity expected{ expectedPid, expectedSessionGeneration };
    return writeMemoryOwned(expected, va, in, n, allowProtectionChange);
}

std::vector<size_t> Debugger::writeMemoryBatchForSession(
    uint32_t expectedPid, uint64_t expectedSessionGeneration,
    const std::vector<MemoryWriteSpan>& writes) {
    std::vector<size_t> results(writes.size(), 0);
    if (writes.empty() || writes.size() > kMaxPendingMemoryWrites) return results;

    std::vector<std::shared_ptr<MemoryWriteRequest>> requests;
    try {
        requests.reserve(writes.size());
        size_t submittedBytes = 0;
        for (const MemoryWriteSpan& write : writes) {
            if (write.bytes.empty() || write.bytes.size() > kMaxMemoryWriteBytes ||
                write.address > UINT64_MAX - static_cast<uint64_t>(write.bytes.size()) ||
                write.bytes.size() > kMaxPendingMemoryWriteBytes - submittedBytes)
                return results;
            submittedBytes += write.bytes.size();
            auto request = std::make_shared<MemoryWriteRequest>();
            request->address = write.address;
            request->bytes = write.bytes;
            request->allowProtectionChange = write.allowProtectionChange;
            requests.push_back(std::move(request));
        }
    } catch (...) {
        return results;
    }

    bool wakeRunningTarget = false;
    {
        std::lock_guard<std::mutex> stateLock(mtx_);
        if (state_ != DbgState::Paused && state_ != DbgState::Running) return results;
        const DebugTargetIdentity expected{
            expectedPid, expectedSessionGeneration
        };
        const DebugTargetIdentity current{ pid_, sessionGeneration_ };
        if (!DebugTargetIdentityMatches(current, expected) ||
            pendingWrites_.size() > kMaxPendingMemoryWrites - requests.size())
            return results;

        size_t submittedBytes = 0;
        for (const auto& request : requests) submittedBytes += request->bytes.size();
        if (submittedBytes > kMaxPendingMemoryWriteBytes - pendingWriteBytes_)
            return results;

        for (const auto& request : requests) {
            request->epoch = controlEpoch_;
            request->identity = current;
            request->submittedState = state_;
            pendingWrites_.push_back(request);
            pendingWriteBytes_ += request->bytes.size();
        }
        wakeRunningTarget = state_ == DbgState::Running;
    }

    cmdCv_.notify_all();
    if (wakeRunningTarget && !requests.empty())
        requestTraceSyncBreak(requests.front()->identity);

    const auto deadline = std::chrono::steady_clock::now() + kMemoryWriteTimeout;
    for (size_t i = 0; i < requests.size(); ++i) {
        const auto& request = requests[i];
        std::unique_lock<std::mutex> completionLock(request->completionMtx);
        if (request->completionCv.wait_until(
                completionLock, deadline, [&request] { return request->done; })) {
            results[i] = request->result;
            continue;
        }
        request->cancelRequested = true;
    }

    // Remove every timed-out request that has not started. An active request
    // observes cancelRequested before committing (or rolls back after verify),
    // exactly like the scalar API.
    std::vector<std::shared_ptr<MemoryWriteRequest>> removed;
    {
        std::lock_guard<std::mutex> stateLock(mtx_);
        for (const auto& request : requests) {
            std::lock_guard<std::mutex> completionLock(request->completionMtx);
            if (request->done || !request->cancelRequested) continue;
            auto it = std::find(pendingWrites_.begin(), pendingWrites_.end(), request);
            if (it == pendingWrites_.end()) continue;
            pendingWriteBytes_ -= request->bytes.size();
            pendingWrites_.erase(it);
            request->result = 0;
            request->done = true;
            removed.push_back(request);
        }
    }
    for (const auto& request : removed) request->completionCv.notify_all();
    return results;
}

static std::vector<MemRegion> enumerateCommittedRegions(HANDLE process) {
    std::vector<MemRegion> out;
    if (!process) return out;
    MEMORY_BASIC_INFORMATION mbi{};
    uint64_t addr = 0;
    while (VirtualQueryEx(process, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD) && !(mbi.Protect & PAGE_NOACCESS)) {
            MemRegion r;
            r.base = (uint64_t)mbi.BaseAddress;
            r.size = (uint64_t)mbi.RegionSize;
            r.allocationBase = (uint64_t)mbi.AllocationBase;
            r.protect = mbi.Protect; r.state = mbi.State; r.type = mbi.Type;
            DWORD p = mbi.Protect & 0xFF;
            r.read  = p & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                           PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
            r.write = p & (PAGE_READWRITE | PAGE_WRITECOPY |
                           PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
            r.exec  = p & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                           PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
            out.push_back(r);
        }
        uint64_t next = (uint64_t)mbi.BaseAddress + (uint64_t)mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
        if (out.size() > 100000) break;
    }
    return out;
}

std::vector<MemRegion> Debugger::regions() {
    std::lock_guard<std::mutex> lk(hProcMtx_);
    return enumerateCommittedRegions(
        static_cast<HANDLE>(hProcessShared_.load()));
}

std::vector<MemRegion> Debugger::regionsForSession(
    uint32_t expectedPid, uint64_t expectedSessionGeneration) {
    std::lock_guard<std::mutex> lk(hProcMtx_);
    HANDLE process = static_cast<HANDLE>(hProcessShared_.load());
    const DebugTargetIdentity expected{
        expectedPid, expectedSessionGeneration
    };
    if (!processHandleMatchesIdentity(process, hProcessIdentity_, expected))
        return {};
    return enumerateCommittedRegions(process);
}

std::vector<DbgModule> Debugger::modulesForSession(
    uint32_t expectedPid, uint64_t expectedSessionGeneration) {
    std::lock_guard<std::mutex> stateLock(mtx_);
    const DebugTargetIdentity expected{
        expectedPid, expectedSessionGeneration
    };
    if (!DebugTargetIdentityMatches({ pid_, sessionGeneration_ }, expected) ||
        (state_ != DbgState::Paused && state_ != DbgState::Running))
        return {};
    return dbgModules_;
}

uint64_t Debugger::allocRemote(size_t n) {
    std::unique_lock<std::mutex> stateLock(mtx_);
    if (state_ != DbgState::Paused) return 0;
    std::lock_guard<std::mutex> lk(hProcMtx_);
    void* h = hProcessShared_.load();
    if (!h || n == 0) return 0;
    void* p = VirtualAllocEx((HANDLE)h, nullptr, n, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!p) return 0;
    remoteAllocs_.push_back((uint64_t)p);
    return (uint64_t)p;
}

void Debugger::freeRemote(uint64_t addr) {
    std::unique_lock<std::mutex> stateLock(mtx_);
    if (state_ != DbgState::Paused) return;
    std::lock_guard<std::mutex> lk(hProcMtx_);
    void* h = hProcessShared_.load();
    auto tracked = std::find(remoteAllocs_.begin(), remoteAllocs_.end(), addr);
    if (!h || !addr || tracked == remoteAllocs_.end() ||
        !VirtualFreeEx((HANDLE)h, (LPVOID)addr, 0, MEM_RELEASE))
        return;
    remoteRegisterBuffers_.erase(addr);
    remoteAllocs_.erase(tracked);
}

void Debugger::freeAllRemote() {
    std::unique_lock<std::mutex> stateLock(mtx_);
    if (state_ != DbgState::Paused) return;
    std::lock_guard<std::mutex> lk(hProcMtx_);
    void* h = hProcessShared_.load();
    if (!h) return;
    for (auto it = remoteAllocs_.begin(); it != remoteAllocs_.end(); ) {
        const uint64_t address = *it;
        if (VirtualFreeEx((HANDLE)h, (LPVOID)address, 0, MEM_RELEASE)) {
            remoteRegisterBuffers_.erase(address);
            it = remoteAllocs_.erase(it);
        } else {
            ++it; // retain ownership so stopped-session cleanup can retry
        }
    }
}

bool Debugger::takeSnapshot(MemSnapshot& out, size_t perRegionCap) {
    DbgSnapshot s = snapshot();          // delegates lock; do NOT hold hProcMtx_ here
    if (!s.attached()) return false;
    out.regs = s.regs;
    out.blocks.clear();
    for (const auto& r : regions()) {    // committed, non-guard regions
        if (!r.read || r.size == 0) continue;
        const size_t len = (r.size < (uint64_t)perRegionCap) ? (size_t)r.size : perRegionCap;
        MemSnapshot::Block b; b.base = r.base; b.bytes.resize(len);
        const size_t got = readMemory(r.base, b.bytes.data(), len);
        if (got) { b.bytes.resize(got); out.blocks.push_back(std::move(b)); }
    }
    return true;
}

bool Debugger::restoreSnapshot(const MemSnapshot& snap) {
    { std::lock_guard<std::mutex> lock(mtx_); if (gmlSnapshot_.stop) return false; }
    if (snapshot().state != DbgState::Paused) return false;   // only safe while stopped
    for (const auto& b : snap.blocks)
        if (!b.bytes.empty()) writeMemory(b.base, b.bytes.data(), b.bytes.size());
    return setRegisters(snap.regs);
}

DbgSnapshot Debugger::snapshot() {
    std::lock_guard<std::mutex> lk(mtx_);
    DbgSnapshot s;
    s.state = state_;
    s.pid = pid_; s.tid = tid_;
    s.sessionGeneration = sessionGeneration_;
    s.regs = regs_;
    s.lastEvent = lastEvent_;
    s.breakpoints.reserve(bps_.size() + failedBpInstalls_.size());
    for (auto& kv : bps_)
        s.breakpoints.push_back({ kv.first, kv.second.cond, kv.second.hits,
                                  kv.second.stops, kv.second.everyN,
                                  kv.second.armed, kv.second.error });
    for (const auto& failed : failedBpInstalls_)
        s.breakpoints.push_back(failed);
    for (auto& hs : hwSlots_) if (hs.used) s.hwBreakpoints.push_back({ hs.addr, hs.kind, hs.size });
    s.threads = threadList_;
    for (auto& t : s.threads) t.suspended = suspended_.count(t.tid) != 0;
    s.frames = frames_;
    s.modules = dbgModules_;
    s.debugOutput.assign(dbgOutput_.begin(), dbgOutput_.end());
    s.activeTid = activeTid_;
    s.is32 = isWow64_.load();
    s.jvmLoaded = jvmLoaded_;
    s.jvmPath = jvmPath_;
    s.jvmExceptionsPassed = jvmExceptionsPassed_;
    s.exceptionSequence = exceptionSequence_;
    s.exceptionCode = exceptionCode_;
    s.exceptionAddress = exceptionAddress_;
    s.exceptionFirstChance = exceptionFirstChance_;
    s.dllHostedLaunch = dllHostedLaunch_;
    s.dllTargetMatched = dllTargetMatched_;
    s.dllTargetPath = dllTargetPath_;
    s.dllTargetBase = dllTargetBase_;
    s.dllTargetSize = dllTargetSize_;
    s.dllTargetLabel = dllTargetLabel_;
    s.dllTargetError = dllTargetError_;
    s.checkedRunTo = checkedRunTo_;
    s.containedJob = containedJob_;
    s.antiDebug = antiDebugStats_;
    return s;
}

Debugger::CommandEnvelope Debugger::waitForCommand(uint64_t controlEpoch) {
    std::unique_lock<std::mutex> lk(mtx_);
    const auto hasBreakpointEdits = [this, controlEpoch] {
        return controlEpoch_ == controlEpoch &&
            (!pendingBpAdds_.empty() || !pendingBpRems_.empty() ||
             !pendingBpConds_.empty() || !pendingBpEveryN_.empty());
    };
    const auto ready = [this, controlEpoch, &hasBreakpointEdits] {
        return quit_ || (pendingCommand_.command != Cmd::None &&
                         pendingCommand_.epoch == controlEpoch) ||
               hasBreakpointEdits() ||
               std::any_of(pendingWrites_.begin(), pendingWrites_.end(),
                           [controlEpoch](const auto& request) {
                               return request->epoch == controlEpoch;
                           });
    };
    // A helper bootstrap may finish host-side preparation while the analyst
    // holds a native pause. Poll its state without waiting for any target work.
    if (gmlSession_) {
        if (!cmdCv_.wait_for(lk, std::chrono::milliseconds(100), ready))
            return {Cmd::ServiceWrites,0,controlEpoch};
    } else cmdCv_.wait(lk, ready);
    CommandEnvelope result{};
    if (quit_) {
        result = { Cmd::Detach, 0, controlEpoch };
    } else {
        const bool hasWrite = std::any_of(
            pendingWrites_.begin(), pendingWrites_.end(),
            [controlEpoch](const auto& request) { return request->epoch == controlEpoch; });
        // Mutations take priority so a Continue queued in the same frame cannot
        // resume the held event before breakpoint changes/writes are serviced.
        if (hasWrite || hasBreakpointEdits()) result = { Cmd::ServiceWrites, 0, controlEpoch };
        else {
            result = pendingCommand_;
            pendingCommand_ = {};
        }
    }
    return result;
}

// ---- debug-thread helpers ---------------------------------------------------

static bool readByteRPM(HANDLE h, uint64_t va, uint8_t& b) {
    SIZE_T got = 0; return ReadProcessMemory(h, (LPCVOID)va, &b, 1, &got) && got == 1;
}
static bool writeByteRPM(HANDLE h, uint64_t va, uint8_t b) {
    SIZE_T put = 0;
    DWORD oldProt = 0;
    BOOL prot = VirtualProtectEx(h, (LPVOID)va, 1, PAGE_EXECUTE_READWRITE, &oldProt);
    bool ok = WriteProcessMemory(h, (LPVOID)va, &b, 1, &put) && put == 1;
    if (prot) VirtualProtectEx(h, (LPVOID)va, 1, oldProt, &oldProt);
    FlushInstructionCache(h, (LPCVOID)va, 1);
    return ok;
}

// A debugger-owned byte transition is valid only while the byte still has the
// value whose ownership we proved. The target is stopped whenever this helper is
// used for breakpoint state, so the compare/write/readback sequence is atomic
// with respect to execution and protects patches/self-modifying code from stale
// cleanup restores.
static bool replaceByteIfEqual(HANDLE h, uint64_t va, uint8_t expected, uint8_t replacement) {
    uint8_t current = 0;
    if (!readByteRPM(h, va, current) || current != expected) return false;
    if (expected == replacement) return true;
    if (!writeByteRPM(h, va, replacement)) return false;
    uint8_t verify = 0;
    if (readByteRPM(h, va, verify) && verify == replacement) return true;
    // Best-effort rollback. Never claim ownership after a failed readback.
    writeByteRPM(h, va, expected);
    return false;
}

static bool restoreDebuggerOwnedByte(HANDLE h, uint64_t va, uint8_t original) {
    uint8_t current = 0;
    if (!readByteRPM(h, va, current)) return false;
    if (current == original) return true; // already exposed/removed
    if (current != 0xCC) return true;     // patch/self-modification superseded us
    return replaceByteIfEqual(h, va, 0xCC, original);
}

debugger_detail::TempBreakpointCleanupDisposition
debugger_detail::ClassifyTempBreakpointCleanup(
    bool persistentOwner,
    bool transitionSucceeded,
    TempBreakpointByteState byteState) noexcept {
    if (transitionSucceeded || persistentOwner ||
        byteState == TempBreakpointByteState::Other ||
        byteState == TempBreakpointByteState::Unmapped)
        return TempBreakpointCleanupDisposition::Release;
    return TempBreakpointCleanupDisposition::Retain;
}

static bool readRemoteExact(HANDLE h, uint64_t va, void* out, size_t size) {
    SIZE_T got = 0;
    return size && ReadProcessMemory(h, (LPCVOID)va, out, size, &got) && got == size;
}

static bool writeRemoteExact(HANDLE h, uint64_t va, const void* in, size_t size) {
    if (!size) return false;
    DWORD oldProt = 0;
    const BOOL changed = VirtualProtectEx(h, (LPVOID)va, size, PAGE_EXECUTE_READWRITE, &oldProt);
    SIZE_T put = 0;
    const bool ok = WriteProcessMemory(h, (LPVOID)va, in, size, &put) && put == size;
    if (changed) VirtualProtectEx(h, (LPVOID)va, size, oldProt, &oldProt);
    FlushInstructionCache(h, (LPCVOID)va, size);
    return ok;
}

void Debugger::rebuildAntiTrapAddrs_() noexcept {
    try {
        std::vector<uint64_t> rebuilt;
        rebuilt.reserve(antiTraps_.size());
        for (const auto& [va, trap] : antiTraps_) {
            (void)trap;
            rebuilt.push_back(va);
        }
        std::sort(rebuilt.begin(), rebuilt.end());
        antiTrapAddrs_.swap(rebuilt);
    } catch (...) {
        // Rebuilds follow erasure; the existing index already contains every
        // surviving address. Allocation-free pruning keeps it conservative.
        antiTrapAddrs_.erase(
            std::remove_if(antiTrapAddrs_.begin(), antiTrapAddrs_.end(),
                           [&](uint64_t va) { return antiTraps_.count(va) == 0; }),
            antiTrapAddrs_.end());
        std::sort(antiTrapAddrs_.begin(), antiTrapAddrs_.end());
    }
}

bool Debugger::installAntiTrap(uint64_t va, AntiTrapKind kind, uint8_t instructionLength,
                               uint64_t ownerImageBase, uint64_t ownerImageSize) {
    if (!hProcess_ ||
        !AntiDebugTrapRangeValid(ownerImageBase, ownerImageSize, va, instructionLength))
        return false;
    MEMORY_BASIC_INFORMATION mbi{};
    auto executableProtection = [](DWORD protection) {
        if (protection & (PAGE_GUARD | PAGE_NOACCESS)) return false;
        switch (protection & 0xFFu) {
            case PAGE_EXECUTE:
            case PAGE_EXECUTE_READ:
            case PAGE_EXECUTE_READWRITE:
            case PAGE_EXECUTE_WRITECOPY: return true;
            default: return false;
        }
    };
    if (VirtualQueryEx((HANDLE)hProcess_, (LPCVOID)va, &mbi, sizeof(mbi)) != sizeof(mbi) ||
        mbi.State != MEM_COMMIT || mbi.Type != MEM_IMAGE ||
        !executableProtection(mbi.Protect) ||
        (uint64_t)(uintptr_t)mbi.AllocationBase != ownerImageBase ||
        !AntiDebugTrapRangeValid((uint64_t)(uintptr_t)mbi.BaseAddress,
                                 static_cast<uint64_t>(mbi.RegionSize),
                                 va, instructionLength))
        return false;
    uint8_t original = 0;
    if (!readByteRPM((HANDLE)hProcess_, va, original) || original == 0xCC) return false;

    // Stage all potentially allocating metadata before mutating target code.
    // If either container rejects/throws, no untracked int3 can be stranded.
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (gameMakerOwnsRangeLocked(va,instructionLength)) return false;
        if (antiTraps_.count(va)) return true;
        if (bps_.count(va) || traceBps_.count(va) || dllTargetBps_.count(va) ||
            authorizationBps_.count(va) || authorizationReturnBps_.count(va))
            return false;
        try {
            auto [it, inserted] = antiTraps_.emplace(
                va, AntiTrap{ original, kind, instructionLength,
                              ownerImageBase, ownerImageSize });
            if (!inserted) return true;
            try {
                antiTrapAddrs_.insert(
                    std::lower_bound(antiTrapAddrs_.begin(), antiTrapAddrs_.end(), va), va);
            } catch (...) {
                antiTraps_.erase(it);
                return false;
            }
        } catch (...) {
            return false;
        }
    }
    if (!writeByteRPM((HANDLE)hProcess_, va, 0xCC)) {
        uint8_t current = 0;
        if (!readByteRPM((HANDLE)hProcess_, va, current) || current != 0xCC) {
            const bool rolledBack = writeByteRPM((HANDLE)hProcess_, va, original);
            if (rolledBack) {
                std::lock_guard<std::mutex> lk(mtx_);
                antiTraps_.erase(va);
                auto indexed = std::lower_bound(antiTrapAddrs_.begin(), antiTrapAddrs_.end(), va);
                if (indexed != antiTrapAddrs_.end() && *indexed == va)
                    antiTrapAddrs_.erase(indexed);
            } else {
                addAntiDebugWarning(
                    "anti-debug trap write and rollback both failed; metadata retained for cleanup");
            }
            return false;
        }
    }

    std::lock_guard<std::mutex> lk(mtx_);
    if (kind == AntiTrapKind::Rdtsc || kind == AntiTrapKind::Rdtscp)
        ++antiDebugStats_.rdtscSitesArmed;
    else
        ++antiDebugStats_.ntdllHooksArmed;
    return true;
}

uint64_t Debugger::resolveMappedExport(uint64_t moduleBase, uint64_t moduleSize,
                                       const char* wanted) {
    if (!hProcess_ || !moduleBase || !moduleSize || !wanted || !*wanted ||
        moduleSize > UINT64_MAX - moduleBase)
        return 0;
    HANDLE hp = (HANDLE)hProcess_;
    auto within = [&](uint64_t offset, uint64_t bytes) {
        return offset <= moduleSize && bytes <= moduleSize - offset;
    };
    auto readAt = [&](uint64_t offset, void* out, size_t bytes) {
        return within(offset, bytes) &&
               readRemoteExact(hp, moduleBase + offset, out, bytes);
    };
    IMAGE_DOS_HEADER dos{};
    if (!readAt(0, &dos, sizeof(dos)) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 || dos.e_lfanew > 0x100000)
        return 0;
    const uint64_t ntOffset = static_cast<uint32_t>(dos.e_lfanew);
    uint32_t signature = 0;
    IMAGE_FILE_HEADER file{};
    if (!readAt(ntOffset, &signature, sizeof(signature)) || signature != IMAGE_NT_SIGNATURE ||
        !readAt(ntOffset + 4, &file, sizeof(file)))
        return 0;
    uint16_t magic = 0;
    if (!readAt(ntOffset + 24, &magic, sizeof(magic))) return 0;
    const uint64_t dataDirectoryOffset = magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? 112u :
                                         magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ? 96u : 0u;
    if (!dataDirectoryOffset || file.SizeOfOptionalHeader < dataDirectoryOffset + 8 ||
        !within(ntOffset + 24, file.SizeOfOptionalHeader))
        return 0;
    const uint64_t dd = ntOffset + 24 + dataDirectoryOffset;
    uint32_t exportRva = 0, exportSize = 0;
    if (!readAt(dd, &exportRva, 4) || !readAt(dd + 4, &exportSize, 4) ||
        !exportRva || !exportSize || !within(exportRva, exportSize) ||
        exportSize < sizeof(IMAGE_EXPORT_DIRECTORY))
        return 0;
    IMAGE_EXPORT_DIRECTORY ex{};
    if (!readAt(exportRva, &ex, sizeof(ex)) ||
        !ex.NumberOfNames || ex.NumberOfNames > 65536 || !ex.NumberOfFunctions ||
        ex.NumberOfFunctions > 65536)
        return 0;

    const uint32_t count = ex.NumberOfNames;
    if (!within(ex.AddressOfNames, uint64_t{count} * sizeof(uint32_t)) ||
        !within(ex.AddressOfNameOrdinals, uint64_t{count} * sizeof(uint16_t)) ||
        !within(ex.AddressOfFunctions,
                uint64_t{ex.NumberOfFunctions} * sizeof(uint32_t)))
        return 0;
    std::vector<uint32_t> names(count);
    std::vector<uint16_t> ordinals(count);
    std::vector<uint32_t> functions(ex.NumberOfFunctions);
    if (!readAt(ex.AddressOfNames, names.data(), names.size() * sizeof(uint32_t)) ||
        !readAt(ex.AddressOfNameOrdinals, ordinals.data(), ordinals.size() * sizeof(uint16_t)) ||
        !readAt(ex.AddressOfFunctions, functions.data(), functions.size() * sizeof(uint32_t)))
        return 0;

    for (uint32_t i = 0; i < count; ++i) {
        if (!within(names[i], 1)) continue;
        char name[128]{};
        SIZE_T got = 0;
        const size_t maxName = static_cast<size_t>((std::min<uint64_t>)(
            sizeof(name) - 1, moduleSize - names[i]));
        if (!ReadProcessMemory(hp, (LPCVOID)(moduleBase + names[i]), name,
                               maxName, &got) || !got)
            continue;
        name[sizeof(name) - 1] = 0;
        if (!std::memchr(name, 0, got)) continue; // reject an unterminated/truncated export name
        if (std::strcmp(name, wanted) != 0) continue;
        const uint16_t ordinal = ordinals[i];
        if (ordinal >= functions.size()) return 0;
        const uint32_t rva = functions[ordinal];
        // A function RVA inside the export directory is a forwarder string.
        const uint64_t exportEnd = uint64_t{exportRva} + exportSize;
        if (!rva || !within(rva, 1) ||
            (rva >= exportRva && uint64_t{rva} < exportEnd))
            return 0;
        return moduleBase + rva;
    }
    return 0;
}

bool Debugger::verifyAntiDebugSyntheticReturns() {
    if (!hProcess_ || !activeAntiDebugPolicy_.requiresNtdllHooks() ||
        !antiDebugCallHooksAllowed_)
        return antiDebugCallHooksAllowed_;

    // SDK-independent ProcessUserShadowStackPolicy layout (enum 15).
    struct ShadowStackPolicyFlags { DWORD Flags = 0; } shadow;
    constexpr auto kUserShadowStackPolicy = static_cast<PROCESS_MITIGATION_POLICY>(15);
    if (GetProcessMitigationPolicy((HANDLE)hProcess_, kUserShadowStackPolicy,
                                   &shadow, sizeof(shadow))) {
        if (shadow.Flags & ((1u << 0) | (1u << 2))) {
            antiDebugCallHooksAllowed_ = false;
            addAntiDebugWarning(
                "CET shadow-stack/IP validation is active; ntdll call concealment was disabled");
        }
    } else {
        const DWORD mitigationError = GetLastError();
        if (mitigationError != ERROR_INVALID_PARAMETER &&
            mitigationError != ERROR_NOT_SUPPORTED) {
            antiDebugCallHooksAllowed_ = false;
            addAntiDebugWarning(
                "could not verify CET shadow-stack policy; ntdll call concealment was disabled");
        }
    }
    return antiDebugCallHooksAllowed_;
}

bool Debugger::normalizeAntiDebugEnvironment(bool deferHeapUnavailableWarning) {
    if (!hProcess_ || (!activeAntiDebugPolicy_.normalizePeb &&
                       !activeAntiDebugPolicy_.normalizeProcessHeap))
        return true;

    using NtQueryInformationProcessFn = LONG (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    auto ntQuery = reinterpret_cast<NtQueryInformationProcessFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    if (!ntQuery) {
        addAntiDebugWarning("NtQueryInformationProcess is unavailable; PEB normalization was skipped");
        return true; // a loader retry cannot make the debugger's own ntdll export appear
    }

    uint64_t peb = 0;
    if (isWow64_.load()) {
        ULONG_PTR wowPeb = 0;
        if (ntQuery((HANDLE)hProcess_, 26, &wowPeb, sizeof(wowPeb), nullptr) >= 0) peb = wowPeb;
    } else {
        struct BasicInfo {
            PVOID reserved1;
            PVOID pebBase;
            PVOID reserved2[2];
            ULONG_PTR processId;
            PVOID reserved3;
        } bi{};
        if (ntQuery((HANDLE)hProcess_, 0, &bi, sizeof(bi), nullptr) >= 0)
            peb = (uint64_t)(uintptr_t)bi.pebBase;
    }
    if (!peb) {
        if (!deferHeapUnavailableWarning)
            addAntiDebugWarning("could not locate the target PEB");
        return false;
    }

    bool complete = true;
    auto reportPatchFailure = [&](const char* label, const char* reason) {
        {
            std::lock_guard<std::mutex> lk(mtx_);
            ++antiDebugStats_.memoryFieldNormalizeFailures;
        }
        addAntiDebugWarning(std::string("could not normalize ") + label + ": " + reason);
    };
    auto patchBytes = [&](uint64_t address, const void* replacement, size_t size,
                          const char* label) -> bool {
        std::vector<uint8_t> original(size), concealed(size);
        std::memcpy(concealed.data(), replacement, size);
        if (!readRemoteExact((HANDLE)hProcess_, address, original.data(), size)) {
            reportPatchFailure(label, "read failed");
            return false;
        }
        if (const PristineMemoryPatch* prior = antiDebugPatches_.find(address)) {
            // A retry must not replace the first observation or overwrite a
            // legitimate target-side mutation made after concealment.
            if (original == prior->concealed) return true;
            reportPatchFailure(label, "target changed the field after concealment; left intact");
            return false;
        }
        if (original == concealed) return true;
        // Save pristine bytes before target mutation. On a failed write, attempt
        // immediate rollback and remove the record only after rollback succeeds.
        if (!antiDebugPatches_.remember(address, original, concealed, label)) {
            reportPatchFailure(label, "pristine-state allocation/capacity failed");
            return false;
        }
        if (!writeRemoteExact((HANDLE)hProcess_, address, concealed.data(), size)) {
            if (writeRemoteExact((HANDLE)hProcess_, address, original.data(), size))
                antiDebugPatches_.forget(address);
            reportPatchFailure(label, "write failed");
            return false;
        }
        std::lock_guard<std::mutex> lk(mtx_);
        ++antiDebugStats_.memoryFieldsNormalized;
        return true;
    };

    if (activeAntiDebugPolicy_.normalizePeb) {
        const uint8_t zero8 = 0;
        complete = patchBytes(peb + 2, &zero8, sizeof(zero8), "PEB.BeingDebugged") && complete;
        const uint64_t ntGlobalAddress = peb + (isWow64_.load() ? 0x68u : 0xBCu);
        uint32_t pristine = 0;
        if (readRemoteExact((HANDLE)hProcess_, ntGlobalAddress, &pristine, sizeof(pristine))) {
            const uint32_t normalized = NormalizeNtGlobalFlag(pristine);
            complete = patchBytes(ntGlobalAddress, &normalized, sizeof(normalized),
                                  "PEB.NtGlobalFlag") && complete;
        } else {
            reportPatchFailure("PEB.NtGlobalFlag", "read failed");
            complete = false;
        }
    }

    if (activeAntiDebugPolicy_.normalizeProcessHeap) {
        const uint64_t heapPtrAddress = peb + (isWow64_.load() ? 0x18u : 0x30u);
        uint64_t heap = 0;
        const size_t ptrSize = isWow64_.load() ? 4u : 8u;
        if (readRemoteExact((HANDLE)hProcess_, heapPtrAddress, &heap, ptrSize) && heap) {
            bool listedHeap = false;
            bool heapListReadable = false;
            HANDLE heapSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, pid_);
            if (heapSnapshot != INVALID_HANDLE_VALUE) {
                HEAPLIST32 item{};
                item.dwSize = sizeof(item);
                if (Heap32ListFirst(heapSnapshot, &item)) {
                    heapListReadable = true;
                    constexpr size_t kHeapListCap = 65536;
                    size_t visited = 0;
                    do {
                        if (static_cast<uint64_t>(item.th32HeapID) == heap) {
                            listedHeap = true;
                            break;
                        }
                        item.dwSize = sizeof(item);
                    } while (++visited < kHeapListCap && Heap32ListNext(heapSnapshot, &item));
                }
                CloseHandle(heapSnapshot);
            }
            if (!heapListReadable || !listedHeap) {
                addAntiDebugWarning(heapListReadable
                    ? "PEB.ProcessHeap did not match the OS heap list; heap fields were left untouched"
                    : "could not verify PEB.ProcessHeap against the OS heap list; heap fields were left untouched");
                return complete;
            }

            uint32_t signature = 0;
            const uint64_t maximumHeapFieldOffset = isWow64_.load() ? 0x48u : 0x78u;
            if (heap > UINT64_MAX - maximumHeapFieldOffset) {
                addAntiDebugWarning(
                    "process-heap field addresses overflowed; heap fields were left untouched");
                return complete;
            }
            const uint64_t signatureAddress = heap + (isWow64_.load() ? 0x08u : 0x10u);
            const uint64_t flagsAddress = heap + (isWow64_.load() ? 0x40u : 0x70u);
            const uint64_t forceAddress = heap + (isWow64_.load() ? 0x44u : 0x74u);
            MEMORY_BASIC_INFORMATION heapRegion{};
            if (VirtualQueryEx((HANDLE)hProcess_, (LPCVOID)heap, &heapRegion,
                               sizeof(heapRegion)) != sizeof(heapRegion) ||
                heapRegion.State != MEM_COMMIT || heapRegion.Type != MEM_PRIVATE ||
                !heapRegion.AllocationBase) {
                addAntiDebugWarning(
                    "the OS-listed process heap had no committed private allocation; heap fields were left untouched");
                return complete;
            }
            const uint64_t heapAllocation =
                static_cast<uint64_t>(reinterpret_cast<uintptr_t>(heapRegion.AllocationBase));
            auto validHeapField = [&](uint64_t address, size_t bytes) {
                if (!address || !bytes || bytes > UINT64_MAX - address) return false;
                MEMORY_BASIC_INFORMATION fieldRegion{};
                if (VirtualQueryEx((HANDLE)hProcess_, (LPCVOID)address, &fieldRegion,
                                   sizeof(fieldRegion)) != sizeof(fieldRegion) ||
                    fieldRegion.State != MEM_COMMIT || fieldRegion.Type != MEM_PRIVATE ||
                    static_cast<uint64_t>(reinterpret_cast<uintptr_t>(fieldRegion.AllocationBase)) !=
                        heapAllocation ||
                    (fieldRegion.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
                    return false;
                const uint64_t regionBase =
                    static_cast<uint64_t>(reinterpret_cast<uintptr_t>(fieldRegion.BaseAddress));
                const uint64_t regionSize = static_cast<uint64_t>(fieldRegion.RegionSize);
                return regionBase <= address && regionSize <= UINT64_MAX - regionBase &&
                       address + bytes <= regionBase + regionSize;
            };
            if (!validHeapField(signatureAddress, sizeof(uint32_t)) ||
                !validHeapField(flagsAddress, sizeof(uint32_t)) ||
                !validHeapField(forceAddress, sizeof(uint32_t))) {
                addAntiDebugWarning(
                    "legacy heap fields were not in one committed OS-listed heap allocation; heap fields were left untouched");
                return complete;
            }
            if (!readRemoteExact((HANDLE)hProcess_, signatureAddress, &signature, sizeof(signature)) ||
                signature != 0xEEFFEEFFu) {
                // Segment heaps and future layouts do not share the legacy
                // _HEAP Flags/ForceFlags offsets.  Refuse to guess and corrupt
                // them; PEB concealment remains active independently.
                addAntiDebugWarning(
                    "process heap is not a validated legacy NT heap; heap fields were left untouched");
                return complete;
            }
            uint32_t flags = 0;
            if (readRemoteExact((HANDLE)hProcess_, flagsAddress, &flags, sizeof(flags))) {
                const uint32_t normalized = NormalizeHeapFlags(flags);
                complete = patchBytes(flagsAddress, &normalized, sizeof(normalized),
                                      "ProcessHeap.Flags") && complete;
            } else {
                reportPatchFailure("ProcessHeap.Flags", "read failed");
                complete = false;
            }
            uint32_t forceFlags = 0;
            if (readRemoteExact((HANDLE)hProcess_, forceAddress, &forceFlags, sizeof(forceFlags))) {
                const uint32_t normalizedForceFlags = NormalizeHeapForceFlags(forceFlags);
                complete = patchBytes(forceAddress, &normalizedForceFlags,
                                      sizeof(normalizedForceFlags),
                                      "ProcessHeap.ForceFlags") && complete;
            } else {
                reportPatchFailure("ProcessHeap.ForceFlags", "read failed");
                complete = false;
            }
        } else {
            if (!deferHeapUnavailableWarning)
                addAntiDebugWarning("could not read the process-heap pointer after the loader breakpoint");
            return false;
        }
    }
    return complete;
}

void Debugger::armAntiDebugForImage(uint64_t base, uint64_t size, bool mainImage,
                                    const std::string& moduleName,
                                    const std::string& modulePath,
                                    bool modulePathTrusted) {
    if (!hProcess_ || !activeAntiDebugPolicy_.enabled() || !base) return;
    IMAGE_DOS_HEADER architectureDos{};
    uint32_t architectureSignature = 0;
    IMAGE_FILE_HEADER architectureFile{};
    uint16_t architectureMagic = 0;
    if (!readRemoteExact((HANDLE)hProcess_, base, &architectureDos, sizeof(architectureDos)) ||
        architectureDos.e_magic != IMAGE_DOS_SIGNATURE || architectureDos.e_lfanew <= 0 ||
        architectureDos.e_lfanew > 0x100000 ||
        !readRemoteExact((HANDLE)hProcess_, base + architectureDos.e_lfanew,
                         &architectureSignature, sizeof(architectureSignature)) ||
        architectureSignature != IMAGE_NT_SIGNATURE ||
        !readRemoteExact((HANDLE)hProcess_, base + architectureDos.e_lfanew + 4,
                         &architectureFile, sizeof(architectureFile)) ||
        !readRemoteExact((HANDLE)hProcess_, base + architectureDos.e_lfanew + 24,
                         &architectureMagic, sizeof(architectureMagic)))
        return;
    // A WOW64 debug session reports both its 32-bit image set and native 64-bit
    // support modules.  Only instrument the architecture represented by ctxReadFull;
    // otherwise an event in the native transition layer would be emulated with the
    // wrong registers/calling convention.
    if ((isWow64_.load() &&
         (architectureMagic != IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
          architectureFile.Machine != IMAGE_FILE_MACHINE_I386)) ||
        (!isWow64_.load() &&
         (architectureMagic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
          architectureFile.Machine != IMAGE_FILE_MACHINE_AMD64)))
        return;
    std::string lower = moduleName;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    // moduleName is the basename derived from the loader's trusted file handle.
    // Require an exact match: suffix matching would instrument evilntdll.dll.
    const bool ntdll = modulePathTrusted && lower == "ntdll.dll" &&
                       isTrustedSystemNtdllPath(modulePath, isWow64_.load());
    if (antiDebugCallHooksAllowed_ && activeAntiDebugPolicy_.requiresNtdllHooks() &&
        lower == "ntdll.dll" && !ntdll) {
        addAntiDebugWarning(modulePathTrusted
            ? "an ntdll-like module was not at the trusted system path; call concealment was skipped"
            : "ntdll loaded without a canonical loader-file path; call concealment was skipped");
    }
    std::vector<uint64_t> trustedFunctionRoots;

    if (ntdll && antiDebugCallHooksAllowed_) {
        const struct Hook { const char* name; AntiTrapKind kind; bool enabled; } hooks[] = {
            { "NtQueryInformationProcess", AntiTrapKind::QueryProcess,
              activeAntiDebugPolicy_.hideProcessDebugQueries },
            { "NtQuerySystemInformation", AntiTrapKind::QuerySystem,
              activeAntiDebugPolicy_.hideKernelDebuggerQuery },
            { "NtQueryInformationThread", AntiTrapKind::QueryThread,
              activeAntiDebugPolicy_.acceptThreadHideRequests },
            { "NtSetInformationThread", AntiTrapKind::SetThread,
              activeAntiDebugPolicy_.acceptThreadHideRequests },
            { "NtClose", AntiTrapKind::CloseHandle,
              activeAntiDebugPolicy_.neutralizeInvalidHandleClose },
            { "NtGetContextThread", AntiTrapKind::GetContext,
              activeAntiDebugPolicy_.maskDebugRegisters },
            { "NtSetContextThread", AntiTrapKind::SetContext,
              activeAntiDebugPolicy_.maskDebugRegisters },
            { "NtQueryPerformanceCounter", AntiTrapKind::QueryPerformanceCounter,
              activeAntiDebugPolicy_.syntheticClock },
            { "NtQuerySystemTime", AntiTrapKind::QuerySystemTime,
              activeAntiDebugPolicy_.syntheticClock },
        };
        for (const Hook& hook : hooks) {
            if (!hook.enabled) continue;
            const uint64_t va = resolveMappedExport(base, size, hook.name);
            if (va) trustedFunctionRoots.push_back(va); // exact trusted ntdll function export
            if (!va || !installAntiTrap(va, hook.kind, 1, base, size)) {
                addAntiDebugWarning(std::string("could not arm ") + hook.name);
            }
        }
    }

    const bool scanTsc = activeAntiDebugPolicy_.rdtsc == RdtscInterception::AllExecutableImages ||
                         (mainImage && activeAntiDebugPolicy_.rdtsc == RdtscInterception::MainExecutable);
    if (!scanTsc) return;
    if (!size || size > UINT64_MAX - base) {
        addAntiDebugWarning("RDTSC discovery skipped an image with an invalid mapped extent");
        return;
    }
    if (!antiDebugRdtscBudgetRemaining_) {
        {
            std::lock_guard<std::mutex> lk(mtx_);
            antiDebugStats_.rdtscDiscoveryBudgetExhausted = true;
            ++antiDebugStats_.rdtscDiscoveryImagesCapped;
            antiDebugStats_.rdtscDiscoveryBudgetRemaining = 0;
        }
        addAntiDebugWarning(
            "session RDTSC discovery budget exhausted; additional images are not covered");
        return;
    }
    const size_t imageBudget = (std::min)(kAntiDebugRdtscPerImageBudget,
                                          antiDebugRdtscBudgetRemaining_);

    IMAGE_DOS_HEADER dos{};
    uint32_t signature = 0;
    IMAGE_FILE_HEADER file{};
    if (!readRemoteExact((HANDLE)hProcess_, base, &dos, sizeof(dos)) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 || dos.e_lfanew > 0x100000 ||
        !readRemoteExact((HANDLE)hProcess_, base + dos.e_lfanew, &signature, 4) ||
        signature != IMAGE_NT_SIGNATURE ||
        !readRemoteExact((HANDLE)hProcess_, base + dos.e_lfanew + 4, &file, sizeof(file)) ||
        !file.NumberOfSections || file.NumberOfSections > 96)
        return;
    const uint64_t ntOffset = static_cast<uint32_t>(dos.e_lfanew);
    const uint64_t optionalOffset = ntOffset + 24;
    if (optionalOffset > size || file.SizeOfOptionalHeader > size - optionalOffset)
        return;
    const uint64_t sectionsOffset = optionalOffset + file.SizeOfOptionalHeader;
    const uint64_t sectionBytes = uint64_t{file.NumberOfSections} * sizeof(IMAGE_SECTION_HEADER);
    if (sectionsOffset > size || sectionBytes > size - sectionsOffset) return;
    const uint64_t sectionsAt = base + sectionsOffset;
    std::vector<IMAGE_SECTION_HEADER> sections(file.NumberOfSections);
    if (!readRemoteExact((HANDLE)hProcess_, sectionsAt, sections.data(),
                         sections.size() * sizeof(IMAGE_SECTION_HEADER)))
        return;

    struct ExecRange { uint64_t begin = 0, end = 0; };
    std::vector<ExecRange> executable;
    executable.reserve(sections.size());
    for (const auto& section : sections) {
        if (!(section.Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        uint64_t span = std::max<uint32_t>(section.Misc.VirtualSize, section.SizeOfRawData);
        if (size && section.VirtualAddress >= size) continue;
        if (size) span = std::min<uint64_t>(span, size - section.VirtualAddress);
        if (!span || base > UINT64_MAX - section.VirtualAddress) continue;
        const uint64_t begin = base + section.VirtualAddress;
        if (span > UINT64_MAX - begin) continue;
        executable.push_back({ begin, begin + span });
    }
    auto isExecutable = [&](uint64_t va) {
        for (const ExecRange& range : executable)
            if (va >= range.begin && va < range.end) return true;
        return false;
    };
    auto isExecutableExtent = [&](uint64_t begin, uint64_t end) {
        if (begin >= end) return false;
        for (const ExecRange& range : executable)
            if (begin >= range.begin && end <= range.end) return true;
        return false;
    };
    if (executable.empty()) return;

    // Seed recursive descent only from loader-proven entry points: the image
    // AddressOfEntryPoint, x64 unwind-function starts, and exact trusted ntdll
    // function exports used above. Never linearly sweep an
    // executable section: packed images commonly mix data/padding with code, and
    // treating a coincidental 0F 31 as an instruction would corrupt the target.
    std::vector<uint64_t> work;
    uint32_t entryRva = 0;
    if (readRemoteExact((HANDLE)hProcess_, base + dos.e_lfanew + 24 + 16,
                        &entryRva, sizeof(entryRva)) && entryRva &&
        base <= UINT64_MAX - entryRva && isExecutable(base + entryRva))
        work.push_back(base + entryRva);
    for (uint64_t root : trustedFunctionRoots)
        if (isExecutable(root)) work.push_back(root);

    const uint64_t dataDirectoryOffset =
        architectureMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? 112u : 96u;
    const uint64_t numberOfDirectoriesOffset =
        architectureMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? 108u : 92u;
    uint32_t numberOfDirectories = 0;
    const bool exceptionDirectoryPresent =
        file.SizeOfOptionalHeader >= dataDirectoryOffset + 4 * 8 &&
        file.SizeOfOptionalHeader >= numberOfDirectoriesOffset + sizeof(uint32_t) &&
        readRemoteExact((HANDLE)hProcess_, base + optionalOffset + numberOfDirectoriesOffset,
                        &numberOfDirectories, sizeof(numberOfDirectories)) &&
        numberOfDirectories >= 4;
    const uint64_t dataDirectory = base + optionalOffset + dataDirectoryOffset;
    uint32_t exceptionRva = 0, exceptionSize = 0;
    if (architectureMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC && exceptionDirectoryPresent &&
        readRemoteExact((HANDLE)hProcess_, dataDirectory + 3 * 8, &exceptionRva, 4) &&
        readRemoteExact((HANDLE)hProcess_, dataDirectory + 3 * 8 + 4, &exceptionSize, 4) &&
        exceptionRva && exceptionSize >= sizeof(RUNTIME_FUNCTION) &&
        exceptionSize % sizeof(RUNTIME_FUNCTION) == 0 &&
        (!size || (exceptionRva < size && exceptionSize <= size - exceptionRva)) &&
        exceptionSize / sizeof(RUNTIME_FUNCTION) <= 65536) {
        const size_t count = std::min<size_t>(exceptionSize / sizeof(RUNTIME_FUNCTION), imageBudget);
        std::vector<RUNTIME_FUNCTION> functions(count);
        if (readRemoteExact((HANDLE)hProcess_, base + exceptionRva,
                            functions.data(), functions.size() * sizeof(RUNTIME_FUNCTION))) {
            for (const RUNTIME_FUNCTION& function : functions) {
                if (!function.BeginAddress || function.BeginAddress >= function.EndAddress ||
                    function.EndAddress > size || !function.UnwindData ||
                    (function.UnwindData & 3u) != 0 || function.UnwindData > size - 4)
                    continue;
                const uint64_t begin = base + function.BeginAddress;
                const uint64_t end = base + function.EndAddress;
                if (!isExecutableExtent(begin, end)) continue;
                uint8_t unwindHeader[4]{};
                if (!readRemoteExact((HANDLE)hProcess_, base + function.UnwindData,
                                     unwindHeader, sizeof(unwindHeader)))
                    continue;
                const uint8_t unwindVersion = unwindHeader[0] & 0x7u;
                const uint8_t unwindFlags = unwindHeader[0] >> 3;
                const uint8_t prologSize = unwindHeader[1];
                const uint8_t codeCount = unwindHeader[2];
                if ((unwindVersion != 1 && unwindVersion != 2) ||
                    (unwindFlags != 0 && unwindFlags != 1 &&
                     unwindFlags != 2 && unwindFlags != 4) ||
                    prologSize > function.EndAddress - function.BeginAddress)
                    continue;
                const uint64_t alignedCodeCount = (uint64_t{codeCount} + 1u) & ~uint64_t{1};
                const uint64_t tailOffset = 4u + alignedCodeCount * 2u;
                if (tailOffset > size - function.UnwindData) continue;
                uint8_t unwindCodes[512]{};
                const size_t unwindCodeBytes = static_cast<size_t>(alignedCodeCount * 2u);
                if (unwindCodeBytes &&
                    !readRemoteExact((HANDLE)hProcess_, base + function.UnwindData + 4,
                                     unwindCodes, unwindCodeBytes))
                    continue;
                const uint64_t tailRva = uint64_t{function.UnwindData} + tailOffset;
                if (unwindFlags == 4) {
                    if (tailRva > size || sizeof(RUNTIME_FUNCTION) > size - tailRva) continue;
                    RUNTIME_FUNCTION chained{};
                    if (!readRemoteExact((HANDLE)hProcess_, base + tailRva,
                                         &chained, sizeof(chained)) ||
                        !chained.BeginAddress || chained.BeginAddress >= chained.EndAddress ||
                        chained.EndAddress > size || !chained.UnwindData ||
                        (chained.UnwindData & 3u) != 0 || chained.UnwindData > size - 4 ||
                        !isExecutableExtent(base + chained.BeginAddress,
                                            base + chained.EndAddress))
                        continue;
                } else if (unwindFlags == 1 || unwindFlags == 2) {
                    if (tailRva > size || sizeof(uint32_t) > size - tailRva) continue;
                    uint32_t handlerRva = 0;
                    if (!readRemoteExact((HANDLE)hProcess_, base + tailRva,
                                         &handlerRva, sizeof(handlerRva)) ||
                        !handlerRva || handlerRva >= size ||
                        !isExecutable(base + handlerRva))
                        continue;
                }
                work.push_back(begin);
            }
        }
    }

    constexpr size_t kTrapCap = 4096;
    IDisassembler* decoder = isWow64_.load() ? ownDis32_.get() : ownDis_.get();
    std::unordered_set<uint64_t> visited;
    visited.reserve(std::min<size_t>(imageBudget, work.size() * 64 + 256));
    size_t cursor = 0;
    size_t consumed = 0;
    bool trapCapHit = false;
    while (decoder && !trapCapHit && cursor < work.size() && visited.size() < imageBudget) {
        uint64_t pc = work[cursor++];
        while (!trapCapHit && isExecutable(pc) && visited.size() < imageBudget) {
            if (!visited.insert(pc).second) break;
            ++consumed;
            --antiDebugRdtscBudgetRemaining_;
            uint8_t bytes[16]{};
            const size_t got = readMemoryMasked(pc, bytes, sizeof(bytes));
            Instruction ins;
            if (!got || !decoder->decodeOne(bytes, got, pc, ins) || !ins.length || ins.length > 15)
                break; // no heuristic byte-by-byte resynchronization
            if (ins.mnemonic == "rdtsc" || ins.mnemonic == "rdtscp") {
                size_t trapCount = 0;
                { std::lock_guard<std::mutex> lk(mtx_); trapCount = antiTraps_.size(); }
                if (trapCount >= kTrapCap) {
                    addAntiDebugWarning(
                        "RDTSC trap cap reached; remaining sites are not covered");
                    trapCapHit = true;
                    antiDebugRdtscBudgetRemaining_ = 0; // no useful future discovery work remains
                    break;
                }
                installAntiTrap(ins.address,
                    ins.mnemonic == "rdtscp" ? AntiTrapKind::Rdtscp : AntiTrapKind::Rdtsc,
                    static_cast<uint8_t>(ins.length), base, size);
            }
            const uint64_t next = pc <= UINT64_MAX - ins.length ? pc + ins.length : 0;
            if (ins.isCall) {
                if (HasBranchTarget(ins) && isExecutable(ins.branchTarget))
                    work.push_back(ins.branchTarget);
                if (!next) break;
                pc = next;
                continue;
            }
            if (ins.isRet) break;
            if (ins.isBranch) {
                if (HasBranchTarget(ins) && isExecutable(ins.branchTarget))
                    work.push_back(ins.branchTarget);
                // Only a direct/indirect unconditional jump has no fallthrough.
                if (ins.mnemonic == "jmp" || ins.mnemonic == "ljmp") break;
            }
            if (!next) break;
            pc = next;
        }
    }
    const bool imageCapped = visited.size() >= imageBudget;
    const bool sessionExhausted = antiDebugRdtscBudgetRemaining_ == 0;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        antiDebugStats_.rdtscDiscoveryInstructions += consumed;
        if (imageCapped) ++antiDebugStats_.rdtscDiscoveryImagesCapped;
        if (sessionExhausted) antiDebugStats_.rdtscDiscoveryBudgetExhausted = true;
        antiDebugStats_.rdtscDiscoveryBudgetRemaining = antiDebugRdtscBudgetRemaining_;
    }
    if (imageCapped)
        addAntiDebugWarning(
            "per-image reachable RDTSC discovery cap reached; undiscovered sites were skipped");
    if (sessionExhausted)
        addAntiDebugWarning(
            "session RDTSC discovery budget exhausted; additional images are not covered");
}

bool Debugger::handleAntiTrap(uint64_t va, uint32_t tid) {
    AntiTrap trap;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = antiTraps_.find(va);
        if (it == antiTraps_.end()) return false;
        trap = it->second;
    }
    auto thread = threads_.find(tid);
    if (thread == threads_.end()) return false;
    Registers regs;
    if (!ctxReadFull(thread->second, regs)) return false;
    HANDLE hp = (HANDLE)hProcess_;
    const bool wow64 = isWow64_.load();
    const size_t ptrSize = wow64 ? 4u : 8u;
    size_t x86StackArgumentBytes = 0;

    auto argument = [&](size_t index, uint64_t& value) -> bool {
        value = 0;
        if (!wow64) {
            if (index == 0) { value = regs.rcx; return true; }
            if (index == 1) { value = regs.rdx; return true; }
            if (index == 2) { value = regs.r8;  return true; }
            if (index == 3) { value = regs.r9;  return true; }
            return readRemoteExact(hp, regs.rsp + 0x28 + (index - 4) * 8, &value, 8);
        }
        uint32_t value32 = 0;
        if (!readRemoteExact(hp, regs.rsp + 4 + index * 4, &value32, 4)) return false;
        value = value32;
        return true;
    };
    auto returnAddress = [&]() -> uint64_t {
        uint64_t result = 0;
        return readRemoteExact(hp, regs.rsp, &result, ptrSize) ? result : 0;
    };
    auto skipFunction = [&](uint32_t status) -> bool {
        const uint64_t ret = returnAddress();
        if (!ret) return false;
        regs.rax = status; // NTSTATUS is returned through EAX (zero-extended on x64)
        regs.rip = ret;
        regs.rsp += ptrSize + (wow64 ? x86StackArgumentBytes : 0);
        return ctxWriteFull(thread->second, regs);
    };
    auto writeDecision = [&](const AntiDebugDecision& decision, uint64_t output) -> bool {
        switch (decision.output) {
            case AntiDebugOutput::None: return true;
            case AntiDebugOutput::ZeroPointer: {
                const uint64_t zero = 0;
                return output && writeRemoteExact(hp, output, &zero, ptrSize);
            }
            case AntiDebugOutput::OneU32: {
                const uint32_t one = 1;
                return output && writeRemoteExact(hp, output, &one, sizeof(one));
            }
            case AntiDebugOutput::KernelDebuggerInfo: {
                const uint8_t value[2] = { 0, 1 };
                return output && writeRemoteExact(hp, output, value, sizeof(value));
            }
            case AntiDebugOutput::FalseByte: {
                const uint8_t zero = 0;
                return output && writeRemoteExact(hp, output, &zero, sizeof(zero));
            }
        }
        return false;
    };
    auto publishConcealed = [&](uint64_t AntiDebugSessionStats::*counter) {
        std::lock_guard<std::mutex> lk(mtx_);
        ++(antiDebugStats_.*counter);
    };

    if (trap.kind == AntiTrapKind::Rdtsc || trap.kind == AntiTrapKind::Rdtscp) {
        const bool rdtscp = trap.kind == AntiTrapKind::Rdtscp;
        const RdtscValue value = antiDebugClock_.nextTsc(rdtscp);
        regs.rax = value.eax;
        regs.rdx = value.edx;
        if (rdtscp) regs.rcx = value.ecx;
        regs.rip = va + trap.instructionLength;
        if (!ctxWriteFull(thread->second, regs)) return false;
        publishConcealed(&AntiDebugSessionStats::rdtscInstructionsEmulated);
        return true;
    }

    // The target may enable CET after CREATE_PROCESS. Re-check immediately
    // before every synthetic function return; on change, fail open through the
    // original ntdll instruction instead of risking shadow-stack divergence.
    if (!verifyAntiDebugSyntheticReturns()) return false;

    AntiDebugCall call = AntiDebugCall::NtQueryInformationProcess;
    const size_t requiredArguments = [&]() -> size_t {
        switch (trap.kind) {
            case AntiTrapKind::QueryProcess:
            case AntiTrapKind::QueryThread: return 5;
            case AntiTrapKind::QuerySystem:
            case AntiTrapKind::SetThread: return 4;
            case AntiTrapKind::GetContext:
            case AntiTrapKind::SetContext:
            case AntiTrapKind::QueryPerformanceCounter: return 2;
            case AntiTrapKind::CloseHandle:
            case AntiTrapKind::QuerySystemTime: return 1;
            case AntiTrapKind::Rdtsc:
            case AntiTrapKind::Rdtscp: return 0;
        }
        return 0;
    }();
    uint64_t args[5]{};
    for (size_t i = 0; i < requiredArguments; ++i) {
        // In WOW64 every argument is stack-backed. Never turn an unreadable
        // stack into plausible zero values (notably a false invalid NtClose).
        if (!argument(i, args[i])) return false;
    }
    const uint64_t arg0 = args[0], arg1 = args[1], arg2 = args[2];
    const uint64_t arg3 = args[3], arg4 = args[4];
    uint32_t infoClass = 0;
    size_t outputLength = 0;
    uint64_t output = 0;
    bool invalidHandle = false;
    bool sameTargetHandle = true;
    bool informationBufferPresent = true;
    const uint64_t currentProcess = wow64 ? 0xFFFFFFFFu : UINT64_MAX;
    const uint64_t currentThread = wow64 ? 0xFFFFFFFEu : UINT64_MAX - 1;
    using CompareObjectHandlesFn = BOOL (WINAPI*)(HANDLE, HANDLE);
    auto compareObjectHandles = reinterpret_cast<CompareObjectHandlesFn>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CompareObjectHandles"));
    if (!compareObjectHandles) {
        compareObjectHandles = reinterpret_cast<CompareObjectHandlesFn>(
            GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "CompareObjectHandles"));
    }
    auto sameProcessHandle = [&](uint64_t raw) -> bool {
        if (raw == currentProcess) return true;
        if (!raw) return false;
        HANDLE duplicate = nullptr;
        if (!DuplicateHandle(hp, (HANDLE)(uintptr_t)raw, GetCurrentProcess(), &duplicate,
                             0, FALSE, DUPLICATE_SAME_ACCESS))
            return false;
        const bool sameObject = compareObjectHandles &&
                                compareObjectHandles(duplicate, (HANDLE)hProcess_) != FALSE;
        const DWORD owner = sameObject ? pid_ : GetProcessId(duplicate);
        CloseHandle(duplicate);
        return owner != 0 && owner == pid_;
    };
    auto sameThreadHandle = [&](uint64_t raw) -> bool {
        if (raw == currentThread) return true;
        if (!raw) return false;
        HANDLE duplicate = nullptr;
        if (!DuplicateHandle(hp, (HANDLE)(uintptr_t)raw, GetCurrentProcess(), &duplicate,
                             0, FALSE, DUPLICATE_SAME_ACCESS))
            return false;
        bool sameObject = false;
        if (compareObjectHandles) {
            for (const auto& [knownTid, knownHandle] : threads_) {
                (void)knownTid;
                if (compareObjectHandles(duplicate, (HANDLE)knownHandle)) {
                    sameObject = true;
                    break;
                }
            }
        }
        const DWORD owner = sameObject ? pid_ : GetProcessIdOfThread(duplicate);
        CloseHandle(duplicate);
        return owner != 0 && owner == pid_;
    };
    switch (trap.kind) {
        case AntiTrapKind::QueryProcess:
            call = AntiDebugCall::NtQueryInformationProcess;
            infoClass = static_cast<uint32_t>(arg1); output = arg2; outputLength = static_cast<size_t>(arg3);
            sameTargetHandle = sameProcessHandle(arg0);
            informationBufferPresent = output != 0;
            break;
        case AntiTrapKind::QuerySystem:
            call = AntiDebugCall::NtQuerySystemInformation;
            infoClass = static_cast<uint32_t>(arg0); output = arg1; outputLength = static_cast<size_t>(arg2);
            informationBufferPresent = output != 0;
            break;
        case AntiTrapKind::QueryThread:
            call = AntiDebugCall::NtQueryInformationThread;
            infoClass = static_cast<uint32_t>(arg1); output = arg2; outputLength = static_cast<size_t>(arg3);
            sameTargetHandle = sameThreadHandle(arg0);
            informationBufferPresent = output != 0;
            break;
        case AntiTrapKind::SetThread:
            call = AntiDebugCall::NtSetInformationThread;
            infoClass = static_cast<uint32_t>(arg1);
            output = arg2;
            outputLength = static_cast<size_t>(arg3);
            sameTargetHandle = sameThreadHandle(arg0);
            informationBufferPresent = output != 0;
            break;
        case AntiTrapKind::CloseHandle: {
            call = AntiDebugCall::NtClose;
            if (arg0 != currentProcess && arg0 != currentThread) {
                HANDLE duplicate = nullptr;
                if (!arg0) invalidHandle = true;
                else if (DuplicateHandle(hp, (HANDLE)(uintptr_t)arg0, GetCurrentProcess(), &duplicate,
                                         0, FALSE, DUPLICATE_SAME_ACCESS)) {
                    CloseHandle(duplicate);
                } else {
                    invalidHandle = GetLastError() == ERROR_INVALID_HANDLE;
                }
            }
            break;
        }
        case AntiTrapKind::GetContext:
            call = AntiDebugCall::NtGetContextThread;
            sameTargetHandle = sameThreadHandle(arg0);
            informationBufferPresent = arg1 != 0;
            break;
        case AntiTrapKind::SetContext:
            call = AntiDebugCall::NtSetContextThread;
            sameTargetHandle = sameThreadHandle(arg0);
            informationBufferPresent = arg1 != 0;
            break;
        case AntiTrapKind::QueryPerformanceCounter: call = AntiDebugCall::NtQueryPerformanceCounter; break;
        case AntiTrapKind::QuerySystemTime: call = AntiDebugCall::NtQuerySystemTime; break;
        case AntiTrapKind::Rdtsc:
        case AntiTrapKind::Rdtscp: break;
    }
    const AntiDebugDecision decision = DecideAntiDebugCall(activeAntiDebugPolicy_, call,
                                                            infoClass, outputLength,
                                                            invalidHandle, ptrSize,
                                                            sameTargetHandle,
                                                            informationBufferPresent);
    x86StackArgumentBytes = AntiDebugX86StackArgumentBytes(call);
    if (!decision.intercept || !returnAddress()) return false;

    if (trap.kind == AntiTrapKind::GetContext || trap.kind == AntiTrapKind::SetContext) {
        const uint64_t rawHandle = arg0;
        HANDLE target = nullptr, duplicate = nullptr;
        bool targetsEventThread = false;
        if (rawHandle == currentThread) {
            target = (HANDLE)thread->second;
            targetsEventThread = true;
        } else if (DuplicateHandle(hp, (HANDLE)(uintptr_t)rawHandle, GetCurrentProcess(), &duplicate,
                                   0, FALSE, DUPLICATE_SAME_ACCESS)) {
            target = duplicate;
            targetsEventThread = compareObjectHandles
                ? compareObjectHandles(duplicate, (HANDLE)thread->second) != FALSE
                : GetThreadId(duplicate) == tid;
        }
        bool mediated = false;
        if (target && arg1) {
            if (wow64) {
                WOW64_CONTEXT context{};
                if (readRemoteExact(hp, arg1, &context, sizeof(context))) {
                    if (trap.kind == AntiTrapKind::GetContext) {
                        if (Wow64GetThreadContext(target, &context)) {
                            context.Dr0 = context.Dr1 = context.Dr2 = context.Dr3 = 0;
                            context.Dr6 = context.Dr7 = 0;
                            mediated = writeRemoteExact(hp, arg1, &context, sizeof(context));
                        }
                    } else {
                        if (!CanMediateSetContext(targetsEventThread, context.ContextFlags)) {
                            addAntiDebugWarning(
                                "self NtSetContextThread requested non-DR groups; call passed through to preserve semantics");
                        } else {
                            context.ContextFlags &= ~DWORD{0x10}; // DEBUG_REGISTERS group only
                            const DWORD groups = context.ContextFlags & 0xFFFFu;
                            mediated = !groups || Wow64SetThreadContext(target, &context) != 0;
                            if (mediated) applyHwToThread(target);
                        }
                    }
                }
            } else {
                CONTEXT context{};
                if (readRemoteExact(hp, arg1, &context, sizeof(context))) {
                    if (trap.kind == AntiTrapKind::GetContext) {
                        if (GetThreadContext(target, &context)) {
                            context.Dr0 = context.Dr1 = context.Dr2 = context.Dr3 = 0;
                            context.Dr6 = context.Dr7 = 0;
                            mediated = writeRemoteExact(hp, arg1, &context, sizeof(context));
                        }
                    } else {
                        if (!CanMediateSetContext(targetsEventThread, context.ContextFlags)) {
                            addAntiDebugWarning(
                                "self NtSetContextThread requested non-DR groups; call passed through to preserve semantics");
                        } else {
                            context.ContextFlags &= ~DWORD{0x10};
                            const DWORD groups = context.ContextFlags & 0xFFFFu;
                            mediated = !groups || SetThreadContext(target, &context) != 0;
                            if (mediated) applyHwToThread(target);
                        }
                    }
                }
            }
        }
        if (duplicate) CloseHandle(duplicate);
        if (!mediated || !skipFunction(0)) return false;
        publishConcealed(&AntiDebugSessionStats::contextCallsMediated);
        return true;
    }

    if (trap.kind == AntiTrapKind::QueryPerformanceCounter) {
        const int64_t counter = static_cast<int64_t>(antiDebugClock_.nextQpc());
        const int64_t frequency = static_cast<int64_t>(antiDebugClock_.qpcFrequency());
        if (!arg0 || !writeRemoteExact(hp, arg0, &counter, sizeof(counter)) ||
            (arg1 && !writeRemoteExact(hp, arg1, &frequency, sizeof(frequency))) ||
            !skipFunction(0))
            return false;
        publishConcealed(&AntiDebugSessionStats::clockCallsSynthesized);
        return true;
    }
    if (trap.kind == AntiTrapKind::QuerySystemTime) {
        const int64_t time = static_cast<int64_t>(antiDebugClock_.nextSystemTime100ns());
        if (!arg0 || !writeRemoteExact(hp, arg0, &time, sizeof(time)) || !skipFunction(0)) return false;
        publishConcealed(&AntiDebugSessionStats::clockCallsSynthesized);
        return true;
    }

    if (!writeDecision(decision, output)) return false;
    // ReturnLength is arg4 for process/thread queries and arg3 for system queries.
    uint64_t returnLength = 0;
    if (trap.kind == AntiTrapKind::QueryProcess || trap.kind == AntiTrapKind::QueryThread)
        returnLength = arg4;
    else if (trap.kind == AntiTrapKind::QuerySystem)
        returnLength = arg3;
    if (returnLength && decision.requiredOutputBytes) {
        const uint32_t length = static_cast<uint32_t>(decision.requiredOutputBytes);
        if (!writeRemoteExact(hp, returnLength, &length, sizeof(length))) return false;
    }
    if (!skipFunction(decision.status)) return false;
    publishConcealed(&AntiDebugSessionStats::queryCallsConcealed);
    return true;
}

void Debugger::restoreAntiDebugState(bool targetAlive) {
    if (!hProcess_) return;
    std::vector<std::pair<uint64_t, AntiTrap>> traps;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        traps.reserve(antiTraps_.size());
        for (const auto& entry : antiTraps_) traps.push_back(entry);
    }
    uint64_t trapRestoreFailures = 0;
    uint64_t memoryRestoreFailures = 0;
    if (targetAlive) {
        for (const auto& [va, trap] : traps) {
            uint8_t current = 0;
            // Conditional restore avoids overwriting self-modified code that replaced
            // our int3 after it was armed.
            if (!readByteRPM((HANDLE)hProcess_, va, current)) {
                ++trapRestoreFailures;
            } else if (current == 0xCC &&
                       !writeByteRPM((HANDLE)hProcess_, va, trap.orig)) {
                ++trapRestoreFailures;
            }
        }
        for (const PristineMemoryPatch& patch : antiDebugPatches_.patches()) {
            std::vector<uint8_t> current(patch.concealed.size());
            if (!readRemoteExact((HANDLE)hProcess_, patch.address,
                                 current.data(), current.size())) {
                ++memoryRestoreFailures;
                continue;
            }
            if (!PristinePatchSet::shouldRestore(patch, current)) continue;
            if (writeRemoteExact((HANDLE)hProcess_, patch.address,
                                 patch.original.data(), patch.original.size())) {
                std::lock_guard<std::mutex> lk(mtx_);
                ++antiDebugStats_.memoryFieldsRestored;
            } else {
                ++memoryRestoreFailures;
            }
        }
    }
    if (trapRestoreFailures || memoryRestoreFailures) {
        {
            std::lock_guard<std::mutex> lk(mtx_);
            antiDebugStats_.antiTrapRestoreFailures += trapRestoreFailures;
            antiDebugStats_.memoryFieldRestoreFailures += memoryRestoreFailures;
        }
        if (trapRestoreFailures)
            addAntiDebugWarning("one or more anti-debug trap bytes could not be restored");
        if (memoryRestoreFailures)
            addAntiDebugWarning("one or more PEB/heap fields could not be restored");
    }
    antiDebugPatches_.clear();
    antiDebugCallHooksAllowed_ = true;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        antiTraps_.clear();
        antiTrapAddrs_.clear();
        antiDebugStats_.active = false;
    }
    activeAntiDebugPolicy_ = {};
    antiDebugRdtscBudgetRemaining_ = 0;
}

void Debugger::retireAntiDebugImage(uint64_t imageBase) {
    if (!imageBase) return;
    std::lock_guard<std::mutex> lk(mtx_);
    for (auto it = antiTraps_.begin(); it != antiTraps_.end(); ) {
        if (it->second.ownerImageBase == imageBase) it = antiTraps_.erase(it);
        else ++it;
    }
    // UNLOAD_DLL is delivered for an image whose mapping is going away. Never
    // write a saved byte here: the VA may already be inaccessible and may be
    // reused before detach. Retirement alone prevents stale masking/restoration.
    rebuildAntiTrapAddrs_();
}

// ---- arch-aware thread-context access ---------------------------------------
// A 32-bit (WOW64) target's registers live in a WOW64_CONTEXT reached via
// Wow64Get/SetThreadContext; a native 64-bit target uses the normal CONTEXT.
// 32-bit values are zero-extended into the 64-bit Registers fields so the rest of
// the engine (stepping, conditions, UI) is arch-agnostic.

bool Debugger::ctxReadFull(void* hThread, Registers& out) {
    out = Registers{};
    if (isWow64_.load()) {
        WOW64_CONTEXT c{}; c.ContextFlags = WOW64_CONTEXT_FULL;
        if (!Wow64GetThreadContext((HANDLE)hThread, &c)) return false;
        out.rip = c.Eip; out.rsp = c.Esp; out.rbp = c.Ebp; out.rflags = c.EFlags;
        out.rax = c.Eax; out.rbx = c.Ebx; out.rcx = c.Ecx; out.rdx = c.Edx;
        out.rsi = c.Esi; out.rdi = c.Edi;   // r8-r15 don't exist in 32-bit mode
        return true;
    }
    CONTEXT c{}; c.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext((HANDLE)hThread, &c)) return false;
    out.rip = c.Rip; out.rsp = c.Rsp; out.rbp = c.Rbp; out.rflags = c.EFlags;
    out.rax = c.Rax; out.rbx = c.Rbx; out.rcx = c.Rcx; out.rdx = c.Rdx;
    out.rsi = c.Rsi; out.rdi = c.Rdi;
    out.r8  = c.R8;  out.r9  = c.R9;  out.r10 = c.R10; out.r11 = c.R11;
    out.r12 = c.R12; out.r13 = c.R13; out.r14 = c.R14; out.r15 = c.R15;
    return true;
}

bool Debugger::ctxWriteFull(void* hThread, const Registers& r) {
    if (isWow64_.load()) {
        WOW64_CONTEXT c{}; c.ContextFlags = WOW64_CONTEXT_FULL;
        if (!Wow64GetThreadContext((HANDLE)hThread, &c)) return false;   // preserve seg/FP/debug
        c.Eip = (DWORD)r.rip; c.Esp = (DWORD)r.rsp; c.Ebp = (DWORD)r.rbp; c.EFlags = (DWORD)r.rflags;
        c.Eax = (DWORD)r.rax; c.Ebx = (DWORD)r.rbx; c.Ecx = (DWORD)r.rcx; c.Edx = (DWORD)r.rdx;
        c.Esi = (DWORD)r.rsi; c.Edi = (DWORD)r.rdi;
        c.ContextFlags = WOW64_CONTEXT_FULL;
        return Wow64SetThreadContext((HANDLE)hThread, &c) != 0;
    }
    CONTEXT c{}; c.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext((HANDLE)hThread, &c)) return false;
    c.Rip = r.rip; c.Rsp = r.rsp; c.Rbp = r.rbp; c.EFlags = (DWORD)r.rflags;
    c.Rax = r.rax; c.Rbx = r.rbx; c.Rcx = r.rcx; c.Rdx = r.rdx; c.Rsi = r.rsi; c.Rdi = r.rdi;
    c.R8  = r.r8;  c.R9  = r.r9;  c.R10 = r.r10; c.R11 = r.r11;
    c.R12 = r.r12; c.R13 = r.r13; c.R14 = r.r14; c.R15 = r.r15;
    c.ContextFlags = CONTEXT_FULL;
    return SetThreadContext((HANDLE)hThread, &c) != 0;
}

uint64_t Debugger::ctxReadRip(void* hThread) {
    if (isWow64_.load()) {
        WOW64_CONTEXT c{}; c.ContextFlags = WOW64_CONTEXT_CONTROL;
        return Wow64GetThreadContext((HANDLE)hThread, &c) ? (uint64_t)c.Eip : 0;
    }
    CONTEXT c{}; c.ContextFlags = CONTEXT_CONTROL;
    return GetThreadContext((HANDLE)hThread, &c) ? (uint64_t)c.Rip : 0;
}

void Debugger::ctxSetRip(void* hThread, uint64_t rip) {
    if (isWow64_.load()) {
        WOW64_CONTEXT c{}; c.ContextFlags = WOW64_CONTEXT_CONTROL;
        if (Wow64GetThreadContext((HANDLE)hThread, &c)) {
            c.Eip = (DWORD)rip; c.ContextFlags = WOW64_CONTEXT_CONTROL;
            Wow64SetThreadContext((HANDLE)hThread, &c);
        }
        return;
    }
    CONTEXT c{}; c.ContextFlags = CONTEXT_CONTROL;
    if (GetThreadContext((HANDLE)hThread, &c)) { c.Rip = rip; SetThreadContext((HANDLE)hThread, &c); }
}

void Debugger::clearBreakpointInstallFailureLocked(uint64_t va) {
    std::erase_if(failedBpInstalls_, [va](const SwBreakpointInfo& failed) {
        return failed.address == va;
    });
}

bool Debugger::armBreakpoint(uint64_t va) {
    uint8_t orig = 0;
    bool ownsByte = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (gameMakerOwnsRangeLocked(va,1)) return false;
        auto it = bps_.find(va);
        if (it == bps_.end()) return false;
        orig = it->second.orig;
        ownsByte = it->second.ownsByte;
        if (!ownsByte) {
            it->second.armed = true;
            it->second.error.clear();
            return true;
        }
    }
    const bool ok = orig != 0xCC &&
        replaceByteIfEqual((HANDLE)hProcess_, va, orig, 0xCC);
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (auto it = bps_.find(va); it != bps_.end()) {
            it->second.armed = ok;
            it->second.error = ok ? std::string{} : "could not re-arm owned breakpoint byte";
        }
    }
    return ok;
}
bool Debugger::disarmBreakpoint(uint64_t va) {
    uint8_t orig = 0;
    bool ownsByte = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = bps_.find(va);
        if (it == bps_.end()) return false;
        orig = it->second.orig;
        ownsByte = it->second.ownsByte;
        if (!ownsByte) return true; // the shared anti-debug hook mediates the byte
    }
    uint8_t current = 0;
    const bool ok = readByteRPM((HANDLE)hProcess_, va, current) &&
        (current == orig || replaceByteIfEqual((HANDLE)hProcess_, va, 0xCC, orig));
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (auto it = bps_.find(va); it != bps_.end()) {
            it->second.armed = false;
            it->second.error = ok ? std::string{} : "could not restore owned breakpoint byte";
        }
    }
    return ok;
}

bool Debugger::disarmAuthorizationBreakpoint(uint64_t va) {
    AuthorizationBp site;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = authorizationBps_.find(va);
        if (it == authorizationBps_.end()) return false;
        site = it->second;
        it->second.armed = false;
        if (auto completion = authorizationReturnBps_.find(va);
            completion != authorizationReturnBps_.end())
            completion->second.armed = false;
    }
    return !site.ownsByte ||
           replaceByteIfEqual((HANDLE)hProcess_, va, 0xCC, site.orig);
}

bool Debugger::rearmAuthorizationBreakpoint(uint64_t va) {
    AuthorizationBp site;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = authorizationBps_.find(va);
        if (it == authorizationBps_.end()) return false;
        site = it->second;
    }
    const bool ok = !site.ownsByte ||
                    replaceByteIfEqual((HANDLE)hProcess_, va, site.orig, 0xCC);
    if (ok) {
        std::lock_guard<std::mutex> lk(mtx_);
        if (auto it = authorizationBps_.find(va); it != authorizationBps_.end())
            it->second.armed = true;
        if (auto it = authorizationReturnBps_.find(va);
            it != authorizationReturnBps_.end())
            it->second.armed = true;
    }
    return ok;
}

bool Debugger::disarmAuthorizationReturn(uint64_t va) {
    AuthorizationReturnBp site;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = authorizationReturnBps_.find(va);
        if (it == authorizationReturnBps_.end()) return false;
        site = it->second;
        it->second.armed = false;
    }
    return !site.ownsByte ||
           replaceByteIfEqual((HANDLE)hProcess_, va, 0xCC, site.orig);
}

bool Debugger::rearmAuthorizationReturn(uint64_t va) {
    AuthorizationReturnBp site;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = authorizationReturnBps_.find(va);
        if (it == authorizationReturnBps_.end()) return false;
        site = it->second;
    }
    const bool ok = !site.ownsByte ||
                    replaceByteIfEqual((HANDLE)hProcess_, va, site.orig, 0xCC);
    if (ok) {
        std::lock_guard<std::mutex> lk(mtx_);
        if (auto it = authorizationReturnBps_.find(va);
            it != authorizationReturnBps_.end())
            it->second.armed = true;
    }
    return ok;
}

// Rebuild the UI-visible thread list (debug thread; debuggee is stopped here).
void Debugger::refreshThreadList() {
    std::vector<ThreadInfo> list;
    std::vector<std::pair<uint32_t, void*>> handles;
    for (auto& kv : threads_) {
        ThreadInfo ti; ti.tid = kv.first;
        ti.rip = ctxReadRip(kv.second);
        list.push_back(ti);
        handles.emplace_back(kv.first, kv.second);
    }
    std::lock_guard<std::mutex> lk(mtx_);
    threadList_.swap(list);
    threadHandles_.swap(handles);
}

// Real call-stack unwind of the stopped debuggee (debug thread only; the target is
// frozen at an event here, so its memory/contexts are stable). Uses DbgHelp's
// StackWalk64, driven by:
//   - ReadProcessMemory       -> read the debuggee's frames/return addresses
//   - SymFunctionTableAccess64 -> the .pdata unwind tables (function table access)
//   - SymGetModuleBase64       -> the image base covering a given address
// The debug thread owns a separate local-only DbgHelp session on the original
// process handle. Binary View's asynchronous symbol worker intentionally uses a
// duplicated handle so its network/PDB lifetime cannot race debugger teardown;
// sharing that worker session here would therefore be both incorrect and unsafe.
//
// WOW64-aware: a 32-bit target is walked as IMAGE_FILE_MACHINE_I386 over its
// WOW64_CONTEXT (same field layout as a 32-bit CONTEXT); a native target as
// IMAGE_FILE_MACHINE_AMD64 over the x64 CONTEXT. Names are filled best-effort here
// (SymFromAddr); the UI may re-resolve through its own heuristic namer.
void Debugger::unwindStack(uint32_t tid) {
    std::vector<CallStackFrame> frames;
    auto it = threads_.find(tid);
    HANDLE hProc = (HANDLE)hProcess_;
    if (it == threads_.end() || !hProc) {
        std::lock_guard<std::mutex> lk(mtx_); frames_.swap(frames); return;
    }
    HANDLE hThread = (HANDLE)it->second;

    // The frame/stack/instruction seeds come from the thread's live context.
    STACKFRAME64 sf{};
    DWORD machine;
    // The CONTEXT StackWalk64 reads+updates. For WOW64 we keep a WOW64_CONTEXT and
    // hand its address in (StackWalk64 treats the pointer opaquely per `machine`).
    CONTEXT       ctx64{};
    WOW64_CONTEXT ctx32{};
    void* ctxPtr = nullptr;

    if (isWow64_.load()) {
        machine = IMAGE_FILE_MACHINE_I386;
        ctx32.ContextFlags = WOW64_CONTEXT_FULL;
        if (!Wow64GetThreadContext(hThread, &ctx32)) {
            std::lock_guard<std::mutex> lk(mtx_); frames_.swap(frames); return;
        }
        sf.AddrPC.Offset    = ctx32.Eip;  sf.AddrPC.Mode    = AddrModeFlat;
        sf.AddrFrame.Offset = ctx32.Ebp;  sf.AddrFrame.Mode = AddrModeFlat;
        sf.AddrStack.Offset = ctx32.Esp;  sf.AddrStack.Mode = AddrModeFlat;
        ctxPtr = &ctx32;
    } else {
        machine = IMAGE_FILE_MACHINE_AMD64;
        ctx64.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(hThread, &ctx64)) {
            std::lock_guard<std::mutex> lk(mtx_); frames_.swap(frames); return;
        }
        sf.AddrPC.Offset    = ctx64.Rip; sf.AddrPC.Mode    = AddrModeFlat;
        sf.AddrFrame.Offset = ctx64.Rbp; sf.AddrFrame.Mode = AddrModeFlat;  // ignored by x64 walk, seeded anyway
        sf.AddrStack.Offset = ctx64.Rsp; sf.AddrStack.Mode = AddrModeFlat;
        ctxPtr = &ctx64;
    }

    const size_t kMaxFrames = 256;
    {
        // DbgHelp's Sym*/StackWalk64 are process-global single-threaded: serialize the
        // whole walk against the asynchronous symbol worker (see DbgHelpLock.h).
        // The debug-owned session invades/refreshes the process module list so
        // .pdata unwind tables are available without depending on UI activity.
        std::lock_guard<std::recursive_mutex> dhlk(DbgHelpMutex());
        const DWORD previousOptions = SymGetOptions();
        struct RestoreDbgHelpOptions {
            DWORD value;
            ~RestoreDbgHelpOptions() { SymSetOptions(value); }
        } restoreOptions{previousOptions};
        DWORD localOptions = previousOptions | SYMOPT_DEFERRED_LOADS |
                             SYMOPT_UNDNAME | SYMOPT_FAIL_CRITICAL_ERRORS |
                             SYMOPT_NO_PROMPTS;
#ifdef SYMOPT_DISABLE_SYMSRV_AUTODETECT
        localOptions |= SYMOPT_DISABLE_SYMSRV_AUTODETECT;
#endif
        SymSetOptions(localOptions);
        if (!dbgHelpSessionInited_) {
            dbgHelpSessionInited_ = SymInitialize(hProc, ".", TRUE) != FALSE;
        }
        if (dbgHelpSessionInited_) SymRefreshModuleList(hProc);
    for (size_t n = 0; n < kMaxFrames; ++n) {
        if (!StackWalk64(machine, hProc, hThread, &sf, ctxPtr,
                         /*ReadMemoryRoutine*/        nullptr,  // null -> StackWalk64 uses ReadProcessMemory(hProc)
                         /*FunctionTableAccess*/      dbgHelpSessionInited_ ? SymFunctionTableAccess64 : nullptr,
                         /*GetModuleBase*/            dbgHelpSessionInited_ ? SymGetModuleBase64 : nullptr,
                         /*TranslateAddress*/         nullptr))
            break;
        uint64_t pc = sf.AddrPC.Offset;
        if (!pc) break;   // unwound off the top of the stack

        CallStackFrame f;
        f.pc       = pc;
        f.frameSp  = sf.AddrFrame.Offset;
        f.stackPtr = sf.AddrStack.Offset;
        // Best-effort symbol (the UI re-resolves through its own namer anyway).
        ULONG64 buf[(sizeof(SYMBOL_INFO) + 256 + sizeof(ULONG64) - 1) / sizeof(ULONG64)] = {0};
        SYMBOL_INFO* si = reinterpret_cast<SYMBOL_INFO*>(buf);
        si->SizeOfStruct = sizeof(SYMBOL_INFO);
        si->MaxNameLen   = 255;
        DWORD64 disp = 0;
        if (dbgHelpSessionInited_ && SymFromAddr(hProc, pc, &disp, si) && si->NameLen)
            f.name.assign(si->Name, si->NameLen < si->MaxNameLen ? si->NameLen : si->MaxNameLen);
        frames.push_back(std::move(f));

        // A self-referential frame (AddrPC unchanged with zero frame movement) means
        // the walk stalled; stop rather than spin to the cap.
        if (n > 0 && sf.AddrReturn.Offset == sf.AddrPC.Offset && !sf.AddrFrame.Offset) break;
    }
    }   // release DbgHelpMutex before taking mtx_

    std::lock_guard<std::mutex> lk(mtx_);
    frames_.swap(frames);
}

// Evaluate a breakpoint's condition for the stopped thread (debug thread).
bool Debugger::evalConditionFor(uint64_t addr, uint32_t tid) {
    // Use the condition compiled once when the breakpoint was set/changed, instead
    // of re-parsing the string on every hit. An empty (unconditional) program is
    // {valid,empty} -> always true.
    CondProgram prog;
    { std::lock_guard<std::mutex> lk(mtx_);
      auto it = bps_.find(addr); if (it != bps_.end()) prog = it->second.prog; }
    // Invalid programs are never supposed to enter bps_ (the public command
    // boundary rejects them). Fail closed here as defense in depth: malformed
    // legacy/corrupt state must not become an unconditional breakpoint.
    if (!prog.valid) return false;
    if (prog.empty) return true;

    auto th = threads_.find(tid);
    if (th == threads_.end()) return true;
    Registers rg;
    if (!ctxReadFull(th->second, rg)) return true;   // 32-bit values map into the low halves

    CondContext cc;
    cc.reg = [&rg](const std::string& n, uint64_t& out) -> bool {
        // Accept both 64-bit and 32-bit register names (eax/eip/esp/... alias rax/rip/rsp).
        if      (n == "rax" || n == "eax") out = rg.rax; else if (n == "rbx" || n == "ebx") out = rg.rbx;
        else if (n == "rcx" || n == "ecx") out = rg.rcx; else if (n == "rdx" || n == "edx") out = rg.rdx;
        else if (n == "rsi" || n == "esi") out = rg.rsi; else if (n == "rdi" || n == "edi") out = rg.rdi;
        else if (n == "rbp" || n == "ebp") out = rg.rbp; else if (n == "rsp" || n == "esp") out = rg.rsp;
        else if (n == "rip" || n == "eip") out = rg.rip;
        else if (n == "rflags" || n == "eflags") out = rg.rflags;
        else if (n == "r8")  out = rg.r8;  else if (n == "r9")  out = rg.r9;
        else if (n == "r10") out = rg.r10; else if (n == "r11") out = rg.r11;
        else if (n == "r12") out = rg.r12; else if (n == "r13") out = rg.r13;
        else if (n == "r14") out = rg.r14; else if (n == "r15") out = rg.r15;
        else return false;
        return true;
    };
    // Read pointer-width: a 32-bit (WOW64) target's [addr] must not pull 4 adjacent bytes into the high dword.
    cc.mem = [this](uint64_t a) -> uint64_t { uint64_t v = 0; readMemory(a, &v, isWow64_.load() ? 4 : 8); return v; };
    return EvalCompiled(prog, cc, /*onError*/ false);  // unknown runtime state fails closed
}

bool Debugger::setTrapFlag(uint32_t tid, bool on) {
    auto it = threads_.find(tid);
    if (it == threads_.end()) return false;
    if (isWow64_.load()) {
        WOW64_CONTEXT c{}; c.ContextFlags = WOW64_CONTEXT_CONTROL;
        if (!Wow64GetThreadContext((HANDLE)it->second, &c)) return false;
        if (on) c.EFlags |= TRAP_FLAG; else c.EFlags &= ~TRAP_FLAG;
        c.ContextFlags = WOW64_CONTEXT_CONTROL;
        return Wow64SetThreadContext((HANDLE)it->second, &c) != 0;
    }
    CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext((HANDLE)it->second, &ctx)) return false;
    if (on) ctx.EFlags |= TRAP_FLAG; else ctx.EFlags &= ~TRAP_FLAG;
    return SetThreadContext((HANDLE)it->second, &ctx) != 0;
}

// Set EFLAGS.RF (resume flag). A fault-class #DB from a hardware *execute*
// breakpoint (or a trap-flag step that lands on one) leaves RIP on the trapping
// instruction; RF makes the CPU run that one instruction without re-raising the
// breakpoint, then the CPU clears RF automatically so the bp stays armed.
void Debugger::setResumeFlag(uint32_t tid) {
    auto it = threads_.find(tid);
    if (it == threads_.end()) return;
    if (isWow64_.load()) {
        WOW64_CONTEXT c{}; c.ContextFlags = WOW64_CONTEXT_CONTROL;
        if (!Wow64GetThreadContext((HANDLE)it->second, &c)) return;
        c.EFlags |= 0x10000; // RF
        c.ContextFlags = WOW64_CONTEXT_CONTROL;
        Wow64SetThreadContext((HANDLE)it->second, &c);
        return;
    }
    CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext((HANDLE)it->second, &ctx)) return;
    ctx.EFlags |= 0x10000; // RF
    SetThreadContext((HANDLE)it->second, &ctx);
}

// Program DR0-DR3 + DR7 on one thread from the current hwSlots_ table.
bool Debugger::applyHwToThread(void* hThread) {
    DWORD64 dr7 = 0;
    DWORD64 addrs[4] = {0, 0, 0, 0};
    for (int i = 0; i < 4; ++i) {
        if (!hwSlots_[i].used) continue;
        addrs[i] = hwSlots_[i].addr;
        dr7 |= (DWORD64)1 << (i * 2);              // Ln: local enable for slot i

        // RWn condition: 00=execute, 01=write, 11=read/write.
        DWORD64 rw = 0;
        switch (hwSlots_[i].kind) {
            case HwKind::Execute:   rw = 0b00; break;
            case HwKind::Write:     rw = 0b01; break;
            case HwKind::ReadWrite: rw = 0b11; break;
        }
        // LENn: 00=1, 01=2, 11=4, 10=8 bytes. Execute must be length 1 (00).
        DWORD64 len = 0b00;
        if (hwSlots_[i].kind != HwKind::Execute) {
            switch (hwSlots_[i].size) { case 2: len = 0b01; break; case 4: len = 0b11; break;
                                         case 8: len = 0b10; break; default: len = 0b00; break; }
        }
        dr7 |= (rw  << (16 + i * 4));
        dr7 |= (len << (18 + i * 4));
    }
    // DR0-DR7 are shared physical registers and the DR7 layout is identical for x86/x64.
    // Program them via the NATIVE 64-bit CONTEXT even for a WOW64 thread: debug registers
    // set through the 32-bit WOW64_CONTEXT are not reliably armed by the kernel, so a
    // WOW64 hardware breakpoint set that way often never fires. 32-bit DR addresses
    // zero-extend into the DWORD64 fields, and CONTEXT_DEBUG_REGISTERS touches only the DRs.
    CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext((HANDLE)hThread, &ctx)) return false;
    ctx.Dr0 = addrs[0]; ctx.Dr1 = addrs[1]; ctx.Dr2 = addrs[2]; ctx.Dr3 = addrs[3];
    ctx.Dr7 = dr7;
    ctx.Dr6 = 0;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    return SetThreadContext((HANDLE)hThread, &ctx) != FALSE;
}

bool Debugger::applyHwAllThreads() {
    bool complete = true;
    for (auto& kv : threads_) complete = applyHwToThread(kv.second) && complete;
    return complete;
}

// Read DR6 for a thread and clear it (so the next hit is distinguishable).
bool Debugger::readDr6Clear(uint32_t tid, uint64_t& dr6) {
    dr6 = 0;
    auto it = threads_.find(tid);
    if (it == threads_.end()) return false;
    // Read/clear DR6 via the native CONTEXT for both x86 and x64 (see applyHwToThread:
    // the WOW64 debug-register view is unreliable). DR6 is the same physical register.
    CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext((HANDLE)it->second, &ctx)) return false;
    dr6 = ctx.Dr6;
    if (ctx.Dr6 & 0xF) {
        ctx.Dr6 = 0;
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!SetThreadContext((HANDLE)it->second, &ctx)) return false;
    }
    return true;
}

void Debugger::captureContext(uint32_t tid) {
    auto it = threads_.find(tid);
    if (it == threads_.end()) return;
    Registers r;
    if (!ctxReadFull(it->second, r)) return;   // arch-aware (native CONTEXT or WOW64_CONTEXT)
    std::lock_guard<std::mutex> lk(mtx_);
    regs_ = r;
}

Debugger::StepDecode Debugger::decodeAt(uint64_t va) {
    StepDecode d;
    // 32-bit (WOW64) code must be measured/classified with an x86 decoder.
    IDisassembler* dis = isWow64_.load() ? ownDis32_.get() : ownDis_.get();
    if (!dis) return d;
    uint8_t buf[16] = {0};
    size_t n = readMemoryMasked(va, buf, sizeof(buf));
    if (!n) return d;
    Instruction in;
    if (dis->decodeOne(buf, n, va, in)) {
        d.length      = in.length ? in.length : 1;
        d.isCall      = in.isCall;
        d.isRet       = in.isRet;
        d.isRepString = in.isRepString;
    }
    return d;
}

// ---- debug-thread main loop -------------------------------------------------

void Debugger::threadEntry(uint32_t pid, bool launch, std::wstring applicationPath,
                           std::wstring commandLine, bool breakAtEntry,
                           std::optional<DllDebugLaunchPlan> dllPlan,
                           bool containedJob, uint64_t controlEpoch) noexcept {
    try {
        threadMain(pid, launch, std::move(applicationPath), std::move(commandLine),
                   breakAtEntry, std::move(dllPlan), containedJob, controlEpoch);
    } catch (const std::exception& e) {
        emergencyThreadCleanup(std::string("debugger worker exception: ") + e.what());
    } catch (...) {
        emergencyThreadCleanup("debugger worker exception: unknown failure");
    }
}

void Debugger::emergencyThreadCleanup(const std::string& reason) noexcept {
    networkObservationWant_.store(false);
    try {
        HANDLE process = (HANDLE)hProcess_;
        uint32_t actualPid = 0;
        std::vector<std::pair<uint64_t, uint8_t>> restores;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            actualPid = pid_;
            restores.reserve(bps_.size() + traceBps_.size() + dllTargetBps_.size() +
                             antiTraps_.size() + networkProbeBps_.size() +
                             networkReturnBps_.size() + authorizationBps_.size() +
                             authorizationReturnBps_.size());
            for (const auto& [va, bp] : bps_)
                if (bp.ownsByte) restores.push_back({ va, bp.orig });
            for (const auto& [va, bp] : traceBps_) restores.push_back({ va, bp.orig });
            for (const auto& [va, bp] : dllTargetBps_)
                if (bp.ownsByte) restores.push_back({ va, bp.orig });
            for (const auto& [va, bp] : antiTraps_) restores.push_back({ va, bp.orig });
            for (const auto& [va, bp] : networkProbeBps_)
                if (bp.ownsByte) restores.push_back({ va, bp.orig });
            for (const auto& [va, bp] : networkReturnBps_)
                if (bp.ownsByte) restores.push_back({ va, bp.orig });
            for (const auto& [va, bp] : authorizationBps_)
                if (bp.ownsByte) restores.push_back({ va, bp.orig });
            for (const auto& [va, bp] : authorizationReturnBps_)
                if (bp.ownsByte) restores.push_back({ va, bp.orig });
        }
        {
            std::lock_guard<std::mutex> lk(hProcMtx_);
            hProcessShared_ = nullptr;
            hProcessIdentity_ = {};
        }
        if (process) {
            try { cleanupGameMakerOwned(true); } catch (...) {}
            for (const auto& [va, orig] : restores)
                (void)replaceByteIfEqual(process, va, 0xCC, orig);
            try { restoreAntiDebugState(true); } catch (...) {}
            for (auto& slot : hwSlots_) slot = HwSlot{};
            try { applyHwAllThreads(); } catch (...) {}
        }
        {
            std::lock_guard<std::recursive_mutex> dhlk(DbgHelpMutex());
            if (dbgHelpSessionInited_ && process) SymCleanup(process);
            dbgHelpSessionInited_ = false;
        }
        if (actualPid) DebugActiveProcessStop(actualPid);
        for (auto& [tid, handle] : threads_) {
            (void)tid;
            if (handle) CloseHandle((HANDLE)handle);
        }
        threads_.clear();
        {
            std::lock_guard<std::mutex> lk(hProcMtx_);
            if (hProcess_) CloseHandle((HANDLE)hProcess_);
            hProcess_ = nullptr;
            hProcessShared_ = nullptr;
            hProcessIdentity_ = {};
            // Never carry target-owned addresses into a later session after an
            // emergency teardown, where they could name unrelated pages.
            remoteAllocs_.clear();
            remoteRegisterBuffers_.clear();
        }
        traceCoverage_.stop();
        {
            std::lock_guard<std::mutex> lk(mtx_);
            cancelPendingWritesLocked();
            activeWrite_.reset();
            state_ = DbgState::Detached;
            failedBpInstalls_.clear();
            dllHostedLaunch_ = false;
            lastEvent_ = reason;
            startupErr_ = reason;
            startupOk_ = false;
            startupDone_ = true;
            pendingCommand_ = {};
            cancelCheckedRunToLocked(
                "the debugger worker stopped before the checked RunTo request fired");
            threadHandles_.clear();
            threadList_.clear();
            activeTid_ = 0;
            pausedUserBpAddr_.reset();
            runtimeTempBpAddr_.reset();
            networkProbeBps_.clear();
            networkProbeBpAddrs_.clear();
            networkReturnBps_.clear();
            networkReturnBpAddrs_.clear();
            authorizationBps_.clear();
            authorizationBpAddrs_.clear();
            authorizationReturnBps_.clear();
            authorizationReturnBpAddrs_.clear();
            authorizationPendingReturnCount_ = 0;
            networkCoverage_.active = false;
            networkCoverage_.requested = false;
            networkPendingPayloadBytes_ = 0;
        }
        networkPendingReturns_.clear();
        authorizationPendingReturns_.clear();
        authorizationWatch_.stop();
        networkHandleLineage_.clear();
        quit_ = true;
        breakRequested_ = false;
        traceSyncBreakRequested_ = false;
        cmdCv_.notify_all();
    } catch (...) {
        // This is the last-resort boundary for the process-wide debugger worker.
        // Preserve liveness even if allocation while constructing diagnostics fails.
        startupOk_ = false;
        startupDone_ = true;
        quit_ = true;
        cmdCv_.notify_all();
    }
}

void Debugger::threadMain(uint32_t pid, bool launch, std::wstring applicationPath,
                          std::wstring commandLine, bool breakAtEntry,
                          std::optional<DllDebugLaunchPlan> dllPlan,
                          bool containedJob, uint64_t controlEpoch) {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (controlEpoch != controlEpoch_ || quit_.load() ||
            (lifecycleAttaching_.load() && lifecycleCancel_.load())) {
            startupErr_ = "debugger session was cancelled or superseded before startup";
            startupOk_ = false;
            startupDone_ = true;
            cmdCv_.notify_all();
            return;
        }
        activeAntiDebugPolicy_ = antiDebugPolicy_;
        antiDebugStats_ = {};
        antiDebugStats_.active = activeAntiDebugPolicy_.enabled();
        antiDebugStats_.policy = activeAntiDebugPolicy_;
        antiTraps_.clear();
        antiTrapAddrs_.clear();
    }
    antiDebugRdtscBudgetRemaining_ =
        activeAntiDebugPolicy_.rdtsc == RdtscInterception::Off
        ? 0 : kAntiDebugRdtscSessionBudget;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        antiDebugStats_.rdtscDiscoveryBudgetTotal = antiDebugRdtscBudgetRemaining_;
        antiDebugStats_.rdtscDiscoveryBudgetRemaining = antiDebugRdtscBudgetRemaining_;
    }
    antiDebugPatches_.clear();
    if (activeAntiDebugPolicy_.syntheticClock ||
        activeAntiDebugPolicy_.rdtsc != RdtscInterception::Off)
        antiDebugClock_.reset(productionSyntheticClockConfig());
    else
        antiDebugClock_.reset();
    {
        std::lock_guard<std::mutex> lk(mtx_);
        antiDebugStats_.clockQpcFrequency = antiDebugClock_.qpcFrequency();
    }
    HANDLE sandboxJob = nullptr;
    if (launch) {
        // The thread that creates a DEBUG-flagged process must be the same one that
        // pumps WaitForDebugEvent, so the process is created here on the debug thread.
        STARTUPINFOW si{}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        // CreateProcessW may write to the command-line buffer, so pass a mutable copy.
        std::vector<wchar_t> cmd(commandLine.begin(), commandLine.end());
        cmd.push_back(L'\0');
        const std::wstring workingDirectory = dllPlan ? std::wstring{}
                                                       : executableDirectory(applicationPath);
        DWORD creationFlags = DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE;
        if (containedJob) creationFlags |= CREATE_SUSPENDED;
        BOOL ok = CreateProcessW(applicationPath.c_str(), cmd.data(), nullptr, nullptr, FALSE,
                                 creationFlags,
                                 nullptr,
                                 workingDirectory.empty() ? nullptr : workingDirectory.c_str(),
                                 &si, &pi);
        if (!ok) {
            std::lock_guard<std::mutex> lk(mtx_);
            startupErr_ = "CreateProcess failed (err " + std::to_string(GetLastError()) +
                          ") - check the path / bitness, or run as Administrator.";
            startupOk_ = false; startupDone_ = true; cmdCv_.notify_all();
            return;
        }
        if (containedJob) {
            sandboxJob = CreateJobObjectW(nullptr, nullptr);
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
            limits.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            limits.BasicLimitInformation.ActiveProcessLimit = 1;
            if (!sandboxJob ||
                !SetInformationJobObject(sandboxJob, JobObjectExtendedLimitInformation,
                                         &limits, sizeof(limits)) ||
                !AssignProcessToJobObject(sandboxJob, pi.hProcess)) {
                const DWORD e = GetLastError();
                // The target is still CREATE_SUSPENDED. Never resume an uncontained
                // target on this failure path; request termination while it cannot run.
                TerminateProcess(pi.hProcess, 1);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                if (sandboxJob) CloseHandle(sandboxJob);
                std::lock_guard<std::mutex> lk(mtx_);
                startupErr_ = "Could not contain the unpack target in a Windows job (err " +
                              std::to_string(e) + ").";
                startupOk_ = false; startupDone_ = true; cmdCv_.notify_all();
                return;
            }
            if (ResumeThread(pi.hThread) == static_cast<DWORD>(-1)) {
                const DWORD e = GetLastError();
                // Assignment already succeeded, so terminate through the job as
                // well as the direct process handle before releasing ownership.
                TerminateJobObject(sandboxJob, 1);
                TerminateProcess(pi.hProcess, 1);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                CloseHandle(sandboxJob);
                sandboxJob = nullptr;
                std::lock_guard<std::mutex> lk(mtx_);
                startupErr_ = "Could not resume the contained unpack target (err " +
                              std::to_string(e) + ").";
                startupOk_ = false; startupDone_ = true; cmdCv_.notify_all();
                return;
            }
        }
        pid = pi.dwProcessId;
        // We receive our own process/thread handles via the debug events; the ones
        // CreateProcess returned are redundant.
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    } else if (!DebugActiveProcess(pid)) {
        std::lock_guard<std::mutex> lk(mtx_);
        startupErr_ = "DebugActiveProcess failed (err " + std::to_string(GetLastError()) +
                      ") - run as Administrator / match bitness.";
        startupOk_ = false; startupDone_ = true; cmdCv_.notify_all();
        return;
    }
    DebugSetProcessKillOnExit(FALSE);
    uint64_t activeSessionGeneration = 0;
    uint64_t moduleLoadGeneration = 0;
    { std::lock_guard<std::mutex> lk(mtx_); pid_ = pid; state_ = DbgState::Running;
      ++sessionGeneration_;
      if (!sessionGeneration_) ++sessionGeneration_;
      activeSessionGeneration = sessionGeneration_;
      networkProbeBps_.clear(); networkProbeBpAddrs_.clear();
      networkReturnBps_.clear(); networkReturnBpAddrs_.clear();
      networkEvents_.clear(); networkEventSequence_ = 0;
      networkCoverage_ = {};
      networkCoverage_.sessionGeneration = sessionGeneration_;
      networkCoverage_.pid = pid;
      networkCoverage_.requested = false;
      netTapArmed_ = false;
      authorizationBps_.clear(); authorizationBpAddrs_.clear();
      authorizationReturnBps_.clear(); authorizationReturnBpAddrs_.clear();
      authorizationPendingReturnCount_ = 0;
      authorizationPendingReturnsDropped_ = 0;
      containedJob_ = containedJob;
      dllHostedLaunch_ = dllPlan.has_value();
      lastEvent_ = launch ? "launched" : "attached";
      // The startup flags MUST be published under mtx_. The waiter in attach()/
      // launchAndAttach() evaluates `startupDone_` while holding mtx_ and then blocks
      // on cmdCv_; setting the flag + notifying outside the lock races with that
      // check-then-wait and can drop the wakeup, hanging the UI forever on attach.
      startupOk_ = true; startupDone_ = true; }
    networkPendingReturns_.clear();
    authorizationPendingReturns_.clear();
    { std::lock_guard<std::mutex> lk(mtx_); networkPendingPayloadBytes_ = 0; }
    networkHandleLineage_.clear();
    cmdCv_.notify_all();

    // Launch + break-at-entry: don't stop on the loader breakpoint; instead arm a
    // one-shot breakpoint at the program entry and continue, landing the user on
    // the first instruction of their code. Captured on CREATE_PROCESS_DEBUG_EVENT.
    bool     wantEntryBreak = launch && breakAtEntry;
    uint64_t entryAddr      = 0;

    // --- parked on a user breakpoint (byte restored, RIP backed up) ---
    bool        pausedOnBp = false; uint64_t pausedOnBpAddr = 0;

    // --- single-step then re-arm a user breakpoint we stepped off of ---
    enum class ReArmOwner {
        User, NetworkProbe, NetworkReturn, Authorization, AuthorizationReturn
    };
    uint64_t    reArmAddr = 0;                       // 0 = none pending
    ReArmOwner  reArmOwner = ReArmOwner::User;
    AfterReArm  reArmAfter = AfterReArm::FreeRun;    // what to do once it is re-armed
    const char* reArmLabel = "step";                 // UI label for AfterReArm::Pause
    bool        parkedInternalTransfer = false;
    ReArmOwner  parkedInternalOwner = ReArmOwner::User;

    bool   stepPause = false;                  // pause on the next single-step
    uint32_t stepTid = 0;                      // thread a single-instruction step is armed on; binds
                                               // the trap-flag #DB so another thread's stray single-step
                                               // can't consume our pending step state

    // A selected ntdll hook only conceals selected information classes. Calls
    // outside policy are passed through by restoring the entry byte for exactly
    // one instruction, trap-stepping it, then re-arming the internal hook.
    AntiDebugRearmState antiRearms;
    auto abandonAntiRearms = [&](bool reportFailures) {
        while (auto pending = antiRearms.takeAny()) {
            if (!setTrapFlag(pending->tid, false) && reportFailures)
                addAntiDebugWarning(
                    "could not clear TF while abandoning a pending Hide Debugger hook");
        }
    };

    // An internal trace breakpoint restores its byte and trap-steps that original
    // instruction once. Unlike a user breakpoint it is never re-armed.
    uint32_t traceStepTid = 0;
    bool     traceStepFreeRun = false;

    // --- step out ---
    bool     steppingOut = false; size_t stepOutIters = 0;
    bool     stepOutFinishing = false;         // ret is executing; pause on next step
    uint64_t stepOutAnchorRsp = 0;             // RSP when step-out began: a ret only leaves
                                               // the frame when RSP rises above this anchor

    // --- one-shot temporary breakpoint (run-to / step-over return / step-out skip) ---
    TempKind tempKind = TempKind::None;
    bool   tempBpSet = false; uint64_t tempBpAddr = 0; uint8_t tempBpOrig = 0;
    uint32_t tempOwnerTid = 0;                 // 0 = process-wide internal target
    uint64_t tempCheckedRunToToken = 0;        // non-zero only for checked Authorization RunTo
    uint32_t foreignTempStepTid = 0;           // non-owner temporarily stepping over temp byte
    bool   tempSharesAnti = false;              // anti trap retains physical-byte ownership
    uint64_t tempAntiOwnerBase = 0;
    uint64_t tempReArm = 0;                     // re-arm this bp when the temp bp fires
    ReArmOwner tempReArmOwner = ReArmOwner::User;
    bool   breakpointTransitionFailed = false;
    bool   breakpointCleanupComplete = true;

    // A software breakpoint is process-wide. While its original instruction is
    // exposed for one owner thread, suspend peers so none can execute through the
    // temporarily disarmed address. The set contains only suspend counts acquired
    // here; user-frozen threads keep their independent count.
    uint32_t exclusiveStepOwner = 0;
    std::unordered_set<uint32_t> exclusiveStepSuspended;

    bool   firstBreakpoint = true;
    // A WOW64 (32-bit) target raises MORE than one loader breakpoint during startup
    // (the x64 ntdll one, then the 32-bit wow64 ntdll one). They must be swallowed,
    // not passed back as unhandled (which terminates the process). loaderPhase stays
    // true until the first user-visible stop.
    bool   loaderPhase = true;
    uint32_t mainTid = 0;   // the process main thread (shown when the user hits Pause)
    uint64_t mainImageBase = 0, mainImageSize = 0;
    uint64_t mainImageLoadGeneration = 0;
    std::string mainImageName, mainImagePath;
    bool mainAntiDebugArmed = false;
    bool antiDebugHeapRetryPending = false;

    // --- JVM awareness (Java EXEs) ---
    // The VM module's mapped range, captured from its LOAD_DLL event; bounds
    // IsJvmInternalException so HotSpot's intentional AVs (null checks, safepoint
    // polls) pass through without pausing or spamming events.
    uint64_t jvmBase = 0, jvmSize = 0;
    // JNI_CreateJavaVM one-shot waiting for the single temp-bp slot to free up
    // (a step's temp bp may be in flight when jvm.dll loads).
    uint64_t pendingJvmInitVA = 0;

    auto removeAllTraceBps = [&]() {
        std::vector<std::pair<uint64_t, TraceBp>> owned;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            owned.reserve(traceBps_.size());
            for (const auto& kv : traceBps_) owned.push_back(kv);
            traceBps_.clear();
            traceBpAddrs_.clear();
        }
        for (const auto& [va, bp] : owned) {
            breakpointCleanupComplete =
                restoreDebuggerOwnedByte((HANDLE)hProcess_, va, bp.orig) &&
                breakpointCleanupComplete;
            traceCoverage_.markDisarmed(bp.generation, va);
        }
    };

    // Consume UI trace requests only on the debug-event thread, while the target
    // is stopped at an event. This keeps all process-memory mutation off the UI.
    auto applyPendingTrace = [&]() {
        bool start = false, stop = false;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            start = pendingTraceStart_;
            stop = pendingTraceStop_;
            pendingTraceStart_ = pendingTraceStop_ = false;
        }
        if (!start && !stop) return;

        // A restart owns a new generation, so restore every site from the old one
        // before planting the replacement plan. Stop is restoration-only.
        removeAllTraceBps();
        if (!start || !traceCoverage_.active()) return;

        const uint64_t generation = traceCoverage_.generation();
        const std::vector<uint64_t> sites = traceCoverage_.pendingSites(generation);
        for (uint64_t va : sites) {
            if (!traceCoverage_.active() || traceCoverage_.generation() != generation) break;

            // Never borrow a byte already owned by another debugger mechanism.
            // A user breakpoint at a planned block is counted when that bp fires.
            bool ownedConflict = false;
            { std::lock_guard<std::mutex> lk(mtx_);
              ownedConflict = gameMakerOwnsRangeLocked(va,1) || bps_.count(va) != 0 || dllTargetBps_.count(va) != 0 ||
                              networkProbeBps_.count(va) != 0 ||
                              networkReturnBps_.count(va) != 0 ||
                              authorizationBps_.count(va) != 0 ||
                              authorizationReturnBps_.count(va) != 0; }
            if (ownedConflict || (tempBpSet && tempBpAddr == va)) {
                traceCoverage_.markSkipped(generation, va);
                continue;
            }

            uint8_t orig = 0;
            if (!readByteRPM((HANDLE)hProcess_, va, orig) || orig == 0xCC ||
                !writeByteRPM((HANDLE)hProcess_, va, 0xCC)) {
                traceCoverage_.markSkipped(generation, va);
                continue;
            }
            {
                std::lock_guard<std::mutex> lk(mtx_);
                traceBps_[va] = TraceBp{ orig, generation };
                traceBpAddrs_.push_back(va); // sites is sorted
            }
            traceCoverage_.markArmed(generation, va);
        }
    };

    auto removeAllAuthorizationBps = [&]() {
        std::vector<std::pair<uint64_t, AuthorizationBp>> removed;
        std::vector<std::pair<uint64_t, AuthorizationReturnBp>> returns;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            removed.reserve(authorizationBps_.size());
            for (const auto& value : authorizationBps_) removed.push_back(value);
            returns.reserve(authorizationReturnBps_.size());
            for (const auto& value : authorizationReturnBps_) returns.push_back(value);
            authorizationBps_.clear();
            authorizationBpAddrs_.clear();
            authorizationReturnBps_.clear();
            authorizationReturnBpAddrs_.clear();
        }
        for (const auto& [va, bp] : removed) {
            if (bp.ownsByte && bp.armed)
                breakpointCleanupComplete =
                    restoreDebuggerOwnedByte((HANDLE)hProcess_, va, bp.orig) &&
                    breakpointCleanupComplete;
            authorizationWatch_.markDisarmed(bp.generation, va);
        }
        for (const auto& [va, site] : returns) {
            if (site.ownsByte && site.armed)
                breakpointCleanupComplete =
                    restoreDebuggerOwnedByte((HANDLE)hProcess_, va, site.orig) &&
                    breakpointCleanupComplete;
        }
        const size_t abandoned = authorizationPendingReturns_.total();
        authorizationPendingReturns_.clear();
        {
            std::lock_guard<std::mutex> lk(mtx_);
            authorizationPendingReturnCount_ = 0;
            if (UINT64_MAX - authorizationPendingReturnsDropped_ < abandoned)
                authorizationPendingReturnsDropped_ = UINT64_MAX;
            else
                authorizationPendingReturnsDropped_ += abandoned;
        }
    };

    // Apply both attached and pre-launch plans only while Windows holds a debug
    // event. On launch, CREATE_PROCESS has already published the main image base,
    // so these RVA probes are live before the event is continued into TLS/entry.
    auto applyPendingAuthorization = [&]() {
        bool start = false, stop = false;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            start = pendingAuthorizationStart_;
            stop = pendingAuthorizationStop_;
            pendingAuthorizationStart_ = pendingAuthorizationStop_ = false;
        }
        if (!start && !stop) return;

        removeAllAuthorizationBps();
        if (parkedInternalTransfer &&
            parkedInternalOwner == ReArmOwner::Authorization) {
            // The original instruction is already exposed at RIP. Retiring the
            // watch while paused means it must execute normally, without a stale
            // attempt to re-arm metadata that no longer exists.
            parkedInternalTransfer = false;
            parkedInternalOwner = ReArmOwner::User;
            pausedOnBp = false;
            pausedOnBpAddr = 0;
        }
        if (!start || !authorizationWatch_.active() || !mainImageBase) return;

        const uint64_t generation = authorizationWatch_.generation();
        const DebugTargetIdentity target{ pid, activeSessionGeneration };
        const AttachedModuleIdentity mainIdentity{
            mainImageBase, mainImageSize, mainImageName, mainImagePath,
            mainImageLoadGeneration
        };
        if (!authorizationWatch_.bindTarget(generation, target, mainIdentity)) return;
        const AuthorizationWatchSnapshot prepared = authorizationWatch_.snapshot();
        const bool imageExtentMismatch =
            prepared.imageSize && mainImageSize && prepared.imageSize != mainImageSize;
        const std::vector<AuthorizationWatchRuntimeSite> sites =
            authorizationWatch_.pendingSites(generation);

        auto executableMainImageRange = [&](uint64_t va, size_t length) {
            if (imageExtentMismatch || va < mainImageBase ||
                !AuthorizationWatchRangeWithinImage(
                    va - mainImageBase, length, mainImageSize) ||
                va > UINT64_MAX - static_cast<uint64_t>(length))
                return false;
            const uint64_t end = va + static_cast<uint64_t>(length);
            uint64_t cursor = va;
            while (cursor < end) {
                MEMORY_BASIC_INFORMATION mbi{};
                if (VirtualQueryEx((HANDLE)hProcess_,
                                   reinterpret_cast<LPCVOID>(cursor),
                                   &mbi, sizeof(mbi)) != sizeof(mbi) ||
                    mbi.State != MEM_COMMIT || mbi.Type != MEM_IMAGE ||
                    reinterpret_cast<uint64_t>(mbi.AllocationBase) !=
                        mainImageBase ||
                    (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
                    return false;
                switch (mbi.Protect & 0xFFu) {
                    case PAGE_EXECUTE:
                    case PAGE_EXECUTE_READ:
                    case PAGE_EXECUTE_READWRITE:
                    case PAGE_EXECUTE_WRITECOPY:
                        break;
                    default:
                        return false;
                }
                const uint64_t regionBase =
                    reinterpret_cast<uint64_t>(mbi.BaseAddress);
                if (regionBase > cursor ||
                    mbi.RegionSize > UINT64_MAX - regionBase)
                    return false;
                const uint64_t regionEnd =
                    regionBase + static_cast<uint64_t>(mbi.RegionSize);
                if (regionEnd <= cursor) return false;
                cursor = (std::min)(end, regionEnd);
            }
            return true;
        };

        for (const AuthorizationWatchRuntimeSite& planned : sites) {
            const uint64_t va = planned.runtimeVa;
            // Windows is holding a debug event here, so the target cannot race
            // this check.  Compare the complete decoded instruction immediately
            // before planting the site's int3. readMemoryMasked restores any
            // debugger-owned breakpoint bytes that already overlap the range.
            if (!ValidCodeByteSignature(planned.signature)) {
                authorizationWatch_.markSkipped(
                    generation, va,
                    AuthorizationWatchSkipReason::SignatureUnavailable);
                continue;
            }
            std::array<uint8_t, kCodeByteSignatureMax> liveInstruction{};
            const size_t signatureBytes = planned.signature.length;
            if (!executableMainImageRange(va, signatureBytes)) {
                authorizationWatch_.markSkipped(generation, va);
                continue;
            }
            const size_t liveBytes = readMemoryMasked(
                va, liveInstruction.data(), signatureBytes);
            if (liveBytes != signatureBytes) {
                authorizationWatch_.markSkipped(
                    generation, va,
                    AuthorizationWatchSkipReason::SignatureUnavailable);
                continue;
            }
            if (!CodeByteSignatureMatches(planned.signature,
                                          liveInstruction.data(), liveBytes)) {
                authorizationWatch_.markSkipped(
                    generation, va,
                    AuthorizationWatchSkipReason::SignatureMismatch);
                continue;
            }

            AuthorizationBp bp;
            bp.generation = generation;
            bp.signature = planned.signature;
            bool sharedWithUser = false;
            bool conflict = false;
            {
                std::lock_guard<std::mutex> lk(mtx_);
                if (auto user = bps_.find(va);
                    user != bps_.end() && user->second.armed) {
                    bp.orig = user->second.orig;
                    bp.ownsByte = false;
                    sharedWithUser = true;
                } else if (bps_.count(va) || traceBps_.count(va) ||
                           dllTargetBps_.count(va) || antiTraps_.count(va) ||
                           networkProbeBps_.count(va) || networkReturnBps_.count(va) ||
                           authorizationReturnBps_.count(va) ||
                           (runtimeTempBpAddr_ && *runtimeTempBpAddr_ == va)) {
                    conflict = true;
                }
            }
            if (conflict || (bp.ownsByte &&
                (!readByteRPM((HANDLE)hProcess_, va, bp.orig) || bp.orig == 0xCC))) {
                authorizationWatch_.markSkipped(generation, va);
                continue;
            }

            bp.armed = false;
            {
                std::lock_guard<std::mutex> lk(mtx_);
                authorizationBps_.emplace(va, bp);
                auto at = std::lower_bound(authorizationBpAddrs_.begin(),
                                           authorizationBpAddrs_.end(), va);
                authorizationBpAddrs_.insert(at, va);
            }
            const bool armed = !bp.ownsByte ||
                replaceByteIfEqual((HANDLE)hProcess_, va, bp.orig, 0xCC);
            if (!armed) {
                {
                    std::lock_guard<std::mutex> lk(mtx_);
                    authorizationBps_.erase(va);
                    auto at = std::lower_bound(authorizationBpAddrs_.begin(),
                                               authorizationBpAddrs_.end(), va);
                    if (at != authorizationBpAddrs_.end() && *at == va)
                        authorizationBpAddrs_.erase(at);
                }
                authorizationWatch_.markSkipped(generation, va);
                continue;
            }
            {
                std::lock_guard<std::mutex> lk(mtx_);
                if (auto it = authorizationBps_.find(va); it != authorizationBps_.end())
                    it->second.armed = true;
            }
            authorizationWatch_.markArmed(generation, va, sharedWithUser);
        }
        if (imageExtentMismatch) {
            std::lock_guard<std::mutex> lk(mtx_);
            lastEvent_ = "Authorization Watch image-size identity mismatch";
        }
    };

    auto applyPendingBps = [&]() {
        std::vector<PendingBp> adds, conds;
        std::vector<uint64_t>  rems;
        { std::lock_guard<std::mutex> lk(mtx_);
          adds.swap(pendingBpAdds_); rems.swap(pendingBpRems_); conds.swap(pendingBpConds_); }
        bool bpSetChanged = false;   // adds/removes that change the bpAddrs_ key set
        auto installFailure = [&](uint64_t va, const char* why,
                                  const std::string* condition = nullptr) {
            char message[256];
            std::snprintf(message, sizeof(message),
                          "breakpoint 0x%llX not installed: %s",
                          (unsigned long long)va, why);
            std::lock_guard<std::mutex> lk(mtx_);
            lastEvent_ = message;
            if (condition) {
                clearBreakpointInstallFailureLocked(va);
                if (failedBpInstalls_.size() == kMaxFailedBreakpointInstalls)
                    failedBpInstalls_.pop_front();
                SwBreakpointInfo failed;
                failed.address = va;
                failed.condition = *condition;
                failed.armed = false;
                failed.error = why;
                failedBpInstalls_.push_back(std::move(failed));
            }
        };
        for (auto& add : adds) {
            // Public callers are validated before enqueueing; retain this guard
            // at the debug-thread boundary so malformed legacy/corrupt commands
            // can never be installed as unconditional breakpoints.
            if (!ValidateBreakpointCondition(add.cond)) continue;
            bool gmlConflict = false;
            { std::lock_guard<std::mutex> lk(mtx_); gmlConflict = gameMakerOwnsRangeLocked(add.va,1); }
            if (gmlConflict) {
                installFailure(add.va,"address belongs to a GameMaker instruction hook or helper",&add.cond);
                continue;
            }
            const CondProgram compiled = CompileCondition(add.cond);
            if (bps_.count(add.va)) {   // re-add of an existing bp only updates its condition
                std::lock_guard<std::mutex> lk(mtx_);
                bps_[add.va].cond = add.cond; bps_[add.va].prog = compiled;
                clearBreakpointInstallFailureLocked(add.va);
                continue;
            }
            if (tempBpSet && tempBpAddr == add.va) {
                installFailure(add.va, "address is owned by a temporary debugger hook", &add.cond);
                continue;
            }

            enum class ExistingOwner {
                None, Trace, DllTarget, AntiTrap, NetworkProbe, NetworkReturn,
                Authorization, AuthorizationReturn
            };
            ExistingOwner owner = ExistingOwner::None;
            uint8_t orig = 0;
            uint64_t traceGeneration = 0;
            uint64_t authorizationGeneration = 0;
            {
                std::lock_guard<std::mutex> lk(mtx_);
                auto trace = traceBps_.find(add.va);
                if (trace != traceBps_.end()) {
                    orig = trace->second.orig;
                    traceGeneration = trace->second.generation;
                    owner = ExistingOwner::Trace;
                }
                auto dll = dllTargetBps_.find(add.va);
                if (owner == ExistingOwner::None && dll != dllTargetBps_.end()) {
                    orig = dll->second.orig;
                    owner = ExistingOwner::DllTarget;
                }
                auto anti = antiTraps_.find(add.va);
                if (owner == ExistingOwner::None && anti != antiTraps_.end()) {
                    orig = anti->second.orig;
                    owner = ExistingOwner::AntiTrap;
                }
                auto networkProbe = networkProbeBps_.find(add.va);
                if (owner == ExistingOwner::None && networkProbe != networkProbeBps_.end()) {
                    orig = networkProbe->second.orig;
                    owner = ExistingOwner::NetworkProbe;
                }
                auto networkReturn = networkReturnBps_.find(add.va);
                if (owner == ExistingOwner::None && networkReturn != networkReturnBps_.end()) {
                    orig = networkReturn->second.orig;
                    owner = ExistingOwner::NetworkReturn;
                }
                auto authorization = authorizationBps_.find(add.va);
                if (owner == ExistingOwner::None &&
                    authorization != authorizationBps_.end()) {
                    orig = authorization->second.orig;
                    authorizationGeneration = authorization->second.generation;
                    owner = ExistingOwner::Authorization;
                }
                auto authorizationReturn = authorizationReturnBps_.find(add.va);
                if (owner == ExistingOwner::None &&
                    authorizationReturn != authorizationReturnBps_.end()) {
                    orig = authorizationReturn->second.orig;
                    owner = ExistingOwner::AuthorizationReturn;
                }
            }

            if (owner == ExistingOwner::None &&
                !readByteRPM((HANDLE)hProcess_, add.va, orig)) {
                installFailure(add.va, "target byte is unreadable", &add.cond);
                continue;
            }
            // A program-authored INT3 has no displaced instruction to execute. Treat
            // it as a native trap and reject the request instead of backing RIP onto
            // it forever or later "restoring" a fabricated byte.
            if (orig == 0xCC) {
                installFailure(add.va, "site contains a native INT3", &add.cond);
                continue;
            }

            bool physicalReady = false;
            if (owner == ExistingOwner::None)
                physicalReady = replaceByteIfEqual((HANDLE)hProcess_, add.va, orig, 0xCC);
            else {
                uint8_t live = 0;
                physicalReady = readByteRPM((HANDLE)hProcess_, add.va, live) && live == 0xCC;
            }
            if (!physicalReady) {
                installFailure(add.va, "byte changed or could not be verified", &add.cond);
                continue;
            }

            SwBp bp;
            bp.orig = orig;
            bp.cond = add.cond;
            bp.prog = compiled;
            bp.ownsByte = owner != ExistingOwner::AntiTrap;
            bp.armed = true;
            try {
                std::lock_guard<std::mutex> lk(mtx_);
                bps_.emplace(add.va, std::move(bp));
                clearBreakpointInstallFailureLocked(add.va);
                if (owner == ExistingOwner::Trace) {
                    traceBps_.erase(add.va);
                    auto ai = std::lower_bound(traceBpAddrs_.begin(), traceBpAddrs_.end(), add.va);
                    if (ai != traceBpAddrs_.end() && *ai == add.va) traceBpAddrs_.erase(ai);
                } else if (owner == ExistingOwner::DllTarget) {
                    if (auto dll = dllTargetBps_.find(add.va); dll != dllTargetBps_.end())
                        dll->second.ownsByte = false;
                } else if (owner == ExistingOwner::NetworkProbe) {
                    if (auto probe = networkProbeBps_.find(add.va); probe != networkProbeBps_.end())
                        probe->second.ownsByte = false;
                } else if (owner == ExistingOwner::NetworkReturn) {
                    if (auto site = networkReturnBps_.find(add.va); site != networkReturnBps_.end())
                        site->second.ownsByte = false;
                } else if (owner == ExistingOwner::Authorization) {
                    if (auto site = authorizationBps_.find(add.va);
                        site != authorizationBps_.end())
                        site->second.ownsByte = false;
                    if (auto completion = authorizationReturnBps_.find(add.va);
                        completion != authorizationReturnBps_.end())
                        completion->second.sharedWithUserBreakpoint = true;
                } else if (owner == ExistingOwner::AuthorizationReturn) {
                    if (auto site = authorizationReturnBps_.find(add.va);
                        site != authorizationReturnBps_.end()) {
                        site->second.ownsByte = false;
                        site->second.sharedWithUserBreakpoint = true;
                    }
                }
                bpSetChanged = true;
            } catch (...) {
                if (owner == ExistingOwner::None)
                    (void)replaceByteIfEqual((HANDLE)hProcess_, add.va, 0xCC, orig);
                throw;
            }
            if (owner == ExistingOwner::Trace)
                traceCoverage_.markSkipped(traceGeneration, add.va);
            if (owner == ExistingOwner::Authorization)
                authorizationWatch_.markArmed(authorizationGeneration, add.va, true);
        }
        for (auto& cset : conds) {
            if (!ValidateBreakpointCondition(cset.cond)) continue;
            const CondProgram compiled = CompileCondition(cset.cond);
            std::lock_guard<std::mutex> lk(mtx_);
            auto it = bps_.find(cset.va);
            if (it != bps_.end()) { it->second.cond = cset.cond; it->second.prog = compiled; }
            for (auto& failed : failedBpInstalls_)
                if (failed.address == cset.va) failed.condition = cset.cond;
        }
        {   // every-Nth-hit updates (applied after adds so a fresh bp can be tuned).
            std::vector<std::pair<uint64_t, uint32_t>> everyNs;
            { std::lock_guard<std::mutex> lk(mtx_); everyNs.swap(pendingBpEveryN_); }
            for (auto& [va, n] : everyNs) {
                std::lock_guard<std::mutex> lk(mtx_);
                auto it = bps_.find(va);
                if (it != bps_.end()) it->second.everyN = n;
                for (auto& failed : failedBpInstalls_)
                    if (failed.address == va) failed.everyN = n;
            }
        }
        for (uint64_t va : rems) {
            SwBp bp;
            {
                std::lock_guard<std::mutex> lk(mtx_);
                clearBreakpointInstallFailureLocked(va);
                auto it = bps_.find(va);
                if (it == bps_.end()) continue;
                bp = it->second;
            }
            bool transferredToDllTarget = false;
            bool transferredToNetworkProbe = false;
            bool transferredToNetworkReturn = false;
            bool transferredToAuthorization = false;
            bool transferredToAuthorizationReturn = false;
            uint64_t transferredAuthorizationGeneration = 0;
            bool retainedByAntiTrap = false;
            bool parkedHere = false;
            {
                std::lock_guard<std::mutex> lk(mtx_);
                transferredToDllTarget = [&] {
                    auto dll = dllTargetBps_.find(va);
                    return dll != dllTargetBps_.end() && !dll->second.ownsByte;
                }();
                transferredToNetworkProbe = [&] {
                    auto probe = networkProbeBps_.find(va);
                    return probe != networkProbeBps_.end() && !probe->second.ownsByte;
                }();
                transferredToNetworkReturn = [&] {
                    auto site = networkReturnBps_.find(va);
                    return site != networkReturnBps_.end() && !site->second.ownsByte;
                }();
                transferredToAuthorization = [&] {
                    auto site = authorizationBps_.find(va);
                    if (site != authorizationBps_.end())
                        transferredAuthorizationGeneration = site->second.generation;
                    return site != authorizationBps_.end() && !site->second.ownsByte;
                }();
                transferredToAuthorizationReturn = [&] {
                    if (transferredToAuthorization) return false;
                    auto site = authorizationReturnBps_.find(va);
                    return site != authorizationReturnBps_.end() &&
                           !site->second.ownsByte;
                }();
                retainedByAntiTrap = antiTraps_.count(va) != 0;
                parkedHere = pausedUserBpAddr_ && *pausedUserBpAddr_ == va;
            }

            bool removalSafe = true;
            const bool transferred = transferredToDllTarget || transferredToNetworkProbe ||
                                     transferredToNetworkReturn ||
                                     transferredToAuthorization ||
                                     transferredToAuthorizationReturn;
            if (bp.ownsByte && !transferred && !retainedByAntiTrap && !parkedHere) {
                uint8_t live = 0;
                if (!readByteRPM((HANDLE)hProcess_, va, live)) {
                    removalSafe = !bp.armed; // failed/unmapped rows remain removable
                } else if (live == 0xCC) {
                    removalSafe = replaceByteIfEqual((HANDLE)hProcess_, va, 0xCC, bp.orig);
                } // A non-INT3 means ownership was superseded by a patch/self-write;
                  // deliberately leave that byte untouched and retire our metadata.
            }
            if (!removalSafe) {
                installFailure(va, "could not safely restore the owned byte");
                continue;
            }

            {
                std::lock_guard<std::mutex> lk(mtx_);
                if (transferredToDllTarget) {
                    if (auto dll = dllTargetBps_.find(va); dll != dllTargetBps_.end()) {
                        dll->second.orig = bp.orig;
                        dll->second.ownsByte = true;
                    }
                }
                if (transferredToNetworkProbe) {
                    if (auto probe = networkProbeBps_.find(va); probe != networkProbeBps_.end()) {
                        probe->second.orig = bp.orig;
                        probe->second.ownsByte = true;
                        probe->second.armed = !parkedHere;
                    }
                }
                if (transferredToNetworkReturn) {
                    if (auto site = networkReturnBps_.find(va); site != networkReturnBps_.end()) {
                        site->second.orig = bp.orig;
                        site->second.ownsByte = true;
                        site->second.armed = !parkedHere;
                    }
                }
                if (transferredToAuthorization) {
                    if (auto site = authorizationBps_.find(va);
                        site != authorizationBps_.end()) {
                        site->second.orig = bp.orig;
                        site->second.ownsByte = true;
                        site->second.armed = !parkedHere;
                    }
                    if (auto completion = authorizationReturnBps_.find(va);
                        completion != authorizationReturnBps_.end())
                        completion->second.sharedWithUserBreakpoint = false;
                }
                if (transferredToAuthorizationReturn) {
                    if (auto site = authorizationReturnBps_.find(va);
                        site != authorizationReturnBps_.end()) {
                        site->second.orig = bp.orig;
                        site->second.ownsByte = true;
                        site->second.armed = !parkedHere;
                        site->second.sharedWithUserBreakpoint = false;
                    }
                }
                bps_.erase(va);
                if (parkedHere) pausedUserBpAddr_.reset();
                bpSetChanged = true;
            }
            if (parkedHere) {
                const bool networkTransfer = transferredToNetworkProbe ||
                                             transferredToNetworkReturn;
                const bool persistentInternalTransfer = networkTransfer ||
                                                        transferredToAuthorization ||
                                                        transferredToAuthorizationReturn;
                if (persistentInternalTransfer) {
                    // RIP still points at the restored original instruction. Keep
                    // the parked state and transfer ownership metadata now, but
                    // defer the physical INT3 until the normal step-off lease has
                    // executed that instruction exactly once.
                    parkedInternalTransfer = true;
                    parkedInternalOwner = transferredToNetworkProbe
                                        ? ReArmOwner::NetworkProbe
                                        : transferredToNetworkReturn
                                        ? ReArmOwner::NetworkReturn
                                        : transferredToAuthorization
                                        ? ReArmOwner::Authorization
                                        : ReArmOwner::AuthorizationReturn;
                } else if (transferred &&
                           !replaceByteIfEqual((HANDLE)hProcess_, va, bp.orig, 0xCC)) {
                    breakpointTransitionFailed = true;
                    { std::lock_guard<std::mutex> lk(mtx_);
                      if (auto probe = networkProbeBps_.find(va); probe != networkProbeBps_.end())
                          probe->second.armed = false;
                      if (auto site = networkReturnBps_.find(va); site != networkReturnBps_.end())
                          site->second.armed = false; }
                    installFailure(va, "could not transfer the parked byte to an internal probe");
                }
                if (!persistentInternalTransfer) {
                    pausedOnBp = false;
                    pausedOnBpAddr = 0;
                }
            }
            if (transferredToAuthorization)
                authorizationWatch_.markArmed(
                    transferredAuthorizationGeneration, va, false);
        }
        // Keep the sorted breakpoint-address cache in sync with the key set, so
        // readMemoryMasked stays O(log n) per read (see rebuildBpAddrs_).
        if (bpSetChanged) { std::lock_guard<std::mutex> lk(mtx_); rebuildBpAddrs_(); }

        // Hardware breakpoints: fold pending changes into slots, reprogram threads.
        std::vector<HwSlot> hwAdds; std::vector<uint64_t> hwRems;
        { std::lock_guard<std::mutex> lk(mtx_); hwAdds.swap(pendingHwAdds_); hwRems.swap(pendingHwRems_); }
        bool hwChanged = false;
        for (uint64_t va : hwRems) {
            for (auto& s : hwSlots_)
                if (s.used && s.addr == va) { std::lock_guard<std::mutex> lk(mtx_); s = HwSlot{}; hwChanged = true; }
        }
        for (auto& add : hwAdds) {
            { std::lock_guard<std::mutex> lk(mtx_);
              if (gameMakerOwnsRangeLocked(add.addr,add.kind==HwKind::Execute?1:add.size)) continue; }
            bool placed = false;
            for (auto& s : hwSlots_) if (s.used && s.addr == add.addr) { placed = true; break; }
            if (placed) continue;
            for (auto& s : hwSlots_) if (!s.used) { std::lock_guard<std::mutex> lk(mtx_); s = add; hwChanged = true; placed = true; break; }
        }
        if (hwChanged && !applyHwAllThreads()) {
            std::lock_guard<std::mutex> lk(mtx_);
            lastEvent_ = "hardware breakpoint update incomplete";
        }

        // Re-scan on every stopped debug event so late module loads gain probes.
        if (networkObservationWant_.load()) {
            armNetTap();
        } else if (netTapArmed_ || !networkProbeBps_.empty() ||
                   !networkReturnBps_.empty()) {
            disarmNetTap();
            if (parkedInternalTransfer) {
                // A queued user-breakpoint removal can transfer a currently
                // parked shared byte to a network probe earlier in this same
                // mutation pass. If Server Watch is also being stopped, the
                // disarm above retires that new owner before resume. Do not
                // single-step and then try to re-arm the now-nonexistent probe:
                // the original instruction is already restored and the removed
                // user breakpoint intentionally has no successor owner.
                parkedInternalTransfer = false;
                parkedInternalOwner = ReArmOwner::User;
                pausedOnBp = false;
                pausedOnBpAddr = 0;
                std::lock_guard<std::mutex> lk(mtx_);
                pausedUserBpAddr_.reset();
            }
        }
    };

    // Publish a one-line status for the UI (locks mtx_; never called while held).
    auto setEvent = [&](const char* s) { std::lock_guard<std::mutex> lk(mtx_); lastEvent_ = s; };

    auto endExclusiveStep = [&]() {
        for (uint32_t tid : exclusiveStepSuspended) {
            if (auto it = threads_.find(tid); it != threads_.end())
                ResumeThread((HANDLE)it->second);
        }
        exclusiveStepSuspended.clear();
        exclusiveStepOwner = 0;
    };
    auto beginExclusiveStep = [&](uint32_t ownerTid) {
        if (!ownerTid || exclusiveStepOwner == ownerTid) return;
        endExclusiveStep();
        std::unordered_set<uint32_t> userSuspended;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            userSuspended = suspended_;
        }
        exclusiveStepOwner = ownerTid;
        for (const auto& [tid, handle] : threads_) {
            if (tid == ownerTid || !handle || userSuspended.count(tid)) continue;
            if (SuspendThread((HANDLE)handle) != static_cast<DWORD>(-1))
                exclusiveStepSuspended.insert(tid);
        }
    };
    auto rearmUserBreakpoint = [&](uint64_t va) {
        if (armBreakpoint(va)) {
            std::lock_guard<std::mutex> lk(mtx_);
            if (auto probe = networkProbeBps_.find(va); probe != networkProbeBps_.end())
                probe->second.armed = true;
            if (auto site = networkReturnBps_.find(va); site != networkReturnBps_.end())
                site->second.armed = true;
            if (auto site = authorizationBps_.find(va); site != authorizationBps_.end())
                site->second.armed = true;
            if (auto site = authorizationReturnBps_.find(va);
                site != authorizationReturnBps_.end())
                site->second.armed = true;
            return true;
        }
        breakpointTransitionFailed = true;
        setEvent("breakpoint re-arm failed");
        return false;
    };
    auto rearmOwnedBreakpoint = [&](uint64_t va, ReArmOwner owner) {
        return owner == ReArmOwner::NetworkProbe ? rearmNetworkProbe(va)
             : owner == ReArmOwner::NetworkReturn ? rearmNetworkReturn(va)
             : owner == ReArmOwner::Authorization ? rearmAuthorizationBreakpoint(va)
             : owner == ReArmOwner::AuthorizationReturn ? rearmAuthorizationReturn(va)
                                                   : rearmUserBreakpoint(va);
    };
    auto hasArmedUserBreakpoint = [&](uint64_t va) {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = bps_.find(va);
        return it != bps_.end() && it->second.armed;
    };
    auto authorizationEntrySignatureMatches = [&](uint64_t va,
                                                   uint64_t generation) {
        CodeByteSignature signature;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            auto it = authorizationBps_.find(va);
            if (it == authorizationBps_.end() ||
                it->second.generation != generation)
                return false;
            signature = it->second.signature;
        }
        if (!ValidCodeByteSignature(signature)) return false;
        std::array<uint8_t, kCodeByteSignatureMax> liveInstruction{};
        const size_t liveBytes = readMemoryMasked(
            va, liveInstruction.data(), signature.length);
        return liveBytes == signature.length &&
               CodeByteSignatureMatches(signature, liveInstruction.data(),
                                        liveBytes);
    };
    auto retireAuthorizationEntryForSignatureMismatch = [&] (
        uint64_t va, uint64_t generation) {
        bool retired = false;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            auto entry = authorizationBps_.find(va);
            if (entry == authorizationBps_.end() ||
                entry->second.generation != generation)
                return;

            // The hit path has already exposed the original first byte. If a
            // pending completion probe shares this physical address, transfer
            // ownership to it before retiring the stale entry metadata. A user
            // breakpoint remains the owner when the entry was only side-band.
            if (auto completion = authorizationReturnBps_.find(va);
                completion != authorizationReturnBps_.end()) {
                completion->second.armed = false;
                if (entry->second.ownsByte && !completion->second.ownsByte) {
                    completion->second.orig = entry->second.orig;
                    completion->second.ownsByte = true;
                    completion->second.sharedWithUserBreakpoint = false;
                }
            }
            authorizationBps_.erase(entry);
            auto at = std::lower_bound(authorizationBpAddrs_.begin(),
                                       authorizationBpAddrs_.end(), va);
            if (at != authorizationBpAddrs_.end() && *at == va)
                authorizationBpAddrs_.erase(at);
            retired = true;
        }
        if (retired)
            authorizationWatch_.markHitSignatureMismatch(generation, va);
    };

    auto ripOf = [&](uint32_t tid) -> uint64_t {
        auto it = threads_.find(tid); if (it == threads_.end()) return 0;
        return ctxReadRip(it->second);   // arch-aware (RIP or EIP)
    };
    auto rspOf = [&](uint32_t tid) -> uint64_t {
        auto it = threads_.find(tid); if (it == threads_.end()) return 0;
        Registers r; return ctxReadFull(it->second, r) ? r.rsp : 0;   // arch-aware (RSP or ESP)
    };
    auto noteAuthorizationReturnDropped = [&](size_t count = 1) {
        std::lock_guard<std::mutex> lk(mtx_);
        if (UINT64_MAX - authorizationPendingReturnsDropped_ < count)
            authorizationPendingReturnsDropped_ = UINT64_MAX;
        else
            authorizationPendingReturnsDropped_ += count;
    };
    auto queueAuthorizationReturn = [&] (
        uint64_t entryAddress, uint32_t ownerTid,
        std::vector<AuthorizationWatchReturnRequest> requests) {
        if (requests.empty()) return true;
        const size_t requestCount = requests.size();
        const StepDecode decoded = decodeAt(entryAddress);
        if (!decoded.isCall || !decoded.length ||
            entryAddress > UINT64_MAX - decoded.length) {
            noteAuthorizationReturnDropped(requestCount);
            return false;
        }
        const uint64_t returnAddress = entryAddress + decoded.length;
        const bool first = authorizationPendingReturns_.references(returnAddress) == 0;
        if (first) {
            AuthorizationReturnBp site;
            bool conflict = false;
            bool sharedOwnerArmed = true;
            {
                std::lock_guard<std::mutex> lk(mtx_);
                if (auto user = bps_.find(returnAddress);
                    user != bps_.end()) {
                    site.orig = user->second.orig;
                    site.ownsByte = false;
                    site.sharedWithUserBreakpoint = true;
                    sharedOwnerArmed = user->second.armed;
                } else if (auto authorization = authorizationBps_.find(returnAddress);
                           authorization != authorizationBps_.end()) {
                    site.orig = authorization->second.orig;
                    site.ownsByte = false;
                    sharedOwnerArmed = authorization->second.armed;
                } else if (traceBps_.count(returnAddress) ||
                           dllTargetBps_.count(returnAddress) ||
                           antiTraps_.count(returnAddress) ||
                           networkProbeBps_.count(returnAddress) ||
                           networkReturnBps_.count(returnAddress) ||
                           authorizationReturnBps_.count(returnAddress) ||
                           (runtimeTempBpAddr_ &&
                            *runtimeTempBpAddr_ == returnAddress)) {
                    conflict = true;
                }
            }
            if (conflict || (site.ownsByte &&
                (!readByteRPM((HANDLE)hProcess_, returnAddress, site.orig) ||
                 site.orig == 0xCC))) {
                noteAuthorizationReturnDropped(requestCount);
                return false;
            }
            site.armed = false;
            {
                std::lock_guard<std::mutex> lk(mtx_);
                authorizationReturnBps_.emplace(returnAddress, site);
                auto at = std::lower_bound(authorizationReturnBpAddrs_.begin(),
                                           authorizationReturnBpAddrs_.end(),
                                           returnAddress);
                authorizationReturnBpAddrs_.insert(at, returnAddress);
            }
            const bool armed = !site.ownsByte ||
                replaceByteIfEqual((HANDLE)hProcess_, returnAddress,
                                   site.orig, 0xCC);
            if (!armed) {
                {
                    std::lock_guard<std::mutex> lk(mtx_);
                    authorizationReturnBps_.erase(returnAddress);
                    auto at = std::lower_bound(authorizationReturnBpAddrs_.begin(),
                                               authorizationReturnBpAddrs_.end(),
                                               returnAddress);
                    if (at != authorizationReturnBpAddrs_.end() &&
                        *at == returnAddress)
                        authorizationReturnBpAddrs_.erase(at);
                }
                noteAuthorizationReturnDropped(requestCount);
                return false;
            }
            {
                std::lock_guard<std::mutex> lk(mtx_);
                if (auto siteIt = authorizationReturnBps_.find(returnAddress);
                    siteIt != authorizationReturnBps_.end())
                    siteIt->second.armed = site.ownsByte || sharedOwnerArmed;
            }
        }

        AuthorizationWatchPendingReturn pending;
        pending.entryAddress = entryAddress;
        pending.requests = std::move(requests);
        if (!authorizationPendingReturns_.push(ownerTid, returnAddress,
                                               std::move(pending))) {
            if (first) {
                AuthorizationReturnBp site;
                bool found = false;
                {
                    std::lock_guard<std::mutex> lk(mtx_);
                    if (auto it = authorizationReturnBps_.find(returnAddress);
                        it != authorizationReturnBps_.end()) {
                        site = it->second;
                        authorizationReturnBps_.erase(it);
                        found = true;
                    }
                    auto at = std::lower_bound(authorizationReturnBpAddrs_.begin(),
                                               authorizationReturnBpAddrs_.end(),
                                               returnAddress);
                    if (at != authorizationReturnBpAddrs_.end() &&
                        *at == returnAddress)
                        authorizationReturnBpAddrs_.erase(at);
                }
                if (found && site.ownsByte && site.armed)
                    (void)replaceByteIfEqual((HANDLE)hProcess_, returnAddress,
                                             0xCC, site.orig);
            }
            noteAuthorizationReturnDropped(requestCount);
            return false;
        }
        {
            std::lock_guard<std::mutex> lk(mtx_);
            authorizationPendingReturnCount_ =
                authorizationPendingReturns_.total();
        }
        return true;
    };
    auto authorizationReturnOnHit = [&] (
        uint64_t returnAddress, uint32_t ownerTid, bool ownerAlreadyDisarmed,
        bool* transitionFailed, bool* pauseRequested) {
        if (transitionFailed) *transitionFailed = false;
        if (pauseRequested) *pauseRequested = false;
        if (!ownerAlreadyDisarmed &&
            !disarmAuthorizationReturn(returnAddress)) {
            if (transitionFailed) *transitionFailed = true;
            return false;
        }
        if (ownerAlreadyDisarmed) {
            std::lock_guard<std::mutex> lk(mtx_);
            if (auto site = authorizationReturnBps_.find(returnAddress);
                site != authorizationReturnBps_.end())
                site->second.armed = false;
        }
        if (auto thread = threads_.find(ownerTid); thread != threads_.end())
            ctxSetRip(thread->second, returnAddress);

        AuthorizationWatchPendingReturn pending;
        const bool popped = authorizationPendingReturns_.pop(
            ownerTid, returnAddress, pending);
        {
            std::lock_guard<std::mutex> lk(mtx_);
            authorizationPendingReturnCount_ =
                authorizationPendingReturns_.total();
        }
        if (popped) {
            Registers registers;
            const bool contextValid = [&] {
                auto thread = threads_.find(ownerTid);
                return thread != threads_.end() &&
                       ctxReadFull(thread->second, registers);
            }();
            const uint8_t pointerBits = contextValid
                ? (isWow64_.load() ? uint8_t{32} : uint8_t{64}) : uint8_t{0};
            bool completionPause = false;
            for (const AuthorizationWatchReturnRequest& request : pending.requests)
                completionPause = authorizationWatch_.recordStateReturn(
                    request, returnAddress, ownerTid, GetTickCount64(),
                    contextValid ? registers.rax : 0, pointerBits) ||
                    completionPause;
            if (pauseRequested) *pauseRequested = completionPause;
        }

        const bool needsRearm =
            authorizationPendingReturns_.references(returnAddress) != 0;
        if (!needsRearm) {
            std::lock_guard<std::mutex> lk(mtx_);
            authorizationReturnBps_.erase(returnAddress);
            auto at = std::lower_bound(authorizationReturnBpAddrs_.begin(),
                                       authorizationReturnBpAddrs_.end(),
                                       returnAddress);
            if (at != authorizationReturnBpAddrs_.end() &&
                *at == returnAddress)
                authorizationReturnBpAddrs_.erase(at);
        }
        return needsRearm;
    };
    auto takeTraceSite = [&](uint64_t addr, TraceBp& out) -> bool {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = traceBps_.find(addr);
        if (it == traceBps_.end()) return false;
        out = it->second;
        traceBps_.erase(it);
        auto ai = std::lower_bound(traceBpAddrs_.begin(), traceBpAddrs_.end(), addr);
        if (ai != traceBpAddrs_.end() && *ai == addr) traceBpAddrs_.erase(ai);
        return true;
    };
    auto dllTargetText = [](const DllTargetBp& bp) {
        std::string text;
        for (const auto& label : bp.labels) {
            if (!text.empty()) text += " / ";
            text += label;
        }
        return text.empty() ? std::string("DLL target") : text;
    };
    auto takeDllTarget = [&](uint64_t addr, DllTargetBp& out) -> bool {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = dllTargetBps_.find(addr);
        if (it == dllTargetBps_.end()) return false;
        out = std::move(it->second);
        dllTargetBps_.erase(it);
        auto ai = std::lower_bound(dllTargetBpAddrs_.begin(), dllTargetBpAddrs_.end(), addr);
        if (ai != dllTargetBpAddrs_.end() && *ai == addr) dllTargetBpAddrs_.erase(ai);
        return true;
    };
    auto isDllTarget = [&](uint64_t addr) {
        std::lock_guard<std::mutex> lk(mtx_);
        return dllTargetBps_.count(addr) != 0;
    };
    auto publishDllTargetHit = [&](const DllTargetBp& target) {
        std::lock_guard<std::mutex> lk(mtx_);
        dllTargetLabel_ = dllTargetText(target);
        lastEvent_ = "DLL target: " + dllTargetLabel_;
    };
    auto appendDllTargetError = [&](const std::string& error) {
        std::lock_guard<std::mutex> lk(mtx_);
        if (!dllTargetError_.empty()) dllTargetError_ += "; ";
        dllTargetError_ += error;
    };
    auto armDllTarget = [&](const DllBreakpointTarget& target) -> bool {
        const uint64_t addr = target.runtimeVA;
        if (!addr) {
            appendDllTargetError("zero runtime address for " + target.label);
            return false;
        }
        {   // Two requested labels can legitimately resolve to one entry point.
            std::lock_guard<std::mutex> lk(mtx_);
            if (auto it = dllTargetBps_.find(addr); it != dllTargetBps_.end()) {
                if (std::find(it->second.labels.begin(), it->second.labels.end(), target.label) ==
                    it->second.labels.end())
                    it->second.labels.push_back(target.label);
                return true;
            }
        }

        DllTargetBp bp;
        bp.labels.push_back(target.label);
        bool userOwns = false;
        { std::lock_guard<std::mutex> lk(mtx_);
          if (auto user = bps_.find(addr); user != bps_.end()) {
              bp.orig = user->second.orig;
              userOwns = true;
          } }

        TraceBp trace;
        if (!userOwns && takeTraceSite(addr, trace)) {
            bp.orig = trace.orig;
            traceCoverage_.markSkipped(trace.generation, addr);
        } else if (!userOwns && tempBpSet && tempBpAddr == addr) {
            bp.orig = tempBpOrig; // the temp mechanism continues owning the int3
            userOwns = true;
        } else if (!userOwns) {
            bool networkConflict = false;
            { std::lock_guard<std::mutex> lk(mtx_);
              networkConflict = networkProbeBps_.count(addr) || networkReturnBps_.count(addr) ||
                                authorizationBps_.count(addr) ||
                                authorizationReturnBps_.count(addr); }
            if (networkConflict) {
                appendDllTargetError("target conflicts with an active internal observation probe: " + target.label);
                return false;
            }
            if (!readByteRPM((HANDLE)hProcess_, addr, bp.orig) || bp.orig == 0xCC) {
                appendDllTargetError("could not read a pristine byte for " + target.label);
                return false;
            }
        }

        bp.ownsByte = !userOwns;
        if (bp.ownsByte && !writeByteRPM((HANDLE)hProcess_, addr, 0xCC)) {
            appendDllTargetError("could not arm " + target.label);
            return false;
        }
        { std::lock_guard<std::mutex> lk(mtx_);
          dllTargetBps_.emplace(addr, std::move(bp));
          auto at = std::lower_bound(dllTargetBpAddrs_.begin(), dllTargetBpAddrs_.end(), addr);
          dllTargetBpAddrs_.insert(at, addr); }
        return true;
    };
    auto removeDllTargets = [&](uint64_t base, uint64_t size) {
        std::vector<std::pair<uint64_t, DllTargetBp>> removed;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            for (auto it = dllTargetBps_.begin(); it != dllTargetBps_.end(); ) {
                const bool inRange = base == 0 ||
                    (it->first >= base && (size == 0 || it->first - base < size));
                if (inRange) {
                    removed.emplace_back(it->first, std::move(it->second));
                    it = dllTargetBps_.erase(it);
                } else {
                    ++it;
                }
            }
            dllTargetBpAddrs_.clear();
            dllTargetBpAddrs_.reserve(dllTargetBps_.size());
            for (const auto& [va, ignored] : dllTargetBps_) {
                (void)ignored;
                dllTargetBpAddrs_.push_back(va);
            }
            std::sort(dllTargetBpAddrs_.begin(), dllTargetBpAddrs_.end());
        }
        for (const auto& [va, bp] : removed)
            if (bp.ownsByte)
                breakpointCleanupComplete =
                    restoreDebuggerOwnedByte((HANDLE)hProcess_, va, bp.orig) &&
                    breakpointCleanupComplete;
    };
    // Arm a one-shot temp breakpoint at `addr`, remembering what it stands for.
    auto setTempBp = [&](uint64_t addr, TempKind kind, uint32_t ownerTid) -> bool {
        { std::lock_guard<std::mutex> lk(mtx_);
          if (gameMakerOwnsRangeLocked(addr,1)) return false; }
        tempBpAddr = addr; tempBpOrig = 0x90;
        tempOwnerTid = ownerTid;
        tempCheckedRunToToken = 0;
        bool inheritedInt3 = false;
        tempSharesAnti = false;
        tempAntiOwnerBase = 0;
        TraceBp trace;
        { std::lock_guard<std::mutex> lk(mtx_);
          if (auto anti = antiTraps_.find(addr); anti != antiTraps_.end()) {
               tempBpOrig = anti->second.orig;
               tempSharesAnti = true;
               inheritedInt3 = true;
              tempAntiOwnerBase = anti->second.ownerImageBase;
          } }
        if (!tempSharesAnti && takeTraceSite(addr, trace)) {
            tempBpOrig = trace.orig;
            inheritedInt3 = true;
            traceCoverage_.markSkipped(trace.generation, addr);
        } else if (!tempSharesAnti) {
            bool tookDllOwnership = false;
            { std::lock_guard<std::mutex> lk(mtx_);
              if (auto dll = dllTargetBps_.find(addr);
                  dll != dllTargetBps_.end() && dll->second.ownsByte) {
                  tempBpOrig = dll->second.orig;
                   dll->second.ownsByte = false;
                   tookDllOwnership = true;
                   inheritedInt3 = true;
              } }
            if (!tookDllOwnership &&
                (!readByteRPM((HANDLE)hProcess_, addr, tempBpOrig) || tempBpOrig == 0xCC)) {
                tempBpSet = false; tempOwnerTid = 0;
                tempCheckedRunToToken = 0;
                tempKind = TempKind::None;
                return false;
            }
        }
        // If the 0xCC can't actually be written (unwritable page / bad addr), don't
        // record a temp bp that was never set: it would later restore a stale byte and
        // make us wait for a stop that can never fire.
        uint8_t live = 0;
        const bool armed = inheritedInt3
            ? (readByteRPM((HANDLE)hProcess_, addr, live) && live == 0xCC)
            : replaceByteIfEqual((HANDLE)hProcess_, addr, tempBpOrig, 0xCC);
        if (!armed) {
            std::lock_guard<std::mutex> lk(mtx_);
            if (auto dll = dllTargetBps_.find(addr); dll != dllTargetBps_.end())
                dll->second.ownsByte = true; // the DLL target's original int3 remains live
            tempBpSet = false; tempSharesAnti = false; tempAntiOwnerBase = 0;
            tempOwnerTid = 0; tempCheckedRunToToken = 0;
            tempKind = TempKind::None; return false;
        }
        tempBpSet = true; tempKind = kind;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            runtimeTempBpAddr_ = addr;
        }
        return true;
    };
    // Tear down any outstanding temp breakpoint and honor a deferred user-bp re-arm.
    // Called whenever an in-progress step is abandoned (a different bp/HW bp fires),
    // so we never leak a 0xCC into the target or strand a disarmed user breakpoint.
    auto clearTempBp = [&]() -> bool {
        const uint64_t abandonedCheckedRunTo = tempCheckedRunToToken;
        std::string abandonmentReason =
            "the checked RunTo breakpoint was abandoned before it fired";
        bool released = true;
        if (tempBpSet) {
            enum class PersistentOwner { None, AntiTrap, User, DllTarget };
            PersistentOwner owner = PersistentOwner::None;
            {
                std::lock_guard<std::mutex> lk(mtx_);
                if (tempSharesAnti) {
                    auto anti = antiTraps_.find(tempBpAddr);
                    if (anti != antiTraps_.end() &&
                        anti->second.ownerImageBase == tempAntiOwnerBase)
                        owner = PersistentOwner::AntiTrap;
                }
                // A user breakpoint can depend on the same Hide Debugger byte.
                // If that anti owner was retired while the temp operation was
                // live, make the user row the next persistent owner.
                if (owner == PersistentOwner::None) {
                    auto user = bps_.find(tempBpAddr);
                    if (user != bps_.end() && user->second.armed)
                        owner = PersistentOwner::User;
                }
                if (owner == PersistentOwner::None) {
                    auto dll = dllTargetBps_.find(tempBpAddr);
                    if (dll != dllTargetBps_.end() && !dll->second.ownsByte)
                        owner = PersistentOwner::DllTarget;
                }
            }

            const bool persistentOwner = owner != PersistentOwner::None;
            bool transitioned = replaceByteIfEqual(
                (HANDLE)hProcess_, tempBpAddr, 0xCC,
                persistentOwner ? uint8_t{0xCC} : tempBpOrig);
            debugger_detail::TempBreakpointByteState byteState =
                persistentOwner
                    ? debugger_detail::TempBreakpointByteState::Int3
                    : debugger_detail::TempBreakpointByteState::Other;
            uint8_t live = 0;
            if (!transitioned) {
                if (readByteRPM((HANDLE)hProcess_, tempBpAddr, live)) {
                    byteState = live == 0xCC
                        ? debugger_detail::TempBreakpointByteState::Int3
                        : debugger_detail::TempBreakpointByteState::Other;
                    // A persistent owner still needs its trap. If a temporary
                    // exposure left the exact displaced byte live, re-arm only
                    // that proved byte; never overwrite self-modified code.
                    if (persistentOwner && live == tempBpOrig &&
                        replaceByteIfEqual((HANDLE)hProcess_, tempBpAddr,
                                           tempBpOrig, 0xCC)) {
                        transitioned = true;
                        byteState =
                            debugger_detail::TempBreakpointByteState::Int3;
                    }
                } else {
                    MEMORY_BASIC_INFORMATION mbi{};
                    if (VirtualQueryEx((HANDLE)hProcess_,
                                       reinterpret_cast<LPCVOID>(tempBpAddr),
                                       &mbi, sizeof(mbi)) == sizeof(mbi) &&
                        mbi.State != MEM_COMMIT) {
                        byteState =
                            debugger_detail::TempBreakpointByteState::Unmapped;
                    } else {
                        byteState =
                            debugger_detail::TempBreakpointByteState::Unknown;
                    }
                }
            }

            released = debugger_detail::ClassifyTempBreakpointCleanup(
                persistentOwner, transitioned, byteState) ==
                debugger_detail::TempBreakpointCleanupDisposition::Release;

            if (released && persistentOwner) {
                // Commit the metadata handoff only after the physical state has
                // been classified. Anti traps already own their shared byte;
                // user/DLL rows inherit the displaced original here.
                std::lock_guard<std::mutex> lk(mtx_);
                if (owner == PersistentOwner::User) {
                    if (auto user = bps_.find(tempBpAddr);
                        user != bps_.end()) {
                        user->second.orig = tempBpOrig;
                        user->second.ownsByte = true;
                    }
                } else if (owner == PersistentOwner::DllTarget) {
                    if (auto dll = dllTargetBps_.find(tempBpAddr);
                        dll != dllTargetBps_.end()) {
                        dll->second.orig = tempBpOrig;
                        dll->second.ownsByte = true;
                    }
                }
            }

            if (released) {
                if (!transitioned) {
                    if (persistentOwner) {
                        abandonmentReason =
                            "the checked RunTo breakpoint was abandoned; its persistent breakpoint owner retained responsibility after the live byte could not be verified";
                    } else if (byteState ==
                               debugger_detail::TempBreakpointByteState::Unmapped) {
                        abandonmentReason =
                            "the checked RunTo breakpoint was abandoned after its continuation mapping disappeared";
                    } else {
                        abandonmentReason =
                            "the checked RunTo breakpoint was abandoned after its INT3 was superseded by another byte";
                    }
                }
                tempBpSet = false;
                tempOwnerTid = 0;
                tempCheckedRunToToken = 0;
                tempSharesAnti = false;
                tempAntiOwnerBase = 0;
                tempKind = TempKind::None;
                {
                    std::lock_guard<std::mutex> lk(mtx_);
                    runtimeTempBpAddr_.reset();
                }
            } else {
                // The byte is still, or may still be, our INT3. Keep every
                // ownership field intact so a later hit/cleanup can reconcile
                // it. Running with forgotten metadata would expose an unowned
                // breakpoint exception to the target.
                breakpointTransitionFailed = true;
                abandonmentReason =
                    "the checked RunTo breakpoint was abandoned, but its INT3 could not be restored; debugger ownership was retained";
                setEvent("temporary breakpoint cleanup failed; debugger ownership retained");
            }
        }
        if (abandonedCheckedRunTo) {
            std::lock_guard<std::mutex> lk(mtx_);
            if (checkedRunTo_.requestToken == abandonedCheckedRunTo &&
                checkedRunTo_.address == tempBpAddr &&
                (checkedRunTo_.state == CheckedRunToState::Pending ||
                 checkedRunTo_.state == CheckedRunToState::Armed))
                cancelCheckedRunToLocked(std::move(abandonmentReason));
        }
        if (tempReArm) {
            if (!rearmOwnedBreakpoint(tempReArm, tempReArmOwner))
                breakpointTransitionFailed = true;
            tempReArm = 0;
            tempReArmOwner = ReArmOwner::User;
        }
        foreignTempStepTid = 0;
        endExclusiveStep();
        return released;
    };
    // Handle a hit on the user software breakpoint at `a`: cancel any step, restore
    // the original byte, back RIP over the int3, then either park on it (condition
    // holds) or silently step+re-arm+run (condition false). Returns true to pause.
    auto handleUserBp = [&](uint64_t a, uint32_t tid) -> bool {
        if (!clearTempBp()) return true;
        steppingOut = false; stepPause = false; stepOutFinishing = false;
        if (!disarmBreakpoint(a)) {
            breakpointTransitionFailed = true;
            setEvent("breakpoint restore failed");
            return true;
        }
        uint64_t authorizationGeneration = 0;
        bool authorizationReturn = false;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            if (auto authorization = authorizationBps_.find(a);
                authorization != authorizationBps_.end()) {
                authorization->second.armed = false;
                authorizationGeneration = authorization->second.generation;
            }
            if (auto completion = authorizationReturnBps_.find(a);
                completion != authorizationReturnBps_.end()) {
                completion->second.armed = false;
                authorizationReturn = true;
            }
        }
        // find(), not operator[]: an unknown tid must not insert a null HANDLE
        // into threads_ (it would linger and get CloseHandle(nullptr)'d at cleanup).
        if (auto th = threads_.find(tid); th != threads_.end()) ctxSetRip(th->second, a);
        // A pre-existing/user breakpoint may have shadowed a planned trace site.
        // Count it without changing any user condition, hit, or stop semantics.
        traceCoverage_.recordBlockHit(traceCoverage_.generation(), a);
        const bool authorizationEntryCurrent = !authorizationGeneration ||
            authorizationEntrySignatureMatches(a, authorizationGeneration);
        if (authorizationGeneration && !authorizationEntryCurrent)
            retireAuthorizationEntryForSignatureMismatch(
                a, authorizationGeneration);
        // Internal observation is side-band metadata. Observe a colliding entry or
        // return, then preserve the analyst breakpoint's normal condition/stop policy.
        NetworkProbeApi networkApi = NetworkProbeApi::Unknown;
        bool networkReturn = false;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            if (auto probe = networkProbeBps_.find(a); probe != networkProbeBps_.end())
                networkApi = probe->second.api;
            networkReturn = networkReturnBps_.count(a) != 0;
        }
        if (networkApi != NetworkProbeApi::Unknown) netTapCapture(a, tid, networkApi);
        if (networkReturn) (void)netTapOnReturn(a, tid);
        bool authorizationReturnPause = false;
        if (authorizationReturn) {
            bool returnTransitionFailed = false;
            (void)authorizationReturnOnHit(a, tid, true,
                                            &returnTransitionFailed,
                                            &authorizationReturnPause);
            if (returnTransitionFailed) {
                breakpointTransitionFailed = true;
                setEvent("authorization return probe restore failed");
                return true;
            }
        }
        AuthorizationWatchHitResult authorizationHit;
        if (authorizationGeneration && authorizationEntryCurrent) {
            authorizationHit = authorizationWatch_.recordEntryHit(
                authorizationGeneration, a, tid, GetTickCount64());
            (void)queueAuthorizationReturn(
                a, tid, std::move(authorizationHit.returnRequests));
        }
        const bool authorizationPause = authorizationReturnPause ||
                                        authorizationHit.pauseRequested;
        bool stop = evalConditionFor(a, tid);
        {   // Hit accounting (under mtx_: snapshot() reads bps_ concurrently). The
            // every-Nth gate composes with the condition: the bp parks only when the
            // condition holds AND this is the Nth raw hit (hits counts every fire).
            std::lock_guard<std::mutex> lk(mtx_);
            if (auto it = bps_.find(a); it != bps_.end()) {
                ++it->second.hits;
                if (stop && it->second.everyN > 1 && (it->second.hits % it->second.everyN) != 0)
                    stop = false;
                if (stop) ++it->second.stops;
            }
        }
        if (stop || authorizationPause) {
            // Park on it; how we step off + re-arm is decided by the next command.
            pausedOnBp = true; pausedOnBpAddr = a;
            { std::lock_guard<std::mutex> lk(mtx_); pausedUserBpAddr_ = a; }
            setEvent(stop ? "breakpoint" : "authorization watch");
            return true;
        }
        // Condition false: single-step the original instruction, re-arm, keep running.
        reArmAddr = a; reArmOwner = ReArmOwner::User; reArmAfter = AfterReArm::FreeRun;
        stepTid = tid;
        beginExclusiveStep(tid);
        setTrapFlag(tid, true);
        return false;
    };
    // One decision tick of a step-out, evaluated against the instruction at the
    // current RIP. Sets the trap flag or a temp breakpoint as needed. Returns true
    // only when the caller should pause immediately (the iteration cap tripped).
    auto stepOutStep = [&](uint32_t tid) -> bool {
        stepTid = tid;
        beginExclusiveStep(tid);
        if (++stepOutIters > kStepOutCap) { steppingOut = false; setEvent("step out (capped)"); return true; }
        uint64_t rip = ripOf(tid);
        StepDecode d = decodeAt(rip);
        switch (DecideStepOut(ClassifyInsn(d.isCall, d.isRet, d.isRepString))) {
            case StepOutAction::StepOverUnit:
                // Skip the call/rep entirely: break at the return point and continue.
                setTempBp(rip + d.length, TempKind::StepOutSkip, tid);
                setTrapFlag(tid, false);
                return false;
            case StepOutAction::FinishAfterRet:
                // Let the ret execute; the following single-step lands in the caller.
                steppingOut = false; stepOutFinishing = true;
                setTrapFlag(tid, true);
                return false;
            case StepOutAction::SingleStep:
            default:
                setTrapFlag(tid, true);
                return false;
        }
    };

    DEBUG_EVENT ev{};
    bool alive = true;
    bool debugEventHeldForCleanup = false;
    DWORD heldContinueStatus = DBG_CONTINUE;
    const bool accountAntiDebugRunTime = activeAntiDebugPolicy_.syntheticClock ||
        activeAntiDebugPolicy_.rdtsc != RdtscInterception::Off;
    LARGE_INTEGER antiDebugRunStarted{};
    bool antiDebugRunActive = false;
    while (alive) {
        if (!WaitForDebugEvent(&ev, 100)) {
            serviceGameMaker(false);
            // Running detach requests an internal debug break first. Wait for
            // that event so cleanup owns a stopped process; if injection failed,
            // the cleanup path explicitly suspends the known threads instead.
            if (quit_ && !traceSyncBreakRequested_.load()) break;
            continue;
        }
        // ContinueDebugEvent resumes the target; WaitForDebugEvent stops it again.
        // Advance the virtual clocks only across that interval, before doing any
        // potentially slow debugger-side event processing or waiting for the user.
        if (antiDebugRunActive) {
            antiDebugRunActive = false;
            LARGE_INTEGER stopped{};
            if (QueryPerformanceCounter(&stopped) &&
                stopped.QuadPart >= antiDebugRunStarted.QuadPart) {
                uint64_t elapsed = static_cast<uint64_t>(
                    stopped.QuadPart - antiDebugRunStarted.QuadPart);
                const uint64_t frequency = antiDebugClock_.qpcFrequency();
                const uint64_t maximum =
                    frequency > UINT64_MAX / kAntiDebugMaxRunIntervalSeconds
                    ? UINT64_MAX : frequency * kAntiDebugMaxRunIntervalSeconds;
                const bool clamped = elapsed > maximum;
                if (clamped) elapsed = maximum;
                antiDebugClock_.advanceRunningQpcTicks(elapsed);
                std::lock_guard<std::mutex> lk(mtx_);
                ++antiDebugStats_.clockRunIntervals;
                if (elapsed > UINT64_MAX - antiDebugStats_.clockRunningQpcTicks)
                    antiDebugStats_.clockRunningQpcTicks = UINT64_MAX;
                else
                    antiDebugStats_.clockRunningQpcTicks += elapsed;
                if (clamped) ++antiDebugStats_.clockRunIntervalsClamped;
            }
        }
        DWORD contStatus = DBG_CONTINUE;
        bool  pause = false;
        bool  gmlEvent = false;
        bool  preserveLoaderPhaseOnPause = false;
        bool  antiTrapTransitionFailed = false;
        bool  antiTrapFatalFailure = false;
        breakpointTransitionFailed = false;
        bool  needResumeFlag = false;   // set when stopped on a fault-class hw execute bp
        uint32_t breakDisplayTid = 0;   // !=0 => a Pause break; show/step this thread, not the helper

        switch (ev.dwDebugEventCode) {
            case CREATE_PROCESS_DEBUG_EVENT:
                {   // Publish the handle and the session it belongs to atomically.
                    // Memory Tools can then validate a captured scan/table owner
                    // without racing a detach followed by PID/handle reuse.
                    std::lock_guard<std::mutex> lk(hProcMtx_);
                    hProcess_ = ev.u.CreateProcessInfo.hProcess;
                    hProcessShared_ = hProcess_;
                    hProcessIdentity_ = { ev.dwProcessId, activeSessionGeneration };
                }
                // A 32-bit (WOW64) target needs the WOW64_CONTEXT register set and an
                // x86 step decoder. Detect it once, before any context access below.
                { BOOL w = FALSE; if (IsWow64Process((HANDLE)hProcess_, &w)) isWow64_.store(w != 0); }
                { std::lock_guard<std::mutex> lk(mtx_); networkCoverage_.wow64 = isWow64_.load(); }
                (void)verifyAntiDebugSyntheticReturns();
                mainTid = ev.dwThreadId;
                threads_[ev.dwThreadId] = ev.u.CreateProcessInfo.hThread;
                { std::lock_guard<std::mutex> lk(mtx_);
                  threadHandles_.push_back({ ev.dwThreadId, ev.u.CreateProcessInfo.hThread });
                  activeTid_ = tid_ = ev.dwThreadId; }
                // Program entry for break-at-entry. lpStartAddress is unreliable for
                // packed/managed images, so prefer the PE AddressOfEntryPoint read from
                // the mapped image (AddressOfEntryPoint sits at e_lfanew+24+16 in both
                // PE32 and PE32+); fall back to lpStartAddress.
                entryAddr = (uint64_t)ev.u.CreateProcessInfo.lpStartAddress;
                {
                    uint64_t imgBase = (uint64_t)ev.u.CreateProcessInfo.lpBaseOfImage;
                    IMAGE_DOS_HEADER dos{}; DWORD sig = 0, aoe = 0;
                    if (imgBase && readMemory(imgBase, &dos, sizeof(dos)) == sizeof(dos) &&
                        dos.e_magic == IMAGE_DOS_SIGNATURE &&
                        readMemory(imgBase + dos.e_lfanew, &sig, 4) == 4 && sig == IMAGE_NT_SIGNATURE &&
                        readMemory(imgBase + dos.e_lfanew + 24 + 16, &aoe, 4) == 4 && aoe)
                        entryAddr = imgBase + aoe;
                }
                {   // Publish the main executable as a real module too. LOAD_DLL
                    // events do not repeat it, and unpack/live-image workflows
                    // must never mistake the first system DLL for the target.
                    DbgModule main;
                    main.base = (uint64_t)(uintptr_t)ev.u.CreateProcessInfo.lpBaseOfImage;
                    main.loadGeneration = ++moduleLoadGeneration;
                    if (ev.u.CreateProcessInfo.hFile) {
                        main.fileIdentity = attachedFileIdentity(
                            ev.u.CreateProcessInfo.hFile);
                        wchar_t wpath[1024]{};
                        DWORD n = GetFinalPathNameByHandleW(ev.u.CreateProcessInfo.hFile, wpath,
                            (DWORD)(sizeof(wpath) / sizeof(wpath[0])), FILE_NAME_NORMALIZED);
                        if (n > 0 && n < sizeof(wpath) / sizeof(wpath[0])) {
                            const wchar_t* p = wpath;
                            if (wcsncmp(p, L"\\\\?\\", 4) == 0) p += 4;
                            char buf[2048]{};
                            if (WideCharToMultiByte(CP_UTF8, 0, p, -1, buf, sizeof(buf), nullptr, nullptr) > 0)
                                main.path = buf;
                        }
                    }
                    if (main.path.empty() && !applicationPath.empty()) {
                        char buf[2048]{};
                        if (WideCharToMultiByte(CP_UTF8, 0, applicationPath.c_str(), -1,
                                               buf, sizeof(buf), nullptr, nullptr) > 0)
                            main.path = buf;
                    }
                    size_t slash = main.path.find_last_of("/\\");
                    main.name = main.path.empty() ? std::string()
                              : (slash == std::string::npos ? main.path : main.path.substr(slash + 1));
                    if (main.name.empty()) {
                        char label[32];
                        std::snprintf(label, sizeof(label), "<main@0x%llX>",
                                      (unsigned long long)main.base);
                        main.name = label;
                    }
                    IMAGE_DOS_HEADER dos{}; DWORD soi = 0;
                    if (main.base && readMemory(main.base, &dos, sizeof(dos)) == sizeof(dos) &&
                        dos.e_magic == IMAGE_DOS_SIGNATURE && dos.e_lfanew > 0 && dos.e_lfanew < 0x100000 &&
                        readMemory(main.base + dos.e_lfanew + 24 + 56, &soi, 4) == 4)
                        main.size = soi;

                    // Launch & Watch retained the exact immutable analysis
                    // bytes and identity before CreateProcess. Validate both
                    // through Windows' CREATE_PROCESS handle while this event
                    // is stopped. No authorization bind or probe is possible
                    // until acceptSourceEvidence publishes this gate.
                    const uint64_t sourceGeneration =
                        authorizationWatch_.generation();
                    if (const auto expectedSource =
                            authorizationWatch_.pendingSourceEvidence(
                                sourceGeneration)) {
                        const HANDLE sourceFile =
                            ev.u.CreateProcessInfo.hFile;
                        const AuthorizationWatchSourceReader readSource =
                            [sourceFile](uint64_t offset, uint8_t* out,
                                         size_t size) {
                                if (!sourceFile ||
                                    sourceFile == INVALID_HANDLE_VALUE ||
                                    !out || !size || size > MAXDWORD ||
                                    offset > static_cast<uint64_t>(
                                        (std::numeric_limits<LONGLONG>::max)()))
                                    return false;
                                LARGE_INTEGER position{};
                                position.QuadPart =
                                    static_cast<LONGLONG>(offset);
                                if (!SetFilePointerEx(sourceFile, position,
                                                      nullptr, FILE_BEGIN))
                                    return false;
                                DWORD got = 0;
                                const DWORD requested =
                                    static_cast<DWORD>(size);
                                return ReadFile(sourceFile, out, requested,
                                                &got, nullptr) &&
                                       got == requested;
                            };
                        const bool exactSource =
                            AuthorizationWatchSourceEvidenceMatches(
                                *expectedSource, main.fileIdentity,
                                readSource);
                        const bool acceptedSource = exactSource &&
                            authorizationWatch_.acceptSourceEvidence(
                                sourceGeneration);
                        if (!acceptedSource &&
                            authorizationWatch_.rejectSourceEvidence(
                                sourceGeneration)) {
                            // startupDone may already have released the UI
                            // waiter. Cancel the queued start explicitly so it
                            // cannot later bind when this event reaches the
                            // common pending-operation drain.
                            // The optional prelaunch Server Watch belongs to
                            // this same source-authorized action. Revoke it
                            // before applyPendingBps reaches its network drain;
                            // no probe/event from the rejected image may be
                            // published under either watch.
                            networkObservationWant_.store(false);
                            // Hold the CREATE_PROCESS event itself. The rejected
                            // image cannot execute TLS callbacks, DllMain, or
                            // its entry point until the user explicitly decides
                            // what to do with this ordinary debugger session.
                            pause = true;
                            preserveLoaderPhaseOnPause = true;
                            std::lock_guard<std::mutex> lk(mtx_);
                            pendingAuthorizationStart_ = false;
                            pendingAuthorizationStop_ = false;
                            networkCoverage_.requested = false;
                            networkEvents_.clear();
                            networkEventSequence_ = 0;
                            lastEvent_ =
                                kAuthorizationWatchSourceRejectionMessage;
                        }
                    }
                    // A freshly created process can report PEB.ProcessHeap == 0
                    // at CREATE_PROCESS. Defer that warning and retry exactly once
                    // at the loader breakpoint, after ntdll initialized the heap.
                    antiDebugHeapRetryPending = !normalizeAntiDebugEnvironment(true);
                    mainImageBase = main.base;
                    mainImageSize = main.size;
                    mainImageName = main.name;
                    mainImagePath = main.path;
                    mainImageLoadGeneration = main.loadGeneration;
                    std::lock_guard<std::mutex> lk(mtx_);
                    if (dbgModules_.size() < kMaxDbgModules) dbgModules_.push_back(std::move(main));
                    // Async Attach completes only when the bitness and main
                    // mapping are ready; otherwise a WOW64 target could open a
                    // transient x64 live view before this first event arrived.
                    initialProcessEventReady_ = true;
                    cmdCv_.notify_all();
                }
                if (ev.u.CreateProcessInfo.hFile) CloseHandle(ev.u.CreateProcessInfo.hFile);
                break;
            case CREATE_THREAD_DEBUG_EVENT:
                threads_[ev.dwThreadId] = ev.u.CreateThread.hThread;
                { std::lock_guard<std::mutex> lk(mtx_);
                  auto known = std::find_if(threadHandles_.begin(), threadHandles_.end(),
                      [&](const auto& value) { return value.first == ev.dwThreadId; });
                  if (known == threadHandles_.end())
                      threadHandles_.push_back({ ev.dwThreadId, ev.u.CreateThread.hThread }); }
                if (!applyHwToThread(ev.u.CreateThread.hThread))
                    setEvent("hardware breakpoint inheritance failed");
                if (!quit_ && exclusiveStepOwner && ev.dwThreadId != exclusiveStepOwner &&
                    SuspendThread(ev.u.CreateThread.hThread) != static_cast<DWORD>(-1))
                    exclusiveStepSuspended.insert(ev.dwThreadId);
                break;
            case EXIT_THREAD_DEBUG_EVENT: {
                exclusiveStepSuspended.erase(ev.dwThreadId);
                if (exclusiveStepOwner == ev.dwThreadId) {
                    exclusiveStepOwner = 0;
                    endExclusiveStep();
                }
                if (stepTid == ev.dwThreadId && reArmAddr &&
                    reArmOwner != ReArmOwner::User) {
                    const bool rearmed = reArmOwner == ReArmOwner::NetworkProbe
                                       ? rearmNetworkProbe(reArmAddr)
                                       : reArmOwner == ReArmOwner::NetworkReturn
                                       ? rearmNetworkReturn(reArmAddr)
                                       : reArmOwner == ReArmOwner::Authorization
                                       ? rearmAuthorizationBreakpoint(reArmAddr)
                                       : rearmAuthorizationReturn(reArmAddr);
                    if (!rearmed) breakpointTransitionFailed = true;
                    reArmAddr = 0;
                    reArmAfter = AfterReArm::FreeRun;
                    reArmOwner = ReArmOwner::User;
                    stepTid = 0;
                }
                uint64_t retiredThreadPayload = 0;
                const std::vector<uint64_t> retiredThreadReturns =
                    networkPendingReturns_.eraseThread(ev.dwThreadId,
                        [&](const NetworkPendingFrame& frame) {
                            retiredThreadPayload += frame.payload.size();
                        });
                if (retiredThreadPayload) {
                    std::lock_guard<std::mutex> lk(mtx_);
                    networkPendingPayloadBytes_ -= (std::min<uint64_t>)(
                        networkPendingPayloadBytes_, retiredThreadPayload);
                }
                for (uint64_t returnAddress : retiredThreadReturns) {
                    NetworkReturnBp site;
                    bool found = false;
                    {
                        std::lock_guard<std::mutex> lk(mtx_);
                        if (auto it = networkReturnBps_.find(returnAddress);
                            it != networkReturnBps_.end()) {
                            site = it->second;
                            networkReturnBps_.erase(it);
                            found = true;
                        }
                        auto at = std::lower_bound(networkReturnBpAddrs_.begin(),
                                                   networkReturnBpAddrs_.end(), returnAddress);
                        if (at != networkReturnBpAddrs_.end() && *at == returnAddress)
                            networkReturnBpAddrs_.erase(at);
                    }
                    if (found && site.ownsByte && site.armed)
                        (void)replaceByteIfEqual((HANDLE)hProcess_, returnAddress, 0xCC, site.orig);
                }
                size_t retiredAuthorizationAttempts = 0;
                const std::vector<uint64_t> retiredAuthorizationReturns =
                    authorizationPendingReturns_.eraseThread(
                        ev.dwThreadId, &retiredAuthorizationAttempts);
                {
                    std::lock_guard<std::mutex> lk(mtx_);
                    authorizationPendingReturnCount_ =
                        authorizationPendingReturns_.total();
                    if (UINT64_MAX - authorizationPendingReturnsDropped_ <
                        retiredAuthorizationAttempts)
                        authorizationPendingReturnsDropped_ = UINT64_MAX;
                    else
                        authorizationPendingReturnsDropped_ +=
                            retiredAuthorizationAttempts;
                }
                for (uint64_t returnAddress : retiredAuthorizationReturns) {
                    AuthorizationReturnBp site;
                    bool found = false;
                    {
                        std::lock_guard<std::mutex> lk(mtx_);
                        if (auto it = authorizationReturnBps_.find(returnAddress);
                            it != authorizationReturnBps_.end()) {
                            site = it->second;
                            authorizationReturnBps_.erase(it);
                            found = true;
                        }
                        auto at = std::lower_bound(
                            authorizationReturnBpAddrs_.begin(),
                            authorizationReturnBpAddrs_.end(), returnAddress);
                        if (at != authorizationReturnBpAddrs_.end() &&
                            *at == returnAddress)
                            authorizationReturnBpAddrs_.erase(at);
                    }
                    if (found && site.ownsByte && site.armed)
                        (void)replaceByteIfEqual(
                            (HANDLE)hProcess_, returnAddress, 0xCC, site.orig);
                }
                if (auto pending = antiRearms.take(ev.dwThreadId)) {
                    // A different thread can terminate a trap-stepping thread
                    // before its #DB. Re-arm its restored hook now or retire it
                    // explicitly; never leave a silently disarmed entry behind.
                    bool retiredForCet = false;
                    if (!antiRearms.hasAddress(pending->address) &&
                        !antiDebugCallHooksAllowed_) {
                        std::lock_guard<std::mutex> lk(mtx_);
                        if (auto trapIt = antiTraps_.find(pending->address);
                            trapIt != antiTraps_.end() &&
                            trapIt->second.kind != AntiTrapKind::Rdtsc &&
                            trapIt->second.kind != AntiTrapKind::Rdtscp) {
                            antiTraps_.erase(trapIt);
                            rebuildAntiTrapAddrs_();
                            retiredForCet = true;
                        }
                    }
                    if (!antiRearms.hasAddress(pending->address) && !retiredForCet &&
                        !writeByteRPM((HANDLE)hProcess_, pending->address, 0xCC)) {
                        {
                            std::lock_guard<std::mutex> lk(mtx_);
                            antiTraps_.erase(pending->address);
                            rebuildAntiTrapAddrs_();
                        }
                        addAntiDebugWarning(
                            "a thread exited before its Hide Debugger hook could be re-armed; hook retired");
                    }
                }
                if (auto it = threads_.find(ev.dwThreadId); it != threads_.end()) {
                    {   // Drop the UI-visible copy under mtx_ BEFORE closing the handle, so a
                        // concurrent setActiveThread() on the UI thread can never resolve a
                        // now-closed (possibly recycled) handle.
                        std::lock_guard<std::mutex> lk(mtx_);
                        for (size_t i = 0; i < threadHandles_.size(); )
                            if (threadHandles_[i].first == ev.dwThreadId) threadHandles_.erase(threadHandles_.begin() + i);
                            else ++i;
                        for (size_t i = 0; i < threadList_.size(); )
                            if (threadList_[i].tid == ev.dwThreadId) threadList_.erase(threadList_.begin() + i);
                            else ++i;
                        if (activeTid_ == ev.dwThreadId) {
                            activeTid_ = threadHandles_.empty() ? 0 : threadHandles_.front().first;
                            if (tid_ == ev.dwThreadId) tid_ = activeTid_;
                        }
                        suspended_.erase(ev.dwThreadId);   // a frozen thread that exits is no longer frozen
                    }
                    CloseHandle((HANDLE)it->second);   // we own thread handles from the debug API
                    threads_.erase(it);
                }
                break;
            }
            case LOAD_DLL_DEBUG_EVENT: {
                DbgModule m;
                bool modulePathTrusted = false;
                m.base = (uint64_t)(uintptr_t)ev.u.LoadDll.lpBaseOfDll;
                m.loadGeneration = ++moduleLoadGeneration;
                // Resolve the path from the file handle Windows hands us (most
                // reliable); fall back to the debuggee-side lpImageName pointer.
                if (ev.u.LoadDll.hFile) {
                    m.fileIdentity = attachedFileIdentity(ev.u.LoadDll.hFile);
                    wchar_t wpath[1024];
                    DWORD n = GetFinalPathNameByHandleW(ev.u.LoadDll.hFile, wpath,
                                                        (DWORD)(sizeof(wpath) / sizeof(wpath[0])), FILE_NAME_NORMALIZED);
                        if (n > 0 && n < sizeof(wpath) / sizeof(wpath[0])) {
                        const wchar_t* p = wpath;
                        if (wcsncmp(p, L"\\\\?\\", 4) == 0) p += 4;   // strip the NT prefix
                        char buf[2048] = {0};
                            if (WideCharToMultiByte(CP_UTF8, 0, p, -1, buf, sizeof(buf), nullptr, nullptr) > 0)
                                m.path = buf;
                            modulePathTrusted = !m.path.empty();
                        }
                    CloseHandle(ev.u.LoadDll.hFile);
                }
                if (m.path.empty() && ev.u.LoadDll.lpImageName) {
                    // lpImageName points (in DEBUGGEE memory) to a pointer to the name.
                    uint64_t namePtr = 0;
                    const size_t psz = isWow64_.load() ? 4 : 8;
                    if (readMemory((uint64_t)(uintptr_t)ev.u.LoadDll.lpImageName, &namePtr, psz) == psz && namePtr) {
                        if (ev.u.LoadDll.fUnicode) {
                            wchar_t wbuf[512] = {0};
                            readMemory(namePtr, wbuf, sizeof(wbuf) - sizeof(wchar_t));
                            char buf[2048] = {0};
                            if (wbuf[0] && WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, buf, sizeof(buf), nullptr, nullptr) > 0)
                                m.path = buf;
                        } else {
                            char abuf[1024] = {0};
                            readMemory(namePtr, abuf, sizeof(abuf) - 1);
                            m.path = abuf;
                        }
                    }
                }
                {   // File name from the path; a nameless module is labelled by base.
                    size_t s = m.path.find_last_of("/\\");
                    m.name = m.path.empty() ? std::string()
                           : (s == std::string::npos ? m.path : m.path.substr(s + 1));
                    if (m.name.empty()) {
                        char b[32]; std::snprintf(b, sizeof(b), "<0x%llX>", (unsigned long long)m.base);
                        m.name = b;
                    }
                }
                {   // SizeOfImage from the mapped PE header (same slot in PE32/PE32+).
                    IMAGE_DOS_HEADER dos{}; DWORD soi = 0;
                    if (m.base && readMemory(m.base, &dos, sizeof(dos)) == sizeof(dos) &&
                        dos.e_magic == IMAGE_DOS_SIGNATURE &&
                        readMemory(m.base + dos.e_lfanew + 24 + 56, &soi, 4) == 4)
                        m.size = soi;
                }
                // A hosted-DLL launch starts in rundll32/custom-host code. Match the
                // exact requested DLL only when its LOAD_DLL event arrives, then add
                // the ASLR base to every validated target RVA and plant all one-shots
                // before this event is continued.
                if (dllPlan && !dllPlan->retarget.matched) {
                    DllDebugLaunchPlan candidate = *dllPlan;
                    const std::string reportedPath = m.path.empty() ? m.name : m.path;
                    if (RetargetDllDebugLaunchPlan(candidate, reportedPath, m.base)) {
                        *dllPlan = std::move(candidate);
                        { std::lock_guard<std::mutex> lk(mtx_);
                          dllTargetMatched_ = true;
                          dllTargetPath_ = reportedPath;
                          dllTargetBase_ = m.base;
                          dllTargetSize_ = m.size;
                          dllTargetError_.clear(); }

                        size_t armed = 0;
                        for (const auto& target : dllPlan->breakpoints) {
                            if (m.size && target.rva >= m.size) {
                                appendDllTargetError("target RVA is outside the loaded image: " + target.label);
                                continue;
                            }
                            if (armDllTarget(target)) ++armed;
                        }
                        std::string status = "loaded; armed " + std::to_string(armed) +
                                             "/" + std::to_string(dllPlan->breakpoints.size()) +
                                             " target(s)";
                        { std::lock_guard<std::mutex> lk(mtx_); dllTargetLabel_ = std::move(status); }
                    }
                }
                // JVM awareness: capture the VM module's range and (when armed) plant
                // the one-shot JNI_CreateJavaVM breakpoint. jli.dll lights the badge
                // but doesn't bound exceptions (IsJvmVmModuleName excludes it).
                if (IsJvmVmModuleName(m.name)) {
                    jvmBase = m.base;
                    jvmSize = m.size ? m.size : (32ull << 20);   // header unreadable: generous bound
                    { std::lock_guard<std::mutex> lk(mtx_);
                      jvmLoaded_ = true; jvmPath_ = m.path.empty() ? m.name : m.path; }
                    if (breakOnJvmInit_.load()) {
                        RemoteReader rr = [this](uint64_t va, void* out, size_t n) {
                            return readMemory(va, out, n) == n;
                        };
                        if (uint32_t rva = FindExportRVA(rr, m.base, "JNI_CreateJavaVM")) {
                            // Only one temp-bp slot exists; if a step's temp bp is in
                            // flight, defer arming until the slot frees (see the
                            // armDeferredJvmInit ticks after applyPendingBps below).
                            if (!tempBpSet) setTempBp(m.base + rva, TempKind::JvmInit, 0);
                            else            pendingJvmInitVA = m.base + rva;
                        }
                    }
                } else if (IsJvmModuleName(m.name)) {
                    std::lock_guard<std::mutex> lk(mtx_);
                    jvmLoaded_ = true;
                    if (jvmPath_.empty()) jvmPath_ = m.path.empty() ? m.name : m.path;
                }
                armAntiDebugForImage(m.base, m.size, false, m.name, m.path,
                                     modulePathTrusted);
                {   // Publish to the UI-visible list (bounded against load/unload churn).
                    std::lock_guard<std::mutex> lk(mtx_);
                    if (dbgModules_.size() < kMaxDbgModules) dbgModules_.push_back(std::move(m));
                }
                break;
            }
            case UNLOAD_DLL_DEBUG_EVENT: {
                const uint64_t b = (uint64_t)(uintptr_t)ev.u.UnloadDll.lpBaseOfDll;
                uint64_t unloadedSize = 0;
                { std::lock_guard<std::mutex> lk(mtx_);
                  if (auto module = std::find_if(dbgModules_.begin(), dbgModules_.end(),
                          [b](const DbgModule& value) { return value.base == b; });
                      module != dbgModules_.end()) unloadedSize = module->size; }
                if (b && b == jvmBase) { jvmBase = 0; jvmSize = 0; }
                uint64_t targetSize = 0;
                bool targetUnload = false;
                { std::lock_guard<std::mutex> lk(mtx_);
                  targetUnload = dllTargetMatched_ && b == dllTargetBase_;
                  targetSize = dllTargetSize_; }
                if (targetUnload) {
                    bool hadPendingTargets = false;
                    { std::lock_guard<std::mutex> lk(mtx_); hadPendingTargets = !dllTargetBps_.empty(); }
                    removeDllTargets(b, targetSize);
                    if (hadPendingTargets)
                        appendDllTargetError("target DLL unloaded before all requested breakpoints fired");
                }
                if (tempSharesAnti && tempAntiOwnerBase == b) {
                    // The physical int3 belonged to the unloading image. Drop only
                    // our temporary metadata; never touch the disappearing/reusable VA.
                    tempBpSet = false;
                    tempOwnerTid = 0;
                    const uint64_t unloadedCheckedRunToToken =
                        tempCheckedRunToToken;
                    tempCheckedRunToToken = 0;
                    tempSharesAnti = false;
                    tempAntiOwnerBase = 0;
                    tempKind = TempKind::None;
                    {
                        std::lock_guard<std::mutex> lk(mtx_);
                        runtimeTempBpAddr_.reset();
                        if (unloadedCheckedRunToToken &&
                            checkedRunTo_.requestToken ==
                                unloadedCheckedRunToToken &&
                            checkedRunTo_.state == CheckedRunToState::Armed)
                            cancelCheckedRunToLocked(
                                "the module owning the shared checked RunTo trap unloaded");
                    }
                    if (tempReArm) {
                        if (!rearmOwnedBreakpoint(tempReArm, tempReArmOwner))
                            breakpointTransitionFailed = true;
                        tempReArm = 0;
                        tempReArmOwner = ReArmOwner::User;
                    }
                    endExclusiveStep();
                } else if (tempBpSet && tempCheckedRunToToken && b &&
                           unloadedSize && tempBpAddr >= b &&
                           tempBpAddr - b < unloadedSize) {
                    // UNLOAD_DLL has already retired this mapping. Drop the
                    // checked one-shot metadata without writing to a VA that
                    // can now be free or reused, and publish the abandonment.
                    const uint64_t unloadedCheckedRunToToken =
                        tempCheckedRunToToken;
                    tempBpSet = false;
                    tempOwnerTid = 0;
                    tempCheckedRunToToken = 0;
                    tempSharesAnti = false;
                    tempAntiOwnerBase = 0;
                    tempKind = TempKind::None;
                    {
                        std::lock_guard<std::mutex> lk(mtx_);
                        runtimeTempBpAddr_.reset();
                        if (checkedRunTo_.requestToken ==
                                unloadedCheckedRunToToken &&
                            checkedRunTo_.state ==
                                CheckedRunToState::Armed)
                            cancelCheckedRunToLocked(
                                "the module owning the checked RunTo continuation unloaded");
                    }
                    if (tempReArm) {
                        if (!rearmOwnedBreakpoint(tempReArm,
                                                  tempReArmOwner))
                            breakpointTransitionFailed = true;
                        tempReArm = 0;
                        tempReArmOwner = ReArmOwner::User;
                    }
                    endExclusiveStep();
                }
                while (auto pending = antiRearms.takeOwner(b)) {
                    // The mapping is disappearing, so there is nothing to re-arm.
                    // Clear this thread's internal TF to prevent a later stray #DB.
                    if (!setTrapFlag(pending->tid, false))
                        addAntiDebugWarning(
                            "could not clear TF for a pending hook in an unloading image");
                }
                retireAntiDebugImage(b);
                retireNetworkModule(b, unloadedSize);
                std::lock_guard<std::mutex> lk(mtx_);
                for (size_t i = 0; i < dbgModules_.size(); )
                    if (dbgModules_[i].base == b) dbgModules_.erase(dbgModules_.begin() + i);
                    else ++i;
                break;
            }
            case OUTPUT_DEBUG_STRING_EVENT: {
                const OUTPUT_DEBUG_STRING_INFO& od = ev.u.DebugString;
                if (od.lpDebugStringData && od.nDebugStringLength) {
                    std::string text;
                    if (od.fUnicode) {
                        size_t chars = od.nDebugStringLength;        // length in WCHARs
                        if (chars * 2 > kDbgOutputLine) chars = kDbgOutputLine / 2;
                        std::vector<wchar_t> wb(chars + 1, 0);
                        size_t got = readMemory((uint64_t)(uintptr_t)od.lpDebugStringData, wb.data(), chars * 2);
                        int wn = (int)(got / 2);
                        while (wn > 0 && wb[wn - 1] == 0) --wn;
                        if (wn > 0) {
                            int k = WideCharToMultiByte(CP_UTF8, 0, wb.data(), wn, nullptr, 0, nullptr, nullptr);
                            if (k > 0) {
                                text.resize(k);
                                WideCharToMultiByte(CP_UTF8, 0, wb.data(), wn, text.data(), k, nullptr, nullptr);
                            }
                        }
                    } else {
                        size_t len = od.nDebugStringLength;          // length in bytes
                        if (len > kDbgOutputLine) len = kDbgOutputLine;
                        text.resize(len);
                        text.resize(readMemory((uint64_t)(uintptr_t)od.lpDebugStringData, text.data(), len));
                        while (!text.empty() && text.back() == '\0') text.pop_back();
                    }
                    while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) text.pop_back();
                    if (!text.empty()) {
                        std::lock_guard<std::mutex> lk(mtx_);
                        dbgOutput_.push_back(std::move(text));
                        while (dbgOutput_.size() > kDbgOutputCap) dbgOutput_.pop_front();
                    }
                }
                break;
            }
            case EXIT_PROCESS_DEBUG_EVENT:
                if (dllPlan && !dllPlan->retarget.matched)
                    appendDllTargetError("host process exited before the target DLL was loaded");
                else if (dllPlan) {
                    bool pendingTargets = false;
                    { std::lock_guard<std::mutex> lk(mtx_); pendingTargets = !dllTargetBps_.empty(); }
                    if (pendingTargets)
                        appendDllTargetError("host process exited before all requested DLL targets fired");
                }
                {
                    std::lock_guard<std::mutex> lk(mtx_);
                    cancelCheckedRunToLocked(
                        "the process exited before the checked RunTo request fired");
                    state_ = DbgState::Terminated;
                    failedBpInstalls_.clear();
                    lastEvent_ = "process exited";
                }
                alive = false;
                break;

            case EXCEPTION_DEBUG_EVENT: {
                const EXCEPTION_RECORD& er = ev.u.Exception.ExceptionRecord;
                const uint64_t addr = (uint64_t)er.ExceptionAddress;
                if (acceptGameMakerException(er.ExceptionCode,
                        ev.u.Exception.dwFirstChance != 0,ev.dwThreadId,
                        er.NumberParameters,er.ExceptionInformation)) {
                    pause = true; gmlEvent = true; contStatus = DBG_CONTINUE;
                    setEvent("GML instruction breakpoint / step");
                    break;
                }
                // WOW64 reports 32-bit int3/single-step under WX86 status codes.
                const bool isBpExc = er.ExceptionCode == EXCEPTION_BREAKPOINT ||
                                     er.ExceptionCode == kStatusWx86Breakpoint;
                const bool isSsExc = er.ExceptionCode == EXCEPTION_SINGLE_STEP ||
                                     er.ExceptionCode == kStatusWx86SingleStep;

                if (!isBpExc && !isSsExc) {
                    std::lock_guard<std::mutex> lk(mtx_);
                    ++exceptionSequence_;
                    exceptionCode_ = er.ExceptionCode;
                    exceptionAddress_ = addr;
                    exceptionFirstChance_ = ev.u.Exception.dwFirstChance != 0;
                }

                if (isBpExc) {
                    const bool knownAntiTrap = [&]() {
                        std::lock_guard<std::mutex> lk(mtx_);
                        return antiTraps_.count(addr) != 0;
                    }();
                    // LOAD_DLL can arm ntdll hooks before the loader's canonical
                    // DbgBreakPoint. A hooked startup call must be mediated first,
                    // never consumed as the positional initial breakpoint.
                    if (!knownAntiTrap && wantEntryBreak && entryAddr && !tempBpSet) {
                        // Arm a one-shot bp at the program entry and continue, landing the
                        // user on their first instruction. Done independently of the
                        // positional `firstBreakpoint` so a stray early int3 (TLS callback /
                        // static initializer) can't consume the chance to arm it.
                        if (antiDebugHeapRetryPending) {
                            (void)normalizeAntiDebugEnvironment(false);
                            antiDebugHeapRetryPending = false;
                        }
                        firstBreakpoint = false;
                        wantEntryBreak = false;
                        setTempBp(entryAddr, TempKind::EntryPoint, mainTid);
                        if (!mainAntiDebugArmed && mainImageBase) {
                            // Plant the requested entry one-shot first.  The RDTSC
                            // scanner then sees that byte as owned and skips it,
                            // preserving break-at-entry semantics.
                            armAntiDebugForImage(mainImageBase, mainImageSize, true,
                                                 mainImageName, mainImagePath, false);
                            mainAntiDebugArmed = true;
                        }
                        setEvent("launching");
                    } else if (!knownAntiTrap && firstBreakpoint) {
                        firstBreakpoint = false; // initial system breakpoint (loader)
                        if (antiDebugHeapRetryPending) {
                            (void)normalizeAntiDebugEnvironment(false);
                            antiDebugHeapRetryPending = false;
                        }
                        if (!mainAntiDebugArmed && mainImageBase) {
                            armAntiDebugForImage(mainImageBase, mainImageSize, true,
                                                 mainImageName, mainImagePath, false);
                            mainAntiDebugArmed = true;
                        }
                        if (dllPlan) {
                            // Hosted-DLL launches are goal-directed: run through
                            // the host's loader break and stop at DllMain/export.
                            setEvent("waiting for target DLL");
                        } else {
                            const AuthorizationWatchSnapshot authorizationState =
                                authorizationWatch_.snapshot();
                            if (authorizationState.sourceValidationFailed) {
                                // Preserve the asynchronous CREATE_PROCESS
                                // rejection as the user-visible stop reason;
                                // launchAndAttach may already have returned true.
                                pause = true;
                                // This is still a startup loader breakpoint.
                                // A WOW64 target can raise another loader INT3
                                // after the user continues this stop, so keep
                                // the loader swallowing phase intact here too.
                                preserveLoaderPhaseOnPause = true;
                                setEvent(kAuthorizationWatchSourceRejectionMessage);
                            } else if (authorizationState.active) {
                                // Launch & Watch is goal-directed. Its main-image
                                // probes were planted on CREATE_PROCESS, so continue
                                // through the loader break without requiring a manual
                                // Continue before startup/TLS authorization code runs.
                                setEvent("authorization watch running");
                            } else {
                                pause = true;
                                setEvent("initial break");
                            }
                        }
                    } else if (knownAntiTrap) {
                        bool userStop = false;
                        const bool sharedTemp = tempBpSet && tempBpAddr == addr &&
                            (!tempOwnerTid || tempOwnerTid == ev.dwThreadId);
                        const TempKind sharedTempKind = sharedTemp ? tempKind : TempKind::None;
                        const uint64_t sharedCheckedRunToToken =
                            sharedTemp ? tempCheckedRunToToken : 0;
                        if (hasArmedUserBreakpoint(addr)) {
                            userStop = evalConditionFor(addr, ev.dwThreadId);
                            std::lock_guard<std::mutex> lk(mtx_);
                            if (auto user = bps_.find(addr); user != bps_.end()) {
                                ++user->second.hits;
                                if (userStop && user->second.everyN > 1 &&
                                    (user->second.hits % user->second.everyN) != 0)
                                    userStop = false;
                                if (userStop) ++user->second.stops;
                            }
                        }
                        traceCoverage_.recordBlockHit(traceCoverage_.generation(), addr);
                        if (!handleAntiTrap(addr, ev.dwThreadId)) {
                            AntiTrap trap;
                            { std::lock_guard<std::mutex> lk(mtx_); trap = antiTraps_.at(addr); }
                            // The policy intentionally passes this class/call through.
                            // Prepare RIP+TF as one checked context update, then expose
                            // the original byte. If the byte write fails, roll the
                            // context back so the real breakpoint exception can be
                            // delivered without skipping or entering mid-instruction.
                            bool prepared = false;
                            bool rollbackFailed = false;
                            auto th = threads_.find(ev.dwThreadId);
                            Registers originalContext;
                            if (th != threads_.end() &&
                                ctxReadFull(th->second, originalContext)) {
                                Registers passContext = originalContext;
                                passContext.rip = addr;
                                passContext.rflags |= TRAP_FLAG;
                                if (ctxWriteFull(th->second, passContext)) {
                                    if (writeByteRPM((HANDLE)hProcess_, addr, trap.orig)) {
                                        prepared = true;
                                    } else {
                                        rollbackFailed = !ctxWriteFull(th->second, originalContext);
                                    }
                                }
                            }
                            if (prepared) {
                                if (!antiRearms.begin(ev.dwThreadId, addr,
                                                      trap.ownerImageBase)) {
                                    // A thread cannot execute a second instruction
                                    // before its TF #DB. Refuse to overwrite state if
                                    // hostile/corrupt event ordering violates that.
                                    addAntiDebugWarning(
                                        "could not record pending Hide Debugger re-arm (duplicate/capacity failure)");
                                    setEvent("Hide Debugger re-arm state conflict");
                                    if (TerminateProcess((HANDLE)hProcess_,
                                                         ERROR_DEBUGGER_INACTIVE)) {
                                        antiTrapFatalFailure = true;
                                    } else {
                                        antiTrapTransitionFailed = true;
                                        pause = true;
                                        contStatus = DBG_EXCEPTION_NOT_HANDLED;
                                    }
                                }
                            } else if (rollbackFailed) {
                                // Continuing with RIP backed up onto an int3 would
                                // loop forever. This requires two independent context/
                                // memory failures; terminate instead of corrupting flow.
                                addAntiDebugWarning(
                                    "Hide Debugger pass-through rollback failed; target was terminated safely");
                                setEvent("Hide Debugger pass-through rollback failed");
                                if (TerminateProcess((HANDLE)hProcess_, ERROR_DEBUGGER_INACTIVE)) {
                                    antiTrapFatalFailure = true;
                                } else {
                                    addAntiDebugWarning(
                                        "Hide Debugger could not terminate after an unrecoverable rollback failure");
                                    antiTrapTransitionFailed = true;
                                    pause = true;
                                    contStatus = DBG_EXCEPTION_NOT_HANDLED;
                                }
                            } else {
                                addAntiDebugWarning(
                                    "Hide Debugger could not prepare a pass-through call; hook exception was exposed");
                                setEvent("Hide Debugger pass-through failed");
                                antiTrapTransitionFailed = true;
                                pause = true;
                                contStatus = DBG_EXCEPTION_NOT_HANDLED;
                            }
                        } else if (stepPause) {
                            stepPause = false;
                            userStop = true;
                        }
                        if (sharedTemp) {
                            tempBpSet = false;
                            tempOwnerTid = 0;
                            tempCheckedRunToToken = 0;
                            tempSharesAnti = false;
                            tempAntiOwnerBase = 0;
                            tempKind = TempKind::None;
                            { std::lock_guard<std::mutex> lk(mtx_); runtimeTempBpAddr_.reset(); }
                            if (tempReArm) {
                                if (!rearmOwnedBreakpoint(tempReArm, tempReArmOwner))
                                    breakpointTransitionFailed = true;
                                tempReArm = 0;
                                tempReArmOwner = ReArmOwner::User;
                            }
                            if (sharedTempKind == TempKind::StepOutSkip) {
                                userStop = false;
                                if (!antiRearms.find(ev.dwThreadId) &&
                                    stepOutStep(ev.dwThreadId))
                                    userStop = true;
                            } else {
                                userStop = true;
                            }
                        }
                        if (antiTrapFatalFailure || antiTrapTransitionFailed) userStop = false;
                        if (sharedCheckedRunToToken &&
                            sharedTempKind == TempKind::RunTo) {
                            std::lock_guard<std::mutex> lk(mtx_);
                            if (checkedRunTo_.requestToken ==
                                    sharedCheckedRunToToken &&
                                checkedRunTo_.target.pid == pid_ &&
                                checkedRunTo_.target.sessionGeneration ==
                                    sessionGeneration_ &&
                                checkedRunTo_.tid == ev.dwThreadId &&
                                checkedRunTo_.address == addr &&
                                checkedRunTo_.state ==
                                    CheckedRunToState::Armed) {
                                if (antiTrapFatalFailure ||
                                    antiTrapTransitionFailed) {
                                    cancelCheckedRunToLocked(
                                        "Hide Debugger could not complete the shared checked RunTo stop");
                                } else {
                                    transitionCheckedRunToLocked(
                                        CheckedRunToState::Hit, {});
                                }
                            }
                        }
                        if (userStop) {
                            pause = true;
                            setEvent(sharedTempKind == TempKind::RunTo ? "run to cursor (Hide Debugger mediated)"
                                   : sharedTempKind == TempKind::StepOver ? "step over (Hide Debugger mediated)"
                                   : sharedTempKind == TempKind::EntryPoint ? "entry point (Hide Debugger mediated)"
                                   : "breakpoint (Hide Debugger mediated)");
                        }
                        if (!antiTrapTransitionFailed) contStatus = DBG_CONTINUE;
                    } else if (tempBpSet && addr == tempBpAddr && tempOwnerTid &&
                               tempOwnerTid != ev.dwThreadId) {
                        // A process-wide int3 can be reached by a non-owner thread.
                        // Step that thread across the pristine instruction without
                        // consuming the selected thread's run-to/step operation.
                        if (replaceByteIfEqual((HANDLE)hProcess_, tempBpAddr, 0xCC,
                                               tempBpOrig)) {
                            if (auto th = threads_.find(ev.dwThreadId); th != threads_.end())
                                ctxSetRip(th->second, tempBpAddr);
                            foreignTempStepTid = ev.dwThreadId;
                            beginExclusiveStep(ev.dwThreadId);
                            setTrapFlag(ev.dwThreadId, true);
                        } else {
                            if (tempCheckedRunToToken) {
                                std::lock_guard<std::mutex> lk(mtx_);
                                if (checkedRunTo_.requestToken ==
                                        tempCheckedRunToToken &&
                                    checkedRunTo_.state ==
                                        CheckedRunToState::Armed)
                                    cancelCheckedRunToLocked(
                                        "a foreign-thread checked RunTo breakpoint transition failed");
                            }
                            breakpointTransitionFailed = true;
                            pause = true;
                            setEvent("temporary breakpoint ownership transition failed");
                        }
                    } else if (tempBpSet && addr == tempBpAddr) {
                        // A temp breakpoint fired (run-to-cursor, step-over return, or a
                        // call/rep skipped during step-out). Remove it and back RIP onto
                        // the target instruction.
                        if (!restoreDebuggerOwnedByte((HANDLE)hProcess_, tempBpAddr,
                                                      tempBpOrig)) {
                            if (tempCheckedRunToToken) {
                                std::lock_guard<std::mutex> lk(mtx_);
                                if (checkedRunTo_.requestToken ==
                                        tempCheckedRunToToken &&
                                    checkedRunTo_.state ==
                                        CheckedRunToState::Armed)
                                    cancelCheckedRunToLocked(
                                        "the checked RunTo fired but its breakpoint byte could not be restored");
                            }
                            breakpointTransitionFailed = true;
                            pause = true;
                            setEvent("temporary breakpoint restore failed");
                            break;
                        }
                        if (auto th = threads_.find(ev.dwThreadId); th != threads_.end())
                            ctxSetRip(th->second, tempBpAddr);
                        tempBpSet = false;
                        tempOwnerTid = 0;
                        const uint64_t hitCheckedRunToToken =
                            tempCheckedRunToToken;
                        tempCheckedRunToToken = 0;
                        {
                            std::lock_guard<std::mutex> lk(mtx_);
                            runtimeTempBpAddr_.reset();
                        }
                        TempKind tk = tempKind; tempKind = TempKind::None;
                        DllTargetBp dllTarget;
                        const bool dllTargetHit = takeDllTarget(tempBpAddr, dllTarget);
                        // A temp operation may have taken ownership of a planned
                        // trace site (run-to/step-over wins). Reaching it still
                        // contributes coverage without altering temp semantics.
                        traceCoverage_.recordBlockHit(traceCoverage_.generation(), tempBpAddr);
                        // If this temp bp also stood in for a user bp we stepped off of,
                        // re-arm that user bp now (its 0xCC was withheld during the run).
                        if (tempReArm) {
                            const bool rearmed = rearmOwnedBreakpoint(tempReArm, tempReArmOwner);
                            if (!rearmed) breakpointTransitionFailed = true;
                            tempReArm = 0;
                            tempReArmOwner = ReArmOwner::User;
                        }
                        if (hasArmedUserBreakpoint(tempBpAddr)) {
                            // A real user breakpoint also lives at this address: it takes
                            // priority over the step (don't silently skip past it).
                            if (handleUserBp(tempBpAddr, ev.dwThreadId)) pause = true;
                        } else if (tk == TempKind::StepOutSkip) {
                            if (stepOutStep(ev.dwThreadId)) pause = true; // keep stepping out
                        } else {
                            pause = true;
                            setEvent(tk == TempKind::RunTo      ? "run to cursor"
                                   : tk == TempKind::EntryPoint ? "entry point"
                                   : tk == TempKind::JvmInit    ? "JVM init (JNI_CreateJavaVM)"
                                                                : "step over");
                        }
                        // A temp operation and a requested DLL target can share one
                        // physical int3. Preserve the temp/user bookkeeping above,
                        // but the explicit DllMain/export target determines the
                        // user-visible stop and consumes its one-shot metadata.
                        if (dllTargetHit) {
                            publishDllTargetHit(dllTarget);
                            pause = true;
                        }
                        if (hitCheckedRunToToken &&
                            tk == TempKind::RunTo) {
                            std::lock_guard<std::mutex> lk(mtx_);
                            if (checkedRunTo_.requestToken ==
                                    hitCheckedRunToToken &&
                                checkedRunTo_.target.pid == pid_ &&
                                checkedRunTo_.target.sessionGeneration ==
                                    sessionGeneration_ &&
                                checkedRunTo_.tid == ev.dwThreadId &&
                                checkedRunTo_.address == tempBpAddr &&
                                checkedRunTo_.state ==
                                    CheckedRunToState::Armed) {
                                if (pause && !breakpointTransitionFailed) {
                                    transitionCheckedRunToLocked(
                                        CheckedRunToState::Hit, {});
                                } else {
                                    cancelCheckedRunToLocked(
                                        "the checked RunTo fired without retaining its exact pause");
                                }
                            }
                        }
                    } else if (isDllTarget(addr)) {
                        DllTargetBp target;
                        if (takeDllTarget(addr, target)) {
                            if (target.ownsByte &&
                                !restoreDebuggerOwnedByte((HANDLE)hProcess_, addr, target.orig)) {
                                breakpointTransitionFailed = true;
                                pause = true;
                                setEvent("DLL target breakpoint restore failed");
                                break;
                            }
                            if (!clearTempBp()) {
                                pause = true;
                                break;
                            }
                            steppingOut = false; stepPause = false; stepOutFinishing = false;
                            if (auto th = threads_.find(ev.dwThreadId); th != threads_.end())
                                ctxSetRip(th->second, addr);

                            // A user bp added after launch may share this exact byte.
                            // Treat the requested DLL target as an unconditional stop,
                            // while parking through the ordinary user-bp resume path so
                            // its original instruction is stepped and the bp is re-armed.
                            if (auto user = bps_.find(addr);
                                user != bps_.end() && user->second.armed) {
                                if (disarmBreakpoint(addr)) {
                                    pausedOnBp = true;
                                    pausedOnBpAddr = addr;
                                    std::lock_guard<std::mutex> lk(mtx_);
                                    pausedUserBpAddr_ = addr;
                                    ++user->second.hits;
                                    ++user->second.stops;
                                } else {
                                    breakpointTransitionFailed = true;
                                }
                            }
                            traceCoverage_.recordBlockHit(traceCoverage_.generation(), addr);
                            publishDllTargetHit(target);
                            pause = true;
                        }
                    } else if (traceBps_.count(addr)) {
                        // Invisible one-shot coverage bp: restore the pristine byte,
                        // back up RIP, account the hit, and execute it once under TF.
                        // There is deliberately no re-arm.
                        TraceBp trace;
                        if (takeTraceSite(addr, trace)) {
                            if (!restoreDebuggerOwnedByte((HANDLE)hProcess_, addr, trace.orig)) {
                                {
                                    std::lock_guard<std::mutex> lk(mtx_);
                                    traceBps_[addr] = trace;
                                    auto at = std::lower_bound(traceBpAddrs_.begin(),
                                                               traceBpAddrs_.end(), addr);
                                    traceBpAddrs_.insert(at, addr);
                                }
                                breakpointTransitionFailed = true;
                                pause = true;
                                setEvent("trace breakpoint restore failed");
                                break;
                            }
                            if (auto th = threads_.find(ev.dwThreadId); th != threads_.end())
                                ctxSetRip(th->second, addr);
                            traceCoverage_.recordBlockHit(trace.generation, addr);
                            traceStepTid = ev.dwThreadId;
                            traceStepFreeRun = !(reArmAddr || stepPause || steppingOut || stepOutFinishing);
                            setTrapFlag(ev.dwThreadId, true);
                        }
                    } else if (hasArmedUserBreakpoint(addr)) {
                        if (handleUserBp(addr, ev.dwThreadId)) pause = true;
                    } else if ([&] {
                        std::lock_guard<std::mutex> lk(mtx_);
                        auto it = authorizationBps_.find(addr);
                        return it != authorizationBps_.end() && it->second.armed;
                    }()) {
                        uint64_t generation = 0;
                        {
                            std::lock_guard<std::mutex> lk(mtx_);
                            generation = authorizationBps_.at(addr).generation;
                        }
                        if (!disarmAuthorizationBreakpoint(addr)) {
                            breakpointTransitionFailed = true;
                            pause = true;
                            setEvent("authorization probe restore failed");
                        } else {
                            if (auto th = threads_.find(ev.dwThreadId);
                                th != threads_.end())
                                ctxSetRip(th->second, addr);
                            // A trace plan may have skipped this byte because the
                            // repeatable authorization probe already owned it. The
                            // actual execution still counts, without consuming or
                            // replacing any other trace site.
                            traceCoverage_.recordBlockHit(
                                traceCoverage_.generation(), addr);
                            const bool authorizationEntryCurrent =
                                authorizationEntrySignatureMatches(addr, generation);
                            if (!authorizationEntryCurrent)
                                retireAuthorizationEntryForSignatureMismatch(
                                    addr, generation);
                            bool returnTransitionFailed = false;
                            bool completionPause = false;
                            {
                                std::lock_guard<std::mutex> lk(mtx_);
                                if (authorizationReturnBps_.count(addr))
                                    authorizationReturnBps_[addr].armed = false;
                            }
                            const bool hasCompletion = [&] {
                                std::lock_guard<std::mutex> lk(mtx_);
                                return authorizationReturnBps_.count(addr) != 0;
                            }();
                            bool completionNeedsRearm = false;
                            if (hasCompletion)
                                completionNeedsRearm = authorizationReturnOnHit(
                                    addr, ev.dwThreadId, true,
                                    &returnTransitionFailed,
                                    &completionPause);
                            if (returnTransitionFailed) {
                                breakpointTransitionFailed = true;
                                pause = true;
                                setEvent("authorization return probe restore failed");
                                break;
                            }
                            AuthorizationWatchHitResult authorizationHit;
                            if (authorizationEntryCurrent) {
                                authorizationHit = authorizationWatch_.recordEntryHit(
                                    generation, addr, ev.dwThreadId,
                                    GetTickCount64());
                                (void)queueAuthorizationReturn(
                                    addr, ev.dwThreadId,
                                    std::move(authorizationHit.returnRequests));
                            }
                            const bool pauseOnHit = completionPause ||
                                authorizationHit.pauseRequested;
                            if (pauseOnHit) {
                                if (authorizationEntryCurrent ||
                                    completionNeedsRearm) {
                                    pausedOnBp = true;
                                    pausedOnBpAddr = addr;
                                    parkedInternalTransfer = true;
                                    parkedInternalOwner = authorizationEntryCurrent
                                        ? ReArmOwner::Authorization
                                        : ReArmOwner::AuthorizationReturn;
                                }
                                pause = true;
                                setEvent(authorizationEntryCurrent
                                    ? "authorization watch"
                                    : "authorization watch completion");
                            } else if (authorizationEntryCurrent ||
                                       completionNeedsRearm) {
                                reArmAddr = addr;
                                reArmOwner = authorizationEntryCurrent
                                    ? ReArmOwner::Authorization
                                    : ReArmOwner::AuthorizationReturn;
                                reArmAfter = AfterReArm::FreeRun;
                                stepTid = ev.dwThreadId;
                                beginExclusiveStep(ev.dwThreadId);
                                setTrapFlag(ev.dwThreadId, true);
                            } else {
                                // The stale entry was retired and no completion
                                // probe remains. Execute the safely restored
                                // instruction once, with no breakpoint to re-arm.
                                traceStepTid = ev.dwThreadId;
                                traceStepFreeRun = !(reArmAddr || stepPause ||
                                    steppingOut || stepOutFinishing);
                                setTrapFlag(ev.dwThreadId, true);
                            }
                        }
                    } else if ([&] {
                        std::lock_guard<std::mutex> lk(mtx_);
                        auto it = authorizationReturnBps_.find(addr);
                        return it != authorizationReturnBps_.end() &&
                               it->second.armed;
                    }()) {
                        bool returnTransitionFailed = false;
                        bool completionPause = false;
                        const bool needsRearm = authorizationReturnOnHit(
                            addr, ev.dwThreadId, false,
                            &returnTransitionFailed, &completionPause);
                        if (returnTransitionFailed) {
                            breakpointTransitionFailed = true;
                            pause = true;
                            setEvent("authorization return probe restore failed");
                        } else if (completionPause) {
                            if (needsRearm) {
                                pausedOnBp = true;
                                pausedOnBpAddr = addr;
                                parkedInternalTransfer = true;
                                parkedInternalOwner =
                                    ReArmOwner::AuthorizationReturn;
                            }
                            pause = true;
                            setEvent("authorization watch completion");
                        } else if (needsRearm) {
                            reArmAddr = addr;
                            reArmOwner = ReArmOwner::AuthorizationReturn;
                            reArmAfter = AfterReArm::FreeRun;
                            stepTid = ev.dwThreadId;
                            beginExclusiveStep(ev.dwThreadId);
                            setTrapFlag(ev.dwThreadId, true);
                        } else {
                            // The last pending call consumed this one-shot return
                            // site. Execute the restored caller instruction once;
                            // no breakpoint metadata remains to re-arm.
                            traceStepTid = ev.dwThreadId;
                            traceStepFreeRun =
                                !(reArmAddr || stepPause || steppingOut ||
                                  stepOutFinishing);
                            beginExclusiveStep(ev.dwThreadId);
                            setTrapFlag(ev.dwThreadId, true);
                        }
                    } else if ([&] {
                        std::lock_guard<std::mutex> lk(mtx_);
                        auto it = networkProbeBps_.find(addr);
                        return it != networkProbeBps_.end() && it->second.armed;
                    }()) {
                        NetworkProbeApi api = NetworkProbeApi::Unknown;
                        { std::lock_guard<std::mutex> lk(mtx_); api = networkProbeBps_.at(addr).api; }
                        if (!disarmNetworkProbe(addr)) {
                            breakpointTransitionFailed = true;
                            pause = true;
                            setEvent("network probe restore failed");
                        } else {
                            if (auto th = threads_.find(ev.dwThreadId); th != threads_.end())
                                ctxSetRip(th->second, addr);
                            netTapCapture(addr, ev.dwThreadId, api);
                            reArmAddr = addr;
                            reArmOwner = ReArmOwner::NetworkProbe;
                            reArmAfter = AfterReArm::FreeRun;
                            stepTid = ev.dwThreadId;
                            beginExclusiveStep(ev.dwThreadId);
                            setTrapFlag(ev.dwThreadId, true);
                        }
                    } else if ([&] {
                        std::lock_guard<std::mutex> lk(mtx_);
                        auto it = networkReturnBps_.find(addr);
                        return it != networkReturnBps_.end() && it->second.armed;
                    }()) {
                        bool transitionFailed = false;
                        const bool rearm = netTapOnReturn(addr, ev.dwThreadId,
                                                          &transitionFailed);
                        if (transitionFailed) {
                            breakpointTransitionFailed = true;
                            pause = true;
                            setEvent("network return probe restore failed");
                        } else if (rearm) {
                            reArmAddr = addr;
                            reArmOwner = ReArmOwner::NetworkReturn;
                            reArmAfter = AfterReArm::FreeRun;
                            stepTid = ev.dwThreadId;
                            beginExclusiveStep(ev.dwThreadId);
                            setTrapFlag(ev.dwThreadId, true);
                        }
                    } else if (breakRequested_.exchange(false)) {
                        // User pressed Pause: DebugBreakProcess put this int3 in a helper
                        // thread (ntdll!DbgBreakPoint). Consume it and show/step a real user
                        // thread (the main thread) so you stop on the code it's executing.
                        pause = true;
                        breakDisplayTid = (mainTid && threads_.count(mainTid)) ? mainTid : ev.dwThreadId;
                        setEvent("paused");
                    } else if (traceSyncBreakRequested_.exchange(false)) {
                        // Internal wake-up used to apply trace, software/hardware
                        // breakpoint, and network-hook mutations while running.
                        // It never surfaces as a user stop.
                        contStatus = DBG_CONTINUE;
                    } else if (isWow64_.load() && loaderPhase) {
                        // An extra WOW64 loader breakpoint (e.g. wow64 ntdll init) before
                        // the program is running: swallow it so the process isn't killed.
                        contStatus = DBG_CONTINUE;
                    } else {
                        contStatus = DBG_EXCEPTION_NOT_HANDLED;
                    }
                } else if (isSsExc) {
                    // A single-step exception is raised both by the trap flag (DR6.BS)
                    // and by a hardware breakpoint hit (DR6 bits 0-3). Read + clear DR6.
                    uint64_t dr6 = 0;
                    if (!readDr6Clear(ev.dwThreadId, dr6)) {
                        pause = true;
                        setEvent("could not read/clear hardware-breakpoint state");
                    }
                    const bool hwHit = (dr6 & 0xF) != 0;
                    const bool traceFreeStep = !hwHit && traceStepTid == ev.dwThreadId &&
                                               traceStepFreeRun;
                    if (traceStepTid == ev.dwThreadId) {
                        traceStepTid = 0;
                        traceStepFreeRun = false;
                    }

                    // Thread binding: only the owning thread may consume temporary
                    // or user-step state. Peers are suspended during the short
                    // process-wide byte exposure window.
                    // single-step from any other thread is a stray (ContinueDebugEvent resumes the
                    // whole process). Don't let it consume the stepped thread's pending state — clear
                    // that thread's trap flag and continue; the stepped thread's own #DB still arrives
                    // and is handled. Nothing is suspended, so (unlike "freeze other threads") this
                    // can't deadlock a thread blocked on a peer's lock/syscall.
                    if (!hwHit && foreignTempStepTid == ev.dwThreadId) {
                        const bool rearmed = tempBpSet &&
                            replaceByteIfEqual((HANDLE)hProcess_, tempBpAddr,
                                               tempBpOrig, 0xCC);
                        foreignTempStepTid = 0;
                        setTrapFlag(ev.dwThreadId, false);
                        endExclusiveStep();
                        if (!rearmed) {
                            const uint64_t failedCheckedRunToToken =
                                tempCheckedRunToToken;
                            tempBpSet = false;
                            tempOwnerTid = 0;
                            tempCheckedRunToToken = 0;
                            tempKind = TempKind::None;
                            {
                                std::lock_guard<std::mutex> lk(mtx_);
                                runtimeTempBpAddr_.reset();
                                if (failedCheckedRunToToken &&
                                    checkedRunTo_.requestToken ==
                                        failedCheckedRunToToken &&
                                    checkedRunTo_.state ==
                                        CheckedRunToState::Armed)
                                    cancelCheckedRunToLocked(
                                        "the checked RunTo breakpoint could not be re-armed after a foreign-thread hit");
                            }
                            breakpointTransitionFailed = true;
                            pause = true;
                            setEvent("temporary breakpoint re-arm failed");
                        }
                    } else if (traceFreeStep) {
                        setTrapFlag(ev.dwThreadId, false);
                    } else if (antiRearms.find(ev.dwThreadId)) {
                        // Finish the one-instruction pass-through window for an
                        // unselected ntdll information class and close the race as
                        // soon as the CPU gives control back to the debugger.
                        const PendingAntiDebugRearm completed =
                            *antiRearms.take(ev.dwThreadId);
                        const uint64_t completedAntiReArm = completed.address;
                        // Two threads can have queued the same int3 before the
                        // first event restores its byte. The last lease to finish
                        // owns the physical re-arm; earlier #DBs leave it original.
                        const bool addressStillLeased = antiRearms.hasAddress(completedAntiReArm);
                        bool retireForCet = false;
                        if (!addressStillLeased && !antiDebugCallHooksAllowed_) {
                            std::lock_guard<std::mutex> lk(mtx_);
                            if (auto trapIt = antiTraps_.find(completedAntiReArm);
                                trapIt != antiTraps_.end()) {
                                retireForCet = trapIt->second.kind != AntiTrapKind::Rdtsc &&
                                               trapIt->second.kind != AntiTrapKind::Rdtscp;
                                if (retireForCet) {
                                    antiTraps_.erase(trapIt);
                                    rebuildAntiTrapAddrs_();
                                }
                            }
                        }
                        const bool antiHookRearmed = addressStillLeased || retireForCet ||
                            writeByteRPM((HANDLE)hProcess_, completedAntiReArm, 0xCC);
                        if (!antiHookRearmed) {
                            // The original byte is still live, so fail open: retire
                            // this hook and clear TF. Never keep stepping forever or
                            // pretend a missing int3 is armed.
                            {
                                std::lock_guard<std::mutex> lk(mtx_);
                                antiTraps_.erase(completedAntiReArm);
                                rebuildAntiTrapAddrs_();
                            }
                            addAntiDebugWarning(
                                "Hide Debugger could not re-arm a pass-through hook; that hook was retired");
                            const bool trapCleared = setTrapFlag(ev.dwThreadId, false);
                            pause = true;
                            setEvent("Hide Debugger hook re-arm failed");
                            if (!trapCleared) {
                                addAntiDebugWarning(
                                    "Hide Debugger could not clear TF after hook re-arm failure");
                                contStatus = DBG_EXCEPTION_NOT_HANDLED;
                                antiTrapTransitionFailed = true;
                            }
                        } else if (hwHit) {
                            const bool tempCleared = clearTempBp();
                            steppingOut = false; stepPause = false; stepOutFinishing = false;
                            for (int i = 0; i < 4; ++i)
                                if (((dr6 >> i) & 1) && hwSlots_[i].used &&
                                    hwSlots_[i].kind == HwKind::Execute)
                                    needResumeFlag = true;
                            pause = true;
                            if (tempCleared) setEvent("hw breakpoint");
                        } else if (stepPause) {
                            stepPause = false;
                            setTrapFlag(ev.dwThreadId, false);
                            pause = true; setEvent("step");
                        } else if (steppingOut) {
                            if (stepOutStep(ev.dwThreadId)) pause = true;
                        } else {
                            setTrapFlag(ev.dwThreadId, false);
                        }
                    } else if (!hwHit && stepTid && ev.dwThreadId != stepTid &&
                        (reArmAddr || stepPause || steppingOut || stepOutFinishing)) {
                        setTrapFlag(ev.dwThreadId, false);
                    } else if (reArmAddr) {
                        // We just single-stepped the original instruction of a user
                        // breakpoint; re-arm its 0xCC, then realize the pending command
                        // from the new RIP (this is what makes Step Over / Step Out /
                        // Continue work correctly even when issued while parked on a bp).
                        bool breakpointRearmed = false;
                        switch (reArmOwner) {
                            case ReArmOwner::NetworkProbe:
                                breakpointRearmed = rearmNetworkProbe(reArmAddr);
                                break;
                            case ReArmOwner::NetworkReturn:
                                breakpointRearmed = rearmNetworkReturn(reArmAddr);
                                break;
                            case ReArmOwner::Authorization:
                                breakpointRearmed = rearmAuthorizationBreakpoint(reArmAddr);
                                break;
                            case ReArmOwner::AuthorizationReturn:
                                breakpointRearmed = rearmAuthorizationReturn(reArmAddr);
                                break;
                            case ReArmOwner::User:
                            default:
                                breakpointRearmed = rearmUserBreakpoint(reArmAddr);
                                break;
                        }
                        AfterReArm after = reArmAfter;
                        reArmAddr = 0; reArmAfter = AfterReArm::FreeRun;
                        reArmOwner = ReArmOwner::User;
                        if (!breakpointRearmed) {
                            breakpointTransitionFailed = true;
                            setEvent("breakpoint re-arm failed");
                            pause = true;
                        } else if (hwHit) {
                            steppingOut = false; stepOutFinishing = false;
                            for (int i = 0; i < 4; ++i)
                                if (((dr6 >> i) & 1) && hwSlots_[i].used && hwSlots_[i].kind == HwKind::Execute) needResumeFlag = true;
                            pause = true; setEvent("hw breakpoint");
                        } else switch (after) {
                            case AfterReArm::Pause:
                                pause = true; setEvent(reArmLabel);
                                break;
                            case AfterReArm::BeginStepOut:
                                steppingOut = true; stepOutIters = 0; stepOutFinishing = false;
                                stepOutAnchorRsp = rspOf(ev.dwThreadId);
                                if (stepOutStep(ev.dwThreadId)) pause = true;
                                break;
                            case AfterReArm::ContinueStepOut: // only reached via the temp-bp path
                            case AfterReArm::FreeRun:
                            default:
                                setTrapFlag(ev.dwThreadId, false);
                                endExclusiveStep();
                                break;
                        }
                    } else if (hwHit) {
                        const bool tempCleared = clearTempBp(); // abandon any outstanding step-over/step-out temp bp
                        steppingOut = false; stepPause = false; stepOutFinishing = false;
                        for (int i = 0; i < 4; ++i)
                            if (((dr6 >> i) & 1) && hwSlots_[i].used && hwSlots_[i].kind == HwKind::Execute) needResumeFlag = true;
                        pause = true;
                        if (tempCleared) setEvent("hw breakpoint");
                    } else if (stepOutFinishing) {
                        // A ret just executed. Only stop if RSP actually rose above the
                        // step-out anchor (we truly left the frame); a stack-neutral
                        // ret-trick (push/ret) or a deeper recursion level leaves RSP at
                        // or below the anchor, so keep stepping out in that case.
                        stepOutFinishing = false;
                        if (rspOf(ev.dwThreadId) > stepOutAnchorRsp) { pause = true; setEvent("step out"); }
                        else { steppingOut = true; if (stepOutStep(ev.dwThreadId)) pause = true; }
                    } else if (steppingOut) {
                        if (stepOutStep(ev.dwThreadId)) pause = true;
                    } else if (stepPause) {
                        stepPause = false; pause = true; setEvent("step");
                    }
                } else {
                    // A real exception. Always passed back to the app (we never
                    // swallow it), but three policies decide what the USER sees:
                    //   1. JVM-internal faults (HotSpot null checks / safepoint polls
                    //      inside jvm.dll) are counted and passed through silently.
                    //   2. A whitelisted code, or break-on-first-chance, pauses on
                    //      the first chance with a semantic label.
                    //   3. A second-chance exception always pauses before the
                    //      semantics-preserving DBG_EXCEPTION_NOT_HANDLED continue.
                    const uint32_t code = er.ExceptionCode;
                    bool whitelisted = false;
                    { std::lock_guard<std::mutex> lk(mtx_); whitelisted = fcWhitelist_.count(code) != 0; }
                    if (ev.u.Exception.dwFirstChance &&
                        IsJvmInternalException(code, addr, jvmBase, jvmSize) && !whitelisted) {
                        std::lock_guard<std::mutex> lk(mtx_);
                        ++jvmExceptionsPassed_;
                    } else if (ev.u.Exception.dwFirstChance &&
                               (breakOnFirstChance_.load() || whitelisted)) {
                        char lbl[128];
                        std::snprintf(lbl, sizeof(lbl), "first-chance %s at 0x%llX",
                                      ExceptionCodeLabel(code).c_str(), (unsigned long long)addr);
                        setEvent(lbl);
                        pause = true;
                    } else if (!ev.u.Exception.dwFirstChance) {
                        char lbl[128];
                        std::snprintf(lbl, sizeof(lbl), "unhandled %s at 0x%llX",
                                      ExceptionCodeLabel(code).c_str(), (unsigned long long)addr);
                        setEvent(lbl);
                        pause = true;
                    }
                    contStatus = DBG_EXCEPTION_NOT_HANDLED; // real exception -> let app handle
                }
                break;
            }
            default: break;
        }

        // We are stopped at an event here, so it's safe to touch debuggee memory.
        serviceGameMaker(true);
        applyPendingBps();
        applyPendingTrace();
        applyPendingAuthorization();
        servicePendingWrites(controlEpoch);
        // A JNI_CreateJavaVM one-shot that was deferred because the single temp-bp
        // slot was busy: arm it as soon as the slot is free.
        if (pendingJvmInitVA && !tempBpSet) {
            setTempBp(pendingJvmInitVA, TempKind::JvmInit, 0);
            pendingJvmInitVA = 0;
        }

        if (pause && alive) {
            if (!gmlEvent) invalidateGameMakerPause();
            endExclusiveStep();
            // A source-rejection stop is held on CREATE_PROCESS, before even
            // the canonical loader break. Preserve WOW64 startup handling so
            // an explicit Continue still swallows its later loader INT3s.
            if (!preserveLoaderPhaseOnPause) loaderPhase = false;
            // On a Pause break, present a user thread (not the DebugBreak helper).
            uint32_t showTid = breakDisplayTid ? breakDisplayTid : ev.dwThreadId;
            captureContext(showTid);
            refreshThreadList();
            unwindStack(showTid);   // real DbgHelp StackWalk64 of the stopped thread
            { std::lock_guard<std::mutex> lk(mtx_); state_ = DbgState::Paused; tid_ = showTid; activeTid_ = showTid; }

        waitForPausedCommand:
            CommandEnvelope command{};
            bool processExitPending=false;
            for (;;) {
                command = waitForCommand(controlEpoch);
                DWORD observedExit=STILL_ACTIVE;
                // TerminateProcess can publish an exit status while the held
                // debug event keeps the process handle unsignaled. Release that
                // event without any target writes so EXIT_PROCESS can drain.
                if(hProcess_ && GetExitCodeProcess((HANDLE)hProcess_,&observedExit) && observedExit!=STILL_ACTIVE) {
                    processExitPending=true;break;
                }
                if (command.command != Cmd::ServiceWrites) break;
                // Preserve submission order with breakpoint ownership changes,
                // then service the write without releasing the held event.
                applyPendingBps();
                applyPendingTrace();
                applyPendingAuthorization();
                servicePendingWrites(controlEpoch);
                serviceGameMaker(true);
            }
            if(processExitPending) {
                cleanupGameMakerOwned(false);
                {std::lock_guard<std::mutex> lk(mtx_);state_=DbgState::Running;pausedUserBpAddr_.reset();}
                ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,contStatus);
                continue;
            }
            Cmd c = command.command;
            if (c == Cmd::Detach || quit_) {
                abandonAntiRearms(true);
                if (traceSyncBreakRequested_.load()) {
                    // A running detach may have raced an already-pending event.
                    // Let that event go and consume the injected DbgBreakPoint
                    // before detaching; otherwise its helper could execute an
                    // unserviced INT3 immediately after DebugActiveProcessStop.
                    pausedOnBp = false;
                    pausedOnBpAddr = 0;
                    { std::lock_guard<std::mutex> lk(mtx_);
                      pausedUserBpAddr_.reset(); state_ = DbgState::Running; }
                    ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, contStatus);
                    continue;
                }
                debugEventHeldForCleanup = true;
                heldContinueStatus = contStatus;
                break;
            }
            applyPendingBps();
            applyPendingTrace();
            applyPendingAuthorization();
            servicePendingWrites(controlEpoch);
            serviceGameMaker(true);
            if (pendingJvmInitVA && !tempBpSet) {   // deferred JVM-init one-shot (see above)
                setTempBp(pendingJvmInitVA, TempKind::JvmInit, 0);
                pendingJvmInitVA = 0;
            }
            if (gmlEvent) {
                // A GML notification is inside the helper's preserved native
                // context. Never single-step those save/restore instructions.
                const bool explicitGml = c == Cmd::GmlResume;
                const bool nativeContinue = c == Cmd::Continue;
                if ((!explicitGml && !nativeContinue) ||
                    !resumeGameMakerOwned(explicitGml ? GmlControlCommand::None : GmlControlCommand::Continue)) {
                    setEvent("Use GML execution controls at a GML instruction stop");
                    goto waitForPausedCommand;
                }
                { std::lock_guard<std::mutex> lk(mtx_); state_ = DbgState::Running; }
                if (ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,DBG_CONTINUE)) {
                    if (accountAntiDebugRunTime && QueryPerformanceCounter(&antiDebugRunStarted))
                        antiDebugRunActive = true;
                }
                continue;
            }
            // Close the paused->running enqueue race atomically. A request that
            // wins mtx_ first is drained under this event; one that loses sees
            // Running and asks DebugBreakProcess for a fresh event.
            bool serviceBreakpointEdits = false;
            for (;;) {
                if (serviceBreakpointEdits) applyPendingBps();
                servicePendingWrites(controlEpoch);
                std::lock_guard<std::mutex> lk(mtx_);
                const bool pendingForThisEpoch = std::any_of(
                    pendingWrites_.begin(), pendingWrites_.end(),
                    [controlEpoch](const auto& request) {
                        return request->epoch == controlEpoch;
                    });
                serviceBreakpointEdits = !pendingBpAdds_.empty() ||
                    !pendingBpRems_.empty() || !pendingBpConds_.empty() ||
                    !pendingBpEveryN_.empty();
                if (!pendingForThisEpoch && !serviceBreakpointEdits) {
                    state_ = DbgState::Running;
                    break;
                }
            }

            // A failed internal trap transition is surfaced as the original
            // breakpoint exception. Do not layer a user step command on top of
            // a context whose concealment setup did not complete.
            if (antiTrapTransitionFailed) c = Cmd::Continue;
            if (breakpointTransitionFailed) {
                c = Cmd::Continue;
                contStatus = DBG_EXCEPTION_NOT_HANDLED;
            }

            // Step/continue commands act on the displayed thread; ContinueDebugEvent still
            // resumes via the event's own thread (the helper just returns and exits).
            uint32_t tid = command.ownerTid ? command.ownerTid : showTid;
            if (!command.ownerTid) {
                std::lock_guard<std::mutex> lk(mtx_);
                if (activeTid_ && threads_.count(activeTid_)) tid = activeTid_;
            }

            // Run-to-cursor: arm a one-shot temp breakpoint at the target, then resume
            // exactly like Continue (which also steps off / re-arms a bp we are parked
            // on). Skip if the target is the very breakpoint we are sitting on.
            if (c == Cmd::RunTo) {
                const uint64_t target = command.argument;
                const bool armed = target && !tempBpSet &&
                    !(pausedOnBp && target == pausedOnBpAddr) &&
                    setTempBp(target, TempKind::RunTo, tid);
                if (!armed) {
                    char message[192]{};
                    std::snprintf(message, sizeof(message),
                                  "run to cursor failed at 0x%llX: temporary breakpoint "
                                  "could not be armed; target remains paused",
                                  static_cast<unsigned long long>(target));
                    {
                        std::lock_guard<std::mutex> lk(mtx_);
                        if (command.checkedRunToToken &&
                            checkedRunTo_.requestToken ==
                                command.checkedRunToToken &&
                            checkedRunTo_.target.pid == pid_ &&
                            checkedRunTo_.target.sessionGeneration ==
                                sessionGeneration_ &&
                            checkedRunTo_.tid == tid &&
                            checkedRunTo_.address == target &&
                            checkedRunTo_.state ==
                                CheckedRunToState::Pending)
                            transitionCheckedRunToLocked(
                                CheckedRunToState::Failed, message);
                        state_ = DbgState::Paused;
                        tid_ = showTid;
                        activeTid_ = showTid;
                        lastEvent_ = message;
                    }
                    goto waitForPausedCommand;
                }
                if (command.checkedRunToToken) {
                    bool accepted = false;
                    {
                        std::lock_guard<std::mutex> lk(mtx_);
                        accepted = checkedRunTo_.requestToken ==
                                command.checkedRunToToken &&
                            checkedRunTo_.target.pid == pid_ &&
                            checkedRunTo_.target.sessionGeneration ==
                                sessionGeneration_ &&
                            checkedRunTo_.tid == tid &&
                            checkedRunTo_.address == target &&
                            checkedRunTo_.state ==
                                CheckedRunToState::Pending;
                        if (accepted) {
                            tempCheckedRunToToken =
                                command.checkedRunToToken;
                            transitionCheckedRunToLocked(
                                CheckedRunToState::Armed, {});
                        }
                    }
                    if (!accepted) {
                        // A detach/replacement can cancel the checked owner
                        // while the debug thread is planting the byte. Remove
                        // it without resuming an unowned one-shot.
                        const bool tempCleared = clearTempBp();
                        {
                            std::lock_guard<std::mutex> lk(mtx_);
                            state_ = DbgState::Paused;
                            tid_ = showTid;
                            activeTid_ = showTid;
                            if (tempCleared)
                                lastEvent_ =
                                    "checked run to cursor was cancelled while arming; target remains paused";
                        }
                        goto waitForPausedCommand;
                    }
                }
                c = Cmd::Continue;
            }

            if (pausedOnBp) {
                // Parked on a user breakpoint (original byte restored, RIP backed up).
                // Decide how to step off it, re-arm it, and then realize the command.
                uint64_t   A  = pausedOnBpAddr; pausedOnBp = false;
                const ReArmOwner resumeOwner = parkedInternalTransfer
                                               ? parkedInternalOwner
                                               : ReArmOwner::User;
                parkedInternalTransfer = false;
                parkedInternalOwner = ReArmOwner::User;
                { std::lock_guard<std::mutex> lk(mtx_); pausedUserBpAddr_.reset(); }
                StepDecode od = decodeAt(A);
                InsnKind   k  = ClassifyInsn(od.isCall, od.isRet, od.isRepString);
                StepCmd    sc = (c == Cmd::StepInto) ? StepCmd::StepInto
                              : (c == Cmd::StepOver) ? StepCmd::StepOver
                              : (c == Cmd::StepOut)  ? StepCmd::StepOut
                                                     : StepCmd::Continue;
                reArmLabel = (sc == StepCmd::StepInto) ? "step into"
                           : (sc == StepCmd::StepOver) ? "step over"
                           : (sc == StepCmd::StepOut)  ? "step out" : "step";
                OnBpResume plan = DecideOnBpResume(sc, k);
                if (plan.method == ReArmMethod::SingleStep) {
                    reArmAddr = A; reArmOwner = resumeOwner; reArmAfter = plan.after;
                    stepTid = tid;
                    beginExclusiveStep(tid);
                    setTrapFlag(tid, true);   // step the original insn; re-arm + resume on #DB
                } else {
                    // TempBpAfter: a call/rep sits directly on the breakpoint. Run over it
                    // and re-arm the user bp once the temp bp at its return point fires.
                    uint32_t L = od.length ? od.length : 1;
                    if (plan.after == AfterReArm::ContinueStepOut) {
                        steppingOut = true; stepOutIters = 0; stepOutFinishing = false;
                        stepOutAnchorRsp = rspOf(tid);
                        setTempBp(A + L, TempKind::StepOutSkip, tid);
                    } else {
                        setTempBp(A + L, TempKind::StepOver, tid);
                    }
                    if (tempBpSet) {
                        tempReArm = A;            // re-armed when the temp bp at the return point fires
                        tempReArmOwner = resumeOwner;
                        beginExclusiveStep(tid);
                    } else {
                        // The temp bp couldn't be written: don't strand the user bp at A (it was
                        // disarmed when we parked on it). Re-arm it now and fall back to a plain
                        // continue with the breakpoint live, rather than free-running past it.
                        const bool rearmed = rearmOwnedBreakpoint(A, resumeOwner);
                        if (!rearmed) breakpointTransitionFailed = true;
                        steppingOut = false; stepOutFinishing = false;
                    }
                    setTrapFlag(tid, false);
                }
            } else {
                switch (c) {
                    case Cmd::StepInto:
                        stepTid = tid; beginExclusiveStep(tid);
                        setTrapFlag(tid, true); stepPause = true; break;
                    case Cmd::StepOver: {
                        StepDecode d = decodeAt(ripOf(tid));
                        if (DecideStepOver(ClassifyInsn(d.isCall, d.isRet, d.isRepString))
                                == StepOverAction::StepOverUnit) {
                            setTempBp(ripOf(tid) + d.length, TempKind::StepOver, tid); // over the call/rep
                            if (tempBpSet) beginExclusiveStep(tid);
                            setTrapFlag(tid, false); // run to the return point, don't single-step
                        } else { stepTid = tid; beginExclusiveStep(tid);
                                 setTrapFlag(tid, true); stepPause = true; }
                        break;
                    }
                    case Cmd::StepOut:
                        steppingOut = true; stepOutIters = 0; stepOutFinishing = false;
                        stepOutAnchorRsp = rspOf(tid);
                        // The first tick cannot trip the iteration cap, so its pause hint
                        // (too late to act on here anyway) is intentionally not checked.
                        stepOutStep(tid);   // inspect the current instruction and act
                        break;
                    case Cmd::Continue:
                    default:
                        setTrapFlag(tid, false); break;
                }
            }

            // We were parked on a fault-class hardware execute breakpoint: RIP is
            // still on the trapping instruction and the DR slot is still armed, so
            // any forward resume would immediately re-trap. Set RF so this one
            // instruction runs; the CPU clears RF afterward, keeping the bp live.
            if (needResumeFlag) setResumeFlag(tid);
            // Continuing from a user breakpoint that shares an ntdll pass-through
            // hook must retain TF until the hook's first original instruction has
            // executed and the internal int3 is re-armed.
            if (antiRearms.find(tid)) setTrapFlag(tid, true);
        }

        if (quit_ && alive) {
            if (!traceSyncBreakRequested_.load()) {
                debugEventHeldForCleanup = true;
                heldContinueStatus = contStatus;
                break;
            }
        }
        if (ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, contStatus) &&
            alive && accountAntiDebugRunTime &&
            QueryPerformanceCounter(&antiDebugRunStarted)) {
            antiDebugRunActive = true;
        }
    }

    // Cleanup: restore all breakpoint bytes, clear DR registers, stop debugging.
    {
        std::lock_guard<std::mutex> lk(mtx_);
        cancelPendingWritesLocked();
        cancelCheckedRunToLocked(
            "the debugger session ended before the checked RunTo request fired");
        failedBpInstalls_.clear();
        activeWrite_.reset();
    }
    {   // Drop the UI-visible handle FIRST: a pause() (DebugBreakProcess) landing after
        // DebugActiveProcessStop would inject an int3 into a process that no longer has
        // a debugger and kill it. Nulling under hProcMtx_ makes the UI see "gone" before
        // we stop debugging; the restores below use hProcess_ directly so they still work.
        std::lock_guard<std::mutex> lk(hProcMtx_);
        hProcessShared_ = nullptr;
        hProcessIdentity_ = {};
    }
    breakRequested_ = false;   // a pause that raced the teardown must not leak into a reattach
    traceSyncBreakRequested_ = false;

    // The normal detach path holds a debug event. If injection failed, explicitly
    // suspend every thread we can still identify before touching code bytes or DR
    // registers. Track only counts acquired here so user/exclusive counts unwind
    // independently below.
    std::unordered_set<uint32_t> cleanupSuspended;
    if (alive && !debugEventHeldForCleanup) {
        for (const auto& [tid, handle] : threads_) {
            if (!handle || exclusiveStepSuspended.count(tid)) continue;
            if (SuspendThread((HANDLE)handle) != static_cast<DWORD>(-1))
                cleanupSuspended.insert(tid);
        }
    }
    cleanupGameMakerOwned(alive);
    {   // Remote detour allocations are target mutations too. Release them only
        // after the process is stopped/suspended, never from detach()'s UI thread.
        // Successful register-text buffers are different: the live target may
        // have copied their pointers anywhere, so detaching transfers their
        // lifetime to the target instead of manufacturing dangling pointers.
        // A terminated process has already reclaimed every mapping itself.
        std::lock_guard<std::mutex> lk(hProcMtx_);
        if (hProcess_ && alive)
            for (uint64_t address : remoteAllocs_)
                if (!remoteRegisterBuffers_.count(address))
                    VirtualFreeEx((HANDLE)hProcess_, (LPVOID)address, 0, MEM_RELEASE);
        remoteAllocs_.clear();
        remoteRegisterBuffers_.clear();
    }
    traceCoverage_.stop();
    removeAllTraceBps();
    authorizationWatch_.stop();
    removeAllAuthorizationBps();
    removeDllTargets(/*all=*/0, 0);
    for (auto& kv : bps_)
        if (kv.second.ownsByte)
            breakpointCleanupComplete =
                restoreDebuggerOwnedByte((HANDLE)hProcess_, kv.first, kv.second.orig) &&
                breakpointCleanupComplete;
    if (tempBpSet)
        breakpointCleanupComplete =
            restoreDebuggerOwnedByte((HANDLE)hProcess_, tempBpAddr, tempBpOrig) &&
            breakpointCleanupComplete;
    // Network entry/return probes are internal and absent from bps_. Restore only
    // physical bytes they still own; user-colliding sites were restored above.
    for (const auto& [addr, probe] : networkProbeBps_)
        if (probe.ownsByte)
            breakpointCleanupComplete =
                restoreDebuggerOwnedByte((HANDLE)hProcess_, addr, probe.orig) &&
                breakpointCleanupComplete;
    for (const auto& [addr, site] : networkReturnBps_)
        if (site.ownsByte)
            breakpointCleanupComplete =
                restoreDebuggerOwnedByte((HANDLE)hProcess_, addr, site.orig) &&
                breakpointCleanupComplete;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        networkProbeBps_.clear(); networkProbeBpAddrs_.clear();
        networkReturnBps_.clear(); networkReturnBpAddrs_.clear();
        networkCoverage_.active = false;
        networkCoverage_.requested = false;
        networkPendingPayloadBytes_ = 0;
    }
    networkPendingReturns_.clear();
    networkHandleLineage_.clear();
    networkObservationWant_.store(false);
    netTapArmed_ = false;
    abandonAntiRearms(false);
    restoreAntiDebugState(alive);             // hooks + PEB/heap pristine values
    for (auto& s : hwSlots_) s = HwSlot{};
    const bool hardwareCleanupComplete = applyHwAllThreads(); // walks threads_; close later
    {   // Thaw any user-frozen threads so the process isn't left with suspended
        // threads after we detach (SuspendThread's count persists past detach).
        std::vector<uint32_t> toResume;
        { std::lock_guard<std::mutex> lk(mtx_); toResume.assign(suspended_.begin(), suspended_.end()); suspended_.clear(); }
        for (uint32_t tid : toResume) { auto it = threads_.find(tid); if (it != threads_.end()) ResumeThread((HANDLE)it->second); }
    }
    endExclusiveStep();
    for (uint32_t tid : cleanupSuspended) {
        if (auto it = threads_.find(tid); it != threads_.end())
            ResumeThread((HANDLE)it->second);
    }
    cleanupSuspended.clear();
    if (debugEventHeldForCleanup)
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, heldContinueStatus);
    {   // Stop publishing borrowed debug-event handles before closing them. UI
        // operations hold mtx_ while using a raw handle; the running sampler owns
        // DuplicateHandle copies, so clearing here closes the last lifetime race.
        std::lock_guard<std::mutex> lk(mtx_);
        threadHandles_.clear();
        threadList_.clear();
        activeTid_ = 0;
        pausedUserBpAddr_.reset();
        runtimeTempBpAddr_.reset();
    }
    for (auto& kv : threads_) CloseHandle((HANDLE)kv.second);
    threads_.clear();

    // A contained unpack target must receive its termination request while the
    // debugger still controls it. Detaching first would briefly let hostile code
    // run outside debugger control before kill-on-close took effect.
    if (sandboxJob) {
        TerminateJobObject(sandboxJob, 1);
        CloseHandle(sandboxJob); // kill-on-close is the in-job termination backstop
        sandboxJob = nullptr;
    }
    {   // The unwind session is keyed to hProcess_ and must be torn down before
        // that handle is closed. It never owns symbol-server access.
        std::lock_guard<std::recursive_mutex> dhlk(DbgHelpMutex());
        if (dbgHelpSessionInited_ && hProcess_) SymCleanup((HANDLE)hProcess_);
        dbgHelpSessionInited_ = false;
    }
    DebugActiveProcessStop(pid);
    {   // Close the process handle under hProcMtx_ so a UI-thread pause/readMemory/
        // writeMemory/regions can't be mid-call on a handle we are about to close.
        std::lock_guard<std::mutex> lk(hProcMtx_);
        if (hProcess_) { CloseHandle((HANDLE)hProcess_); hProcess_ = nullptr; }
        hProcessShared_ = nullptr;
        hProcessIdentity_ = {};
    }
    { std::lock_guard<std::mutex> lk(mtx_);
      if (state_ != DbgState::Terminated) state_ = DbgState::Detached;
      if (alive && (!hardwareCleanupComplete || !breakpointCleanupComplete))
          lastEvent_ = !hardwareCleanupComplete && !breakpointCleanupComplete
              ? "detached with incomplete breakpoint-byte and hardware-register cleanup"
              : (!hardwareCleanupComplete
                    ? "detached with incomplete hardware-breakpoint cleanup"
                    : "detached with incomplete breakpoint-byte cleanup"); }
}

} // namespace ds
