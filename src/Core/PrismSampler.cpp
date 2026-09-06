#include "PrismSampler.h"
#include "DbgHelpLock.h"

#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <evntrace.h>
#include <evntcons.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <exception>
#include <limits>
#include <utility>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "advapi32.lib")

namespace ds {

namespace {

constexpr size_t kMaxFrames = 64;
constexpr UCHAR kKernelSampleProfileOpcode = 46;
constexpr UCHAR kKernelContextSwitchOpcode = 36;
constexpr UCHAR kKernelReadyThreadOpcode = 50;

const GUID kPerfInfoGuid =
    { 0xce1dbfb4, 0x137e, 0x4da6, { 0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc } };
const GUID kSystemTraceControlGuid =
    { 0x9e814aad, 0x3204, 0x11d2, { 0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39 } };
const GUID kImageLoadGuid =
    { 0x2cb15d1d, 0x5fc1, 0x11d2, { 0xab, 0xe1, 0x00, 0xa0, 0xc9, 0x11, 0xf5, 0x18 } };
const GUID kThreadGuid =
    { 0x3d6fa8d1, 0xfe05, 0x11d0, { 0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c } };
const GUID kDiskIoGuid =
    { 0x3d6fa8d4, 0xfe05, 0x11d0, { 0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c } };
const GUID kFileIoGuid =
    { 0x90cbdc39, 0x4a3e, 0x11d1, { 0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3 } };
const GUID kTcpIpGuid =
    { 0x9a280ac0, 0xc8e0, 0x11d1, { 0x84, 0xe2, 0x00, 0xc0, 0x4f, 0xb9, 0x98, 0xa2 } };
const GUID kUdpIpGuid =
    { 0xbf3a50c5, 0xa9c9, 0x4988, { 0xa0, 0x05, 0x2d, 0xf0, 0xb7, 0xc8, 0x0f, 0x80 } };

bool sameGuid(const GUID& a, const GUID& b) {
    return std::memcmp(&a, &b, sizeof(GUID)) == 0;
}

std::string win32Message(const char* prefix, ULONG code) {
    char text[192];
    std::snprintf(text, sizeof(text), "%s (Win32 error %lu)", prefix,
                  static_cast<unsigned long>(code));
    return text;
}

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

// Caller holds DbgHelpMutex. True means a function name (not merely a module/raw
// address) resolved, which feeds the collection-quality percentage.
bool symbolize(HANDLE process, uint64_t pc, std::string& out) {
    std::string module, function;
    IMAGEHLP_MODULE64 mi{};
    mi.SizeOfStruct = sizeof(mi);
    if (SymGetModuleInfo64(process, pc, &mi) && mi.ModuleName[0]) module = mi.ModuleName;

    ULONG64 storage[(sizeof(SYMBOL_INFO) + 512 + sizeof(ULONG64) - 1) / sizeof(ULONG64)]{};
    SYMBOL_INFO* symbol = reinterpret_cast<SYMBOL_INFO*>(storage);
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol->MaxNameLen = 511;
    DWORD64 displacement = 0;
    if (SymFromAddr(process, pc, &displacement, symbol) && symbol->NameLen)
        function.assign(symbol->Name, std::min<ULONG>(symbol->NameLen, symbol->MaxNameLen));

    char address[24];
    std::snprintf(address, sizeof(address), "0x%llX", static_cast<unsigned long long>(pc));
    if (!module.empty() && !function.empty()) out = module + "!" + function;
    else if (!module.empty()) out = module + "!" + address;
    else if (!function.empty()) out = function;
    else out = address;
    return !function.empty();
}

struct TracePropertiesBlock {
    EVENT_TRACE_PROPERTIES properties{};
    wchar_t loggerName[128]{};
};

void initializeTraceProperties(TracePropertiesBlock& block, const wchar_t* name) {
    block = {};
    block.properties.Wnode.BufferSize = sizeof(block);
    block.properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    block.properties.Wnode.ClientContext = 1;
    block.properties.Wnode.Guid = kSystemTraceControlGuid;
    block.properties.BufferSize = 64;
    block.properties.MinimumBuffers = 2;
    block.properties.MaximumBuffers = 16;
    block.properties.FlushTimer = 1;
    block.properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    block.properties.EnableFlags =
        EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_THREAD | EVENT_TRACE_FLAG_IMAGE_LOAD |
        EVENT_TRACE_FLAG_PROFILE | EVENT_TRACE_FLAG_CSWITCH | EVENT_TRACE_FLAG_DISK_IO |
        EVENT_TRACE_FLAG_DISK_FILE_IO | EVENT_TRACE_FLAG_FILE_IO | EVENT_TRACE_FLAG_FILE_IO_INIT |
        EVENT_TRACE_FLAG_NETWORK_TCPIP;
    block.properties.LoggerNameOffset = offsetof(TracePropertiesBlock, loggerName);
    if (name) wcsncpy_s(block.loggerName, name, _TRUNCATE);
}

uint32_t readU32(const void* data, size_t size, size_t offset) {
    uint32_t value = 0;
    if (data && offset <= size && size - offset >= sizeof(value))
        std::memcpy(&value, static_cast<const uint8_t*>(data) + offset, sizeof(value));
    return value;
}

} // namespace

const char* PrismStartModeName(PrismStartMode mode) {
    switch (mode) {
        case PrismStartMode::EtwOnly:          return "ETW only";
        case PrismStartMode::SuspendWalkOnly: return "Suspend-and-walk only";
        default:                              return "Automatic (ETW preferred)";
    }
}

PrismSampler::PrismSampler() {
    report_ = std::make_shared<PrismReport>(BuildPrismReport({}));
    // The constructor body runs after every member is initialized, so the report
    // worker cannot race unconstructed mutex/report state.
    reportThread_ = std::thread([this] { reportThreadEntry(); });
}

PrismSampler::~PrismSampler() {
    stop();
    reportStop_.store(true, std::memory_order_release);
    reportCv_.notify_all();
    if (reportThread_.joinable()) reportThread_.join();
}

bool PrismSampler::start(uint32_t pid, PrismStartMode mode, std::string& err) {
    if (running_.load(std::memory_order_acquire)) {
        err = "a Prism collector is already running";
        return false;
    }
    if (thread_.joinable()) stop();
    if (!pid) {
        err = "process ID must be non-zero";
        return false;
    }
    if (pid == GetCurrentProcessId()) {
        err = "profiling DisasmStudio itself is disabled (fallback suspension could deadlock the UI)";
        return false;
    }

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE,
                                 FALSE, pid);
    if (!process) {
        err = win32Message("OpenProcess failed (elevation or process access policy)", GetLastError());
        return false;
    }
    BOOL wow64 = FALSE;
    if (!IsWow64Process(process, &wow64)) {
        const DWORD code = GetLastError();
        CloseHandle(process);
        err = win32Message("could not determine target architecture", code);
        return false;
    }
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) {
        const DWORD code = GetLastError();
        CloseHandle(process);
        err = win32Message("could not read target process identity", code);
        return false;
    }
    const uint64_t creationTime =
        (uint64_t{ created.dwHighDateTime } << 32) | created.dwLowDateTime;
    if (!creationTime) {
        CloseHandle(process);
        err = "target process returned an invalid creation-time identity";
        return false;
    }

    std::deque<PrismSample> previous;
    std::shared_ptr<const PrismReport> previousReport;
    const uint32_t previousPid = pid_;
    const uint64_t previousCreationTime = creationTime100ns_.load(
        std::memory_order_acquire);
    {
        std::lock_guard<std::mutex> lock(mtx_);
        previous.swap(samples_);
        previousReport = report_;
        error_.clear();
        quality_ = {};
        quality_.collector = mode == PrismStartMode::SuspendWalkOnly
                           ? PrismCollectorKind::SuspendWalk : PrismCollectorKind::Etw;
        quality_.wow64Target = wow64 != FALSE;
        report_ = std::make_shared<PrismReport>(BuildPrismReport({}, quality_));
    }

    pid_ = pid;
    creationTime100ns_.store(creationTime, std::memory_order_release);
    hProc_ = process;
    startMode_ = mode;
    wow64_.store(wow64 != FALSE, std::memory_order_release);
    collector_.store(mode == PrismStartMode::SuspendWalkOnly
                         ? PrismCollectorKind::SuspendWalk : PrismCollectorKind::Etw,
                     std::memory_order_release);
    stop_.store(false, std::memory_order_release);
    running_.store(true, std::memory_order_release);
    generation_.fetch_add(1, std::memory_order_acq_rel);
    reportCv_.notify_all();
    lastCycles_.clear();
    targetThreads_.clear();

    try {
        thread_ = std::thread([this] { collectorThreadEntry(); });
    } catch (const std::exception& ex) {
        running_.store(false, std::memory_order_release);
        CloseHandle(process);
        hProc_ = nullptr;
        pid_ = previousPid;
        creationTime100ns_.store(previousCreationTime, std::memory_order_release);
        {
            std::lock_guard<std::mutex> lock(mtx_);
            samples_.swap(previous);
            report_ = std::move(previousReport);
        }
        generation_.fetch_add(1, std::memory_order_acq_rel);
        reportCv_.notify_all();
        err = std::string("failed to start Prism worker: ") + ex.what();
        return false;
    } catch (...) {
        running_.store(false, std::memory_order_release);
        CloseHandle(process);
        hProc_ = nullptr;
        pid_ = previousPid;
        creationTime100ns_.store(previousCreationTime, std::memory_order_release);
        {
            std::lock_guard<std::mutex> lock(mtx_);
            samples_.swap(previous);
            report_ = std::move(previousReport);
        }
        generation_.fetch_add(1, std::memory_order_acq_rel);
        reportCv_.notify_all();
        err = "failed to start Prism worker due to an unknown thread-creation failure";
        return false;
    }
    return true;
}

void PrismSampler::requestStop() {
    stop_.store(true, std::memory_order_release);
    // The ETW watcher polls this edge and stops the owned session. Keeping the OS
    // control call off the UI thread makes this cancellation request non-blocking.
    reportCv_.notify_all();
}

void PrismSampler::stop() {
    requestStop();
    if (thread_.joinable()) thread_.join();
    if (hProc_) {
        CloseHandle(static_cast<HANDLE>(hProc_));
        hProc_ = nullptr;
    }
    running_.store(false, std::memory_order_release);
}

std::vector<PrismSample> PrismSampler::snapshot() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return { samples_.begin(), samples_.end() };
}

size_t PrismSampler::sampleCount() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return samples_.size();
}

PrismCollectionQuality PrismSampler::quality() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return FinalizePrismQuality(quality_);
}

std::shared_ptr<const PrismReport> PrismSampler::report() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return report_;
}

void PrismSampler::clearSamples() {
    {
        std::lock_guard<std::mutex> lock(mtx_);
        samples_.clear();
        PrismCollectionQuality fresh;
        fresh.collector = quality_.collector;
        fresh.wow64Target = quality_.wow64Target;
        fresh.stackTracingConfigured = quality_.stackTracingConfigured;
        fresh.fallbackReason = quality_.fallbackReason;
        fresh.warning = quality_.warning;
        quality_ = std::move(fresh);
        report_ = std::make_shared<PrismReport>(BuildPrismReport({}, quality_));
    }
    generation_.fetch_add(1, std::memory_order_acq_rel);
    reportCv_.notify_all();
}

std::string PrismSampler::lastError() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return error_;
}

void PrismSampler::publishError(std::string error) {
    std::lock_guard<std::mutex> lock(mtx_);
    error_ = std::move(error);
}

void PrismSampler::publishFatalError(const char* message) noexcept {
    try {
        std::lock_guard<std::mutex> lock(mtx_);
        error_ = message ? message : "Prism worker failed safely.";
    } catch (...) {
        // The error string is advisory; retaining process integrity and cleanup
        // takes precedence when memory is exhausted.
    }
}

void PrismSampler::cleanupFailedCollector(const char* message) noexcept {
    publishFatalError(message);
    stop_.store(true, std::memory_order_release);

    const TRACEHANDLE session = static_cast<TRACEHANDLE>(
        etwSession_.exchange(0, std::memory_order_acq_rel));
    if (session) {
        TracePropertiesBlock properties{};
        initializeTraceProperties(properties, nullptr);
        ControlTraceW(session, nullptr, &properties.properties, EVENT_TRACE_CONTROL_STOP);
    }

    HANDLE process = static_cast<HANDLE>(hProc_);
    if (process) {
        try {
            std::lock_guard<std::recursive_mutex> lock(DbgHelpMutex());
            SymCleanup(process);
        } catch (...) {
        }
        CloseHandle(process);
        hProc_ = nullptr;
    }
    running_.store(false, std::memory_order_release);
    generation_.fetch_add(1, std::memory_order_acq_rel);
    reportCv_.notify_all();
}

void PrismSampler::collectorThreadEntry() noexcept {
    try {
        run();
    } catch (const std::exception&) {
        cleanupFailedCollector("Prism collection stopped safely after an unexpected worker exception.");
    } catch (...) {
        cleanupFailedCollector("Prism collection stopped safely after an unknown worker exception.");
    }
}

void PrismSampler::reportThreadEntry() noexcept {
    try {
        reportLoop();
    } catch (const std::exception&) {
        publishFatalError("Prism report aggregation stopped safely after an unexpected worker exception.");
    } catch (...) {
        publishFatalError("Prism report aggregation stopped safely after an unknown worker exception.");
    }
}

void PrismSampler::setQuality(const PrismCollectionQuality& quality) {
    {
        std::lock_guard<std::mutex> lock(mtx_);
        quality_ = quality;
    }
    generation_.fetch_add(1, std::memory_order_acq_rel);
    reportCv_.notify_all();
}

void PrismSampler::appendSample(PrismSample&& sample, uint32_t resolvedFrames) {
    const uint32_t frameCount = static_cast<uint32_t>(
        std::min<size_t>(sample.frames.size(), (std::numeric_limits<uint32_t>::max)()));
    {
        std::lock_guard<std::mutex> lock(mtx_);
        AccumulatePrismTraceEvent(quality_, PrismTraceEventKind::SampledProfile,
                                  frameCount, resolvedFrames);
        if (samples_.size() >= kMaxSamples) samples_.pop_front();
        samples_.push_back(std::move(sample));
    }
    generation_.fetch_add(1, std::memory_order_acq_rel);
    reportCv_.notify_one();
}

void PrismSampler::reportLoop() {
    uint64_t built = (std::numeric_limits<uint64_t>::max)();
    while (!reportStop_.load(std::memory_order_acquire)) {
        {
            std::unique_lock<std::mutex> lock(mtx_);
            // Bound refresh work even when profile events arrive continuously.
            // Cancellation still wakes immediately; normal publication is capped
            // at roughly three reports per second.
            reportCv_.wait_for(lock, std::chrono::milliseconds(350), [&] {
                return reportStop_.load(std::memory_order_acquire);
            });
        }
        if (reportStop_.load(std::memory_order_acquire)) break;
        const uint64_t generation = generation_.load(std::memory_order_acquire);
        if (generation == built) continue;
        try {
            std::vector<PrismSample> samples;
            PrismCollectionQuality quality;
            {
                std::lock_guard<std::mutex> lock(mtx_);
                samples.assign(samples_.begin(), samples_.end());
                quality = quality_;
            }
            PrismReport next = BuildPrismReport(samples, std::move(quality));
            // Do not briefly republish a pre-clear/pre-restart window. A newer
            // generation will be picked up by the next bounded refresh.
            if (generation == generation_.load(std::memory_order_acquire)) {
                std::lock_guard<std::mutex> lock(mtx_);
                report_ = std::make_shared<PrismReport>(std::move(next));
            }
            reportGeneration_.store(generation, std::memory_order_release);
        } catch (...) {
            // Retain the last immutable report and retry only after fresh input,
            // avoiding both process termination and a tight allocation loop.
            publishFatalError("Prism could not aggregate the latest sample window; the previous report was retained.");
        }
        built = generation;
    }
}

void PrismSampler::run() {
    HANDLE process = static_cast<HANDLE>(hProc_);
    bool symbolsReady = false;
    DWORD symbolError = ERROR_SUCCESS;
    {
        std::lock_guard<std::recursive_mutex> lock(DbgHelpMutex());
        SymSetOptions(SymGetOptions() | SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME);
        // Prism is local-only unless the app's opt-in symbol service explicitly
        // supplies a policy in a future integration. Never inherit a process-wide
        // _NT_SYMBOL_PATH that could silently trigger network access here.
        symbolsReady = SymInitialize(process, ".", TRUE) != FALSE;
        if (!symbolsReady) symbolError = GetLastError();
    }
    if (!symbolsReady) {
        publishError(win32Message("DbgHelp symbol initialization failed", symbolError));
        CloseHandle(process);
        hProc_ = nullptr;
        running_.store(false, std::memory_order_release);
        return;
    }

    HANDLE threadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (threadSnapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 entry{};
        entry.dwSize = sizeof(entry);
        if (Thread32First(threadSnapshot, &entry)) {
            do {
                if (entry.th32OwnerProcessID == pid_) targetThreads_.insert(entry.th32ThreadID);
            } while (Thread32Next(threadSnapshot, &entry));
        }
        CloseHandle(threadSnapshot);
    }

    std::string etwFailure;
    bool usedEtw = false;
    if (startMode_ != PrismStartMode::SuspendWalkOnly && !stop_.load(std::memory_order_acquire)) {
        collector_.store(PrismCollectorKind::Etw, std::memory_order_release);
        PrismCollectionQuality initial;
        initial.collector = PrismCollectorKind::Etw;
        initial.wow64Target = wow64_.load(std::memory_order_acquire);
        setQuality(initial);
        usedEtw = runEtw(process, etwFailure);
    }

    if (!stop_.load(std::memory_order_acquire) && !usedEtw &&
        WaitForSingleObject(process, 0) != WAIT_OBJECT_0) {
        if (startMode_ == PrismStartMode::EtwOnly) {
            publishError(etwFailure.empty() ? "ETW collection ended without target samples" : etwFailure);
        } else {
            collector_.store(PrismCollectorKind::SuspendWalk, std::memory_order_release);
            PrismCollectionQuality fallback;
            fallback.collector = PrismCollectorKind::SuspendWalk;
            fallback.wow64Target = wow64_.load(std::memory_order_acquire);
            fallback.stackTracingConfigured = true;
            fallback.fallbackReason = etwFailure;
            if (!etwFailure.empty())
                fallback.warning = "ETW was unavailable; measurements use intrusive thread suspension.";
            setQuality(fallback);
            runSuspendWalk(process);
        }
    }

    {
        std::lock_guard<std::recursive_mutex> lock(DbgHelpMutex());
        SymCleanup(process);
    }
    CloseHandle(process);
    hProc_ = nullptr;
    generation_.fetch_add(1, std::memory_order_acq_rel);
    reportCv_.notify_all();
    running_.store(false, std::memory_order_release);
}

bool PrismSampler::runEtw(void* processValue, std::string& reason) {
    HANDLE process = static_cast<HANDLE>(processValue);
    wchar_t sessionName[128];
    std::swprintf(sessionName, std::size(sessionName), L"DisasmStudio-Prism-%lu-%lu-%llu",
                  static_cast<unsigned long>(GetCurrentProcessId()),
                  static_cast<unsigned long>(pid_),
                  static_cast<unsigned long long>(GetTickCount64()));

    TracePropertiesBlock properties{};
    initializeTraceProperties(properties, sessionName);
    TRACEHANDLE session = 0;
    ULONG status = StartTraceW(&session, sessionName, &properties.properties);
    if (status != ERROR_SUCCESS) {
        reason = win32Message("ETW kernel session could not start (administrator/profile privilege may be required)", status);
        return false;
    }
    etwSession_.store(static_cast<uint64_t>(session), std::memory_order_release);

    CLASSIC_EVENT_ID stackEvent{};
    stackEvent.EventGuid = kPerfInfoGuid;
    stackEvent.Type = kKernelSampleProfileOpcode;
    status = TraceSetInformation(session, TraceStackTracingInfo,
                                 &stackEvent, sizeof(stackEvent));
    {
        std::lock_guard<std::mutex> lock(mtx_);
        quality_.collector = PrismCollectorKind::Etw;
        quality_.wow64Target = wow64_.load(std::memory_order_acquire);
        quality_.stackTracingConfigured = status == ERROR_SUCCESS;
        if (status != ERROR_SUCCESS)
            quality_.warning = win32Message("ETW stack capture was unavailable; leaf samples are still valid", status);
    }

    EVENT_TRACE_LOGFILEW log{};
    log.LoggerName = sessionName;
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.Context = this;
    log.EventRecordCallback = reinterpret_cast<PEVENT_RECORD_CALLBACK>(&PrismSampler::etwEventThunk);
    log.BufferCallback = reinterpret_cast<PEVENT_TRACE_BUFFER_CALLBACKW>(&PrismSampler::etwBufferThunk);

    TRACEHANDLE trace = OpenTraceW(&log);
    if (trace == INVALID_PROCESSTRACE_HANDLE) {
        const ULONG code = GetLastError();
        TracePropertiesBlock stopProperties{};
        initializeTraceProperties(stopProperties, nullptr);
        ControlTraceW(session, nullptr, &stopProperties.properties, EVENT_TRACE_CONTROL_STOP);
        etwSession_.store(0, std::memory_order_release);
        reason = win32Message("ETW real-time consumer could not open", code);
        return false;
    }

    std::atomic<bool> watcherDone{ false };
    std::thread watcher;
    try {
        watcher = std::thread([&]() noexcept {
            while (!watcherDone.load(std::memory_order_acquire) &&
                   !stop_.load(std::memory_order_acquire)) {
                if (WaitForSingleObject(process, 100) == WAIT_OBJECT_0) break;
            }
            if (!watcherDone.load(std::memory_order_acquire)) {
                TracePropertiesBlock stopProperties{};
                initializeTraceProperties(stopProperties, nullptr);
                ControlTraceW(session, nullptr, &stopProperties.properties, EVENT_TRACE_CONTROL_STOP);
            }
        });
    } catch (const std::exception& error) {
        CloseTrace(trace);
        TracePropertiesBlock stopProperties{};
        initializeTraceProperties(stopProperties, nullptr);
        ControlTraceW(session, nullptr, &stopProperties.properties, EVENT_TRACE_CONTROL_STOP);
        etwSession_.store(0, std::memory_order_release);
        reason = std::string("ETW cancellation watcher could not start: ") + error.what();
        return false;
    } catch (...) {
        CloseTrace(trace);
        TracePropertiesBlock stopProperties{};
        initializeTraceProperties(stopProperties, nullptr);
        ControlTraceW(session, nullptr, &stopProperties.properties, EVENT_TRACE_CONTROL_STOP);
        etwSession_.store(0, std::memory_order_release);
        reason = "ETW cancellation watcher could not start due to an unknown thread-creation failure";
        return false;
    }

    const ULONG processStatus = ProcessTrace(&trace, 1, nullptr, nullptr);
    watcherDone.store(true, std::memory_order_release);
    if (watcher.joinable()) watcher.join();
    CloseTrace(trace);

    TracePropertiesBlock stopProperties{};
    initializeTraceProperties(stopProperties, nullptr);
    ControlTraceW(session, nullptr, &stopProperties.properties, EVENT_TRACE_CONTROL_STOP);
    etwSession_.store(0, std::memory_order_release);

    {
        std::lock_guard<std::mutex> lock(mtx_);
        quality_.lostEvents = std::max<uint64_t>(quality_.lostEvents, log.EventsLost);
        quality_.lostBuffers = std::max<uint64_t>(quality_.lostBuffers, log.LogfileHeader.BuffersLost);
    }
    generation_.fetch_add(1, std::memory_order_acq_rel);
    reportCv_.notify_all();

    const bool cancelled = stop_.load(std::memory_order_acquire);
    const uint64_t sampled = quality().sampledEvents;
    if (!cancelled && processStatus != ERROR_SUCCESS && processStatus != ERROR_CANCELLED) {
        reason = win32Message("ETW processing failed", processStatus);
        return sampled != 0;
    }
    if (!cancelled && sampled == 0) {
        reason = "ETW session produced no sampled-profile events for the target";
        return false;
    }
    return true;
}

void __stdcall PrismSampler::etwEventThunk(void* record) {
    auto* event = static_cast<EVENT_RECORD*>(record);
    if (!event || !event->UserContext) return;
    auto* sampler = static_cast<PrismSampler*>(event->UserContext);
    try {
        sampler->onEtwEvent(event);
    } catch (...) {
        // Never unwind a C++ exception through the ETW C callback ABI.
        sampler->publishFatalError("Prism stopped ETW collection after a callback exception.");
        sampler->stop_.store(true, std::memory_order_release);
    }
}

unsigned long __stdcall PrismSampler::etwBufferThunk(void* logfile) {
    auto* log = static_cast<EVENT_TRACE_LOGFILEW*>(logfile);
    if (!log || !log->Context) return TRUE;
    auto* sampler = static_cast<PrismSampler*>(log->Context);
    try {
        return sampler->onEtwBuffer(log);
    } catch (...) {
        sampler->publishFatalError("Prism stopped ETW collection after a buffer-callback exception.");
        sampler->stop_.store(true, std::memory_order_release);
        return FALSE;
    }
}

unsigned long PrismSampler::onEtwBuffer(void* logfileValue) {
    auto* log = static_cast<EVENT_TRACE_LOGFILEW*>(logfileValue);
    {
        std::lock_guard<std::mutex> lock(mtx_);
        quality_.lostEvents = std::max<uint64_t>(quality_.lostEvents, log->EventsLost);
        quality_.lostBuffers = std::max<uint64_t>(quality_.lostBuffers, log->LogfileHeader.BuffersLost);
    }
    return stop_.load(std::memory_order_acquire) ? FALSE : TRUE;
}

void PrismSampler::onEtwEvent(void* recordValue) {
    auto* event = static_cast<EVENT_RECORD*>(recordValue);
    if (stop_.load(std::memory_order_acquire)) return;

    const GUID& provider = event->EventHeader.ProviderId;
    const uint8_t opcode = event->EventHeader.EventDescriptor.Opcode;
    uint32_t processId = event->EventHeader.ProcessId;
    uint32_t threadId = event->EventHeader.ThreadId;

    if (sameGuid(provider, kThreadGuid) && event->UserDataLength >= 8) {
        const uint32_t payloadPid = readU32(event->UserData, event->UserDataLength, 0);
        const uint32_t payloadTid = readU32(event->UserData, event->UserDataLength, 4);
        if (!processId || processId == static_cast<uint32_t>(-1)) processId = payloadPid;
        if (!threadId || threadId == static_cast<uint32_t>(-1)) threadId = payloadTid;
        if (processId == pid_) {
            if (opcode == EVENT_TRACE_TYPE_START || opcode == EVENT_TRACE_TYPE_DC_START)
                targetThreads_.insert(threadId);
            else if (opcode == EVENT_TRACE_TYPE_END || opcode == EVENT_TRACE_TYPE_DC_END)
                targetThreads_.erase(threadId);
        }
    }

    const bool targetHeader = processId == pid_ || targetThreads_.count(threadId) != 0;
    if (sameGuid(provider, kPerfInfoGuid) && opcode == kKernelSampleProfileOpcode) {
        const size_t pointerBytes = (event->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER)
                                  ? sizeof(uint32_t) : sizeof(uint64_t);
        const uint32_t payloadThread = readU32(event->UserData, event->UserDataLength,
                                               pointerBytes);
        if ((!threadId || threadId == static_cast<uint32_t>(-1)) && payloadThread)
            threadId = payloadThread;
        if (processId != pid_ && targetThreads_.count(threadId) == 0) return;
        PrismSample sample;
        sample.threadId = threadId;
        sample.cpuCycles = 1;
        // Real-time callbacks use a monotonic app clock for timeline buckets. The
        // ETW header is QPC-based here and must not be divided as FILETIME ticks.
        sample.timeMs = GetTickCount64();

        uint64_t leaf = 0;
        if ((event->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) != 0) {
            leaf = readU32(event->UserData, event->UserDataLength, 0);
        } else if (event->UserDataLength >= sizeof(uint64_t)) {
            std::memcpy(&leaf, event->UserData, sizeof(leaf));
        }

        std::array<uint64_t, kMaxFrames> addresses{};
        size_t count = 0;
        if (leaf) addresses[count++] = leaf;
        for (USHORT i = 0; i < event->ExtendedDataCount && count < addresses.size(); ++i) {
            const EVENT_HEADER_EXTENDED_DATA_ITEM& item = event->ExtendedData[i];
            if (item.ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE64 &&
                item.DataSize >= offsetof(EVENT_EXTENDED_ITEM_STACK_TRACE64, Address)) {
                const auto* stack = reinterpret_cast<const EVENT_EXTENDED_ITEM_STACK_TRACE64*>(
                    static_cast<uintptr_t>(item.DataPtr));
                const size_t n = (item.DataSize - offsetof(EVENT_EXTENDED_ITEM_STACK_TRACE64, Address)) /
                                 sizeof(stack->Address[0]);
                for (size_t j = 0; j < n && count < addresses.size(); ++j) {
                    const uint64_t pc = stack->Address[j];
                    if (pc && (!count || addresses[count - 1] != pc)) addresses[count++] = pc;
                }
            } else if (item.ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE32 &&
                       item.DataSize >= offsetof(EVENT_EXTENDED_ITEM_STACK_TRACE32, Address)) {
                const auto* stack = reinterpret_cast<const EVENT_EXTENDED_ITEM_STACK_TRACE32*>(
                    static_cast<uintptr_t>(item.DataPtr));
                const size_t n = (item.DataSize - offsetof(EVENT_EXTENDED_ITEM_STACK_TRACE32, Address)) /
                                 sizeof(stack->Address[0]);
                for (size_t j = 0; j < n && count < addresses.size(); ++j) {
                    const uint64_t pc = stack->Address[j];
                    if (pc && (!count || addresses[count - 1] != pc)) addresses[count++] = pc;
                }
            }
        }
        if (!count) return;

        uint32_t resolved = 0;
        sample.frames.reserve(count);
        {
            std::lock_guard<std::recursive_mutex> lock(DbgHelpMutex());
            for (size_t i = 0; i < count; ++i) {
                PrismFrame frame;
                frame.address = addresses[i];
                if (symbolize(static_cast<HANDLE>(hProc_), addresses[i], frame.symbol)) ++resolved;
                sample.frames.push_back(std::move(frame));
            }
        }
        appendSample(std::move(sample), resolved);
        return;
    }

    if (sameGuid(provider, kThreadGuid) && opcode == kKernelContextSwitchOpcode &&
        event->UserDataLength >= 15) {
        const uint32_t newThread = readU32(event->UserData, event->UserDataLength, 0);
        const uint32_t oldThread = readU32(event->UserData, event->UserDataLength, 4);
        const bool relevant = targetThreads_.count(newThread) || targetThreads_.count(oldThread);
        if (relevant) {
            std::lock_guard<std::mutex> lock(mtx_);
            AccumulatePrismTraceEvent(quality_, PrismTraceEventKind::ContextSwitch);
            const uint8_t oldState = static_cast<const uint8_t*>(event->UserData)[14];
            if (targetThreads_.count(oldThread) && oldState == 5)
                AccumulatePrismTraceEvent(quality_, PrismTraceEventKind::Wait);
        }
        return;
    }

    if (!targetHeader) return;
    std::lock_guard<std::mutex> lock(mtx_);
    if (sameGuid(provider, kImageLoadGuid)) {
        AccumulatePrismTraceEvent(quality_, PrismTraceEventKind::Image);
    } else if (sameGuid(provider, kThreadGuid)) {
        AccumulatePrismTraceEvent(quality_, PrismTraceEventKind::Thread);
        if (opcode == kKernelReadyThreadOpcode)
            AccumulatePrismTraceEvent(quality_, PrismTraceEventKind::Wait);
    } else if (sameGuid(provider, kDiskIoGuid) || sameGuid(provider, kFileIoGuid) ||
               sameGuid(provider, kTcpIpGuid) || sameGuid(provider, kUdpIpGuid)) {
        AccumulatePrismTraceEvent(quality_, PrismTraceEventKind::IO);
    }
}

void PrismSampler::runSuspendWalk(void* processValue) {
    HANDLE process = static_cast<HANDLE>(processValue);
    uint64_t nextModuleRefresh = 0;
    while (!stop_.load(std::memory_order_acquire)) {
        if (WaitForSingleObject(process, 0) == WAIT_OBJECT_0) break;
        const uint64_t now = GetTickCount64();
        if (now >= nextModuleRefresh) {
            std::lock_guard<std::recursive_mutex> lock(DbgHelpMutex());
            SymRefreshModuleList(process);
            nextModuleRefresh = now + 1000;
        }
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot != INVALID_HANDLE_VALUE) {
            THREADENTRY32 entry{};
            entry.dwSize = sizeof(entry);
            if (Thread32First(snapshot, &entry)) {
                do {
                    if (entry.th32OwnerProcessID == pid_) {
                        targetThreads_.insert(entry.th32ThreadID);
                        {
                            std::lock_guard<std::mutex> lock(mtx_);
                            AccumulatePrismTraceEvent(quality_, PrismTraceEventKind::Thread);
                        }
                        sampleThread(process, entry.th32ThreadID);
                    }
                } while (!stop_.load(std::memory_order_acquire) && Thread32Next(snapshot, &entry));
            }
            CloseHandle(snapshot);
        }
        Sleep(1);
    }
}

bool PrismSampler::sampleThread(void* processValue, uint32_t threadId) {
    HANDLE process = static_cast<HANDLE>(processValue);
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME,
                               FALSE, threadId);
    if (!thread) return false;
    SuspendedThread held{ thread, false };

    PrismSample sample;
    sample.threadId = threadId;
    sample.timeMs = GetTickCount64();
    ULONG64 cycles = 0;
    if (QueryThreadCycleTime(thread, &cycles)) {
        auto [it, inserted] = lastCycles_.emplace(threadId, static_cast<uint64_t>(cycles));
        if (!inserted) {
            if (static_cast<uint64_t>(cycles) >= it->second)
                sample.cpuCycles = static_cast<uint64_t>(cycles) - it->second;
            it->second = static_cast<uint64_t>(cycles);
        }
    }

    std::array<uint64_t, kMaxFrames> addresses{};
    size_t count = 0;
    {
        std::lock_guard<std::recursive_mutex> lock(DbgHelpMutex());
        if (SuspendThread(thread) == static_cast<DWORD>(-1)) return false;
        held.suspended = true;

        STACKFRAME64 stack{};
        DWORD machine = IMAGE_FILE_MACHINE_AMD64;
        bool haveContext = false;
        CONTEXT nativeContext{};
#if defined(_WIN64)
        WOW64_CONTEXT wowContext{};
        if (wow64_.load(std::memory_order_acquire)) {
            wowContext.ContextFlags = WOW64_CONTEXT_FULL;
            haveContext = Wow64GetThreadContext(thread, &wowContext) != FALSE;
            if (haveContext) {
                machine = IMAGE_FILE_MACHINE_I386;
                stack.AddrPC.Offset = wowContext.Eip;
                stack.AddrFrame.Offset = wowContext.Ebp;
                stack.AddrStack.Offset = wowContext.Esp;
            }
        } else
#endif
        {
            nativeContext.ContextFlags = CONTEXT_FULL;
            haveContext = GetThreadContext(thread, &nativeContext) != FALSE;
#if defined(_M_X64) || defined(__x86_64__)
            if (haveContext) {
                stack.AddrPC.Offset = nativeContext.Rip;
                stack.AddrFrame.Offset = nativeContext.Rbp;
                stack.AddrStack.Offset = nativeContext.Rsp;
            }
#else
            machine = IMAGE_FILE_MACHINE_I386;
            if (haveContext) {
                stack.AddrPC.Offset = nativeContext.Eip;
                stack.AddrFrame.Offset = nativeContext.Ebp;
                stack.AddrStack.Offset = nativeContext.Esp;
            }
#endif
        }
        stack.AddrPC.Mode = AddrModeFlat;
        stack.AddrFrame.Mode = AddrModeFlat;
        stack.AddrStack.Mode = AddrModeFlat;

        if (haveContext && stack.AddrPC.Offset) {
            addresses[count++] = stack.AddrPC.Offset;
            void* context = &nativeContext;
#if defined(_WIN64)
            if (wow64_.load(std::memory_order_acquire)) context = &wowContext;
#endif
            for (size_t n = 0; n + 1 < addresses.size(); ++n) {
                if (!StackWalk64(machine, process, thread, &stack, context, nullptr,
                                 SymFunctionTableAccess64, SymGetModuleBase64, nullptr))
                    break;
                const uint64_t pc = stack.AddrPC.Offset;
                if (!pc) break;
                if (pc != addresses[count - 1]) addresses[count++] = pc;
                if (count >= addresses.size()) break;
                if (n > 0 && stack.AddrReturn.Offset == stack.AddrPC.Offset &&
                    !stack.AddrFrame.Offset) break;
            }
        }

        held.resumeAndClose();
        sample.frames.reserve(count);
        uint32_t resolved = 0;
        for (size_t i = 0; i < count; ++i) {
            PrismFrame frame;
            frame.address = addresses[i];
            if (symbolize(process, addresses[i], frame.symbol)) ++resolved;
            sample.frames.push_back(std::move(frame));
        }
        if (!sample.frames.empty()) {
            appendSample(std::move(sample), resolved);
            return true;
        }
    }
    return false;
}

} // namespace ds
