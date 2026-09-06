#include "ProcessMemorySession.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cstdio>
#include <cwchar>
#include <cstring>
#include <limits>
#include <mutex>
#include <utility>

namespace ds {
namespace {

class OwnedHandle {
public:
    OwnedHandle() = default;
    explicit OwnedHandle(HANDLE value) : value_(value) {}
    ~OwnedHandle() { reset(); }

    OwnedHandle(const OwnedHandle&) = delete;
    OwnedHandle& operator=(const OwnedHandle&) = delete;

    OwnedHandle(OwnedHandle&& other) noexcept : value_(other.release()) {}
    OwnedHandle& operator=(OwnedHandle&& other) noexcept {
        if (this != &other) reset(other.release());
        return *this;
    }

    HANDLE get() const { return value_; }
    explicit operator bool() const { return value_ != nullptr && value_ != INVALID_HANDLE_VALUE; }

    HANDLE release() {
        HANDLE value = value_;
        value_ = nullptr;
        return value;
    }

    void reset(HANDLE value = nullptr) {
        if (*this) CloseHandle(value_);
        value_ = value;
    }

private:
    HANDLE value_ = nullptr;
};

std::string utf8FromWide(const wchar_t* value, size_t length) {
    if (!value || !length) return {};
    const int boundedLength = length > static_cast<size_t>((std::numeric_limits<int>::max)())
                            ? (std::numeric_limits<int>::max)()
                            : static_cast<int>(length);
    const int needed = WideCharToMultiByte(CP_UTF8, 0, value, boundedLength,
                                            nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string result(static_cast<size_t>(needed), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, value, boundedLength, result.data(), needed,
                            nullptr, nullptr) != needed)
        return {};
    return result;
}

std::string win32Message(DWORD code) {
    if (!code) return "unknown Windows error";
    wchar_t* raw = nullptr;
    const DWORD count = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, 0, reinterpret_cast<wchar_t*>(&raw), 0, nullptr);
    std::string message = count && raw ? utf8FromWide(raw, count) : std::string{};
    if (raw) LocalFree(raw);
    while (!message.empty() &&
           (message.back() == '\r' || message.back() == '\n' ||
            message.back() == ' ' || message.back() == '\t'))
        message.pop_back();
    if (message.empty()) message = "Windows error " + std::to_string(code);
    return message;
}

std::string operationError(const char* operation, DWORD code) {
    std::string result = operation ? operation : "operation failed";
    result += " (error ";
    result += std::to_string(code);
    result += "): ";
    result += win32Message(code);
    return result;
}

uint64_t fileTimeTicks(const FILETIME& value) {
    ULARGE_INTEGER ticks{};
    ticks.LowPart = value.dwLowDateTime;
    ticks.HighPart = value.dwHighDateTime;
    return ticks.QuadPart;
}

std::string queryImagePath(HANDLE process) {
    std::vector<wchar_t> buffer(32768, L'\0');
    DWORD length = static_cast<DWORD>(buffer.size());
    if (!QueryFullProcessImageNameW(process, 0, buffer.data(), &length) || !length)
        return {};
    return utf8FromWide(buffer.data(), length);
}

std::string basenameOf(std::string path) {
    const size_t slash = path.find_last_of("/\\");
    if (slash != std::string::npos) path.erase(0, slash + 1);
    return path;
}

std::string queryToolhelpName(uint32_t pid) {
    OwnedHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot || snapshot.get() == INVALID_HANDLE_VALUE) return {};
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot.get(), &entry)) return {};
    do {
        if (entry.th32ProcessID == pid)
            return utf8FromWide(entry.szExeFile, std::wcslen(entry.szExeFile));
    } while (Process32NextW(snapshot.get(), &entry));
    return {};
}

bool processAlive(HANDLE process) {
    if (!process) return false;
    return WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
}

DWORD baseProtection(DWORD protection) {
    return protection & 0xFFu;
}

ProcessMemoryAccess accessFromProtection(DWORD state, DWORD protection) {
    const DWORD base = baseProtection(protection);
    ProcessMemoryAccess access;
    access.committed = state == MEM_COMMIT;
    access.guarded = (protection & PAGE_GUARD) != 0;
    access.noAccess = base == PAGE_NOACCESS || base == 0;
    access.readable = base == PAGE_READONLY || base == PAGE_READWRITE ||
                      base == PAGE_WRITECOPY || base == PAGE_EXECUTE_READ ||
                      base == PAGE_EXECUTE_READWRITE ||
                      base == PAGE_EXECUTE_WRITECOPY;
    access.writable = base == PAGE_READWRITE || base == PAGE_WRITECOPY ||
                      base == PAGE_EXECUTE_READWRITE ||
                      base == PAGE_EXECUTE_WRITECOPY;
    access.executable = base == PAGE_EXECUTE || base == PAGE_EXECUTE_READ ||
                        base == PAGE_EXECUTE_READWRITE ||
                        base == PAGE_EXECUTE_WRITECOPY;
    return access;
}

ProcessMemoryRegion makeRegion(const MEMORY_BASIC_INFORMATION& info) {
    ProcessMemoryRegion region;
    region.base = reinterpret_cast<uint64_t>(info.BaseAddress);
    region.size = static_cast<uint64_t>(info.RegionSize);
    region.allocationBase = reinterpret_cast<uint64_t>(info.AllocationBase);
    region.allocationProtect = info.AllocationProtect;
    region.protect = info.Protect;
    region.state = info.State;
    region.type = info.Type;
    const ProcessMemoryAccess access = accessFromProtection(info.State, info.Protect);
    region.committed = access.committed;
    region.readable = access.readable;
    region.writable = access.writable;
    region.executable = access.executable;
    region.copyOnWrite = baseProtection(info.Protect) == PAGE_WRITECOPY ||
                         baseProtection(info.Protect) == PAGE_EXECUTE_WRITECOPY;
    region.guarded = access.guarded;
    region.noAccess = access.noAccess;
    return region;
}

DWORD temporaryWritableProtection(bool executable) {
    return executable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
}

} // namespace

struct ProcessMemorySession::Impl {
    mutable std::mutex mutex;
    OwnedHandle process;
    ProcessMemoryIdentity identity{};
    uint64_t generationCounter = 0;
    bool canRead = false;
    bool canWrite = false;
    bool is32 = false;
    bool bitnessKnown = false;
    std::string path;
    std::string name;
    std::string lastError;
};

ProcessMemorySession::ProcessMemorySession() : impl_(std::make_unique<Impl>()) {}
ProcessMemorySession::~ProcessMemorySession() = default;

bool ProcessMemorySession::open(uint32_t pid, ProcessMemoryOpenOptions options,
                                std::string* error) {
    auto publishFailure = [&](std::string message) {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        impl_->lastError = std::move(message);
        if (error) *error = impl_->lastError;
        return false;
    };

    if (!pid) return publishFailure("cannot open process PID 0");

    constexpr DWORD kReadAccess = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE;
    constexpr DWORD kWriteAccess = PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
    bool canWrite = false;
    OwnedHandle candidate;
    DWORD writeOpenError = ERROR_SUCCESS;

    if (options.requestWrite) {
        candidate.reset(OpenProcess(kReadAccess | kWriteAccess, FALSE, pid));
        if (candidate) {
            canWrite = true;
        } else {
            writeOpenError = GetLastError();
        }
    }
    if (!candidate && (!options.requestWrite || options.allowReadOnlyFallback)) {
        candidate.reset(OpenProcess(kReadAccess, FALSE, pid));
    }
    if (!candidate) {
        const DWORD code = GetLastError();
        std::string message = operationError("OpenProcess failed", code);
        if (writeOpenError != ERROR_SUCCESS && code != writeOpenError) {
            message += "; write-capable open also failed: ";
            message += win32Message(writeOpenError);
        }
        return publishFailure(std::move(message));
    }
    if (!processAlive(candidate.get()))
        return publishFailure("process exited before the memory session could be opened");

    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(candidate.get(), &created, &exited, &kernel, &user))
        return publishFailure(operationError("GetProcessTimes failed", GetLastError()));
    const uint64_t creationTime = fileTimeTicks(created);
    if (!creationTime)
        return publishFailure("process creation time was unavailable; refusing an ambiguous PID identity");

    BOOL wow64 = FALSE;
    const bool bitnessKnown = IsWow64Process(candidate.get(), &wow64) != FALSE;
    const bool is32 = bitnessKnown && wow64 != FALSE;
    std::string path = queryImagePath(candidate.get());
    std::string name = basenameOf(path);
    if (name.empty()) name = queryToolhelpName(pid);
    if (name.empty()) name = "PID " + std::to_string(pid);

    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->generationCounter == (std::numeric_limits<uint64_t>::max)()) {
        impl_->lastError = "process-memory session generation exhausted";
        if (error) *error = impl_->lastError;
        return false;
    }
    const uint64_t generation = ++impl_->generationCounter;
    impl_->process = std::move(candidate);
    impl_->identity = { pid, creationTime, generation };
    impl_->canRead = true;
    impl_->canWrite = canWrite;
    impl_->is32 = is32;
    impl_->bitnessKnown = bitnessKnown;
    impl_->path = std::move(path);
    impl_->name = std::move(name);
    impl_->lastError.clear();
    if (error) error->clear();
    return true;
}

void ProcessMemorySession::close() {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->process.reset();
    impl_->identity = {};
    impl_->canRead = false;
    impl_->canWrite = false;
    impl_->is32 = false;
    impl_->bitnessKnown = false;
    impl_->path.clear();
    impl_->name.clear();
    impl_->lastError.clear();
}

ProcessMemorySessionSnapshot ProcessMemorySession::snapshot() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    ProcessMemorySessionSnapshot result;
    result.open = static_cast<bool>(impl_->process);
    result.alive = result.open && processAlive(impl_->process.get());
    result.canRead = result.open && impl_->canRead;
    result.canWrite = result.open && impl_->canWrite;
    result.is32 = impl_->is32;
    result.bitnessKnown = impl_->bitnessKnown;
    result.identity = impl_->identity;
    result.path = impl_->path;
    result.name = impl_->name;
    result.error = impl_->lastError;
    return result;
}

size_t ProcessMemorySession::read(ProcessMemoryIdentity expected, uint64_t address,
                                  void* output, size_t size, std::string* error) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    auto fail = [&](std::string message, size_t partial = 0) {
        impl_->lastError = std::move(message);
        if (error) *error = impl_->lastError;
        return partial;
    };

    if (!output || !size || address > UINT64_MAX - static_cast<uint64_t>(size))
        return fail("invalid process-memory read range");
    if (!impl_->process) return fail("process-memory session is closed");
    if (!ProcessMemoryIdentityMatches(impl_->identity, expected))
        return fail("process-memory read identity no longer owns the open target");
    if (!processAlive(impl_->process.get())) return fail("process exited before memory could be read");

    SIZE_T readSize = 0;
    SetLastError(ERROR_SUCCESS);
    const BOOL ok = ReadProcessMemory(impl_->process.get(),
                                      reinterpret_cast<LPCVOID>(address),
                                      output, size, &readSize);
    if (!ok || readSize != size) {
        const DWORD code = GetLastError();
        std::string message = "ReadProcessMemory returned " +
            std::to_string(static_cast<size_t>(readSize)) + " of " +
            std::to_string(size) + " byte(s)";
        if (code != ERROR_SUCCESS) {
            message += ": ";
            message += win32Message(code);
        }
        return fail(std::move(message), static_cast<size_t>(readSize));
    }

    impl_->lastError.clear();
    if (error) error->clear();
    return static_cast<size_t>(readSize);
}

ProcessMemoryRegionResult ProcessMemorySession::committedRegions(
    ProcessMemoryIdentity expected) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    ProcessMemoryRegionResult result;
    result.identity = expected;
    auto fail = [&](std::string message) {
        result.error = std::move(message);
        impl_->lastError = result.error;
        return result;
    };

    if (!impl_->process) return fail("process-memory session is closed");
    if (!ProcessMemoryIdentityMatches(impl_->identity, expected))
        return fail("memory-region query identity no longer owns the open target");
    if (!processAlive(impl_->process.get()))
        return fail("process exited before memory regions could be queried");

    SYSTEM_INFO systemInfo{};
    GetNativeSystemInfo(&systemInfo);
    uint64_t maximumAddress = reinterpret_cast<uint64_t>(
        systemInfo.lpMaximumApplicationAddress);
    if (impl_->is32) maximumAddress = UINT32_MAX;

    constexpr size_t kMaxRegions = 1'000'000;
    result.regions.reserve(2048);
    uint64_t address = 0;
    while (address <= maximumAddress) {
        MEMORY_BASIC_INFORMATION info{};
        SetLastError(ERROR_SUCCESS);
        const SIZE_T queried = VirtualQueryEx(impl_->process.get(),
                                               reinterpret_cast<LPCVOID>(address),
                                               &info, sizeof(info));
        if (queried != sizeof(info)) {
            const DWORD code = GetLastError();
            // ERROR_INVALID_PARAMETER is VirtualQueryEx's normal end marker
            // once the address is beyond the target's user address space.
            if (code == ERROR_INVALID_PARAMETER) {
                result.complete = true;
                break;
            }
            return fail(operationError("VirtualQueryEx failed", code));
        }

        const uint64_t base = reinterpret_cast<uint64_t>(info.BaseAddress);
        const uint64_t regionSize = static_cast<uint64_t>(info.RegionSize);
        if (!regionSize || base > UINT64_MAX - regionSize || base + regionSize <= address)
            return fail("VirtualQueryEx returned a non-advancing memory region");

        if (info.State == MEM_COMMIT) {
            result.regions.push_back(makeRegion(info));
            if (result.regions.size() >= kMaxRegions)
                return fail("memory-region enumeration reached the defensive region limit");
        }
        address = base + regionSize;
        if (address > maximumAddress) {
            result.complete = true;
            break;
        }
    }

    if (result.complete) impl_->lastError.clear();
    return result;
}

ProcessMemoryWriteResult ProcessMemorySession::write(
    ProcessMemoryIdentity expected, uint64_t address, const void* bytes, size_t size,
    ProcessMemoryWriteOptions options) {
    ProcessMemoryWriteResult result;
    std::vector<uint8_t> desired;
    if (!bytes || !size || size > kProcessMemoryMaxTransactionalWriteBytes ||
        address > UINT64_MAX - static_cast<uint64_t>(size)) {
        result.code = ProcessMemoryWriteCode::InvalidRequest;
        result.error = "invalid or oversized process-memory write range";
        std::lock_guard<std::mutex> lock(impl_->mutex);
        impl_->lastError = result.error;
        return result;
    }
    try {
        const auto* first = static_cast<const uint8_t*>(bytes);
        desired.assign(first, first + size);
    } catch (...) {
        result.code = ProcessMemoryWriteCode::InvalidRequest;
        result.error = "unable to retain the requested memory-write bytes";
        std::lock_guard<std::mutex> lock(impl_->mutex);
        impl_->lastError = result.error;
        return result;
    }

    std::lock_guard<std::mutex> lock(impl_->mutex);
    auto finishFailure = [&](ProcessMemoryWriteCode code, std::string message) {
        result.code = code;
        result.bytesWritten = 0;
        result.error = std::move(message);
        impl_->lastError = result.error;
        return result;
    };

    if (!impl_->process)
        return finishFailure(ProcessMemoryWriteCode::SessionClosed,
                             "process-memory session is closed");
    if (!ProcessMemoryIdentityMatches(impl_->identity, expected))
        return finishFailure(ProcessMemoryWriteCode::IdentityMismatch,
                             "process-memory write identity no longer owns the open target");
    if (!processAlive(impl_->process.get()))
        return finishFailure(ProcessMemoryWriteCode::ProcessExited,
                             "process exited before memory could be written");
    if (!impl_->canWrite)
        return finishFailure(ProcessMemoryWriteCode::WriteAccessUnavailable,
                             "the process-memory session is read-only");

    struct NativeSpan {
        uint64_t address = 0;
        size_t size = 0;
        DWORD originalProtect = 0;
        DWORD restoreProtect = 0;
        bool needsProtectionChange = false;
        bool executable = false;
        bool changed = false;
    };
    std::vector<NativeSpan> spans;
    try {
        spans.reserve(8);
    } catch (...) {
        return finishFailure(ProcessMemoryWriteCode::InvalidRequest,
                             "unable to retain memory-write region metadata");
    }

    const uint64_t end = address + static_cast<uint64_t>(size);
    uint64_t cursor = address;
    bool touchesExecutable = false;
    while (cursor < end) {
        MEMORY_BASIC_INFORMATION info{};
        SetLastError(ERROR_SUCCESS);
        if (VirtualQueryEx(impl_->process.get(), reinterpret_cast<LPCVOID>(cursor),
                           &info, sizeof(info)) != sizeof(info))
            return finishFailure(ProcessMemoryWriteCode::RegionQueryFailed,
                                 operationError("VirtualQueryEx failed for write range",
                                                GetLastError()));

        const uint64_t regionBase = reinterpret_cast<uint64_t>(info.BaseAddress);
        const uint64_t regionSize = static_cast<uint64_t>(info.RegionSize);
        if (!regionSize || regionBase > UINT64_MAX - regionSize ||
            regionBase + regionSize <= cursor)
            return finishFailure(ProcessMemoryWriteCode::RegionQueryFailed,
                                 "VirtualQueryEx returned a non-advancing write region");
        const uint64_t spanEnd = (std::min)(end, regionBase + regionSize);
        const ProcessMemoryAccess access = accessFromProtection(info.State, info.Protect);
        const ProcessMemoryWritePolicy policy =
            EvaluateProcessMemoryWritePolicy(access, options.allowProtectionChange);
        if (policy.code == ProcessMemoryWritePolicyCode::Deny) {
            std::string why = !access.committed ? "uncommitted"
                            : access.guarded ? "guarded"
                            : access.noAccess ? "PAGE_NOACCESS"
                            : "inaccessible";
            return finishFailure(ProcessMemoryWriteCode::RegionDenied,
                                 "write range touches a " + why + " memory region");
        }
        if (policy.code == ProcessMemoryWritePolicyCode::ExplicitAuthorizationRequired) {
            const char* why = access.executable ? "an executable page"
                              : "a page whose protection must change";
            return finishFailure(
                ProcessMemoryWriteCode::ExplicitAuthorizationRequired,
                std::string("write range touches ") + why +
                    "; retry only with allowProtectionChange after explicit user approval");
        }

        try {
            spans.push_back({ cursor, static_cast<size_t>(spanEnd - cursor),
                              info.Protect, 0, policy.needsProtectionChange,
                              policy.touchesExecutable, false });
        } catch (...) {
            return finishFailure(ProcessMemoryWriteCode::InvalidRequest,
                                 "unable to retain memory-write region metadata");
        }
        touchesExecutable = touchesExecutable || policy.touchesExecutable;
        cursor = spanEnd;
    }

    HANDLE process = impl_->process.get();
    auto restoreProtections = [&]() {
        bool restored = true;
        for (auto it = spans.rbegin(); it != spans.rend(); ++it) {
            if (!it->changed) continue;
            DWORD ignored = 0;
            if (VirtualProtectEx(process, reinterpret_cast<LPVOID>(it->address),
                                 it->size, it->restoreProtect, &ignored)) {
                it->changed = false;
            } else {
                restored = false;
            }
        }
        result.protectionsRestored = restored;
        return restored;
    };

    for (NativeSpan& span : spans) {
        if (!span.needsProtectionChange) continue;
        DWORD previous = 0;
        if (!VirtualProtectEx(process, reinterpret_cast<LPVOID>(span.address), span.size,
                              temporaryWritableProtection(span.executable), &previous)) {
            const std::string errorMessage =
                operationError("VirtualProtectEx could not make the write range writable",
                               GetLastError());
            const bool restored = restoreProtections();
            return finishFailure(
                restored ? ProcessMemoryWriteCode::ProtectionChangeFailed
                         : ProcessMemoryWriteCode::ProtectionRestoreFailed,
                restored ? errorMessage
                         : errorMessage + "; an earlier page protection could not be restored");
        }
        span.restoreProtect = previous;
        span.changed = true;
        result.protectionChanged = true;
    }

    std::vector<uint8_t> before;
    std::vector<uint8_t> verify;
    try {
        before.resize(size);
        verify.resize(size);
    } catch (...) {
        const bool restored = restoreProtections();
        return finishFailure(
            restored ? ProcessMemoryWriteCode::ReadBeforeWriteFailed
                     : ProcessMemoryWriteCode::ProtectionRestoreFailed,
            restored ? "unable to allocate transactional write verification buffers"
                     : "verification-buffer allocation failed and page protection restoration was incomplete");
    }

    SIZE_T transferred = 0;
    SetLastError(ERROR_SUCCESS);
    if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address),
                           before.data(), size, &transferred) || transferred != size) {
        const DWORD code = GetLastError();
        const bool restored = restoreProtections();
        std::string message = "could not capture every original byte before writing";
        if (code != ERROR_SUCCESS) message += ": " + win32Message(code);
        if (!restored) message += "; page protection restoration was incomplete";
        return finishFailure(
            restored ? ProcessMemoryWriteCode::ReadBeforeWriteFailed
                     : ProcessMemoryWriteCode::ProtectionRestoreFailed,
            std::move(message));
    }

    auto rollbackBytes = [&]() {
        result.rollbackAttempted = true;
        SIZE_T putBack = 0;
        const BOOL wroteBack = WriteProcessMemory(
            process, reinterpret_cast<LPVOID>(address), before.data(), size, &putBack);
        if (!wroteBack || putBack != size) return false;
        if (touchesExecutable &&
            !FlushInstructionCache(process, reinterpret_cast<LPCVOID>(address), size))
            return false;
        SIZE_T checked = 0;
        if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address),
                               verify.data(), size, &checked) || checked != size ||
            verify != before)
            return false;
        result.rollbackComplete = true;
        return true;
    };

    auto finishPostWriteFailure = [&](ProcessMemoryWriteCode originalCode,
                                      std::string message) {
        const bool rolledBack = rollbackBytes();
        const bool protectionsRestored = restoreProtections();
        if (!rolledBack) {
            message += "; verified byte rollback failed";
            if (!protectionsRestored) message += " and page protections were not fully restored";
            return finishFailure(ProcessMemoryWriteCode::RollbackFailed, std::move(message));
        }
        if (!protectionsRestored) {
            message += "; bytes were rolled back but page protection restoration failed";
            return finishFailure(ProcessMemoryWriteCode::ProtectionRestoreFailed,
                                 std::move(message));
        }
        return finishFailure(originalCode, std::move(message));
    };

    transferred = 0;
    SetLastError(ERROR_SUCCESS);
    if (!WriteProcessMemory(process, reinterpret_cast<LPVOID>(address),
                            desired.data(), size, &transferred) || transferred != size) {
        const DWORD code = GetLastError();
        std::string message = "WriteProcessMemory did not commit the complete request";
        if (code != ERROR_SUCCESS) message += ": " + win32Message(code);
        return finishPostWriteFailure(ProcessMemoryWriteCode::WriteFailed,
                                      std::move(message));
    }
    if (touchesExecutable &&
        !FlushInstructionCache(process, reinterpret_cast<LPCVOID>(address), size)) {
        return finishPostWriteFailure(
            ProcessMemoryWriteCode::WriteFailed,
            operationError("FlushInstructionCache failed after executable-memory write",
                           GetLastError()));
    }

    transferred = 0;
    if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address),
                           verify.data(), size, &transferred) || transferred != size ||
        verify != desired) {
        return finishPostWriteFailure(ProcessMemoryWriteCode::VerificationFailed,
                                      "memory-write verification did not match the requested bytes");
    }

    if (!restoreProtections()) {
        // Some spans may already be back to read-only.  Re-open only the spans
        // whose original protection required a change, retain the original
        // restore value, then put the original bytes back and retry restoration.
        bool writableAgain = true;
        for (NativeSpan& span : spans) {
            if (!span.needsProtectionChange || span.changed) continue;
            DWORD ignored = 0;
            if (!VirtualProtectEx(process, reinterpret_cast<LPVOID>(span.address), span.size,
                                  temporaryWritableProtection(span.executable), &ignored)) {
                writableAgain = false;
            } else {
                span.changed = true;
            }
        }
        const bool rolledBack = writableAgain && rollbackBytes();
        const bool restored = restoreProtections();
        if (!rolledBack || !restored) {
            std::string message = "page protection restoration failed after a verified write";
            if (!rolledBack) message += "; verified byte rollback failed";
            if (!restored) message += "; original page protections remain incomplete";
            return finishFailure(ProcessMemoryWriteCode::RollbackFailed, std::move(message));
        }
        return finishFailure(
            ProcessMemoryWriteCode::ProtectionRestoreFailed,
            "page protection restoration initially failed; original bytes and protections were restored");
    }

    result.code = ProcessMemoryWriteCode::Applied;
    result.bytesWritten = size;
    result.error.clear();
    impl_->lastError.clear();
    return result;
}

} // namespace ds
