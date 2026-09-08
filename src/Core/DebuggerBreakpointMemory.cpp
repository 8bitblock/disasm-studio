#include "Debugger.h"
#include "DebuggerInternal.h"
#include "DebuggerMemoryMutation.h"
#include <windows.h>
#include <algorithm>
#include <cstring>
#include <memory>
#include <sstream>
#include <stdexcept>

namespace ds {
namespace {
struct RetainedNativeMutation {
    HANDLE process = nullptr;
    debugger_detail::MemoryMutation state;
    DWORD firstError = ERROR_SUCCESS;
    ~RetainedNativeMutation() { if (process) CloseHandle(process); }
    bool read(uint64_t address, void* bytes, size_t size) {
        SIZE_T got = 0;
        const bool ok = ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address), bytes, size, &got) && got == size;
        if (!ok && !firstError) firstError = GetLastError();
        return ok;
    }
    bool write(uint64_t address, const void* bytes, size_t size) {
        SIZE_T put = 0;
        const bool ok = WriteProcessMemory(process, reinterpret_cast<LPVOID>(address), bytes, size, &put) && put == size;
        if (!ok && !firstError) firstError = GetLastError();
        return ok;
    }
    bool protect(uint64_t address, size_t size, uint32_t protection) {
        DWORD previous = 0;
        const bool ok = VirtualProtectEx(process, reinterpret_cast<LPVOID>(address), size, protection, &previous) != FALSE;
        if (!ok && !firstError) firstError = GetLastError();
        return ok;
    }
    bool protectionMatches(uint64_t address, size_t size, uint32_t protection) {
        size_t offset = 0;
        while (offset < size) {
            MEMORY_BASIC_INFORMATION region{};
            const uint64_t at = address + offset;
            if (!VirtualQueryEx(process, reinterpret_cast<LPCVOID>(at), &region, sizeof(region)) ||
                region.State != MEM_COMMIT || region.Protect != protection) return false;
            const auto base = reinterpret_cast<uintptr_t>(region.BaseAddress);
            if (at < base || at - base >= region.RegionSize) return false;
            offset += std::min<size_t>(size - offset, region.RegionSize - static_cast<size_t>(at - base));
        }
        return true;
    }
    bool flush(uint64_t address, size_t size) {
        const bool ok = FlushInstructionCache(process, reinterpret_cast<LPCVOID>(address), size) != FALSE;
        if (!ok && !firstError) firstError = GetLastError();
        return ok;
    }
};
thread_local std::unique_ptr<RetainedNativeMutation> retainedMutation;
struct NativeFailure { uint64_t address = 0; uint32_t flags = 0; DWORD code = 0; };
thread_local NativeFailure nativeFailure;

void rememberFailure(const RetainedNativeMutation& mutation) {
    if (!mutation.state.failures) return;
    nativeFailure = { mutation.state.address, mutation.state.failures, mutation.firstError };
}
std::string describeFailure(const NativeFailure& failure) {
    if (!failure.flags) return {};
    std::ostringstream text;
    text << "Native memory mutation at 0x" << std::hex << failure.address << std::dec << " failed:";
    using namespace debugger_detail;
    if (failure.flags & MutationProtectFailed) text << " writable protection;";
    if (failure.flags & MutationWriteFailed) text << " byte write;";
    if (failure.flags & MutationVerifyFailed) text << " readback verification;";
    if (failure.flags & MutationRollbackFailed) text << " rollback;";
    if (failure.flags & MutationRestoreProtectionFailed) text << " original protection restoration;";
    if (failure.flags & MutationFlushFailed) text << " instruction-cache flush;";
    if (failure.code) text << " Windows error " << failure.code << '.';
    if (retainedMutation) text << " Recovery is retained; execution must stay paused.";
    return text.str();
}
bool reconcileRetainedMutation() {
    if (!retainedMutation) return true;
    // The duplicated handle cannot be confused with a newly reused PID/handle.
    // Once the original process has exited there is no target state to restore.
    if (WaitForSingleObject(retainedMutation->process, 0) == WAIT_OBJECT_0) {
        retainedMutation.reset();
        return true;
    }
    const bool recovered = debugger_detail::ReconcileMemoryMutation(*retainedMutation, retainedMutation->state);
    rememberFailure(*retainedMutation);
    if (recovered) retainedMutation.reset();
    return recovered;
}
bool checkedRemoteWrite(HANDLE process, uint64_t address, const void* bytes, size_t size) {
    if (!reconcileRetainedMutation()) return false;
    constexpr size_t maxMutationBytes = 16u * 1024u * 1024u;
    if (!process || !bytes || !size || size > maxMutationBytes ||
        address > UINTPTR_MAX || size - 1 > UINTPTR_MAX - address) {
        nativeFailure = { address, debugger_detail::MutationWriteFailed, ERROR_INVALID_PARAMETER };
        return false;
    }
    try {
        // Finish every allocation and retain a stable process handle before the
        // first protection/byte change. A failed install always has an owner.
        auto mutation = std::make_unique<RetainedNativeMutation>();
        auto& state = mutation->state;
        state.address = address;
        state.original.resize(size);
        state.replacement.assign(static_cast<const uint8_t*>(bytes), static_cast<const uint8_t*>(bytes) + size);
        state.working.resize(size);
        state.verified.resize(size);
        if (!DuplicateHandle(GetCurrentProcess(), process, GetCurrentProcess(), &mutation->process,
                             0, FALSE, DUPLICATE_SAME_ACCESS)) {
            nativeFailure = { address, debugger_detail::MutationWriteFailed, GetLastError() };
            return false;
        }
        size_t offset = 0;
        while (offset < size) {
            MEMORY_BASIC_INFORMATION region{};
            const uint64_t at = address + offset;
            if (!VirtualQueryEx(mutation->process, reinterpret_cast<LPCVOID>(at), &region, sizeof(region)) ||
                region.State != MEM_COMMIT || !region.RegionSize ||
                (region.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
                nativeFailure = { address, debugger_detail::MutationProtectFailed, GetLastError() };
                return false;
            }
            const auto base = reinterpret_cast<uintptr_t>(region.BaseAddress);
            if (at < base || at - base >= region.RegionSize) return false;
            const size_t count = std::min<size_t>(size - offset, region.RegionSize - static_cast<size_t>(at - base));
            const DWORD protection = region.Protect & 0xff;
            const bool executable = protection == PAGE_EXECUTE || protection == PAGE_EXECUTE_READ ||
                protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY;
            state.regions.push_back({ at, count, region.Protect,
                static_cast<uint32_t>(executable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE), false });
            offset += count;
        }
        if (!mutation->read(address, state.original.data(), size)) {
            nativeFailure = { address, debugger_detail::MutationVerifyFailed, mutation->firstError };
            return false;
        }
        retainedMutation = std::move(mutation);
        const bool applied = debugger_detail::ApplyMemoryMutation(*retainedMutation, retainedMutation->state);
        rememberFailure(*retainedMutation);
        if (!debugger_detail::MemoryMutationPending(retainedMutation->state)) retainedMutation.reset();
        return applied;
    } catch (const std::bad_alloc&) {
        nativeFailure = { address, debugger_detail::MutationWriteFailed, ERROR_NOT_ENOUGH_MEMORY };
        return false;
    } catch (const std::length_error&) {
        nativeFailure = { address, debugger_detail::MutationWriteFailed, ERROR_NOT_ENOUGH_MEMORY };
        return false;
    }
}
} // namespace

bool nativeMutationsPending() { return retainedMutation != nullptr; }
bool reconcileNativeMutations(std::string& error) {
    const bool recovered = reconcileRetainedMutation();
    error = recovered ? std::string{} : describeFailure(nativeFailure);
    return recovered;
}
std::string consumeNativeMutationFailure() {
    auto result = describeFailure(nativeFailure);
    nativeFailure = {};
    return result;
}

bool readByteRPM(HANDLE h, uint64_t va, uint8_t& b) {
    SIZE_T got = 0; return ReadProcessMemory(h, (LPCVOID)va, &b, 1, &got) && got == 1;
}
bool writeByteRPM(HANDLE h, uint64_t va, uint8_t b) {
    return checkedRemoteWrite(h, va, &b, 1);
}

// A debugger-owned byte transition is valid only while the byte still has the
// value whose ownership we proved. The target is stopped whenever this helper is
// used for breakpoint state, so the compare/write/readback sequence is atomic
// with respect to execution and protects patches/self-modifying code from stale
// cleanup restores.
bool replaceByteIfEqual(HANDLE h, uint64_t va, uint8_t expected, uint8_t replacement) {
    if (!reconcileRetainedMutation()) return false;
    uint8_t current = 0;
    if (!readByteRPM(h, va, current) || current != expected) return false;
    if (expected == replacement) return true;
    return writeByteRPM(h, va, replacement);
}

bool restoreDebuggerOwnedByte(HANDLE h, uint64_t va, uint8_t original) {
    if (!reconcileRetainedMutation()) return false;
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

bool readRemoteExact(HANDLE h, uint64_t va, void* out, size_t size) {
    SIZE_T got = 0;
    return size && ReadProcessMemory(h, (LPCVOID)va, out, size, &got) && got == size;
}

bool writeRemoteExact(HANDLE h, uint64_t va, const void* in, size_t size) {
    return checkedRemoteWrite(h, va, in, size);
}


} // namespace ds
