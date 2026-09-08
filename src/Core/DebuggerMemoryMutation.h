#pragma once
// Allocation-free execution/rollback policy for a preflighted remote write.
// IO supplies read/write/protect/flush. The debug-event owner is the only caller.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace ds::debugger_detail {
enum MemoryMutationFailure : uint32_t {
    MutationProtectFailed = 1,
    MutationWriteFailed = 2,
    MutationVerifyFailed = 4,
    MutationRollbackFailed = 8,
    MutationRestoreProtectionFailed = 16,
    MutationFlushFailed = 32,
};
struct MemoryMutationRegion {
    uint64_t address = 0;
    size_t size = 0;
    uint32_t originalProtection = 0, writableProtection = 0;
    bool restorePending = false;
};
struct MemoryMutation {
    uint64_t address = 0;
    std::vector<uint8_t> original, replacement, working, verified;
    std::vector<MemoryMutationRegion> regions;
    bool rollbackPending = false, flushPending = false, applied = false;
    uint32_t failures = 0;
};
inline bool MemoryMutationPending(const MemoryMutation& mutation) noexcept {
    return mutation.rollbackPending || mutation.flushPending ||
        std::any_of(mutation.regions.begin(), mutation.regions.end(),
            [](const auto& region) { return region.restorePending; });
}
template<class IO>
bool MakeMutationWritable(IO& io, MemoryMutation& mutation) {
    for (auto& region : mutation.regions) {
        // Retain the original even when the native API reports failure: a
        // failure does not grant permission to forget a protection obligation.
        region.restorePending = true;
        if (!io.protect(region.address, region.size, region.writableProtection)) {
            mutation.failures |= MutationProtectFailed;
            return false;
        }
    }
    return true;
}
template<class IO>
void RestoreMutationEnvironment(IO& io, MemoryMutation& mutation) {
    for (auto at = mutation.regions.rbegin(); at != mutation.regions.rend(); ++at) {
        if (!at->restorePending) continue;
        const bool restored = io.protect(at->address, at->size, at->originalProtection);
        if (!restored) mutation.failures |= MutationRestoreProtectionFailed;
        if (restored || io.protectionMatches(at->address, at->size, at->originalProtection))
            at->restorePending = false;
    }
    if (mutation.flushPending) {
        if (io.flush(mutation.address, mutation.original.size())) mutation.flushPending = false;
        else mutation.failures |= MutationFlushFailed;
    }
}
template<class IO>
bool ReconcileMemoryMutation(IO& io, MemoryMutation& mutation) {
    if (mutation.rollbackPending) {
        if (!io.read(mutation.address, mutation.working.data(), mutation.working.size())) {
            mutation.failures |= MutationRollbackFailed;
        } else {
            bool needsWrite = false;
            for (size_t i = 0; i < mutation.working.size(); ++i) {
                // Restore only bytes that still match this write. Unrelated
                // target-side changes supersede our ownership and are kept.
                if (mutation.working[i] == mutation.replacement[i] &&
                    mutation.working[i] != mutation.original[i]) {
                    mutation.working[i] = mutation.original[i];
                    needsWrite = true;
                }
            }
            if (!needsWrite) mutation.rollbackPending = false;
            else if (MakeMutationWritable(io, mutation)) {
                mutation.flushPending = true;
                const bool wrote = io.write(mutation.address, mutation.working.data(), mutation.working.size());
                const bool verified = io.read(mutation.address, mutation.verified.data(), mutation.verified.size()) &&
                    mutation.verified == mutation.working;
                // A failed API may still write bytes. Readback proves cleanup,
                // but the failed operation remains in the diagnostic flags.
                if (!wrote) mutation.failures |= MutationRollbackFailed;
                if (verified) mutation.rollbackPending = false;
                else mutation.failures |= MutationRollbackFailed;
            } else mutation.failures |= MutationRollbackFailed;
        }
    }
    RestoreMutationEnvironment(io, mutation);
    return !MemoryMutationPending(mutation);
}
template<class IO>
bool ApplyMemoryMutation(IO& io, MemoryMutation& mutation) {
    if (!MakeMutationWritable(io, mutation)) {
        RestoreMutationEnvironment(io, mutation);
        return false;
    }
    mutation.flushPending = true; // set before even a partially failing write
    const bool wrote = io.write(mutation.address, mutation.replacement.data(), mutation.replacement.size());
    const bool verified = io.read(mutation.address, mutation.verified.data(), mutation.verified.size()) &&
        mutation.verified == mutation.replacement;
    if (!wrote) mutation.failures |= MutationWriteFailed;
    if (!verified) mutation.failures |= MutationVerifyFailed;
    mutation.applied = wrote && verified;
    mutation.rollbackPending = !mutation.applied;
    ReconcileMemoryMutation(io, mutation);
    return mutation.applied;
}
} // namespace ds::debugger_detail
