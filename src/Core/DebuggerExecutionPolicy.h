#pragma once
// Pure control-register and hardware-breakpoint policy. The native adapter runs
// each transaction on the sole debug-event owner while all threads are stopped.
#include <cstdint>

namespace ds::debugger_detail {

enum class ControlMutationResult { Applied, ReadFailed, WriteFailed, VerifyFailed, RollbackFailed };

template<class Read, class Write>
ControlMutationResult UpdateControlBits(uint32_t mask, bool enabled, Read&& read, Write&& write) {
    uint32_t before = 0;
    if (!read(before)) return ControlMutationResult::ReadFailed;
    const uint32_t expected = enabled ? before | mask : before & ~mask;
    if (expected == before) return ControlMutationResult::Applied;
    const bool written = write(expected);
    uint32_t verified = 0;
    if (written && read(verified) && (verified & mask) == (expected & mask))
        return ControlMutationResult::Applied;
    // A failed native write is not evidence that the context stayed unchanged.
    // Preserve unrelated flags and restore just the bit we own, then verify it.
    uint32_t current = 0;
    if (!read(current) || !write((current & ~mask) | (before & mask)) ||
        !read(verified) || (verified & mask) != (before & mask))
        return ControlMutationResult::RollbackFailed;
    return written ? ControlMutationResult::VerifyFailed : ControlMutationResult::WriteFailed;
}

inline bool ValidHardwareBreakpoint(uint64_t address, bool execute, uint8_t size, bool wow64) {
    if (execute) size = 1;
    if (size != 1 && size != 2 && size != 4 && size != 8) return false;
    if (wow64 && (size == 8 || address > UINT32_MAX || size - 1 > UINT32_MAX - address))
        return false;
    if (address > UINT64_MAX - (size - 1)) return false;
    return address % size == 0;
}

inline bool CheckedInstructionContinuation(uint64_t address, uint32_t length,
                                           bool decoded, bool wow64, uint64_t& out) {
    if (!decoded || !length || length > 15 || address > UINT64_MAX - length) return false;
    out = address + length;
    return !wow64 || out <= UINT32_MAX;
}

} // namespace ds::debugger_detail
