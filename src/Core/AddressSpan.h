#pragma once
//
// AddressSpan.h
// Small, dependency-light helpers for treating virtual-address ranges as byte
// counts without ever wrapping UINT64_MAX back to address zero.
//

#include <cstddef>
#include <cstdint>
#include <limits>

namespace ds {

inline bool CheckedAddressAdd(uint64_t base, uint64_t offset, uint64_t& result) noexcept {
    if (offset > (std::numeric_limits<uint64_t>::max)() - base) return false;
    result = base + offset;
    return true;
}

inline bool CheckedAddressAddSigned(uint64_t base, int64_t delta,
                                    uint64_t& result) noexcept {
    if (delta >= 0) return CheckedAddressAdd(base, static_cast<uint64_t>(delta), result);

    // Written this way so INT64_MIN never has to be negated directly.
    const uint64_t magnitude = static_cast<uint64_t>(-(delta + 1)) + 1;
    if (magnitude > base) return false;
    result = base - magnitude;
    return true;
}

// Clamp a byte count so every address start+[0,count) remains representable.
// At start==0 every representable size_t count already fits; spelling 2^64 as
// a uint64_t count is neither necessary nor possible.
inline size_t ClampAddressableBytes(uint64_t start, size_t requested) noexcept {
    if (!requested || start == 0) return requested;
    const uint64_t room = (std::numeric_limits<uint64_t>::max)() - start + 1;
    return room < static_cast<uint64_t>(requested)
        ? static_cast<size_t>(room)
        : requested;
}

// Containment for a byte-count span. Subtraction is intentional: unlike an
// exclusive end address, it stays correct when the span includes UINT64_MAX.
inline bool AddressInSpan(uint64_t start, size_t byteCount, uint64_t address) noexcept {
    return byteCount != 0 && address >= start &&
           address - start < static_cast<uint64_t>(byteCount);
}

// Useful only for descriptive end fields whose type cannot express 2^64.
// Consumers that need containment or a successor must use AddressInSpan or a
// checked add instead of relying on this saturated value as an exclusive end.
inline uint64_t SaturatingAddressAdd(uint64_t base, uint64_t offset) noexcept {
    uint64_t result = 0;
    return CheckedAddressAdd(base, offset, result)
        ? result
        : (std::numeric_limits<uint64_t>::max)();
}

} // namespace ds
