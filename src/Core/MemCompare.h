#pragma once
//
// MemCompare.h
// Pure, header-only numeric interpretation + ordered comparison of a raw
// little-endian value read from process memory, shared by the Memory Tools
// scanner. Integer values can be interpreted as SIGNED or UNSIGNED (the scanner
// exposes this as a mode), float/double always use their IEEE value. Kept free of
// ImGui/Win32 deps so the compare logic is unit-testable with cl.
//
#include "DebugTargetIdentity.h"
#include <cerrno>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>

namespace ds {

// Value-type tags mirror MemoryToolsTab::ValueType, duplicated here so this
// header has no dependency on the ImGui tab. (Static-asserted equal in the tab.)
enum class MemValType { Byte = 0, Word = 1, Dword = 2, Qword = 3, Float = 4, Double = 5 };

inline size_t MemTypeSize(int t) {
    switch (t) {
        case (int)MemValType::Byte:  return 1;
        case (int)MemValType::Word:  return 2;
        case (int)MemValType::Dword: return 4;
        case (int)MemValType::Qword: return 8;
        case (int)MemValType::Float: return 4;
        case (int)MemValType::Double:return 8;
    }
    return 4;
}

inline bool MemValueTypeValid(int type) {
    return type >= (int)MemValType::Byte && type <= (int)MemValType::Double;
}

inline const char* MemSkipAsciiSpace(const char* text) {
    if (!text) return nullptr;
    while (*text && std::isspace(static_cast<unsigned char>(*text))) ++text;
    return text;
}

inline bool MemConsumedAll(const char* end) {
    end = MemSkipAsciiSpace(end);
    return end && *end == '\0';
}

// Strict scanner/address-table value parser. Successful decimal integers cover
// both the signed destination range and its unsigned upper half; negative values
// are stored as the destination-width two's-complement bit pattern. Hex input is
// an unsigned raw bit pattern. Floating values must be finite and in range.
inline bool MemParseValue(int type, const char* text, bool hex,
                          uint64_t& bitsOut, size_t& sizeOut) {
    if (!MemValueTypeValid(type)) return false;
    const char* start = MemSkipAsciiSpace(text);
    if (!start || !*start) return false;
    const size_t size = MemTypeSize(type);

    uint64_t parsedBits = 0;
    if (type == (int)MemValType::Float) {
        errno = 0;
        char* end = nullptr;
        const float value = std::strtof(start, &end);
        if (end == start || errno == ERANGE || !std::isfinite(value) ||
            !MemConsumedAll(end))
            return false;
        std::memcpy(&parsedBits, &value, sizeof(value));
    } else if (type == (int)MemValType::Double) {
        errno = 0;
        char* end = nullptr;
        const double value = std::strtod(start, &end);
        if (end == start || errno == ERANGE || !std::isfinite(value) ||
            !MemConsumedAll(end))
            return false;
        std::memcpy(&parsedBits, &value, sizeof(value));
    } else if (!hex && *start == '-') {
        errno = 0;
        char* end = nullptr;
        const long long value = std::strtoll(start, &end, 10);
        if (end == start || errno == ERANGE || !MemConsumedAll(end)) return false;
        const int bits = static_cast<int>(size * 8);
        const int64_t minimum = bits == 64
            ? std::numeric_limits<int64_t>::min()
            : -(int64_t{1} << (bits - 1));
        if (value < minimum || value > 0) return false;
        parsedBits = size == 8 ? static_cast<uint64_t>(value)
                               : static_cast<uint64_t>(value) &
                                 ((uint64_t{1} << bits) - 1);
    } else {
        if (hex && (*start == '-' || *start == '+')) return false;
        errno = 0;
        char* end = nullptr;
        const unsigned long long value = std::strtoull(start, &end, hex ? 16 : 10);
        if (end == start || errno == ERANGE || !MemConsumedAll(end)) return false;
        const uint64_t maximum = size == 8
            ? std::numeric_limits<uint64_t>::max()
            : (uint64_t{1} << (size * 8)) - 1;
        if (static_cast<uint64_t>(value) > maximum) return false;
        parsedBits = static_cast<uint64_t>(value);
    }

    bitsOut = parsedBits;
    sizeOut = size;
    return true;
}

// Explicit-validity hexadecimal address parser. Outputs are untouched on
// failure, so empty/malformed/overflowed text can never be coerced to VA 0;
// valid spellings such as "0", "000", and "0x0" still represent VA 0.
inline bool MemParseHexAddress(const char* text, uint64_t& addressOut) {
    const char* start = MemSkipAsciiSpace(text);
    if (!start || !*start || *start == '-' || *start == '+') return false;
    errno = 0;
    char* end = nullptr;
    const unsigned long long value = std::strtoull(start, &end, 16);
    if (end == start || errno == ERANGE || !MemConsumedAll(end)) return false;
    addressOut = static_cast<uint64_t>(value);
    return true;
}

// Interpret the raw low-order bits of `bits` as a real number for ordered
// (bigger/smaller) comparisons. Integers honour `unsignedMode`: when false they
// are sign-extended (so -1 < 0); when true they are zero-extended (so 0xFFFFFFFF
// reads as ~4.29e9, larger than 0). Float/Double ignore `unsignedMode`.
inline double MemAsNumber(int valueType, uint64_t bits, bool unsignedMode) {
    if (valueType == (int)MemValType::Float)  { float f;  std::memcpy(&f, &bits, 4); return (double)f; }
    if (valueType == (int)MemValType::Double) { double d; std::memcpy(&d, &bits, 8); return d; }
    switch (MemTypeSize(valueType)) {
        case 1: return unsignedMode ? (double)(uint8_t)bits  : (double)(int8_t)(uint8_t)bits;
        case 2: return unsignedMode ? (double)(uint16_t)bits : (double)(int16_t)(uint16_t)bits;
        case 4: return unsignedMode ? (double)(uint32_t)bits : (double)(int32_t)(uint32_t)bits;
        default:return unsignedMode ? (double)(uint64_t)bits : (double)(int64_t)bits;
    }
}

// Zero-/sign-extend the low `sz` bytes of `bits` to the full 64-bit width.
inline uint64_t MemZeroExt(uint64_t bits, size_t sz) {
    return sz >= 8 ? bits : (bits & ((1ull << (sz * 8)) - 1));
}
inline int64_t MemSignExt(uint64_t bits, size_t sz) {
    const int shift = (int)(64 - sz * 8);
    return shift <= 0 ? (int64_t)bits : ((int64_t)(bits << shift)) >> shift;
}

// a > b under the chosen interpretation. Integer types compare as integers (a
// double round-trip would lose precision above 2^53 for qwords); float/double
// compare by IEEE value.
inline bool MemGreater(int valueType, bool unsignedMode, uint64_t a, uint64_t b) {
    if (valueType == (int)MemValType::Float || valueType == (int)MemValType::Double)
        return MemAsNumber(valueType, a, unsignedMode) > MemAsNumber(valueType, b, unsignedMode);
    const size_t sz = MemTypeSize(valueType);
    return unsignedMode ? MemZeroExt(a, sz) > MemZeroExt(b, sz)
                        : MemSignExt(a, sz) > MemSignExt(b, sz);
}
// a < b under the chosen interpretation (same integer/float split as MemGreater).
inline bool MemLess(int valueType, bool unsignedMode, uint64_t a, uint64_t b) {
    if (valueType == (int)MemValType::Float || valueType == (int)MemValType::Double)
        return MemAsNumber(valueType, a, unsignedMode) < MemAsNumber(valueType, b, unsignedMode);
    const size_t sz = MemTypeSize(valueType);
    return unsignedMode ? MemZeroExt(a, sz) < MemZeroExt(b, sz)
                        : MemSignExt(a, sz) < MemSignExt(b, sz);
}

// Address-table rows have an explicit master switch. A disabled row must never
// mutate the target, even if its Freeze checkbox remains selected. Keeping this
// policy pure makes the safety invariant independently regression-testable.
inline constexpr bool MemAddressTableShouldWrite(bool attached, bool active, bool frozen) {
    return attached && active && frozen;
}

// Target identity is part of the write authority.  A debugger session generation
// changes on every successful attach/launch, and the PID protects against a
// malformed/reused generation value.  Rows captured for an earlier target must
// never become live merely because the new process happens to map the same VA.
inline constexpr bool MemAddressTableShouldWrite(bool attached, bool active, bool frozen,
                                                  uint64_t currentGeneration, uint32_t currentPid,
                                                  uint64_t ownerGeneration, uint32_t ownerPid) {
    return attached && active && frozen && DebugTargetIdentityMatches(
        { currentPid, currentGeneration }, { ownerPid, ownerGeneration });
}

// Memory ownership ends when execution is no longer backed by a live process.
// Debugger snapshots deliberately retain DbgState::Terminated for post-mortem UI,
// so callers must not equate "not Detached" with a usable memory target.
inline constexpr bool MemTargetSessionUsable(bool runningOrPaused,
                                              uint64_t generation, uint32_t pid) {
    return runningOrPaused && generation != 0 && pid != 0;
}

inline constexpr bool MemTargetSessionChanged(bool currentUsable,
                                               uint64_t currentGeneration, uint32_t currentPid,
                                               bool previousUsable,
                                               uint64_t previousGeneration, uint32_t previousPid) {
    return currentUsable != previousUsable ||
           currentGeneration != previousGeneration || currentPid != previousPid;
}

} // namespace ds
