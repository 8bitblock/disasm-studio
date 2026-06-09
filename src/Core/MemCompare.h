#pragma once
//
// MemCompare.h
// Pure, header-only numeric interpretation + ordered comparison of a raw
// little-endian value read from process memory, shared by the Memory Tools
// scanner. Integer values can be interpreted as SIGNED or UNSIGNED (the scanner
// exposes this as a mode), float/double always use their IEEE value. Kept free of
// ImGui/Win32 deps so the compare logic is unit-testable with cl.
//
#include <cstdint>
#include <cstring>

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

// a > b under the chosen interpretation.
inline bool MemGreater(int valueType, bool unsignedMode, uint64_t a, uint64_t b) {
    return MemAsNumber(valueType, a, unsignedMode) > MemAsNumber(valueType, b, unsignedMode);
}
// a < b under the chosen interpretation.
inline bool MemLess(int valueType, bool unsignedMode, uint64_t a, uint64_t b) {
    return MemAsNumber(valueType, a, unsignedMode) < MemAsNumber(valueType, b, unsignedMode);
}

} // namespace ds
