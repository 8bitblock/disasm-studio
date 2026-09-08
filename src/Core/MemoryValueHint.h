#pragma once

#include "InstructionReference.h"
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <string>

namespace ds {

struct MemoryValueReference {
    uint64_t address = 0;
    uint16_t widthBits = 0;
};

// Only decoder-proven scalar memory operands. An immediate or LEA is an
// address/value computation, not evidence that memory at that number is read.
inline bool TryGetMemoryValueReference(const Instruction& in,
                                       MemoryValueReference& reference) {
    reference = {};
    if (in.mnemonic == "lea") return false;
    for (const auto& operand : in.typedOperands) {
        if (!OperandReads(operand.access) && !OperandWrites(operand.access)) continue;
        if (operand.widthBits != 8 && operand.widthBits != 16 &&
            operand.widthBits != 32 && operand.widthBits != 64) continue;
        uint64_t address = 0;
        if (!TryGetStaticMemoryAddress(in, operand, address) ||
            ClampAddressableBytes(address, operand.widthBits / 8) != operand.widthBits / 8) continue;
        reference = {address, operand.widthBits};
        return true;
    }
    return false;
}

struct MemoryValueHint {
    std::string text;
    std::string tooltip;
};

// A full-width read is mandatory: missing bytes must never become zeroes.
// Integer signedness and floating point interpretations are labelled, because
// the memory operand width does not prove the application's variable type.
inline MemoryValueHint FormatMemoryValueHint(MemoryValueReference reference,
                                             const uint8_t* bytes, size_t count,
                                             ByteOrder order, bool live) {
    if (reference.widthBits != 8 && reference.widthBits != 16 &&
        reference.widthBits != 32 && reference.widthBits != 64) return {};
    const size_t width = reference.widthBits / 8;
    const char* source = live ? "LIVE" : "FILE";
    char text[200];
    MemoryValueHint hint;
    if (!bytes || count < width) {
        std::snprintf(text, sizeof(text), "%s [0x%llX] = unavailable (u%u)",
                      source, (unsigned long long)reference.address, reference.widthBits);
        hint.text = text;
        hint.tooltip = live ? "The complete operand could not be read from this process session."
                            : "The complete operand has no backing bytes in this file. Runtime memory may have a value here.";
        return hint;
    }
    uint64_t value = 0;
    for (size_t i = 0; i < width; ++i) {
        const size_t at = order == ByteOrder::Big ? width - i - 1 : i;
        value |= static_cast<uint64_t>(bytes[at]) << (i * 8);
    }
    std::snprintf(text, sizeof(text), "%s [0x%llX] = %llu (u%u, 0x%0*llX)",
                  source, (unsigned long long)reference.address,
                  (unsigned long long)value, reference.widthBits,
                  static_cast<int>(width * 2), (unsigned long long)value);
    hint.text = text;
    hint.tooltip = live ? "Process memory sample; refreshes about every 250 ms while visible.\n"
                        : "Bytes in the loaded file, including applied FILE patches; not a runtime value.\n";
    hint.tooltip += "Width comes from the decoded memory operand. The program's variable type is unknown.\n";
    const uint64_t sign = uint64_t{1} << (reference.widthBits - 1);
    // Compute negative magnitude without implementation-defined signed casts,
    // including the full int64 minimum.
    const uint64_t mask = reference.widthBits == 64 ? UINT64_MAX : (sign * 2 - 1);
    const std::string signedValue = (value & sign)
        ? "-" + std::to_string(((~value) & mask) + 1) : std::to_string(value);
    hint.tooltip += "Signed i" + std::to_string(reference.widthBits) + ": " + signedValue;
    if (width == 4) {
        const uint32_t bits = static_cast<uint32_t>(value);
        float number = 0; std::memcpy(&number, &bits, sizeof(number));
        std::snprintf(text, sizeof(text), "\nIEEE float32 interpretation: %.9g", static_cast<double>(number));
        hint.tooltip += text;
    } else if (width == 8) {
        double number = 0; std::memcpy(&number, &value, sizeof(number));
        std::snprintf(text, sizeof(text), "\nIEEE float64 interpretation: %.17g", number);
        hint.tooltip += text;
    }
    hint.tooltip += "\nThis is the stored value, not the result of executing the instruction.";
    return hint;
}

} // namespace ds
