#pragma once

#include "BinaryFile.h"
#include "CodeByteSignature.h"
#include "../Disasm/IDisassembler.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <utility>
#include <vector>

namespace ds {

struct CodeByteRelocationSpan {
    uint64_t address = 0;
    uint8_t width = 0;
};

inline std::vector<CodeByteRelocationSpan> NormalizeCodeByteRelocations(
    std::vector<CodeByteRelocationSpan> relocations) {
    std::sort(relocations.begin(), relocations.end(),
              [](const CodeByteRelocationSpan& a,
                 const CodeByteRelocationSpan& b) {
                  return a.address < b.address;
              });
    std::vector<CodeByteRelocationSpan> normalized;
    normalized.reserve(relocations.size());
    for (const CodeByteRelocationSpan& relocation : relocations) {
        if (normalized.empty() ||
            normalized.back().address != relocation.address) {
            normalized.push_back(relocation);
            continue;
        }
        // Repeated rows are one lookup. An unknown type at the same address
        // poisons that address; otherwise retain the widest known write.
        if (!normalized.back().width || !relocation.width)
            normalized.back().width = 0;
        else
            normalized.back().width = (std::max)(
                normalized.back().width, relocation.width);
    }
    return normalized;
}

// Pre-indexes the bounded PE base-relocation table once, then captures complete
// decoder-confirmed instructions. Relative operands remain compared; an
// instruction touched by any base relocation is unavailable rather than masked.
class CodeByteSignatureBuilder {
public:
    explicit CodeByteSignatureBuilder(const BinaryFile& binary)
        : binary_(binary) {
        // A mapped-image document already contains the exact post-loader bytes
        // captured from this process. Revalidation compares those bytes as-is.
        if (binary.isMappedImage()) return;
        relocations_.reserve(binary.relocations().size());
        for (const auto& [address, type] : binary.relocations())
            relocations_.push_back({address, relocationWidth(type)});
        relocations_ = NormalizeCodeByteRelocations(std::move(relocations_));
    }

    CodeByteSignature capture(IDisassembler& decoder,
                              uint64_t address) const {
        CodeByteSignature result;
        size_t available = 0;
        const uint8_t* bytes = binary_.ptrFromVA(address, available);
        if (!bytes || !available) return result;
        Instruction instruction;
        if (!decoder.decodeOne(bytes, available, address, instruction) ||
            !instruction.length || instruction.length > kCodeByteSignatureMax ||
            instruction.length > available)
            return result;

        result.length = static_cast<uint8_t>(instruction.length);
        std::memcpy(result.expected.data(), bytes, result.length);
        std::fill_n(result.compareMask.begin(), result.length, uint8_t{0xFF});

        const uint64_t start = address;
        if (result.length > (std::numeric_limits<uint64_t>::max)() - start)
            return {};
        const uint64_t end = start + result.length;
        const uint64_t searchStart = start > 7 ? start - 7 : 0;
        auto relocation = std::lower_bound(
            relocations_.begin(), relocations_.end(), searchStart,
            [](const CodeByteRelocationSpan& value, uint64_t key) {
                return value.address < key;
            });
        for (; relocation != relocations_.end() && relocation->address < end;
             ++relocation) {
            if (!relocation->width) {
                // The width is architecture-specific. Because its address lies
                // within the largest supported relocation overlap window, the
                // instruction cannot be proven byte-current.
                return {};
            }
            if (relocation->address >
                (std::numeric_limits<uint64_t>::max)() - relocation->width) {
                return {};
            }
            const uint64_t relocationEnd = relocation->address + relocation->width;
            if (relocationEnd <= start) continue;
            if (relocation->address < end && relocationEnd > start)
                return {};
        }
        if (!ValidCodeByteSignature(result)) return {};
        return result;
    }

private:
    static uint8_t relocationWidth(int type) noexcept {
        switch (type) {
        case 1: return 2; // IMAGE_REL_BASED_HIGH
        case 2: return 2; // IMAGE_REL_BASED_LOW
        case 3: return 4; // IMAGE_REL_BASED_HIGHLOW
        case 4: return 2; // IMAGE_REL_BASED_HIGHADJ location
        case 10: return 8; // IMAGE_REL_BASED_DIR64
        default: return 0;
        }
    }

    const BinaryFile& binary_;
    std::vector<CodeByteRelocationSpan> relocations_;
};

} // namespace ds
