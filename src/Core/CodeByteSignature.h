#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace ds {

// Bounded, architecture-independent bytes for one fully decoded instruction.
// Every byte of the decoded instruction is authoritative. A zero compare-mask
// byte makes the signature invalid; producers exclude any instruction touched
// by a base relocation rather than wildcarding potentially executable bytes.
inline constexpr size_t kCodeByteSignatureMax = 16;

struct CodeByteSignature {
    uint8_t length = 0;
    std::array<uint8_t, kCodeByteSignatureMax> expected{};
    std::array<uint8_t, kCodeByteSignatureMax> compareMask{};
};

inline bool ValidCodeByteSignature(const CodeByteSignature& signature) noexcept {
    if (!signature.length || signature.length > kCodeByteSignatureMax)
        return false;
    for (size_t i = 0; i < signature.length; ++i)
        if (!signature.compareMask[i]) return false;
    return true;
}

inline bool CodeByteSignatureMatches(const CodeByteSignature& signature,
                                     const uint8_t* actual,
                                     size_t actualSize) noexcept {
    if (!actual || actualSize < signature.length ||
        !ValidCodeByteSignature(signature))
        return false;
    for (size_t i = 0; i < signature.length; ++i) {
        if (signature.compareMask[i] &&
            signature.expected[i] != actual[i])
            return false;
    }
    return true;
}

inline bool CodeByteSignaturesEqual(const CodeByteSignature& a,
                                    const CodeByteSignature& b) noexcept {
    if (a.length > kCodeByteSignatureMax ||
        b.length > kCodeByteSignatureMax || a.length != b.length)
        return false;
    for (size_t i = 0; i < a.length; ++i) {
        if (a.expected[i] != b.expected[i] ||
            a.compareMask[i] != b.compareMask[i])
            return false;
    }
    return true;
}

} // namespace ds
