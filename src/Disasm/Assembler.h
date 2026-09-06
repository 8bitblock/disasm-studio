#pragma once
//
// Assembler.h
// Thin wrapper over Keystone for turning assembly text into machine code, used
// by the Binary View's live "Patch" feature (type `mov rax, 1` -> bytes).
//
#include "IDisassembler.h"   // Arch
#include <cstdint>
#include <string>
#include <vector>

namespace ds {

struct AsmResult {
    bool                 ok = false;
    std::vector<uint8_t> bytes;
    size_t               count = 0;   // number of instructions encoded
    std::string          error;       // human-readable message when !ok
};

// Assemble one or more instructions (';' or newline separated) for `arch`,
// resolving relative operands against `address`. Intel syntax.
AsmResult Assemble(Arch arch, const std::string& text, uint64_t address);

// Produce an exact-length architectural NOP sequence. Fixed-width ISAs reject
// a length that would split an instruction; callers must not fall back to x86
// 0x90 bytes on ARM-family images.
inline bool ArchitectureNopFill(Arch arch, size_t length, std::vector<uint8_t>& out,
                                std::string* error = nullptr) {
    out.clear();
    const uint8_t* pattern = nullptr;
    size_t width = 0;
    static constexpr uint8_t x86[]   = { 0x90 };
    static constexpr uint8_t arm[]   = { 0x00, 0xF0, 0x20, 0xE3 }; // mov r0,r0
    static constexpr uint8_t thumb[] = { 0x00, 0xBF };             // nop
    static constexpr uint8_t arm64[] = { 0x1F, 0x20, 0x03, 0xD5 };// nop
    switch (arch) {
        case Arch::X86_16: case Arch::X86: case Arch::X64: pattern = x86; width = sizeof(x86); break;
        case Arch::ARM:     pattern = arm;   width = sizeof(arm); break;
        case Arch::THUMB:   pattern = thumb; width = sizeof(thumb); break;
        case Arch::ARM64:   pattern = arm64; width = sizeof(arm64); break;
        default:
            if (error) *error = std::string("NOP fill is unsupported for ") + ArchName(arch);
            return false;
    }
    if (length % width != 0) {
        if (error) *error = std::string("NOP fill length must be a multiple of ") +
                            std::to_string(width) + " bytes for " + ArchName(arch);
        return false;
    }
    out.reserve(length);
    while (out.size() < length) out.insert(out.end(), pattern, pattern + width);
    if (error) error->clear();
    return true;
}

inline bool PadWithArchitectureNops(Arch arch, std::vector<uint8_t>& bytes,
                                    size_t targetLength, std::string* error = nullptr) {
    if (bytes.size() > targetLength) {
        if (error) *error = "encoded bytes exceed the requested span";
        return false;
    }
    std::vector<uint8_t> fill;
    if (!ArchitectureNopFill(arch, targetLength - bytes.size(), fill, error)) return false;
    bytes.insert(bytes.end(), fill.begin(), fill.end());
    return true;
}

} // namespace ds
