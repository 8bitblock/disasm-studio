#pragma once
//
// Assembler.h
// Thin wrapper over Keystone for turning assembly text into machine code, used
// by the Binary View's live "Patch" feature (type `mov rax, 1` -> bytes).
//
#include "IDisassembler.h"   // Arch
#include <cstdint>
#include <algorithm>
#include <array>
#include <new>
#include <stdexcept>
#include <string>
#include <vector>

namespace ds {

struct AsmResult {
    bool                 ok = false;
    std::vector<uint8_t> bytes;
    size_t               count = 0;   // number of instructions encoded
    std::string          error;       // human-readable message when !ok
};

// Encoding consumes the same machine configuration as decoding. The decoder
// engine is immaterial; byte order and ISA restrictions must never be dropped.
AsmResult Assemble(const DecoderConfig& config, const std::string& text, uint64_t address);

inline bool PatchEncodingConfigurationValid(const DecoderConfig& config,
                                             std::string* error = nullptr) {
    const char* reason = nullptr;
    if (config.byteOrder != ByteOrder::Little && config.byteOrder != ByteOrder::Big)
        reason = "unknown instruction byte order";
    else if (ArchIsX86(config.arch) && config.byteOrder != ByteOrder::Little)
        reason = "x86 instructions require little-endian byte order";
    else if (config.features.mipsMicro)
        reason = "microMIPS patch encoding is unsupported";
    else if ((config.features.armV8 || config.features.armMClass) && !ArchIsArm(config.arch))
        reason = "ARM ISA features require an ARM target";
    else if (config.features.armMClass && config.arch != Arch::THUMB)
        reason = "ARM M-class instructions require Thumb mode";
    if (error) *error = reason ? reason : "";
    return reason == nullptr;
}

inline bool PatchAssemblerAvailable(const DecoderConfig& config, std::string* error = nullptr) {
    if (!PatchEncodingConfigurationValid(config, error)) return false;
    const char* reason = nullptr;
    if (!ArchSupportsAssembler(config.arch))
        reason = "patch assembler supports x86 / x64 / ARM / Thumb / ARM64 only";
    else if (config.features.armMClass)
        reason = "Keystone cannot enforce the requested ARM M-class instruction set; use checked Hex bytes";
    if (error) *error = reason ? reason : "";
    return reason == nullptr;
}

inline AsmResult Assemble(Arch arch, const std::string& text, uint64_t address) {
    DecoderConfig config; config.arch = arch;
    return Assemble(config, text, address);
}

// Produce an exact-length architectural NOP sequence. Fixed-width ISAs reject
// a length that would split an instruction; callers must not fall back to x86
// 0x90 bytes on ARM-family images.
inline bool ArchitectureNopFill(const DecoderConfig& config, size_t length, std::vector<uint8_t>& out,
                                std::string* error = nullptr) {
    out.clear();
    if (!PatchEncodingConfigurationValid(config, error)) return false;
    const Arch arch = config.arch;
    const uint8_t* pattern = nullptr;
    size_t width = 0;
    static constexpr uint8_t x86[]   = { 0x90 };
    static constexpr uint8_t arm[]   = { 0x00, 0xF0, 0x20, 0xE3 }; // architectural nop
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
    // Patterns describe one instruction in little-endian order. Reverse each
    // instruction independently, never an entire sequence (Thumb uses halfwords).
    std::array<uint8_t, 4> instruction{};
    std::copy_n(pattern, width, instruction.begin());
    if (config.byteOrder == ByteOrder::Big)
        std::reverse(instruction.begin(), instruction.begin() + width);
    try {
        std::vector<uint8_t> fill(length);
        for (size_t offset = 0; offset < length; offset += width)
            std::copy_n(instruction.begin(), width, fill.begin() + offset);
        out.swap(fill);
    } catch (const std::bad_alloc&) {
        if (error) *error = "not enough memory to generate NOP padding";
        return false;
    } catch (const std::length_error&) {
        if (error) *error = "NOP padding exceeds the container limit";
        return false;
    }
    if (error) error->clear();
    return true;
}

inline bool PadWithArchitectureNops(const DecoderConfig& config, std::vector<uint8_t>& bytes,
                                    size_t targetLength, std::string* error = nullptr) {
    if (!PatchEncodingConfigurationValid(config, error)) return false;
    if (bytes.size() % ArchInstructionAlignment(config) != 0) {
        if (error) *error = "encoded bytes end inside an instruction alignment unit";
        return false;
    }
    if (bytes.size() > targetLength) {
        if (error) *error = "encoded bytes exceed the requested span";
        return false;
    }
    std::vector<uint8_t> fill;
    if (!ArchitectureNopFill(config, targetLength - bytes.size(), fill, error)) return false;
    try { bytes.insert(bytes.end(), fill.begin(), fill.end()); }
    catch (const std::bad_alloc&) {
        if (error) *error = "not enough memory to pad the patch";
        return false;
    } catch (const std::length_error&) {
        if (error) *error = "padded patch exceeds the container limit";
        return false;
    }
    return true;
}

// Compatibility for callers which explicitly want the historical little-endian
// default. Production image patching passes DecoderConfig instead.
inline bool ArchitectureNopFill(Arch arch, size_t length, std::vector<uint8_t>& out,
                                std::string* error = nullptr) {
    DecoderConfig config; config.arch = arch;
    return ArchitectureNopFill(config, length, out, error);
}
inline bool PadWithArchitectureNops(Arch arch, std::vector<uint8_t>& bytes,
                                    size_t length, std::string* error = nullptr) {
    DecoderConfig config; config.arch = arch;
    return PadWithArchitectureNops(config, bytes, length, error);
}

} // namespace ds
