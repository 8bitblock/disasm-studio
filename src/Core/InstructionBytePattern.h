#pragma once

#include "../Disasm/IDisassembler.h"
#include <Zydis/Zydis.h>
#include <array>
#include <cctype>
#include <span>
#include <string>
#include <vector>

namespace ds {

inline constexpr size_t kInstructionPatternByteLimit = 64 * 1024;
inline constexpr const char* kInstructionWildcardHelp =
    "Replaces relative branch operands and absolute / IP-relative memory addresses with ??. "
    "Keeps opcodes, registers, register-based offsets and immediate constants. "
    "Automatic wildcards support x86-16, x86 and x64.";

// Use the decoder's encoding offsets: trailing-byte heuristics corrupt prefixed
// branches and instructions whose memory displacement precedes an immediate.
inline bool InstructionBytePattern(const Instruction& in, Arch arch, bool wildcard,
                                   std::string& pattern, std::string& error) {
    pattern.clear(); error.clear();
    if (!in.length || in.length > kInstructionPatternByteLimit) {
        error = "Instruction bytes are unavailable or exceed the 64 KiB copy limit.";
        return false;
    }
    auto hex = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<uint8_t> bytes;
    bytes.reserve(in.length);
    for (size_t i = 0; i < in.bytes.size();) {
        if (std::isspace(static_cast<unsigned char>(in.bytes[i]))) { ++i; continue; }
        if (i + 1 >= in.bytes.size() || hex(in.bytes[i]) < 0 || hex(in.bytes[i + 1]) < 0 ||
            bytes.size() >= in.length) {
            error = "The instruction does not contain a complete set of literal bytes.";
            return false;
        }
        bytes.push_back(static_cast<uint8_t>((hex(in.bytes[i]) << 4) | hex(in.bytes[i + 1])));
        i += 2;
        if (i < in.bytes.size() && !std::isspace(static_cast<unsigned char>(in.bytes[i]))) {
            error = "Instruction byte tokens must be separated by whitespace.";
            return false;
        }
    }
    if (bytes.size() != in.length) {
        error = "The displayed instruction bytes are incomplete; refresh the view before copying.";
        return false;
    }
    std::array<bool, ZYDIS_MAX_INSTRUCTION_LENGTH> masked{};
    if (wildcard) {
        if (!ArchIsX86(arch)) {
            error = "Automatic wildcards support x86-16, x86 and x64. Copy literal bytes for this architecture.";
            return false;
        }
        ZydisDecoder decoder;
        const ZydisMachineMode mode = arch == Arch::X86_16 ? ZYDIS_MACHINE_MODE_REAL_16
            : arch == Arch::X86 ? ZYDIS_MACHINE_MODE_LEGACY_32 : ZYDIS_MACHINE_MODE_LONG_64;
        const ZydisStackWidth width = arch == Arch::X86_16 ? ZYDIS_STACK_WIDTH_16
            : arch == Arch::X86 ? ZYDIS_STACK_WIDTH_32 : ZYDIS_STACK_WIDTH_64;
        ZydisDecodedInstruction decoded{};
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
        if (ZYAN_FAILED(ZydisDecoderInit(&decoder, mode, width)) ||
            ZYAN_FAILED(ZydisDecoderDecodeFull(&decoder, bytes.data(), bytes.size(), &decoded, operands)) ||
            decoded.length != bytes.size()) {
            error = "Automatic wildcards require one complete, valid x86 instruction.";
            return false;
        }
        auto mask = [&](uint8_t offset, uint8_t bits) {
            if (bits && bits % 8 == 0 && offset <= decoded.length && bits / 8 <= decoded.length - offset)
                for (size_t i = offset; i < size_t(offset) + bits / 8; ++i) masked[i] = true;
        };
        for (const auto& immediate : decoded.raw.imm)
            if (immediate.is_relative) mask(immediate.offset, immediate.size);
        for (size_t i = 0; i < decoded.operand_count_visible; ++i) {
            const auto& op = operands[i];
            if (op.type != ZYDIS_OPERAND_TYPE_MEMORY || !op.mem.disp.has_displacement) continue;
            const bool absolute = op.mem.base == ZYDIS_REGISTER_NONE && op.mem.index == ZYDIS_REGISTER_NONE;
            const bool ipRelative = op.mem.base == ZYDIS_REGISTER_RIP || op.mem.base == ZYDIS_REGISTER_EIP;
            // FS/GS absolute offsets are thread/object offsets, not fixed image addresses.
            const bool segmented = op.mem.segment == ZYDIS_REGISTER_FS || op.mem.segment == ZYDIS_REGISTER_GS;
            if (ipRelative || (absolute && !segmented)) mask(decoded.raw.disp.offset, decoded.raw.disp.size);
        }
    }
    static constexpr char digits[] = "0123456789ABCDEF";
    pattern.reserve(bytes.size() * 3 - 1);
    for (size_t i = 0; i < bytes.size(); ++i) {
        if (i) pattern += ' ';
        if (wildcard && masked[i]) pattern += "??";
        else { pattern += digits[bytes[i] >> 4]; pattern += digits[bytes[i] & 15]; }
    }
    return true;
}

// Callers provide exactly the selected rows, in address order. Gaps are separate
// lines, never hidden unselected bytes or an invented contiguous scan pattern.
inline bool InstructionSelectionBytePattern(std::span<const Instruction> instructions,
                                            Arch arch, bool wildcard,
                                            std::string& pattern, std::string& error) {
    pattern.clear(); error.clear();
    if (instructions.empty()) { error = "Select an instruction to copy."; return false; }
    std::string result;
    size_t byteCount = 0;
    const Instruction* previous = nullptr;
    for (const auto& in : instructions) {
        if (in.length > kInstructionPatternByteLimit - byteCount) {
            error = "Select at most 64 KiB of instruction bytes to copy.";
            return false;
        }
        if (previous && (previous->address > UINT64_MAX - previous->length ||
                         in.address < previous->address + previous->length)) {
            error = "The selected instructions overlap or are not ordered. Refresh the selection.";
            return false;
        }
        std::string row;
        if (!InstructionBytePattern(in, arch, wildcard, row, error)) return false;
        if (previous) result += in.address == previous->address + previous->length ? ' ' : '\n';
        result += row;
        byteCount += in.length;
        previous = &in;
    }
    pattern = std::move(result);
    return true;
}

} // namespace ds
