#pragma once

#include "CFG.h"
#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

namespace ds {

// A lossless, typed boundary between decoding and analysis. These operations
// describe machine effects, not C expressions: widths, subregister slices,
// accesses, flag masks and unsupported behavior survive subsequent rendering.
// Unknown means the value transformation has not been lifted, even when its
// decoder-reported inputs and outputs are usable for conservative data flow.
enum class IntermediateOpcode : uint8_t {
    Unknown, Copy, Address, ZeroExtend, SignExtend, Add, Subtract,
    And, Or, Xor, Not, Negate, Compare, Test, ShiftLeft, ShiftRight,
    ArithmeticShiftRight, Call, Return, Branch, NoOperation
};
enum class IntermediateSignedness : uint8_t { Unspecified, Unsigned, Signed };

struct RegisterSlice {
    std::string name;
    std::string storage;
    uint16_t widthBits = 0;
    uint16_t offsetBits = 0;
    bool zeroExtendsStorage = false;
};

struct IntermediateOperand {
    TypedOperand decoded;
    RegisterSlice reg;
    // LEA computes an address; it does not dereference its memory operand.
    bool addressOnly = false;
};

struct IntermediateOperation {
    uint64_t sourceVA = 0;
    uint32_t sourceLength = 0;
    std::string instructionText; // retained for unsupported operation rendering
    Arch architecture = Arch::X64;
    DecompileABI callingConvention = DecompileABI::Unknown;
    IntermediateOpcode opcode = IntermediateOpcode::Unknown;
    IntermediateSignedness signedness = IntermediateSignedness::Unspecified;
    uint16_t widthBits = 0;
    FlowInfo flow;
    std::vector<IntermediateOperand> operands;
    std::vector<std::string> registersRead;
    std::vector<std::string> registersWritten;
    uint64_t flagsRead = 0;
    uint64_t flagsWritten = 0; // includes potential/undefined writes
    bool readsMemory = false;
    bool writesMemory = false;
    bool unknownRegisterEffects = false;
    bool unknownMemoryEffects = false;
    bool unknownFlagEffects = false;
    bool atomic = false;
    bool repeated = false;
    bool typedOperandsAvailable = false;
};

inline RegisterSlice DescribeRegisterSlice(std::string name, uint16_t width,
                                           Arch architecture) {
    std::transform(name.begin(), name.end(), name.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    RegisterSlice result{ name, name, width };
    if (!ArchIsX86(architecture)) return result;
    static constexpr const char* names[][5] = {
        {"rax", "eax", "ax", "al", "ah"}, {"rcx", "ecx", "cx", "cl", "ch"},
        {"rdx", "edx", "dx", "dl", "dh"}, {"rbx", "ebx", "bx", "bl", "bh"},
        {"rsp", "esp", "sp", "spl", ""}, {"rbp", "ebp", "bp", "bpl", ""},
        {"rsi", "esi", "si", "sil", ""}, {"rdi", "edi", "di", "dil", ""}
    };
    for (const auto& family : names) {
        for (size_t part = 0; part < 5; ++part) {
            if (name.empty() || name != family[part]) continue;
            result.storage = architecture == Arch::X64 ? family[0] : family[1];
            const uint16_t inferred = part == 0 ? 64 : part == 1 ? 32 : part == 2 ? 16 : 8;
            if (!result.widthBits) result.widthBits = inferred;
            result.offsetBits = part == 4 ? 8 : 0;
            result.zeroExtendsStorage = architecture == Arch::X64 && part == 1;
            return result;
        }
    }
    if (architecture == Arch::X64) {
        for (unsigned i = 8; i < 16; ++i) {
            const std::string base = "r" + std::to_string(i);
            if (name == base || name == base + "d" || name == base + "w" || name == base + "b") {
                result.storage = base;
                if (!result.widthBits) result.widthBits = name == base ? 64 : name.back() == 'd' ? 32 : name.back() == 'w' ? 16 : 8;
                result.zeroExtendsStorage = name == base + "d";
                return result;
            }
        }
    }
    return result;
}

inline IntermediateOperation LiftInstructionSemantics(
    const Instruction& instruction, Arch architecture,
    DecompileABI abi = DecompileABI::Unknown) {
    IntermediateOperation result;
    result.sourceVA = instruction.address;
    result.sourceLength = instruction.length;
    result.instructionText = InstructionText(instruction);
    result.architecture = architecture;
    result.callingConvention = abi;
    result.flow = instruction.flow;
    result.registersRead = instruction.registersRead;
    result.registersWritten = instruction.registersWritten;
    result.flagsRead = instruction.flagsRead;
    result.flagsWritten = instruction.flagsWritten;
    result.typedOperandsAvailable = !instruction.typedOperands.empty();
    result.repeated = instruction.isRepString;
    for (InstructionPrefix prefix : instruction.prefixes) {
        result.atomic |= prefix == InstructionPrefix::Lock;
        result.repeated |= prefix == InstructionPrefix::Rep ||
            prefix == InstructionPrefix::Repe || prefix == InstructionPrefix::Repne;
    }
    std::string mnemonic = instruction.mnemonic;
    std::transform(mnemonic.begin(), mnemonic.end(), mnemonic.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (ArchIsX86_32Or64(architecture) && !result.repeated) {
        if (mnemonic == "mov" || mnemonic == "movabs") result.opcode = IntermediateOpcode::Copy;
        else if (mnemonic == "lea") result.opcode = IntermediateOpcode::Address;
        else if (mnemonic == "movzx") result.opcode = IntermediateOpcode::ZeroExtend;
        else if (mnemonic == "movsx" || mnemonic == "movsxd") result.opcode = IntermediateOpcode::SignExtend;
        else if (mnemonic == "add") result.opcode = IntermediateOpcode::Add;
        else if (mnemonic == "sub") result.opcode = IntermediateOpcode::Subtract;
        else if (mnemonic == "and") result.opcode = IntermediateOpcode::And;
        else if (mnemonic == "or") result.opcode = IntermediateOpcode::Or;
        else if (mnemonic == "xor") result.opcode = IntermediateOpcode::Xor;
        else if (mnemonic == "not") result.opcode = IntermediateOpcode::Not;
        else if (mnemonic == "neg") result.opcode = IntermediateOpcode::Negate;
        else if (mnemonic == "cmp") result.opcode = IntermediateOpcode::Compare;
        else if (mnemonic == "test") result.opcode = IntermediateOpcode::Test;
        else if (mnemonic == "shl" || mnemonic == "sal") result.opcode = IntermediateOpcode::ShiftLeft;
        else if (mnemonic == "shr") result.opcode = IntermediateOpcode::ShiftRight;
        else if (mnemonic == "sar") result.opcode = IntermediateOpcode::ArithmeticShiftRight;
        else if (mnemonic == "nop") result.opcode = IntermediateOpcode::NoOperation;
    }
    if (InstructionIsCall(instruction)) result.opcode = IntermediateOpcode::Call;
    else if (InstructionIsReturn(instruction)) result.opcode = IntermediateOpcode::Return;
    else if (InstructionEndsBlock(instruction)) result.opcode = IntermediateOpcode::Branch;
    if (result.opcode == IntermediateOpcode::SignExtend || result.opcode == IntermediateOpcode::ArithmeticShiftRight)
        result.signedness = IntermediateSignedness::Signed;
    else if (result.opcode == IntermediateOpcode::ZeroExtend || result.opcode == IntermediateOpcode::ShiftRight)
        result.signedness = IntermediateSignedness::Unsigned;
    auto addRegister = [](std::vector<std::string>& registers, const std::string& name) {
        if (!name.empty() && std::find(registers.begin(), registers.end(), name) == registers.end())
            registers.push_back(name);
    };
    for (const TypedOperand& operand : instruction.typedOperands) {
        IntermediateOperand lifted;
        lifted.decoded = operand;
        if (operand.kind == OperandKind::Register) {
            lifted.reg = DescribeRegisterSlice(operand.registerName, operand.widthBits, architecture);
            if (OperandReads(operand.access)) addRegister(result.registersRead, operand.registerName);
            if (OperandWrites(operand.access)) addRegister(result.registersWritten, operand.registerName);
            if (operand.access == OperandAccess::None) result.unknownRegisterEffects = true;
        } else if (operand.kind == OperandKind::Memory) {
            lifted.addressOnly = result.opcode == IntermediateOpcode::Address;
            addRegister(result.registersRead, operand.baseRegister);
            addRegister(result.registersRead, operand.indexRegister);
            addRegister(result.registersRead, operand.segmentRegister);
            if (!lifted.addressOnly) {
                result.readsMemory |= OperandReads(operand.access);
                result.writesMemory |= OperandWrites(operand.access);
                result.unknownMemoryEffects |= operand.access == OperandAccess::None;
            }
        } else if (operand.kind == OperandKind::Invalid) {
            result.unknownRegisterEffects = result.unknownMemoryEffects = true;
        }
        result.operands.push_back(std::move(lifted));
    }
    if (!result.operands.empty()) {
        const auto& first = result.operands.front();
        result.widthBits = first.decoded.kind == OperandKind::Register
            ? first.reg.widthBits : first.decoded.widthBits;
    }
    // The value operations below have architectural flag effects even when a
    // compatibility decoder supplies typed operands without its flag masks.
    if (ArchIsX86_32Or64(architecture) && !result.flagsWritten) {
        constexpr uint64_t arithmeticFlags = SemanticFlagBit(SemanticFlag::Carry) |
            SemanticFlagBit(SemanticFlag::Parity) | SemanticFlagBit(SemanticFlag::AuxCarry) |
            SemanticFlagBit(SemanticFlag::Zero) | SemanticFlagBit(SemanticFlag::Sign) |
            SemanticFlagBit(SemanticFlag::Overflow);
        switch (result.opcode) {
            case IntermediateOpcode::Add: case IntermediateOpcode::Subtract:
            case IntermediateOpcode::And: case IntermediateOpcode::Or:
            case IntermediateOpcode::Xor: case IntermediateOpcode::Negate:
            case IntermediateOpcode::Compare: case IntermediateOpcode::Test:
                result.flagsWritten = arithmeticFlags;
                break;
            case IntermediateOpcode::ShiftLeft: case IntermediateOpcode::ShiftRight:
            case IntermediateOpcode::ArithmeticShiftRight: {
                bool zeroCount = false;
                if (result.operands.size() >= 2 &&
                    result.operands[1].decoded.kind == OperandKind::Immediate && result.widthBits) {
                    const uint64_t mask = result.widthBits == 64 ? 63 : 31;
                    zeroCount = (result.operands[1].decoded.immediate & mask) == 0;
                }
                if (!zeroCount) result.flagsWritten = arithmeticFlags;
                break;
            }
            default: break;
        }
    }
    // A call's callee is outside the decoded instruction's effect description.
    // Keep that boundary explicit; ABI-aware consumers may refine registers.
    if (result.opcode == IntermediateOpcode::Call) {
        result.unknownRegisterEffects = result.unknownMemoryEffects = result.unknownFlagEffects = true;
    } else if (!result.typedOperandsAvailable && instruction.registersRead.empty() &&
               instruction.registersWritten.empty() && result.opcode != IntermediateOpcode::NoOperation) {
        result.unknownRegisterEffects = result.unknownMemoryEffects = result.unknownFlagEffects = true;
    }
    if (ArchIsX86_32Or64(architecture)) {
        result.writesMemory |= mnemonic == "push" || result.opcode == IntermediateOpcode::Call;
        result.readsMemory |= mnemonic == "pop" || result.opcode == IntermediateOpcode::Return;
        // String instructions often have no visible operands. The implicit
        // memory walk must not disappear merely because register metadata is
        // present, and REP may perform zero or many iterations.
        if (result.repeated) result.unknownMemoryEffects = true;
        if (!result.typedOperandsAvailable) {
            const bool stringWidth = !mnemonic.empty() &&
                (mnemonic.back() == 'b' || mnemonic.back() == 'w' || mnemonic.back() == 'd' || mnemonic.back() == 'q');
            if (stringWidth) {
                const std::string base = mnemonic.substr(0, mnemonic.size()-1);
                result.writesMemory |= base == "movs" || base == "stos" || base == "ins";
                result.readsMemory |= base == "movs" || base == "lods" || base == "cmps" || base == "scas" || base == "outs";
            }
        }
    }
    // Decoder metadata identifies effects, not necessarily a supported value
    // transform. Do not promote mnemonic-only text into a typed value operation.
    if (!result.typedOperandsAvailable && result.opcode != IntermediateOpcode::Call &&
        result.opcode != IntermediateOpcode::Return && result.opcode != IntermediateOpcode::Branch &&
        result.opcode != IntermediateOpcode::NoOperation)
        result.opcode = IntermediateOpcode::Unknown;
    return result;
}

} // namespace ds
