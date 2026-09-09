#pragma once
// Small, decoder-typed observations shared by string tracing and name guessing.
// These identify machine operations, never the meaning of a field or message.
#include "InstructionSemantics.h"
#include <unordered_map>

namespace ds {
enum class StringActionKind : uint8_t { Write, Add, Subtract };
struct StringActionMutation {
    uint64_t instructionVA = 0;
    uint64_t producerVA = 0;
    bool producerVAValid = false;
    StringActionKind kind = StringActionKind::Write;
    std::string instruction;
    std::string evidence;
};

inline bool StringActionStackRegister(const std::string& name) {
    return name == "rsp" || name == "esp" || name == "sp" ||
           name == "rbp" || name == "ebp" || name == "bp";
}
inline const char* StringActionKindName(StringActionKind kind) {
    switch (kind) {
        case StringActionKind::Add: return "addition to stored value";
        case StringActionKind::Subtract: return "subtraction from stored value";
        default: return "memory write";
    }
}

// Track at most twelve instructions within a single basic block. A call,
// unsupported effect, register overwrite, width change or address-only LEA
// cannot establish arithmetic-to-store lineage. Stack mechanics are excluded.
inline std::vector<StringActionMutation> FindStringActionMutations(
    const std::vector<Instruction>& instructions, Arch arch) {
    std::vector<StringActionMutation> result;
    if (!ArchIsX86_32Or64(arch)) return result;
    struct Producer { RegisterSlice slice; uint64_t va; size_t index; StringActionKind kind; };
    std::unordered_map<std::string, Producer> producers;
    for (size_t i = 0; i < instructions.size(); ++i) {
        const auto& in = instructions[i];
        if (!in.length || InstructionIsCall(in) || InstructionEndsBlock(in) ||
            in.typedOperands.empty() || in.isRepString) {
            producers.clear(); continue;
        }
        bool repeated = false;
        for (auto prefix : in.prefixes)
            repeated |= prefix == InstructionPrefix::Rep || prefix == InstructionPrefix::Repe ||
                        prefix == InstructionPrefix::Repne;
        if (repeated) { producers.clear(); continue; }
        const auto& dst = in.typedOperands.front();
        const bool addition = in.mnemonic == "add" || in.mnemonic == "inc";
        const bool subtraction = in.mnemonic == "sub" || in.mnemonic == "dec";
        bool arithmetic = (addition || subtraction) && OperandReads(dst.access) &&
                          OperandWrites(dst.access) && dst.widthBits != 0;
        if ((in.mnemonic == "add" || in.mnemonic == "sub") &&
            (in.typedOperands.size() < 2 ||
             (in.typedOperands[1].kind == OperandKind::Immediate &&
              in.typedOperands[1].immediate == 0))) arithmetic = false;
        bool negativeImmediate = false;
        if (arithmetic && in.typedOperands.size() >= 2) {
            const auto& source = in.typedOperands[1];
            // An explicitly signed immediate is interpreted at its decoder
            // width. ADD -1 is a decrease, and SUB -1 is an increase; the raw
            // instruction spelling remains visible in either case.
            negativeImmediate = source.kind == OperandKind::Immediate && source.immediateSigned &&
                source.widthBits != 0 && source.widthBits <= 64 &&
                (source.immediate & (uint64_t{1} << (source.widthBits - 1))) != 0;
        }
        const auto kind = addition != negativeImmediate ? StringActionKind::Add : StringActionKind::Subtract;
        const bool stored = dst.kind == OperandKind::Memory && OperandWrites(dst.access) &&
            dst.widthBits != 0 && !StringActionStackRegister(dst.baseRegister) &&
            !StringActionStackRegister(dst.indexRegister);
        if (stored && arithmetic) {
            result.push_back({in.address, 0, false, kind, InstructionText(in),
                "Decoder reports a non-stack memory read/write arithmetic operand."});
        } else if (stored && in.mnemonic == "mov" && in.typedOperands.size() == 2 &&
                   OperandReads(in.typedOperands[1].access)) {
            const auto& src = in.typedOperands[1];
            StringActionMutation mutation{in.address, 0, false, StringActionKind::Write,
                InstructionText(in), "Decoder reports a non-stack memory destination."};
            if (src.kind == OperandKind::Register && src.widthBits == dst.widthBits) {
                auto reg = DescribeRegisterSlice(src.registerName, src.widthBits, arch);
                auto found = producers.find(reg.storage);
                if (found != producers.end() && i - found->second.index <= 12 &&
                    reg.offsetBits == found->second.slice.offsetBits &&
                    reg.widthBits == found->second.slice.widthBits) {
                    mutation.kind = found->second.kind;
                    mutation.producerVA = found->second.va;
                    mutation.producerVAValid = true;
                    mutation.evidence = "Arithmetic result reaches this same-width memory store through an unchanged register slice in one basic block.";
                }
            }
            result.push_back(std::move(mutation));
        }

        // Capture a copy before invalidating written register families.
        Producer copied{}; bool copyValid = false;
        if (in.mnemonic == "mov" && in.typedOperands.size() == 2 &&
            dst.kind == OperandKind::Register && OperandWrites(dst.access)) {
            const auto& src = in.typedOperands[1];
            if (src.kind == OperandKind::Register && OperandReads(src.access) &&
                src.widthBits && src.widthBits == dst.widthBits) {
                auto source = DescribeRegisterSlice(src.registerName, src.widthBits, arch);
                auto found = producers.find(source.storage);
                if (found != producers.end() && i - found->second.index <= 12 &&
                    source.widthBits == found->second.slice.widthBits &&
                    source.offsetBits == found->second.slice.offsetBits) {
                    copied = found->second;
                    copied.slice = DescribeRegisterSlice(dst.registerName, dst.widthBits, arch);
                    copyValid = true;
                }
            }
        }
        bool unknown = false;
        for (const auto& operand : in.typedOperands) {
            unknown |= operand.kind == OperandKind::Invalid || operand.access == OperandAccess::None;
            if (operand.kind == OperandKind::Register && OperandWrites(operand.access))
                producers.erase(DescribeRegisterSlice(operand.registerName, operand.widthBits, arch).storage);
        }
        for (const auto& name : in.registersWritten)
            producers.erase(DescribeRegisterSlice(name, 0, arch).storage);
        if (unknown) { producers.clear(); continue; }
        if (copyValid && !StringActionStackRegister(dst.registerName))
            producers[copied.slice.storage] = copied;
        if (arithmetic && dst.kind == OperandKind::Register &&
            !StringActionStackRegister(dst.registerName)) {
            auto reg = DescribeRegisterSlice(dst.registerName, dst.widthBits, arch);
            producers[reg.storage] = {reg, in.address, i, kind};
        }
    }
    return result;
}

inline std::string StringActionSuggestedName(const std::string& text, StringActionKind kind) {
    if (kind == StringActionKind::Write || text.size() > 2048) return {};
    std::vector<std::string> words;
    std::string word;
    for (unsigned char c : text) {
        if (std::isalnum(c)) word += static_cast<char>(std::tolower(c));
        else if (!word.empty()) { words.push_back(word); word.clear(); }
    }
    if (!word.empty()) words.push_back(word);
    const auto has = [&](const char* value) {
        return std::find(words.begin(), words.end(), value) != words.end();
    };
    for (const char* negative : {"not", "never", "no", "cannot", "can", "couldn", "didn",
             "wasn", "isn", "failed", "failure", "error", "unable", "without"})
        if (has(negative)) return {};
    const bool add = has("added") || has("add") || has("increased") || has("incremented") ||
                     has("awarded") || has("gained");
    const bool subtract = has("subtracted") || has("removed") || has("decreased") ||
                          has("deducted") || has("lost");
    if (add == subtract || (kind == StringActionKind::Add ? !add : !subtract)) return {};
    std::string subject = "value";
    if (has("point") || has("points")) subject = "points";
    else if (has("score")) subject = "score";
    else if (has("coin") || has("coins")) subject = "coins";
    else if (has("experience") || has("xp")) subject = "experience";
    else if (has("counter")) subject = "counter";
    return std::string(kind == StringActionKind::Add ? "add_" : "subtract_") + subject + "_candidate";
}
} // namespace ds
