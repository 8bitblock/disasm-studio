#pragma once

#include "../Disasm/IDisassembler.h"

#include <cctype>
#include <cstdio>
#include <string>
#include <string_view>

namespace ds {

// Static semantics describe both possible destinations. They never imply that
// flags/registers have been observed or that a particular branch was taken.
inline std::string ConditionalBranchComment(std::string_view condition,
                                             std::string_view target = {}) {
    std::string text = "jumps";
    if (!target.empty()) { text += " to "; text += target; }
    text += " if ";
    text += condition.empty() ? "its condition is true" : condition;
    text += "; otherwise falls through";
    return text;
}

inline std::string StaticBranchComment(const Instruction& in, Arch arch) {
    const bool typed = in.flow.kind != FlowKind::None;
    const bool conditional = in.flow.kind == FlowKind::ConditionalBranch;
    const bool unconditional = in.flow.kind == FlowKind::UnconditionalBranch ||
                               in.flow.kind == FlowKind::IndirectBranch;
    if (typed ? (!conditional && !unconditional)
              : (!in.isBranch || in.isCall || in.isRet)) return {};

    std::string mnemonic = in.mnemonic;
    for (char& c : mnemonic) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    std::string text;
    const bool x86 = arch == Arch::X86_16 || arch == Arch::X86 || arch == Arch::X64;
    if (x86 && !unconditional) {
        // Without a proven flag producer, state the flag condition itself;
        // equality/ordering of particular operands belongs to FuncAnnotate.
        struct Condition { const char* mnemonic; const char* meaning; };
        static constexpr Condition conditions[] = {
            {"je", "zero flag is set"}, {"jz", "zero flag is set"},
            {"jne", "zero flag is clear"}, {"jnz", "zero flag is clear"},
            {"jb", "carry flag is set"}, {"jc", "carry flag is set"}, {"jnae", "carry flag is set"},
            {"jae", "carry flag is clear"}, {"jnc", "carry flag is clear"}, {"jnb", "carry flag is clear"},
            {"jbe", "carry or zero flag is set"}, {"jna", "carry or zero flag is set"},
            {"ja", "carry and zero flags are clear"}, {"jnbe", "carry and zero flags are clear"},
            {"jl", "sign and overflow flags differ"}, {"jnge", "sign and overflow flags differ"},
            {"jge", "sign and overflow flags agree"}, {"jnl", "sign and overflow flags agree"},
            {"jle", "zero flag is set or sign and overflow flags differ"},
            {"jng", "zero flag is set or sign and overflow flags differ"},
            {"jg", "zero flag is clear and sign and overflow flags agree"},
            {"jnle", "zero flag is clear and sign and overflow flags agree"},
            {"js", "sign flag is set"}, {"jns", "sign flag is clear"},
            {"jo", "overflow flag is set"}, {"jno", "overflow flag is clear"},
            {"jp", "parity flag is set"}, {"jpe", "parity flag is set"},
            {"jnp", "parity flag is clear"}, {"jpo", "parity flag is clear"},
            {"jcxz", "CX is zero"}, {"jecxz", "ECX is zero"}, {"jrcxz", "RCX is zero"},
            {"loop", "the decremented loop counter is non-zero"},
            {"loope", "the decremented loop counter is non-zero and zero flag is set"},
            {"loopz", "the decremented loop counter is non-zero and zero flag is set"},
            {"loopne", "the decremented loop counter is non-zero and zero flag is clear"},
            {"loopnz", "the decremented loop counter is non-zero and zero flag is clear"},
        };
        for (const Condition& condition : conditions)
            if (mnemonic == condition.mnemonic) {
                text = ConditionalBranchComment(condition.meaning);
                break;
            }
    }
    if (text.empty() && conditional)
        text = ConditionalBranchComment("its condition is true");
    if (text.empty() && (unconditional ||
        (x86 && !typed && (mnemonic == "jmp" || mnemonic == "ljmp")))) {
        uint64_t target = 0;
        if (TryGetDirectTarget(in, target)) {
            char address[24];
            std::snprintf(address, sizeof(address), "0x%llX", static_cast<unsigned long long>(target));
            text = std::string("jumps to ") + address;
        } else {
            text = "jumps to the branch target";
        }
    }
    if (!text.empty() && in.flow.delaySlots) text += "; delay-slot rules apply";
    return text;
}

} // namespace ds
