#pragma once
//
// InstructionReference.h
// instrDataRef(): the data address an instruction references (RIP-relative or an
// absolute memory immediate), used for inline string comments and xref matching.
// Extracted to a header so it can be unit-tested in isolation (tests/instr_dataref_test.cpp).
//
#include "../Disasm/IDisassembler.h"
#include "AddressSpan.h"
#include <cctype>
#include <cstdio>
#include <limits>
#include <string>

namespace ds {

// Returns true and writes the data address an instruction references via its
// memory operand.  Address zero is valid; callers must use the boolean rather
// than reserving zero as a sentinel. The address is read ONLY from inside the
// first "[...]" so a
// stored immediate (e.g. `mov [rbp-0x4], 0x140002000`) is never mistaken for an
// address, and indirect calls/jumps through memory (`call [0x...]`, an IAT slot)
// still resolve. A relative branch has no bracket and is matched via branchTarget.
//
// Two memory-operand forms are handled:
//   - "[rip + 0x..]" / "[rip - 0x..]"  (Capstone keeps RIP symbolic): next_ip + disp
//   - "[0x..]" / "[seg:0x..]"          (Zydis resolves RIP to absolute): the disp
// Register-based memory (`[rbp-0x4]`, `[rax*8+disp]`, `[rsp+0x20]`) is dynamic -> 0.
// FS/GS offsets depend on a live thread's segment base. LEA computes only
// the effective offset and ignores segment overrides.
inline bool InstructionUsesRuntimeSegment(const Instruction& in,
                                           const TypedOperand& operand) {
    if (in.mnemonic == "lea") return false;
    return operand.segmentRegister == "fs" || operand.segmentRegister == "gs";
}
inline bool InstructionTextUsesRuntimeSegment(const Instruction& in) {
    if (in.mnemonic == "lea") return false;
    std::string text = in.operands;
    for (char& c : text) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return text.find("fs:") != std::string::npos || text.find("gs:") != std::string::npos;
}

// Resolve a single decoder-proven static memory operand. Dynamic base/index and
// thread-relative segments remain unresolved; a legitimate target VA 0 is valid.
inline bool TryGetStaticMemoryAddress(const Instruction& in,
                                      const TypedOperand& operand, uint64_t& result) {
    result = 0;
    if (operand.kind != OperandKind::Memory || InstructionUsesRuntimeSegment(in, operand) ||
        !operand.indexRegister.empty() || !operand.displacementValid) return false;
    if (operand.baseRegister == "rip" || operand.baseRegister == "eip") {
        // EIP-relative addressing in long mode truncates the effective address
        // to 32 bits before zero extension; RIP-relative addressing stays 64-bit.
        if (operand.baseRegister == "eip") {
            result = static_cast<uint32_t>(static_cast<uint32_t>(in.address) +
                     in.length + static_cast<uint32_t>(operand.displacement));
            return true;
        }
        uint64_t next = 0;
        return CheckedAddressAdd(in.address, in.length, next) &&
               CheckedAddressAddSigned(next, operand.displacement, result);
    }
    if (!operand.baseRegister.empty() || operand.displacement < 0) return false;
    result = static_cast<uint64_t>(operand.displacement);
    return true;
}

inline bool TryGetInstrDataRef(const Instruction& in, uint64_t& result) {
    result = 0;
    if (!in.typedOperands.empty()) {
        for (const TypedOperand& operand : in.typedOperands)
            if (TryGetStaticMemoryAddress(in, operand, result)) return true;
        // Decoder semantics are authoritative even when no address is resolved.
        return false;
    }
    if (InstructionTextUsesRuntimeSegment(in)) return false;
    const std::string& o = in.operands;
    size_t lb = o.find('[');
    if (lb == std::string::npos) return false;            // no memory operand -> no data ref
    size_t rb = o.find(']', lb);
    std::string inner = o.substr(lb + 1, (rb == std::string::npos ? o.size() : rb) - lb - 1);

    // RIP-relative form: ref = address of the next instruction + signed displacement.
    size_t rp = inner.find("rip");
    if (rp != std::string::npos) {
        size_t i = rp + 3;
        while (i < inner.size() && inner[i] == ' ') ++i;
        if (i < inner.size() && (inner[i] == '+' || inner[i] == '-')) {
            int64_t sign = (inner[i] == '-') ? -1 : 1; ++i;
            while (i < inner.size() && inner[i] == ' ') ++i;
            unsigned long long v = 0;
            if (std::sscanf(inner.c_str() + i, "0x%llx", &v) == 1 || std::sscanf(inner.c_str() + i, "%llx", &v) == 1)
            {
                if (in.length > (std::numeric_limits<uint64_t>::max)() - in.address) return false;
                const uint64_t next = in.address + in.length;
                if (sign > 0) {
                    if (v > (std::numeric_limits<uint64_t>::max)() - next) return false;
                    result = next + static_cast<uint64_t>(v);
                } else {
                    if (v > next) return false;
                    result = next - static_cast<uint64_t>(v);
                }
                return true;
            }
        }
        return false;
    }

    // Pure absolute form: optional 2-letter segment prefix, then exactly "0x<hex>"
    // with no base/index register (anything else means a dynamic, register-based ref).
    size_t i = 0;
    if (inner.size() > 3 && inner[2] == ':' &&
        std::isalpha((unsigned char)inner[0]) && std::isalpha((unsigned char)inner[1]))
        i = 3;                                           // skip "fs:" / "ds:" / ...
    while (i < inner.size() && inner[i] == ' ') ++i;
    if (i + 1 < inner.size() && inner[i] == '0' && (inner[i + 1] == 'x' || inner[i + 1] == 'X')) {
        bool pure = (i + 2 < inner.size());
        for (size_t k = i + 2; k < inner.size(); ++k) {  // remainder must be only hex digits
            char c = inner[k];
            if (c == ' ') continue;
            if (!std::isxdigit((unsigned char)c)) { pure = false; break; }
        }
        if (pure) {
            unsigned long long v = 0;
            if (std::sscanf(inner.c_str() + i, "0x%llx", &v) == 1) {
                result = static_cast<uint64_t>(v);
                return true;
            }
        }
    }
    return false;
}

// Compatibility helper for display-only call sites that do not need to
// distinguish a real reference to VA 0. New analysis code must use
// TryGetInstrDataRef().
inline uint64_t instrDataRef(const Instruction& in) {
    uint64_t result = 0;
    return TryGetInstrDataRef(in, result) ? result : 0;
}

// How an instruction ACCESSES the data address instrDataRef() reports: does it
// read the memory, write (modify) it, or merely take/transfer through the
// address (lea, or an immediate that happens to be a pointer). Drives the Xrefs
// panel's Writers / Readers grouping ("who modifies this global?"). Pure
// operand-shape + mnemonic classification; unit-tested with the xref tests.
enum class XrefAccess : uint8_t { Read = 0, Write = 1, Ref = 2 };

inline XrefAccess instrDataAccess(const Instruction& in) {
    const std::string& m = in.mnemonic;
    if (m == "lea") return XrefAccess::Ref;              // address taken, memory untouched
    for (const TypedOperand& operand : in.typedOperands) {
        if (operand.kind != OperandKind::Memory) continue;
        if (OperandWrites(operand.access)) return XrefAccess::Write;
        if (OperandReads(operand.access)) return XrefAccess::Read;
        return XrefAccess::Ref;
    }
    const std::string& o = in.operands;
    size_t lb = o.find('[');
    if (lb == std::string::npos) return XrefAccess::Ref; // bare immediate pointer (no deref)
    size_t comma = o.find(',');
    const bool memIsFirst = (comma == std::string::npos) || lb < comma;
    if (!memIsFirst) return XrefAccess::Read;            // [mem] as a source operand
    // Memory is the first operand. Compare/test and push only read it; an
    // indirect call/jmp reads the slot; single-operand RMW and two-operand
    // "op [mem], src" forms (mov/add/and/...) write it.
    if (m == "cmp" || m == "test" || m == "push" || m == "call" || m == "jmp")
        return XrefAccess::Read;
    if (comma == std::string::npos) {
        if (m == "pop" || m == "inc" || m == "dec" || m == "neg" || m == "not" ||
            m.rfind("set", 0) == 0)
            return XrefAccess::Write;
        return XrefAccess::Read;                          // unknown single-operand: assume read
    }
    return XrefAccess::Write;                             // op [mem], src -> stores
}

// The address an instruction loads as an IMMEDIATE (not through a memory operand):
// the source of `mov reg, 0x..` / `movabs reg, 0x..` or the operand of `push 0x..`
// (the 32-bit "mov reg, offset aString" / "push offset aString" idioms). Returns
// validity separately because address zero is representable. The immediate must be
// zero or at least 0x1000 (the long-standing small-scalar false-positive guard) and
// must have NO memory operand (no '['), so a
// stored constant `mov [mem], 0x..` is never treated as an address. The caller still
// gates on whether the address actually resolves to a string, so a numeric constant
// that isn't a pointer simply produces no annotation. Complements instrDataRef (which
// covers memory operands incl. lea / [rip+x] / [abs] / IAT). Unit-tested.
inline bool TryGetInstrImmRef(const Instruction& in, uint64_t& result) {
    result = 0;
    if (InstructionHasMemoryOperand(in) || in.operands.find('[') != std::string::npos)
        return false;                                            // memory operand -> instrDataRef's job
    // A dedicated VM decoder can prove an archive string/function address even
    // when its mnemonic is not a native mov/push. Pointer is explicit semantic
    // evidence, so the small-scalar heuristic below does not apply. Far native
    // control-transfer pointers remain the direct-target resolver's concern.
    if (!in.isBranch && !in.isCall && in.flow.kind == FlowKind::None) {
        for (const auto& operand : in.typedOperands)
            if (operand.kind == OperandKind::Pointer && !operand.pcRelative) {
                result = operand.immediate;
                return true;
            }
    }
    const std::string& m = in.mnemonic;
    if (m != "mov" && m != "movabs" && m != "push") return false; // only data-load / push carry an offset
    if (!in.typedOperands.empty()) {
        for (auto it = in.typedOperands.rbegin(); it != in.typedOperands.rend(); ++it) {
            if (it->kind != OperandKind::Immediate || it->pcRelative) continue;
            if (it->immediate != 0 && it->immediate < 0x1000) return false;
            result = it->immediate;
            return true;
        }
        return false;
    }
    const std::string& o = in.operands;
    size_t comma = o.rfind(',');                                 // mov reg, imm -> after the comma; push imm -> whole
    size_t s = (comma == std::string::npos) ? 0 : comma + 1;
    while (s < o.size() && o[s] == ' ') ++s;
    if (!(s + 1 < o.size() && o[s] == '0' && (o[s + 1] == 'x' || o[s + 1] == 'X'))) return false; // need a register-free hex imm
    for (size_t k = s + 2; k < o.size(); ++k) { char c = o[k]; if (c == ' ') continue; if (!std::isxdigit((unsigned char)c)) return false; }
    unsigned long long v = 0;
    if (std::sscanf(o.c_str() + s, "0x%llx", &v) != 1) return false;
    if (v != 0 && v < 0x1000) return false;                       // explicit scalar heuristic
    result = static_cast<uint64_t>(v);
    return true;
}

// Compatibility wrapper. New authority-sensitive code must consume the valid
// bit from TryGetInstrImmRef so a legitimate VA zero is not lost.
inline uint64_t instrImmRef(const Instruction& in) {
    uint64_t result = 0;
    return TryGetInstrImmRef(in, result) ? result : 0;
}

// True if `in` references the exact address `target`: a relative branch/call target,
// a memory data ref (instrDataRef: [abs] or [rip+disp]), OR a pointer-shaped
// absolute immediate equal to target. x86-32 loads a string pointer as a bare immediate
// (`push offset str` / `mov reg, offset str`), which instrDataRef intentionally skips;
// for a TARGETED "who references this exact address" query, matching the immediate is
// precise for mapped nonzero addresses. Bare zero remains an ambiguous scalar/null
// sentinel and is not an immediate xref; explicit memory and control-flow forms still
// preserve genuine VA-zero references. Shared by the UI's xref popup and the Core
// live-xref sweep (FindRefsInBuffer).
inline bool instrRefsAddr(const Instruction& in, uint64_t target) {
    uint64_t directTarget = 0;
    if (TryGetDirectTarget(in, directTarget) && directTarget == target) return true;
    uint64_t dataTarget = 0;
    if (TryGetInstrDataRef(in, dataTarget) && dataTarget == target) return true;
    uint64_t immediateTarget = 0;
    return target != 0 && TryGetInstrImmRef(in, immediateTarget) &&
           immediateTarget == target;
}

} // namespace ds
