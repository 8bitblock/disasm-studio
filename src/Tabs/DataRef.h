#pragma once
//
// DataRef.h
// instrDataRef(): the data address an instruction references (RIP-relative or an
// absolute memory immediate), used for inline string comments and xref matching.
// Extracted to a header so it can be unit-tested in isolation (tests/instr_dataref_test.cpp).
//
#include "../Disasm/IDisassembler.h"
#include <cctype>
#include <cstdio>
#include <string>

namespace ds {

// Returns the data address an instruction references via its memory operand, or 0
// if it has none. The address is read ONLY from inside the first "[...]" so a
// stored immediate (e.g. `mov [rbp-0x4], 0x140002000`) is never mistaken for an
// address, and indirect calls/jumps through memory (`call [0x...]`, an IAT slot)
// still resolve. A relative branch has no bracket and is matched via branchTarget.
//
// Two memory-operand forms are handled:
//   - "[rip + 0x..]" / "[rip - 0x..]"  (Capstone keeps RIP symbolic): next_ip + disp
//   - "[0x..]" / "[seg:0x..]"          (Zydis resolves RIP to absolute): the disp
// Register-based memory (`[rbp-0x4]`, `[rax*8+disp]`, `[rsp+0x20]`) is dynamic -> 0.
inline uint64_t instrDataRef(const Instruction& in) {
    const std::string& o = in.operands;
    size_t lb = o.find('[');
    if (lb == std::string::npos) return 0;               // no memory operand -> no data ref
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
                return in.address + in.length + (uint64_t)(sign * (int64_t)v);
        }
        return 0;
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
            if (std::sscanf(inner.c_str() + i, "0x%llx", &v) == 1) return (uint64_t)v;
        }
    }
    return 0;
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
// (the 32-bit "mov reg, offset aString" / "push offset aString" idioms). Returns 0
// unless the operand is a bare hex immediate with NO memory operand (no '['), so a
// stored constant `mov [mem], 0x..` is never treated as an address. The caller still
// gates on whether the address actually resolves to a string, so a numeric constant
// that isn't a pointer simply produces no annotation. Complements instrDataRef (which
// covers memory operands incl. lea / [rip+x] / [abs] / IAT). Unit-tested.
inline uint64_t instrImmRef(const Instruction& in) {
    if (in.operands.find('[') != std::string::npos) return 0;   // memory operand -> instrDataRef's job
    const std::string& m = in.mnemonic;
    if (m != "mov" && m != "movabs" && m != "push") return 0;    // only data-load / push carry an offset
    const std::string& o = in.operands;
    size_t comma = o.rfind(',');                                 // mov reg, imm -> after the comma; push imm -> whole
    size_t s = (comma == std::string::npos) ? 0 : comma + 1;
    while (s < o.size() && o[s] == ' ') ++s;
    if (!(s + 1 < o.size() && o[s] == '0' && (o[s + 1] == 'x' || o[s + 1] == 'X'))) return 0;  // need a register-free hex imm
    for (size_t k = s + 2; k < o.size(); ++k) { char c = o[k]; if (c == ' ') continue; if (!std::isxdigit((unsigned char)c)) return 0; }
    unsigned long long v = 0;
    if (std::sscanf(o.c_str() + s, "0x%llx", &v) != 1) return 0;
    if (v < 0x1000) return 0;                                    // small constants aren't addresses
    return (uint64_t)v;
}

// True if `in` references the exact address `target`: a relative branch/call target,
// a memory data ref (instrDataRef: [abs] or [rip+disp]), OR an absolute immediate
// operand equal to target. x86-32 loads a string pointer as a bare immediate
// (`push offset str` / `mov reg, offset str`), which instrDataRef intentionally skips;
// for a TARGETED "who references this exact address" query, matching the immediate is
// precise (a constant rarely equals a specific .rdata address by accident). Shared by
// the UI's xref popup and the Core live-xref sweep (FindRefsInBuffer).
inline bool instrRefsAddr(const Instruction& in, uint64_t target) {
    if (!target) return false;
    if (in.branchTarget == target) return true;
    if (instrDataRef(in) == target) return true;
    const std::string& o = in.operands;
    for (size_t i = 0; i + 1 < o.size(); ++i)
        if (o[i] == '0' && (o[i + 1] == 'x' || o[i + 1] == 'X')) {
            unsigned long long v = 0;
            if (std::sscanf(o.c_str() + i, "0x%llx", &v) == 1 && (uint64_t)v == target) return true;
        }
    return false;
}

} // namespace ds
