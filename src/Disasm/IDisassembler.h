#pragma once
//
// IDisassembler.h
// Engine-agnostic disassembly interface. Both the Zydis and Capstone backends
// implement this so the UI never depends on a concrete engine.
//
#include <cstdint>
#include <string>
#include <vector>

namespace ds {

// A single decoded instruction in a form the UI can render directly.
struct Instruction {
    uint64_t    address   = 0;     // virtual address of the instruction
    uint32_t    length    = 0;     // size in bytes
    std::string bytes;             // hex byte string, e.g. "48 89 5C 24 08"
    std::string mnemonic;          // e.g. "mov"
    std::string operands;          // e.g. "rbx, [rsp+0x8]"
    bool        isBranch  = false; // jmp/jcc/call/ret family
    bool        isCall    = false;
    bool        isRet     = false; // ret/retf/iret family (returns from a call frame)
    bool        isRepString = false; // has a REP/REPE/REPNE prefix (rep movs/stos/cmps/scas/...)
    uint64_t    branchTarget = 0;  // resolved target if statically known, else 0
    // Decoder-supplied inline annotation (rendered as a "; ..." comment). The
    // JVM backend fills it with resolved constant-pool text (method/field refs,
    // string literals); the x86/ARM backends leave it empty.
    std::string comment;
    // Additional statically-known control-flow targets beyond branchTarget:
    // tableswitch/lookupswitch case targets (JVM). branchTarget holds the
    // switch default. Empty for ordinary instructions; CFG links these as
    // switch-case successors.
    std::vector<uint64_t> extraTargets;
};

enum class Arch  { X86, X64, ARM, ARM64, MIPS, MIPS64, PPC, PPC64, RISCV32, RISCV64, JVM };
enum class Engine { Zydis, Capstone };

// True for the architectures Zydis can decode (x86 family); everything else
// must be routed to Capstone.
inline bool ArchIsX86(Arch a) { return a == Arch::X86 || a == Arch::X64; }
// Short display name for an architecture.
inline const char* ArchName(Arch a) {
    switch (a) {
        case Arch::X86:     return "x86";
        case Arch::X64:     return "x64";
        case Arch::ARM:     return "ARM";
        case Arch::ARM64:   return "ARM64";
        case Arch::MIPS:    return "MIPS";
        case Arch::MIPS64:  return "MIPS64";
        case Arch::PPC:     return "PPC";
        case Arch::PPC64:   return "PPC64";
        case Arch::RISCV32: return "RISC-V 32";
        case Arch::RISCV64: return "RISC-V 64";
        case Arch::JVM:     return "JVM";
    }
    return "?";
}

// Inverse of ArchName: parse a saved arch string back to the enum (for per-project
// persistence). Returns false for an unrecognized / empty name.
inline bool ArchFromName(const char* s, Arch& out) {
    if (!s) return false;
    const std::string n(s);
    if      (n == "x86")       out = Arch::X86;
    else if (n == "x64")       out = Arch::X64;
    else if (n == "ARM")       out = Arch::ARM;
    else if (n == "ARM64")     out = Arch::ARM64;
    else if (n == "MIPS")      out = Arch::MIPS;
    else if (n == "MIPS64")    out = Arch::MIPS64;
    else if (n == "PPC")       out = Arch::PPC;
    else if (n == "PPC64")     out = Arch::PPC64;
    else if (n == "RISC-V 32") out = Arch::RISCV32;
    else if (n == "RISC-V 64") out = Arch::RISCV64;
    else if (n == "JVM")       out = Arch::JVM;
    else return false;
    return true;
}

// Name <-> enum for the disassembly engine (for per-project persistence).
inline const char* EngineNameOf(Engine e) { return e == Engine::Zydis ? "Zydis" : "Capstone"; }
inline bool EngineFromName(const char* s, Engine& out) {
    if (!s) return false;
    const std::string n(s);
    if (n == "Zydis")    { out = Engine::Zydis;    return true; }
    if (n == "Capstone") { out = Engine::Capstone; return true; }
    return false;
}

// Pure interface. Implementations live in ZydisDisassembler / CapstoneDisassembler.
class IDisassembler {
public:
    virtual ~IDisassembler() = default;

    virtual Engine engine() const = 0;
    virtual const char* engineName() const = 0;

    // Decode a buffer starting at the given virtual address. Stops after
    // `maxInstructions` or when the buffer is exhausted.
    virtual std::vector<Instruction> disassemble(const uint8_t* data,
                                                 size_t          size,
                                                 uint64_t        virtualAddress,
                                                 size_t          maxInstructions = 0) = 0;

    // Decode exactly one instruction; returns false on a decode error.
    virtual bool decodeOne(const uint8_t* data, size_t size,
                           uint64_t virtualAddress, Instruction& out) = 0;
};

} // namespace ds
// (engine-agnostic disassembly interface)
