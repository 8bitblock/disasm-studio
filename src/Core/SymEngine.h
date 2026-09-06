#pragma once
//
// SymEngine.h
// The SWAPPABLE symbolic/concrete execution facade shared by F1 (clean-room
// synthesis) and F3 (path explorer). Consumers depend ONLY on this header — never on
// Triton/Unicorn/Z3 — so they compile and unit-test against a mock with `cl`. The
// production backend (SymEngine.cpp) wraps Triton (symbolic, bundled Z3) and uses
// Triton's concrete evaluation for runConcrete (Unicorn was dropped: GPL-2.0 + Triton
// covers it). Decode for the UI/CFG stays on ds::IDisassembler; the engine reads the
// same raw bytes+VA window and uses its own semantics internally.
//
// All symbolic values are ExprAst (src/Core/ExprAst.h) bit-vectors — the single
// cross-feature representation (resolves the spec's triple-defined ExprAst).
//
#include "ExprAst.h"
#include "../Disasm/IDisassembler.h"   // ds::Arch

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace ds {

// ---- engine-agnostic seed (built by SymSeed from BinaryFile or Debugger) ----
enum MemPerm : uint32_t { P_R = 1, P_W = 2, P_X = 4 };

struct MemBlock {
    uint64_t             base = 0;
    std::vector<uint8_t> bytes;
    uint32_t             perms = P_R | P_W | P_X;
};

// 64-bit GP register file (mirrors ds::Registers without pulling in Debugger/Win32).
struct RegFile {
    uint64_t rax=0,rbx=0,rcx=0,rdx=0,rsi=0,rdi=0,rbp=0,rsp=0;
    uint64_t r8=0,r9=0,r10=0,r11=0,r12=0,r13=0,r14=0,r15=0;
    uint64_t rip=0, rflags=0;
};

struct SeedSource {
    Arch                  arch = Arch::X64;
    RegFile               regs;
    std::vector<MemBlock> mem;     // concrete memory the region may read
};

// A location whose bytes are made symbolic before execution.
struct SymbolicInput {
    enum Kind { Reg, Mem } kind = Mem;
    std::string regName;           // when kind==Reg (e.g. "rcx")
    uint64_t    addr = 0;          // when kind==Mem
    uint32_t    bytes = 1;         // width in bytes (1..8)
    uint64_t    varId = 0;         // ExprAst Var id assigned to it
    std::string tag;               // human label ("input[0]")
};

// One branch decision taken during symbolic execution.
struct PathConstraint {
    ExprRef  pred;                 // 1-bit predicate that was true to take this edge
    bool     taken = true;
    uint64_t fromVA = 0, toVA = 0;
};

enum class SymStatus { Ok, Unavailable, DecodeError, StepLimit, Unsupported, Escaped };

struct SymOptions {
    uint32_t maxSteps = 4096;      // instruction budget
    uint32_t timeoutMs = 5000;
    bool     useZ3 = false;        // allow solver-backed simplify/equivalence
};

// An (location, value) output produced by symbolic execution.
struct SymValue { std::string loc; ExprRef expr; };

struct SymOutputs {
    SymStatus                   status = SymStatus::Unavailable;
    std::vector<SymValue>       outputs;          // output regs/slots as ExprAst
    std::vector<PathConstraint> pathConstraints;  // F3
};

struct ConcreteState {
    SymStatus status = SymStatus::Unavailable;
    RegFile   regs;
};

// Symbolically execute [startVA,endVA): returns output expressions + path constraints.
// Concretely execute [startVA,endVA) from `seed`: returns the final register state.
class ISymEngine {
public:
    virtual ~ISymEngine() = default;
    virtual SymStatus symbolizeRegion(const SeedSource& seed, uint64_t startVA, uint64_t endVA,
                                      const std::vector<SymbolicInput>& inputs,
                                      const SymOptions& opt, SymOutputs& out) = 0;
    virtual SymStatus runConcrete(const SeedSource& seed, uint64_t startVA, uint64_t endVA,
                                  const SymOptions& opt, ConcreteState& out) = 0;
};

// A solved variable binding (input varId -> concrete value).
struct VarBinding { uint64_t varId = 0; uint64_t value = 0; uint32_t bytes = 1; };

class ISolver {
public:
    virtual ~ISolver() = default;
    // Find an input model satisfying all constraints. False if UNSAT/unknown.
    virtual bool solveForInput(const std::vector<PathConstraint>& constraints,
                               std::vector<VarBinding>& model) = 0;
    // Backend simplify (defaults to ds::Simplify when no solver is linked).
    virtual ExprRef simplify(const ExprRef& e) = 0;
    // 1 = sat, 0 = unsat, -1 = unknown.
    virtual int isSat(const ExprRef& pred1bit) = 0;
};

// Factories — defined in SymEngine.cpp (Triton/Z3). When the engines are not compiled
// in (DS_HAVE_SYMENGINE undefined) these return engines whose calls yield Unavailable,
// so the app still links. Tests inject their own mocks instead.
std::unique_ptr<ISymEngine> MakeSymEngine(Arch arch);
std::unique_ptr<ISolver>    MakeSolver();
bool SymEngineAvailable();

} // namespace ds
