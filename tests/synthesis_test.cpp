//
// synthesis_test.cpp
// Off-target unit test for the F1 clean-room synthesis pipeline
// (src/Core/Synthesis.cpp) using a MOCK SymEngine/Solver (no Triton): envelope
// gating, simplify, and the N-sample I/O-equivalence confidence badge — including a
// deliberately-wrong engine to prove the verifier actually catches divergence.
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\synthesis_test.cpp src\Core\Synthesis.cpp ^
//      src\Core\ExprAst.cpp src\Core\Simplify.cpp
//   .\synthesis_test.exe
//
#include "Core/Synthesis.h"
#include "Core/Simplify.h"

#include <cstdint>
#include <cstdio>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

// Models the obfuscated function  f(a) = (a ^ a) + (a * 2)  == 2a, input rcx -> rax.
struct MockEngine : ISymEngine {
    bool buggy = false;   // when true, runConcrete computes 2a+1 (a wrong implementation)
    SymStatus symbolizeRegion(const SeedSource&, uint64_t, uint64_t,
                              const std::vector<SymbolicInput>&,
                              const SymOptions&, SymOutputs& out) override {
        ExprRef a = Var(0, 64);                                   // varId 0 == rcx
        ExprRef expr = Bin(ExprOp::Add, Bin(ExprOp::Xor, a, a),
                                        Bin(ExprOp::Mul, a, C(2, 64)));
        out.outputs.push_back(SymValue{ "rax", expr });
        out.status = SymStatus::Ok;
        return SymStatus::Ok;
    }
    SymStatus runConcrete(const SeedSource& seed, uint64_t, uint64_t,
                          const SymOptions&, ConcreteState& out) override {
        const uint64_t a = seed.regs.rcx;
        out.regs = seed.regs;
        out.regs.rax = a * 2 + (buggy ? 1 : 0);
        out.status = SymStatus::Ok;
        return SymStatus::Ok;
    }
};

struct MockSolver : ISolver {
    bool solveForInput(const std::vector<PathConstraint>&, std::vector<VarBinding>&) override { return false; }
    ExprRef simplify(const ExprRef& e) override { return Simplify(e); }
    int isSat(const ExprRef& pred) override { uint64_t v; return EvalConst(pred, v) ? (v ? 1 : 0) : -1; }
};

static Instruction insn(uint64_t addr, uint32_t len, const char* mn, bool call=false) {
    Instruction in; in.address = addr; in.length = len; in.mnemonic = mn; in.isCall = call;
    return in;
}

int main() {
    const uint64_t lo = 0x401000, hi = 0x401010;
    std::vector<Instruction> insns = {
        insn(0x401000, 3, "mov"), insn(0x401003, 3, "xor"),
        insn(0x401006, 4, "imul"), insn(0x40100A, 3, "add"),
    };
    std::vector<SymbolicInput> inputs = { { SymbolicInput::Reg, "rcx", 0, 8, /*varId*/0, "a" } };
    SeedSource seed; seed.arch = Arch::X64;

    SynthesisOptions opt; opt.samples = 256; opt.seed = 0xABCDEF; opt.useZ3 = true;

    // ---- happy path: 2a recovered, 100% sample equivalence ----------------
    {
        MockEngine eng; MockSolver solver;
        SynthResult r = Synthesize(insns, lo, hi, inputs, seed, eng, solver, opt);
        CHECK(r.inEnvelope);
        CHECK(r.rejectedReason.empty());
        CHECK(r.outputs.size() == 1);
        if (r.outputs.size() == 1) {
            // simplified to  rax = a * 2
            CHECK(ExprEqual(r.outputs[0].expr, Bin(ExprOp::Mul, Var(0, 64), C(2, 64))));
            CHECK(r.outputs[0].loc == "rax");
        }
        CHECK(r.samplesTotal == 256);
        CHECK(r.samplesPassed == 256);
        CHECK(r.confidence == 1.0);
        CHECK(r.cleanedPseudoC.find("rax") != std::string::npos);
        std::printf("  pseudo-C: %s\n  note: %s\n", r.cleanedPseudoC.c_str(), r.reasoning.c_str());
    }

    // ---- verifier catches a wrong engine: confidence collapses ------------
    {
        MockEngine eng; eng.buggy = true; MockSolver solver;
        SynthResult r = Synthesize(insns, lo, hi, inputs, seed, eng, solver, opt);
        CHECK(r.inEnvelope);
        // simplified expr says 2a, but runConcrete yields 2a+1 -> every sample mismatches
        CHECK(r.samplesPassed == 0);
        CHECK(r.confidence == 0.0);
    }

    // ---- envelope rejection: a CALL in the region -------------------------
    {
        std::vector<Instruction> withCall = insns;
        withCall.push_back(insn(0x40100D, 3, "call", /*call*/true));
        MockEngine eng; MockSolver solver;
        SynthResult r = Synthesize(withCall, lo, hi, inputs, seed, eng, solver, opt);
        CHECK(!r.inEnvelope);
        CHECK(r.rejectedReason.find("CALL") != std::string::npos);
        CHECK(r.samplesTotal == 0);
    }

    // ---- envelope rejection: a back-edge (loop) ---------------------------
    {
        std::vector<Instruction> withLoop = insns;
        Instruction jb; jb.address = 0x40100D; jb.length = 2; jb.mnemonic = "jne";
        jb.isBranch = true; jb.branchTarget = 0x401000;   // jumps backward into the region
        withLoop.push_back(jb);
        MockEngine eng; MockSolver solver;
        SynthResult r = Synthesize(withLoop, lo, hi, inputs, seed, eng, solver, opt);
        CHECK(!r.inEnvelope);
        CHECK(r.rejectedReason.find("loop") != std::string::npos);
    }

    if (g_fail == 0) std::printf("ALL SYNTHESIS TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
