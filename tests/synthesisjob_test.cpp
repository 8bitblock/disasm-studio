//
// synthesisjob_test.cpp
// Compile + link + smoke test for SynthesisJob (src/Core/SynthesisJob.cpp): proves the
// F1 entry point binds BinaryFile + the SymEngine facade + Synthesis and runs end to
// end. With the stub engine (no DS_HAVE_SYMENGINE) it returns a clean
// "engine unavailable" result — the path the default build takes.
//
//   cl /std:c++20 /EHsc /I src tests\synthesisjob_test.cpp src\Core\SynthesisJob.cpp ^
//      src\Core\Synthesis.cpp src\Core\SymEngine.cpp src\Core\ExprAst.cpp ^
//      src\Core\Simplify.cpp src\Core\BinaryFile.cpp
//
#include "Core/SynthesisJob.h"
#include "Core/BinaryFile.h"
#include "Disasm/IDisassembler.h"

#include <cstdio>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

// Decodes every byte as a 1-byte "nop" (enough to exercise the decode loop + seeding).
struct NopDis : IDisassembler {
    Engine engine() const override { return Engine::Zydis; }
    const char* engineName() const override { return "nop"; }
    std::vector<Instruction> disassemble(const uint8_t*, size_t, uint64_t, size_t) override { return {}; }
    bool decodeOne(const uint8_t*, size_t size, uint64_t va, Instruction& out) override {
        if (size == 0) return false;
        out = Instruction{}; out.address = va; out.length = 1; out.mnemonic = "nop";
        return true;
    }
};

int main() {
    BinaryFile bin;
    std::vector<uint8_t> blob(32, 0x90);
    bin.loadFromMemory(blob, 0x1000, "smoke");   // falls back to a flat Raw mapping

    NopDis dis;
    SynthesisOptions opt; opt.samples = 16;
    SynthResult r = SynthesizeJob(bin, dis, Arch::X64, 0x1000, 0x1010, opt);

    CHECK(r.regionStart == 0x1000);
    CHECK(r.regionSize == 0x10);
    // With the stub engine, the region is in-envelope (all nops) but symbolic execution
    // is unavailable, so we expect a clean rejection reason and zero confidence.
    std::printf("  inEnvelope=%d reason=\"%s\" conf=%.2f\n",
                (int)r.inEnvelope, r.rejectedReason.c_str(), r.confidence);

    if (g_fail == 0) std::printf("ALL SYNTHESISJOB TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
