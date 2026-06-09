//
// cond_eval_test.cpp
// Off-target unit test for src/Core/Cond.cpp: the new EvalExpression single-
// operand evaluator (backs the Watch panel) plus a sanity check that the
// existing EvalCondition comparison path is unchanged.
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\cond_eval_test.cpp src\Core\Cond.cpp
//   .\cond_eval_test.exe
//
#include "Core/Cond.h"

#include <cstdint>
#include <cstdio>
#include <string>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

int main() {
    CondContext cc;
    // rax=0x1000, rsp=0x2000; memory: [0x1000]=0x42, [0x2008]=0xDEAD.
    cc.reg = [](const std::string& n, uint64_t& o) -> bool {
        if (n == "rax") { o = 0x1000; return true; }
        if (n == "rsp") { o = 0x2000; return true; }
        return false;
    };
    cc.mem = [](uint64_t a) -> uint64_t {
        if (a == 0x1000) return 0x42;
        if (a == 0x2008) return 0xDEAD;
        return 0;
    };

    uint64_t v = 0;
    CHECK(EvalExpression("rax", cc, v) && v == 0x1000);          // register
    CHECK(EvalExpression("0x2000", cc, v) && v == 0x2000);       // hex literal
    CHECK(EvalExpression("4096", cc, v) && v == 4096);           // decimal literal
    CHECK(EvalExpression("[rax]", cc, v) && v == 0x42);          // memory deref
    CHECK(EvalExpression("[rsp+8]", cc, v) && v == 0xDEAD);      // base + disp
    CHECK(EvalExpression("[rsp + 0x8]", cc, v) && v == 0xDEAD);  // spaced + hex disp
    CHECK(!EvalExpression("r9", cc, v));                         // unknown register
    CHECK(!EvalExpression("garbage", cc, v));                    // not a number/register

    // EvalCondition still compares two operands as before.
    CHECK(EvalCondition("rax == 0x1000", cc, false));
    CHECK(EvalCondition("[rsp+8] != 0", cc, false));
    CHECK(!EvalCondition("rax < 0x10", cc, true));
    CHECK(EvalCondition("", cc, false));                        // empty == unconditional (true)

    // Pre-compiled conditions evaluate identically to the string path (parse once,
    // evaluate per hit). See cond_compiled_test.cpp for the exhaustive sweep.
    CHECK(EvalCompiled(CompileCondition("rax == 0x1000"), cc, false));
    CHECK(EvalCompiled(CompileCondition("[rsp+8] != 0"), cc, false));
    CHECK(!EvalCompiled(CompileCondition("rax < 0x10"), cc, false));
    CHECK(EvalCompiled(CompileCondition(""), cc, false));       // empty == unconditional (true)
    CHECK(EvalCompiled(CompileCondition("garbage"), cc, true) &&
          !EvalCompiled(CompileCondition("garbage"), cc, false)); // onError honored

    if (g_fail) { std::printf("\n%d CHECK(s) FAILED\n", g_fail); return 1; }
    std::printf("cond_eval_test: all checks passed\n");
    return 0;
}
