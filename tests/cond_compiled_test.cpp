//
// cond_compiled_test.cpp
// Off-target unit test for the pre-compiled breakpoint-condition path in
// src/Core/Cond.cpp. A breakpoint's condition is parsed ONCE into a CondProgram
// (CompileCondition) and evaluated repeatedly via EvalCompiled, instead of
// re-parsing the string on every hit. This test proves the compiled evaluation
// matches the string-based EvalCondition / EvalExpression across a range of
// expressions (registers, literals, memory derefs, displacements, every
// comparison operator, and error cases).
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\cond_compiled_test.cpp src\Core\Cond.cpp
//   .\cond_compiled_test.exe
//
#include "Core/Cond.h"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

int main() {
    CondContext cc;
    // rax=0x1000, rsp=0x2000, rbx=5; memory: [0x1000]=0x42, [0x2008]=0xDEAD,
    // [0xFF8]=7, [0x2000]=0x99.
    cc.reg = [](const std::string& n, uint64_t& o) -> bool {
        if (n == "rax") { o = 0x1000; return true; }
        if (n == "rsp") { o = 0x2000; return true; }
        if (n == "rbx") { o = 5;      return true; }
        return false;
    };
    cc.mem = [](uint64_t a) -> uint64_t {
        if (a == 0x1000) return 0x42;
        if (a == 0x2008) return 0xDEAD;
        if (a == 0x0FF8) return 7;
        if (a == 0x2000) return 0x99;
        return 0;
    };

    // ---- 1) Compiled comparison eval matches string EvalCondition exactly. ----
    // A spread of expressions: registers, literals (hex+dec), every operator,
    // memory derefs with +/- displacements (hex and decimal), spacing variants.
    const char* exprs[] = {
        "rax == 0x1000",
        "rax != 0x1000",
        "rax == 4096",
        "rsp > 0x1000",
        "rsp < 0x1000",
        "rax >= 0x1000",
        "rax <= 0x0FFF",
        "rbx >= 5",
        "rbx <= 4",
        "[rax] == 0x42",
        "[rax] != 0",
        "[rsp+8] == 0xDEAD",
        "[rsp + 0x8] == 0xDEAD",
        "[rax-8] == 7",
        "[rax - 0x8] == 7",
        "[0x2000] == 0x99",
        "[rsp] == 0x99",
        "  rax  ==  0x1000  ",   // surrounding + internal whitespace
        "5 == rbx",              // literal on the left, register on the right
        "[rax] < [rsp]",         // memory vs memory
        "",                      // empty -> unconditional (always true)
        "garbage",               // no operator -> error
        "r9 == 1",               // unknown register -> error
        "[r9] == 1",             // unknown register in a deref base -> error
        "rax == bogus",          // unknown register on the rhs -> error
        // Signed operators (and the s-tokenizer boundary cases).
        "rax s< 0",
        "rax s> 0",
        "rax s<= 0x1000",
        "rax s>= 0x1000",
        "rbx s> -5",
        "rbx s< -5",
        "rax s<0x1001",          // no space before the rhs
        "[rsp+8] s>= 0",
        "s< 5",                  // operator without lhs -> error
    };

    for (const char* e : exprs) {
        // String path, then compiled path; both with onError=true and onError=false.
        for (bool onErr : { true, false }) {
            bool s = EvalCondition(e, cc, onErr);
            CondProgram p = CompileCondition(e);
            bool c = EvalCompiled(p, cc, onErr);
            if (s != c) {
                std::printf("MISMATCH expr=\"%s\" onError=%d  string=%d compiled=%d\n",
                            e, (int)onErr, (int)s, (int)c);
                ++g_fail;
            }
        }
    }

    // ---- 2) Spot-check the concrete truth values (not just string==compiled). ----
    CHECK(EvalCompiled(CompileCondition("rax == 0x1000"), cc, false));
    CHECK(!EvalCompiled(CompileCondition("rax != 0x1000"), cc, true));
    CHECK(EvalCompiled(CompileCondition("[rsp+8] == 0xDEAD"), cc, false));
    CHECK(EvalCompiled(CompileCondition("[rax-8] == 7"), cc, false));
    CHECK(EvalCompiled(CompileCondition("[0x2000] == 0x99"), cc, false));
    CHECK(EvalCompiled(CompileCondition(""), cc, false));        // empty == always true

    // Error programs honor onError both ways.
    CHECK(EvalCompiled(CompileCondition("garbage"), cc, true));
    CHECK(!EvalCompiled(CompileCondition("garbage"), cc, false));
    CHECK(EvalCompiled(CompileCondition("r9 == 1"), cc, true));
    CHECK(!EvalCompiled(CompileCondition("r9 == 1"), cc, false));

    // The empty program is flagged empty+valid; a malformed one is invalid.
    CHECK(CompileCondition("").empty && CompileCondition("").valid);
    CHECK(!CompileCondition("garbage").valid);
    CHECK(CompileCondition("rax == 1").valid && !CompileCondition("rax == 1").empty);

    // Breakpoint commands validate both syntax and the debugger's concrete
    // register vocabulary before they are queued. Empty remains the intentional
    // unconditional form; malformed/unknown input must never reach the hit path.
    {
        std::string error = "stale";
        CHECK(ValidateBreakpointCondition("", &error));
        CHECK(error.empty());
        CHECK(ValidateBreakpointCondition("rax == 1", &error));
        CHECK(ValidateBreakpointCondition("[rsp+8] != 0", &error));
        CHECK(ValidateBreakpointCondition("rflags != 0", &error));
        CHECK(!ValidateBreakpointCondition("garbage", &error));
        CHECK(!error.empty());
        CHECK(!ValidateBreakpointCondition("rax = 1", &error));
        CHECK(!ValidateBreakpointCondition("bogus == 1", &error));
        CHECK(error.find("bogus") != std::string::npos);
        CHECK(!ValidateBreakpointCondition("[unknown+8] == 0", &error));
        CHECK(ValidateBreakpointCondition("RAX == 1", &error));
    }

    // ---- 2b) Signed operators: concrete truth values. ----
    CHECK(EvalCompiled(CompileCondition("rbx s> -5"), cc, false));    // 5 > -5 signed
    CHECK(!EvalCompiled(CompileCondition("rbx > -5"), cc, true));     // unsigned: 5 not > 0xFF..FB
    CHECK(!EvalCompiled(CompileCondition("rbx s< -5"), cc, true));
    CHECK(EvalCompiled(CompileCondition("rax s<= 0x1000"), cc, false));
    CHECK(EvalCompiled(CompileCondition("rax s>= 0x1000"), cc, false));
    CHECK(!EvalCompiled(CompileCondition("rax s< 0"), cc, true));     // 0x1000 not negative
    CHECK(CompileCondition("rax s< 0").valid && CompileCondition("rax s< 0").op == CondOp::SLt);
    CHECK(CompileCondition("rax s<= 0").op == CondOp::SLe);           // longest-match at same position
    CHECK(CompileCondition("rax s>= 0").op == CondOp::SGe);
    CHECK(!CompileCondition("s< 5").valid);                           // no lhs operand
    // Boundary guard: an identifier's trailing 's' never becomes the operator.
    CHECK(CompileCondition("flags<1").valid && CompileCondition("flags<1").op == CondOp::Lt &&
          CompileCondition("flags<1").lhs.reg == "flags");
    CHECK(CompileCondition("flags<=1").op == CondOp::Le &&
          CompileCondition("flags<=1").lhs.reg == "flags");

    // ---- 3) Compiled single-operand eval matches EvalExpression (watch path). ----
    const char* ops[] = {
        "rax", "rsp", "0x2000", "4096", "[rax]", "[rsp+8]", "[rsp + 0x8]",
        "[rax-8]", "[0x2000]", "r9", "garbage", "[r9]",
    };
    for (const char* o : ops) {
        uint64_t sv = 0, cv = 0;
        bool sok = EvalExpression(o, cc, sv);
        CondOperand co;
        bool cok = CompileExpression(o, co) && EvalCompiled(co, cc, cv);
        if (sok != cok || (sok && sv != cv)) {
            std::printf("OPERAND MISMATCH \"%s\"  string(ok=%d,v=0x%llX) compiled(ok=%d,v=0x%llX)\n",
                        o, (int)sok, (unsigned long long)sv, (int)cok, (unsigned long long)cv);
            ++g_fail;
        }
    }

    // ---- 4) Re-evaluating one compiled program many times is stable (the whole
    //         point: parse once, evaluate per hit). Flip a "register" value via a
    //         fresh context and confirm the same program tracks it. ----
    {
        CondProgram p = CompileCondition("rax == 0x1000");
        for (int i = 0; i < 1000; ++i) CHECK(EvalCompiled(p, cc, false));
        CondContext cc2 = cc;
        cc2.reg = [](const std::string& n, uint64_t& o) -> bool {
            if (n == "rax") { o = 0x2000; return true; }  // now rax != 0x1000
            return false;
        };
        CHECK(!EvalCompiled(p, cc2, false));   // same program, different live state
    }

    if (g_fail) { std::printf("\n%d CHECK(s)/mismatch(es) FAILED\n", g_fail); return 1; }
    std::printf("cond_compiled_test: all checks passed\n");
    return 0;
}
