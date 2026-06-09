//
// expr_simplify_test.cpp
// Off-target unit test for the PURE bit-vector AST (src/Core/ExprAst.cpp) and the
// sound simplifier (src/Core/Simplify.cpp): width masking, constant folding,
// signed/unsigned ops, and semantics-preserving identities.
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\expr_simplify_test.cpp src\Core\ExprAst.cpp src\Core\Simplify.cpp
//   .\expr_simplify_test.exe
//
#include "Core/ExprAst.h"
#include "Core/Simplify.h"

#include <cstdint>
#include <cstdio>
#include <functional>
#include <random>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

// Evaluate a constant expr and assert it equals v (masked to width).
static void evalIs(const ExprRef& e, uint64_t v) {
    uint64_t out = 0;
    CHECK(EvalConst(e, out));
    CHECK(out == MaskToBits(v, e->bits));
    if (out != MaskToBits(v, e->bits))
        std::printf("  evalIs: got 0x%llX want 0x%llX  [%s]\n",
                    (unsigned long long)out, (unsigned long long)MaskToBits(v, e->bits),
                    ExprToString(e).c_str());
}

int main() {
    // ---- width masking ----------------------------------------------------
    CHECK(MaskToBits(0x1FF, 8) == 0xFF);
    CHECK(MaskToBits(0x1234, 64) == 0x1234);
    CHECK(SignExtendTo64(0x80, 8) == (uint64_t)(int64_t)-128);
    CHECK(SignExtendTo64(0x7F, 8) == 0x7F);

    // ---- constant folding (modular) ---------------------------------------
    evalIs(Bin(ExprOp::Add, C(3, 8), C(5, 8)), 8);
    evalIs(Bin(ExprOp::Add, C(200, 8), C(100, 8)), 44);                 // 300 mod 256
    evalIs(Bin(ExprOp::Mul, C(2, 8), C(3, 8)), 6);
    evalIs(Bin(ExprOp::Sub, C(5, 8), C(9, 8)), (uint64_t)(uint8_t)(5 - 9)); // wrap
    evalIs(Bin(ExprOp::Add, Bin(ExprOp::Mul, C(2, 8), C(3, 8)), C(1, 8)), 7); // nested
    evalIs(Bin(ExprOp::Xor, C(0xF0, 8), C(0x0F, 8)), 0xFF);
    evalIs(Bin(ExprOp::Shl, C(1, 8), C(3, 8)), 8);
    evalIs(Bin(ExprOp::Shl, C(1, 8), C(9, 8)), 0);                      // shift >= width -> 0
    evalIs(Bin(ExprOp::LShr, C(0x80, 8), C(3, 8)), 0x10);
    evalIs(Bin(ExprOp::AShr, C(0x80, 8), C(3, 8)), 0xF0);               // arithmetic: sign fill

    // signed vs unsigned comparisons
    evalIs(Bin(ExprOp::Ult, C(0x80, 8), C(0x10, 8)), 0);               // 128 <u 16 -> false
    evalIs(Bin(ExprOp::Slt, C(0x80, 8), C(0x10, 8)), 1);               // -128 <s 16 -> true

    // UDiv-by-zero is not foldable
    { uint64_t o; CHECK(!EvalConst(Bin(ExprOp::UDiv, C(4, 8), C(0, 8)), o)); }

    // structural ops
    evalIs(ConcatE(C(0xAB, 8), C(0xCD, 8)), 0xABCD);
    evalIs(Extract(C(0xABCD, 16), 8, 8), 0xAB);
    evalIs(Ext(ExprOp::SExt, C(0x80, 8), 16), 0xFF80);
    evalIs(Ext(ExprOp::ZExt, C(0x80, 8), 16), 0x0080);
    evalIs(IteE(C(1, 1), C(7, 8), C(9, 8)), 7);
    evalIs(IteE(C(0, 1), C(7, 8), C(9, 8)), 9);

    // a Var is not constant-evaluable
    { uint64_t o; CHECK(!EvalConst(Var(0, 32), o)); }

    // ---- ExprEqual --------------------------------------------------------
    CHECK(ExprEqual(Var(1, 32), Var(1, 32)));
    CHECK(!ExprEqual(Var(1, 32), Var(2, 32)));
    CHECK(ExprEqual(Bin(ExprOp::Add, Var(1, 8), C(2, 8)), Bin(ExprOp::Add, Var(1, 8), C(2, 8))));

    // ---- Simplify: sound identities ---------------------------------------
    auto x = Var(0, 32), y = Var(1, 32);
    CHECK(ExprEqual(Simplify(Bin(ExprOp::Xor, x, x)), C(0, 32)));          // x^x = 0
    CHECK(ExprEqual(Simplify(Bin(ExprOp::Sub, x, x)), C(0, 32)));          // x-x = 0
    CHECK(ExprEqual(Simplify(Bin(ExprOp::Add, x, C(0, 32))), x));         // x+0 = x
    CHECK(ExprEqual(Simplify(Bin(ExprOp::Or, x, C(0, 32))), x));          // x|0 = x
    CHECK(ExprEqual(Simplify(Bin(ExprOp::And, x, x)), x));                // x&x = x
    CHECK(ExprEqual(Simplify(Bin(ExprOp::Mul, x, C(0, 32))), C(0, 32)));  // x*0 = 0
    CHECK(ExprEqual(Simplify(Bin(ExprOp::Mul, x, C(1, 32))), x));         // x*1 = x
    CHECK(ExprEqual(Simplify(Bin(ExprOp::And, x, C(0xFFFFFFFF, 32))), x));// x & ~0 = x
    CHECK(ExprEqual(Simplify(Un(ExprOp::Not, Un(ExprOp::Not, x))), x));   // ~~x = x
    CHECK(ExprEqual(Simplify(Un(ExprOp::Neg, Un(ExprOp::Neg, x))), x));   // --x = x
    CHECK(ExprEqual(Simplify(Bin(ExprOp::Eq, x, x)), C(1, 1)));           // x==x -> 1
    CHECK(ExprEqual(Simplify(IteE(C(1, 1), x, y)), x));                   // ite(1,x,y)=x
    CHECK(ExprEqual(Simplify(IteE(C(0, 1), x, y)), y));                   // ite(0,x,y)=y

    // nested: (x + 0) ^ (y * 1) -> x ^ y
    CHECK(ExprEqual(Simplify(Bin(ExprOp::Xor, Bin(ExprOp::Add, x, C(0, 32)),
                                              Bin(ExprOp::Mul, y, C(1, 32)))),
                    Bin(ExprOp::Xor, x, y)));

    // whole-constant subtree folds: (2*3 + 1) & 0xFF -> 7
    CHECK(ExprEqual(Simplify(Bin(ExprOp::And,
                                 Bin(ExprOp::Add, Bin(ExprOp::Mul, C(2, 8), C(3, 8)), C(1, 8)),
                                 C(0xFF, 8))),
                    C(7, 8)));

    // ---- Simplify SOUNDNESS fuzz: simplified expr agrees with original on
    //      random concrete inputs (substitute Vars with constants, compare). --
    {
        std::mt19937 rng(0x5EED);
        for (int trial = 0; trial < 500; ++trial) {
            // Build a small random expression over two 8-bit vars + constants.
            auto leaf = [&](void) -> ExprRef {
                int r = rng() % 4;
                if (r == 0) return Var(0, 8);
                if (r == 1) return Var(1, 8);
                return C(rng() & 0xFF, 8);
            };
            ExprOp ops[] = { ExprOp::Add, ExprOp::Sub, ExprOp::Mul, ExprOp::And,
                             ExprOp::Or, ExprOp::Xor, ExprOp::Shl, ExprOp::LShr };
            ExprRef e = Bin(ops[rng() % 8], leaf(), leaf(), 8);
            e = Bin(ops[rng() % 8], e, leaf(), 8);
            e = Un((rng() & 1) ? ExprOp::Not : ExprOp::Neg, e, 8);
            ExprRef s = Simplify(e);
            // Evaluate both with Vars bound to concrete values, for all 256x a few b.
            for (int t2 = 0; t2 < 12; ++t2) {
                uint64_t va = rng() & 0xFF, vb = rng() & 0xFF;
                // substitute by rebuilding: cheap recursive bind
                std::function<ExprRef(const ExprRef&)> bind = [&](const ExprRef& n) -> ExprRef {
                    if (!n) return n;
                    if (n->op == ExprOp::Var) return C(n->val == 0 ? va : vb, n->bits);
                    if (n->op == ExprOp::Const) return n;
                    std::vector<ExprRef> kk;
                    for (auto& c : n->kids) kk.push_back(bind(c));
                    auto m = std::make_shared<Expr>(); m->op = n->op; m->bits = n->bits; m->val = n->val; m->kids = kk;
                    return m;
                };
                uint64_t ve = 0, vs = 0;
                bool oe = EvalConst(bind(e), ve), os = EvalConst(bind(s), vs);
                CHECK(oe == os);
                if (oe && os) CHECK(ve == vs);
                if (oe && os && ve != vs) {
                    std::printf("  SOUNDNESS FAIL a=%llu b=%llu: e=%llu s=%llu\n    e=%s\n    s=%s\n",
                                (unsigned long long)va, (unsigned long long)vb,
                                (unsigned long long)ve, (unsigned long long)vs,
                                ExprToString(e).c_str(), ExprToString(s).c_str());
                }
            }
        }
    }

    if (g_fail == 0) std::printf("ALL EXPR/SIMPLIFY TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
