//
// solver_test.cpp
// Verifies the linkable facade backend (src/Core/SymEngine.cpp) built WITHOUT Triton:
// MakeSolver()'s DefaultSolver does simplify / isSat / bounded solveForInput. Proves
// the app links and F3 path-solving works with zero engine deps.
//
//   cl /std:c++20 /EHsc /I src tests\solver_test.cpp src\Core\SymEngine.cpp ^
//      src\Core\ExprAst.cpp src\Core\Simplify.cpp
//   .\solver_test.exe
//
#include "Core/SymEngine.h"

#include <cstdio>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

int main() {
    auto solver = MakeSolver();
    auto eng = MakeSymEngine(Arch::X64);   // stub without DS_HAVE_SYMENGINE -> Unavailable

    // simplify
    CHECK(ExprEqual(solver->simplify(Bin(ExprOp::Xor, Var(0, 32), Var(0, 32))), C(0, 32)));

    // isSat
    CHECK(solver->isSat(C(1, 1)) == 1);
    CHECK(solver->isSat(C(0, 1)) == 0);
    CHECK(solver->isSat(Bin(ExprOp::Ult, C(0x41, 8), Var(0, 8))) == -1);  // free var -> unknown

    // solveForInput: input > 0x41  (0x41 < v)
    {
        std::vector<PathConstraint> pcs = { { Bin(ExprOp::Ult, C(0x41, 8), Var(0, 8)), true, 0, 0 } };
        std::vector<VarBinding> model;
        CHECK(solver->solveForInput(pcs, model));
        CHECK(model.size() == 1 && model[0].value > 0x41);
    }

    // solveForInput: contradictory constraints -> no model
    {
        std::vector<PathConstraint> pcs = {
            { Bin(ExprOp::Eq, Var(0, 8), C(5, 8)), true, 0, 0 },
            { Bin(ExprOp::Eq, Var(0, 8), C(6, 8)), true, 0, 0 },
        };
        std::vector<VarBinding> model;
        CHECK(!solver->solveForInput(pcs, model));
    }

    // stub engine reports Unavailable (no Triton compiled in)
    {
        SeedSource seed; SymOptions opt; SymOutputs out;
        CHECK(eng->symbolizeRegion(seed, 0, 0, {}, opt, out) == SymStatus::Unavailable);
    }

    if (g_fail == 0) std::printf("ALL SOLVER TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
