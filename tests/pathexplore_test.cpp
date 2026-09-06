//
// pathexplore_test.cpp
// Off-target unit test for the F3 path explorer (src/Core/PathExplore.cpp) using a
// MOCK symbolic CFG + a REAL bounded byte solver: tree forking at an input-dependent
// branch, heuristic tags (Safe / IntOverflow / HiddenCode / Escaped), budget
// truncation, and solving a chosen path's constraints into a concrete input.
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\pathexplore_test.cpp src\Core\PathExplore.cpp src\Core\ExprAst.cpp
//   .\pathexplore_test.exe
//
#include "Core/PathExplore.h"

#include <cstdint>
#include <cstdio>
#include <unordered_map>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

static ExprRef substVars(const ExprRef& e, const std::unordered_map<uint64_t, uint64_t>& m) {
    if (!e) return e;
    if (e->op == ExprOp::Var) { auto it = m.find(e->val); return it != m.end() ? C(it->second, e->bits) : e; }
    if (e->kids.empty()) return e;
    std::vector<ExprRef> k; for (auto& c : e->kids) k.push_back(substVars(c, m));
    auto n = std::make_shared<Expr>(); n->op = e->op; n->bits = e->bits; n->val = e->val; n->kids = k;
    return n;
}

// Real bounded solver over a single 8-bit input var (id 0): brute force 0..255 for a
// value making every stored constraint predicate true.
struct ByteSolver : ISolver {
    bool solveForInput(const std::vector<PathConstraint>& pcs, std::vector<VarBinding>& model) override {
        for (uint32_t v = 0; v < 256; ++v) {
            std::unordered_map<uint64_t, uint64_t> m{ { 0, v } };
            bool all = true;
            for (const auto& pc : pcs) { uint64_t r; if (!EvalConst(substVars(pc.pred, m), r) || r != 1) { all = false; break; } }
            if (all) { model.clear(); model.push_back({ 0, v, 1 }); return true; }
        }
        return false;
    }
    ExprRef simplify(const ExprRef& e) override { return e; }
    int isSat(const ExprRef& p) override { uint64_t v; return EvalConst(p, v) ? (v ? 1 : 0) : -1; }
};

// Mock program:  root 0x1000: if (input > 0x41) goto 0x1100 (overflow) else goto 0x9000 (hidden)
struct MockCfg : ISymCfg {
    BranchInfo blockTerminator(uint64_t va, const std::vector<PathConstraint>&) override {
        BranchInfo bi;
        if (va == 0x1000) {
            bi.kind = BranchInfo::CondBranch;
            bi.pred = Bin(ExprOp::Ult, C(0x41, 8), Var(0, 8));   // 0x41 < input  ==  input > 0x41
            bi.targetA = 0x1100; bi.targetB = 0x9000;
            bi.targetAValid = bi.targetBValid = true;
        } else if (va == 0x1100) {
            bi.kind = BranchInfo::Return; bi.overflowFeasible = true;
        } else {
            bi.kind = BranchInfo::Return;
        }
        return bi;
    }
    bool isStaticallyReached(uint64_t va) override { return va != 0x9000; } // 0x9000 = hidden
    bool inAnyFunction(uint64_t va) override { return va != 0x9000; }
};

struct EscapeCfg : ISymCfg {
    BranchInfo blockTerminator(uint64_t, const std::vector<PathConstraint>&) override {
        BranchInfo bi; bi.kind = BranchInfo::Escape; return bi;
    }
    bool isStaticallyReached(uint64_t) override { return true; }
    bool inAnyFunction(uint64_t) override { return true; }
};

struct ZeroTargetCfg : ISymCfg {
    BranchInfo blockTerminator(uint64_t va, const std::vector<PathConstraint>&) override {
        BranchInfo bi;
        if (va == 0x1000) {
            bi.kind = BranchInfo::Jump;
            bi.targetA = 0;
            bi.targetAValid = true;
        }
        return bi;
    }
    bool isStaticallyReached(uint64_t) override { return true; }
    bool inAnyFunction(uint64_t) override { return true; }
};

struct MissingTargetCfg : ISymCfg {
    BranchInfo blockTerminator(uint64_t, const std::vector<PathConstraint>&) override {
        BranchInfo bi;
        bi.kind = BranchInfo::Jump; // default target value is not an implicit VA 0
        return bi;
    }
    bool isStaticallyReached(uint64_t) override { return true; }
    bool inAnyFunction(uint64_t) override { return true; }
};

int main() {
    // ---- DependsOnInput ----------------------------------------------------
    CHECK(DependsOnInput(Bin(ExprOp::Ult, C(0x41, 8), Var(0, 8))));
    CHECK(!DependsOnInput(Bin(ExprOp::Add, C(1, 8), C(2, 8))));

    // ---- full explore: fork into IntOverflow + HiddenCode -----------------
    {
        MockCfg cfg; ByteSolver solver; ExploreConfig ec;
        PathTree t = Explore(0x1000, cfg, solver, ec);
        CHECK(t.nodes.size() == 3);
        CHECK(!t.truncated);
        if (t.nodes.size() == 3) {
            CHECK(t.nodes[0].blockVA == 0x1000 && t.nodes[0].tag == PathTag::Safe);
            CHECK(t.nodes[0].children.size() == 2);
            CHECK(t.nodes[1].blockVA == 0x1100 && t.nodes[1].tag == PathTag::IntOverflow);
            CHECK(t.nodes[2].blockVA == 0x9000 && t.nodes[2].tag == PathTag::HiddenCode);

            // Solve the overflow path -> a concrete input > 0x41.
            std::vector<VarBinding> model;
            CHECK(SolvePath(t, 1, solver, model));
            CHECK(model.size() == 1);
            if (model.size() == 1) {
                CHECK(model[0].varId == 0);
                CHECK(model[0].value > 0x41);
                std::printf("  solved overflow input: v0 = 0x%llX\n", (unsigned long long)model[0].value);
            }
        }
    }

    // ---- budget truncation -------------------------------------------------
    {
        MockCfg cfg; ByteSolver solver; ExploreConfig ec; ec.maxNodes = 2;
        PathTree t = Explore(0x1000, cfg, solver, ec);
        CHECK(t.truncated);
        CHECK(t.nodes.size() <= 2);
    }

    // ---- Escaped tag -------------------------------------------------------
    {
        EscapeCfg cfg; ByteSolver solver; ExploreConfig ec;
        PathTree t = Explore(0x2000, cfg, solver, ec);
        CHECK(t.nodes.size() == 1);
        CHECK(t.nodes[0].tag == PathTag::Escaped);
    }

    // ---- Explicit target validity preserves a real branch to VA 0 --------
    {
        ZeroTargetCfg cfg; ByteSolver solver; ExploreConfig ec;
        PathTree t = Explore(0x1000, cfg, solver, ec);
        CHECK(t.nodes.size() == 2);
        if (t.nodes.size() == 2) CHECK(t.nodes[1].blockVA == 0);
    }
    {
        MissingTargetCfg cfg; ByteSolver solver; ExploreConfig ec;
        PathTree t = Explore(0x1000, cfg, solver, ec);
        CHECK(t.nodes.size() == 1);
        CHECK(t.nodes[0].tag == PathTag::Escaped);
    }

    if (g_fail == 0) std::printf("ALL PATHEXPLORE TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
